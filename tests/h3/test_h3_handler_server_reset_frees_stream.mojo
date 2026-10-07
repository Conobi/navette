# tests/h3/test_h3_handler_server_reset_frees_stream.mojo
#
# A client that cancels a request with RESET_STREAM alone (no
# STOP_SENDING) while the handler's response is still open must not leak
# the stream. The server drops the request, so it must also cancel its
# own side (RFC 9114 Section 4.1.1); otherwise the QUIC stream never
# becomes terminal in both directions, is never freed, and never returns
# its MAX_STREAMS credit.

from std.collections import Span
from navette.h3.h3_handler_server import H3HandlerServer
from navette.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
    StreamHandler,
)
from navette.http import StatusCode, Headers, BodyFrame
from navette.http.request import Request
from navette.quic.connection import QuicConnection
from navette.quic.event import QuicEvent
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.tls.lib import TlsBackend
from tests._test_util import (
    assert_true, assert_equal_int, load_test_cert, load_test_ca,
)
from tests.h3._h3_raw_pair import raw_params, headers_get

# raw_params grants 100 bidi streams; going past it proves credit returns.
comptime _INITIAL_BIDI = 100


struct _OpenResponse(StreamHandler):
    """Starts a response and never finishes it: the request is cancelled
    mid-response."""

    def __init__(out self):
        pass

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        resp.send_status(StatusCode(200), Headers())
        var chunk = List[Byte]()
        for _ in range(32):
            chunk.append(0x61)
        _ = resp.try_send_body(BodyFrame.data(chunk^))

    def on_body_available(
        mut self, mut body: RecvBody, mut resp: ResponseWriter
    ) raises:
        pass

    def on_request_end(
        mut self, mut body: RecvBody, mut resp: ResponseWriter
    ) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


struct _Pair(Movable):
    """Raw QUIC client against an H3HandlerServer, pumped in memory."""

    var srv: H3HandlerServer[_OpenResponse]
    var cli: QuicConnection
    var now: UInt64

    def __init__(out self) raises:
        var tls = TlsBackend("lib/librustls_mojo.so")
        var ck = load_test_cert()
        var cert = ck[0].copy()
        var key = ck[1].copy()
        var ca = load_test_ca()
        var srv_cfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
        var cli_cfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
        self.now = UInt64(1_000_000)
        var cli = QuicConnection.client(
            tls.shared(), cli_cfg, "localhost", raw_params(), self.now
        )
        var odcid = List[Byte](cli.initial_dcid.as_span())
        var cdcid = List[Byte](cli.initial_dcid.as_span())
        var sq = QuicConnection.server(
            tls.shared(), srv_cfg, raw_params(), Span(odcid), Span(cdcid), self.now,
        )
        self.srv = H3HandlerServer[_OpenResponse](quic=sq^, handler=_OpenResponse())
        self.cli = cli^
        _ = tls^
        self.pump(20)
        assert_true(self.cli.is_established(), "handshake completes")

    def pump(mut self, rounds: Int) raises:
        """Exchange datagrams both ways; the client drains its events."""
        var scratch = List[List[Byte]](capacity=1)
        for _ in range(rounds):
            self.now += UInt64(10_000)
            for _ in range(64):
                scratch.clear()
                var n = self.cli.send(self.now, scratch)
                if n == 0:
                    break
                for i in range(n):
                    try:
                        self.srv.feed_datagram(Span(scratch[i]), self.now)
                    except:
                        pass
            var dgs = List[List[Byte]]()
            self.srv.drain_datagrams(self.now, dgs)
            for i in range(len(dgs)):
                try:
                    self.cli.recv(Span(dgs[i]), self.now)
                except:
                    pass
            while True:
                var ev = self.cli.poll()
                if not ev:
                    break
                assert_true(
                    ev.value().type_id != QuicEvent.CONNECTION_CLOSED,
                    "connection stays open",
                )


def test_reset_only_cancel_frees_stream_and_returns_credit() raises:
    var p = _Pair()
    var baseline = len(p.srv._h3._quic.stream_map.streams)
    for i in range(_INITIAL_BIDI + 10):
        var sid = p.cli.open_stream(True)
        var h = headers_get()
        p.cli.send_stream_data(sid, Span(h), False)
        p.pump(3)
        if i == 0:
            assert_true(p.srv.has_stream(Int(sid)), "request is in flight")
        p.cli.reset_stream(sid, UInt64(0x10C))
        p.pump(4)
        assert_true(not p.srv.has_stream(Int(sid)), "request context dropped")
    assert_equal_int(
        len(p.srv._h3._quic.stream_map.streams), baseline, "streams freed"
    )
    assert_true(
        p.cli.stream_map.peer_max_streams_bidi > UInt64(_INITIAL_BIDI),
        "MAX_STREAMS credit re-granted",
    )
    print("  test_reset_only_cancel_frees_stream_and_returns_credit: PASS")


def main() raises:
    print("test_h3_handler_server_reset_frees_stream:")
    test_reset_only_cancel_frees_stream_and_returns_credit()
    print("All test_h3_handler_server_reset_frees_stream tests passed.")
