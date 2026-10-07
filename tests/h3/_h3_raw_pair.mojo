"""H3 server driven by a raw QUIC client, for HTTP/3 framing tests.

The client has no H3 layer of its own, so each test controls exactly the
stream bytes the server sees. `RawPair.pump` delivers datagrams in order
and records what both sides observed; `hold_server_events` lets a test
queue many packets in the server's QUIC layer and have H3 drain them in
one go.
"""

from std.collections import Span
from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.event import QuicEvent, ConnectionClosedPayload
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.h3.connection import H3Connection, H3Event
from tests._test_util import assert_true, load_test_cert, load_test_ca


def put_varint(mut out: List[Byte], v: UInt64):
    """Append `v` as a minimal QUIC varint."""
    var n = 8
    var tag = UInt64(0xC0)
    if v < 64:
        n = 1
        tag = 0x00
    elif v < 16384:
        n = 2
        tag = 0x40
    elif v < UInt64(1) << 30:
        n = 4
        tag = 0x80
    for i in range(n):
        var byte = (v >> UInt64(8 * (n - 1 - i))) & 0xFF
        if i == 0:
            byte |= tag
        out.append(UInt8(byte))


def raw_params(stream_window: UInt64 = UInt64(65_536)) -> TransportParams:
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    p.initial_max_data = UInt64(4_194_304)
    p.initial_max_stream_data_bidi_local = stream_window
    p.initial_max_stream_data_bidi_remote = stream_window
    p.initial_max_stream_data_uni = stream_window
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


def headers_get() -> List[Byte]:
    """HEADERS frame: empty QPACK prefix + indexed static 17 (:method GET)."""
    var f: List[Byte] = [0x01, 0x03, 0x00, 0x00, 0xD1]
    return f^


def filler(mut out: List[Byte], n: Int):
    for _ in range(n):
        out.append(0xAB)


struct RawPair(Movable):
    """H3 server + raw QUIC client, plus what the harness observed."""

    var srv: H3Connection
    var cli: QuicConnection
    var now: UInt64
    var close_code: Int  # app error code the client saw, -1 if none
    var data: List[Byte]  # concatenated DATA_RECEIVED payloads
    var headers_events: Int
    var ended_events: Int
    # When set, `pump` feeds the server's QUIC layer only; H3 sees the
    # queued stream data at the next `release_server_events`.
    var hold_server_events: Bool

    def __init__(out self, stream_window: UInt64 = UInt64(65_536)) raises:
        var tls = TlsBackend("lib/librustls_mojo.so")
        var ck = load_test_cert()
        var cert = ck[0].copy()
        var key = ck[1].copy()
        var ca = load_test_ca()
        var srv_cfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
        var cli_cfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
        self.now = UInt64(1_000_000)
        var cli = QuicConnection.client(
            tls.shared(), cli_cfg, "localhost", raw_params(stream_window), self.now
        )
        var odcid = List[Byte](cli.initial_dcid.as_span())
        var cdcid = List[Byte](cli.initial_dcid.as_span())
        var sq = QuicConnection.server(
            tls.shared(), srv_cfg, raw_params(stream_window), Span(odcid), Span(cdcid), self.now,
        )
        self.srv = H3Connection.server(sq^)
        self.cli = cli^
        self.close_code = -1
        self.data = List[Byte]()
        self.headers_events = 0
        self.ended_events = 0
        self.hold_server_events = False
        _ = tls^
        self.pump(20)
        assert_true(self.cli.is_established(), "handshake completes")

    def pump(mut self, rounds: Int) raises:
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
                        if self.hold_server_events:
                            self.srv._quic.recv(Span(scratch[i]), self.now)
                        else:
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
                if ev.value().type_id == QuicEvent.CONNECTION_CLOSED:
                    self.close_code = Int(
                        ev.value().payload.unsafe_get[ConnectionClosedPayload]().error_code
                    )
            self.collect()

    def release_server_events(mut self) raises:
        """Let H3 process everything its QUIC layer queued while held."""
        self.hold_server_events = False
        self.srv._poll_quic_events(self.now)
        self.collect()

    def collect(mut self):
        while True:
            var hev = self.srv.poll_event()
            if not hev:
                break
            if hev.value().kind == H3Event.DATA_RECEIVED:
                self.data.extend(Span(hev.value().data))
            elif hev.value().kind == H3Event.HEADERS_RECEIVED:
                self.headers_events += 1
            elif hev.value().kind == H3Event.STREAM_ENDED:
                self.ended_events += 1

    def buffered(self, sid: UInt64) -> Int:
        var e = self.srv._stream_bufs.find(Int(sid))
        if not e:
            return 0
        return len(e.value().buf)

    def send(mut self, sid: UInt64, bytes: List[Byte], fin: Bool = False) raises:
        self.cli.send_stream_data(sid, Span(bytes), fin)
        self.pump(30)

    def control_stream(mut self) raises -> UInt64:
        """Open the client control stream and send an empty SETTINGS."""
        var ctrl = self.cli.open_stream(False)
        var b: List[Byte] = [0x00, 0x04, 0x00]
        self.send(ctrl, b)
        return ctrl
