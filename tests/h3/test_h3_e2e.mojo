# tests/test_h3_e2e.mojo
#
# Full QUIC loopback E2E tests for H3HandlerServer and H3Session.
# Run with:
#   uv run mojo run -I . -I conformance -D ASSERT=all tests/test_h3_e2e.mojo

from std.collections.deque import Deque
from std.memory import Pointer
from std.collections import Dict, Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.cc.cc_trait import AckedPacket
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.h3.connection import H3Connection, H3Event, MAX_DATAGRAMS_PER_DRAIN
from navette.h3.h3_handler_server import H3HandlerServer
from navette.h3.h3_session import H3Session
from navette.h3.qpack import FieldSection, QpackEncoder, QpackDecoder
from navette.h3.frame import DataFrame, HeadersFrame
from navette.http.handler import StreamHandler, RecvBody, ResponseWriter, Capabilities, StreamError
from navette.http.request import Request, RequestBody
from navette.http.response import Response
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.http.body import BodyFrame
from navette.http.method import Method
from navette.http.version import Version
from navette.http.session import RequestHandle
from navette.http.handler import STREAM_ERR_LOCAL_ABORT, STREAM_ERR_RST_STREAM
from navette.h3.error import H3_NO_ERROR, H3_INTERNAL_ERROR, H3_MESSAGE_ERROR
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca
from tests.http._driver_script import ScriptHandler, _bytes


# ── Helpers ─────────────────────────────────────────────────────────────


def generate_ephemeral_cert() raises -> Tuple[List[Byte], List[Byte]]:
    # Backed by tests/fixtures/tls/server.{crt,key} (regen via
    # scripts/regen_test_certs.sh). See plans/2026-05-13-deps-enhancement.md §3.1.
    return load_test_cert()


def _h3_default_params() -> TransportParams:
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    p.initial_max_data = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_local = UInt64(65_536)
    p.initial_max_stream_data_bidi_remote = UInt64(65_536)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


struct _TestConfigs(Movable):
    var _tls: TlsBackend
    var srv_cfg: QuicServerConfig
    var cli_cfg: QuicClientConfig

    def __init__(out self) raises:
        self._tls = TlsBackend("lib/librustls_mojo.so")
        var ck = generate_ephemeral_cert()
        var cert_bytes = ck[0].copy()
        var key_bytes = ck[1].copy()
        var ca_bytes = load_test_ca()
        self.srv_cfg = QuicServerConfig(
            self._tls.shared(), Span(cert_bytes), Span(key_bytes),
        )
        self.cli_cfg = QuicClientConfig.with_ca(
            self._tls.shared(), Span(ca_bytes),
        )

    def __init__(out self, *, deinit move: Self):
        self._tls = move._tls^
        self.srv_cfg = move.srv_cfg^
        self.cli_cfg = move.cli_cfg^


def _pump_server_client[H: StreamHandler](
    mut server: H3HandlerServer[H],
    mut client: H3Connection,
    mut now: UInt64,
    rounds: Int = 5,
) raises -> UInt64:
    """Exchange datagrams between server adapter and raw client H3Connection."""
    for _ in range(rounds):
        now += UInt64(10_000)
        var s_dgs = List[List[Byte]]()
        server.drain_datagrams(now, s_dgs)
        for i in range(len(s_dgs)):
            try:
                client.feed_datagram(Span(s_dgs[i]), now)
            except:
                pass
        var c_dgs = List[List[Byte]]()
        client.drain_datagrams(now, c_dgs)
        for i in range(len(c_dgs)):
            try:
                server.feed_datagram(Span(c_dgs[i]), now)
            except:
                pass
    return now


# ── Test handler ─────────────────────────────────────────────────────────


struct _FixedResponseHandler(StreamHandler):
    """Handler that always sends a fixed status + body, ignoring the request."""
    var _body: String

    def __init__(out self, body: String):
        self._body = body

    def __init__(out self, *, deinit move: Self):
        self._body = move._body^

    def on_request(
        mut self, var req: Request, mut body: RecvBody, mut resp: ResponseWriter, caps: Capabilities
    ) raises:
        resp.send_status(StatusCode.ok(), Headers())
        var body_bytes = List[Byte]()
        var src = self._body.as_bytes()
        for i in range(len(src)):
            body_bytes.append(src[i])
        _ = resp.try_send_body(BodyFrame.data(body_bytes^))
        resp.end()

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


# ── Tests ────────────────────────────────────────────────────────────────


def test_h3_simple_get() raises:
    """GET / → 200 OK with body 'hello'."""
    var tc = _TestConfigs()
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(tc._tls.shared(), tc.cli_cfg, "localhost", params, now)
    var orig_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var client_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var server_quic = QuicConnection.server(
        tc._tls.shared(), tc.srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3HandlerServer[_FixedResponseHandler](
        quic=server_quic^, handler=_FixedResponseHandler("hello")
    )
    var client = H3Connection.client(client_quic^)

    # Pump handshake + bootstrap (50 rounds max)
    now = _pump_server_client(server, client, now, 50)

    # Client opens bidi stream and sends GET /
    var stream_id = client.open_bidi_stream()
    var req_fields = FieldSection(method="GET", scheme="https", authority="localhost", path="/")
    client.send_headers(stream_id, req_fields, True)  # fin=True (no body)

    # Pump 20 more rounds for request/response
    now = _pump_server_client(server, client, now, 20)

    # Collect client events: expect HEADERS_RECEIVED + DATA_RECEIVED
    var got_200 = False
    var body_bytes = List[Byte]()
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.HEADERS_RECEIVED:
            got_200 = got_200 or e.section.status == "200"
        elif e.kind == H3Event.DATA_RECEIVED:
            for i in range(len(e.data)):
                body_bytes.append(e.data[i])

    assert_true(got_200, "client did not receive 200 OK")
    var body_str = String(unsafe_from_utf8=body_bytes)
    assert_true(body_str == "hello", "response body expected 'hello', got: " + body_str)
    print("  test_h3_simple_get: PASS")


def test_h3_post_with_body() raises:
    """POST /upload with body 'data' → server responds 200."""
    var tc = _TestConfigs()
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(tc._tls.shared(), tc.cli_cfg, "localhost", params, now)
    var orig_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var client_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var server_quic = QuicConnection.server(
        tc._tls.shared(), tc.srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3HandlerServer[_FixedResponseHandler](
        quic=server_quic^, handler=_FixedResponseHandler("data")
    )
    var client = H3Connection.client(client_quic^)

    now = _pump_server_client(server, client, now, 50)

    # Client sends POST /upload with body
    var stream_id = client.open_bidi_stream()
    var req_fields = FieldSection(method="POST", scheme="https", authority="localhost", path="/upload")
    client.send_headers(stream_id, req_fields, False)
    var body_bytes = List[Byte]()
    var src = "data".as_bytes()
    for i in range(len(src)):
        body_bytes.append(src[i])
    client.send_data(stream_id, body_bytes, True)

    now = _pump_server_client(server, client, now, 20)

    # Verify response
    var got_200 = False
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.HEADERS_RECEIVED:
            got_200 = got_200 or e.section.status == "200"

    assert_true(got_200, "POST: client did not receive 200 OK")
    print("  test_h3_post_with_body: PASS")


def _pump_e2e[H: StreamHandler](
    mut server: H3HandlerServer[H],
    mut client: H3Session,
    mut now: UInt64,
    rounds: Int = 5,
) raises -> UInt64:
    """Exchange datagrams between HandlerServer and H3Session."""
    for _ in range(rounds):
        now += UInt64(10_000)
        var s_dgs = List[List[Byte]]()
        server.drain_datagrams(now, s_dgs)
        for i in range(len(s_dgs)):
            try:
                client.feed_datagram(Span(s_dgs[i]), now)
            except:
                pass
        var c_dgs = List[List[Byte]]()
        client.drain_datagrams(now, c_dgs)
        for i in range(len(c_dgs)):
            try:
                server.feed_datagram(Span(c_dgs[i]), now)
            except:
                pass
    return now


def test_h3_session_get() raises:
    """H3Session.submit(GET /) → response 200 with body 'hello'."""
    var tc = _TestConfigs()
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(tc._tls.shared(), tc.cli_cfg, "localhost", params, now)
    var orig_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var client_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var server_quic = QuicConnection.server(
        tc._tls.shared(), tc.srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3HandlerServer[_FixedResponseHandler](
        quic=server_quic^, handler=_FixedResponseHandler("hello")
    )
    var client = H3Session(quic=client_quic^)

    # Pump handshake
    now = _pump_e2e(server, client, now, 50)

    # Submit GET /. H3Session derives :authority from the host header
    # (RFC 9114 §4.2), so any non-empty placeholder works for loopback.
    var hdrs = Headers()
    hdrs.add(String("host"), String("test.local"))
    var req = Request(
        method=Method.get(),
        target=String("/"),
        version=Version.http_3(),
        headers=hdrs^,
    )
    var handle = client.submit(req^)

    # Pump until complete
    var complete = False
    for _ in range(30):
        now = _pump_e2e(server, client, now, 3)
        client.run_one(handle)
        if handle.is_complete():
            complete = True
            break

    assert_true(complete, "H3Session GET: handle did not complete")
    assert_true(handle.has_headers(), "H3Session GET: no response headers")
    var resp_opt = handle.try_take_response()
    assert_true(Bool(resp_opt), "H3Session GET: try_take_response returned none")
    var resp = resp_opt.take()
    assert_equal_int(Int(resp.status.code()), 200, "status 200")
    print("  test_h3_session_get: PASS")


def test_h3_multi_request() raises:
    """Three concurrent GET requests all complete successfully."""
    var tc = _TestConfigs()
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(tc._tls.shared(), tc.cli_cfg, "localhost", params, now)
    var orig_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var client_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var server_quic = QuicConnection.server(
        tc._tls.shared(), tc.srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3HandlerServer[_FixedResponseHandler](
        quic=server_quic^, handler=_FixedResponseHandler("ok")
    )
    var client = H3Session(quic=client_quic^)

    now = _pump_e2e(server, client, now, 50)

    # Submit three requests — RequestHandle is Movable but not Copyable,
    # so keep them as individual named variables.
    # H3Session needs a host header to derive :authority (RFC 9114 §4.2).
    var hdrs0 = Headers(); hdrs0.add(String("host"), String("test.local"))
    var hdrs1 = Headers(); hdrs1.add(String("host"), String("test.local"))
    var hdrs2 = Headers(); hdrs2.add(String("host"), String("test.local"))
    var req0 = Request(method=Method.get(), target=String("/"), version=Version.http_3(), headers=hdrs0^)
    var req1 = Request(method=Method.get(), target=String("/"), version=Version.http_3(), headers=hdrs1^)
    var req2 = Request(method=Method.get(), target=String("/"), version=Version.http_3(), headers=hdrs2^)
    var h0 = client.submit(req0^)
    var h1 = client.submit(req1^)
    var h2 = client.submit(req2^)

    for _ in range(60):
        now = _pump_e2e(server, client, now, 3)
        client.run_one(h0)
        client.run_one(h1)
        client.run_one(h2)
        if h0.is_complete() and h1.is_complete() and h2.is_complete():
            break

    assert_true(h0.is_complete(), "handle 0 not complete")
    assert_true(h1.is_complete(), "handle 1 not complete")
    assert_true(h2.is_complete(), "handle 2 not complete")
    assert_true(h0.has_headers(), "handle 0 no headers")
    assert_true(h1.has_headers(), "handle 1 no headers")
    assert_true(h2.has_headers(), "handle 2 no headers")
    print("  test_h3_multi_request: PASS")


def test_h3_goaway() raises:
    """Server sends GOAWAY; client receives GOAWAY_RECEIVED event."""
    var tc = _TestConfigs()
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(tc._tls.shared(), tc.cli_cfg, "localhost", params, now)
    var orig_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var client_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var server_quic = QuicConnection.server(
        tc._tls.shared(), tc.srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3HandlerServer[_FixedResponseHandler](
        quic=server_quic^, handler=_FixedResponseHandler("bye")
    )
    var client = H3Session(quic=client_quic^)

    now = _pump_e2e(server, client, now, 50)

    # Server sends GOAWAY
    server.send_goaway(UInt64(0))

    # Pump so client receives it
    now = _pump_e2e(server, client, now, 10)

    # H3Session.feed_datagram dispatches events internally and sets
    # received_goaway when a GOAWAY_RECEIVED event is observed.
    assert_true(client.received_goaway, "client did not receive GOAWAY_RECEIVED")
    print("  test_h3_goaway: PASS")


# ── Send loop: drain-terminates / drain-cap-is-observable ────────────────


struct _BigResponseHandler(StreamHandler):
    """Handler that answers every request with `size` bytes of 'x'."""
    var _size: Int

    def __init__(out self, size: Int):
        self._size = size

    def __init__(out self, *, deinit move: Self):
        self._size = move._size

    def on_request(
        mut self, var req: Request, mut body: RecvBody, mut resp: ResponseWriter, caps: Capabilities
    ) raises:
        resp.send_status(StatusCode.ok(), Headers())
        var body_bytes = List[Byte](capacity=self._size)
        for _ in range(self._size):
            body_bytes.append(UInt8(120))
        _ = resp.try_send_body(BodyFrame.data(body_bytes^))
        resp.end()

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


def _send_get(mut client: H3Connection) raises -> UInt64:
    """Open a bidi stream and send `GET /` with FIN; returns the stream id."""
    var stream_id = client.open_bidi_stream()
    var req_fields = FieldSection(method="GET", scheme="https", authority="localhost", path="/")
    client.send_headers(stream_id, req_fields, True)
    return stream_id


def _open_server_cwnd[H: StreamHandler](
    mut server: H3HandlerServer[H], bytes: Int
) raises:
    """Grow the server's cwnd by `bytes` through synthetic ACKs; unpace it."""
    var acked = 0
    var i = 0
    while acked < bytes:
        var pkt = AckedPacket(
            pkt_num=UInt64(100_000 + i),
            size=UInt64(1200),
            time_sent=UInt64(i * 1000),
            time_acked=UInt64(i * 1000 + 500),
            rtt_sample=UInt64(500),
        )
        server._h3._quic.recovery.cc.on_packet_acked(
            pkt, UInt64(500), UInt64(i * 1000 + 500)
        )
        acked += 1200
        i += 1
    server._h3._quic.recovery.pacer.enabled = False


def test_h3_drain_terminates() raises:
    """drain-terminates: idle → second drain empty; local close → one CLOSE then empty."""
    var tc = _TestConfigs()
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(tc._tls.shared(), tc.cli_cfg, "localhost", params, now)
    var orig_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var client_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var server_quic = QuicConnection.server(
        tc._tls.shared(), tc.srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3HandlerServer[_FixedResponseHandler](
        quic=server_quic^, handler=_FixedResponseHandler("hello")
    )
    var client = H3Connection.client(client_quic^)

    now = _pump_server_client(server, client, now, 50)
    _ = _send_get(client)
    now = _pump_server_client(server, client, now, 20)

    # Idle exchange: the drain runs dry within the cap, and a second call
    # at the same clock returns nothing.
    now += UInt64(10_000)
    var first = List[List[Byte]]()
    server.drain_datagrams(now, first)
    assert_true(
        len(first) < MAX_DATAGRAMS_PER_DRAIN,
        "idle drain must terminate below the cap",
    )
    assert_true(not server.has_pending_egress(), "idle drain must not report pending egress")
    var second = List[List[Byte]]()
    server.drain_datagrams(now, second)
    assert_equal_int(len(second), 0, "second idle drain must be empty")

    # Local close: exactly one CLOSE datagram, then empty.
    server._h3._quic.close_app(UInt64(0x100), String("bye"), now)
    var close_dgs = List[List[Byte]]()
    server.drain_datagrams(now, close_dgs)
    assert_equal_int(len(close_dgs), 1, "close drain must yield exactly one datagram")
    assert_true(not server.has_pending_egress(), "close drain must not report pending egress")
    var after_close = List[List[Byte]]()
    server.drain_datagrams(now, after_close)
    assert_equal_int(len(after_close), 0, "drain after the CLOSE must be empty")
    print("  test_h3_drain_terminates: PASS")


def test_h3_drain_cap_is_observable() raises:
    """drain-cap-is-observable: a 200 kB response yields exactly 64 datagrams
    from one drain (egress_capped set) and the remainder from the next."""
    var tc = _TestConfigs()
    var params = _h3_default_params()
    # Lift the per-stream windows so 200 kB fits without a MAX_STREAM_DATA
    # round-trip; connection-level data is already 1 MiB.
    params.initial_max_stream_data_bidi_local = UInt64(1_048_576)
    params.initial_max_stream_data_bidi_remote = UInt64(1_048_576)
    var now = UInt64(1_000_000)
    var body_size = 200_000

    var client_quic = QuicConnection.client(tc._tls.shared(), tc.cli_cfg, "localhost", params, now)
    var orig_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var client_dcid = List[Byte](client_quic.initial_dcid.as_span())
    var server_quic = QuicConnection.server(
        tc._tls.shared(), tc.srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3HandlerServer[_BigResponseHandler](
        quic=server_quic^, handler=_BigResponseHandler(body_size)
    )
    var client = H3Connection.client(client_quic^)

    now = _pump_server_client(server, client, now, 50)
    assert_true(server._h3.is_established(), "handshake did not complete")

    # A cwnd well above the whole response so the congestion gate never
    # closes the loop before the cap does.
    _open_server_cwnd[_BigResponseHandler](server, 2 * body_size)

    _ = _send_get(client)
    now += UInt64(10_000)
    var c_dgs = List[List[Byte]]()
    client.drain_datagrams(now, c_dgs)
    for i in range(len(c_dgs)):
        server.feed_datagram(Span(c_dgs[i]), now)

    now += UInt64(10_000)
    var first = List[List[Byte]]()
    server.drain_datagrams(now, first)
    assert_equal_int(
        len(first), MAX_DATAGRAMS_PER_DRAIN,
        "first drain must stop exactly at the cap",
    )
    assert_true(server.has_pending_egress(), "capped drain must report pending egress")

    # Drained into a non-empty list: the cap counts what this drain appends.
    var second = List[List[Byte]]()
    second.append(List[Byte]())
    server.drain_datagrams(now, second)
    assert_true(len(second) > 1, "second drain must carry the remainder")
    assert_equal_int(len(second[0]), 0, "drain appends, never clears")
    _ = second.pop(0)

    # Keep draining without feeding the client: the total must cover the
    # body and the loop must eventually run dry (egress_capped cleared).
    var total = len(first) + len(second)
    var calls = 2
    while server.has_pending_egress() and calls < 32:
        var more = List[List[Byte]]()
        server.drain_datagrams(now, more)
        total += len(more)
        calls += 1
    assert_true(not server.has_pending_egress(), "drain must run dry once the response is out")
    assert_true(
        total * 1200 >= body_size,
        "drained datagrams cannot carry the whole body: " + String(total),
    )
    print("  test_h3_drain_cap_is_observable: PASS")


def _sent_bytes(mut h3: H3Connection, sid: UInt64) raises -> List[Byte]:
    """Everything queued so far on `sid`'s send side."""
    var p = h3._quic.stream_map.stream_ptr(Int(sid))
    var out = p[].send_buf.value().data.copy()
    _ = h3._quic.stream_map.streams
    return out^


def _assert_same_bytes(got: List[Byte], want: List[Byte], what: String) raises:
    assert_equal_int(len(got), len(want), what + ": length")
    for i in range(len(want)):
        assert_equal_int(Int(got[i]), Int(want[i]), what + ": byte " + String(i))


def test_h3_frame_wire_bytes() raises:
    """DATA and HEADERS frames keep the type + varint length + payload layout byte for byte."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert = ck[0].copy()
    var key = ck[1].copy()
    var ca = load_test_ca()
    var srv_cfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
    var cli_cfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(tls.shared(), cli_cfg, "localhost", _h3_default_params(), now)
    var dcid = List[Byte](client.initial_dcid.as_span())
    var dcid2 = dcid.copy()
    var h3 = H3Connection.server(QuicConnection.server(
        tls.shared(), srv_cfg, _h3_default_params(), Span(dcid), Span(dcid2), now,
    ))
    h3._quic.stream_map.peer_max_streams_bidi = UInt64(16)
    var sizes: List[Int] = [0, 1, 63, 64, 16_383, 16_384]
    for size in sizes:
        var sid = h3.open_bidi_stream()
        var body = List[Byte](capacity=size)
        for i in range(size):
            body.append(UInt8(i % 251))
        h3.send_data(sid, Span(body), True)
        var want = List[Byte]()
        if size > 0:  # an empty body with FIN queues no DATA frame
            DataFrame(body.copy()).encode(want)
        _assert_same_bytes(_sent_bytes(h3, sid), want, "DATA " + String(size))
        var p = h3._quic.stream_map.stream_ptr(Int(sid))
        assert_true(p[].send_buf.value().fin, "FIN queued for size " + String(size))
    for count in [0, 20]:
        var sid = h3.open_bidi_stream()
        var fields = FieldSection(status="200")
        for i in range(count):
            fields.headers.add("x-h" + String(i), "value-" + String(i))
        h3.send_headers(sid, fields, False)
        var block = List[Byte]()
        QpackEncoder(False).encode(block, fields)  # H3Connection encodes without Huffman
        var want = List[Byte]()
        HeadersFrame(block.copy()).encode(want)
        var got = _sent_bytes(h3, sid)
        _assert_same_bytes(got, want, "HEADERS " + String(count))
        var dec = QpackDecoder()
        var decoded = dec.decode(Span(got)[len(got) - len(block):])
        assert_true(decoded.status == "200", "HEADERS decodes :status")
        assert_equal_int(len(decoded.headers), count, "HEADERS decode count")
        for i in range(count):
            assert_true(
                decoded.headers.name_at(i) == fields.headers.name_at(i)
                and decoded.headers.value_at(i) == fields.headers.value_at(i),
                "field " + String(i),
            )
    _ = h3._quic.stream_map.streams
    _ = tls^
    print("  test_h3_frame_wire_bytes: PASS")



# ── Shared driver: 1xx, the handler-failure policy, malformed trailers ──


struct _Script(Movable):
    """H3HandlerServer[ScriptHandler] against a raw client H3Connection; `log` holds the client's events per stream."""

    var tc: _TestConfigs
    var server: H3HandlerServer[ScriptHandler]
    var client: H3Connection
    var now: UInt64
    var log: Dict[Int, String]

    def __init__(out self) raises:
        var tc = _TestConfigs()
        var params = _h3_default_params()
        var now = UInt64(1_000_000)
        var client_quic = QuicConnection.client(tc._tls.shared(), tc.cli_cfg, "localhost", params, now)
        var odcid = List[Byte](client_quic.initial_dcid.as_span())
        var cdcid = odcid.copy()
        var server_quic = QuicConnection.server(tc._tls.shared(), tc.srv_cfg, params, Span(odcid), Span(cdcid), now)
        self.server = H3HandlerServer[ScriptHandler](quic=server_quic^, handler=ScriptHandler())
        self.client = H3Connection.client(client_quic^)
        self.tc = tc^
        self.now = _pump_server_client(self.server, self.client, now, 50)
        self.log = Dict[Int, String]()

    def request(mut self, method: String, path: String, fin: Bool) raises -> UInt64:
        var sid = self.client.open_bidi_stream()
        self.client.send_headers(sid, FieldSection(method=method, scheme="https", authority="localhost", path=path), fin)
        return sid

    def to_server(mut self) raises:
        """Deliver the client's datagrams to the server only, so its staged frames are still observable."""
        self.now += UInt64(10_000)
        var dgs = List[List[Byte]]()
        self.client.drain_datagrams(self.now, dgs)
        for i in range(len(dgs)):
            self.server.feed_datagram(Span(dgs[i]), self.now)

    def stop_code(self, sid: UInt64) -> Int:
        """The STOP_SENDING code the server has queued on `sid`, or -1."""
        var p = self.server._h3._quic.stream_map.try_stream_ptr(Int(sid))
        if not p or not p.value()[].needs_stop_sending:
            return -1
        return Int(p.value()[].stop_sending_error)

    def pump(mut self, rounds: Int) raises:
        """Exchange datagrams, then log the client's events: H<status>[<link>][/cl<content-length>], D<body>, E, R<code>."""
        self.now = _pump_server_client(self.server, self.client, self.now, rounds)
        while True:
            var ev = self.client.poll_event()
            if not ev:
                break
            var e = ev.take()
            var tok: String
            if e.kind == H3Event.HEADERS_RECEIVED:
                var cl = e.section.headers.get("content-length")
                tok = "H" + e.section.status + e.section.headers.get("link") + ("/cl" + cl if cl else "")
            elif e.kind == H3Event.DATA_RECEIVED:
                tok = "D" + String(unsafe_from_utf8=e.data.copy())
            elif e.kind == H3Event.STREAM_ENDED:
                tok = "E"
            elif e.kind == H3Event.STREAM_RESET:
                tok = "R" + String(Int(e.error_code))
            else:
                continue
            var prev = self.log.find(Int(e.stream_id))
            self.log[Int(e.stream_id)] = (prev.value() if prev else String("")) + tok + " "

    def of(self, sid: UInt64) -> String:
        var v = self.log.find(Int(sid))
        return v.value() if v else String("")


def test_h3_informational_then_final() raises:
    """Two 103s reach the client in order before the final head and body."""
    var t = _Script()
    var sid = t.request("GET", "/info", True)
    t.pump(20)
    assert_true(t.of(sid) == "H103</a> H103</b> H200 Dok E ", "1xx then final, got: " + t.of(sid))
    assert_true(t.server.driver.handler.info_after_final_raised, "a 1xx after the final status raises")
    assert_equal_int(len(t.server.driver.streams), 0, "stream freed")
    print("  test_h3_informational_then_final: PASS")


def test_h3_raise_before_headers() raises:
    """A raise before any head answers 500 with an empty body and FIN; an open request body also gets STOP_SENDING H3_NO_ERROR."""
    var t = _Script()
    var closed = t.request("GET", "/boom", True)
    t.to_server()
    assert_equal_int(t.stop_code(closed), -1, "a finished request is not stopped")
    t.pump(20)
    assert_true(t.of(closed) == "H500/cl0 E ", "500 then FIN, got: " + t.of(closed))
    var open = t.request("POST", "/boom", False)
    t.to_server()
    assert_equal_int(t.stop_code(open), Int(H3_NO_ERROR), "STOP_SENDING H3_NO_ERROR")
    t.pump(20)
    assert_true(t.of(open) == "H500/cl0 E ", "500 then FIN, got: " + t.of(open))
    var next = t.request("GET", "/", True)
    t.pump(20)
    assert_true(t.of(next) == "H200 Dok E ", "the connection keeps serving, got: " + t.of(next))
    assert_equal_int(t.server.driver.handler.resets, 0, "no on_reset")
    assert_equal_int(len(t.server.driver.streams), 0, "streams freed")
    print("  test_h3_raise_before_headers: PASS")


def test_h3_raise_after_headers_resets_only_that_stream() raises:
    """A raise after the head was sent resets the stream with H3_INTERNAL_ERROR both ways (no FIN), calls on_reset(local_abort) once, and spares the other stream."""
    var t = _Script()
    var late = t.request("POST", "/late", False)
    t.pump(20)
    assert_true(t.of(late) == "H200 Dpart ", "head and first chunk sent, got: " + t.of(late))
    var other = t.request("GET", "/", True)
    t.client.send_data(late, Span(_bytes("x")), False)
    t.to_server()
    assert_equal_int(t.stop_code(late), Int(H3_INTERNAL_ERROR), "STOP_SENDING H3_INTERNAL_ERROR")
    t.pump(20)
    assert_true(t.of(late) == "H200 Dpart R" + String(Int(H3_INTERNAL_ERROR)) + " ", "RESET_STREAM, got: " + t.of(late))
    assert_true(t.of(other) == "H200 Dok E ", "other stream answered, got: " + t.of(other))
    ref h = t.server.driver.handler
    assert_true(h.resets == 1 and h.reset_kind == STREAM_ERR_LOCAL_ABORT, "on_reset(local_abort) once")
    assert_equal_int(len(t.server.driver.streams), 0, "streams freed")
    print("  test_h3_raise_after_headers_resets_only_that_stream: PASS")


def test_h3_trailers_with_pseudo_header_rejected() raises:
    """A pseudo-header in request trailers is a malformed message: H3_MESSAGE_ERROR, trailers never delivered."""
    var t = _Script()
    var sid = t.request("POST", "/", False)
    t.client.send_data(sid, Span(_bytes("data")), False)
    var trailers = Headers()
    trailers.add("x-checksum", "abc")
    t.client.send_headers(sid, FieldSection(path="/smuggled", headers=trailers^), True)
    t.pump(20)
    assert_true(t.of(sid) == "R" + String(Int(H3_MESSAGE_ERROR)) + " ", "RESET_STREAM H3_MESSAGE_ERROR, got: " + t.of(sid))
    ref h = t.server.driver.handler
    assert_true(h.trailers == 0 and h.resets == 1, "the handler sees a reset, not trailers")
    assert_true(h.reset_kind == STREAM_ERR_RST_STREAM and Int(h.reset_code) == Int(H3_MESSAGE_ERROR), "reset code")
    assert_equal_int(len(t.server.driver.streams), 0, "stream freed")
    print("  test_h3_trailers_with_pseudo_header_rejected: PASS")

def main() raises:
    print("=== test_h3_e2e ===")
    test_h3_simple_get()
    test_h3_post_with_body()
    test_h3_session_get()
    test_h3_multi_request()
    test_h3_goaway()
    test_h3_drain_cap_is_observable()
    test_h3_drain_terminates()
    test_h3_frame_wire_bytes()
    test_h3_informational_then_final()
    test_h3_raise_before_headers()
    test_h3_raise_after_headers_resets_only_that_stream()
    test_h3_trailers_with_pseudo_header_rejected()
    print("All H3 E2E tests passed.")
