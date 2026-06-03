"""End-to-end tests for the H3 early-data filter integration.

Covers (one representative adapter: H3HandlerServer):
  - 0-RTT POST through the adapter -> handler NOT invoked, 425 emitted
  - 0-RTT GET through the adapter -> handler invoked with caps.is_early_data=True
    and request.headers["early-data"]=="1"
  - 1-RTT POST through the adapter -> handler invoked normally, no
    Early-Data header, caps.is_early_data=False

The other two adapters (H3SyncServer, H3StreamingServer) share the
exact same dispatch shape — that shape is static-checked by the
`scripts/check_integrations.sh §3.11` regex (every adapter calls
`apply_early_data_filter`). This trade-off avoids triplicating
end-to-end tests.

Synthetic-event drive (not full QUIC handshake):
  - Build a QuicConnection.server skeleton (handshake NOT driven).
  - Pre-create the request stream by calling `_handle_stream_frame`
    with `_current_space_idx` toggled to 0-RTT or 1-RTT, so
    `Stream.is_zero_rtt` is set at insertion time.
  - Hand-construct an `H3Event.HEADERS_RECEIVED` for the same
    stream id with synthetic `:method`/`:path`/`:scheme`/`:authority`
    pseudo-headers, then invoke `H3HandlerServer._on_request` directly.
This bypasses TLS/QPACK and exercises only the adapter's filter
dispatch + handler-invocation path. Wire-level e2e lives in the
anti-replay test family; adapter-level coverage lives here.
"""

from std.collections import Optional
from std.memory import Span, UnsafePointer

from navette.h3.connection import H3Connection, H3Event
from navette.h3.error import H3_REQUEST_CANCELLED
from navette.h3.h3_handler_server import H3HandlerServer
from navette.h3.qpack import QpackHeaderField
from navette.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
    StreamHandler,
)
from navette.http.request import Request
from navette.quic.connection import QuicConnection
from navette.quic.frame import StreamFrame
from navette.quic.guard_predicates import ZERO_RTT_SPACE_IDX
from navette.quic.profile import AcceptProfile
from navette.quic.trans_param import default_transport_params
from navette.tls.config import QuicServerConfig
from navette.tls.early_data_filter import IdempotentOnlyFilter
from navette.tls.lib import TlsBackend
from tests._test_util import (
    assert_equal_int,
    assert_false,
    assert_true,
    load_test_cert,
)


# ---------------------------------------------------------------------------
# RecordingHandler — stub StreamHandler with call counter + capture
# ---------------------------------------------------------------------------


struct RecordingHandler(StreamHandler):
    """Test handler that records every `on_request` invocation.

    Captures the `early-data` header observed on the request and the
    `caps.is_early_data` flag so the test can assert both halves of the
    accept-path AC. The remaining StreamHandler callbacks
    (`on_body_available`, `on_request_end`, `on_send_drained`,
    `on_reset`) are no-ops — the synthetic-event drive feeds exactly
    one HEADERS_RECEIVED per test.
    """

    var calls: Int
    var last_early_data_header: String
    var last_caps_is_early_data: Bool

    def __init__(out self):
        """Default ctor — zero counters, empty captured header."""
        self.calls = 0
        self.last_early_data_header = String("")
        self.last_caps_is_early_data = False

    def __init__(out self, *, deinit take: Self):
        """Move-from ctor for trait-bound generic code."""
        self.calls = take.calls
        self.last_early_data_header = take.last_early_data_header^
        self.last_caps_is_early_data = take.last_caps_is_early_data

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        """Record the invocation and capture the early-data header + caps flag."""
        self.calls += 1
        self.last_early_data_header = req.headers.get(String("early-data"))
        self.last_caps_is_early_data = caps.is_early_data

    def on_body_available(
        mut self, mut body: RecvBody, mut resp: ResponseWriter
    ) raises:
        """No-op — synthetic drive sends no body frames."""
        pass

    def on_request_end(
        mut self, mut body: RecvBody, mut resp: ResponseWriter
    ) raises:
        """No-op — synthetic drive does not deliver STREAM_ENDED."""
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        """No-op — no backpressure under synthetic drive."""
        pass

    def on_reset(mut self, error: StreamError):
        """No-op — synthetic drive does not deliver STREAM_RESET."""
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_h3_event(
    stream_id: UInt64, method: String, fin: Bool
) raises -> H3Event:
    """Synthesise an `H3Event.HEADERS_RECEIVED` with the given `:method`.

    Includes the four pseudo-headers required by the adapter's QPACK
    walk (`:method`, `:scheme`, `:path`, `:authority`). No regular
    headers — the test only exercises pseudo-header dispatch.
    """
    var ev = H3Event(H3Event.HEADERS_RECEIVED)
    ev.stream_id = stream_id
    ev.fin = fin
    ev.fields.append(QpackHeaderField(String(":method"), method))
    ev.fields.append(QpackHeaderField(String(":scheme"), String("https")))
    ev.fields.append(QpackHeaderField(String(":path"), String("/")))
    ev.fields.append(QpackHeaderField(String(":authority"), String("localhost")))
    return ev^


def _make_server(
    lib: TlsBackend,
    ref cfg: QuicServerConfig,
    mut filter: IdempotentOnlyFilter,
    mut prof: AcceptProfile,
) raises -> H3HandlerServer[RecordingHandler]:
    """Build an `H3HandlerServer` with stack-rooted filter + profile pointers.

    The handshake is NOT driven; the test creates the request stream
    manually via `_force_stream_space` so the adapter's QPACK walk
    can read `Stream.is_zero_rtt` from a deterministically-tagged
    stream.

    Caller MUST keep `filter` and `prof` alive past the server's
    lifetime — they are stack-rooted UnsafePointer references.
    """
    var tp = default_transport_params()
    var dcid_a = List[UInt8]()
    var dcid_b = List[UInt8]()
    for _ in range(8):
        dcid_a.append(UInt8(0xab))
        dcid_b.append(UInt8(0xcd))
    var now = UInt64(1_000_000)
    var quic = QuicConnection.server(
        lib.shared(), cfg, tp, Span(dcid_a), Span(dcid_b), now,
    )
    var prof_ptr = Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]](
        UnsafePointer(to=prof)
    )
    var filter_ptr = Optional[
        UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]
    ](UnsafePointer(to=filter))
    return H3HandlerServer[RecordingHandler](
        quic=quic^,
        handler=RecordingHandler(),
        profile_ptr=prof_ptr,
        early_data_filter_ptr=filter_ptr,
    )


def _force_stream_in_space(
    mut server: H3HandlerServer[RecordingHandler],
    stream_id: UInt64,
    space_idx: Int,
):
    """Test-only: create the peer-initiated stream `stream_id` inside
    the connection's stream_map, with `Stream.is_zero_rtt` tagged by
    the supplied `space_idx`.

    Pass `ZERO_RTT_SPACE_IDX` to tag the stream as 0-RTT-originated;
    any other value (e.g. `2` = Application/1-RTT) leaves
    `is_zero_rtt = False`. Bookends `_current_space_idx` exactly like
    the production per-packet dispatch loop, so the
    `_handle_stream_frame` insertion path runs through its real code.
    """
    server._h3._quic._current_space_idx = space_idx
    var payload = List[UInt8]()
    payload.append(UInt8(0x00))
    var sf = StreamFrame(stream_id, UInt64(0), payload^, False)
    try:
        server._h3._quic._handle_stream_frame(sf)
    except:
        pass
    server._h3._quic._current_space_idx = -1


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_h3_handler_server_filter_fires_on_0rtt_post() raises:
    """AC `h3-handler-server-filter-fires-on-0rtt-request`.

    0-RTT POST -> handler.on_request NEVER called; the adapter
    synthesises a HEADERS frame with `:status=425` on the response
    stream (which queues a FIN); the `reject_425` profile counter
    increments by exactly one.
    """
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    var filter = IdempotentOnlyFilter()
    var prof = AcceptProfile()
    var server = _make_server(lib, cfg, filter, prof)

    var stream_id: UInt64 = 0
    _force_stream_in_space(server, stream_id, ZERO_RTT_SPACE_IDX)
    var ev = _build_h3_event(stream_id, String("POST"), True)
    server._on_request(ev, UInt64(1_000_001))

    assert_equal_int(
        server.handler.calls, 0,
        String("handler must not be invoked when 425 is emitted"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_reject_425), 1,
        String("reject_425 counter += 1"),
    )
    # FIN queued on the response stream confirms the 425 synthesis.
    var key = Int(stream_id)
    assert_true(
        key in server._h3._quic.stream_map.streams,
        String("response stream must still exist after 425"),
    )
    var send_buf_opt = server._h3._quic.stream_map.streams[key].send_buf.copy()
    assert_true(
        Bool(send_buf_opt),
        String("stream must have a send buffer for the 425 response"),
    )
    var sb = send_buf_opt.value().copy()
    # `send_headers(..., fin=True)` queues bytes + sets the `fin` flag on
    # the send buffer; `fin_offset` is only stamped once the bytes are
    # framed (drain_datagrams), which the synthetic-event drive
    # intentionally does NOT trigger. The pair "non-empty data + fin
    # queued" is the load-bearing evidence that the 425 response was
    # synthesised on this stream.
    assert_true(
        len(sb.data) > 0,
        String("response stream must have queued 425 HEADERS bytes"),
    )
    assert_true(
        sb.fin,
        String("FIN must be queued on the response stream (425 closes it)"),
    )
    # Reject path must NOT allocate a per-stream H3 context: the handler
    # was skipped, so the adapter must not have called the
    # `_streams[ev.stream_id] = _H3StreamCtx(...)` line that lives on the
    # accept path. Guards against a regression where the 425 short-circuit
    # is bolted on AFTER the per-stream-ctx allocation.
    assert_false(
        Int(ev.stream_id) in server._streams,
        String("rejected stream must not allocate _H3StreamCtx (handler skip)"),
    )
    _ = server._h3._quic.conn_handle
    _ = cfg._handle


def test_h3_handler_server_filter_reject_emits_stop_sending() raises:
    """0-RTT POST reject MUST queue a STOP_SENDING with H3_REQUEST_CANCELLED.

    The 425 short-circuits the handler at the H3 layer; without
    STOP_SENDING the peer would keep filling the request stream's
    recv buffer up to `fc_recv_limit` even though those bytes are
    dropped. Verifying the stream-local flags
    (`needs_stop_sending=True`, `stop_sending_error=0x010C`) is the
    earliest observable proof that `_quic.stop_sending` has been
    called — the frame is later marshalled into a STOP_SENDING frame
    by `drain_datagrams`, but the synthetic-event drive does not pump
    egress.
    """
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    var filter = IdempotentOnlyFilter()
    var prof = AcceptProfile()
    var server = _make_server(lib, cfg, filter, prof)

    var stream_id: UInt64 = 0
    _force_stream_in_space(server, stream_id, ZERO_RTT_SPACE_IDX)
    var ev = _build_h3_event(stream_id, String("POST"), False)
    server._on_request(ev, UInt64(1_000_001))

    var key = Int(stream_id)
    assert_true(
        key in server._h3._quic.stream_map.streams,
        String("request stream must exist after 425 reject"),
    )
    var stream = server._h3._quic.stream_map.streams[key].copy()
    assert_true(
        stream.needs_stop_sending,
        String("STOP_SENDING must be queued on the rejected stream"),
    )
    assert_equal_int(
        Int(stream.stop_sending_error), Int(H3_REQUEST_CANCELLED),
        String("STOP_SENDING error must be H3_REQUEST_CANCELLED (0x010C)"),
    )
    _ = server._h3._quic.conn_handle
    _ = cfg._handle


def test_h3_handler_server_filter_accept_injects_early_data_header() raises:
    """AC `h3-handler-server-filter-accept-injects-early-data-header`.

    0-RTT GET -> handler.on_request IS called; the request seen by the
    handler has `headers['early-data'] == '1'` AND
    `caps.is_early_data == True`; the `accept` profile counter
    increments by exactly one.
    """
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    var filter = IdempotentOnlyFilter()
    var prof = AcceptProfile()
    var server = _make_server(lib, cfg, filter, prof)

    var stream_id: UInt64 = 0
    _force_stream_in_space(server, stream_id, ZERO_RTT_SPACE_IDX)
    var ev = _build_h3_event(stream_id, String("GET"), True)
    server._on_request(ev, UInt64(1_000_001))

    assert_equal_int(
        server.handler.calls, 1,
        String("handler must be invoked once on 0-RTT accept"),
    )
    assert_true(
        server.handler.last_early_data_header == "1",
        String("Early-Data: 1 header must be visible to the handler"),
    )
    assert_true(
        server.handler.last_caps_is_early_data,
        String("caps.is_early_data must be True on 0-RTT accept"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_accept), 1,
        String("accept counter += 1"),
    )
    _ = server._h3._quic.conn_handle
    _ = cfg._handle


def test_h3_handler_server_1rtt_request_bypasses_filter() raises:
    """AC `h3-handler-server-1rtt-request-bypasses-filter`.

    1-RTT POST -> handler invoked normally; the request seen by the
    handler has NO `early-data` header (`Headers.get` returns ""); the
    `caps.is_early_data` flag is False; the `1rtt_bypassed` profile
    counter increments by exactly one. POST is intentional here — it
    exercises the bypass path on a method the filter WOULD reject if
    is_zero_rtt were True, confirming that the bypass is purely a
    function of the QUIC packet-space tag, not of the request method.
    """
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    var filter = IdempotentOnlyFilter()
    var prof = AcceptProfile()
    var server = _make_server(lib, cfg, filter, prof)

    # Application-space (1-RTT) tag -> stream's is_zero_rtt stays False.
    var APPLICATION_SPACE_IDX: Int = 2
    var stream_id: UInt64 = 0
    _force_stream_in_space(server, stream_id, APPLICATION_SPACE_IDX)
    var ev = _build_h3_event(stream_id, String("POST"), True)
    server._on_request(ev, UInt64(1_000_001))

    assert_equal_int(
        server.handler.calls, 1,
        String("handler must be invoked once on 1-RTT POST"),
    )
    assert_true(
        server.handler.last_early_data_header == "",
        String("no Early-Data header must appear on 1-RTT requests"),
    )
    assert_false(
        server.handler.last_caps_is_early_data,
        String("caps.is_early_data must be False on 1-RTT"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_1rtt_bypassed), 1,
        String("1rtt_bypassed counter += 1"),
    )
    _ = server._h3._quic.conn_handle
    _ = cfg._handle


def main() raises:
    """Driver for `scripts/run_tests.sh`: each test must be invoked here."""
    print("=== test_h3_adapter_early_data_filter ===")
    test_h3_handler_server_filter_fires_on_0rtt_post()
    print("  test_h3_handler_server_filter_fires_on_0rtt_post: PASS")
    test_h3_handler_server_filter_reject_emits_stop_sending()
    print("  test_h3_handler_server_filter_reject_emits_stop_sending: PASS")
    test_h3_handler_server_filter_accept_injects_early_data_header()
    print("  test_h3_handler_server_filter_accept_injects_early_data_header: PASS")
    test_h3_handler_server_1rtt_request_bypasses_filter()
    print("  test_h3_handler_server_1rtt_request_bypasses_filter: PASS")
    print("test_h3_adapter_early_data_filter: all tests passed")
    print("ok")
