# tests/test_h3_sync_server.mojo
#
# Tests for H3CoroServer (Sprint 2A Path A — sync handler).
# Ports the two REWRITE-classified tests from test_h3_coro_server.mojo:
#   test_h3_sync_simple_get  (was test_h3_coro_simple_get)
#   test_h3_sync_goaway      (was test_h3_coro_goaway)
#
# Run with:
#   uv run mojo run -I . -I conformance tests/test_h3_sync_server.mojo

from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection
from src.quic.trans_param import TransportParams, default_transport_params
from src.h3.connection import H3Connection, H3Event
from src.h3.h3_sync_server import H3CoroServer, CoroStreamCtx, H3BodyFn
from src.h3.qpack import QpackHeaderField
from src.http.handler import RecvBody, ResponseWriter, StreamError, Capabilities
from src.http.headers import Headers
from src.http.body import BodyFrame
from src.http.status import StatusCode
from tests._test_util import assert_true, assert_equal_int, load_test_cert


# ── Shared loopback helpers ──────────────────────────────────────────────────


def generate_ephemeral_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
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


def _make_lib_and_configs() raises -> Tuple[UInt64, Int32, Int32]:
    """Return (lib_addr, server_config_handle, client_config_handle)."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var cert_ptr = cert_bytes.unsafe_ptr().as_any_origin()
    var key_ptr = key_bytes.unsafe_ptr().as_any_origin()
    var cert_len = Int32(len(cert_bytes))
    var key_len = Int32(len(key_bytes))
    var alpn_ptr = _heap_alloc[UInt8](2).as_any_origin()
    alpn_ptr[0] = UInt8(ord("h"))
    alpn_ptr[1] = UInt8(ord("3"))
    var alpn_len = Int32(2)
    var srv_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    _ = lib_ptr[].quic_server_config_new(cert_ptr, cert_len, key_ptr, key_len, alpn_ptr, alpn_len, Int32(0), srv_cfg_ptr)
    var srv_cfg = srv_cfg_ptr[0]
    srv_cfg_ptr.free()
    var cli_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    _ = lib_ptr[].quic_client_config_with_ca(cert_ptr, cert_len, alpn_ptr, alpn_len, cli_cfg_ptr)
    var cli_cfg = cli_cfg_ptr[0]
    cli_cfg_ptr.free()
    alpn_ptr.free()
    return (lib_addr, srv_cfg, cli_cfg)


def _pump_sync_client(
    mut server: H3CoroServer,
    mut client: H3Connection,
    mut now: UInt64,
    rounds: Int = 5,
) raises -> UInt64:
    """Exchange QUIC datagrams between H3CoroServer (sync) and client H3Connection."""
    for _ in range(rounds):
        now += UInt64(10_000)
        var s_dgs = server.drain()
        for i in range(len(s_dgs)):
            try:
                client.feed_datagram(Span(s_dgs[i]), now)
            except:
                pass
        var c_dgs = client.drain_datagrams(now)
        for i in range(len(c_dgs)):
            try:
                server.feed_datagram(Span(c_dgs[i]), now)
            except:
                pass
    return now


# ── Sync body functions ──────────────────────────────────────────────────────


fn _simple_get_body(
    ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]
) raises:
    """Respond immediately with 200 OK + 'hello' body."""
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), Headers())
    var body = List[UInt8]()
    var src = String("hello").as_bytes()
    for i in range(len(src)):
        body.append(src[i])
    _ = ctx_ptr[].resp_writer.try_send_body(BodyFrame.data(body^))
    ctx_ptr[].resp_writer.end()


fn _path_echo_body(
    ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]
) raises:
    """Respond with 200 OK and an x-path header echoing the request target.
    Used by the multi-stream test to verify each concurrent stream gets a
    response keyed to its own request rather than another stream's."""
    var hdrs = Headers()
    hdrs.add("x-path", String(ctx_ptr[].request.target))
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)
    ctx_ptr[].resp_writer.end()


fn _error_body(
    ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]
) raises:
    """Always raise — exercises the RST_STREAM-on-handler-error path."""
    raise Error("h3 handler error")


# ── Tests ────────────────────────────────────────────────────────────────────


def test_h3_sync_simple_get() raises:
    """GET / → sync handler responds immediately with 200 OK + 'hello'."""
    var configs = _make_lib_and_configs()
    var lib_addr = configs[0]
    var srv_cfg = configs[1]
    var cli_cfg = configs[2]
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(lib_addr, cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        lib_addr, srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3CoroServer(quic=server_quic^, body_fn=_simple_get_body)
    var client = H3Connection.client(client_quic^)

    # Handshake + H3 bootstrap
    now = _pump_sync_client(server, client, now, 50)

    # Send GET / with fin=True (no body)
    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "GET"))
    req_fields.append(QpackHeaderField(":path", "/"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, True)  # fin=True

    now = _pump_sync_client(server, client, now, 20)

    # Collect response events
    var got_200 = False
    var body_bytes = List[UInt8]()
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.HEADERS_RECEIVED:
            for i in range(len(e.fields)):
                if e.fields[i].name == ":status" and e.fields[i].value == "200":
                    got_200 = True
        elif e.kind == H3Event.DATA_RECEIVED:
            for i in range(len(e.data)):
                body_bytes.append(e.data[i])

    assert_true(got_200, "client did not receive 200 OK")
    var body_str = String(unsafe_from_utf8=body_bytes)
    assert_true(body_str == "hello", "response body expected 'hello', got: " + body_str)
    print("  test_h3_sync_simple_get: PASS")


def test_h3_sync_goaway() raises:
    """Server sends GOAWAY → client receives GOAWAY_RECEIVED event."""
    var configs = _make_lib_and_configs()
    var lib_addr = configs[0]
    var srv_cfg = configs[1]
    var cli_cfg = configs[2]
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(lib_addr, cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        lib_addr, srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3CoroServer(quic=server_quic^, body_fn=_simple_get_body)
    var client = H3Connection.client(client_quic^)

    now = _pump_sync_client(server, client, now, 50)

    # Server sends GOAWAY before any request
    server.send_goaway(UInt64(0))
    now = _pump_sync_client(server, client, now, 20)

    # Client should receive GOAWAY_RECEIVED event
    var got_goaway = False
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.GOAWAY_RECEIVED:
            got_goaway = True

    assert_true(got_goaway, "client did not receive GOAWAY from server")
    print("  test_h3_sync_goaway: PASS")


def test_h3_sync_multiple_streams() raises:
    """Open 3 concurrent bidi streams with distinct paths; each handler
    runs synchronously and responds with x-path: <its own target>.
    Verify every stream gets its own response — proves per-stream ctx
    isolation in the H3 sync server. Mirrors test_multiple_streams in
    test_h2_sync_server.mojo."""
    var configs = _make_lib_and_configs()
    var lib_addr = configs[0]
    var srv_cfg = configs[1]
    var cli_cfg = configs[2]
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(lib_addr, cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        lib_addr, srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3CoroServer(quic=server_quic^, body_fn=_path_echo_body)
    var client = H3Connection.client(client_quic^)

    now = _pump_sync_client(server, client, now, 50)

    # Open 3 streams concurrently with distinct paths.
    var paths = List[String]()
    paths.append(String("/alpha"))
    paths.append(String("/bravo"))
    paths.append(String("/charlie"))
    var stream_ids = List[UInt64]()
    for i in range(len(paths)):
        var sid = client.open_bidi_stream()
        stream_ids.append(sid)
        var fields = List[QpackHeaderField]()
        fields.append(QpackHeaderField(":method", "GET"))
        fields.append(QpackHeaderField(":path", paths[i]))
        fields.append(QpackHeaderField(":scheme", "https"))
        fields.append(QpackHeaderField(":authority", "localhost"))
        client.send_headers(sid, fields, True)  # fin=True (no body)

    now = _pump_sync_client(server, client, now, 30)

    # Map sid -> observed x-path
    var observed = List[String]()
    for _ in range(len(paths)):
        observed.append(String(""))

    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.HEADERS_RECEIVED:
            var got_200 = False
            var path_value = String("")
            for i in range(len(e.fields)):
                if e.fields[i].name == ":status" and e.fields[i].value == "200":
                    got_200 = True
                elif e.fields[i].name == "x-path":
                    path_value = e.fields[i].value
            if got_200:
                # Find the index of this stream id in stream_ids
                for i in range(len(stream_ids)):
                    if stream_ids[i] == e.stream_id:
                        observed[i] = path_value

    for i in range(len(paths)):
        assert_true(
            observed[i] == paths[i],
            "stream " + String(stream_ids[i])
            + " expected x-path '" + paths[i]
            + "', got '" + observed[i] + "'"
        )
    print("  test_h3_sync_multiple_streams: PASS")


def test_h3_sync_error_propagation() raises:
    """Handler raises an Error → server sends RST_STREAM and survives.
    Mirrors test_error_propagation in test_h2_sync_server.mojo."""
    var configs = _make_lib_and_configs()
    var lib_addr = configs[0]
    var srv_cfg = configs[1]
    var cli_cfg = configs[2]
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(lib_addr, cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        lib_addr, srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3CoroServer(quic=server_quic^, body_fn=_error_body)
    var client = H3Connection.client(client_quic^)

    now = _pump_sync_client(server, client, now, 50)

    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "GET"))
    req_fields.append(QpackHeaderField(":path", "/boom"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, True)

    now = _pump_sync_client(server, client, now, 30)

    var got_reset = False
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.STREAM_RESET and e.stream_id == stream_id:
            got_reset = True

    assert_true(got_reset, "client did not observe STREAM_RESET on the failed stream")
    assert_true(not server.should_close(), "server connection closed after handler error — must survive")
    print("  test_h3_sync_error_propagation: PASS")


def main() raises:
    print("=== test_h3_sync_server ===")
    test_h3_sync_simple_get()
    test_h3_sync_goaway()
    test_h3_sync_multiple_streams()
    test_h3_sync_error_propagation()
    print("All H3SyncServer tests passed.")
    print("ok")
