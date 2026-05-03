# tests/test_h3_streaming_server.mojo
#
# Tests for H3StreamingServer (Plan 2B — stackful coroutine streaming).
# Ported from tests/_h3_streaming_pending.mojo (stashed at e775866).
#
# API changes vs. stash:
#   - Handlers use boucle CoroBody signature: fn(mut CoroYielder) raises -> None
#   - ctx accessed via yld.user_data().bitcast[H3StreamingCtx, MutAnyOrigin]()
#   - yield_to_caller() (not .suspend())
#   - raise Error("...") (not raise StreamError(...))
#   - write_chunk / finish helpers (not resp_writer.write_body)
#   - Server type is H3StreamingServer (not H3CoroServer)
#
# Run with:
#   uv run mojo run -I . -I conformance tests/test_h3_streaming_server.mojo

from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.python import Python, PythonObject

from boucle.stackful import CoroYielder

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection
from src.quic.trans_param import TransportParams, default_transport_params
from src.h3.connection import H3Connection, H3Event
from src.h3.h3_streaming_server import (
    H3StreamingServer,
    H3StreamingCtx,
    H3StreamingHandlerFn,
    next_chunk,
    write_chunk,
    finish,
    cancelled,
)
from src.h3.qpack import QpackHeaderField
from src.http.handler import RecvBody, ResponseWriter, StreamError, Capabilities
from src.http.headers import Headers
from src.http.body import BodyFrame
from src.http.status import StatusCode
from tests._test_util import assert_true, assert_equal_int


# ── Shared loopback helpers ──────────────────────────────────────────────────


def py_bytes_to_mojo(raw: PythonObject) raises -> List[UInt8]:
    var builtins = Python.import_module("builtins")
    var result = List[UInt8]()
    for i in range(Int(py=builtins.len(raw))):
        result.append(UInt8(Int(py=raw[i])))
    return result^


def generate_ephemeral_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    var ec_mod = Python.import_module("cryptography.hazmat.primitives.asymmetric.ec")
    var x509_mod = Python.import_module("cryptography.x509")
    var oid_mod = Python.import_module("cryptography.x509.oid")
    var ser_mod = Python.import_module("cryptography.hazmat.primitives.serialization")
    var hash_mod = Python.import_module("cryptography.hazmat.primitives.hashes")
    var dt_mod = Python.import_module("datetime")
    var builtins = Python.import_module("builtins")
    var py_key = ec_mod.generate_private_key(ec_mod.SECP256R1())
    var name_attrs = builtins.list()
    name_attrs.append(x509_mod.NameAttribute(oid_mod.NameOID.COMMON_NAME, "localhost"))
    var subject = x509_mod.Name(name_attrs)
    var san_list = builtins.list()
    san_list.append(x509_mod.DNSName("localhost"))
    var py_cert = (
        x509_mod.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(py_key.public_key())
        .serial_number(x509_mod.random_serial_number())
        .not_valid_before(dt_mod.datetime(2024, 1, 1))
        .not_valid_after(dt_mod.datetime(2034, 1, 1))
        .add_extension(
            x509_mod.SubjectAlternativeName(san_list),
            critical=False,
        )
        .sign(py_key, hash_mod.SHA256())
    )
    var cert_bytes = py_bytes_to_mojo(py_cert.public_bytes(ser_mod.Encoding.PEM))
    var key_bytes = py_bytes_to_mojo(
        py_key.private_bytes(ser_mod.Encoding.PEM, ser_mod.PrivateFormat.PKCS8, ser_mod.NoEncryption())
    )
    return (cert_bytes^, key_bytes^)


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


def _pump_streaming_client(
    mut server: H3StreamingServer,
    mut client: H3Connection,
    mut now: UInt64,
    rounds: Int = 5,
) raises -> UInt64:
    """Exchange QUIC datagrams between H3StreamingServer and client H3Connection."""
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


# ── Streaming handler bodies ─────────────────────────────────────────────────
#
# Each handler uses the CoroBody shape: fn(mut CoroYielder) raises -> None
# (must be `fn`, not `def`, to match the CoroBody function-pointer type)
# ctx is accessed via yld.user_data().bitcast[H3StreamingCtx]().as_any_origin()


fn _echo_body_streaming(mut yld: CoroYielder) raises:
    """POST handler: reads all body chunks, responds with 200 + x-body-length header."""
    var ctx_ptr = yld.user_data().bitcast[H3StreamingCtx]().as_any_origin()

    # Accumulate all body bytes
    var total_len = Int(0)
    while True:
        var chunk_opt = next_chunk(ctx_ptr, yld)
        if not chunk_opt:
            break
        var chunk = chunk_opt.unsafe_take()
        if chunk.is_data():
            total_len += len(chunk.data())

    # Send response headers
    var hdrs = Headers()
    hdrs.add("x-body-length", String(total_len))
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)

    # Empty body
    var empty = List[UInt8]()
    write_chunk(ctx_ptr, yld, empty^)
    finish(ctx_ptr, yld)


fn _trailer_check_streaming(mut yld: CoroYielder) raises:
    """POST with trailers: reads body + trailer, sets found_ptr[]=1 if trailer seen."""
    var ctx_ptr = yld.user_data().bitcast[H3StreamingCtx]().as_any_origin()
    var found_ptr = ctx_ptr[].extra_data.bitcast[Int]().as_any_origin()

    # Consume body and trailers
    while True:
        var chunk_opt = next_chunk(ctx_ptr, yld)
        if not chunk_opt:
            break
        var chunk = chunk_opt.unsafe_take()
        if chunk.is_trailers():
            var trailer_hdrs = chunk.trailers().copy()
            for i in range(len(trailer_hdrs)):
                if trailer_hdrs.name_at(i) == "x-custom-trailer":
                    found_ptr[0] = Int(1)

    # Send minimal 200 response
    var hdrs = Headers()
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)
    var empty = List[UInt8]()
    write_chunk(ctx_ptr, yld, empty^)
    finish(ctx_ptr, yld)


fn _multi_chunk_concat_body(mut yld: CoroYielder) raises:
    """POST handler: yield several times to let multiple DATA frames queue
    into body_frame_ring before draining, then read chunks in arrival
    order and concatenate into extra_data (max 64 bytes).

    The pre-drain yields are what cause ≥2 frames to coexist in the ring
    at the moment next_chunk pops the first one. Without that, the
    adapter delivers one frame at a time and a LIFO pop hides itself."""
    var ctx_ptr = yld.user_data().bitcast[H3StreamingCtx]().as_any_origin()
    var sink_ptr = ctx_ptr[].extra_data.bitcast[UInt8]().as_any_origin()
    var written = Int(0)
    # Yield several times before reading so the adapter can deliver
    # multiple DATA events into body_frame_ring while we're suspended.
    yld.yield_to_caller()
    yld.yield_to_caller()
    yld.yield_to_caller()
    while True:
        var chunk_opt = next_chunk(ctx_ptr, yld)
        if not chunk_opt:
            break
        var chunk = chunk_opt.unsafe_take()
        if chunk.is_data():
            var data = chunk.data().copy()
            for i in range(len(data)):
                if written < 64:
                    sink_ptr[written] = data[i]
                    written += 1
    var hdrs = Headers()
    hdrs.add("x-chunks-len", String(written))
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)
    var empty = List[UInt8]()
    write_chunk(ctx_ptr, yld, empty^)
    finish(ctx_ptr, yld)


fn _blocking_body_streaming(mut yld: CoroYielder) raises:
    """POST handler that suspends in next_chunk waiting for body.
    On cancellation (H3StreamCancelled), writes signal=42 to extra_data."""
    var ctx_ptr = yld.user_data().bitcast[H3StreamingCtx]().as_any_origin()
    var signal_ptr = ctx_ptr[].extra_data.bitcast[Int]().as_any_origin()

    try:
        # This will suspend, then raise H3StreamCancelled when reset arrives
        var chunk_opt = next_chunk(ctx_ptr, yld)
        # If we somehow got a chunk (shouldn't happen in this test), just end
        var hdrs = Headers()
        ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)
        finish(ctx_ptr, yld)
    except e:
        # Cancellation path: write signal value 42
        signal_ptr[0] = Int(42)


# ── Tests ────────────────────────────────────────────────────────────────────


def test_h3_streaming_post_with_body() raises:
    """POST /upload with body 'hello world' → server echoes body length 11."""
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
    var server = H3StreamingServer(quic=server_quic^, handler_fn=_echo_body_streaming)
    var client = H3Connection.client(client_quic^)

    now = _pump_streaming_client(server, client, now, 50)

    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "POST"))
    req_fields.append(QpackHeaderField(":path", "/upload"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, False)  # no fin yet

    var body_data = List[UInt8]()
    var src = String("hello world").as_bytes()
    for i in range(len(src)):
        body_data.append(src[i])
    client.send_data(stream_id, body_data^, True)  # fin=True with body

    now = _pump_streaming_client(server, client, now, 30)

    var got_200 = False
    var got_body_length = String("")
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.HEADERS_RECEIVED:
            for i in range(len(e.fields)):
                if e.fields[i].name == ":status" and e.fields[i].value == "200":
                    got_200 = True
                elif e.fields[i].name == "x-body-length":
                    got_body_length = e.fields[i].value

    assert_true(got_200, "did not receive 200 OK")
    assert_true(got_body_length == "11", "expected body length 11, got: " + got_body_length)
    print("  test_h3_streaming_post_with_body: PASS")


def test_h3_streaming_trailers() raises:
    """POST with trailers → coroutine reads trailer header x-custom-trailer."""
    var found_ptr = _heap_alloc[Int](1).as_any_origin()
    found_ptr.init_pointee_move(Int(0))
    var extra = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(found_ptr)
    )

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
    var server = H3StreamingServer(quic=server_quic^, handler_fn=_trailer_check_streaming, extra_data=extra)
    var client = H3Connection.client(client_quic^)

    now = _pump_streaming_client(server, client, now, 50)

    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "POST"))
    req_fields.append(QpackHeaderField(":path", "/"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, False)

    var body_data = List[UInt8]()
    body_data.append(UInt8(65))  # 'A'
    client.send_data(stream_id, body_data^, False)

    # Send trailers (second HEADERS frame, fin=True)
    var trailer_fields = List[QpackHeaderField]()
    trailer_fields.append(QpackHeaderField("x-custom-trailer", "test"))
    client.send_headers(stream_id, trailer_fields, True)

    now = _pump_streaming_client(server, client, now, 30)

    var found_val = found_ptr[]
    found_ptr.destroy_pointee()
    found_ptr.free()
    assert_equal_int(found_val, 1, "trailer header x-custom-trailer not received by coroutine")
    print("  test_h3_streaming_trailers: PASS")


def test_h3_streaming_rst_stream() raises:
    """Client resets a stream → coroutine receives H3StreamCancelled, sets signal=42."""
    var signal_ptr = _heap_alloc[Int](1).as_any_origin()
    signal_ptr.init_pointee_move(Int(0))
    var extra = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(signal_ptr)
    )

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
    var server = H3StreamingServer(quic=server_quic^, handler_fn=_blocking_body_streaming, extra_data=extra)
    var client = H3Connection.client(client_quic^)

    now = _pump_streaming_client(server, client, now, 50)

    # Send POST without fin — coroutine yields waiting for body
    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "POST"))
    req_fields.append(QpackHeaderField(":path", "/"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, False)

    now = _pump_streaming_client(server, client, now, 10)

    # Client resets the stream
    client.reset_stream(stream_id, UInt64(0x010c))   # H3_REQUEST_CANCELLED

    now = _pump_streaming_client(server, client, now, 20)

    var signal_val = signal_ptr[]
    signal_ptr.destroy_pointee()
    signal_ptr.free()
    assert_equal_int(signal_val, 42, "coroutine did not receive stream reset error")
    print("  test_h3_streaming_rst_stream: PASS")


def test_h3_streaming_cancel_via_rst_stream() raises:
    """Cancellation path: server sets ctx.cancelled=True directly, handler unwinds.

    This test verifies the cancellation unwind path end-to-end:
    1. Server + client QUIC pair (loopback).
    2. Client opens stream, sends POST HEADERS (no body) — handler suspends
       in next_chunk().
    3. Client sends RESET_STREAM, which the server processes in _on_stream_reset:
       sets ctx.cancelled=True, resumes the coroutine once, and then pops +
       frees the stream.
    4. The handler catches the H3StreamCancelled error raised by next_chunk and
       writes signal=99 to extra_data.
    5. Assert: stream is cleaned up (server._streams has zero entries) and
       signal == 99.
    """
    var signal_ptr = _heap_alloc[Int](1).as_any_origin()
    signal_ptr.init_pointee_move(Int(0))
    var extra = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(signal_ptr)
    )

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

    # Use a dedicated cancellation handler that writes signal=99
    var server = H3StreamingServer(quic=server_quic^, handler_fn=_cancel_signal_handler, extra_data=extra)
    var client = H3Connection.client(client_quic^)

    now = _pump_streaming_client(server, client, now, 50)

    # Open stream; POST without body — handler will suspend waiting for next_chunk
    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "POST"))
    req_fields.append(QpackHeaderField(":path", "/stream"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, False)

    # Pump enough to ensure the handler has started and suspended
    now = _pump_streaming_client(server, client, now, 15)

    # Client resets the stream — triggers _on_stream_reset on server side
    client.reset_stream(stream_id, UInt64(0x010c))

    # Pump to deliver reset to server
    now = _pump_streaming_client(server, client, now, 20)

    var signal_val = signal_ptr[]
    signal_ptr.destroy_pointee()
    signal_ptr.free()

    # Handler should have caught H3StreamCancelled and written 99
    assert_equal_int(signal_val, 99, "cancellation handler did not write signal=99; got: " + String(signal_val))
    print("  test_h3_streaming_cancel_via_rst_stream: PASS")


fn _cancel_signal_handler(mut yld: CoroYielder) raises:
    """Streaming handler for cancel test. Writes 99 to extra_data on cancellation."""
    var ctx_ptr = yld.user_data().bitcast[H3StreamingCtx]().as_any_origin()
    var signal_ptr = ctx_ptr[].extra_data.bitcast[Int]().as_any_origin()

    try:
        # Will suspend here, then raise H3StreamCancelled when reset arrives
        _ = next_chunk(ctx_ptr, yld)
        # Unexpected: body arrived instead of cancellation
        var hdrs = Headers()
        ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)
        finish(ctx_ptr, yld)
    except e:
        # Cancellation path — write signal 99
        signal_ptr[0] = Int(99)


def test_h3_streaming_multi_chunk_body_fifo_order() raises:
    """Regression test: 3 separate DATA frames must be delivered to
    next_chunk in arrival order (FIFO), not reverse order (LIFO).

    Caught a real bug where body_frame_ring.pop() (default = pop last)
    paired with append() to deliver multi-chunk POST bodies in REVERSE
    order — silent data corruption."""
    var sink_ptr = _heap_alloc[UInt8](64).as_any_origin()
    for i in range(64):
        sink_ptr[i] = UInt8(0)
    var extra = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(sink_ptr)
    )

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
    var server = H3StreamingServer(quic=server_quic^, handler_fn=_multi_chunk_concat_body, extra_data=extra)
    var client = H3Connection.client(client_quic^)

    now = _pump_streaming_client(server, client, now, 50)

    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "POST"))
    req_fields.append(QpackHeaderField(":path", "/multi"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, False)

    # Send 3 distinct body chunks via 3 separate DATA frames, all queued
    # before draining to the server so multiple frames coexist in the
    # body_frame_ring when the handler runs next_chunk. Coupled with the
    # pre-drain yields in the handler, this exposes any LIFO pop bug.
    var c1 = List[UInt8]()
    c1.append(UInt8(ord("A"))); c1.append(UInt8(ord("A"))); c1.append(UInt8(ord("A")))
    client.send_data(stream_id, c1^, False)
    var c2 = List[UInt8]()
    c2.append(UInt8(ord("B"))); c2.append(UInt8(ord("B"))); c2.append(UInt8(ord("B")))
    client.send_data(stream_id, c2^, False)
    var c3 = List[UInt8]()
    c3.append(UInt8(ord("C"))); c3.append(UInt8(ord("C"))); c3.append(UInt8(ord("C")))
    client.send_data(stream_id, c3^, True)  # fin
    now = _pump_streaming_client(server, client, now, 30)

    # Read sink and free
    var observed = List[UInt8]()
    for i in range(9):
        observed.append(sink_ptr[i])
    sink_ptr.free()

    var observed_str = String(unsafe_from_utf8=observed)
    assert_true(
        observed_str == "AAABBBCCC",
        "expected FIFO order 'AAABBBCCC', got: '" + observed_str + "'"
        " — body chunk ring is delivering in reverse order"
    )
    print("  test_h3_streaming_multi_chunk_body_fifo_order: PASS")


def main() raises:
    print("=== test_h3_streaming_server ===")
    test_h3_streaming_post_with_body()
    test_h3_streaming_trailers()
    test_h3_streaming_rst_stream()
    test_h3_streaming_cancel_via_rst_stream()
    test_h3_streaming_multi_chunk_body_fifo_order()
    print("All H3StreamingServer tests passed.")
    print("ok")
