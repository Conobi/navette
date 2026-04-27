# tests/_h3_streaming_pending.mojo
#
# PENDING — streaming tests stashed for Plan 2B (H3 streaming server).
# These tests were classified MOVE from tests/test_h3_coro_server.mojo
# (Plan 2A Task 2.2, 2026-04-27) because they exercise coroutine
# suspension/resume paths (y.yield_to_caller()) that only make sense
# for a stackful-coroutine-based handler.
#
# DO NOT register in scripts/run_tests.sh until Plan 2B lands.
# Function names use _streaming_ instead of _coro_ per Task 2.2 spec.

from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.python import Python, PythonObject

from boucle.stackful import CoroYielder

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection
from src.quic.trans_param import TransportParams, default_transport_params
from src.h3.connection import H3Connection, H3Event
from src.h3.h3_coro_server import H3CoroServer, CoroStreamCtx
from src.h3.qpack import QpackHeaderField
from src.http.handler import RecvBody, ResponseWriter, StreamError, Capabilities
from src.http.headers import Headers
from src.http.body import BodyFrame
from src.http.status import StatusCode
from tests._test_util import assert_true, assert_equal_int


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
    var server = H3CoroServer(quic=server_quic^, body_fn=_echo_body_coro)
    var client = H3Connection.client(client_quic^)

    now = _pump_coro_client(server, client, now, 50)

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

    now = _pump_coro_client(server, client, now, 30)

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
    var server = H3CoroServer(quic=server_quic^, body_fn=_trailer_check_coro, extra_data=extra)
    var client = H3Connection.client(client_quic^)

    now = _pump_coro_client(server, client, now, 50)

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

    now = _pump_coro_client(server, client, now, 30)

    var found_val = found_ptr[]
    found_ptr.destroy_pointee()
    found_ptr.free()
    assert_equal_int(found_val, 1, "trailer header x-custom-trailer not received by coroutine")
    print("  test_h3_streaming_trailers: PASS")


def test_h3_streaming_rst_stream() raises:
    """Client resets a stream → coroutine receives StreamError (signal=42)."""
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
    var server = H3CoroServer(quic=server_quic^, body_fn=_blocking_body_coro, extra_data=extra)
    var client = H3Connection.client(client_quic^)

    now = _pump_coro_client(server, client, now, 50)

    # Send POST without fin — coroutine yields waiting for body
    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "POST"))
    req_fields.append(QpackHeaderField(":path", "/"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, False)

    now = _pump_coro_client(server, client, now, 10)

    # Client resets the stream
    client.reset_stream(stream_id, UInt64(0x010c))   # H3_REQUEST_CANCELLED

    now = _pump_coro_client(server, client, now, 20)

    var signal_val = signal_ptr[]
    signal_ptr.destroy_pointee()
    signal_ptr.free()
    assert_equal_int(signal_val, 42, "coroutine did not receive stream reset error")
    print("  test_h3_streaming_rst_stream: PASS")
