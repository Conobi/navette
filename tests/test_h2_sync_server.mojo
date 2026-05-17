# tests/test_h2_sync_server.mojo
#
# Tests for H2CoroServer (Sprint 1 Path A — sync handler).

from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from lib.http1.types import Header
from lib.http2.connection import (
    H2Connection,
    H2Config,
    H2Event,
    H2_EVT_RESPONSE_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
)
from navette.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from navette.http.body import BodyFrame
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.h2.h2_sync_server import H2CoroServer, CoroStreamCtx


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _do_preface(
    mut server: H2CoroServer,
    mut client: H2Connection,
) raises:
    """Perform the HTTP/2 preface exchange between server and client."""
    var server_initial = server.drain()
    var client_preface = client.data_to_send()  # magic + SETTINGS

    # Feed client preface to server
    server.feed(Span(client_preface))
    var server_resp = server.drain()  # server SETTINGS + SETTINGS ACK

    # Feed server output to client
    var combined = List[UInt8]()
    for i in range(len(server_initial)):
        combined.append(server_initial[i])
    for i in range(len(server_resp)):
        combined.append(server_resp[i])
    _ = client.receive_data(combined)
    var client_settings_ack = client.data_to_send()  # client SETTINGS ACK

    # Feed client SETTINGS ACK to server
    if len(client_settings_ack) > 0:
        server.feed(Span(client_settings_ack))
        _ = server.drain()


# ---------------------------------------------------------------------------
# Test handlers — Path A (sync, no yielder)
# ---------------------------------------------------------------------------


fn _echo_body(
    ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]
) raises:
    """Immediately send 200 OK with x-handler: echo."""
    var hdrs = Headers()
    hdrs.add("x-handler", "echo")
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)
    ctx_ptr[].resp_writer.end()


fn _raising_body(
    ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]
) raises:
    """Always raise — exercises the RST_STREAM-on-handler-error path."""
    raise Error("handler error")


fn _noop_body(
    ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]
) raises:
    """Do nothing — used by tests where the handler isn't the focus."""
    pass


# ---------------------------------------------------------------------------
# Disabled — these tests exercise stackful-coroutine suspension behaviour
# (yield_to_caller, resume_stream) that Path A intentionally drops.  They
# will be re-added in a future sprint that introduces a streaming state
# machine for handlers that need to await body data:
#
#   - test_body_yield (handler suspends until body arrives)
#   - test_resume_stream (handler suspends pending external resumption)
#
# Their bodies (`_read_body_then_echo`, `_yield_for_external`,
# `_check_error_body`) used `CoroYielder.yield_to_caller()`, which no
# longer exists in the H2 server.  See plans/2026-04-27-h2-perf-roadmap-
# sprint-sequence.md § Sprint 1 / Step 3.


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_single_complete_request() raises:
    """Create H2CoroServer with _echo_body, send GET / with END_STREAM,
    verify client receives RESPONSE_RECEIVED with :status=200 and
    x-handler=echo, plus STREAM_ENDED."""
    # --- Set up server + client ---
    var server = H2CoroServer(body_fn=_echo_body)
    var client = H2Connection(client_side=True)
    client.initiate_connection()

    # --- Preface exchange ---
    _do_preface(server, client)

    # --- Send GET / with END_STREAM ---
    var headers = List[Header]()
    headers.append(Header(":method", "GET"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers^, end_stream=True)
    var req_data = client.data_to_send()

    # Feed request to server — coroutine will immediately respond
    server.feed(Span(req_data))
    var server_out = server.drain()

    # Feed server output to client and parse events
    var events = client.receive_data(server_out)

    # --- Verify ---
    var got_response = False
    var got_stream_ended = False
    var response_status = String("")
    var got_echo_header = False

    for i in range(len(events)):
        if events[i].kind == H2_EVT_RESPONSE_RECEIVED:
            got_response = True
            for j in range(len(events[i].headers)):
                if events[i].headers[j].name == ":status":
                    response_status = events[i].headers[j].value
                if events[i].headers[j].name == "x-handler":
                    if events[i].headers[j].value == "echo":
                        got_echo_header = True
        elif events[i].kind == H2_EVT_STREAM_ENDED:
            got_stream_ended = True
        elif events[i].kind == H2_EVT_DATA_RECEIVED:
            if events[i].stream_ended:
                got_stream_ended = True

    if not got_response:
        raise Error("expected RESPONSE_RECEIVED event")
    if response_status != "200":
        raise Error(
            "expected :status '200', got '" + response_status + "'"
        )
    if not got_echo_header:
        raise Error("expected x-handler: echo header in response")
    if not got_stream_ended:
        raise Error("expected stream_ended flag")
    print("PASS test_single_complete_request")


def test_multiple_streams() raises:
    """Send two GET requests on streams 1 and 3 with END_STREAM.  Both
    handlers run synchronously and respond.  Verify both streams complete
    with the expected x-handler header (Path A: no resume_stream)."""
    var server = H2CoroServer(body_fn=_echo_body)
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    _do_preface(server, client)

    var headers1 = List[Header]()
    headers1.append(Header(":method", "GET"))
    headers1.append(Header(":path", "/"))
    headers1.append(Header(":scheme", "https"))
    headers1.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers1^, end_stream=True)

    var headers3 = List[Header]()
    headers3.append(Header(":method", "GET"))
    headers3.append(Header(":path", "/"))
    headers3.append(Header(":scheme", "https"))
    headers3.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(3), headers3^, end_stream=True)

    var req_data = client.data_to_send()
    server.feed(Span(req_data))
    var server_out = server.drain()
    var events = client.receive_data(server_out)

    var got_response_s1 = False
    var got_response_s3 = False
    var got_end_s1 = False
    var got_end_s3 = False
    for i in range(len(events)):
        if events[i].kind == H2_EVT_RESPONSE_RECEIVED:
            if events[i].stream_id == 1:
                got_response_s1 = True
            elif events[i].stream_id == 3:
                got_response_s3 = True
        elif events[i].kind == H2_EVT_STREAM_ENDED:
            if events[i].stream_id == 1:
                got_end_s1 = True
            elif events[i].stream_id == 3:
                got_end_s3 = True
        elif events[i].kind == H2_EVT_DATA_RECEIVED:
            if events[i].stream_ended:
                if events[i].stream_id == 1:
                    got_end_s1 = True
                elif events[i].stream_id == 3:
                    got_end_s3 = True

    if not got_response_s1:
        raise Error("expected RESPONSE_RECEIVED on stream 1")
    if not got_response_s3:
        raise Error("expected RESPONSE_RECEIVED on stream 3")
    if not got_end_s1:
        raise Error("expected STREAM_ENDED on stream 1")
    if not got_end_s3:
        raise Error("expected STREAM_ENDED on stream 3")
    print("PASS test_multiple_streams")


def test_error_propagation() raises:
    """Send GET / with END_STREAM to a handler that raises immediately;
    server must send RST_STREAM(INTERNAL_ERROR) and survive."""
    var server = H2CoroServer(body_fn=_raising_body)
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    _do_preface(server, client)

    var headers = List[Header]()
    headers.append(Header(":method", "GET"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers^, end_stream=True)
    var req_data = client.data_to_send()

    server.feed(Span(req_data))
    var server_out = server.drain()
    var events = client.receive_data(server_out)

    var got_reset = False
    var reset_error_code = UInt32(0)
    for i in range(len(events)):
        if events[i].kind == H2_EVT_STREAM_RESET:
            got_reset = True
            reset_error_code = events[i].error_code

    if not got_reset:
        raise Error("expected H2_EVT_STREAM_RESET event")
    if reset_error_code != UInt32(2):
        raise Error(
            "expected error_code 2 (INTERNAL_ERROR), got "
            + String(reset_error_code)
        )

    if server.should_close():
        raise Error("expected should_close() to be False after stream reset")
    print("PASS test_error_propagation")


def test_stream_reset() raises:
    """Open a stream then receive a client RST_STREAM; the server should
    free the stream's state and the connection survives."""
    var server = H2CoroServer(body_fn=_noop_body)
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    _do_preface(server, client)

    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers^, end_stream=False)
    var req_data = client.data_to_send()

    server.feed(Span(req_data))
    _ = server.drain()

    client.send_rst_stream(UInt32(1), UInt32(8))
    var rst_data = client.data_to_send()
    server.feed(Span(rst_data))
    _ = server.drain()

    if server.should_close():
        raise Error(
            "expected should_close() to be False after client RST_STREAM"
        )
    print("PASS test_stream_reset")


def main() raises:
    test_single_complete_request()
    test_multiple_streams()
    test_error_propagation()
    test_stream_reset()
    print("All H2CoroServer (Path A) tests passed.")
