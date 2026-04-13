# tests/test_h2_coro_server.mojo
#
# Tests for H2CoroServer (M2.6 Tasks 2-3).

from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from boucle.stackful import CoroYielder

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
from src.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from src.http.body import BodyFrame
from src.http.headers import Headers
from src.http.status import StatusCode
from src.h2.h2_coro_server import H2CoroServer, CoroStreamCtx


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
# _echo_body — coroutine that immediately sends 200 OK with x-handler: echo
# ---------------------------------------------------------------------------


fn _echo_body(mut y: CoroYielder) raises:
    var ctx_ptr = UnsafePointer[CoroStreamCtx, MutAnyOrigin](
        unsafe_from_address=Int(y.user_data())
    )
    var hdrs = Headers()
    hdrs.add("x-handler", "echo")
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)
    ctx_ptr[].resp_writer.end()


# ---------------------------------------------------------------------------
# _read_body_then_echo — coroutine that reads the full body, then responds
# ---------------------------------------------------------------------------


fn _read_body_then_echo(mut y: CoroYielder) raises:
    """Read full body (yielding when empty), then respond with body length."""
    var ctx = UnsafePointer[CoroStreamCtx, MutAnyOrigin](
        unsafe_from_address=Int(y.user_data())
    )
    var total = 0
    while True:
        var frame = ctx[].recv_body.try_read()
        if not frame:
            y.yield_to_caller()
            continue
        var f = frame.unsafe_take()
        if f.is_data():
            total += len(f.data())
        elif f.is_end():
            break
        elif f.is_error():
            return
    var resp_headers = Headers()
    resp_headers.add("x-body-length", String(total))
    ctx[].resp_writer.send_status(StatusCode.ok(), resp_headers^)
    ctx[].resp_writer.end()


# ---------------------------------------------------------------------------
# _yield_for_external — coroutine that reads body, yields for "backend I/O",
# then reads extra_data and responds with x-signal header
# ---------------------------------------------------------------------------


fn _yield_for_external(mut y: CoroYielder) raises:
    """Read body until END_STREAM (yielding when queue empty), then yield a
    second time simulating waiting for backend I/O.  After second resume,
    read extra_data as UnsafePointer[Int], get the value, respond with
    header x-signal: <value>."""
    var ctx = UnsafePointer[CoroStreamCtx, MutAnyOrigin](
        unsafe_from_address=Int(y.user_data())
    )
    # 1. Read body until END_STREAM
    while True:
        var frame = ctx[].recv_body.try_read()
        if not frame:
            y.yield_to_caller()
            continue
        var f = frame.unsafe_take()
        if f.is_data():
            pass  # consume data
        elif f.is_end():
            break
        elif f.is_error():
            return
    # 2. Yield a second time — simulating "waiting for backend I/O"
    y.yield_to_caller()
    # 3. After second resume: read extra_data as pointer to Int
    var int_ptr = UnsafePointer[Int, MutAnyOrigin](
        unsafe_from_address=Int(ctx[].extra_data)
    )
    var value = int_ptr[]
    var resp_headers = Headers()
    resp_headers.add("x-signal", String(value))
    ctx[].resp_writer.send_status(StatusCode.ok(), resp_headers^)
    ctx[].resp_writer.end()


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


def test_body_yield() raises:
    """Create H2CoroServer with _read_body_then_echo, send POST /upload
    WITHOUT end_stream, verify NO response yet (coroutine yielded), then
    send DATA "hello world" + end_stream=True, verify response arrives
    with x-body-length header = "11"."""
    # --- Set up server + client ---
    var server = H2CoroServer(body_fn=_read_body_then_echo)
    var client = H2Connection(client_side=True)
    client.initiate_connection()

    # --- Preface exchange ---
    _do_preface(server, client)

    # --- Send HEADERS for POST /upload WITHOUT end_stream ---
    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/upload"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers^, end_stream=False)
    var req_data = client.data_to_send()

    # Feed HEADERS to server — coroutine should yield (no body yet)
    server.feed(Span(req_data))
    var server_out1 = server.drain()

    # Feed server output to client and check: NO response yet
    if len(server_out1) > 0:
        var events1 = client.receive_data(server_out1)
        for i in range(len(events1)):
            if events1[i].kind == H2_EVT_RESPONSE_RECEIVED:
                raise Error(
                    "expected NO response after HEADERS-only, but got one"
                )

    # --- Send DATA "hello world" + end_stream=True ---
    var body_str = String("hello world")
    var body_bytes = List[UInt8]()
    var sbytes = body_str.as_bytes()
    for i in range(len(sbytes)):
        body_bytes.append(sbytes[i])
    client.send_data(UInt32(1), body_bytes^, end_stream=True)
    var data_frame = client.data_to_send()

    # Feed DATA to server — coroutine should complete and send response
    server.feed(Span(data_frame))
    var server_out2 = server.drain()

    # Feed server output to client and parse events
    var events2 = client.receive_data(server_out2)

    # --- Verify ---
    var got_response = False
    var got_stream_ended = False
    var body_length_value = String("")

    for i in range(len(events2)):
        if events2[i].kind == H2_EVT_RESPONSE_RECEIVED:
            got_response = True
            for j in range(len(events2[i].headers)):
                if events2[i].headers[j].name == "x-body-length":
                    body_length_value = events2[i].headers[j].value
        elif events2[i].kind == H2_EVT_STREAM_ENDED:
            got_stream_ended = True
        elif events2[i].kind == H2_EVT_DATA_RECEIVED:
            if events2[i].stream_ended:
                got_stream_ended = True

    if not got_response:
        raise Error("expected RESPONSE_RECEIVED event")
    if body_length_value != "11":
        raise Error(
            "expected x-body-length '11', got '" + body_length_value + "'"
        )
    if not got_stream_ended:
        raise Error("expected stream_ended flag")
    print("PASS test_body_yield")


def test_resume_stream() raises:
    """Create H2CoroServer with _yield_for_external, send GET / with
    END_STREAM.  After feed+drain the coroutine has consumed the body and
    yielded for "backend I/O" — verify NO response yet.  Then call
    resume_stream(1), drain, and verify response arrives with x-signal=42."""
    # --- Set up server + client ---
    var signal_ptr = _heap_alloc[Int](1)
    signal_ptr.init_pointee_move(42)
    var extra = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(signal_ptr)
    )
    var server = H2CoroServer(body_fn=_yield_for_external, extra_data=extra)
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

    # Feed request to server — coroutine reads body (END_STREAM on HEADERS),
    # then yields for "backend I/O"
    server.feed(Span(req_data))
    var server_out1 = server.drain()

    # Verify NO response yet (coroutine is suspended waiting for resume)
    if len(server_out1) > 0:
        var events1 = client.receive_data(server_out1)
        for i in range(len(events1)):
            if events1[i].kind == H2_EVT_RESPONSE_RECEIVED:
                raise Error(
                    "expected NO response before resume_stream, but got one"
                )

    # --- Resume stream 1 (external resume) ---
    server.resume_stream(1)
    var server_out2 = server.drain()

    # Feed server output to client and parse events
    var events2 = client.receive_data(server_out2)

    # --- Verify ---
    var got_response = False
    var got_stream_ended = False
    var signal_value = String("")

    for i in range(len(events2)):
        if events2[i].kind == H2_EVT_RESPONSE_RECEIVED:
            got_response = True
            for j in range(len(events2[i].headers)):
                if events2[i].headers[j].name == "x-signal":
                    signal_value = events2[i].headers[j].value
        elif events2[i].kind == H2_EVT_STREAM_ENDED:
            got_stream_ended = True
        elif events2[i].kind == H2_EVT_DATA_RECEIVED:
            if events2[i].stream_ended:
                got_stream_ended = True

    if not got_response:
        raise Error("expected RESPONSE_RECEIVED event after resume_stream")
    if signal_value != "42":
        raise Error(
            "expected x-signal '42', got '" + signal_value + "'"
        )
    if not got_stream_ended:
        raise Error("expected stream_ended flag")
    signal_ptr.destroy_pointee()
    signal_ptr.free()
    print("PASS test_resume_stream")


def main() raises:
    test_single_complete_request()
    test_body_yield()
    test_resume_stream()
    print("All H2CoroServer tests passed.")
