# tests/test_h2_sync_server.mojo
#
# Tests for H2CoroServer (Sprint 1 Path A — sync handler).

from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc

from oracle.http1.types import Header
from oracle.http2.connection import (
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
from tests.h2._h2_log import event_log, send_request
from tests.http._driver_script import _bytes, _link


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
    var combined = List[Byte]()
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


def _echo_body(
    ctx_ptr: Pointer[CoroStreamCtx, MutUntrackedOrigin]
) raises:
    """Immediately send 200 OK with x-handler: echo."""
    var hdrs = Headers()
    hdrs.add("x-handler", "echo")
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), hdrs^)
    ctx_ptr[].resp_writer.end()


def _script_body(ctx_ptr: Pointer[CoroStreamCtx, MutUntrackedOrigin]) raises:
    """`/info`: two 103s, then 200 "ok"; `/boom`: raise; anything else: 200 "ok"."""
    var target = String(ctx_ptr[].request.target)
    if target == "/boom":
        raise Error("boom")
    if target == "/info":
        ctx_ptr[].resp_writer.send_informational(StatusCode(103), _link("</a>"))
        ctx_ptr[].resp_writer.send_informational(StatusCode(103), _link("</b>"))
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), Headers())
    _ = ctx_ptr[].resp_writer.try_send_body(BodyFrame.data(_bytes("ok")))
    ctx_ptr[].resp_writer.end()


def _exchange(mut server: H2CoroServer, mut client: H2Connection) raises -> List[H2Event]:
    """Deliver the client's queued frames to the server, and the server's answer back."""
    server.feed(Span(client.data_to_send()))
    return client.receive_data(server.drain())


def _noop_body(
    ctx_ptr: Pointer[CoroStreamCtx, MutUntrackedOrigin]
) raises:
    """Do nothing — used by tests where the handler isn't the focus."""
    pass


# ---------------------------------------------------------------------------
# Disabled — these tests exercise stackful-coroutine suspension behaviour
# (suspend/resume of the per-stream handler) that Path A intentionally
# drops.  They will be re-added if a streaming state machine is introduced
# for handlers that need to await body data:
#
#   - test_body_yield (handler suspends until body arrives)
#   - test_resume_stream (handler suspends pending external resumption)
#
# Their bodies (`_read_body_then_echo`, `_yield_for_external`,
# `_check_error_body`) suspended the coroutine mid-request; the H2 sync
# server has no suspension point at all.  Handlers that need one belong in
# `navette/h2/h2_streaming_server.mojo`.


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
            ref hdrs = events[i].headers
            for j in range(len(hdrs)):
                if hdrs[j].name == ":status":
                    response_status = hdrs[j].value
                if hdrs[j].name == "x-handler":
                    if hdrs[j].value == "echo":
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
            var sid = events[i].stream_id
            if sid == 1:
                got_response_s1 = True
            elif sid == 3:
                got_response_s3 = True
        elif events[i].kind == H2_EVT_STREAM_ENDED:
            var sid = events[i].stream_id
            if sid == 1:
                got_end_s1 = True
            elif sid == 3:
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


def test_informational_then_final() raises:
    """Two 103s go out in order, without END_STREAM, before the final head."""
    var server = H2CoroServer(body_fn=_script_body)
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    _do_preface(server, client)
    send_request(client, 1, "GET", "/info", True)
    var log = event_log(_exchange(server, client), 1)
    if log != "H103</a> H103</b> H200 Dok D! ":
        raise Error("1xx then final, got: " + log)
    if len(server._streams) != 0:
        raise Error("stream freed")
    print("PASS test_informational_then_final")


def test_raise_answers_500() raises:
    """A raising handler gets 500 + content-length 0 + END_STREAM; an open request body is refused with RST_STREAM NO_ERROR; other streams and the connection carry on."""
    var server = H2CoroServer(body_fn=_script_body)
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    _do_preface(server, client)
    send_request(client, 1, "GET", "/boom", True)
    var log1 = event_log(_exchange(server, client), 1)
    if log1 != "H500/cl0! ":
        raise Error("500 then END_STREAM, got: " + log1)
    send_request(client, 3, "POST", "/boom", False)
    send_request(client, 5, "GET", "/", True)
    var events = _exchange(server, client)
    var log3 = event_log(events, 3)
    if log3 != "H500/cl0! R0 ":
        raise Error("500, END_STREAM, RST_STREAM NO_ERROR, got: " + log3)
    var log5 = event_log(events, 5)
    if log5 != "H200 Dok D! ":
        raise Error("other stream answered, got: " + log5)
    if len(server._streams) != 0 or server.should_close():
        raise Error("streams freed; connection open")
    print("PASS test_raise_answers_500")


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
    test_informational_then_final()
    test_raise_answers_500()
    test_stream_reset()
    print("All H2CoroServer (Path A) tests passed.")
