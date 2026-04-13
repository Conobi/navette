# tests/test_h2_coro_server.mojo
#
# Tests for H2CoroServer (M2.6 Tasks 2-3).

from std.memory import Span, UnsafePointer

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


def main() raises:
    test_single_complete_request()
    print("All H2CoroServer tests passed.")
