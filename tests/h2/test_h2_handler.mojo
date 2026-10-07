# tests/test_h2_handler.mojo
#
# Tests for H2HandlerServer (M5.5 Tasks 4-7).

from std.collections import Span

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
    StreamHandler,
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from navette.http.body import BodyFrame
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.http.request import Request
from navette.h2.h2_handler_server import H2HandlerServer
from navette.http.handler import STREAM_ERR_LOCAL_ABORT, STREAM_ERR_RST_STREAM
from tests.http._driver_script import ScriptHandler, _bytes


# ---------------------------------------------------------------------------
# _DummyHandler — empty StreamHandler implementation
# ---------------------------------------------------------------------------


struct _DummyHandler(StreamHandler):

    def __init__(out self):
        pass

    def __init__(out self, *, deinit move: Self):
        pass

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        pass

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_send_drained(
        mut self,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_reset(
        mut self,
        error: StreamError,
    ):
        pass


# ---------------------------------------------------------------------------
# _RecordingHandler — records on_request calls
# ---------------------------------------------------------------------------


struct _RecordingHandler(StreamHandler):
    var got_method: String
    var got_target: String
    var request_count: Int
    var request_end_count: Int

    def __init__(out self):
        self.got_method = String("")
        self.got_target = String("")
        self.request_count = 0
        self.request_end_count = 0

    def __init__(out self, *, deinit move: Self):
        self.got_method = move.got_method^
        self.got_target = move.got_target^
        self.request_count = move.request_count
        self.request_end_count = move.request_end_count

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        self.got_method = String(req.method)
        self.got_target = req.target
        self.request_count += 1

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        self.request_end_count += 1

    def on_send_drained(
        mut self,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_reset(
        mut self,
        error: StreamError,
    ):
        pass


# ---------------------------------------------------------------------------
# _BodyRecordingHandler — records on_request AND body data
# ---------------------------------------------------------------------------


struct _BodyRecordingHandler(StreamHandler):
    var got_method: String
    var got_target: String
    var request_count: Int
    var request_end_count: Int
    var body_available_count: Int
    var body_data: String
    var got_trailers: Bool

    def __init__(out self):
        self.got_method = String("")
        self.got_target = String("")
        self.request_count = 0
        self.request_end_count = 0
        self.body_available_count = 0
        self.body_data = String("")
        self.got_trailers = False

    def __init__(out self, *, deinit move: Self):
        self.got_method = move.got_method^
        self.got_target = move.got_target^
        self.request_count = move.request_count
        self.request_end_count = move.request_end_count
        self.body_available_count = move.body_available_count
        self.body_data = move.body_data^
        self.got_trailers = move.got_trailers

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        self.got_method = String(req.method)
        self.got_target = req.target
        self.request_count += 1

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        self.body_available_count += 1
        # Drain all available frames
        while True:
            var maybe_frame = body.try_read()
            if not maybe_frame:
                break
            var frame = maybe_frame.unsafe_take()
            if frame.is_data():
                for i in range(len(frame.data())):
                    self.body_data += chr(Int(frame.data()[i]))
            if frame.is_trailers():
                self.got_trailers = True

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        self.request_end_count += 1

    def on_send_drained(
        mut self,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_reset(
        mut self,
        error: StreamError,
    ):
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_construct_and_drain() raises:
    """Construct H2HandlerServer, drain initial output (server SETTINGS
    preface).  Verify it's non-empty."""
    var server = H2HandlerServer[_DummyHandler](handler=_DummyHandler())
    var initial = server.drain()
    if len(initial) == 0:
        raise Error("expected non-empty initial output (server SETTINGS preface)")
    # A SETTINGS frame is at least 9 bytes (frame header) + payload.
    if len(initial) < 9:
        raise Error(
            "initial output too short for a SETTINGS frame: "
            + String(len(initial))
            + " bytes"
        )
    print("PASS test_construct_and_drain")


def test_should_close_initially_false() raises:
    """A freshly constructed server should not be closed."""
    var server = H2HandlerServer[_DummyHandler](handler=_DummyHandler())
    _ = server.drain()
    if server.should_close():
        raise Error("expected should_close() == False on a fresh connection")
    print("PASS test_should_close_initially_false")


def _feed(mut target: H2Connection, data: List[Byte]) raises -> List[Byte]:
    """Feed data into a connection, return its data_to_send()."""
    _ = target.receive_data(data)
    return target.data_to_send()


def test_basic_get_dispatch() raises:
    """Send a GET / request from a client H2Connection and verify the
    server handler receives method=GET, target=/."""
    # --- Set up server ---
    var server = H2HandlerServer[_RecordingHandler](
        handler=_RecordingHandler()
    )
    var server_initial = server.drain()

    # --- Set up client ---
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()  # magic + SETTINGS

    # --- Preface exchange ---
    # 1. Feed client preface (magic + SETTINGS) to server
    server.feed(Span(client_preface))
    var server_resp = server.drain()  # server SETTINGS + SETTINGS ACK

    # 2. Feed server's initial output + response to client
    #    (server_initial = server SETTINGS, server_resp = SETTINGS ACK for client)
    var combined = List[Byte]()
    for i in range(len(server_initial)):
        combined.append(server_initial[i])
    for i in range(len(server_resp)):
        combined.append(server_resp[i])
    _ = client.receive_data(combined)
    var client_settings_ack = client.data_to_send()  # client SETTINGS ACK

    # 3. Feed client SETTINGS ACK to server
    if len(client_settings_ack) > 0:
        server.feed(Span(client_settings_ack))
        _ = server.drain()

    # --- Send GET / ---
    var headers = List[Header]()
    headers.append(Header(":method", "GET"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers^, end_stream=True)
    var req_data = client.data_to_send()

    # Feed to server
    server.feed(Span(req_data))
    _ = server.drain()

    # --- Verify ---
    if server.driver.handler.got_method != "GET":
        raise Error(
            "expected method 'GET', got '" + server.driver.handler.got_method + "'"
        )
    if server.driver.handler.got_target != "/":
        raise Error(
            "expected target '/', got '" + server.driver.handler.got_target + "'"
        )
    if server.driver.handler.request_count != 1:
        raise Error(
            "expected request_count 1, got "
            + String(server.driver.handler.request_count)
        )
    if server.driver.handler.request_end_count != 1:
        raise Error(
            "expected request_end_count 1, got "
            + String(server.driver.handler.request_end_count)
        )
    print("PASS test_basic_get_dispatch")


def _do_preface_exchange(
    mut server: H2HandlerServer[_BodyRecordingHandler],
    mut client: H2Connection,
) raises:
    """Perform the HTTP/2 preface exchange between server and client."""
    var server_initial = server.drain()
    var client_preface = client.data_to_send()  # magic + SETTINGS

    # Feed client preface to server
    server.feed(Span(client_preface))
    var server_resp = server.drain()

    # Feed server output to client
    var combined = List[Byte]()
    for i in range(len(server_initial)):
        combined.append(server_initial[i])
    for i in range(len(server_resp)):
        combined.append(server_resp[i])
    _ = client.receive_data(combined)
    var client_settings_ack = client.data_to_send()

    # Feed client SETTINGS ACK to server
    if len(client_settings_ack) > 0:
        server.feed(Span(client_settings_ack))
        _ = server.drain()


def test_post_with_body() raises:
    """Send a POST with body data from client and verify handler receives
    the method and body content."""
    # --- Set up server + client ---
    var server = H2HandlerServer[_BodyRecordingHandler](
        handler=_BodyRecordingHandler()
    )
    var client = H2Connection(client_side=True)
    client.initiate_connection()

    # --- Preface exchange ---
    _do_preface_exchange(server, client)

    # --- Send POST / with headers (no END_STREAM) ---
    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/upload"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers^, end_stream=False)
    var headers_data = client.data_to_send()

    # Feed HEADERS to server
    server.feed(Span(headers_data))
    _ = server.drain()

    # --- Send DATA with END_STREAM ---
    var body_bytes = List[Byte]()
    var hello = String("hello")
    for i in range(len(hello.as_bytes())):
        body_bytes.append(hello.as_bytes()[i])
    client.send_data(UInt32(1), body_bytes, end_stream=True)
    var data_frame = client.data_to_send()

    # Feed DATA to server
    server.feed(Span(data_frame))
    _ = server.drain()

    # --- Verify ---
    if server.driver.handler.got_method != "POST":
        raise Error(
            "expected method 'POST', got '" + server.driver.handler.got_method + "'"
        )
    if server.driver.handler.got_target != "/upload":
        raise Error(
            "expected target '/upload', got '" + server.driver.handler.got_target + "'"
        )
    if server.driver.handler.request_count != 1:
        raise Error(
            "expected request_count 1, got "
            + String(server.driver.handler.request_count)
        )
    if server.driver.handler.body_available_count < 1:
        raise Error(
            "expected body_available_count >= 1, got "
            + String(server.driver.handler.body_available_count)
        )
    if server.driver.handler.body_data != "hello":
        raise Error(
            "expected body_data 'hello', got '" + server.driver.handler.body_data + "'"
        )
    if server.driver.handler.request_end_count != 1:
        raise Error(
            "expected request_end_count 1, got "
            + String(server.driver.handler.request_end_count)
        )
    print("PASS test_post_with_body")


def test_trailers() raises:
    """Send HEADERS + DATA + trailer HEADERS and verify handler receives
    trailers."""
    # --- Set up server + client ---
    var server = H2HandlerServer[_BodyRecordingHandler](
        handler=_BodyRecordingHandler()
    )
    var client = H2Connection(client_side=True)
    client.initiate_connection()

    # --- Preface exchange ---
    _do_preface_exchange(server, client)

    # --- Send HEADERS (no END_STREAM) ---
    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/trailer-test"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers^, end_stream=False)
    var headers_data = client.data_to_send()
    server.feed(Span(headers_data))
    _ = server.drain()

    # --- Send DATA (no END_STREAM) ---
    var body_bytes = List[Byte]()
    var body_str = String("data")
    for i in range(len(body_str.as_bytes())):
        body_bytes.append(body_str.as_bytes()[i])
    client.send_data(UInt32(1), body_bytes, end_stream=False)
    var data_frame = client.data_to_send()
    server.feed(Span(data_frame))
    _ = server.drain()

    # --- Send trailer HEADERS (with END_STREAM) ---
    var trailers = List[Header]()
    trailers.append(Header("x-checksum", "abc123"))
    client.send_headers(UInt32(1), trailers^, end_stream=True)
    var trailer_frame = client.data_to_send()
    server.feed(Span(trailer_frame))
    _ = server.drain()

    # --- Verify ---
    if server.driver.handler.body_data != "data":
        raise Error(
            "expected body_data 'data', got '" + server.driver.handler.body_data + "'"
        )
    if not server.driver.handler.got_trailers:
        raise Error("expected handler to receive trailers")
    if server.driver.handler.request_end_count != 1:
        raise Error(
            "expected request_end_count 1, got "
            + String(server.driver.handler.request_end_count)
        )
    print("PASS test_trailers")


# ---------------------------------------------------------------------------
# _RespondingHandler — sends a 200 OK response with body "ok"
# ---------------------------------------------------------------------------


struct _RespondingHandler(StreamHandler):
    var request_count: Int
    var request_end_count: Int

    def __init__(out self):
        self.request_count = 0
        self.request_end_count = 0

    def __init__(out self, *, deinit move: Self):
        self.request_count = move.request_count
        self.request_end_count = move.request_end_count

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        self.request_count += 1
        resp.send_status(StatusCode.ok(), Headers())

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        self.request_end_count += 1
        # Send body data and end
        var body_bytes = List[Byte]()
        var msg = String("ok")
        for i in range(len(msg.as_bytes())):
            body_bytes.append(msg.as_bytes()[i])
        _ = resp.try_send_body(BodyFrame.data(body_bytes^))
        resp.end()

    def on_send_drained(
        mut self,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_reset(
        mut self,
        error: StreamError,
    ):
        pass


# ---------------------------------------------------------------------------
# _ResetRecordingHandler — records on_reset calls
# ---------------------------------------------------------------------------


struct _ResetRecordingHandler(StreamHandler):
    var request_count: Int
    var reset_count: Int
    var reset_code: UInt32

    def __init__(out self):
        self.request_count = 0
        self.reset_count = 0
        self.reset_code = UInt32(0)

    def __init__(out self, *, deinit move: Self):
        self.request_count = move.request_count
        self.reset_count = move.reset_count
        self.reset_code = move.reset_code

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        self.request_count += 1

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_send_drained(
        mut self,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_reset(
        mut self,
        error: StreamError,
    ):
        self.reset_count += 1
        self.reset_code = error.code


# ---------------------------------------------------------------------------
# Preface exchange helpers (generic over handler)
# ---------------------------------------------------------------------------


def _do_preface_exchange_responding(
    mut server: H2HandlerServer[_RespondingHandler],
    mut client: H2Connection,
) raises:
    """Perform the HTTP/2 preface exchange between server and client."""
    var server_initial = server.drain()
    var client_preface = client.data_to_send()

    server.feed(Span(client_preface))
    var server_resp = server.drain()

    var combined = List[Byte]()
    for i in range(len(server_initial)):
        combined.append(server_initial[i])
    for i in range(len(server_resp)):
        combined.append(server_resp[i])
    _ = client.receive_data(combined)
    var client_settings_ack = client.data_to_send()

    if len(client_settings_ack) > 0:
        server.feed(Span(client_settings_ack))
        _ = server.drain()


def _do_preface_exchange_reset(
    mut server: H2HandlerServer[_ResetRecordingHandler],
    mut client: H2Connection,
) raises:
    """Perform the HTTP/2 preface exchange between server and client."""
    var server_initial = server.drain()
    var client_preface = client.data_to_send()

    server.feed(Span(client_preface))
    var server_resp = server.drain()

    var combined = List[Byte]()
    for i in range(len(server_initial)):
        combined.append(server_initial[i])
    for i in range(len(server_resp)):
        combined.append(server_resp[i])
    _ = client.receive_data(combined)
    var client_settings_ack = client.data_to_send()

    if len(client_settings_ack) > 0:
        server.feed(Span(client_settings_ack))
        _ = server.drain()


# ---------------------------------------------------------------------------
# New tests (Task 7)
# ---------------------------------------------------------------------------


def test_response_round_trip() raises:
    """Feed a GET request to server, handler sends 200 + body 'ok' + END.
    Drain server output. Parse with client H2Connection. Verify
    ResponseReceived with :status 200, DataReceived with body, StreamEnded."""
    # --- Set up server + client ---
    var server = H2HandlerServer[_RespondingHandler](
        handler=_RespondingHandler()
    )
    var client = H2Connection(client_side=True)
    client.initiate_connection()

    # --- Preface exchange ---
    _do_preface_exchange_responding(server, client)

    # --- Send GET / with END_STREAM ---
    var headers = List[Header]()
    headers.append(Header(":method", "GET"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers^, end_stream=True)
    var req_data = client.data_to_send()

    # Feed request to server — handler will send_status + body + end
    server.feed(Span(req_data))
    var server_out = server.drain()

    # Feed server output to client and parse events
    var events = client.receive_data(server_out)

    # Verify: we expect RESPONSE_RECEIVED, DATA_RECEIVED (with body),
    # and stream_ended flag set on the final event.
    var got_response = False
    var got_data = False
    var got_stream_ended = False
    var response_status = String("")
    var received_data = String("")

    for i in range(len(events)):
        if events[i].kind == H2_EVT_RESPONSE_RECEIVED:
            got_response = True
            # Extract :status from headers
            ref hdrs = events[i].headers
            for j in range(len(hdrs)):
                if hdrs[j].name == ":status":
                    response_status = hdrs[j].value
        elif events[i].kind == H2_EVT_DATA_RECEIVED:
            got_data = True
            for j in range(len(events[i].data)):
                received_data += chr(Int(events[i].data[j]))
            if events[i].stream_ended:
                got_stream_ended = True
        elif events[i].kind == H2_EVT_STREAM_ENDED:
            got_stream_ended = True

    if not got_response:
        raise Error("expected RESPONSE_RECEIVED event")
    if response_status != "200":
        raise Error(
            "expected :status '200', got '" + response_status + "'"
        )
    if not got_data:
        raise Error("expected DATA_RECEIVED event")
    if received_data != "ok":
        raise Error(
            "expected body 'ok', got '" + received_data + "'"
        )
    if not got_stream_ended:
        raise Error("expected stream_ended flag")
    print("PASS test_response_round_trip")


def test_stream_reset() raises:
    """Feed a GET request (HEADERS with END_STREAM), then feed a RST_STREAM
    frame. Verify handler.on_reset was called."""
    # --- Set up server + client ---
    var server = H2HandlerServer[_ResetRecordingHandler](
        handler=_ResetRecordingHandler()
    )
    var client = H2Connection(client_side=True)
    client.initiate_connection()

    # --- Preface exchange ---
    _do_preface_exchange_reset(server, client)

    # --- Send GET / with END_STREAM ---
    var headers = List[Header]()
    headers.append(Header(":method", "GET"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(1), headers^, end_stream=True)
    var req_data = client.data_to_send()

    # Feed request to server
    server.feed(Span(req_data))
    _ = server.drain()

    # Verify request was received
    if server.driver.handler.request_count != 1:
        raise Error(
            "expected request_count 1, got "
            + String(server.driver.handler.request_count)
        )

    # --- Send RST_STREAM (CANCEL = 8) ---
    client.send_rst_stream(UInt32(1), UInt32(8))
    var rst_data = client.data_to_send()

    # Feed RST to server
    server.feed(Span(rst_data))
    _ = server.drain()

    # --- Verify ---
    if server.driver.handler.reset_count != 1:
        raise Error(
            "expected reset_count 1, got "
            + String(server.driver.handler.reset_count)
        )
    if server.driver.handler.reset_code != UInt32(8):
        raise Error(
            "expected reset_code 8, got "
            + String(server.driver.handler.reset_code)
        )
    print("PASS test_stream_reset")



# ---------------------------------------------------------------------------
# Shared driver: 1xx, the handler-failure policy, malformed trailers
# ---------------------------------------------------------------------------


def _script_pair(mut client: H2Connection) raises -> H2HandlerServer[ScriptHandler]:
    """A ScriptHandler server with the preface exchanged against `client`."""
    var server = H2HandlerServer[ScriptHandler](handler=ScriptHandler())
    client.initiate_connection()
    var server_initial = server.drain()
    server.feed(Span(client.data_to_send()))
    server_initial.extend(Span(server.drain()))
    _ = client.receive_data(server_initial)
    server.feed(Span(client.data_to_send()))
    _ = server.drain()
    return server^


def _send_req(mut client: H2Connection, sid: Int, method: String, path: String, end: Bool) raises:
    var headers = List[Header]()
    headers.append(Header(":method", method))
    headers.append(Header(":path", path))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(sid), headers^, end_stream=end)


def _exchange(mut server: H2HandlerServer[ScriptHandler], mut client: H2Connection) raises -> List[H2Event]:
    """Deliver the client's queued frames to the server, and the server's answer back."""
    server.feed(Span(client.data_to_send()))
    return client.receive_data(server.drain())


def _status(evt: H2Event) -> String:
    for ref h in evt.headers:
        if h.name == ":status":
            return h.value
    return ""


def _header(evt: H2Event, name: String) -> String:
    for ref h in evt.headers:
        if h.name == name:
            return h.value
    return ""


def _log(events: List[H2Event], sid: Int) -> String:
    """One token per event on `sid`: H<status>[!] (! = END_STREAM), D<bytes>[!], E (ended), R<code>."""
    var out = String("")
    for ref e in events:
        if Int(e.stream_id) != sid:
            continue
        if e.kind == H2_EVT_RESPONSE_RECEIVED:
            out += "H" + _status(e) + ("!" if e.stream_ended else "") + " "
        elif e.kind == H2_EVT_DATA_RECEIVED:
            out += "D" + String(unsafe_from_utf8=e.data.copy()) + ("!" if e.stream_ended else "") + " "
        elif e.kind == H2_EVT_STREAM_ENDED:
            out += "E "
        elif e.kind == H2_EVT_STREAM_RESET:
            out += "R" + String(Int(e.error_code)) + " "
    return out


def test_informational_then_final() raises:
    """Two 103s go out in order, without END_STREAM, before the final head; a 1xx after it raises and sends nothing."""
    var client = H2Connection(client_side=True)
    var server = _script_pair(client)
    _send_req(client, 1, "GET", "/info", True)
    var events = _exchange(server, client)
    var log = _log(events, 1)
    if log != "H103 H103 H200 Dok D! ":
        raise Error("1xx then final, got: " + log)
    var links = String("")
    for ref e in events:
        if e.kind == H2_EVT_RESPONSE_RECEIVED:
            links += _header(e, "link")
    if links != "</a></b>":
        raise Error("1xx order, got links: " + links)
    if not server.driver.handler.info_after_final_raised:
        raise Error("send_informational after send_status must raise")
    if len(server.driver.streams) != 0:
        raise Error("stream freed")
    print("PASS test_informational_then_final")


def test_raise_before_headers_body_closed() raises:
    """A raise before any head answers 500 with an empty body and END_STREAM; no reset, no on_reset."""
    var client = H2Connection(client_side=True)
    var server = _script_pair(client)
    _send_req(client, 1, "GET", "/boom", True)
    var events = _exchange(server, client)
    var log = _log(events, 1)
    if log != "H500! ":
        raise Error("500 then END_STREAM, got: " + log)
    for ref e in events:
        if e.kind == H2_EVT_RESPONSE_RECEIVED and _header(e, "content-length") != "0":
            raise Error("content-length: 0 expected")
    if server.driver.handler.resets != 0 or len(server.driver.streams) != 0:
        raise Error("no on_reset, stream freed")
    print("PASS test_raise_before_headers_body_closed")


def test_raise_before_headers_body_open() raises:
    """With the request body still open the 500 is followed by RST_STREAM NO_ERROR; the connection keeps serving."""
    var client = H2Connection(client_side=True)
    var server = _script_pair(client)
    _send_req(client, 1, "POST", "/boom", False)
    var log = _log(_exchange(server, client), 1)
    if log != "H500! R0 ":
        raise Error("500, END_STREAM, RST_STREAM NO_ERROR, got: " + log)
    _send_req(client, 3, "GET", "/", True)
    var log3 = _log(_exchange(server, client), 3)
    if log3 != "H200 Dok D! ":
        raise Error("next stream answered, got: " + log3)
    if server.driver.handler.resets != 0 or server.should_close():
        raise Error("no on_reset; connection open")
    print("PASS test_raise_before_headers_body_open")


def test_raise_after_headers_resets_only_that_stream() raises:
    """A raise after the head was sent resets the stream with INTERNAL_ERROR (no END_STREAM), calls on_reset(local_abort) once, and spares the other stream."""
    var client = H2Connection(client_side=True)
    var server = _script_pair(client)
    _send_req(client, 1, "POST", "/late", False)
    var log = _log(_exchange(server, client), 1)
    if log != "H200 Dpart ":
        raise Error("head and first chunk sent, got: " + log)
    _send_req(client, 3, "GET", "/", True)
    client.send_data(UInt32(1), _bytes("x"), end_stream=False)
    var events = _exchange(server, client)
    var log1 = _log(events, 1)
    if log1 != "R2 ":
        raise Error("RST_STREAM INTERNAL_ERROR only, got: " + log1)
    var log3 = _log(events, 3)
    if log3 != "H200 Dok D! ":
        raise Error("other stream answered, got: " + log3)
    ref h = server.driver.handler
    if h.resets != 1 or h.reset_kind != STREAM_ERR_LOCAL_ABORT:
        raise Error("on_reset(local_abort) once, got " + String(h.resets) + " kind " + String(h.reset_kind))
    if len(server.driver.streams) != 0 or server.should_close():
        raise Error("both streams freed; connection open")
    print("PASS test_raise_after_headers_resets_only_that_stream")


def test_trailers_with_pseudo_header_rejected() raises:
    """A pseudo-header in request trailers is a malformed message: stream PROTOCOL_ERROR, trailers never delivered."""
    var client = H2Connection(client_side=True)
    var server = _script_pair(client)
    _send_req(client, 1, "POST", "/", False)
    client.send_data(UInt32(1), _bytes("data"), end_stream=False)
    var trailers = List[Header]()
    trailers.append(Header(":path", "/smuggled"))
    trailers.append(Header("x-checksum", "abc"))
    client.send_headers(UInt32(1), trailers^, end_stream=True)
    var log = _log(_exchange(server, client), 1)
    if log != "R1 ":
        raise Error("RST_STREAM PROTOCOL_ERROR, got: " + log)
    ref h = server.driver.handler
    if h.trailers != 0 or h.resets != 1 or h.reset_kind != STREAM_ERR_RST_STREAM or h.reset_code != 1:
        raise Error("handler sees a reset, not trailers")
    if len(server.driver.streams) != 0 or server.should_close():
        raise Error("stream freed; connection open")
    print("PASS test_trailers_with_pseudo_header_rejected")

def main() raises:
    test_construct_and_drain()
    test_should_close_initially_false()
    test_basic_get_dispatch()
    test_post_with_body()
    test_trailers()
    test_response_round_trip()
    test_stream_reset()
    test_informational_then_final()
    test_raise_before_headers_body_closed()
    test_raise_before_headers_body_open()
    test_raise_after_headers_resets_only_that_stream()
    test_trailers_with_pseudo_header_rejected()
    print("PASS")
