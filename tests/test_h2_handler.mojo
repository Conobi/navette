# tests/test_h2_handler.mojo
#
# Tests for H2HandlerServer (M5.5 Tasks 4-5).

from std.memory import Span

from lib.http1.types import Header
from lib.http2.connection import H2Connection, H2Config
from src.http.handler import (
    StreamHandler,
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from src.http.request import Request
from src.h2.h2_handler_server import H2HandlerServer


# ---------------------------------------------------------------------------
# _DummyHandler — empty StreamHandler implementation
# ---------------------------------------------------------------------------


struct _DummyHandler(StreamHandler):

    def __init__(out self):
        pass

    def __init__(out self, *, deinit take: Self):
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

    def __init__(out self, *, deinit take: Self):
        self.got_method = take.got_method^
        self.got_target = take.got_target^
        self.request_count = take.request_count
        self.request_end_count = take.request_end_count

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


def _feed(mut target: H2Connection, data: List[UInt8]) raises -> List[UInt8]:
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
    var combined = List[UInt8]()
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
    if server.handler.got_method != "GET":
        raise Error(
            "expected method 'GET', got '" + server.handler.got_method + "'"
        )
    if server.handler.got_target != "/":
        raise Error(
            "expected target '/', got '" + server.handler.got_target + "'"
        )
    if server.handler.request_count != 1:
        raise Error(
            "expected request_count 1, got "
            + String(server.handler.request_count)
        )
    if server.handler.request_end_count != 1:
        raise Error(
            "expected request_end_count 1, got "
            + String(server.handler.request_end_count)
        )
    print("PASS test_basic_get_dispatch")


def main() raises:
    test_construct_and_drain()
    test_should_close_initially_false()
    test_basic_get_dispatch()
    print("PASS")
