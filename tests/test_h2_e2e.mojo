# tests/test_h2_e2e.mojo
#
# End-to-end integration tests: H2HandlerServer (server) <-> H2Session (client).
# Verifies the full request-response round-trip through both adapters without
# any raw H2Connection usage.  (M5.5 Task 11)

from std.memory import Span

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
from navette.http.request import Request, RequestBody
from navette.http.method import Method
from navette.http.version import Version
from navette.http.session import RequestHandle
from navette.h2.h2_handler_server import H2HandlerServer
from navette.h2.h2_session import H2Session


# ---------------------------------------------------------------------------
# _EchoHandler -- responds 200 with request body echoed back, or "ok" if
# no body was sent.
# ---------------------------------------------------------------------------


struct _EchoHandler(StreamHandler):
    var _body_buf: List[UInt8]

    def __init__(out self):
        self._body_buf = List[UInt8]()

    def __init__(out self, *, deinit take: Self):
        self._body_buf = take._body_buf^

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        # Don't respond yet -- wait for on_request_end
        pass

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        # Drain available body frames
        while True:
            var frame_opt = body.try_read()
            if not frame_opt:
                break
            var frame = frame_opt.unsafe_take()
            if frame.is_data():
                for i in range(len(frame.data())):
                    self._body_buf.append(frame.data()[i])

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        var headers = Headers()
        headers.add("content-type", "text/plain")
        resp.send_status(StatusCode.ok(), headers^)
        if len(self._body_buf) > 0:
            var echo = self._body_buf^
            self._body_buf = List[UInt8]()
            _ = resp.try_send_body(BodyFrame.data(echo^))
        else:
            var default_body = List[UInt8]()
            var s = String("ok")
            var b = s.as_bytes()
            for i in range(len(b)):
                default_body.append(b[i])
            _ = resp.try_send_body(BodyFrame.data(default_body^))
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
# Pump helper -- shuttle bytes between server and client until quiescent.
# Inlined because the generic handler type prevents a shared function.
# ---------------------------------------------------------------------------


def _pump(
    mut server: H2HandlerServer[_EchoHandler],
    mut client: H2Session,
    max_rounds: Int = 10,
) raises:
    """Shuttle bytes between server and client until neither produces output."""
    for _ in range(max_rounds):
        var c_out = client.drain()
        var s_out = server.drain()
        var progress = False
        if len(c_out) > 0:
            server.feed(Span(c_out))
            progress = True
        if len(s_out) > 0:
            client.feed(Span(s_out))
            progress = True
        if not progress:
            break


# ---------------------------------------------------------------------------
# Bootstrap helper
# ---------------------------------------------------------------------------


def _bootstrap(
    mut server: H2HandlerServer[_EchoHandler],
    mut client: H2Session,
) raises:
    """Exchange connection preface + SETTINGS + SETTINGS ACK."""
    # 1. Client drains magic + SETTINGS -> feed to server
    var client_preface = client.drain()
    server.feed(Span(client_preface))

    # 2. Server drains SETTINGS + SETTINGS ACK -> feed to client
    var server_settings = server.drain()
    client.feed(Span(server_settings))

    # 3. Client drains SETTINGS ACK -> feed to server
    var client_ack = client.drain()
    if len(client_ack) > 0:
        server.feed(Span(client_ack))

    # 4. Server may produce more output -> feed to client
    var server_ack = server.drain()
    if len(server_ack) > 0:
        client.feed(Span(server_ack))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_e2e_get_round_trip() raises:
    """GET / -> 200 with body 'ok'."""
    var server = H2HandlerServer[_EchoHandler](handler=_EchoHandler())
    var client = H2Session()

    # Bootstrap
    _bootstrap(server, client)

    # Submit GET /
    var req = Request(
        method=Method.get(),
        target="/",
        version=Version.http_2(),
    )
    var handle = client.submit(req^)

    # Pump bytes until quiescent
    _pump(server, client)

    # Deliver response to handle
    client.run_one(handle)

    # Verify
    if not handle.is_complete():
        raise Error("expected handle to be complete")

    var resp = handle^.take_response()
    if Int(resp.status.code()) != 200:
        raise Error(
            "expected status 200, got " + String(Int(resp.status.code()))
        )

    var body_str = String("")
    for i in range(len(resp.body)):
        if resp.body[i].is_data():
            for j in range(len(resp.body[i].data())):
                body_str += chr(Int(resp.body[i].data()[j]))
    if body_str != "ok":
        raise Error("expected body 'ok', got '" + body_str + "'")

    _ = server^
    _ = client^
    print("PASS test_e2e_get_round_trip")


def test_e2e_post_with_body() raises:
    """POST / with body 'hello world' -> 200 with echoed body."""
    var server = H2HandlerServer[_EchoHandler](handler=_EchoHandler())
    var client = H2Session()

    # Bootstrap
    _bootstrap(server, client)

    # Build body bytes
    var body_bytes = List[UInt8]()
    var msg = String("hello world")
    var msg_b = msg.as_bytes()
    for i in range(len(msg_b)):
        body_bytes.append(msg_b[i])

    # Submit POST with body
    var req = Request(
        method=Method.post(),
        target="/echo",
        version=Version.http_2(),
        body=RequestBody.buffered(body_bytes^),
    )
    var handle = client.submit(req^)

    # Pump bytes until quiescent
    _pump(server, client)

    # Deliver response to handle
    client.run_one(handle)

    # Verify
    if not handle.is_complete():
        raise Error("expected handle to be complete")

    var resp = handle^.take_response()
    if Int(resp.status.code()) != 200:
        raise Error(
            "expected status 200, got " + String(Int(resp.status.code()))
        )

    var body_str = String("")
    for i in range(len(resp.body)):
        if resp.body[i].is_data():
            for j in range(len(resp.body[i].data())):
                body_str += chr(Int(resp.body[i].data()[j]))
    if body_str != "hello world":
        raise Error(
            "expected body 'hello world', got '" + body_str + "'"
        )

    _ = server^
    _ = client^
    print("PASS test_e2e_post_with_body")


def test_e2e_concurrent_streams() raises:
    """Submit 3 GET requests before pumping, verify all 3 complete."""
    var server = H2HandlerServer[_EchoHandler](handler=_EchoHandler())
    var client = H2Session()

    # Bootstrap
    _bootstrap(server, client)

    # Submit 3 GET requests
    var handle1 = client.submit(
        Request(
            method=Method.get(),
            target="/a",
            version=Version.http_2(),
        )
    )
    var handle2 = client.submit(
        Request(
            method=Method.get(),
            target="/b",
            version=Version.http_2(),
        )
    )
    var handle3 = client.submit(
        Request(
            method=Method.get(),
            target="/c",
            version=Version.http_2(),
        )
    )

    # Pump bytes until quiescent
    _pump(server, client)

    # Deliver responses
    client.run_one(handle1)
    client.run_one(handle2)
    client.run_one(handle3)

    # Verify all complete
    if not handle1.is_complete():
        raise Error("handle1 not complete")
    if not handle2.is_complete():
        raise Error("handle2 not complete")
    if not handle3.is_complete():
        raise Error("handle3 not complete")

    # Verify status and body for each
    var resp1 = handle1^.take_response()
    if Int(resp1.status.code()) != 200:
        raise Error(
            "handle1: expected status 200, got "
            + String(Int(resp1.status.code()))
        )
    var body1 = String("")
    for i in range(len(resp1.body)):
        if resp1.body[i].is_data():
            for j in range(len(resp1.body[i].data())):
                body1 += chr(Int(resp1.body[i].data()[j]))
    if body1 != "ok":
        raise Error("handle1: expected body 'ok', got '" + body1 + "'")

    var resp2 = handle2^.take_response()
    if Int(resp2.status.code()) != 200:
        raise Error(
            "handle2: expected status 200, got "
            + String(Int(resp2.status.code()))
        )
    var body2 = String("")
    for i in range(len(resp2.body)):
        if resp2.body[i].is_data():
            for j in range(len(resp2.body[i].data())):
                body2 += chr(Int(resp2.body[i].data()[j]))
    if body2 != "ok":
        raise Error("handle2: expected body 'ok', got '" + body2 + "'")

    var resp3 = handle3^.take_response()
    if Int(resp3.status.code()) != 200:
        raise Error(
            "handle3: expected status 200, got "
            + String(Int(resp3.status.code()))
        )
    var body3 = String("")
    for i in range(len(resp3.body)):
        if resp3.body[i].is_data():
            for j in range(len(resp3.body[i].data())):
                body3 += chr(Int(resp3.body[i].data()[j]))
    if body3 != "ok":
        raise Error("handle3: expected body 'ok', got '" + body3 + "'")

    _ = server^
    _ = client^
    print("PASS test_e2e_concurrent_streams")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
    print("test_h2_e2e")
    test_e2e_get_round_trip()
    test_e2e_post_with_body()
    test_e2e_concurrent_streams()
    print("PASS")
