# tests/test_h1_client_session.mojo
#
# Loopback integration test for H1Session via H1HandlerServer (M2.5a §8.2).
from src.h1.h1_session import H1Session
from src.h1.handler_server import H1HandlerServer
from src.http.handler import (
    StreamHandler,
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from src.http.request import Request, RequestBody
from src.http.method import Method
from src.http.headers import Headers
from src.http.status import StatusCode
from std.memory import Span
from tests._test_util import assert_true, assert_equal_int


struct EchoHandler(StreamHandler):
    def __init__(out self):
        pass

    def __init__(out self, *, deinit take: Self):
        pass

    def on_request(
        mut self,
        var req: Request,
        var body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        resp.send_status(StatusCode(200), Headers())
        resp.end()

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


def test_h1_session_roundtrips_via_in_memory_loopback() raises:
    var server = H1HandlerServer[EchoHandler](handler=EchoHandler())
    var session = H1Session()
    var hdrs = Headers()
    hdrs.add("Host", "example.com")
    var req = Request(
        method=Method.get(),
        target=String("/"),
        headers=hdrs^,
        body=RequestBody.empty(),
    )
    var handle = session.submit(req^)

    var to_server = session.drain()
    server.feed(Span(to_server))
    var to_client = server.drain()
    session.feed(Span(to_client))
    session.run_one(handle)

    assert_true(handle.is_complete(), "complete")
    var resp = handle^.take_response()
    assert_equal_int(Int(resp.status.code()), 200, "status_200")


def main() raises:
    test_h1_session_roundtrips_via_in_memory_loopback()
    print("test_h1_client_session: all tests passed")
