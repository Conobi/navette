# tests/test_coro_client.mojo
#
# Unit tests for HttpCoroClient (M6c).

from std.memory import Span
from src.http.coro_client import HttpCoroClient
from src.http.session_slot import SessionSlot
from src.http.alt_svc import Origin, AltSvcEntry
from src.http.request import Request, RequestBody
from src.http.response import Response
from src.http.method import Method
from src.http.headers import Headers
from src.http.status import StatusCode
from src.h1.h1_session import H1Session
from src.h1.handler_server import H1HandlerServer
from src.http.handler import StreamHandler, Capabilities, RecvBody, ResponseWriter, StreamError
from tests._test_util import assert_true, assert_equal_int


struct OkHandler(StreamHandler):
    def __init__(out self):
        pass
    def __init__(out self, *, deinit take: Self):
        pass
    def on_request(
        mut self, var req: Request, mut body: RecvBody,
        mut resp: ResponseWriter, caps: Capabilities,
    ) raises:
        var h = Headers()
        h.add("content-type", "text/plain")
        h.add("alt-svc", "h3=\":443\"; ma=86400")
        resp.send_status(StatusCode(200), h^)
        resp.end()
    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass
    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass
    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass
    def on_reset(mut self, error: StreamError):
        pass


def test_coro_client_roundtrip() raises:
    """HttpCoroClient basic request/response via loopback."""
    var client = HttpCoroClient()
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    var origin = Origin(scheme="https", host="test.example", port=UInt16(443))
    client.attach_session(Origin(other=origin), slot^)

    var handle = client.get("https://test.example/hello")

    # Pump: drain client → feed server → drain server → feed client → run_one
    var server = H1HandlerServer[OkHandler](handler=OkHandler())
    var req_bytes = client.drain(Origin(other=origin))
    server.feed(Span(req_bytes))
    var resp_bytes = server.drain()
    client.feed(Span(resp_bytes), Origin(other=origin))
    client.run_one(Origin(other=origin), handle)

    assert_true(handle.is_complete(), "complete")
    var resp = handle^.take_response()
    assert_equal_int(Int(resp.status.code()), 200, "status 200")


def test_coro_client_alt_svc_caching() raises:
    """HttpCoroClient caches Alt-Svc from responses."""
    var client = HttpCoroClient()
    var origin = Origin(scheme="https", host="cached.test", port=UInt16(443))
    # Simulate a response with Alt-Svc header
    var hdrs = Headers()
    hdrs.add("alt-svc", "h3=\":443\"; ma=3600")
    var resp = Response(status=StatusCode(200), headers=hdrs^)
    client.update_alt_svc(Origin(other=origin), resp^, UInt(1000))
    # Lookup should find h3 entry
    var entries = client.lookup_alt_svc(Origin(other=origin), UInt(1500))
    assert_equal_int(len(entries), 1, "one alt-svc entry")
    assert_true(entries[0].protocol == "h3", "protocol is h3")


def test_coro_client_has_connection() raises:
    """Verify has_connection reports pool state."""
    var client = HttpCoroClient()
    var origin = Origin(scheme="https", host="pool.test", port=UInt16(443))
    assert_true(not client.has_connection(Origin(other=origin)), "empty initially")
    var session = H1Session()
    client.attach_session(Origin(other=origin), SessionSlot.from_h1(session^))
    assert_true(client.has_connection(Origin(other=origin)), "has connection after attach")


def main() raises:
    test_coro_client_roundtrip()
    test_coro_client_alt_svc_caching()
    test_coro_client_has_connection()
    print("test_coro_client: 3/3 passed")
