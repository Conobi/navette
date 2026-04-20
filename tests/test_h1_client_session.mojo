# tests/test_h1_client_session.mojo
#
# Loopback integration test for H1Session via H1HandlerServer (M2.5a §8.2).
from src.h1.h1_session import H1Session
from src.h1.handler_server import H1HandlerServer
from src.http.handler import (
    StreamHandler,
    Capabilities,
    DetachedBody,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from src.http.body import BodyFrame
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
        mut body: RecvBody,
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


def _bytes_to_string(data: List[UInt8]) -> String:
    """Convert a List[UInt8] to a String for assertion checking."""
    var result = String()
    for i in range(len(data)):
        result += chr(Int(data[i]))
    return result^


def test_h1_session_chunked_streaming_body() raises:
    var session = H1Session()

    # Build a POST request with a stream body.
    var hdrs = Headers()
    hdrs.add("Host", "example.com")
    var detached = DetachedBody(take_body=RecvBody())
    var req = Request(
        method=Method.post(),
        target=String("/upload"),
        headers=hdrs^,
        body=RequestBody.stream(detached^),
    )
    var handle = session.submit(req^)
    var handle_id = handle.id()

    # Feed two data chunks and an end frame.
    var hello_bytes = String("hello").as_bytes()
    var chunk1 = List[UInt8]()
    for i in range(len(hello_bytes)):
        chunk1.append(hello_bytes[i])
    session.feed_body(handle_id, BodyFrame.data(chunk1^))

    var world_bytes = String(" world").as_bytes()
    var chunk2 = List[UInt8]()
    for i in range(len(world_bytes)):
        chunk2.append(world_bytes[i])
    session.feed_body(handle_id, BodyFrame.data(chunk2^))

    session.feed_body(handle_id, BodyFrame.end())

    # Drain all output and verify chunked encoding.
    var wire = session.drain()
    var wire_str = _bytes_to_string(wire)

    # The output should contain the request line + headers + chunked body.
    # Check Transfer-Encoding: chunked header is present.
    assert_true(
        String("transfer-encoding: chunked\r\n") in wire_str,
        "chunked_header",
    )

    # Check first chunk: "5\r\nhello\r\n"
    assert_true(
        String("5\r\nhello\r\n") in wire_str,
        "chunk1",
    )

    # Check second chunk: "6\r\n world\r\n"
    assert_true(
        String("6\r\n world\r\n") in wire_str,
        "chunk2",
    )

    # Check terminal chunk: "0\r\n\r\n"
    assert_true(
        String("0\r\n\r\n") in wire_str,
        "terminal_chunk",
    )

    # Verify request line
    assert_true(
        String("POST /upload HTTP/1.1\r\n") in wire_str,
        "request_line",
    )


def main() raises:
    test_h1_session_roundtrips_via_in_memory_loopback()
    test_h1_session_chunked_streaming_body()
    print("test_h1_client_session: all tests passed")
