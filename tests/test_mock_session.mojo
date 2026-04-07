# tests/test_mock_session.mojo
#
# Trait conformance test using the in-process MockServer/MockSession
# substrate (M2.5a §5).
from src.http.mock_session import MockServer, MockSession
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
from src.http.body import BodyFrame
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
        var headers = Headers()
        headers.set(String("content-length"), String("3"))
        resp.send_status(StatusCode(200), headers^)
        var bytes: List[UInt8] = [UInt8(0x68), UInt8(0x69), UInt8(0x21)]
        _ = resp.try_send_body(BodyFrame.data(bytes^))
        resp.end()

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


def test_mock_roundtrip_echo() raises:
    var server = MockServer[EchoHandler](handler=EchoHandler())
    var session = MockSession[EchoHandler](server=server^)
    var req = Request(method=Method.get(), target=String("/"), body=RequestBody.empty())
    var handle = session.submit(req^)
    session.run_one(handle)
    assert_true(handle.is_complete(), "complete")
    var resp = handle^.take_response()
    assert_equal_int(Int(resp.status.code()), 200, "status")


def main() raises:
    test_mock_roundtrip_echo()
    print("test_mock_session: all tests passed")
