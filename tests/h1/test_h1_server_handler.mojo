# tests/test_h1_server_handler.mojo
#
# Integration test for the H1HandlerServer adapter (M2.5a §8.1).
from navette.h1.handler_server import H1HandlerServer
from navette.http.handler import (
    StreamHandler,
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from navette.http.request import Request
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.http.body import BodyFrame
from std.memory import Span
from tests._test_util import assert_true


struct HelloHandler(StreamHandler):
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
        headers.set(String("content-length"), String("5"))
        resp.send_status(StatusCode(200), headers^)
        var bytes: List[UInt8] = [
            UInt8(0x68), UInt8(0x65), UInt8(0x6c), UInt8(0x6c), UInt8(0x6f),
        ]
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


def _bytes_to_string(data: List[UInt8]) -> String:
    var s = String()
    for i in range(len(data)):
        s += chr(Int(data[i]))
    return s^


def _str_to_bytes(s: String) -> List[UInt8]:
    var result = List[UInt8]()
    var bytes = s.as_bytes()
    for i in range(len(bytes)):
        result.append(bytes[i])
    return result^


def _str_contains(haystack: String, needle: String) -> Bool:
    var hb = haystack.as_bytes()
    var nb = needle.as_bytes()
    var hl = len(hb)
    var nl = len(nb)
    if nl == 0:
        return True
    if nl > hl:
        return False
    for i in range(hl - nl + 1):
        var ok = True
        for j in range(nl):
            if hb[i + j] != nb[j]:
                ok = False
                break
        if ok:
            return True
    return False


def test_h1_handler_server_serves_hello() raises:
    var server = H1HandlerServer[HelloHandler](handler=HelloHandler())
    var raw = _str_to_bytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    server.feed(Span(raw))
    var out = server.drain()
    var s = _bytes_to_string(out)
    assert_true(_str_contains(s, "HTTP/1.1 200"), "200_status_line")
    assert_true(_str_contains(s, "hello"), "body_hello")


def main() raises:
    test_h1_handler_server_serves_hello()
    print("test_h1_server_handler: all tests passed")
