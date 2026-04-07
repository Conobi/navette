# tests/test_handler_lifecycle.mojo
#
# Verifies that StreamHandler can be implemented by a concrete struct,
# i.e. the trait surface compiles end-to-end (M2.5a §5.9).
from src.http.handler import (
    StreamHandler,
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from src.http.request import Request
from src.http.headers import Headers
from src.http.status import StatusCode
from tests._test_util import assert_equal_int


struct CountingHandler(StreamHandler):
    var on_request_count: Int
    var on_body_available_count: Int
    var on_request_end_count: Int
    var on_send_drained_count: Int
    var on_reset_count: Int

    def __init__(out self):
        self.on_request_count = 0
        self.on_body_available_count = 0
        self.on_request_end_count = 0
        self.on_send_drained_count = 0
        self.on_reset_count = 0

    def __init__(out self, *, deinit take: Self):
        self.on_request_count = take.on_request_count
        self.on_body_available_count = take.on_body_available_count
        self.on_request_end_count = take.on_request_end_count
        self.on_send_drained_count = take.on_send_drained_count
        self.on_reset_count = take.on_reset_count

    def on_request(
        mut self,
        var req: Request,
        var body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        self.on_request_count += 1
        resp.send_status(StatusCode(200), Headers())

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        self.on_body_available_count += 1

    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        self.on_request_end_count += 1
        resp.end()

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        self.on_send_drained_count += 1

    def on_reset(mut self, error: StreamError):
        self.on_reset_count += 1


def test_handler_compiles_and_implements_trait() raises:
    var h = CountingHandler()
    assert_equal_int(h.on_request_count, 0, "initial.on_request_count")


def main() raises:
    test_handler_compiles_and_implements_trait()
    print("test_handler_lifecycle: all tests passed")
