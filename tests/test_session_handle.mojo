# tests/test_session_handle.mojo
#
# Unit tests for RequestHandle and Session trait shape (M2.5a §5.11).
from std.collections.deque import Deque
from mojo_net.http.session import RequestHandle, Session
from mojo_net.http.handler import RecvBody, StreamError, Capabilities
from mojo_net.http.response import Response
from mojo_net.http.status import StatusCode
from mojo_net.http.headers import Headers
from mojo_net.http.request import Request
from mojo_net.http.body import BodyFrame
from tests._test_util import assert_true, assert_false, assert_equal_int


def test_pending_handle_is_not_complete() raises:
    var h = RequestHandle(id=UInt64(1))
    assert_false(h.is_complete(), "pending.not_complete")
    assert_false(h.has_headers(), "pending.no_headers")
    assert_false(h.is_errored(), "pending.not_errored")
    assert_equal_int(Int(h.id()), 1, "pending.id")


def test_runtime_can_attach_response_and_handle_reports_headers() raises:
    var h = RequestHandle(id=UInt64(2))
    h._set_response(Response(status=StatusCode(200), headers=Headers()))
    assert_true(h.has_headers(), "after_set.has_headers")
    var r_opt = h.try_take_response()
    assert_true(Bool(r_opt), "took_response")


def test_take_body_after_headers() raises:
    var h = RequestHandle(id=UInt64(3))
    h._set_response(Response(status=StatusCode(200), headers=Headers()))
    h._set_recv_body(RecvBody())
    var b = h.take_body()
    assert_equal_int(Int(b.bytes_buffered()), 0, "body.empty")


def test_handle_error_state() raises:
    var h = RequestHandle(id=UInt64(4))
    h._set_error(StreamError.peer_closed())
    assert_true(h.is_errored(), "errored")
    assert_true(h.is_complete(), "errored_is_complete")


struct StubSession(Session):
    var caps: Capabilities

    def __init__(out self):
        self.caps = Capabilities.for_h1()

    def __init__(out self, *, deinit take: Self):
        self.caps = take.caps^

    def submit(mut self, var req: Request) raises -> RequestHandle:
        return RequestHandle(id=UInt64(0))

    def run_until(mut self, mut handle_ids: Deque[UInt64]) raises:
        pass

    def run_one(mut self, mut handle: RequestHandle) raises:
        pass

    def capabilities(self) -> Capabilities:
        return Capabilities(other=self.caps)

    def alpn(self) -> Int:
        return self.caps.alpn

    def close(deinit self) raises:
        pass

    def feed_body(mut self, handle_id: UInt64, var frame: BodyFrame) raises:
        pass


def test_stub_session_compiles() raises:
    var s = StubSession()
    assert_equal_int(s.alpn(), 0, "stub.alpn_h1")


def main() raises:
    test_pending_handle_is_not_complete()
    test_runtime_can_attach_response_and_handle_reports_headers()
    test_take_body_after_headers()
    test_handle_error_state()
    test_stub_session_compiles()
    print("test_session_handle: all tests passed")
