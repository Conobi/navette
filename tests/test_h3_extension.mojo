# tests/test_h3_extension.mojo
#
# Unit tests for H3Context and H3StreamExtension scaffolding (M2.5a §5.10).
from std.memory import Span
from mojo_net.http.h3_extension import H3Context, H3StreamExtension
from mojo_net.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from mojo_net.http.request import Request
from tests._test_util import assert_true, assert_false, assert_equal_int


def test_h3_context_starts_with_no_datagrams() raises:
    var ctx = H3Context(stream_id=UInt64(7))
    assert_equal_int(Int(ctx.stream_id()), 7, "stream_id")
    var dg = ctx.try_recv_datagram()
    assert_false(Bool(dg), "no_datagrams")


def test_try_send_datagram_returns_closed_in_v1() raises:
    var ctx = H3Context(stream_id=UInt64(1))
    var bytes: List[UInt8] = [UInt8(1)]
    var r = ctx.try_send_datagram(Span(bytes))
    assert_true(r.is_closed(), "datagram.closed_in_v1")


struct StubH3Handler(H3StreamExtension):
    var seen: Int

    def __init__(out self):
        self.seen = 0

    def __init__(out self, *, deinit take: Self):
        self.seen = take.seen

    def on_h3_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        mut h3: H3Context,
        caps: Capabilities,
    ) raises:
        self.seen += 1

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        mut h3: H3Context,
    ) raises:
        pass

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        mut h3: H3Context,
    ) raises:
        pass

    def on_send_drained(
        mut self,
        mut resp: ResponseWriter,
        mut h3: H3Context,
    ) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


def test_stub_h3_handler_compiles() raises:
    var h = StubH3Handler()
    assert_equal_int(h.seen, 0, "stub.seen")


def main() raises:
    test_h3_context_starts_with_no_datagrams()
    test_try_send_datagram_returns_closed_in_v1()
    test_stub_h3_handler_compiles()
    print("test_h3_extension: all tests passed")
