# tests/test_request_body.mojo
#
# Unit tests for RequestBody (M2.5a §5.12).
from navette.http.request import RequestBody
from navette.http.handler import RecvBody, DetachedBody
from navette.http.body import BodyFrame
from tests._test_util import assert_true, assert_false, assert_equal_int


def test_buffered_factory() raises:
    var bytes: List[UInt8] = [UInt8(1), UInt8(2), UInt8(3)]
    var rb = RequestBody.buffered(bytes^)
    assert_true(rb.is_buffered(), "buffered.is_buffered")
    assert_false(rb.is_stream(), "buffered.is_stream")
    assert_false(rb.is_empty(), "buffered.is_empty")
    assert_equal_int(len(rb.bytes()), 3, "buffered.len")


def test_empty_factory() raises:
    var rb = RequestBody.empty()
    assert_true(rb.is_empty(), "empty.is_empty")
    assert_false(rb.is_buffered(), "empty.is_buffered")
    assert_false(rb.is_stream(), "empty.is_stream")


def test_stream_factory_from_detached() raises:
    var inner = RecvBody()
    inner._set_end()
    var detached = inner^.detach()
    var rb = RequestBody.stream(detached^)
    assert_true(rb.is_stream(), "stream.is_stream")
    assert_false(rb.is_buffered(), "stream.is_buffered")
    assert_false(rb.is_empty(), "stream.is_empty")


def test_take_stream_consumes() raises:
    var inner = RecvBody()
    inner._set_end()
    var detached = inner^.detach()
    var rb = RequestBody.stream(detached^)
    var d2 = rb^.take_stream()
    var f_opt = d2.try_read()
    assert_true(f_opt.value().is_end(), "take_stream.is_end")


def main() raises:
    test_buffered_factory()
    test_empty_factory()
    test_stream_factory_from_detached()
    test_take_stream_consumes()
    print("test_request_body: all tests passed")
