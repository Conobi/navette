# tests/test_body_frame_v2.mojo
#
# Unit tests for the End/Error variants of BodyFrame (M2.5a §5.2).
from src.http.body import BodyFrame
from src.http.handler import StreamError, STREAM_ERR_PARSER, STREAM_ERR_PEER_CLOSED
from tests._test_util import assert_true, assert_false, assert_equal_int, assert_equal_str


def test_end_factory_and_predicate() raises:
    var f = BodyFrame.end()
    assert_true(f.is_end(), "end.is_end")
    assert_false(f.is_data(), "end.is_data")
    assert_false(f.is_trailers(), "end.is_trailers")
    assert_false(f.is_error(), "end.is_error")


def test_error_factory_and_accessor() raises:
    var f = BodyFrame.error(StreamError.parser(String("bad")))
    assert_true(f.is_error(), "error.is_error")
    assert_false(f.is_end(), "error.is_end")
    assert_equal_int(f.error().kind, STREAM_ERR_PARSER, "error.kind")
    assert_equal_str(f.error().message, String("bad"), "error.message")


def test_existing_data_still_works() raises:
    var bytes: List[UInt8] = [UInt8(1), UInt8(2), UInt8(3)]
    var f = BodyFrame.data(bytes^)
    assert_true(f.is_data(), "data.is_data")
    assert_equal_int(len(f.data()), 3, "data.len")


def test_copy_preserves_error_variant() raises:
    var f = BodyFrame.error(StreamError.peer_closed())
    var g = BodyFrame(other=f)
    assert_true(g.is_error(), "copy.is_error")
    assert_equal_int(g.error().kind, STREAM_ERR_PEER_CLOSED, "copy.kind")


def main() raises:
    test_end_factory_and_predicate()
    test_error_factory_and_accessor()
    test_existing_data_still_works()
    test_copy_preserves_error_variant()
    print("test_body_frame_v2: all tests passed")
