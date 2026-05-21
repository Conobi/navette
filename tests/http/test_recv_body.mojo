# tests/test_recv_body.mojo
#
# Unit tests for RecvBody (M2.5a §5.6).
from navette.http.handler import RecvBody, StreamError
from navette.http.body import BodyFrame
from tests._test_util import assert_true, assert_false, assert_equal_int


def test_default_watermarks_match_config() raises:
    var b = RecvBody()
    assert_equal_int(Int(b.bytes_buffered()), 0, "default.bytes_buffered")
    assert_false(b.is_end(), "default.is_end")
    assert_false(b.is_errored(), "default.is_errored")


def test_push_then_try_read_returns_data() raises:
    var b = RecvBody()
    var bytes: List[UInt8] = [UInt8(1), UInt8(2)]
    b._push(BodyFrame.data(bytes^))
    var f_opt = b.try_read()
    assert_true(Bool(f_opt), "push.has_frame")
    var f = f_opt.value().copy()
    assert_true(f.is_data(), "push.is_data")
    assert_equal_int(len(f.data()), 2, "push.len")
    assert_equal_int(Int(b.bytes_buffered()), 0, "push.drained")


def test_try_read_returns_none_when_empty_and_open() raises:
    var b = RecvBody()
    var f_opt = b.try_read()
    assert_false(Bool(f_opt), "empty.no_frame")


def test_set_end_pushes_end_frame_then_is_end_after_consumed() raises:
    var b = RecvBody()
    b._set_end()
    assert_false(b.is_end(), "set_end.before_consume")
    var f_opt = b.try_read()
    assert_true(Bool(f_opt), "set_end.has_frame")
    assert_true(f_opt.value().is_end(), "set_end.frame_is_end")
    assert_true(b.is_end(), "set_end.after_consume")
    var f2 = b.try_read()
    assert_false(Bool(f2), "set_end.no_more_frames")


def test_set_error_records_error() raises:
    var b = RecvBody()
    b._set_error(StreamError.parser(String("bad")))
    assert_true(b.is_errored(), "set_error.is_errored")
    var f_opt = b.try_read()
    assert_true(Bool(f_opt), "set_error.has_frame")
    assert_true(f_opt.value().is_error(), "set_error.frame_is_error")
    assert_true(b.is_end(), "set_error.terminal_consumed")


def test_set_end_after_set_error_is_noop() raises:
    var b = RecvBody()
    b._set_error(StreamError.parser(String("first")))
    b._set_end()
    var f_opt = b.try_read()
    assert_true(f_opt.value().is_error(), "error_wins")
    var f2 = b.try_read()
    assert_false(Bool(f2), "no_extra_frames")


def test_watermark_accounting_excludes_trailers_end_error() raises:
    var b = RecvBody()
    var bytes: List[UInt8] = [UInt8(0), UInt8(0), UInt8(0), UInt8(0)]
    b._push(BodyFrame.data(bytes^))
    assert_equal_int(Int(b.bytes_buffered()), 4, "after_data")
    b._push(BodyFrame.end())
    assert_equal_int(Int(b.bytes_buffered()), 4, "end_no_change")
    _ = b.try_read()
    assert_equal_int(Int(b.bytes_buffered()), 0, "after_drain")


def test_set_watermarks_overrides() raises:
    var b = RecvBody()
    b.set_watermarks(high=UInt(64), low=UInt(16))
    assert_equal_int(Int(b.bytes_buffered()), 0, "watermarks.no_corruption")


def main() raises:
    test_default_watermarks_match_config()
    test_push_then_try_read_returns_data()
    test_try_read_returns_none_when_empty_and_open()
    test_set_end_pushes_end_frame_then_is_end_after_consumed()
    test_set_error_records_error()
    test_set_end_after_set_error_is_noop()
    test_watermark_accounting_excludes_trailers_end_error()
    test_set_watermarks_overrides()
    print("test_recv_body: all tests passed")
