# tests/test_send_body.mojo
#
# Unit tests for SendBody (M2.5a §5.7).
from src.http.handler import SendBody, WriteResult
from src.http.body import BodyFrame
from tests._test_util import assert_true, assert_false, assert_equal_int


def _bytes(n: Int) -> List[UInt8]:
    var l = List[UInt8]()
    var i = 0
    while i < n:
        l.append(UInt8(0))
        i += 1
    return l^


def test_try_write_accepts_data_under_high_water() raises:
    var b = SendBody()
    var bytes: List[UInt8] = [UInt8(1), UInt8(2)]
    var r = b.try_write(BodyFrame.data(bytes^))
    assert_true(r.is_ok(), "ok")
    assert_equal_int(Int(b.bytes_buffered()), 2, "bytes")


def test_try_write_returns_would_block_above_high_water() raises:
    var b = SendBody()
    b.set_watermarks(high=UInt(4), low=UInt(2))
    var b1: List[UInt8] = [UInt8(0), UInt8(0), UInt8(0), UInt8(0)]
    _ = b.try_write(BodyFrame.data(b1^))
    var b2: List[UInt8] = [UInt8(0)]
    var r = b.try_write(BodyFrame.data(b2^))
    assert_true(r.is_would_block(), "would_block")


def test_pop_drains_and_clears_back_pressure() raises:
    var b = SendBody()
    b.set_watermarks(high=UInt(4), low=UInt(2))
    var b1: List[UInt8] = [UInt8(0), UInt8(0), UInt8(0), UInt8(0)]
    _ = b.try_write(BodyFrame.data(b1^))
    var f_opt = b._pop()
    assert_true(Bool(f_opt), "pop.has_frame")
    assert_equal_int(Int(b.bytes_buffered()), 0, "drained")


def test_end_marks_closed_and_subsequent_writes_return_closed() raises:
    var b = SendBody()
    b.end()
    var b1: List[UInt8] = [UInt8(1)]
    var r = b.try_write(BodyFrame.data(b1^))
    assert_true(r.is_closed(), "closed_after_end")


def test_abort_marks_closed() raises:
    var b = SendBody()
    b.abort(UInt32(7))
    var b1: List[UInt8] = [UInt8(1)]
    var r = b.try_write(BodyFrame.data(b1^))
    assert_true(r.is_closed(), "closed_after_abort")


def test_double_end_raises() raises:
    var b = SendBody()
    b.end()
    var raised = False
    try:
        b.end()
    except:
        raised = True
    assert_true(raised, "double_end_raises")


def main() raises:
    test_try_write_accepts_data_under_high_water()
    test_try_write_returns_would_block_above_high_water()
    test_pop_drains_and_clears_back_pressure()
    test_end_marks_closed_and_subsequent_writes_return_closed()
    test_abort_marks_closed()
    test_double_end_raises()
    print("test_send_body: all tests passed")
