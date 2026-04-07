# tests/test_handler_detach.mojo
#
# Unit tests for DetachedBody + RecvBody.detach() (M2.5a §5.5).
from src.http.handler import RecvBody, DetachedBody
from src.http.body import BodyFrame
from tests._test_util import assert_true, assert_equal_int


def test_detach_moves_state_into_detached_body() raises:
    var b = RecvBody()
    var bytes: List[UInt8] = [UInt8(1), UInt8(2)]
    b._push(BodyFrame.data(bytes^))
    var d = b^.detach()
    var f_opt = d.try_read()
    assert_true(Bool(f_opt), "has_frame")
    var f = f_opt.value().copy()
    assert_true(f.is_data(), "is_data")
    assert_equal_int(len(f.data()), 2, "len")


def test_detached_body_reports_end() raises:
    var b = RecvBody()
    b._set_end()
    var d = b^.detach()
    var f_opt = d.try_read()
    assert_true(f_opt.value().is_end(), "is_end_frame")
    assert_true(d.is_end(), "is_end")


def test_detached_take_inner_returns_recv_body() raises:
    var b = RecvBody()
    b._set_end()
    var d = b^.detach()
    var inner = d^.take_inner()
    var f_opt = inner.try_read()
    assert_true(f_opt.value().is_end(), "inner_drained")


def main() raises:
    test_detach_moves_state_into_detached_body()
    test_detached_body_reports_end()
    test_detached_take_inner_returns_recv_body()
    print("test_handler_detach: all tests passed")
