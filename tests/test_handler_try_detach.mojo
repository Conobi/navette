# tests/test_handler_try_detach.mojo
#
# Tests for RecvBody._BODY_DETACHED tombstone behavior.
from src.http.handler import RecvBody, DetachedBody, StreamError
from src.http.body import BodyFrame
from tests._test_util import assert_true, assert_equal_int


def test_push_on_detached_body_is_noop() raises:
    """A body in _BODY_DETACHED state silently drops pushes."""
    var b = RecvBody()
    # Manually set state to detached (constant = 3)
    b._state = 3
    var bytes: List[UInt8] = [UInt8(1), UInt8(2)]
    b._push(BodyFrame.data(bytes^))
    assert_equal_int(Int(b.bytes_buffered()), 0, "bytes_buffered after push on detached")
    assert_equal_int(len(b._frames), 0, "frames after push on detached")


def test_set_end_on_detached_body_is_noop() raises:
    """_set_end on a detached body is a no-op."""
    var b = RecvBody()
    b._state = 3
    b._set_end()
    assert_equal_int(len(b._frames), 0, "frames after _set_end on detached")


def test_set_error_on_detached_body_is_noop() raises:
    """_set_error on a detached body is a no-op."""
    var b = RecvBody()
    b._state = 3
    b._set_error(StreamError.peer_closed())
    assert_equal_int(len(b._frames), 0, "frames after _set_error on detached")


def test_try_detach_on_open_body_returns_some() raises:
    """Try_detach on an open body swaps frames into DetachedBody."""
    var b = RecvBody()
    var bytes: List[UInt8] = [UInt8(1), UInt8(2)]
    b._push(BodyFrame.data(bytes^))
    var bytes2: List[UInt8] = [UInt8(3)]
    b._push(BodyFrame.data(bytes2^))
    var opt = b.try_detach()
    assert_true(Bool(opt), "try_detach returned Some")
    # Tombstone: original body is now detached
    assert_equal_int(b._state, 3, "tombstone state is _BODY_DETACHED")
    assert_equal_int(Int(b.bytes_buffered()), 0, "tombstone bytes_buffered")
    assert_equal_int(len(b._frames), 0, "tombstone frames empty")
    # Detached body has the original frames
    var d = opt.unsafe_take()
    var f1 = d.try_read()
    assert_true(Bool(f1), "d has frame 1")
    assert_true(f1.value().is_data(), "frame 1 is data")
    assert_equal_int(len(f1.value().data()), 2, "frame 1 len")
    var f2 = d.try_read()
    assert_true(Bool(f2), "d has frame 2")
    assert_true(f2.value().is_data(), "frame 2 is data")


def test_try_detach_on_ended_body_returns_none() raises:
    """Try_detach on an ended body returns None."""
    var b = RecvBody()
    b._set_end()
    var opt = b.try_detach()
    assert_true(not Bool(opt), "try_detach on ended body returns None")


def test_try_detach_on_errored_body_returns_none() raises:
    """Try_detach on an errored body returns None."""
    var b = RecvBody()
    b._set_error(StreamError.peer_closed())
    var opt = b.try_detach()
    assert_true(not Bool(opt), "try_detach on errored body returns None")


def test_try_detach_on_already_detached_returns_none() raises:
    """Try_detach on an already-detached tombstone returns None."""
    var b = RecvBody()
    var bytes3: List[UInt8] = [UInt8(1)]
    b._push(BodyFrame.data(bytes3^))
    var opt1 = b.try_detach()
    assert_true(Bool(opt1), "first try_detach succeeds")
    _ = opt1.unsafe_take()
    var opt2 = b.try_detach()
    assert_true(not Bool(opt2), "second try_detach returns None")


def test_tombstone_drops_pushes_after_try_detach() raises:
    """After try_detach, pushes to the tombstone body are silently dropped."""
    var b = RecvBody()
    _ = b.try_detach()
    var bytes: List[UInt8] = [UInt8(9)]
    b._push(BodyFrame.data(bytes^))
    assert_equal_int(Int(b.bytes_buffered()), 0, "tombstone ignores pushes")


def main() raises:
    test_push_on_detached_body_is_noop()
    test_set_end_on_detached_body_is_noop()
    test_set_error_on_detached_body_is_noop()
    test_try_detach_on_open_body_returns_some()
    test_try_detach_on_ended_body_returns_none()
    test_try_detach_on_errored_body_returns_none()
    test_try_detach_on_already_detached_returns_none()
    test_tombstone_drops_pushes_after_try_detach()
    print("test_handler_try_detach: all tests passed")
