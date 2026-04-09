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


def main() raises:
    test_push_on_detached_body_is_noop()
    test_set_end_on_detached_body_is_noop()
    test_set_error_on_detached_body_is_noop()
    print("test_handler_try_detach: all tests passed (Task 1)")
