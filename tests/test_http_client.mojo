# tests/test_http_client.mojo
#
# Unit tests for M6a HttpClient (pool, dispatch, convenience API).

from std.collections.optional import Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from src.http.session_slot import SessionSlot, SessionSlotPtr, SLOT_H1
from src.http.handler import Capabilities, ALPN_H1
from src.http.request import Request, RequestBody
from src.http.method import Method
from src.http.headers import Headers
from src.h1.h1_session import H1Session
from tests._test_util import assert_true, assert_equal_int


def test_session_slot_from_h1() raises:
    """SessionSlot wraps H1Session and delegates submit."""
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    assert_equal_int(Int(slot.kind), Int(SLOT_H1), "kind")
    assert_true(not slot.is_idle(), "should be active initially")
    var caps = slot.capabilities()
    assert_equal_int(caps.alpn, ALPN_H1, "alpn")


def test_session_slot_idle_tracking() raises:
    """Mark_idle / mark_active transitions."""
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    assert_true(not slot.is_idle(), "not idle initially")
    slot.mark_idle(UInt64(1000))
    assert_true(slot.is_idle(), "idle after mark")
    assert_true(slot.idle_since == UInt64(1000), "idle_since")
    slot.mark_active()
    assert_true(not slot.is_idle(), "active after mark_active")


def test_session_slot_submit_h1() raises:
    """Submit a request through SessionSlot -> H1Session."""
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    var hdrs = Headers()
    hdrs.add("Host", "example.com")
    var req = Request(
        method=Method.get(),
        target=String("/"),
        headers=hdrs^,
        body=RequestBody.empty(),
    )
    var handle = slot.submit(req^)
    assert_true(handle.id() == UInt64(1), "handle id")


def test_session_slot_ptr_round_trip() raises:
    """SessionSlotPtr stores on heap and retrieves."""
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    var ptr = _heap_alloc[SessionSlot](1).as_any_origin()
    ptr.init_pointee_move(slot^)
    var slot_ptr = SessionSlotPtr(UInt64(Int(ptr)))
    # Access through pointer
    var caps = slot_ptr.ptr()[].capabilities()
    assert_equal_int(caps.alpn, ALPN_H1, "ptr round-trip")
    # Cleanup
    slot_ptr.ptr().destroy_pointee()
    slot_ptr.ptr().free()


def main() raises:
    test_session_slot_from_h1()
    test_session_slot_idle_tracking()
    test_session_slot_submit_h1()
    test_session_slot_ptr_round_trip()
    print("test_http_client: 4/4 passed")
