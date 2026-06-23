"""test_owned_alloc.mojo — Owned[T] RAII heap-alloc wrapper.

The foundational safety test for the memory.alloc adoption cycle: Owned[T]
must free on EVERY path, including exception unwind, without a manual dealloc.
The alloc-then-raise test compiling at all is the proof — a leaked Allocation
would be a compile error; Owned makes the free automatic on the raise path.
"""

from std.testing import assert_equal, assert_true, assert_raises

from navette.util.owned_alloc import Owned


def test_alloc_and_count() raises:
    """Basic allocation: count is preserved and storage is writable."""
    var b = Owned[UInt8](32)
    assert_equal(b.count(), 32)
    var p = b.ptr()
    for i in range(32):
        p[i] = UInt8(i)
    assert_equal(Int(p[31]), 31)
    print("PASS test_alloc_and_count")


def test_aligned_ctor() raises:
    """The explicit-alignment ctor allocates usable storage."""
    var b = Owned[UInt8](count=64, alignment=64)
    assert_equal(b.count(), 64)
    var p = b.ptr()
    p[0] = UInt8(7)
    assert_equal(Int(p[0]), 7)
    print("PASS test_aligned_ctor")


def test_move() raises:
    """Owned is move-only and transfers ownership without double-free."""
    var a = Owned[UInt64](4)
    var moved = a^
    assert_equal(moved.count(), 4)
    print("PASS test_move")


def _alloc_then_raise(trip: Bool) raises:
    """Allocate, then maybe raise — no manual dealloc; Owned must auto-free."""
    var b = Owned[UInt8](128)
    var p = b.ptr()
    p[0] = UInt8(1)
    if trip:
        raise "tripped"
    _ = b


def test_alloc_then_raise_autofrees() raises:
    """Auto-free on the raise path (compiles ⇒ leak-free by construction)."""
    with assert_raises():
        _alloc_then_raise(True)
    _alloc_then_raise(False)
    print("PASS test_alloc_then_raise_autofrees")


def main() raises:
    test_alloc_and_count()
    test_aligned_ctor()
    test_move()
    test_alloc_then_raise_autofrees()
    print("All Owned[T] tests passed.")
