"""Memory-safety hardening tests.

Covers: PtrBox roundtrip + null. Swap-and-pop demux preservation and
stale-generation rejection live in tests/h3/test_conn_table.mojo.

H3UdpHandler.__del__ freeing pbuf_pool / msghdr_template / timeout_ts
is exercised implicitly by tests/test_h3_udp_server.mojo (construct +
tick + drop). The buf-ring `_acquire_buf` / `_release_buf` ledger is
unit-tested via its `debug_assert`s, which fire under ASSERT=all
whenever any test runs a real recvmsg CQE path through the server.

See specs/2026-05-18-memory-safety-hardening.md.
"""

from std.testing import assert_equal, assert_true, assert_false

from std.memory.alloc import unsafe_alloc as _heap_alloc

from navette.util.ptrbox import PtrBox


# ---------------------------------------------------------------------------
# PtrBox tests (AC1)
# ---------------------------------------------------------------------------


def test_ptrbox_roundtrip() raises:
    var p = _heap_alloc[Int](1)
    p.init_pointee_move(123)
    var box = PtrBox[Int](p)
    assert_true(box.is_some())
    assert_equal(box.ptr()[], 123)

    var box2 = PtrBox[Int](copy=box)
    assert_equal(box2.ptr()[], 123)

    var raw = box.ptr()
    raw.destroy_pointee()
    raw.free()


def test_ptrbox_null() raises:
    var box = PtrBox[Int].null()
    assert_false(box.is_some())


def main() raises:
    test_ptrbox_roundtrip()
    test_ptrbox_null()
    print("OK")
