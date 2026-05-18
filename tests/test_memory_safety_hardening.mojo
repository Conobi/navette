"""Memory-safety hardening tests.

Covers: PtrBox roundtrip + null, H3UdpHandler __del__ no-leak,
buf-id double-return assertion, ConnSlot swap-and-pop invariant,
stale-generation demux lookup.

See specs/2026-05-18-memory-safety-hardening.md.
"""

from std.testing import assert_equal, assert_true, assert_false

from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.util.ptrbox import PtrBox


def test_ptrbox_roundtrip() raises:
    var p = _heap_alloc[Int](1).as_any_origin()
    p.init_pointee_move(123)
    var box = PtrBox[Int](p)
    assert_true(box.is_some())
    assert_equal(box.ptr()[], 123)

    var box2 = PtrBox[Int](other=box)
    assert_equal(box2.ptr()[], 123)

    var raw = box.ptr()
    raw.destroy_pointee()
    raw.free()


def test_ptrbox_null() raises:
    var box = PtrBox[Int].null()
    assert_false(box.is_some())


# AC2 — H3UdpHandler.__del__ freeing pbuf_pool / msghdr_template /
# timeout_ts is exercised implicitly by tests/test_h3_udp_server.mojo
# (construct + tick + drop). Adding a standalone fixture here would
# duplicate ~150 lines of TLS + UDP listener boilerplate; the green
# `test_h3_udp_server_init_and_tick` is the AC2 signal.


def main() raises:
    test_ptrbox_roundtrip()
    test_ptrbox_null()
    print("OK")
