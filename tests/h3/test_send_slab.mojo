"""Unit tests for SendSlabPool.

Verifies acquire/release lifecycle, exhaustion semantics, and buffer
pointer layout for the fixed-size slab pool used by proactor sendmsg.
"""

from std.memory import UnsafePointer

from navette.h3.send_slab import SendSlab, SendSlabPool


def test_acquire_release():
    """Acquire a slot, verify in_flight=1, release, verify in_flight=0."""
    var pool = SendSlabPool(capacity=4)
    pool.wire_completions()

    var idx = pool.acquire()
    debug_assert(idx >= 0, "acquire must return a valid slot index")
    debug_assert(pool.in_flight == 1, "in_flight must be 1 after one acquire")

    pool.release(idx)
    debug_assert(pool.in_flight == 0, "in_flight must be 0 after release")

    pool.teardown()
    print("PASS test_acquire_release")


def test_exhaustion():
    """Acquire all slots, verify next acquire returns -1, release one,
    verify acquire succeeds again."""
    var pool = SendSlabPool(capacity=3)
    pool.wire_completions()

    var indices = List[Int]()
    for _ in range(3):
        var idx = pool.acquire()
        debug_assert(idx >= 0, "acquire must succeed while pool has free slots")
        indices.append(idx)

    debug_assert(pool.in_flight == 3, "in_flight must equal capacity after full drain")
    debug_assert(not pool.has_available(), "has_available must be False when exhausted")

    var exhausted = pool.acquire()
    debug_assert(exhausted == -1, "acquire must return -1 when pool is exhausted")

    # Release one slot and re-acquire.
    pool.release(indices[1])
    debug_assert(pool.in_flight == 2, "in_flight must be 2 after releasing one")
    debug_assert(pool.has_available(), "has_available must be True after release")

    var reclaimed = pool.acquire()
    debug_assert(reclaimed >= 0, "acquire must succeed after release")
    debug_assert(pool.in_flight == 3, "in_flight must be 3 after re-acquire")

    # Clean up: release all.
    pool.release(indices[0])
    pool.release(indices[2])
    pool.release(reclaimed)

    pool.teardown()
    print("PASS test_exhaustion")


def test_slot_buffers():
    """Acquire a slot, verify msghdr_ptr/iov_ptr/addr_ptr/data_ptr are
    non-null and at the correct offsets within the contiguous buffer."""
    var pool = SendSlabPool(capacity=2)
    pool.wire_completions()

    var idx = pool.acquire()
    debug_assert(idx >= 0, "acquire must return a valid slot index")

    var slab_ptr = pool.slot_ptr(idx)

    var msghdr = slab_ptr[].msghdr_ptr()
    var iov = slab_ptr[].iov_ptr()
    var addr = slab_ptr[].addr_ptr()
    var data = slab_ptr[].data_ptr()

    debug_assert(Int(msghdr) != 0, "msghdr_ptr must be non-null")
    debug_assert(Int(iov) != 0, "iov_ptr must be non-null")
    debug_assert(Int(addr) != 0, "addr_ptr must be non-null")
    debug_assert(Int(data) != 0, "data_ptr must be non-null")

    # Verify relative offsets: msghdr @ 0, iov @ 56, addr @ 72, data @ 100.
    var base = Int(msghdr)
    debug_assert(Int(iov) == base + 56, "iov_ptr must be at msghdr + 56")
    debug_assert(Int(addr) == base + 72, "addr_ptr must be at msghdr + 72")
    debug_assert(Int(data) == base + 100, "data_ptr must be at msghdr + 100")

    pool.release(idx)
    pool.teardown()
    print("PASS test_slot_buffers")


def test_fill():
    """Verify fill() writes data and addr into the buffer and wires
    msghdr/iovec fields correctly."""
    var pool = SendSlabPool(capacity=1)
    pool.wire_completions()

    var idx = pool.acquire()
    debug_assert(idx >= 0, "acquire must return a valid slot index")

    # Prepare test data: 4 bytes of payload, 16 bytes of addr (IPv4 sockaddr).
    var data = List[UInt8]()
    data.append(0xDE)
    data.append(0xAD)
    data.append(0xBE)
    data.append(0xEF)

    var addr = List[UInt8]()
    for i in range(16):
        addr.append(UInt8(i + 1))

    var slab_ptr = pool.slot_ptr(idx)
    slab_ptr[].fill(data, addr)

    # Verify payload was copied.
    var data_p = slab_ptr[].data_ptr()
    debug_assert(data_p[0] == 0xDE, "data byte 0 must be 0xDE")
    debug_assert(data_p[1] == 0xAD, "data byte 1 must be 0xAD")
    debug_assert(data_p[2] == 0xBE, "data byte 2 must be 0xBE")
    debug_assert(data_p[3] == 0xEF, "data byte 3 must be 0xEF")

    # Verify addr was copied (first 16 bytes) and padded (bytes 16..27).
    var addr_p = slab_ptr[].addr_ptr()
    for i in range(16):
        debug_assert(
            addr_p[i] == UInt8(i + 1),
            "addr byte must match input",
        )
    for i in range(16, 28):
        debug_assert(addr_p[i] == 0, "addr padding bytes must be zero")

    # Verify msghdr.msg_name points at addr region.
    var msghdr_p = slab_ptr[].msghdr_ptr()
    var msg_name_val = UInt64(0)
    var msg_name_bytes = UnsafePointer(to=msg_name_val).bitcast[UInt8]()
    for i in range(8):
        msg_name_bytes[i] = msghdr_p[i]
    debug_assert(
        Int(msg_name_val) == Int(addr_p),
        "msghdr.msg_name must point at addr region",
    )

    # Verify msghdr.msg_namelen = 28.
    var msg_namelen = UInt32(0)
    var namelen_bytes = UnsafePointer(to=msg_namelen).bitcast[UInt8]()
    for i in range(4):
        namelen_bytes[i] = msghdr_p[8 + i]
    debug_assert(
        Int(msg_namelen) == 28,
        "msghdr.msg_namelen must be 28",
    )

    pool.release(idx)
    pool.teardown()
    print("PASS test_fill")


def main():
    test_acquire_release()
    test_exhaustion()
    test_slot_buffers()
    test_fill()
    print("ALL PASS")
