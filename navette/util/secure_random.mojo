"""Kernel CSPRNG bytes via getrandom(2), failing loudly instead of silently.

Keys drawn here (SipHash table keys, secrets) are only as strong as the
fill: a buffer left zeroed after an ignored failure (ENOSYS on an old
kernel, a seccomp filter) is a known key, so every failure other than
EINTR raises.
"""

from std.ffi import external_call

comptime _GetrandomFn = def (Pointer[UInt8, MutAnyOrigin], Int) thin -> Int
"""Writes up to `n` bytes at `p`; returns the count written or `-errno`."""

comptime _EINTR = 4


def _getrandom(p: Pointer[UInt8, MutAnyOrigin], n: Int) -> Int:
    """getrandom(2) with blocking semantics (flags 0), errno folded into the result."""
    var r = external_call["getrandom", Int](p, UInt64(n), UInt32(0))
    if r < 0:
        return -Int(external_call["__errno_location", Pointer[Int32, MutAnyOrigin]]()[])
    return r


def _fill_random_with[source: _GetrandomFn](buf: Span[mut=True, UInt8, _]) raises:
    """Fills every byte of `buf` from `source`, the testable core of `fill_random`.

    Retries on EINTR and on short reads. Raises on any other error and on a
    zero-byte read of a non-empty request (which would otherwise loop forever),
    and on a count above the bytes requested: such a count cannot be trusted,
    and accepting it would end the loop over bytes never written.
    """
    var p = buf.unsafe_ptr().as_unsafe_any_origin()
    var n = len(buf)
    var off = 0
    while off < n:
        var r = source(p.unsafe_offset(off), n - off)
        if r == -_EINTR:
            continue
        if r <= 0:
            raise Error("getrandom failed: errno " + String(-r))
        if r > n - off:
            raise Error("getrandom reported more bytes than requested")
        off += r


def fill_random(buf: Span[mut=True, UInt8, _]) raises:
    """Fills `buf` from the kernel CSPRNG; raises rather than returning a partial fill."""
    _fill_random_with[_getrandom](buf)
