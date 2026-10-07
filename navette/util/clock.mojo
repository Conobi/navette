"""Monotonic clock helper shared by the transports."""

from std.ffi import external_call
from std.memory import Pointer

comptime _CLOCK_MONOTONIC: Int32 = 1


def monotonic_us() -> UInt64:
    """`clock_gettime(CLOCK_MONOTONIC)` in microseconds, sans-I/O."""
    var ts = InlineArray[Int64, 2](fill=0)
    var ts_ptr = Pointer(to=ts).unsafe_bitcast[UInt8]()
    _ = external_call["clock_gettime", Int32](_CLOCK_MONOTONIC, ts_ptr)
    return UInt64(ts[0]) * 1_000_000 + UInt64(ts[1]) / 1_000
