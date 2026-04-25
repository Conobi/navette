# src/quic/profile.mojo
#
# QUIC accept-loop profile module (Plan A).
#
# Provides AcceptProfile (counter struct + report formatters), monotonic_us
# (sans-I/O CLOCK_MONOTONIC wrapper), and PROFILE_ACCEPT (comptime opt-in).
#
# Hand-edit PROFILE_ACCEPT to True to produce a profile build (see Plan B
# for how this gates instrumentation in connection.mojo + bench/h3_server.mojo).

from std.ffi import external_call
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc


comptime PROFILE_ACCEPT: Bool = False
comptime _CLOCK_MONOTONIC: Int32 = 1


def monotonic_us() -> UInt64:
    """clock_gettime(CLOCK_MONOTONIC) → microseconds. Sans-I/O."""
    # struct timespec: tv_sec(i64) + tv_nsec(i64) = 16 bytes
    var ts = alloc[UInt8](16).as_any_origin()
    for i in range(16):
        ts[i] = 0
    _ = external_call["clock_gettime", Int32](_CLOCK_MONOTONIC, ts)
    var tv_sec = UInt64(0)
    for i in range(8):
        tv_sec = tv_sec | (UInt64(ts[i]) << UInt64(i * 8))
    var tv_nsec = UInt64(0)
    for i in range(8):
        tv_nsec = tv_nsec | (UInt64(ts[8 + i]) << UInt64(i * 8))
    ts.free()
    return tv_sec * 1_000_000 + tv_nsec / 1_000
