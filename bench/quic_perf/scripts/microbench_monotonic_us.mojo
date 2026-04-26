# bench/quic_perf/scripts/microbench_monotonic_us.mojo
#
# Plan B pre-flight gate: measure monotonic_us() per-call cost.
# Required: <= 30 ns/call (Plan A's stack-buffer target).
# If this fails, do not proceed with Plan B insertion work.

from src.quic.profile import monotonic_us


fn main() raises:
    var iters = UInt64(1_000_000)

    # Warm the I-cache, page in the syscall page, etc.
    var sink = UInt64(0)
    for _ in range(10_000):
        sink += monotonic_us()

    var t0 = monotonic_us()
    for _ in range(Int(iters)):
        sink += monotonic_us()
    var t1 = monotonic_us()

    var elapsed_us = t1 - t0
    var elapsed_ns = elapsed_us * UInt64(1000)
    var ns_per_call = elapsed_ns / iters

    print("microbench monotonic_us:")
    print("  iters:        ", iters)
    print("  elapsed_us:   ", elapsed_us)
    print("  ns/call:      ", ns_per_call)
    print("  sink (ignore):", sink)

    if ns_per_call > UInt64(30):
        print("FAIL: ns/call > 30 - Plan B overhead budget unreachable.")
        print("FAIL: triage timer cost before any connection.mojo edits.")
        raise "monotonic_us microbench failed: " + String(ns_per_call) + " ns/call"

    print("PASS: <= 30 ns/call gate cleared.")
