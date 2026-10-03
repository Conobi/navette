"""Overload governor core: queue-wait sensor arithmetic, the server-wide stream budget, per-connection windows.

Pure: imports `std` only, reads no clock, never allocates after
construction, uses saturating `UInt64` arithmetic and no floats. The
server shell passes time and counters in. Every time constant derives
from the one dial `t = max_queue_delay_us`.
"""

from std.bit import bit_width

comptime _BUCKETS = 32
comptime MIN_SAMPLES = 20
"""Fewer samples in an interval read as idle: p90 then rests on at least 2 of them."""


def interval_us(t: UInt64) -> UInt64:
    """Sensing interval `I = 20 t` (CoDel's 5 ms / 100 ms ratio)."""
    return 20 * t


def retry_after_s(t: UInt64) -> UInt64:
    """`Retry-After` of a refusal: the calm time `200 t` rounded up to whole seconds, at least 1."""
    return max(UInt64(1), (200 * t + 999_999) // 1_000_000)


def kwait_us(rmem: UInt64, truesize: UInt64, deliveries_prev: UInt64, interval: UInt64) -> UInt64:
    """Kernel socket-queue wait: `rmem` bytes ahead drain at the last interval's read rate, capped at `interval`.

    `rmem` is `sk_rmem_alloc` (skb truesize, not payload), so it is divided
    by the per-datagram `truesize`. 0 while uncalibrated or empty; a queue
    with no reads in the last interval waited the whole interval.
    """
    if rmem == 0 or truesize == 0:
        return 0
    if deliveries_prev == 0:
        return interval
    var w = UInt128(rmem) * UInt128(interval) // (UInt128(truesize) * UInt128(deliveries_prev))
    return UInt64(min(w, UInt128(interval)))


def ewma8(prev: UInt64, x: UInt64) -> UInt64:
    """Weight-1/8 moving average (msquic's); a zero `prev` means no history and seeds with `x`."""
    if prev == 0:
        return x
    return prev - (prev >> 3) + (x >> 3)


def truesize_ewma(prev: UInt64, rmem: UInt64, d: UInt64) -> UInt64:
    """Per-datagram truesize from a pass that read `d` datagrams and drained `rmem` queued bytes; no-op without both."""
    if rmem == 0 or d == 0:
        return prev
    return ewma8(prev, rmem // d)


struct DelayHist(Copyable, Movable):
    """Per-interval wait samples in µs, log2 buckets: bucket `b` holds `[2^(b-1), 2^b - 1]`, the top one everything above."""

    var buckets: InlineArray[UInt32, _BUCKETS]
    var total: UInt64

    def __init__(out self):
        self.buckets = InlineArray[UInt32, _BUCKETS](fill=0)
        self.total = 0

    def insert(mut self, us: UInt64):
        self.buckets[Int(min(bit_width(us), UInt64(_BUCKETS - 1)))] += 1
        self.total += 1

    def insert_pass(mut self, kwait: UInt64, n: UInt64, span: UInt64):
        """Insert the waits of a pass's `n` requests: `kwait` plus the `k`-th request's share `k * span / n` of the pass."""
        for k in range(n):
            self.insert(kwait + UInt64((UInt128(k) * UInt128(span)) // UInt128(n)))

    def p90(self) -> UInt64:
        """90th percentile (rank `ceil(0.9 total)`), linearly interpolated inside its bucket; 0 when empty."""
        var rank = (9 * self.total + 9) // 10
        var seen = UInt64(0)
        for b in range(_BUCKETS):
            var count = UInt64(self.buckets[b])
            if count != 0 and seen + count >= rank:
                if b == 0:
                    return 0
                var lo = UInt64(1) << UInt64(b - 1)
                return lo + (lo - 1) * (rank - seen) // count
            seen += count
        return 0

    def close_delay(mut self, gap_us: UInt64, interval: UInt64) -> UInt64:
        """The closing interval's delay, then reset: 0 (idle) below `MIN_SAMPLES` or after a pass-free gap of `interval`, else p90."""
        var d = UInt64(0) if self.total < MIN_SAMPLES or gap_us >= interval else self.p90()
        self.reset()
        return d

    def reset(mut self):
        for b in range(_BUCKETS):
            self.buckets[b] = 0
        self.total = 0
