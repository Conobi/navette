"""Event count over the last second, in ten 100 ms buckets.

Backs the per-connection abuse guards (H2 peer resets and induced
errors, H3 stream churn): `add` records one event and returns how many
fell in the current window, in O(1) with 56 bytes of state.
"""

from std.collections import InlineArray

comptime RATE_BUCKETS: Int = 10
comptime RATE_BUCKET_US: UInt64 = 100_000


struct RateWindow(Copyable, Movable):
    """Time is protocol µs; a clock that steps back counts into the newest bucket."""

    var _b: InlineArray[UInt32, RATE_BUCKETS]
    var _slot: UInt64
    var _sum: Int

    def __init__(out self):
        self._b = InlineArray[UInt32, RATE_BUCKETS](fill=UInt32(0))
        self._slot = 0
        self._sum = 0

    def _advance(mut self, now_us: UInt64):
        var slot = now_us // RATE_BUCKET_US
        if slot <= self._slot:
            return
        var gap = slot - self._slot
        if gap >= UInt64(RATE_BUCKETS):
            for i in range(RATE_BUCKETS):
                self._b[i] = 0
            self._sum = 0
        else:
            for k in range(1, Int(gap) + 1):
                var idx = Int((self._slot + UInt64(k)) % UInt64(RATE_BUCKETS))
                self._sum -= Int(self._b[idx])
                self._b[idx] = 0
        self._slot = slot

    def add(mut self, now_us: UInt64) -> Int:
        """Record one event at `now_us`; returns the events in the window ending at `now_us`, this one included."""
        self._advance(now_us)
        var idx = Int(self._slot % UInt64(RATE_BUCKETS))
        self._b[idx] += 1
        self._sum += 1
        return self._sum

    def count(mut self, now_us: UInt64) -> Int:
        self._advance(now_us)
        return self._sum
