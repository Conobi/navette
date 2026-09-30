"""Token bucket in integer microseconds.

Paces the server's stateless responses (Version Negotiation, stateless
CONNECTION_CLOSE): a flood of junk Initials must not turn the server
into a reflector. Retry is not paced here; it is bounded by admission.
"""

comptime _MICRO: UInt64 = 1_000_000


struct TokenBucket(Copyable, Movable):
    """At most `burst + rate_per_s * elapsed_s` successful `take`s over any schedule.

    Integer-only: the level is kept in millionths of a token, so refill
    is exact with no float drift. Starts full. A clock that steps back
    neither refills nor moves the reference time, so it cannot mint
    tokens; a huge forward gap is clamped before the multiply, so the
    level saturates at `burst` instead of overflowing.
    """

    var rate_per_s: UInt64
    var burst: UInt64
    var _micro: UInt64
    var _last_us: UInt64

    def __init__(out self, *, rate_per_s: Int, burst: Int):
        """Both must be > 0; a zero rate would never refill and a zero burst never admit."""
        self.rate_per_s = UInt64(max(rate_per_s, 1))
        self.burst = UInt64(max(burst, 1))
        self._micro = self.burst * _MICRO
        self._last_us = 0

    def take(mut self, now_us: UInt64) -> Bool:
        """Spend one token at protocol time `now_us`; False when the bucket is empty."""
        var full = self.burst * _MICRO
        if now_us > self._last_us:
            var gap = min(now_us - self._last_us, full // self.rate_per_s + 1)
            self._micro = min(full, self._micro + gap * self.rate_per_s)
            self._last_us = now_us
        if self._micro >= _MICRO:
            self._micro -= _MICRO
            return True
        return False
