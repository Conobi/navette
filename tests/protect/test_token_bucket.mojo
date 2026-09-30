"""TokenBucket: burst bound, exact refill, clock steps back, no overflow."""

from navette.protect.token_bucket import TokenBucket
from tests._test_util import assert_true, assert_equal_int
from tests.protect._prop import Rng, prop_iters


def test_burst_then_refill() raises:
    var b = TokenBucket(rate_per_s=500, burst=16)
    var ok = 0
    for _ in range(40):
        if b.take(UInt64(1_000_000)):
            ok += 1
    assert_equal_int(ok, 16, "burst of 16 at one instant")
    assert_true(not b.take(UInt64(1_001_999)), "1.999 ms < one token at 500/s")
    assert_true(b.take(UInt64(1_002_000)), "2 ms = one token")


def test_rate_bound_property() raises:
    """Over any schedule, successes <= burst + floor(rate * elapsed / 1e6), and a clock stepping back never mints tokens."""
    for seed in range(prop_iters(200)):
        var rng = Rng(UInt64(0xB0C4 + seed))
        var rate = 1 + rng.below(1000)
        var burst = 1 + rng.below(32)
        var b = TokenBucket(rate_per_s=rate, burst=burst)
        var start = UInt64(5_000_000)
        var now = start
        var newest = start
        # Anchor the bucket's clock at `start`: the oracle measures refill from there.
        var ok = 1 if b.take(start) else 0
        for i in range(500):
            var k = rng.below(10)
            if k < 7:
                now += UInt64(rng.below(5_000))
            elif k < 9:
                now += UInt64(rng.below(2_000_000))
            else:
                now -= UInt64(rng.below(100_000))
            newest = max(newest, now)
            if b.take(now):
                ok += 1
            var cap = burst + Int((newest - start) * UInt64(rate) // 1_000_000)
            assert_true(ok <= cap, "seed " + String(seed) + " step " + String(i))


def test_huge_gap_saturates() raises:
    var b = TokenBucket(rate_per_s=100, burst=4)
    for _ in range(4):
        _ = b.take(UInt64(1))
    var ok = 0
    for _ in range(10):
        if b.take(UInt64.MAX - 1):
            ok += 1
    assert_equal_int(ok, 4, "refill saturates at burst, no multiply overflow")


def main() raises:
    test_burst_then_refill()
    test_rate_bound_property()
    test_huge_gap_saturates()
    print("PASS: test_token_bucket")
