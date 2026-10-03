"""Overload governor core: histogram, sensor arithmetic, controller, per-connection limits, facade (pure, fake clock)."""

from std.bit import bit_width
from navette.protect.governor import DelayHist, interval_us, retry_after_s, kwait_us, ewma8, truesize_ewma, MIN_SAMPLES
from tests._test_util import assert_true
from tests.protect._prop import Rng, prop_iters


def _bucket(us: UInt64) -> UInt64:
    return min(bit_width(us), 31)


def test_p90_exact_property() raises:
    """The histogram p90 lies in the log2 bucket of the exact sorted p90."""
    var rng = Rng(0x6090)
    for c in range(prop_iters(300)):
        var n = 20 + rng.below(400)
        var xs = List[UInt64]()
        var h = DelayHist()
        var top = 1 + rng.below(30)
        for _ in range(n):
            var v = rng.next() >> UInt64(64 - top)
            xs.append(v)
            h.insert(v)
        sort(xs)
        var exact = xs[(9 * n + 9) // 10 - 1]
        var got = h.p90()
        assert_true(_bucket(got) == _bucket(exact), "case " + String(c) + ": p90 " + String(got) + " vs exact " + String(exact))


def test_insert_pass_and_reset() raises:
    var h = DelayHist()
    h.insert_pass(100, 10, 1000)
    assert_true(h.total == 10, "ten samples")
    for k in range(10):
        assert_true(h.buckets[Int(_bucket(UInt64(100 * (k + 1))))] >= 1, "sample " + String(100 * (k + 1)))
    h.insert(UInt64.MAX)
    assert_true(h.buckets[31] == 1, "UInt64.MAX lands in the top bucket")
    h.reset()
    assert_true(h.total == 0 and h.p90() == 0, "reset zeroes")
    for i in range(32):
        assert_true(h.buckets[i] == 0, "bucket zeroed")


def test_derived_constants() raises:
    assert_true(interval_us(5_000) == 100_000, "I = 20 t")
    assert_true(retry_after_s(5_000) == 1, "1 s at the default")
    assert_true(retry_after_s(1_000) == 1, "at least 1 s")
    assert_true(retry_after_s(10_000_000) == 2_000, "200 t in whole seconds")


def _edge(mut rng: Rng) -> UInt64:
    """Mostly small values, sometimes the saturation edges."""
    var k = rng.below(10)
    if k == 0:
        return 0
    if k == 1:
        return UInt64.MAX - UInt64(rng.below(2))
    return rng.next() >> UInt64(rng.below(64))


def test_kwait_bounds_property() raises:
    var rng = Rng(0x4A17)
    for c in range(prop_iters(300)):
        var i_us = interval_us(UInt64(1_000 + rng.below(10_000_000)))
        var rmem = _edge(rng)
        var ts = _edge(rng)
        var d = _edge(rng)
        var w = kwait_us(rmem, ts, d, i_us)
        var tag = "case " + String(c) + ": "
        assert_true(w <= i_us, tag + "capped at I")
        if rmem == 0 or ts == 0:
            assert_true(w == 0, tag + "empty socket or uncalibrated truesize reads 0")
        elif d == 0:
            assert_true(w == i_us, tag + "no reads last interval reads I")
        var more = rmem + UInt64(rng.below(1 << 20))
        if more >= rmem:
            assert_true(kwait_us(more, ts, d, i_us) >= w, tag + "monotone in rmem")


def test_truesize_ewma() raises:
    assert_true(truesize_ewma(0, 23_040, 10) == 2_304, "first sample seeds")
    assert_true(truesize_ewma(2_304, 99_999, 0) == 2_304, "no deliveries leaves it")
    assert_true(truesize_ewma(2_304, 0, 10) == 2_304, "empty socket leaves it")
    var rng = Rng(0x7E5)
    for c in range(prop_iters(300)):
        var target = UInt64(64 + rng.below(1 << 20))
        var v = truesize_ewma(0, UInt64(1 + rng.below(4 * Int(target))), 1)
        for _ in range(40):
            v = truesize_ewma(v, target * 7, 7)
        var err = v - target if v > target else target - v
        assert_true(err <= target // 32 + 8, "case " + String(c) + ": converges within 40 steps")
    assert_true(ewma8(UInt64.MAX, UInt64.MAX) >= UInt64.MAX - 8, "no wrap")


def test_close_delay() raises:
    var h = DelayHist()
    for _ in range(MIN_SAMPLES - 1):
        h.insert(50_000)
    assert_true(h.close_delay(0, 100_000) == 0, "fewer than MIN_SAMPLES reads idle")
    assert_true(h.total == 0, "closing resets")
    for _ in range(MIN_SAMPLES):
        h.insert(50_000)
    assert_true(h.close_delay(100_000, 100_000) == 0 and h.total == 0, "a gap of one interval reads idle and resets")
    for _ in range(MIN_SAMPLES):
        h.insert(50_000)
    var d = h.close_delay(99_999, 100_000)
    assert_true(d >= 32_768 and d < 65_536 and h.total == 0, "otherwise the p90, then reset")


def main() raises:
    test_p90_exact_property()
    test_insert_pass_and_reset()
    test_derived_constants()
    test_kwait_bounds_property()
    test_truesize_ewma()
    test_close_delay()
    print("PASS: test_governor")
