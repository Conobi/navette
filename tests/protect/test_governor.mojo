"""Overload governor core: histogram, sensor arithmetic, controller, per-connection limits, facade (pure, fake clock)."""

from std.bit import bit_width
from navette.protect.governor import DelayHist, interval_us, retry_after_s, kwait_us, ewma8, truesize_ewma, MIN_SAMPLES
from navette.protect.governor import GovState, Sample, step, UNLIMITED, RELEASE, PENDING_MAX
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


def _rand_cap(mut rng: Rng) -> UInt64:
    return UInt64(1 + rng.below(200)) if rng.chance(30) else 100


def _rand_state(mut rng: Rng, cap: UInt64) -> GovState:
    """Any reachable state: budget at or above the floor (or unlimited), ages within their clamps."""
    var s = GovState()
    if rng.chance(70):
        s.budget = min(UInt64(32), cap) + (_edge(rng) >> 1)
    s.cut_pending = rng.chance(50) and s.budget != UNLIMITED
    s.pending_age = UInt64(rng.below(PENDING_MAX + 1))
    s.clear_streak = UInt64(rng.below(RELEASE + 1))
    s.pressure = rng.chance(50)
    s.refuse_new = s.pressure and rng.chance(30)
    return s^


def _rand_sample(mut rng: Rng, t: UInt64, over: Int) -> Sample:
    """`over`: 1 above target, 0 at or below it, -1 either."""
    var d = UInt64(rng.below(Int(t) + 1))
    if over == 1 or (over == -1 and rng.chance(50)):
        d = t + 1 + (UInt64(rng.below(Int(8 * t))) if rng.chance(90) else _edge(rng) >> 1)
    return Sample(delay_us=d, done=_edge(rng), rtt_sum_us=_edge(rng), work=_edge(rng), active=_edge(rng))


def test_step_properties() raises:
    """inert-below-target, one-decrease, decrease-bounded, floor, rung-4 threshold, saturation."""
    var rng = Rng(0x57E9)
    for c in range(prop_iters(300)):
        var t = UInt64(1_000 + rng.below(10_000_000))
        var cap = _rand_cap(rng)
        var floor = min(UInt64(32), cap)
        var s0 = _rand_state(rng, cap)
        var x = _rand_sample(rng, t, -1)
        var s = s0.copy()
        step(s, t, x, cap)
        var tag = "case " + String(c) + ": "
        assert_true(s.budget >= floor, tag + "floor")
        assert_true(not s.refuse_new or x.delay_us > 4 * t or s0.refuse_new, tag + "rung 4 only above 4 t")
        if x.delay_us <= t:
            assert_true(s.cuts == s0.cuts and s.budget >= s0.budget, tag + "below target never cuts")
            assert_true(not s.pressure and not s.refuse_new, tag + "below target clears the flags")
        if s0.cut_pending and x.work > s0.budget and s0.pending_age + 1 < PENDING_MAX:
            assert_true(s.cuts == s0.cuts and s.budget >= s0.budget, tag + "one decrease in flight")
        if s.cuts != s0.cuts:
            var base = min(s0.budget, x.work)
            assert_true(s.budget >= max(floor, base // 2) and s.budget <= max(floor, base), tag + "cut bounded")


def test_recovery_and_liveness() raises:
    var rng = Rng(0x2EC0)
    for c in range(prop_iters(300)):
        var t = UInt64(1_000 + rng.below(10_000_000))
        var cap = _rand_cap(rng)
        var s = _rand_state(rng, cap)
        var tag = "case " + String(c) + ": "
        var live = s.copy()
        var cuts0 = live.cuts
        for _ in range(PENDING_MAX):
            step(live, t, _rand_sample(rng, t, -1), cap)
        assert_true(not live.cut_pending or live.cuts > cuts0, tag + "a pending cut ends within PENDING_MAX closes")
        for _ in range(RELEASE):
            step(s, t, _rand_sample(rng, t, 0), cap)
        assert_true(s.budget == UNLIMITED and not s.pressure and not s.refuse_new, tag + "RELEASE clear closes release")


def main() raises:
    test_p90_exact_property()
    test_insert_pass_and_reset()
    test_derived_constants()
    test_kwait_bounds_property()
    test_truesize_ewma()
    test_close_delay()
    test_step_properties()
    test_recovery_and_liveness()
    print("PASS: test_governor")
