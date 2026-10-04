"""Overload governor core: histogram, sensor arithmetic, controller, per-connection limits, facade (pure, fake clock)."""

from std.bit import bit_width
from navette.protect.governor import DelayHist, interval_us, retry_after_s, kwait_us, MIN_SAMPLES, DATAGRAM_TRUESIZE
from navette.protect.governor import GovState, Mode, Sample, Decision, step, UNLIMITED, RELEASE, PENDING_MAX, REFUSE_AFTER
from navette.protect.governor import conn_limit, Governor, FEW_ACTIVE, WARN_EVERY, MIN_CREDIT
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
    _ = h.close_delay()
    assert_true(h.total == 0 and h.p90() == 0, "closing zeroes")
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
        var d = _edge(rng)
        var w = kwait_us(rmem, d, i_us)
        var tag = "case " + String(c) + ": "
        assert_true(w <= i_us, tag + "capped at I")
        if rmem == 0 or d < MIN_SAMPLES:
            assert_true(w == 0, tag + "empty socket or unknown read rate reads 0")
        var more = rmem + UInt64(rng.below(1 << 20))
        if more >= rmem:
            assert_true(kwait_us(more, d, i_us) >= w, tag + "monotone in rmem")
    assert_true(kwait_us(100 * DATAGRAM_TRUESIZE, 500, 100_000) == 20_000, "100 datagrams ahead at 500 per interval")


def test_kwait_under_sustained_overload() raises:
    """No ingest ever drains the socket: the wait is still read (it used to wait for a draining pass to calibrate)."""
    var now = UInt64(1_000_000)
    var g = Governor(5_000, now)
    for _ in range(50):
        g.on_ingest(UInt64(100) * DATAGRAM_TRUESIZE, 10, False)
        now += 2_000
        g.on_pass(now, now - 100)
    g.close(now, 500, 50, 10, 100)
    g.on_ingest(UInt64(100) * DATAGRAM_TRUESIZE, 10, False)
    assert_true(g.kwait == 20_000, "100 datagrams ahead, 500 read last interval: " + String(g.kwait))


def test_close_delay() raises:
    var h = DelayHist()
    for _ in range(MIN_SAMPLES - 1):
        h.insert(50_000)
    assert_true(h.close_delay() == 0, "fewer than MIN_SAMPLES reads idle")
    assert_true(h.total == 0, "closing resets")
    for _ in range(MIN_SAMPLES):
        h.insert(50_000)
    var d = h.close_delay()
    assert_true(d >= 32_768 and d < 65_536 and h.total == 0, "otherwise the p90, then reset")


def _pressure(s: GovState) -> Bool:
    return s.mode == Mode.CUTTING or s.mode == Mode.HOLDING


def _rand_cap(mut rng: Rng) -> UInt64:
    return UInt64(1 + rng.below(200)) if rng.chance(30) else 100


def _rand_state(mut rng: Rng, cap: UInt64) -> GovState:
    """Any reachable state: budget at or above the floor (or unlimited), ages within their clamps."""
    var s = GovState()
    if rng.chance(70):
        s.budget = min(UInt64(32), cap) + (_edge(rng) >> 1)
        s.mode = Mode(UInt8(1 + rng.below(3)))
    s.since_cut = UInt64(rng.below(PENDING_MAX + 1))
    s.clear_streak = UInt64(rng.below(RELEASE + 1))
    s.hot_streak = UInt64(rng.below(Int(REFUSE_AFTER) + 1))
    s.refuse_new = _pressure(s) and rng.chance(30)
    return s^


def _rand_sample(mut rng: Rng, t: UInt64, over: Int) -> Sample:
    """`over`: 1 above target, 0 at or below it, -1 either."""
    var d = UInt64(rng.below(Int(t) + 1))
    if over == 1 or (over == -1 and rng.chance(50)):
        d = t + 1 + (UInt64(rng.below(Int(8 * t))) if rng.chance(90) else _edge(rng) >> 1)
    return Sample(delay_us=d, done=_edge(rng), work=_edge(rng), active=_edge(rng))


def test_step_properties() raises:
    """inert-below-target, one-decrease, decrease-bounded, floor, refuse-new threshold, saturation."""
    var rng = Rng(0x57E9)
    for c in range(prop_iters(300)):
        var t = UInt64(1_000 + rng.below(10_000_000))
        var cap = _rand_cap(rng)
        var floor = min(UInt64(32), cap)
        var s0 = _rand_state(rng, cap)
        var x = _rand_sample(rng, t, -1)
        var s = s0.copy()
        var d = step(s, x, t, cap)
        var tag = "case " + String(c) + ": "
        assert_true(s.budget >= floor, tag + "floor")
        assert_true(not s.refuse_new or s0.refuse_new or (x.delay_us > 4 * t and s.hot_streak == REFUSE_AFTER), tag + "refuse-new only after a streak above 4 t")
        if x.delay_us <= t:
            assert_true(s.cuts == s0.cuts and s.budget >= s0.budget, tag + "below target never cuts")
            assert_true(s.mode == (Mode.NORMAL if s0.mode == Mode.NORMAL or s.budget == UNLIMITED else Mode.RECOVERING), tag + "clear")
            assert_true(not s.refuse_new and d.share == UNLIMITED, tag + "below target refuses nothing")
        else:
            assert_true(_pressure(s) and d.share == max(min(MIN_CREDIT, cap), d.shed_above), tag + "over target: CUTTING or HOLDING, credit share = the even split")
        if x.work > s0.budget and s0.since_cut + 1 < PENDING_MAX:
            assert_true(s.cuts == s0.cuts and s.budget >= s0.budget, tag + "one decrease in flight")
            assert_true(x.delay_us <= t or s.mode == Mode.HOLDING, tag + "over with a cut in flight holds")
        assert_true(d.budget == s.budget and d.refuse_new == s.refuse_new, tag + "decision mirrors state")
        if s.cuts != s0.cuts:
            var base = min(s0.budget, x.work)
            assert_true(s.budget >= max(floor, base // 2) and s.budget <= max(floor, base), tag + "cut bounded")


def _hot(mut s: GovState, t: UInt64, delay: UInt64, work: UInt64, done: UInt64) -> Bool:
    """One close with p90 `delay`; returns refuse_new."""
    return step(s, Sample(delay_us=delay, done=done, work=work, active=10), t, 100).refuse_new


def test_refuse_new_needs_a_streak_at_the_floor() raises:
    """Refusing new connections takes REFUSE_AFTER consecutive closes above 4 t with nothing left to cut."""
    var t = UInt64(5_000)
    var s = GovState()
    assert_true(not _hot(s, t, 5 * t, 1_000, 3_000), "one close above 4 t is not enough")
    assert_true(not _hot(s, t, 5 * t, 1_000, 3_000) and not _hot(s, t, 5 * t, 1_000, 3_000), "nor three while cuts remain")
    s = GovState()
    s.mode, s.budget = Mode.HOLDING, 32
    assert_true(not _hot(s, t, 5 * t, 1_000, 0) and not _hot(s, t, 5 * t, 1_000, 0), "at the floor: not after two")
    assert_true(_hot(s, t, 5 * t, 1_000, 0), "the third consecutive one refuses")
    assert_true(_hot(s, t, 2 * t, 1_000, 0), "an over close below 4 t keeps it")
    assert_true(not _hot(s, t, t, 1_000, 0), "a clear close clears it")
    s.mode, s.budget = Mode.HOLDING, 32
    _ = _hot(s, t, 5 * t, 1_000, 0)
    _ = _hot(s, t, 5 * t, 1_000, 0)
    _ = _hot(s, t, 2 * t, 1_000, 0)
    assert_true(not _hot(s, t, 5 * t, 1_000, 0), "the streak is consecutive")
    s = GovState()
    s.mode, s.budget = Mode.HOLDING, 147
    _ = _hot(s, t, 5 * t, 200, 200)
    _ = _hot(s, t, 5 * t, 200, 200)
    assert_true(_hot(s, t, 5 * t, 200, 200), "a budget at or below the target (work 200 - excess 40) has nothing left to cut")


def test_cut_grow_release_rules() raises:
    """Pinned values: the cut removes the excess queue `done (d - t) / I` from the open work, at most halving the used
    budget; recovery grows by `active` while half used; release on `RELEASE` clear closes or full credit for every connection."""
    var t = UInt64(5_000)
    var s = GovState()
    _ = step(s, Sample(delay_us=2 * t, done=30_000, work=1_000, active=10), t, 100)
    assert_true(s.budget == 500, "at most half of the used budget: " + String(s.budget))
    s = GovState()
    _ = step(s, Sample(delay_us=3 * t, done=3_000, work=1_000, active=10), t, 100)
    assert_true(s.budget == 700, "work minus the excess 3000 x 2t / I: " + String(s.budget))
    s.mode, s.budget = Mode.RECOVERING, 100
    _ = step(s, Sample(delay_us=0, done=0, work=50, active=7), t, 100)
    assert_true(s.budget == 107 and s.mode == Mode.RECOVERING, "grows by active while half used: " + String(s.budget))
    _ = step(s, Sample(delay_us=0, done=0, work=52, active=7), t, 100)
    assert_true(s.budget == 107, "not below half used")
    _ = step(s, Sample(delay_us=0, done=0, work=0, active=1), t, 100)
    assert_true(s.budget == UNLIMITED and s.mode == Mode.NORMAL, "released once it covers every connection's credit")
    s.mode, s.budget, s.clear_streak = Mode.RECOVERING, 100, 0
    for k in range(RELEASE):
        _ = step(s, Sample(delay_us=0, done=0, work=0, active=1_000), t, 100)
        assert_true((s.budget == UNLIMITED) == (k == RELEASE - 1), "released on the RELEASE-th clear close")


def test_credit_held_outside_the_server_is_kept() raises:
    """200 connections x 10 streams, 29.4 K req/s, p90 6 ms: most of each stream's life is RTT, ACK delay and client
    turnaround, not server queue. Only the 1 ms excess (29 streams) is cut, not down to `done t / I` = 147."""
    var s = GovState()
    var d = step(s, Sample(delay_us=6_000, done=2_940, work=2_000, active=200), 5_000, 100)
    assert_true(s.mode == Mode.CUTTING and s.budget == 1_971, "budget " + String(s.budget))
    assert_true(d.shed_above == 9 and d.share == 9, "credit stays near 10 per connection: " + String(d.share))


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
            _ = step(live, _rand_sample(rng, t, 1), t, cap)
        assert_true(live.cuts > cuts0, tag + "sustained overload cuts again within PENDING_MAX closes")
        for _ in range(RELEASE):
            _ = step(s, _rand_sample(rng, t, 0), t, cap)
        assert_true(s.mode == Mode.NORMAL and s.budget == UNLIMITED and not s.refuse_new, tag + "RELEASE clear closes release")


def test_conn_limit_properties() raises:
    """fair-share, lend at most 2x, one halving step, no second cut before the first took effect, floor, unlimited gives CAP."""
    var rng = Rng(0xFA12)
    for c in range(prop_iters(300)):
        var cap = _rand_cap(rng)
        var floor = min(MIN_CREDIT, cap)
        var budget = min(UInt64(32), cap) + (UInt64(rng.below(20_000)) if rng.chance(80) else _edge(rng) >> 1)
        var work = UInt64(rng.below(2 * Int(min(budget, 1 << 40)) + 1)) if rng.chance(80) else _edge(rng)
        var n = UInt64(rng.below(1_000)) if rng.chance(90) else _edge(rng)
        var mean = max(UInt64(1), budget // max(UInt64(1), n))
        var l = floor + UInt64(rng.below(300))
        if rng.chance(40):
            l = UInt64(rng.below(3 * Int(min(mean, 1 << 40)) + 1))
        elif rng.chance(10):
            l = _edge(rng)
        var open_c = UInt64(rng.below(400)) if rng.chance(90) else _edge(rng)
        var w = conn_limit(l, open_c, budget, work, n, cap)
        var tag = "case " + String(c) + ": "
        var share = min(cap, max(floor, mean))
        assert_true(w >= floor and w <= cap, tag + "within [floor, CAP]")
        assert_true(w >= min(l, cap) // 2, tag + "at most one halving per interval")
        if w > l:
            assert_true(w <= max(floor, 2 * mean) or 2 * mean < mean, tag + "lends at most 2x the mean")
        if work >= budget:
            assert_true(w >= min(l, share), tag + "no spare: never cut below the share")
            if open_c > l:
                assert_true(w == min(max(l, floor), cap), tag + "no second cut before the first took effect")
    assert_true(conn_limit(40, 500, UNLIMITED, 10_000, 3, 100) == 100, "unlimited gives CAP")
    assert_true(conn_limit(32, 10, 853, 2_000, 200, 100) == 16, "credit halves below 32 under pressure")
    assert_true(conn_limit(6, 6, 853, 2_000, 200, 100) == 4, "down to the even split")
    assert_true(conn_limit(4, 4, 147, 2_000, 200, 100) == MIN_CREDIT, "never below MIN_CREDIT")


def test_refuse_only_culprits() raises:
    """503 only under pressure and only above `max(1, budget / active)`, with no 32 floor; the credit share is the same split, at least MIN_CREDIT."""
    var rng = Rng(0xC011)
    for c in range(prop_iters(300)):
        var cap = _rand_cap(rng)
        var s = _rand_state(rng, cap)
        var active = UInt64(rng.below(500)) if rng.chance(90) else _edge(rng)
        var open_c = UInt64(rng.below(2_000)) if rng.chance(90) else _edge(rng)
        var x = _rand_sample(rng, UInt64(5_000), -1)
        x.active = active
        var d = step(s, x, 5_000, cap)
        var tag = "case " + String(c) + ": "
        if open_c > d.shed_above:
            assert_true(_pressure(s) and open_c > max(UInt64(1), s.budget // max(UInt64(1), active)), tag + "sheds only above the share under pressure")
        if _pressure(s):
            assert_true(d.shed_above >= 1 and d.shed_above <= max(UInt64(1), s.budget // max(UInt64(1), active)), tag + "no floor on the 503 threshold")
        assert_true(d.share == (max(min(MIN_CREDIT, cap), d.shed_above) if _pressure(s) else UNLIMITED), tag + "credit share = the 503 split, floored at MIN_CREDIT")


def test_shed_threshold_binds_with_many_connections() raises:
    """200 connections x 10 in flight: the credit share comes down to the 503 split, never below MIN_CREDIT."""
    var s = GovState()
    s.mode, s.budget, s.since_cut = Mode.HOLDING, 147, 0
    var d = step(s, Sample(delay_us=100_000, done=3_000, work=2_000, active=200), 5_000, 100)
    assert_true(d.share == MIN_CREDIT and d.shed_above == 1, "share " + String(d.share) + ", shed above " + String(d.shed_above))
    s.mode, s.budget, s.since_cut = Mode.HOLDING, 147, 0
    d = step(s, Sample(delay_us=100_000, done=3_000, work=2_000, active=10), 5_000, 100)
    assert_true(d.shed_above == 14 and d.share == 14, "budget / active: " + String(d.shed_above))
    s.mode, s.budget, s.since_cut = Mode.HOLDING, 853, 0
    d = step(s, Sample(delay_us=100_000, done=3_000, work=2_000, active=200), 5_000, 100)
    assert_true(d.share == 4 and d.shed_above == 4, "the local overload smoke's split: " + String(d.share))


def test_fluid_recovery_model() raises:
    """Capacity mu, load 0.5 mu, then 2 mu for 20 intervals, then 0.5 mu: the governor settles and releases.

    Each interval is 20 ticks of `t`. Outstanding work (queued and in
    service) is capped by the budget (stream credit, the excess waits at
    the client), and while under pressure the excess is refused (503). A
    tick's wait is the work ahead over the per-tick capacity.
    """
    var t = UInt64(5_000)
    var mu_tick = UInt64(100)
    var s = GovState()
    var h = DelayHist()
    var queue = UInt64(0)
    var client_q = UInt64(0)
    var surge_end = 30
    var delay_ok_at = -1
    var released_at = -1
    for i in range(200):
        var load = 4 * mu_tick // 2 if i >= 10 and i < surge_end else mu_tick // 2
        var done = UInt64(0)
        var refused = UInt64(0)
        var work = UInt64(0)
        for _ in range(20):
            var demand = load + client_q
            var admit = min(demand, s.budget - min(s.budget, queue))
            if _pressure(s):
                refused += demand - admit
                client_q = 0
            else:
                client_q = demand - admit
            queue += admit
            work = queue
            h.insert(queue * t // mu_tick)
            var served = min(queue, mu_tick)
            queue -= served
            done += served
        var delay = h.close_delay()
        _ = step(s, Sample(delay_us=delay, done=done, work=work, active=10), t, 100)
        if i >= surge_end:
            if delay_ok_at < 0 and delay <= t:
                delay_ok_at = i
            if released_at < 0 and s.budget == UNLIMITED:
                released_at = i
            if released_at >= 0:
                assert_true(refused == 0, "interval " + String(i) + ": no refusals after release")
        elif i >= 12:
            assert_true(s.budget != UNLIMITED, "interval " + String(i) + ": surge is governed")
    assert_true(s.cuts > 0, "the surge cut the budget")
    assert_true(delay_ok_at >= 0 and delay_ok_at - surge_end < 10, "wait back under target within 10 intervals: " + String(delay_ok_at))
    assert_true(released_at >= 0 and released_at - surge_end <= RELEASE + 2, "released within RELEASE + 2: " + String(released_at))


def test_want_rmem() raises:
    var now = UInt64(1_000_000)
    var g = Governor(5_000, now)
    for p in range(17):
        assert_true(g.want_rmem() == (p % 16 == 0), "pass " + String(p) + ": only every 16th pass while ingest drains")
        g.on_ingest(None, 5, True)
        now += 1_000
        g.on_pass(now, now - 100)
    g.on_ingest(None, 40, False)
    assert_true(g.want_rmem(), "after an ingest that left datagrams queued")


def test_facade_interval_close() raises:
    """An idle interval of reads, then 25 passes of 10 requests behind 20 ms of socket queue; then an idle gap."""
    var now = UInt64(1_000_000)
    var g = Governor(5_000, now)
    assert_true(g.decision.share == UNLIMITED and g.decision.budget == UNLIMITED and g.decision.retry_after_s == 1, "starts open")
    for _ in range(50):
        g.on_ingest(UInt64(10) * DATAGRAM_TRUESIZE, 10, True)
        now += 1_000
        g.on_pass(now, now - 100)
    now = 1_100_000
    assert_true(g.close_due(now), "close due after one interval")
    g.close(now, 500, 50, 10, 100)
    assert_true(g.stats.state.mode == Mode.NORMAL and g.stats.queue_delay_us == 0, "idle")
    for _ in range(25):
        g.on_ingest(UInt64(100) * DATAGRAM_TRUESIZE, 10, False)
        g.requests += 10
        now += 3_000
        g.on_pass(now, now - 1_000)
    assert_true(g.kwait == 20_000 and g.requests == 0, "20 ms of socket queue; requests consumed per pass")
    assert_true(not g.close_due(now), "interval still open")
    now = 1_200_000
    g.close(now, 2_500, 400, 10, 100)
    var st = g.stats.copy()
    assert_true(st.state.mode == Mode.CUTTING and st.decision.budget != UNLIMITED and st.state.cuts == 1, "over target: one cut")
    assert_true(st.queue_delay_us >= 16_384 and st.kernel_wait_us == 20_000, "p90 wait " + String(st.queue_delay_us))
    assert_true(st.intervals == 2 and g.decision.shed_above == g.decision.budget // 10, "503 threshold published")
    for _ in range(30):
        g.requests += 10
        now += 1_000
        g.on_pass(now, now - 100)
    now += 150_000
    g.requests = 5
    g.on_pass(now, now - 100)
    g.close(now, 5, 1, 10, 100)
    assert_true(g.stats.queue_delay_us == 0 and g.state.mode == Mode.RECOVERING and g.decision.share == UNLIMITED, "an idle gap drops the stale samples")
    g.refused_503 += 3
    g.close(now + 100_000, 0, 0, 0, 100)
    assert_true(g.stats.refused_streams_503 == 3, "503 count reaches the stats at close")
    assert_true(g.stats.slow_handler_warnings == 0, "a cut over 10 active connections is real overload")


def _overloaded_close(mut g: Governor, mut now: UInt64, active: UInt64):
    """One interval of 25 passes, 10 requests each spread over 20 ms of pass, closed with little open work."""
    for _ in range(25):
        g.requests += 10
        now += 3_000
        g.on_pass(now, now - 20_000)
    g.close(now, 50, 1, active, 100)


def test_slow_handler_warning() raises:
    """Cutting with few active connections points at handlers slower than the dial: warned once per WARN_EVERY closes."""
    var now = UInt64(1_000_000)
    var g = Governor(5_000, now)
    _overloaded_close(g, now, FEW_ACTIVE)
    assert_true(g.state.mode == Mode.CUTTING and g.stats.slow_handler_warnings == 1, "warned on the first cut")
    _overloaded_close(g, now, FEW_ACTIVE)
    assert_true(g.state.cuts == 2 and g.stats.slow_handler_warnings == 1, "not again within WARN_EVERY closes")
    for _ in range(WARN_EVERY):
        _overloaded_close(g, now, FEW_ACTIVE)
    assert_true(g.stats.slow_handler_warnings == 2, "again after WARN_EVERY closes")
    var h = Governor(5_000, now)
    _overloaded_close(h, now, FEW_ACTIVE + 1)
    assert_true(h.state.cuts == 1 and h.stats.slow_handler_warnings == 0, "not with more active connections")


def main() raises:
    test_p90_exact_property()
    test_insert_pass_and_reset()
    test_derived_constants()
    test_kwait_bounds_property()
    test_kwait_under_sustained_overload()
    test_close_delay()
    test_step_properties()
    test_refuse_new_needs_a_streak_at_the_floor()
    test_cut_grow_release_rules()
    test_credit_held_outside_the_server_is_kept()
    test_recovery_and_liveness()
    test_conn_limit_properties()
    test_refuse_only_culprits()
    test_shed_threshold_binds_with_many_connections()
    test_fluid_recovery_model()
    test_want_rmem()
    test_facade_interval_close()
    test_slow_handler_warning()
    print("PASS: test_governor")
