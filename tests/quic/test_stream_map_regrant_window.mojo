"""StreamMap's bidi re-grant window: identity by default, narrowed and released through `apply_budget`.

No streams are created: the tests drive `peer_opened_bidi` (O) and `peer_completed_bidi` (D)
directly and call the re-grant methods, so MAX_STREAMS = M = `local_max_streams_bidi`.
"""

from navette.quic.stream_map import StreamMap
from navette.protect.governor import UNLIMITED, MIN_CREDIT
from tests._test_util import assert_true
from tests.protect._prop import Rng, prop_iters


def _map(initial: UInt64) -> StreamMap:
    return StreamMap(
        is_server=True,
        conn_recv_limit=UInt64(1 << 20),
        conn_recv_window=UInt64(1 << 20),
        conn_send_limit=UInt64(0),
        local_max_streams_bidi=initial,
        local_max_streams_uni=UInt64(3),
        local_window_bidi_local=UInt64(1 << 16),
        local_window_bidi_remote=UInt64(1 << 16),
        local_window_uni=UInt64(1 << 16),
    )


def _complete(mut sm: StreamMap, k: UInt64):
    sm.peer_opened_bidi = max(sm.peer_opened_bidi, sm.peer_completed_bidi + k)
    sm.peer_completed_bidi += k
    sm.check_max_streams_update()


def test_window_default_is_identity() raises:
    """Without a budget the grants are today's: M = max(M, D + initial)."""
    var rng = Rng(0x7E61)
    for c in range(prop_iters(300)):
        var sm = _map(100)
        for _ in range(20):
            var prev = sm.local_max_streams_bidi
            _complete(sm, UInt64(rng.below(30)))
            var want = max(prev, sm.peer_completed_bidi + 100)
            assert_true(sm.local_max_streams_bidi == want, "case " + String(c) + ": M " + String(sm.local_max_streams_bidi))


def test_narrow_window_delays_grants() raises:
    var sm = _map(100)
    sm.regrant_window = 10
    _complete(sm, 90)
    assert_true(sm.local_max_streams_bidi == 100 and not sm.needs_max_streams_bidi, "no grant up to D = 90")
    _complete(sm, 1)
    assert_true(sm.local_max_streams_bidi == 101 and sm.needs_max_streams_bidi, "D = 91 grants one")
    _complete(sm, 1)
    assert_true(sm.local_max_streams_bidi == 102, "then one per completion")


def test_release_grants_at_once() raises:
    var sm = _map(100)
    sm.regrant_window = 10
    _complete(sm, 5)
    assert_true(not sm.needs_max_streams_bidi, "narrowed: no grant yet")
    assert_true(sm.apply_budget(UNLIMITED, 0, 1), "release reports a grant")
    assert_true(sm.needs_max_streams_bidi, "MAX_STREAMS pending")
    assert_true(sm.local_max_streams_bidi == 105 and sm.regrant_window == 100, "M = D + initial")
    assert_true(not sm.apply_budget(UNLIMITED, 0, 1), "second release grants nothing new")


def test_monotone_credit_property() raises:
    """M never decreases and the outstanding credit never exceeds max(window, previous credit)."""
    var rng = Rng(0x40A0)
    for c in range(prop_iters(300)):
        var sm = _map(UInt64(1 + rng.below(200)))
        for _ in range(30):
            var prev = sm.local_max_streams_bidi
            var prev_credit = prev - sm.peer_completed_bidi
            if rng.chance(50):
                sm.peer_opened_bidi = min(prev, sm.peer_opened_bidi + UInt64(rng.below(50)))
                var budget = UNLIMITED if rng.chance(20) else UInt64(rng.below(500))
                _ = sm.apply_budget(budget, UInt64(rng.below(1000)), UInt64(1 + rng.below(20)))
            else:
                _complete(sm, min(UInt64(rng.below(10)), sm.peer_opened_bidi - sm.peer_completed_bidi))
            var m = sm.local_max_streams_bidi
            var w = sm.regrant_window
            assert_true(m >= prev, "case " + String(c) + ": M decreased")
            assert_true(m - sm.peer_completed_bidi <= max(w, prev_credit), "case " + String(c) + ": credit over window")
            assert_true(w >= 1 and w <= sm.initial_max_streams_bidi, "case " + String(c) + ": window outside [1, initial]")


def test_floor_and_one_step() raises:
    var sm = _map(100)
    for _ in range(10):
        _ = sm.apply_budget(1, 100_000, 1000)
    assert_true(sm.regrant_window == MIN_CREDIT, "tiny budget stops at MIN_CREDIT: " + String(sm.regrant_window))
    var small = _map(1)
    _ = small.apply_budget(1, 100_000, 1000)
    assert_true(small.regrant_window == 1, "floor is min(MIN_CREDIT, initial)")
    var one = _map(100)
    one.peer_opened_bidi = 80
    _ = one.apply_budget(64, 1000, 1)
    var w = one.regrant_window
    assert_true(w < 100 and w < 80, "first over-budget call narrows: " + String(w))
    _ = one.apply_budget(64, 1000, 1)
    assert_true(one.regrant_window == w, "no second cut while O - D > w")


def test_narrowed_start_released() raises:
    """A connection built with 32 (narrowed at the door) and ceiling 100 is raised to D + 100."""
    var sm = _map(32)
    sm.initial_max_streams_bidi = 100
    _complete(sm, 7)
    assert_true(sm.local_max_streams_bidi == 39, "narrowed start re-grants D + 32")
    assert_true(sm.apply_budget(UNLIMITED, 0, 1), "release grants")
    assert_true(sm.local_max_streams_bidi == 107, "M = D + 100")


def test_clamp_to_initial() raises:
    var sm = _map(1)
    _ = sm.apply_budget(0, 100_000, 1000)
    assert_true(sm.regrant_window == 1, "never below 1")
    _ = sm.apply_budget(100_000, 0, 1)
    assert_true(sm.regrant_window == 1, "never above initial")


def main() raises:
    var failed = 0
    try:
        test_window_default_is_identity()
    except e:
        print("FAIL test_window_default_is_identity:", e)
        failed += 1
    try:
        test_narrow_window_delays_grants()
    except e:
        print("FAIL test_narrow_window_delays_grants:", e)
        failed += 1
    try:
        test_release_grants_at_once()
    except e:
        print("FAIL test_release_grants_at_once:", e)
        failed += 1
    try:
        test_monotone_credit_property()
    except e:
        print("FAIL test_monotone_credit_property:", e)
        failed += 1
    try:
        test_floor_and_one_step()
    except e:
        print("FAIL test_floor_and_one_step:", e)
        failed += 1
    try:
        test_narrowed_start_released()
    except e:
        print("FAIL test_narrowed_start_released:", e)
        failed += 1
    try:
        test_clamp_to_initial()
    except e:
        print("FAIL test_clamp_to_initial:", e)
        failed += 1
    if failed:
        raise Error(String(failed) + " failed")
    print("PASS: test_stream_map_regrant_window")
