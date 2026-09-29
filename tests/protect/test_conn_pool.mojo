"""ConnPool: invariants under random operation sequences, fair share, tie-break, spoofed inflation."""

from navette.protect.conn_pool import (
    ConnPool,
    AdmitOutcome,
    ADMIT,
    ADMIT_EVICT_UNVALIDATED,
    ADMIT_EVICT_FAIR,
    REJECT,
    POOL_FREE,
    POOL_ADMITTED,
    POOL_CLOSING,
    CLOSE_DRAIN,
    CLOSE_FLUSH,
    CLOSE_QUIC,
    CLOSING_REFUSED,
    DRAIN_DEADLINE_US,
)
from navette.protect.ready_list import ReadyList
from navette.protect.descriptor_budget import MAX_CONN_CAP, MAX_CLOSING_CAP
from navette.protect.source_key import SourceKey, source_key_from_sockaddr
from navette.util.siphash import SipKey
from tests._test_util import assert_true, assert_equal_int
from tests.protect._prop import Rng, sockaddr_in


def src(i: Int) -> SourceKey:
    """Source `i` as the IPv4 host 10.0.x.y."""
    return source_key_from_sockaddr(Span(sockaddr_in(10, 0, UInt8((i >> 8) & 0xFF), UInt8(i & 0xFF), 1000 + i)), 48)


def _pool(cap: Int, closing: Int) raises -> ConnPool:
    return ConnPool(cap, closing, SipKey(k0=UInt64(11), k1=UInt64(22)))


def _check(p: ConnPool, ctx: String) raises:
    var v = p.invariant_violation()
    assert_true(v == "", ctx + ": " + v)


def _assert_victim_above_fair_share(counts: List[Int], s: Int, victim_src: Int, conn_cap: Int, ctx: String) raises:
    """A fair eviction never takes from a source at or below ⌊conn_cap / k⌋, k counting the newcomer.

    `counts` are the validated counts before the admission; `s` is the newcomer's source.
    """
    var k = 0
    for j in range(len(counts)):
        if counts[j] > 0 or j == s:
            k += 1
    assert_true(
        counts[victim_src] > conn_cap // k,
        ctx + " victim source " + String(victim_src) + " holds " + String(counts[victim_src])
        + " <= fair share " + String(conn_cap // k),
    )
    assert_true(counts[victim_src] > counts[s] + 1, ctx + " victim source exceeds the newcomer by 2+")


def _pick(mut rng: Rng, p: ConnPool, pool: UInt8) -> Int:
    """A random id currently in `pool`, -1 when none."""
    var n = p.conn_cap + p.closing_cap
    var start = rng.below(n)
    for k in range(n):
        var id = (start + k) % n
        if p.pool_of(id) == pool:
            return id
    return -1


def _closing_deadlines(p: ConnPool) -> List[Int]:
    """Deadline of every closing id, -1 for the others; a snapshot taken before a call that may reuse ids."""
    var out = List[Int](length=p.conn_cap + p.closing_cap, fill=-1)
    for id in range(len(out)):
        if p.pool_of(id) == POOL_CLOSING:
            out[id] = Int(p.closing_deadline(id))
    return out^


def _earliest_own_deadline(deadlines: List[Int], owner: List[Int], s: Int) -> Int:
    """Earliest snapshot deadline among closing entries of oracle source `s`, -1 when none."""
    var best = -1
    for id in range(len(deadlines)):
        if deadlines[id] >= 0 and owner[id] == s and (best < 0 or deadlines[id] < best):
            best = deadlines[id]
    return best


def _assert_room_rule(
    deadlines: List[Int], owner: List[Int], full: Bool, own: Int, s: Int, forced: Int, ctx: String
) raises:
    """A full closing pool gives up the requester's own earliest entry, else refuses; a non-full one forces nothing.

    `own` is the earliest own deadline before the call (-1: none);
    `deadlines` and `owner` are pre-call snapshots,
    since the forced id may already be reused.
    """
    if not full:
        assert_equal_int(forced, -1, ctx + ": room without forcing")
    elif own < 0:
        assert_equal_int(forced, CLOSING_REFUSED, ctx + ": refused without an own entry")
    else:
        assert_true(forced >= 0, ctx + ": own entry force-closed")
        assert_equal_int(owner[forced], s, ctx + ": forced entry belongs to the requester's source")
        assert_equal_int(deadlines[forced], own, ctx + ": and has its earliest deadline")


def test_invariants_under_random_ops_property() raises:
    """25 seeds × 3,000 ops over admit/validate/touch/busy/handshake/closing/release/expiry.

    Every closing-room decision (drain, to_closing, flush) is checked
    against the own-source rule with an oracle owner map; an unvalidated
    id is always refused.
    """
    for seed in range(25):
        var rng = Rng(UInt64(0xC0 + seed))
        var cap = 4 + rng.below(40)
        var ccap = 1 + rng.below(12)
        var p = _pool(cap, ccap)
        var nsrc = 1 + rng.below(12)
        var now = UInt64(1_000_000)
        var last_adm = List[UInt64](length=nsrc, fill=UInt64(0))
        var owner = List[Int](length=cap + ccap, fill=-1)  # source index per id, oracle side
        var tick = UInt64(0)
        for op in range(3000):
            now += UInt64(rng.below(50_000))
            var ctx = "seed " + String(seed) + " op " + String(op)
            var r = rng.below(100)
            if r < 35:
                var s = rng.below(nsrc)
                var validated = rng.chance(70)
                var before = List[Int](capacity=nsrc)
                for j in range(nsrc):
                    before.append(p.count_of(src(j)))
                var largest = p.largest_count()
                var had_unvalidated = p.unvalidated > 0
                var at_cap = p.admitted >= p.conn_cap
                # The expected victim source: max count, ties to the latest admission.
                var want_victim_src = -1
                for j in range(nsrc):
                    if before[j] == 0:
                        continue
                    if want_victim_src < 0 or before[j] > before[want_victim_src] or (
                        before[j] == before[want_victim_src] and last_adm[j] > last_adm[want_victim_src]
                    ):
                        want_victim_src = j
                var full = p.closing == p.closing_cap
                var dl = _closing_deadlines(p)
                var refused_before = p.closing_refused
                var killed_before = p.busy_victims_killed
                var out = p.admit(src(s), validated, rng.chance(50), now)
                var killed = Int(p.busy_victims_killed - killed_before)
                assert_equal_int(Int(p.closing_refused - refused_before), killed, ctx + " only a killed busy victim is refused")
                if killed == 1:
                    assert_true(full and out.kind == ADMIT_EVICT_FAIR and not out.victim_drains, ctx + " killed: full pool, fair victim")
                if out.victim >= 0 and out.victim_drains:
                    var vs = owner[out.victim]
                    _assert_room_rule(dl, owner, full, _earliest_own_deadline(dl, owner, vs), vs, out.forced, ctx + " drain")
                elif out.victim >= 0:
                    assert_equal_int(out.forced, -1, ctx + " a killed victim forces nothing")
                if not at_cap:
                    assert_equal_int(out.kind, ADMIT, ctx + " below cap admits")
                elif validated and had_unvalidated:
                    assert_equal_int(out.kind, ADMIT_EVICT_UNVALIDATED, ctx + " unvalidated evicted first")
                elif validated and before[s] + 1 < largest:
                    # Fair-share guarantee: a smaller validated source always gets in.
                    assert_equal_int(out.kind, ADMIT_EVICT_FAIR, ctx + " fair share admits")
                    assert_equal_int(owner[out.victim], want_victim_src, ctx + " victim from the largest, most recent source")
                    _assert_victim_above_fair_share(before, s, owner[out.victim], p.conn_cap, ctx)
                else:
                    assert_equal_int(out.kind, REJECT, ctx + " otherwise rejected")
                if out.id >= 0:
                    owner[out.id] = s  # after the victim check: the victim's id may be reused
                if not validated:
                    for j in range(nsrc):
                        assert_equal_int(p.count_of(src(j)), before[j], ctx + " unvalidated admit changes no count")
                elif out.kind != REJECT:
                    tick += 1
                    last_adm[s] = tick
            elif r < 45:
                var id = _pick(rng, p, POOL_ADMITTED)
                if id >= 0 and not p.is_validated(id):
                    p.validate(id)
                    tick += 1
                    last_adm[owner[id]] = tick
            elif r < 55:
                var id = _pick(rng, p, POOL_ADMITTED)
                if id >= 0:
                    p.touch(id)
            elif r < 65:
                var id = _pick(rng, p, POOL_ADMITTED)
                if id >= 0:
                    p.set_busy(id, rng.chance(50))
            elif r < 70:
                var id = _pick(rng, p, POOL_ADMITTED)
                if id >= 0:
                    p.handshake_done(id)
            elif r < 78:
                var id = _pick(rng, p, POOL_ADMITTED)
                if id >= 0:
                    var validated = p.is_validated(id)
                    var full = p.closing == p.closing_cap
                    var dl = _closing_deadlines(p)
                    var own = _earliest_own_deadline(dl, owner, owner[id])
                    var refused_before = p.closing_refused
                    var forced = p.to_closing(id, now + UInt64(rng.below(3_000_000)), CLOSE_QUIC)
                    var counted = Int(p.closing_refused - refused_before)
                    assert_equal_int(counted, 1 if validated and forced == CLOSING_REFUSED else 0, ctx + " refusal counted")
                    if validated:
                        _assert_room_rule(dl, owner, full, own, owner[id], forced, ctx + " to_closing")
                    else:
                        assert_equal_int(forced, CLOSING_REFUSED, ctx + " unvalidated never enters closing")
                    if forced == CLOSING_REFUSED:
                        assert_equal_int(Int(p.pool_of(id)), Int(POOL_ADMITTED), ctx + " refused id stays admitted")
                        p.release(id)
                    else:
                        assert_equal_int(Int(p.pool_of(id)), Int(POOL_CLOSING), ctx + " entered closing")
            elif r < 82:
                var es = rng.below(nsrc)
                var full = p.closing == p.closing_cap
                var dl = _closing_deadlines(p)
                var own = _earliest_own_deadline(dl, owner, es)
                var refused_before = p.closing_refused
                var e = p.enter_closing(src(es), now + UInt64(2_000_000), CLOSE_FLUSH)
                assert_equal_int(Int(p.closing_refused - refused_before), 1 if e.id < 0 else 0, ctx + " refused flush counted")
                _assert_room_rule(dl, owner, full, own, es, e.forced if e.id >= 0 else CLOSING_REFUSED, ctx + " enter_closing")
                if e.id >= 0:
                    owner[e.id] = es
                    assert_equal_int(Int(p.pool_of(e.id)), Int(POOL_CLOSING), ctx + " entered closing")
                else:
                    assert_equal_int(e.forced, -1, ctx + " a refused flush forces nothing")
            elif r < 95:
                var id = _pick(rng, p, POOL_ADMITTED if rng.chance(70) else POOL_CLOSING)
                if id >= 0:
                    p.release(id)
                    assert_equal_int(Int(p.pool_of(id)), Int(POOL_FREE), ctx + " released")
            else:
                var e = p.pop_expired_closing(now)
                if e >= 0:
                    assert_equal_int(Int(p.pool_of(e)), Int(POOL_FREE), ctx + " expired entry freed")
            _check(p, ctx)
    print("PASS: test_invariants_under_random_ops_property")


def test_fair_share_convergence_property() raises:
    """With k demanding sources at the cap each end with ≥ ⌊cap/k⌋ connections (40 random configurations)."""
    for seed in range(40):
        var rng = Rng(UInt64(0xFA1 + seed))
        var cap = 16 + rng.below(100)
        var k = 2 + rng.below(12)
        var p = _pool(cap, 8)
        var owner = List[Int](length=cap + 8, fill=-1)
        # Source 0 grabs everything first, as a single-host attacker would.
        for _ in range(cap):
            owner[p.admit(src(0), True, False, UInt64(0)).id] = 0
        for i in range(20 * cap):
            var ctx = "convergence seed " + String(seed) + " admission " + String(i)
            var s = rng.below(k)
            var before = List[Int](capacity=k)
            for j in range(k):
                before.append(p.count_of(src(j)))
            var id_out = p.admit(src(s), True, False, UInt64(0))
            if id_out.kind == ADMIT_EVICT_FAIR:
                _assert_victim_above_fair_share(before, s, owner[id_out.victim], cap, ctx)
            if id_out.id >= 0:
                owner[id_out.id] = s
                if rng.chance(30):
                    p.set_busy(id_out.id, True)
            _check(p, ctx)
        for s in range(k):
            assert_true(p.count_of(src(s)) >= cap // k, "seed " + String(seed) + " source " + String(s) + " holds its share")
    print("PASS: test_fair_share_convergence_property")


def test_fair_share_at_scale_property() raises:
    """4,096 slots, 1,000 sources, a hot tenth of them sending half the load; 3 seeds × 30,000 operations."""
    comptime CAP = 4096
    comptime CLOSING = 64
    comptime NSRC = 1000
    for seed in range(3):
        var rng = Rng(UInt64(0x5CA1E + seed))
        var p = _pool(CAP, CLOSING)
        var owner = List[Int](length=CAP + CLOSING, fill=-1)
        var cnt = List[Int](length=NSRC, fill=0)  # oracle validated counts
        var fair_evictions = 0
        for op in range(30000):
            var ctx = "scale seed " + String(seed) + " op " + String(op)
            if rng.chance(90):
                var s = rng.below(NSRC // 10) if rng.chance(50) else rng.below(NSRC)
                var out = p.admit(src(s), True, False, UInt64(op))
                if out.kind == ADMIT_EVICT_FAIR:
                    _assert_victim_above_fair_share(cnt, s, owner[out.victim], CAP, ctx)
                    fair_evictions += 1
                if out.victim >= 0:
                    cnt[owner[out.victim]] -= 1
                if out.id >= 0:
                    owner[out.id] = s
                    cnt[s] += 1
                    if rng.chance(30):
                        p.set_busy(out.id, True)
            else:
                var id = _pick(rng, p, POOL_ADMITTED)
                if id >= 0:
                    p.release(id)
                    cnt[owner[id]] -= 1
            if op % 1000 == 999:
                _check(p, ctx)
                for j in range(NSRC):
                    assert_equal_int(p.count_of(src(j)), cnt[j], ctx + " count of source " + String(j))
        assert_true(fair_evictions > 1000, "scale seed " + String(seed) + " exercised fair eviction: " + String(fair_evictions))
    print("PASS: test_fair_share_at_scale_property")


def test_tie_goes_to_most_recent_admission() raises:
    var p = _pool(4, 4)
    _ = p.admit(src(1), True, False, UInt64(0))
    var b1 = p.admit(src(2), True, False, UInt64(0)).id
    _ = p.admit(src(1), True, False, UInt64(0))
    var b2 = p.admit(src(2), True, False, UInt64(0)).id  # src 2 admitted last; tie at 2 each
    var out = p.admit(src(3), True, False, UInt64(0))
    assert_equal_int(out.kind, ADMIT_EVICT_FAIR, "newcomer gets in")
    assert_true(out.victim == b1 or out.victim == b2, "the most recently admitted tied source loses")
    assert_equal_int(p.count_of(src(2)), 1, "it drops to 1")
    assert_equal_int(p.count_of(src(1)), 2, "the older tied source keeps both")
    print("PASS: test_tie_goes_to_most_recent_admission")


def test_idle_victim_preferred_busy_victim_drains() raises:
    var p = _pool(3, 4)
    var a = p.admit(src(1), True, False, UInt64(0)).id
    var b = p.admit(src(1), True, False, UInt64(0)).id
    var c = p.admit(src(1), True, False, UInt64(0)).id
    p.set_busy(a, True)
    p.set_busy(c, True)
    var out = p.admit(src(2), True, False, UInt64(5))
    assert_equal_int(out.victim, b, "the idle connection goes first")
    assert_true(not out.victim_drains, "idle victim is killed")
    assert_equal_int(out.id, b, "its released id is the one handed to the newcomer")
    assert_equal_int(p.count_of(src(1)), 2, "source 1 lost one connection")
    assert_equal_int(Int(p.busy_victims_killed), 0, "an idle victim is not a killed busy one")
    var out2 = p.admit(src(3), True, False, UInt64(5))
    assert_equal_int(out2.victim, a, "least recently active busy connection next")
    assert_true(out2.victim_drains, "busy victim drains")
    assert_equal_int(Int(p.pool_of(a)), Int(POOL_CLOSING), "it sits in the closing pool")
    assert_true(p.closing_deadline(a) == UInt64(5) + DRAIN_DEADLINE_US, "with the 10 s drain deadline")
    _check(p, "idle/busy victims")
    print("PASS: test_idle_victim_preferred_busy_victim_drains")


def test_activity_does_not_protect() raises:
    """Touching a connection reorders within its source but never changes which source loses."""
    var p = _pool(4, 4)
    var ids = List[Int]()
    for _ in range(3):
        ids.append(p.admit(src(1), True, False, UInt64(0)).id)
    _ = p.admit(src(2), True, False, UInt64(0))
    p.touch(ids[0])
    var out = p.admit(src(3), True, False, UInt64(0))
    assert_equal_int(out.victim, ids[1], "LRU head after the touch")
    print("PASS: test_activity_does_not_protect")


def test_spoofed_initials_cannot_inflate_victim() raises:
    """256 token-less slots carrying the victim's key: its count, sources_active and connections are untouched."""
    var p = _pool(300, 16)
    var v1 = p.admit(src(7), True, False, UInt64(0)).id
    var sources_before = p.sources_active()
    for _ in range(256):
        _ = p.admit(src(7), False, True, UInt64(0))
    assert_equal_int(p.count_of(src(7)), 1, "spoofed slots do not count")
    assert_equal_int(p.sources_active(), sources_before, "nor create a source")
    assert_equal_int(p.unvalidated, 256, "they are unvalidated")
    var s = 100
    while p.admitted < p.conn_cap:
        _ = p.admit(src(s), True, False, UInt64(0))
        s += 1
    var back = p.admit(src(7), True, False, UInt64(0))
    assert_equal_int(back.kind, ADMIT_EVICT_UNVALIDATED, "the victim's reconnect evicts a spoofed slot")
    assert_equal_int(Int(p.pool_of(v1)), Int(POOL_ADMITTED), "none of the victim's connections is evicted")
    assert_equal_int(p.count_of(src(7)), 2, "victim now holds 2")
    _check(p, "spoofed inflation")
    print("PASS: test_spoofed_initials_cannot_inflate_victim")


def test_transitions_on_ids_in_any_state_property() raises:
    """20 seeds × 3,000 ops calling every transition on arbitrary ids, including wrong-state and repeated calls."""
    for seed in range(20):
        var rng = Rng(UInt64(0x57A7E + seed))
        var cap = 2 + rng.below(20)
        var ccap = 1 + rng.below(6)
        var p = _pool(cap, ccap)
        var n = cap + ccap
        var nsrc = 1 + rng.below(6)
        for op in range(3000):
            var ctx = "seed " + String(seed) + " op " + String(op)
            var id = rng.below(n)
            var state = p.pool_of(id)
            var r = rng.below(9)
            if r == 0:
                _ = p.admit(src(rng.below(nsrc)), rng.chance(60), rng.chance(50), UInt64(op))
            elif r == 1:
                _ = p.enter_closing(src(rng.below(nsrc)), UInt64(op + rng.below(100)), CLOSE_FLUSH)
            elif r == 2:
                var admitted = p.admitted
                var closing = p.closing
                var unvalidated = state == POOL_ADMITTED and not p.is_validated(id)
                var forced = p.to_closing(id, UInt64(op + rng.below(100)), CLOSE_DRAIN)
                if unvalidated:
                    assert_equal_int(forced, CLOSING_REFUSED, ctx + " an unvalidated id is refused")
                    assert_equal_int(Int(p.pool_of(id)), Int(POOL_ADMITTED), ctx + " and stays admitted")
                    assert_equal_int(p.closing, closing, ctx + " closing unchanged")
                elif state != POOL_ADMITTED:
                    assert_equal_int(forced, -1, ctx + " to_closing on a non-admitted id forces nothing")
                    assert_equal_int(Int(p.pool_of(id)), Int(state), ctx + " and leaves its pool alone")
                    assert_equal_int(p.admitted, admitted, ctx + " admitted unchanged")
                    assert_equal_int(p.closing, closing, ctx + " closing unchanged")
            elif r == 3:
                p.release(id)
            elif r == 4:
                p.validate(id)
            elif r == 5:
                p.touch(id)
            elif r == 6:
                var busy = p.is_busy(id)
                p.set_busy(id, rng.chance(50))
                if state != POOL_ADMITTED:
                    assert_true(p.is_busy(id) == busy, ctx + " set_busy on a non-admitted id is a no-op")
            elif r == 7:
                p.handshake_done(id)
            else:
                _ = p.pop_expired_closing(UInt64(op))
            _check(p, ctx)
    print("PASS: test_transitions_on_ids_in_any_state_property")


def test_zero_closing_cap_is_rejected() raises:
    """A pool with no closing room could never drain a busy victim, so construction refuses it."""
    var raised = False
    try:
        _ = _pool(4, 0)
    except:
        raised = True
    assert_true(raised, "closing_cap 0 raises")
    # `conn_cap + closing_cap` sizes every table: out-of-range caps would wrap it.
    for caps in [(Int.MAX - 100, 256), (0, 1), (-5, 4), (MAX_CONN_CAP + 1, 1), (4, MAX_CLOSING_CAP + 1), (4, -1)]:
        var r = False
        try:
            _ = _pool(caps[0], caps[1])
        except:
            r = True
        assert_true(r, "caps " + String(caps[0]) + "/" + String(caps[1]) + " raise")
    print("PASS: test_zero_closing_cap_is_rejected")


def test_closing_pool_bounds() raises:
    var p = _pool(8, 2)
    var a = p.admit(src(1), True, True, UInt64(0)).id
    var b = p.admit(src(1), True, False, UInt64(0)).id
    var c = p.admit(src(1), True, False, UInt64(0)).id
    assert_equal_int(p.handshaking, 1, "one handshaking")
    _ = p.to_closing(a, UInt64(300), CLOSE_DRAIN)
    assert_equal_int(p.handshaking, 0, "entering closing clears the handshake flag")
    assert_true(p.closing_at_most_half_full() and p.closing_at_least_half_full(), "1 of 2 is exactly half")
    _ = p.to_closing(b, UInt64(100), CLOSE_DRAIN)
    var forced = p.to_closing(c, UInt64(200), CLOSE_DRAIN)
    assert_equal_int(forced, b, "full pool force-closes the earliest deadline")
    assert_equal_int(p.pop_expired_closing(UInt64(199)), -1, "nothing expired yet")
    assert_equal_int(p.pop_expired_closing(UInt64(200)), c, "earliest expired entry released")
    _check(p, "closing bounds")
    print("PASS: test_closing_pool_bounds")


def test_none_sentinel_id_is_a_no_op() raises:
    """Every transition called with -1 (the "none" id `admit` and `pop_expired_closing` return) changes nothing.

    The last id is admitted, validated, busy and handshaking, so a
    negative index that wrapped to it would show up as a changed state.
    """
    var p = _pool(2, 1)
    var a = p.admit(src(1), True, False, UInt64(0)).id
    _ = p.admit(src(2), True, False, UInt64(0))
    _ = p.to_closing(a, UInt64(100), CLOSE_DRAIN)
    var last = p.admit(src(3), True, True, UInt64(0)).id
    assert_equal_int(last, 2, "setup: the newest admission holds the last id")
    p.set_busy(last, True)

    def _unchanged(p: ConnPool, last: Int, what: String) raises:
        _check(p, what)
        assert_equal_int(Int(p.pool_of(last)), Int(POOL_ADMITTED), what + " left the last id admitted")
        assert_true(p.is_validated(last), what + " left the last id validated")
        assert_true(p.is_busy(last), what + " left the last id busy")
        assert_true(p.is_handshaking(last), what + " left the last id handshaking")
        assert_equal_int(p.admitted, 2, what + " left admitted alone")
        assert_equal_int(p.closing, 1, what + " left closing alone")

    p.validate(-1)
    _unchanged(p, last, "validate(-1)")
    p.touch(-1)
    _unchanged(p, last, "touch(-1)")
    p.set_busy(-1, False)
    _unchanged(p, last, "set_busy(-1)")
    p.handshake_done(-1)
    _unchanged(p, last, "handshake_done(-1)")
    assert_equal_int(p.to_closing(-1, UInt64(5), CLOSE_DRAIN), -1, "to_closing(-1) forces nothing")
    _unchanged(p, last, "to_closing(-1)")
    p.release(-1)
    _unchanged(p, last, "release(-1)")
    print("PASS: test_none_sentinel_id_is_a_no_op")


def test_none_sentinel_id_reads_neutral() raises:
    """Every read accessor answers the neutral value for -1 instead of reading the last id's state."""
    var p = _pool(2, 1)
    var a = p.admit(src(1), True, False, UInt64(0)).id
    _ = p.admit(src(2), True, False, UInt64(0))
    _ = p.to_closing(a, UInt64(100), CLOSE_DRAIN)
    var last = p.admit(src(3), True, True, UInt64(0)).id
    p.set_busy(last, True)
    assert_equal_int(Int(p.pool_of(-1)), Int(POOL_FREE), "pool_of(-1) is free")
    assert_true(not p.is_validated(-1), "is_validated(-1) is False")
    assert_true(not p.is_busy(-1), "is_busy(-1) is False")
    assert_true(not p.is_handshaking(-1), "is_handshaking(-1) is False")
    assert_equal_int(p.source_of(-1), -1, "source_of(-1) is -1")
    assert_true(p.key_of(-1) == SourceKey(), "key_of(-1) is the empty key")
    assert_true(p.closing_deadline(-1) == UInt64(0), "closing_deadline(-1) is 0")
    assert_equal_int(Int(p.closing_kind(-1)), 0, "closing_kind(-1) is 0")
    print("PASS: test_none_sentinel_id_reads_neutral")


def test_drained_victim_stays_dispatchable() raises:
    """A busy victim moved to the closing pool keeps a dispatch source, so its in-flight request can finish."""
    var p = _pool(3, 4)
    var r = ReadyList(3 + 4, p.dispatch_sources())
    var ids = List[Int]()
    for _ in range(3):
        var id = p.admit(src(1), True, False, UInt64(0)).id
        p.set_busy(id, True)
        r.push(id, p.dispatch_source_of(id))
        ids.append(id)
    var out = p.admit(src(2), True, False, UInt64(5))
    assert_true(out.victim_drains, "busy victim drains")
    var v = out.victim
    assert_equal_int(p.source_of(v), -1, "a draining victim counts towards no source")
    assert_equal_int(p.dispatch_source_of(v), p.dispatch_sources() - 1, "it dispatches as the closing pseudo-source")
    r.push(v, p.dispatch_source_of(v))
    for id in ids:
        if id != v:
            r.remove(id)
    r.begin_pass()
    assert_equal_int(r.next(), v, "the drained victim is dispatched")
    # A never-admitted flush entry dispatches the same way; free and unvalidated ids have no source.
    var flush = p.enter_closing(src(3), UInt64(9), CLOSE_FLUSH).id
    assert_equal_int(p.dispatch_source_of(flush), p.dispatch_sources() - 1, "flush entries too")
    var raised = False
    try:
        r.push(v, p.source_of(v))
    except:
        raised = True
    assert_true(raised, "pushing with the pool source -1 is refused, not dropped")
    assert_equal_int(p.dispatch_source_of(-1), -1, "none id has no dispatch source")
    var q = _pool(2, 1)
    var u = q.admit(src(4), False, True, UInt64(0)).id
    assert_equal_int(q.dispatch_source_of(u), -1, "unvalidated ids have no dispatch source")
    assert_equal_int(q.dispatch_source_of(1), -1, "free ids have no dispatch source")
    q.validate(u)
    assert_equal_int(q.dispatch_source_of(u), q.source_of(u), "validated ids dispatch as their source")
    _check(p, "drained victim")
    print("PASS: test_drained_victim_stays_dispatchable")


def _closing_ids_of(p: ConnPool, key: SourceKey) -> List[Int]:
    var out = List[Int]()
    for id in range(p.conn_cap + p.closing_cap):
        if p.pool_of(id) == POOL_CLOSING and p.key_of(id) == key:
            out.append(id)
    return out^


def test_drain_churn_never_force_closes_another_source() raises:
    """Two-address churn: A holds every slot busy, B connects and leaves, A reconnects.

    Each B admission drains a busy A connection into the full closing pool;
    the entry force-closed for room must be one of A's, never the honest
    flush that has the earliest deadline.
    """
    var p = _pool(64, 4)
    var h = p.admit(src(1), True, False, UInt64(0)).id
    p.set_busy(h, True)
    assert_equal_int(p.to_closing(h, UInt64(2_000_000), CLOSE_FLUSH), -1, "honest flush enters a free slot")
    while p.admitted < p.conn_cap:
        p.set_busy(p.admit(src(2), True, False, UInt64(0)).id, True)
    var now = UInt64(10)
    var forced_count = 0
    for cycle in range(200):
        now += UInt64(1_000)
        var ctx = "cycle " + String(cycle)
        var a_entries = _closing_ids_of(p, src(2))
        var out = p.admit(src(3), True, False, now)
        assert_equal_int(out.kind, ADMIT_EVICT_FAIR, ctx + " B evicts from A")
        assert_true(out.victim_drains, ctx + " the busy A victim drains")
        if out.forced >= 0:
            forced_count += 1
            assert_true(out.forced != h, ctx + " the honest flush is never force-closed")
            var was_a = False
            for e in a_entries:
                if e == out.forced:
                    was_a = True
            assert_true(was_a, ctx + " the force-closed entry is one of A's")
        p.release(out.id)
        p.set_busy(p.admit(src(2), True, False, now).id, True)
        _check(p, ctx)
        assert_equal_int(Int(p.pool_of(h)), Int(POOL_CLOSING), ctx + " honest flush still closing")
        assert_true(p.closing_deadline(h) == UInt64(2_000_000), ctx + " with its own deadline")
    assert_true(forced_count >= 190, "the churn did fill the pool: " + String(forced_count))
    print("PASS: test_drain_churn_never_force_closes_another_source")


def test_full_closing_pool_of_other_sources_kills_the_victim() raises:
    """With no closing entry of the victim's source to give up, the busy victim is closed outright instead of drained."""
    var p = _pool(8, 2)
    var h1 = p.admit(src(1), True, False, UInt64(0)).id
    var h4 = p.admit(src(4), True, False, UInt64(0)).id
    _ = p.to_closing(h1, UInt64(100), CLOSE_FLUSH)
    _ = p.to_closing(h4, UInt64(200), CLOSE_DRAIN)
    while p.admitted < p.conn_cap:
        p.set_busy(p.admit(src(2), True, False, UInt64(0)).id, True)
    var a_before = p.count_of(src(2))
    var out = p.admit(src(3), True, False, UInt64(50))
    assert_equal_int(out.kind, ADMIT_EVICT_FAIR, "the newcomer gets in")
    assert_true(out.victim >= 0 and not out.victim_drains, "the busy victim is killed, not drained")
    assert_equal_int(out.forced, -1, "nothing force-closed")
    assert_equal_int(out.id, out.victim, "the victim's released id goes to the newcomer")
    assert_equal_int(p.count_of(src(2)), a_before - 1, "A lost the connection")
    assert_true(p.pool_of(h1) == POOL_CLOSING and p.pool_of(h4) == POOL_CLOSING, "other sources' entries survive")
    assert_equal_int(p.closing, 2, "closing pool unchanged")
    assert_equal_int(Int(p.busy_victims_killed), 1, "counted as a killed busy victim")
    assert_equal_int(Int(p.closing_refused), 1, "and as a closing refusal")
    _check(p, "victim killed")
    print("PASS: test_full_closing_pool_of_other_sources_kills_the_victim")


def test_full_closing_pool_refuses_other_sources() raises:
    """`to_closing` and `enter_closing` free room only from the requester's own validated source, else refuse."""
    var p = _pool(8, 2)
    var h1 = p.admit(src(1), True, False, UInt64(0)).id
    var h2 = p.admit(src(1), True, False, UInt64(0)).id
    _ = p.to_closing(h1, UInt64(300), CLOSE_FLUSH)
    _ = p.to_closing(h2, UInt64(100), CLOSE_FLUSH)
    var other = p.admit(src(2), True, False, UInt64(0)).id
    assert_equal_int(p.to_closing(other, UInt64(5), CLOSE_FLUSH), CLOSING_REFUSED, "another source is refused")
    assert_equal_int(Int(p.pool_of(other)), Int(POOL_ADMITTED), "and left admitted for the caller to close")
    assert_equal_int(Int(p.closing_refused), 1, "the refusal is counted")
    var free_before = p.conn_cap + p.closing_cap - p.admitted - p.closing
    var e = p.enter_closing(src(2), UInt64(5), CLOSE_FLUSH)
    assert_true(e.id == -1 and e.forced == -1, "a flush of another source is refused")
    assert_equal_int(p.conn_cap + p.closing_cap - p.admitted - p.closing, free_before, "no id taken")
    assert_equal_int(Int(p.closing_refused), 2, "a refused flush is counted too")
    # A spoofable unvalidated connection carrying source 1's key may not evict source 1's entries.
    var spoof = p.admit(src(1), False, True, UInt64(0)).id
    assert_equal_int(p.to_closing(spoof, UInt64(5), CLOSE_QUIC), CLOSING_REFUSED, "unvalidated requester refused")
    assert_equal_int(Int(p.closing_refused), 2, "an unvalidated id is not a full-pool refusal")
    var own = p.admit(src(1), True, False, UInt64(0)).id
    assert_equal_int(p.to_closing(own, UInt64(400), CLOSE_FLUSH), h2, "own source: its earliest entry goes")
    var e2 = p.enter_closing(src(1), UInt64(500), CLOSE_FLUSH)
    assert_equal_int(e2.forced, h1, "a flush of the same source takes its earliest entry")
    assert_equal_int(Int(p.pool_of(e2.id)), Int(POOL_CLOSING), "and enters")
    _check(p, "refusals")
    print("PASS: test_full_closing_pool_refuses_other_sources")


def test_spoofed_initial_flood_cannot_occupy_the_closing_pool() raises:
    """300 forged addresses, each admitted unvalidated then closed: none takes a closing entry.

    RFC 9000 Section 10.2: an endpoint that has not established state
    does not enter the closing state. An honest validated drain still
    gets its entry afterwards.
    """
    var p = _pool(64, 256)
    for i in range(300):
        var u = p.admit(src(1000 + i), False, True, UInt64(0)).id
        assert_true(u >= 0, "spoofed Initial " + String(i) + " admitted")
        assert_equal_int(p.to_closing(u, UInt64(3_000_000), CLOSE_QUIC), CLOSING_REFUSED, "no closing state")
        assert_equal_int(Int(p.pool_of(u)), Int(POOL_ADMITTED), "left admitted for the caller")
        p.release(u)
    assert_equal_int(p.closing, 0, "the flood holds no closing entry")
    assert_equal_int(p.admitted, 0, "and no admitted slot")
    var h = p.admit(src(1), True, False, UInt64(0)).id
    p.set_busy(h, True)
    assert_equal_int(p.to_closing(h, UInt64(10_000_000), CLOSE_DRAIN), -1, "honest drain gets an entry")
    assert_equal_int(Int(p.pool_of(h)), Int(POOL_CLOSING), "and is draining")
    _check(p, "spoofed flood")
    print("PASS: test_spoofed_initial_flood_cannot_occupy_the_closing_pool")


def test_unvalidated_to_closing_changes_nothing() raises:
    """With room to spare, `to_closing` on an unvalidated id refuses and leaves every counter alone."""
    var p = _pool(8, 4)
    var u = p.admit(src(5), False, True, UInt64(0)).id
    var admitted = p.admitted
    var unvalidated = p.unvalidated
    var handshaking = p.handshaking
    assert_equal_int(p.to_closing(u, UInt64(100), CLOSE_QUIC), CLOSING_REFUSED, "refused")
    assert_equal_int(p.closing, 0, "no closing entry")
    assert_true(
        p.admitted == admitted and p.unvalidated == unvalidated and p.handshaking == handshaking,
        "admitted, unvalidated and handshaking unchanged",
    )
    assert_true(p.is_handshaking(u) and not p.is_validated(u), "the id keeps its state")
    p.release(u)
    assert_equal_int(p.unvalidated, 0, "the caller's release frees it")
    _check(p, "unvalidated to_closing")
    print("PASS: test_unvalidated_to_closing_changes_nothing")


def main() raises:
    test_spoofed_initial_flood_cannot_occupy_the_closing_pool()
    test_unvalidated_to_closing_changes_nothing()
    test_drain_churn_never_force_closes_another_source()
    test_full_closing_pool_of_other_sources_kills_the_victim()
    test_full_closing_pool_refuses_other_sources()
    test_invariants_under_random_ops_property()
    test_fair_share_convergence_property()
    test_fair_share_at_scale_property()
    test_tie_goes_to_most_recent_admission()
    test_idle_victim_preferred_busy_victim_drains()
    test_activity_does_not_protect()
    test_spoofed_initials_cannot_inflate_victim()
    test_closing_pool_bounds()
    test_transitions_on_ids_in_any_state_property()
    test_zero_closing_cap_is_rejected()
    test_none_sentinel_id_is_a_no_op()
    test_none_sentinel_id_reads_neutral()
    test_drained_victim_stays_dispatchable()
