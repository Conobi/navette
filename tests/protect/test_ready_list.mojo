"""ReadyList: per-source fairness, per-connection rotation, pass budget, O(1) removal."""

from navette.protect.ready_list import ReadyList, DISPATCH_PER_SOURCE_ROUND, DISPATCH_PASS_BUDGET
from tests._test_util import assert_true, assert_equal_int
from tests.protect._prop import Rng


def test_two_sources_equal_share_under_saturation() raises:
    """2,000 ready connections of source 0 vs 1 of source 1: 512 dispatches each per pass."""
    var r = ReadyList(2001, 2)
    for c in range(2000):
        r.push(c, 0)
    r.push(2000, 1)
    r.begin_pass()
    var per_src = List[Int](length=2, fill=0)
    while True:
        var c = r.next()
        if c < 0:
            break
        per_src[1 if c == 2000 else 0] += 1
    assert_equal_int(per_src[0] + per_src[1], DISPATCH_PASS_BUDGET, "the pass budget is spent exactly")
    assert_equal_int(per_src[0], 512, "source 0 gets half")
    assert_equal_int(per_src[1], 512, "source 1 gets half")
    print("PASS: test_two_sources_equal_share_under_saturation")


def test_pipelined_backlog_fully_served() raises:
    """100 pipelined requests on one connection, then silence: all dispatched across passes."""
    var r = ReadyList(4, 4)
    var pending = 100
    r.push(3, 2)
    var passes = 0
    while pending > 0:
        r.begin_pass()
        passes += 1
        while True:
            var c = r.next()
            if c < 0:
                break
            pending -= 1
            if pending == 0:
                r.remove(c)
    assert_equal_int(pending, 0, "every request served")
    assert_equal_int(passes, 1, "100 < pass budget: one pass")
    assert_equal_int(len(r), 0, "list empty")
    print("PASS: test_pipelined_backlog_fully_served")


def test_fairness_property() raises:
    """Random always-ready populations: per-pass source counts differ by ≤ 16, per-connection by ≤ 1 within a source."""
    for seed in range(40):
        var rng = Rng(UInt64(0x2E + seed))
        var nsrc = 1 + rng.below(10)
        var owner = List[Int]()
        var r = ReadyList(600, nsrc)
        for s in range(nsrc):
            for _ in range(1 + rng.below(60)):
                owner.append(s)
                r.push(len(owner) - 1, s)
        var per_src = List[Int](length=nsrc, fill=0)
        var per_conn = List[Int](length=len(owner), fill=0)
        r.begin_pass()
        while True:
            var c = r.next()
            if c < 0:
                break
            per_src[owner[c]] += 1
            per_conn[c] += 1
        var lo = per_src[0]
        var hi = per_src[0]
        for s in range(nsrc):
            lo = min(lo, per_src[s])
            hi = max(hi, per_src[s])
        assert_true(hi - lo <= DISPATCH_PER_SOURCE_ROUND, "seed " + String(seed) + " sources within 16")
        for s in range(nsrc):
            var clo = 1 << 30
            var chi = 0
            for c in range(len(owner)):
                if owner[c] == s:
                    clo = min(clo, per_conn[c])
                    chi = max(chi, per_conn[c])
            assert_true(chi - clo <= 1, "seed " + String(seed) + " connections of a source within 1")
    print("PASS: test_fairness_property")


def _assert_dispatched_under_current_source(
    mut r: ReadyList, queued: List[Bool], src_of: List[Int], nsources: Int, ctx: String
) raises:
    """One full pass: every dispatch is a queued connection served in its latest source's turn.

    A source's turn is a run of consecutive dispatches: whatever quota the
    cursor source had left, then `DISPATCH_PER_SOURCE_ROUND` each. Every
    run must hold connections of one oracle source, and any `k`
    consecutive runs (`k` = sources with queued connections) must name `k`
    distinct sources, so a moved connection still queued under its old
    source shows up as a mixed run or as its new source served twice in a
    round.
    """
    var seq = List[Int]()
    r.begin_pass()
    for _ in range(DISPATCH_PASS_BUDGET):
        var got = r.next()
        if got < 0:
            break
        assert_true(queued[got], ctx + " after moves, next returns only queued connections")
        seq.append(got)
    if len(seq) == 0:
        return
    var seen = List[Bool](length=nsources, fill=False)
    var k = 0
    for c in range(len(queued)):
        if queued[c] and not seen[src_of[c]]:
            seen[src_of[c]] = True
            k += 1
    var labels = List[Int]()
    var i = 0
    while i < len(seq) and src_of[seq[i]] == src_of[seq[0]]:
        i += 1
    assert_true(k == 1 or i <= DISPATCH_PER_SOURCE_ROUND, ctx + " first turn within the quota")
    labels.append(src_of[seq[0]])
    while i < len(seq):
        var end = min(i + DISPATCH_PER_SOURCE_ROUND, len(seq))
        for j in range(i, end):
            assert_equal_int(src_of[seq[j]], src_of[seq[i]], ctx + " dispatch " + String(j) + " under its latest source")
        labels.append(src_of[seq[i]])
        i = end
    for w in range(len(labels) - k + 1):
        for x in range(w, w + k):
            for y in range(x + 1, w + k):
                assert_true(labels[x] != labels[y], ctx + " each source served once per round, turn " + String(x))


def test_random_push_remove_property() raises:
    """Membership and length stay exact under random push/move/remove/next (30 seeds × 3,000 ops).

    A move re-pushes a connection under another source, as entering the
    closing pool does; `next` must only ever return queued connections,
    each under its latest source, and draining everything must leave the
    list empty.
    """
    for seed in range(30):
        var rng = Rng(UInt64(0x9E + seed))
        var n = 64
        var r = ReadyList(n, 8)
        var queued = List[Bool](length=n, fill=False)
        var src_of = List[Int](length=n, fill=0)
        for i in range(n):
            src_of[i] = rng.below(8)
        var count = 0
        var moves = 0
        r.begin_pass()
        for op in range(3000):
            var c = rng.below(n)
            var k = rng.below(10)
            if k < 3:
                r.push(c, src_of[c])
                if not queued[c]:
                    queued[c] = True
                    count += 1
            elif k < 5:
                src_of[c] = (src_of[c] + 1 + rng.below(7)) % 8
                r.push(c, src_of[c])
                if queued[c]:
                    moves += 1
                else:
                    queued[c] = True
                    count += 1
            elif k < 7:
                r.remove(c)
                if queued[c]:
                    queued[c] = False
                    count -= 1
            else:
                if rng.chance(5):
                    r.begin_pass()
                var got = r.next()
                if got >= 0:
                    assert_true(queued[got], "next returns only queued connections")
            assert_equal_int(len(r), count, "seed " + String(seed) + " op " + String(op))
            assert_true(r.contains(c) == queued[c], "membership")
        assert_true(moves > 100, "seed " + String(seed) + " exercised moves: " + String(moves))
        _assert_dispatched_under_current_source(r, queued, src_of, 8, "seed " + String(seed))
        for i in range(n):
            r.remove(i)
        assert_equal_int(len(r), 0, "seed " + String(seed) + " drained")
        r.begin_pass()
        assert_equal_int(r.next(), -1, "seed " + String(seed) + " nothing left to dispatch")
    print("PASS: test_random_push_remove_property")


def test_out_of_range_ids_are_rejected() raises:
    """Push on -1 or ids/sources past the tables raises instead of silently dropping the connection; remove and contains ignore them."""
    var r = ReadyList(4, 2)
    r.push(3, 1)
    var raised = 0
    for bad in [-1, 4, 1000]:
        try:
            r.push(bad, 0)
        except:
            raised += 1
        try:
            r.push(0, bad)
        except:
            raised += 1
        r.remove(bad)
        assert_true(not r.contains(bad), "contains(" + String(bad) + ") is False")
    assert_equal_int(raised, 6, "every invalid push raises")
    assert_equal_int(len(r), 1, "only the valid push counted")
    assert_true(r.contains(3) and not r.contains(0), "valid membership unchanged")
    r.begin_pass()
    assert_equal_int(r.next(), 3, "the valid connection is dispatched")
    print("PASS: test_out_of_range_ids_are_rejected")


def test_push_under_a_new_source_moves_the_connection() raises:
    """A queued connection pushed under another source leaves its old source's rotation."""
    var r = ReadyList(3, 2)
    r.push(0, 0)
    r.push(1, 0)
    r.push(0, 1)
    assert_equal_int(len(r), 2, "moved, not duplicated")
    r.begin_pass()
    for i in range(DISPATCH_PER_SOURCE_ROUND):
        assert_equal_int(r.next(), 1, "source 0 now holds only connection 1, dispatch " + String(i))
    assert_equal_int(r.next(), 0, "connection 0 is served as source 1")
    r.remove(0)
    r.remove(1)
    assert_equal_int(len(r), 0, "both removable from their current source")
    print("PASS: test_push_under_a_new_source_moves_the_connection")


def main() raises:
    test_two_sources_equal_share_under_saturation()
    test_pipelined_backlog_fully_served()
    test_fairness_property()
    test_random_push_remove_property()
    test_out_of_range_ids_are_rejected()
    test_push_under_a_new_source_moves_the_connection()
