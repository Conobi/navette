"""LocallyClosedSet against an explicit set with the 1,024-stream window."""

from navette.protect.locally_closed import LocallyClosedSet, LOCALLY_CLOSED_WINDOW
from tests._test_util import assert_true
from tests.protect._prop import Rng


def test_matches_oracle_property() raises:
    """20 seeds × 3,000 ops: advance by random odd steps (incl. jumps over the window), mark, query."""
    for seed in range(20):
        var rng = Rng(UInt64(0x1C + seed))
        var s = LocallyClosedSet()
        var marked = List[UInt32]()
        var last = UInt32(0)
        for op in range(3000):
            var k = rng.below(10)
            if k < 4:
                var step = UInt32(2 * rng.below(8) + 1) if last == 0 else UInt32(2 * (1 + rng.below(40 if rng.chance(95) else 3000)))
                last += step
                s.advance(last)
            elif k < 7 and last > 0:
                var back = UInt32(2 * rng.below(1200))
                if back <= last:
                    var sid = last - back
                    s.mark(sid)
                    if s.in_window(sid):
                        marked.append(sid)
            else:
                var back = UInt32(2 * rng.below(1500))
                if back <= last:
                    var sid = last - back
                    var want = False
                    if (sid & 1) == 1 and last - sid < UInt32(2 * LOCALLY_CLOSED_WINDOW):
                        for m in marked:
                            if m == sid:
                                want = True
                    assert_true(s.is_marked(sid) == want, "seed " + String(seed) + " op " + String(op) + " sid " + String(sid))
    print("PASS: test_matches_oracle_property")


def test_even_and_future_ids_never_marked() raises:
    var s = LocallyClosedSet()
    s.advance(101)
    s.mark(100)
    s.mark(103)
    assert_true(not s.is_marked(100), "even id")
    assert_true(not s.is_marked(103), "id above the window")
    s.mark(99)
    assert_true(s.is_marked(99), "in window")
    s.advance(UInt32(99 + 2 * LOCALLY_CLOSED_WINDOW))
    assert_true(not s.is_marked(99), "slid out of the window")
    print("PASS: test_even_and_future_ids_never_marked")


def main() raises:
    test_matches_oracle_property()
    test_even_and_future_ids_never_marked()
