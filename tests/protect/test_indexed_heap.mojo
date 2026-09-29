"""IndexedMaxHeap against a brute-force maximum over random set/remove sequences."""

from navette.protect.indexed_heap import IndexedMaxHeap
from tests._test_util import assert_true, assert_equal_int
from tests.protect._prop import Rng


def test_matches_bruteforce_property() raises:
    """30 seeds × 3,000 ops; small key ranges force many ties on `hi`."""
    for seed in range(30):
        var rng = Rng(UInt64(0x4EA9 + seed))
        var cap = 1 + rng.below(40)
        var h = IndexedMaxHeap(cap)
        var live = List[Bool](length=cap, fill=False)
        var hi = List[UInt64](length=cap, fill=UInt64(0))
        var lo = List[UInt64](length=cap, fill=UInt64(0))
        for op in range(3000):
            var it = rng.below(cap)
            if rng.chance(70):
                hi[it] = UInt64(rng.below(8))
                lo[it] = UInt64(rng.below(1000))
                h.set(it, hi[it], lo[it])
                live[it] = True
            else:
                h.remove(it)
                live[it] = False
            var best = -1
            var n = 0
            for i in range(cap):
                if not live[i]:
                    continue
                n += 1
                if best < 0 or hi[i] > hi[best] or (hi[i] == hi[best] and lo[i] > lo[best]):
                    best = i
            assert_equal_int(len(h), n, "size, seed " + String(seed) + " op " + String(op))
            assert_true(h.heap_property_holds(), "heap property")
            if best < 0:
                assert_equal_int(h.top(), -1, "empty top")
            else:
                var t = h.top()
                assert_true(hi[t] == hi[best] and lo[t] == lo[best], "top is a maximum, seed " + String(seed) + " op " + String(op))
            assert_true(h.contains(it) == live[it], "contains")
    print("PASS: test_matches_bruteforce_property")


def main() raises:
    test_matches_bruteforce_property()
