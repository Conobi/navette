"""SourceTable against a linear oracle over random insert/remove churn."""

from navette.protect.source_key import SourceKey, source_key_from_sockaddr
from navette.protect.source_table import SourceTable
from navette.util.siphash import SipKey
from tests._test_util import assert_true, assert_equal_int
from tests.protect._prop import Rng, sockaddr_in


def _key(i: Int) -> SourceKey:
    return source_key_from_sockaddr(Span(sockaddr_in(10, UInt8((i >> 16) & 0xFF), UInt8((i >> 8) & 0xFF), UInt8(i & 0xFF), 80)), 48)


def test_churn_matches_oracle_property() raises:
    """20 seeds × 4,000 ops: find/insert/remove agree with a list oracle; no tombstones ever."""
    for seed in range(20):
        var rng = Rng(UInt64(0x7AB1E + seed))
        var cap = 1 + rng.below(64)
        var t = SourceTable(cap, SipKey(k0=rng.next(), k1=rng.next()))
        var oracle = List[Int]()  # live key ids
        var slot_of = List[Int](length=256, fill=-1)
        for op in range(4000):
            var k = rng.below(256)
            var present = k in oracle
            if rng.chance(55):
                var s = t.insert(_key(k))
                if present:
                    assert_equal_int(s, slot_of[k], "insert of present key returns its slot")
                elif len(oracle) == cap:
                    assert_equal_int(s, -1, "insert when full returns -1")
                else:
                    assert_true(s >= 0 and s < cap, "slot in range")
                    for o in oracle:
                        assert_true(slot_of[o] != s, "slot unique")
                    oracle.append(k)
                    slot_of[k] = s
            else:
                var removed = t.remove(_key(k))
                assert_true(removed == present, "remove reports presence")
                if present:
                    var j = 0
                    while oracle[j] != k:
                        j += 1
                    _ = oracle.pop(j)
                    slot_of[k] = -1
            assert_equal_int(len(t), len(oracle), "len, seed " + String(seed) + " op " + String(op))
            assert_true(t.probe_invariant_holds(), "no tombstones / reachable, seed " + String(seed) + " op " + String(op))
            var probe = rng.below(256)
            assert_equal_int(t.find(_key(probe)), slot_of[probe], "find agrees")
    print("PASS: test_churn_matches_oracle_property")


def test_key_of_round_trips() raises:
    var t = SourceTable(8, SipKey(k0=UInt64(3), k1=UInt64(4)))
    var s = t.insert(_key(7))
    assert_true(t.key_of(s) == _key(7), "key_of returns the inserted key")
    assert_true(t.is_live(s), "live after insert")
    _ = t.remove(_key(7))
    assert_true(not t.is_live(s), "not live after remove")
    print("PASS: test_key_of_round_trips")


def main() raises:
    test_churn_matches_oracle_property()
    test_key_of_round_trips()
