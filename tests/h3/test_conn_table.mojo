"""ConnTable: stable ids, generation tags and demux keys against a Dict oracle."""

from navette.h3.conn_table import ConnTable, KEYS_PER_CONN
from tests._test_util import assert_true, assert_equal_int
from tests.protect._prop import Rng, prop_iters

comptime _CAP = 16


def _pick(mut rng: Rng, slot_of: Dict[Int, Int]) -> Int:
    """A random live id of the oracle; the caller checked it is non-empty."""
    var ids = List[Int]()
    for k in slot_of.keys():
        ids.append(k)
    return ids[rng.below(len(ids))]


def _nkeys(owner: Dict[UInt64, Int], id: Int) -> Int:
    var n = 0
    for e in owner.items():
        if e.value == id:
            n += 1
    return n


def _count_true(flags: Dict[Int, Bool]) -> Int:
    var n = 0
    for e in flags.items():
        if e.value:
            n += 1
    return n


def _id_at_slot(slot_of: Dict[Int, Int], slot: Int) -> Int:
    for e in slot_of.items():
        if e.value == slot:
            return e.key
    return -1


def test_table_matches_oracle() raises:
    """Property: random open / add_key / remove_key / validate / release+move / stale release vs a Dict oracle."""
    for seed in range(prop_iters(100)):
        var rng = Rng(UInt64(0xC7AB + seed))
        var t = ConnTable(capacity=_CAP)
        var owner = Dict[UInt64, Int]()  # key -> id
        var slot_of = Dict[Int, Int]()  # id -> slot
        var gen_of = Dict[Int, UInt32]()  # live id -> generation at open
        var last_gen = Dict[Int, UInt32]()  # every id ever opened -> its latest generation
        var unval = Dict[Int, Bool]()
        var stale_id = List[Int]()
        var stale_gen = List[UInt32]()
        for step in range(400):
            var op = rng.below(6)
            var ctx = "seed " + String(seed) + " step " + String(step) + " op " + String(op)
            if op == 0:
                var s = len(slot_of)
                var u = rng.chance(50)
                var id = t.open(s, unvalidated=u)
                if s >= _CAP:
                    assert_equal_int(id, -1, ctx + ": full")
                else:
                    assert_true(id >= 0 and id < _CAP and id not in slot_of, ctx + ": fresh id")
                    var g = t.gen_of(id)
                    var prev = last_gen.find(id)
                    if prev:
                        assert_true(g > prev.value(), ctx + ": reused id gets a newer generation")
                    last_gen[id] = g
                    slot_of[id] = s
                    gen_of[id] = g
                    unval[id] = u
            elif op == 1 and len(slot_of) > 0:
                var id = _pick(rng, slot_of)
                var key = UInt64(rng.below(64))  # small key space forces collisions
                var ok = t.add_key(id, key)
                var cur = owner.find(key)
                var want: Bool
                if cur:
                    want = cur.value() == id
                else:
                    want = _nkeys(owner, id) < KEYS_PER_CONN
                assert_true(ok == want, ctx + ": add_key " + String(key))
                if ok:
                    owner[key] = id
            elif op == 2 and len(slot_of) > 0:
                var id = _pick(rng, slot_of)
                var key = UInt64(rng.below(64))
                t.remove_key(id, key)
                var cur = owner.find(key)
                if cur and cur.value() == id:
                    _ = owner.pop(key)
            elif op == 3 and len(slot_of) > 0:
                var id = _pick(rng, slot_of)
                t.validate(id)
                unval[id] = False
            elif op == 4 and len(slot_of) > 0:
                # The server's swap-and-pop free: the id at the last slot moves into the hole.
                var victim = _pick(rng, slot_of)
                var hole = slot_of[victim]
                var last = _id_at_slot(slot_of, len(slot_of) - 1)
                var g = gen_of[victim]
                t.release(victim, g)
                stale_id.append(victim)
                stale_gen.append(g)
                _ = slot_of.pop(victim)
                _ = gen_of.pop(victim)
                _ = unval.pop(victim)
                var dead = List[UInt64]()
                for e in owner.items():
                    if e.value == victim:
                        dead.append(e.key)
                for k in dead:
                    _ = owner.pop(k)
                if last != victim:
                    t.moved(last, hole)
                    slot_of[last] = hole
            elif op == 5 and len(stale_id) > 0:
                # A second release with a generation that is no longer current changes nothing.
                var j = rng.below(len(stale_id))
                t.release(stale_id[j], stale_gen[j])

            assert_equal_int(t.live, len(slot_of), ctx + ": live")
            for e in slot_of.items():
                assert_equal_int(t.slot_of(e.key), e.value, ctx + ": slot_of")
                assert_true(t.gen_of(e.key) == gen_of[e.key], ctx + ": generation stable while live")
                assert_true(t.is_unvalidated(e.key) == unval[e.key], ctx + ": flag")
            for e in owner.items():
                assert_equal_int(t.lookup(e.key), slot_of[e.value], ctx + ": lookup")
                assert_equal_int(t.id_of_key(e.key), e.value, ctx + ": id_of_key")
            var probe = UInt64(rng.below(64))
            if probe not in owner:
                assert_equal_int(t.lookup(probe), -1, ctx + ": unowned key misses")
            assert_equal_int(t.unvalidated_count, _count_true(unval), ctx + ": handshake counter = flagged ids")
            var bad = t.invariant_violation()
            assert_equal_int(bad.byte_length(), 0, ctx + ": " + bad)


def test_release_removes_every_key() raises:
    """Releasing an id drops all its keys; reopening reuses the id with a newer generation."""
    var t = ConnTable(capacity=4)
    var id = t.open(0, unvalidated=True)
    var g = t.gen_of(id)
    for k in range(KEYS_PER_CONN):
        assert_true(t.add_key(id, UInt64(100 + k)), "key " + String(k))
    assert_true(not t.add_key(id, UInt64(999)), "one key over KEYS_PER_CONN refused")
    assert_equal_int(t.unvalidated_count, 1, "flagged")
    t.release(id, g)
    for k in range(KEYS_PER_CONN):
        assert_equal_int(t.lookup(UInt64(100 + k)), -1, "key " + String(k) + " gone")
    assert_equal_int(t.unvalidated_count, 0, "flag cleared on release")
    var again = t.open(0, unvalidated=False)
    assert_equal_int(again, id, "LIFO free list reuses the id")
    assert_true(t.gen_of(again) == g + 1, "generation bumped")
    t.release(id, g)
    assert_equal_int(t.live, 1, "stale release after reuse is a no-op")
    assert_equal_int(t.invariant_violation().byte_length(), 0, t.invariant_violation())


def test_key_owned_by_other_id_refused() raises:
    """Two ids cannot share a demux key: the first owner keeps it."""
    var t = ConnTable(capacity=4)
    var a = t.open(0, unvalidated=False)
    var b = t.open(1, unvalidated=False)
    assert_true(t.add_key(a, UInt64(7)), "first owner")
    assert_true(t.add_key(a, UInt64(7)), "re-adding its own key is a no-op")
    assert_true(not t.add_key(b, UInt64(7)), "second owner refused")
    assert_equal_int(t.lookup(UInt64(7)), 0, "still routes to a")
    t.remove_key(b, UInt64(7))
    assert_equal_int(t.lookup(UInt64(7)), 0, "remove by a non-owner is a no-op")
    assert_equal_int(t.invariant_violation().byte_length(), 0, t.invariant_violation())


def test_validate_counts_once() raises:
    var t = ConnTable(capacity=2)
    var a = t.open(0, unvalidated=True)
    t.validate(a)
    t.validate(a)
    assert_equal_int(t.unvalidated_count, 0, "validate is idempotent")


def main() raises:
    print("test_conn_table:")
    test_table_matches_oracle()
    test_release_removes_every_key()
    test_key_owned_by_other_id_refused()
    test_validate_counts_once()
    print("PASS: test_conn_table")
