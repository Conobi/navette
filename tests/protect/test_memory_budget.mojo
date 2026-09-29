"""MemoryBudget: conservation, share floor, heaviest-first, validated-only activity."""

from navette.protect.descriptor_budget import MAX_CONN_CAP, MAX_CLOSING_CAP
from navette.protect.memory_budget import MemoryBudget
from navette.protect.source_key import SourceKey, source_key_from_sockaddr
from navette.util.siphash import SipKey
from tests._test_util import assert_true, assert_equal_int
from tests.protect._prop import Rng, sockaddr_in

comptime MiB = 1024 * 1024


def src(i: Int) -> SourceKey:
    return source_key_from_sockaddr(Span(sockaddr_in(172, 16, UInt8((i >> 8) & 0xFF), UInt8(i & 0xFF), 443)), 48)


def _budget(bytes: Int, conns: Int) raises -> MemoryBudget:
    return MemoryBudget(bytes, conns, SipKey(k0=UInt64(5), k1=UInt64(6)))


def test_conservation_property() raises:
    """20 seeds × 2,000 ops: totals, per-source sums and the heap always match a recount."""
    for seed in range(20):
        var rng = Rng(UInt64(0x3E3 + seed))
        var b = _budget(1 * MiB, 64)
        var live = List[Int]()
        for op in range(2000):
            var r = rng.below(100)
            if r < 30:
                var h = b.register(rng.below(3), rng.below(1000), src(rng.below(10)), rng.chance(70))
                if h >= 0:
                    live.append(h)
            elif r < 75 and len(live) > 0:
                b.set_mem(live[rng.below(len(live))], rng.below(64 * 1024))
            elif r < 85 and len(live) > 0:
                b.validate(live[rng.below(len(live))])
            elif len(live) > 0:
                var i = rng.below(len(live))
                b.unregister(live[i])
                _ = live.pop(i)
            var v = b.invariant_violation()
            assert_true(v == "", "seed " + String(seed) + " op " + String(op) + ": " + v)
    print("PASS: test_conservation_property")


def test_never_below_share_property() raises:
    """Evicting until under budget never picks a source at or below `budget / sources_active` (30 seeds)."""
    for seed in range(30):
        var rng = Rng(UInt64(0x5A4E + seed))
        var b = _budget(64 * MiB, 512)
        var k = 2 + rng.below(20)
        var handles_of = List[Int](length=k, fill=0)
        var src_of = Dict[Int, Int]()
        for _ in range(300):
            var i = rng.below(k)
            var h = b.register(0, 0, src(i), True)
            if h >= 0:
                handles_of[i] += 1
                src_of[h] = i
                b.set_mem(h, rng.below(2 * MiB))
        var guard = 0
        while True:
            var v = b.pick_victim()
            if v < 0:
                break
            var smem = b.source_mem(b.key_of(v))
            var active = 0
            for i in range(k):
                if handles_of[i] > 0:
                    active += 1
            assert_true(smem > (64 * MiB) // active, "picked source is above budget / sources with a live handle")
            for i in range(k):
                assert_true(b.source_mem(src(i)) <= smem, "picked source is the heaviest")
            handles_of[src_of[v]] -= 1
            b.unregister(v)
            b.note_eviction()
            guard += 1
            assert_true(guard < 1000, "eviction terminates")
        assert_true(not b.over_budget() or b.pick_victim() < 0, "stops only under budget or with every source at its share")
    print("PASS: test_never_below_share_property")


def test_honest_heavy_source_trimmed_to_share() raises:
    """64 attackers at their share plus one honest source with 50 MiB: trimmed to ≈ budget/65, never below."""
    var b = _budget(512 * MiB, 1024)
    var share = (512 * MiB) // 65
    for a in range(64):
        var h = b.register(0, a, src(a), True)
        b.set_mem(h, share)
    var honest = List[Int]()
    for i in range(50):
        var h = b.register(1, 1000 + i, src(999), True)
        b.set_mem(h, MiB)
        honest.append(h)
    while True:
        var v = b.pick_victim()
        if v < 0:
            break
        assert_true(b.server_of(v) == 1, "only the honest source is above its share")
        b.unregister(v)
    assert_true(b.source_mem(src(999)) >= share - MiB, "trimmed to about its share")
    assert_true(b.source_mem(src(999)) <= share + MiB, "and not left far above it")
    print("PASS: test_honest_heavy_source_trimmed_to_share")


def test_unvalidated_bytes_are_unattributed() raises:
    var b = _budget(10, 16)
    var h = b.register(0, 0, src(1), False)
    b.set_mem(h, 1000)
    assert_equal_int(b.sources_active(), 0, "unvalidated never makes a source active")
    assert_equal_int(b.source_mem(src(1)), 0, "nor carries bytes for it")
    assert_true(b.over_budget(), "but its bytes count towards the total")
    assert_equal_int(b.pick_victim(), -1, "and no source can be picked")
    b.validate(h)
    assert_equal_int(b.source_mem(src(1)), 1000, "validation attributes the bytes")
    assert_equal_int(b.pick_victim(), h, "now it is the heaviest connection of the heaviest source")
    print("PASS: test_unvalidated_bytes_are_unattributed")


def test_reserve_before_first_handle() raises:
    var b = _budget(MiB, 2)
    b.reserve(10)
    assert_equal_int(b.capacity(), 12, "reserve grows capacity")
    _ = b.register(0, 0, src(1), True)
    var raised = False
    try:
        b.reserve(1)
    except:
        raised = True
    assert_true(raised, "reserve after the first handle raises")
    print("PASS: test_reserve_before_first_handle")


def test_reserve_rejects_out_of_range_sizes() raises:
    """A negative reserve would shrink the tables below `capacity()`; a huge one would overflow the Int32 handles."""
    for extra in [-4, -1, MAX_CONN_CAP + MAX_CLOSING_CAP + 1, Int.MAX]:
        var b = _budget(MiB, 8)
        var raised = False
        try:
            b.reserve(extra)
        except:
            raised = True
        assert_true(raised, "reserve(" + String(extra) + ") raises")
        assert_equal_int(b.capacity(), 8, "capacity unchanged after reserve(" + String(extra) + ")")
        assert_true(b.invariant_violation() == "", "still consistent after reserve(" + String(extra) + ")")
    var b = _budget(MiB, 8)
    b.reserve(0)
    assert_equal_int(b.capacity(), 8, "reserve(0) is allowed")
    print("PASS: test_reserve_rejects_out_of_range_sizes")


def test_non_positive_budget_is_rejected() raises:
    for bytes in [0, -1, -(1 << 40)]:
        var raised = False
        try:
            _ = _budget(bytes, 8)
        except:
            raised = True
        assert_true(raised, "budget " + String(bytes) + " raises")
    _ = _budget(1, 8)
    print("PASS: test_non_positive_budget_is_rejected")


def test_none_handle_is_a_no_op() raises:
    """`register` returns -1 when full; passing it back into set_mem, validate or unregister changes nothing."""
    var b = _budget(MiB, 1)
    var h = b.register(0, 0, src(1), False)
    assert_equal_int(b.register(0, 1, src(2), True), -1, "full budget hands out no handle")
    b.set_mem(h, 100)
    b.set_mem(-1, 5000)
    b.validate(-1)
    b.unregister(-1)
    assert_equal_int(b.total, 100, "total unchanged")
    assert_equal_int(b.sources_active(), 0, "the live handle stays unvalidated")
    assert_equal_int(b.handles(), 1, "the live handle stays registered")
    assert_true(b.invariant_violation() == "", "invariants hold")
    print("PASS: test_none_handle_is_a_no_op")


def test_victim_is_heaviest_connection_of_its_source() raises:
    """30 seeds: with varied sizes, the victim holds the most bytes among its source's live connections."""
    for seed in range(30):
        var rng = Rng(UInt64(0xB16 + seed))
        var b = _budget(MiB, 256)
        var live = List[Int]()
        for _ in range(200):
            var h = b.register(0, 0, src(rng.below(4)), True)
            if h >= 0:
                b.set_mem(h, 1 + rng.below(64 * 1024))
                live.append(h)
        while True:
            var v = b.pick_victim()
            if v < 0:
                break
            var key = b.key_of(v)
            for h in live:
                if b.key_of(h) == key:
                    assert_true(b.mem_of(h) <= b.mem_of(v), "seed " + String(seed) + " victim is the heaviest of its source")
            b.unregister(v)
            for i in range(len(live)):
                if live[i] == v:
                    _ = live.pop(i)
                    break
    print("PASS: test_victim_is_heaviest_connection_of_its_source")


def test_negative_bytes_clamp_to_zero() raises:
    """A negative report counts as 0 instead of wrapping the heap key and pinning the source as heaviest."""
    var b = _budget(100, 4)
    var bad = b.register(0, 0, src(1), True)
    var good = b.register(0, 1, src(2), True)
    b.set_mem(good, 500)
    b.set_mem(bad, -5)
    assert_equal_int(b.mem_of(bad), 0, "clamped to 0")
    assert_equal_int(b.total, 500, "total not reduced")
    assert_equal_int(b.pick_victim(), good, "the real heaviest source is picked")
    assert_true(b.invariant_violation() == "", "invariants hold")
    print("PASS: test_negative_bytes_clamp_to_zero")


def _corruptible() raises -> MemoryBudget:
    """Source A holds h1 -> h0 (head first), source B holds h2, h3 is unvalidated; 8 handle slots."""
    var b = _budget(1 * MiB, 8)
    _ = b.register(0, 0, src(1), True)
    _ = b.register(0, 1, src(1), True)
    _ = b.register(0, 2, src(2), True)
    _ = b.register(0, 3, src(3), False)
    return b^


def test_invariant_catches_broken_source_lists() raises:
    """Each corruption of the per-source intrusive lists is reported, not only its effect on the sums."""
    var clean = _corruptible()
    assert_true(clean.invariant_violation() == "", "the fixture is consistent: " + clean.invariant_violation())
    var sa = Int(clean._src[0])
    var sb = Int(clean._src[2])
    assert_equal_int(Int(clean._src_head[sa]), 1, "fixture: h1 heads source A")

    var dropped = _corruptible()  # h0 unreachable from A's head, yet still attributed to A
    dropped._next[1] = -1
    assert_true(dropped.invariant_violation() != "", "a member dropped from its list is caught")

    var back = _corruptible()  # h0's back link skips h1
    back._prev[0] = -1
    assert_true(back.invariant_violation() != "", "a wrong back link is caught")

    var foreign = _corruptible()  # h2 (source B) spliced into source A's list
    foreign._next[0] = 2
    foreign._prev[2] = 0
    assert_true(foreign.invariant_violation() != "", "a member of another source is caught")

    var unattributed = _corruptible()  # unvalidated h3 spliced into source A's list
    unattributed._next[0] = 3
    unattributed._prev[3] = 0
    assert_true(unattributed.invariant_violation() != "", "an unattributed handle in a list is caught")

    var cyclic = _corruptible()  # A's list loops back to its head
    cyclic._next[0] = 1
    assert_true(cyclic.invariant_violation() != "", "a cycle is caught instead of looping forever")

    var dead_head = _corruptible()  # a dead source slot still points at a handle
    var free_slot = 0
    while free_slot == sa or free_slot == sb:
        free_slot += 1
    dead_head._src_head[free_slot] = 2
    assert_true(dead_head.invariant_violation() != "", "a dead source with a list head is caught")
    print("PASS: test_invariant_catches_broken_source_lists")


def test_invariant_catches_broken_source_table() raises:
    """Corruptions that leave every sum and list intact but break the source table's mapping."""
    var rekeyed = _corruptible()  # h0 still in A's list, but its key now names another source
    rekeyed._key[0] = src(9)
    assert_true(rekeyed.invariant_violation() != "", "a handle whose key disagrees with its source slot is caught")

    var miscounted = _corruptible()  # sources_active() over-reports
    miscounted._table._len += 1
    assert_true(miscounted.invariant_violation() != "", "a source count drift is caught")

    var unreachable = _corruptible()  # A's entry can no longer be probed from its home cell
    var sa = Int(unreachable._src[0])
    var mask = unreachable._table._mask
    var cell = -1
    for c in range(len(unreachable._table._cells)):
        if Int(unreachable._table._cells[c]) == sa:
            cell = c
    var empty_after = (cell + 1) & mask
    while unreachable._table._cells[empty_after] != -1:
        empty_after = (empty_after + 1) & mask
    unreachable._table._homes[sa] = empty_after
    assert_true(unreachable.invariant_violation() != "", "a broken probe chain is caught")
    print("PASS: test_invariant_catches_broken_source_table")


def main() raises:
    test_conservation_property()
    test_never_below_share_property()
    test_honest_heavy_source_trimmed_to_share()
    test_unvalidated_bytes_are_unattributed()
    test_reserve_before_first_handle()
    test_reserve_rejects_out_of_range_sizes()
    test_non_positive_budget_is_rejected()
    test_none_handle_is_a_no_op()
    test_victim_is_heaviest_connection_of_its_source()
    test_negative_bytes_clamp_to_zero()
    test_invariant_catches_broken_source_lists()
    test_invariant_catches_broken_source_table()
