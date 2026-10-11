# tests/util/test_split_harness.mojo
"""Self-test for the seeded split harness used by the boundary suites."""
from tests._split_harness import (
    SplitRng, SplitPlan, split_plans, payload, compressible_payload,
    boundary_sizes, assert_bytes_equal, tls_probe_layout, TLS_PROBE_MIN_A,
)
from tests._test_util import assert_true, assert_equal_int


def _sum(plan: SplitPlan) -> Int:
    var s = 0
    for i in range(len(plan.chunks)):
        s += plan.chunks[i]
    return s


def test_plans_cover_total() raises:
    var totals: List[Int] = [0, 1, 7, 4096, 4097, 65536, 65537, 262145]
    for t in range(len(totals)):
        var total = totals[t]
        var plans = split_plans(total, UInt64(42), sampled=8, randoms=4)
        assert_true(len(plans) >= 1, "at least the whole plan")
        for p in range(len(plans)):
            assert_equal_int(_sum(plans[p]), total, plans[p].label)
            for c in range(len(plans[p].chunks)):
                assert_true(plans[p].chunks[c] > 0, plans[p].label + ": empty chunk")


def _has_label(plans: List[SplitPlan], label: String) -> Bool:
    for p in range(len(plans)):
        if plans[p].label == label:
            return True
    return False


def test_small_plans_only_for_small_totals() raises:
    var big = split_plans(65537, UInt64(1), sampled=4, randoms=2)
    assert_true(not _has_label(big, "fixed(1)"), "1-byte plan must not appear above 64 KiB")
    assert_true(not _has_label(big, "fixed(7)"), "7-byte plan must not appear above 64 KiB")
    var small = split_plans(65536, UInt64(1), sampled=4, randoms=2)
    assert_true(_has_label(small, "fixed(1)"), "1-byte plan must appear at 64 KiB")
    assert_true(_has_label(small, "fixed(7)"), "7-byte plan must appear at 64 KiB")


def test_probe_layout_total() raises:
    var layout = tls_probe_layout()
    var s = 0
    for i in range(len(layout)):
        s += layout[i]
    assert_equal_int(s, TLS_PROBE_MIN_A, "probe layout sums to its total")


def test_deterministic_for_seed() raises:
    var a = split_plans(100000, UInt64(7), sampled=4, randoms=3)
    var b = split_plans(100000, UInt64(7), sampled=4, randoms=3)
    assert_equal_int(len(a), len(b), "same plan count")
    for p in range(len(a)):
        assert_true(a[p].label == b[p].label, "same labels")
        assert_equal_int(len(a[p].chunks), len(b[p].chunks), a[p].label)
        for c in range(len(a[p].chunks)):
            assert_equal_int(a[p].chunks[c], b[p].chunks[c], a[p].label + " chunk value")


def test_payloads() raises:
    assert_equal_int(len(payload(1000, UInt64(3))), 1000, "payload length")
    assert_equal_int(len(compressible_payload(1000)), 1000, "compressible length")
    var sizes = boundary_sizes()
    assert_true(len(sizes) >= 14, "boundary sizes present")


def test_assert_bytes_equal_reports_offset() raises:
    var a = payload(10, UInt64(5))
    var b = a.copy()
    b[6] = b[6] ^ 1
    try:
        assert_bytes_equal(b, a, "ctx")
        assert_true(False, "difference not detected")
    except e:
        assert_true("offset 6" in String(e), "offset reported: " + String(e))


def main() raises:
    test_plans_cover_total()
    test_small_plans_only_for_small_totals()
    test_deterministic_for_seed()
    test_payloads()
    test_assert_bytes_equal_reports_offset()
    test_probe_layout_total()
    print("test_split_harness: 6/6 passed")
