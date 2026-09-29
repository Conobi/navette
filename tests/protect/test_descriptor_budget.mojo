"""DescriptorBudget: proportional split, clamping, minimum, freeze, order independence."""

from navette.protect.descriptor_budget import (
    DescriptorBudget,
    _from_process_with,
    FD_SLACK,
    MIN_CONN_CAP,
    MAX_CONN_CAP,
    MAX_CLOSING_CAP,
    MAX_FD_LIMIT,
    default_closing_cap,
)
from tests._test_util import assert_true, assert_equal_int
from tests.protect._prop import Rng


def test_ample_limit_keeps_requested_caps() raises:
    var b = DescriptorBudget(limit=100_000, base=20)
    b.reserve_udp(1)
    var h1 = b.register_tcp(4096, 256)
    var h2 = b.register_tcp(4096, 256)
    assert_equal_int(b.tcp_conn_cap(h1), 4096, "h1 keeps 4096")
    assert_equal_int(b.tcp_conn_cap(h2), 4096, "h2 keeps 4096")
    print("PASS: test_ample_limit_keeps_requested_caps")


def test_short_limit_clamps_proportionally() raises:
    var b = DescriptorBudget(limit=4096, base=20)
    b.reserve_udp(1)  # 17 descriptors
    var a = b.register_tcp(4096, 256)
    var c = b.register_tcp(1024, 256)
    var remainder = 4096 - 20 - (1 + FD_SLACK)
    var extra = remainder - 2 * (MIN_CONN_CAP + 256 + FD_SLACK)
    var weights = (4096 - MIN_CONN_CAP) + (1024 - MIN_CONN_CAP)
    assert_equal_int(
        b.tcp_conn_cap(a), MIN_CONN_CAP + extra * (4096 - MIN_CONN_CAP) // weights,
        "a gets its minimum plus its share of what is left beyond every minimum and overhead",
    )
    assert_equal_int(b.tcp_conn_cap(c), MIN_CONN_CAP + extra * (1024 - MIN_CONN_CAP) // weights, "c likewise")
    print("PASS: test_short_limit_clamps_proportionally")


def test_below_minimum_raises() raises:
    var b = DescriptorBudget(limit=300, base=20)
    var t = b.register_tcp(4096, 256)
    var raised = False
    try:
        _ = b.tcp_conn_cap(t)
    except e:
        raised = True
        assert_true("minimum" in String(e), "error names the minimum")
    assert_true(raised, "fewer than 64 connections raises")
    print("PASS: test_below_minimum_raises")


def test_frozen_after_first_resolution() raises:
    var b = DescriptorBudget(limit=100_000, base=20)
    var t = b.register_tcp(4096, 256)
    _ = b.tcp_conn_cap(t)
    var raised_tcp = False
    try:
        _ = b.register_tcp(10, 256)
    except:
        raised_tcp = True
    var raised_udp = False
    try:
        b.reserve_udp(1)
    except:
        raised_udp = True
    assert_true(raised_tcp and raised_udp, "late registration raises")
    print("PASS: test_frozen_after_first_resolution")


def test_split_is_order_independent_property() raises:
    """Registration order never changes any server's cap (300 random configurations)."""
    var rng = Rng(0xFD)
    for ci in range(300):
        var n = 1 + rng.below(4)
        var caps = List[Int]()
        for _ in range(n):
            caps.append(64 + rng.below(8000))
        var limit = 2000 + rng.below(40000)
        var fwd = DescriptorBudget(limit=limit, base=30)
        var rev = DescriptorBudget(limit=limit, base=30)
        fwd.reserve_udp(1)
        var tf = List[Int]()
        for i in range(n):
            tf.append(fwd.register_tcp(caps[i], 256))
        var tr = List[Int](length=n, fill=0)
        for i in range(n - 1, -1, -1):
            tr[i] = rev.register_tcp(caps[i], 256)
        rev.reserve_udp(1)
        for i in range(n):
            var a: Int
            var b: Int
            try:
                a = fwd.tcp_conn_cap(tf[i])
            except:
                a = -1
            try:
                b = rev.tcp_conn_cap(tr[i])
            except:
                b = -1
            assert_equal_int(a, b, "case " + String(ci) + " server " + String(i))
            assert_true(a == -1 or (a >= MIN_CONN_CAP and a <= caps[i]), "cap within [64, requested]")
    print("PASS: test_split_is_order_independent_property")


def test_from_process_is_sane() raises:
    var b = DescriptorBudget.from_process()
    assert_true(b.base >= 3, "stdio at least")
    assert_true(b.limit > b.base, "limit above what is already open")
    print("PASS: test_from_process_is_sane")


def test_unknown_token_raises() raises:
    """A token this budget never issued raises instead of reading out of bounds."""
    var b = DescriptorBudget(limit=100_000, base=20)
    _ = b.register_tcp(4096, 256)
    for bad in [-1, 1]:
        var raised = False
        try:
            _ = b.tcp_conn_cap(bad)
        except:
            raised = True
        assert_true(raised, "token " + String(bad) + " raises")
    print("PASS: test_unknown_token_raises")


def test_small_server_fits_beside_a_large_one() raises:
    """Caps 4096 and 64 need 4,704 descriptors of 8,176: both keep their request."""
    var b = DescriptorBudget(limit=8192, base=16)
    var big = b.register_tcp(4096, 256)
    var small = b.register_tcp(64, 256)
    assert_equal_int(b.tcp_conn_cap(big), 4096, "big keeps 4096")
    assert_equal_int(b.tcp_conn_cap(small), 64, "small keeps 64")
    print("PASS: test_small_server_fits_beside_a_large_one")


def test_requests_kept_when_everything_fits_property() raises:
    """500 random server sets: when Σ(cap + closing + slack) fits the remainder, every cap equals its request;
    otherwise the resolved caps never overcommit the remainder."""
    var rng = Rng(0xF17)
    for ci in range(500):
        var n = 1 + rng.below(5)
        var caps = List[Int]()
        var closing = List[Int]()
        var need = 0
        for _ in range(n):
            caps.append(64 + rng.below(8000))
            closing.append(1 + rng.below(512))
            need += caps[len(caps) - 1] + closing[len(closing) - 1] + FD_SLACK
        var udp = rng.below(3)
        var base = 3 + rng.below(100)
        var limit = max(base + udp * (1 + FD_SLACK) + need + rng.below(2000) - 1000, 0)
        var remainder = limit - base - udp * (1 + FD_SLACK)
        var b = DescriptorBudget(limit=limit, base=base)
        for _ in range(udp):
            b.reserve_udp(1)
        var tokens = List[Int]()
        for i in range(n):
            tokens.append(b.register_tcp(caps[i], closing[i]))
        var used = 0
        for i in range(n):
            var got: Int
            try:
                got = b.tcp_conn_cap(tokens[i])
            except:
                got = -1
            var ctx = "case " + String(ci) + " server " + String(i)
            if need <= remainder:
                assert_equal_int(got, caps[i], ctx + " keeps its request when everything fits")
            if got >= 0:
                assert_true(got >= MIN_CONN_CAP and got <= caps[i], ctx + " cap within [64, requested]")
                used += got + closing[i] + FD_SLACK
        assert_true(used <= max(remainder, 0), "case " + String(ci) + " never overcommits")
    print("PASS: test_requests_kept_when_everything_fits_property")


def _caps_or_raise(limit: Int, base: Int, caps: List[Int], closing: Int) raises -> List[Int]:
    """Resolve every server's cap; -1 where it raises."""
    var b = DescriptorBudget(limit=limit, base=base)
    var tokens = List[Int]()
    for c in caps:
        tokens.append(b.register_tcp(c, closing))
    var out = List[Int]()
    for t in tokens:
        try:
            out.append(b.tcp_conn_cap(t))
        except:
            out.append(-1)
    return out^


def test_small_server_keeps_its_minimum_one_short_of_fitting() raises:
    """Caps 4096 and 64 with 4,703 descriptors for a need of 4,704: the small server keeps 64."""
    var got = _caps_or_raise(16 + 4703, 16, [4096, 64], 256)
    assert_equal_int(got[1], 64, "small server keeps its minimum")
    assert_true(got[0] >= MIN_CONN_CAP and got[0] < 4096, "big server absorbs the shortfall")
    print("PASS: test_small_server_keeps_its_minimum_one_short_of_fitting")


def test_small_server_keeps_its_minimum_under_a_tight_limit() raises:
    """Limit 3,000 with caps 4096 and 100: the minimums (672 descriptors) fit, so neither raises."""
    var got = _caps_or_raise(3000, 16, [4096, 100], 256)
    assert_true(got[0] >= MIN_CONN_CAP, "big server resolves")
    assert_true(got[1] >= MIN_CONN_CAP and got[1] <= 100, "small server gets at least its minimum")
    print("PASS: test_small_server_keeps_its_minimum_under_a_tight_limit")


def test_minimums_fit_means_no_raise_property() raises:
    """500 random sets: when Σ(min(cap, 64) + closing + slack) fits, no server raises and each gets ≥ min(cap, 64)."""
    var rng = Rng(0x64F)
    for ci in range(500):
        var n = 1 + rng.below(5)
        var caps = List[Int]()
        var closing = List[Int]()
        var min_need = 0
        for _ in range(n):
            var c = 64 + rng.below(8000) if rng.chance(50) else 64 + rng.below(64)
            caps.append(c)
            closing.append(1 + rng.below(512))
            min_need += min(c, MIN_CONN_CAP) + closing[len(closing) - 1] + FD_SLACK
        var base = 3 + rng.below(100)
        var limit = max(base + min_need + rng.below(3000) - 200, 0)
        var remainder = limit - base
        var b = DescriptorBudget(limit=limit, base=base)
        var tokens = List[Int]()
        for i in range(n):
            tokens.append(b.register_tcp(caps[i], closing[i]))
        var used = 0
        for i in range(n):
            var got: Int
            try:
                got = b.tcp_conn_cap(tokens[i])
            except:
                got = -1
            var ctx = "case " + String(ci) + " server " + String(i)
            if min_need <= remainder:
                assert_true(got >= min(caps[i], MIN_CONN_CAP), ctx + " keeps at least its minimum")
            else:
                assert_equal_int(got, -1, ctx + " raises when the minimums cannot fit")
            if got >= 0:
                assert_true(got <= caps[i], ctx + " never above its request")
                used += got + closing[i] + FD_SLACK
        assert_true(used <= max(remainder, 0), "case " + String(ci) + " never overcommits")
    print("PASS: test_minimums_fit_means_no_raise_property")


def _register_raises(conn_cap: Int, closing_cap: Int) raises -> Bool:
    var b = DescriptorBudget(limit=4096, base=20)
    try:
        _ = b.register_tcp(conn_cap, closing_cap)
    except:
        return True
    return False


def test_register_rejects_out_of_range_caps() raises:
    """Caps that would wrap the split or overshoot it are refused at registration, not silently resolved."""
    var bad_conn = [Int.MAX - 100, -10000, -1, 0, MIN_CONN_CAP - 1, MAX_CONN_CAP + 1]
    for c in bad_conn:
        assert_true(_register_raises(c, 256), "conn_cap " + String(c) + " raises")
    var bad_closing = [Int.MAX - 100, -1, 0, MAX_CLOSING_CAP + 1]
    for c in bad_closing:
        assert_true(_register_raises(4096, c), "closing_cap " + String(c) + " raises")
    assert_true(not _register_raises(MIN_CONN_CAP, 1), "the lower bounds are accepted")
    assert_true(not _register_raises(MAX_CONN_CAP, MAX_CLOSING_CAP), "the upper bounds are accepted")
    print("PASS: test_register_rejects_out_of_range_caps")


def test_huge_request_is_clamped_not_returned() raises:
    """The largest accepted request under a 4,096 limit resolves within the remainder."""
    var b = DescriptorBudget(limit=4096, base=20)
    var t = b.register_tcp(MAX_CONN_CAP, MAX_CLOSING_CAP)
    var u = b.register_tcp(MAX_CONN_CAP, 256)
    var raised = False
    try:
        _ = b.tcp_conn_cap(t)
    except:
        raised = True
    assert_true(raised, "65,536 closing entries cannot fit 4,076 descriptors")
    var c = DescriptorBudget(limit=4096, base=20)
    var v = c.register_tcp(MAX_CONN_CAP, 256)
    var w = c.register_tcp(MAX_CONN_CAP, 256)
    var got = c.tcp_conn_cap(v) + c.tcp_conn_cap(w)
    assert_true(got + 2 * (256 + FD_SLACK) <= 4096 - 20, "two maximal requests share the remainder")
    _ = u
    print("PASS: test_huge_request_is_clamped_not_returned")


def test_negative_limits_and_udp_counts_are_rejected() raises:
    """A limit or base outside 0..MAX_FD_LIMIT, or a UDP reservation outside 1..MAX_UDP_SOCKETS, would skew or wrap the remainder."""
    var raised = 0
    try:
        _ = DescriptorBudget(limit=Int.MAX, base=0)
    except:
        raised += 1
    try:
        _ = DescriptorBudget(limit=4096, base=Int.MAX)
    except:
        raised += 1
    try:
        _ = DescriptorBudget(limit=-1, base=0)
    except:
        raised += 1
    try:
        _ = DescriptorBudget(limit=4096, base=-5)
    except:
        raised += 1
    var b = DescriptorBudget(limit=4096, base=20)
    for s in [0, -3, Int.MAX]:
        try:
            b.reserve_udp(s)
        except:
            raised += 1
    assert_equal_int(raised, 7, "every bad value raises")
    _ = DescriptorBudget(limit=MAX_FD_LIMIT, base=MAX_FD_LIMIT)
    print("PASS: test_negative_limits_and_udp_counts_are_rejected")


def _getrlimit_eperm(resource: Int32, rl: Pointer[UInt64, MutAnyOrigin]) -> Int:
    return -1  # EPERM


def test_getrlimit_failure_raises_with_errno() raises:
    """A failed getrlimit raises naming the errno instead of reporting a limit of 0."""
    var raised = False
    try:
        _ = _from_process_with[_getrlimit_eperm]()
    except e:
        raised = True
        assert_true("errno 1" in String(e), "error names the errno: " + String(e))
    assert_true(raised, "getrlimit failure raises")
    print("PASS: test_getrlimit_failure_raises_with_errno")


def test_default_closing_cap_fits_the_split() raises:
    """A quarter of `conn_cap`, clamped to `[1, MAX_CLOSING_CAP]`, and the split still resolves with it."""
    assert_equal_int(default_closing_cap(4096), 1024, "a quarter")
    assert_equal_int(default_closing_cap(MIN_CONN_CAP), 16, "a quarter of the minimum")
    assert_equal_int(default_closing_cap(1), 1, "never 0")
    assert_equal_int(default_closing_cap(MAX_CONN_CAP), MAX_CLOSING_CAP, "clamped to the maximum")
    var b = DescriptorBudget(limit=4096, base=10)
    var t = b.register_tcp(4096, default_closing_cap(4096))
    assert_equal_int(b.tcp_conn_cap(t), 4096 - 10 - 1024 - FD_SLACK, "a default server under a 4,096 limit")
    print("PASS: test_default_closing_cap_fits_the_split")


def main() raises:
    test_default_closing_cap_fits_the_split()
    test_ample_limit_keeps_requested_caps()
    test_short_limit_clamps_proportionally()
    test_below_minimum_raises()
    test_frozen_after_first_resolution()
    test_split_is_order_independent_property()
    test_from_process_is_sane()
    test_unknown_token_raises()
    test_small_server_fits_beside_a_large_one()
    test_requests_kept_when_everything_fits_property()
    test_small_server_keeps_its_minimum_one_short_of_fitting()
    test_small_server_keeps_its_minimum_under_a_tight_limit()
    test_minimums_fit_means_no_raise_property()
    test_register_rejects_out_of_range_caps()
    test_huge_request_is_clamped_not_returned()
    test_negative_limits_and_udp_counts_are_rejected()
    test_getrlimit_failure_raises_with_errno()
