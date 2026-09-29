"""ProtectionConfig defaults, validation and budget sharing; ProtectionStats starts at zero."""

from std.memory import ArcPointer

from navette.protect.config import ProtectionConfig, ProtectionStats, MAX_TIMEOUT_S
from navette.protect.descriptor_budget import DescriptorBudget, MAX_CONN_CAP, MAX_CLOSING_CAP
from navette.protect.memory_budget import MemoryBudget
from navette.util.siphash import SipKey
from tests._test_util import assert_true, assert_equal_int


def test_defaults_match_the_table() raises:
    var c = ProtectionConfig()
    assert_equal_int(c.conn_cap, 4096, "conn_cap")
    assert_equal_int(c.header_timeout_s, 10, "header")
    assert_equal_int(c.body_read_timeout_s, 30, "body")
    assert_equal_int(c.request_wall_s, 60, "wall")
    assert_equal_int(c.send_timeout_s, 30, "send")
    assert_equal_int(c.ipv6_source_prefix, 48, "prefix")
    assert_true(not c.fd_budget and not c.mem_budget, "no shared budgets by default")
    c.validate()
    ProtectionConfig(conn_cap=MAX_CONN_CAP).validate()
    ProtectionConfig(
        header_timeout_s=MAX_TIMEOUT_S,
        body_read_timeout_s=MAX_TIMEOUT_S,
        request_wall_s=MAX_TIMEOUT_S,
        send_timeout_s=MAX_TIMEOUT_S,
    ).validate()
    assert_equal_int(MAX_TIMEOUT_S, 86_400, "timeouts cap at one day")
    print("PASS: test_defaults_match_the_table")


def test_validate_rejects_disabling_values() raises:
    var bad = List[ProtectionConfig]()
    bad.append(ProtectionConfig(conn_cap=63))
    bad.append(ProtectionConfig(conn_cap=MAX_CONN_CAP + 1))
    bad.append(ProtectionConfig(conn_cap=Int.MAX - 100))
    bad.append(ProtectionConfig(conn_cap=-10000))
    bad.append(ProtectionConfig(header_timeout_s=0))
    bad.append(ProtectionConfig(request_wall_s=0))
    bad.append(ProtectionConfig(send_timeout_s=-1))
    bad.append(ProtectionConfig(ipv6_source_prefix=0))
    bad.append(ProtectionConfig(ipv6_source_prefix=129))
    # Seconds are multiplied into microseconds: an unbounded timeout would wrap.
    bad.append(ProtectionConfig(header_timeout_s=MAX_TIMEOUT_S + 1))
    bad.append(ProtectionConfig(body_read_timeout_s=Int.MAX))
    bad.append(ProtectionConfig(request_wall_s=Int.MAX // 1_000_000 + 1))
    bad.append(ProtectionConfig(send_timeout_s=MAX_TIMEOUT_S + 1))
    # No closing entry: a busy victim could never drain; the bound keeps table sizes from wrapping.
    bad.append(ProtectionConfig(closing_cap=0))
    bad.append(ProtectionConfig(closing_cap=-1))
    bad.append(ProtectionConfig(closing_cap=MAX_CLOSING_CAP + 1))
    for i in range(len(bad)):
        var raised = False
        try:
            bad[i].validate()
        except:
            raised = True
        assert_true(raised, "config " + String(i) + " rejected")
    print("PASS: test_validate_rejects_disabling_values")


def test_budgets_are_shared_not_copied() raises:
    var fds = ArcPointer(DescriptorBudget(limit=100_000, base=10))
    var mem = ArcPointer(MemoryBudget(1024, 8, SipKey(k0=UInt64(1), k1=UInt64(2))))
    var a = ProtectionConfig(fd_budget=fds, mem_budget=mem)
    var b = a.copy()
    _ = b.fd_budget.value()[].register_tcp(100, 256)
    b.mem_budget.value()[].budget = 2048
    assert_equal_int(fds[].limit, 100_000, "same descriptor budget")
    assert_equal_int(mem[].budget, 2048, "a copy of the config mutates the one shared budget")
    print("PASS: test_budgets_are_shared_not_copied")


def test_stats_start_at_zero() raises:
    var s = ProtectionStats()
    assert_true(s.retry_sent == 0 and s.refused_streams == 0 and s.egress_fallback_datagrams == 0, "zeroed")
    assert_true(s.closing_refused == 0 and s.busy_victims_killed == 0, "closing counters zeroed")
    print("PASS: test_stats_start_at_zero")


def test_closing_cap_scales_with_conn_cap() raises:
    """The default is a quarter of `conn_cap` within `[1, MAX_CLOSING_CAP]`; an explicit value wins."""
    assert_equal_int(ProtectionConfig().effective_closing_cap(), 1024, "a quarter of the default 4096")
    assert_equal_int(ProtectionConfig(conn_cap=64).effective_closing_cap(), 16, "a quarter of the minimum")
    assert_equal_int(ProtectionConfig(conn_cap=MAX_CONN_CAP).effective_closing_cap(), MAX_CLOSING_CAP, "clamped")
    assert_equal_int(ProtectionConfig(conn_cap=64, closing_cap=256).effective_closing_cap(), 256, "explicit wins")
    assert_equal_int(ProtectionConfig(closing_cap=1).effective_closing_cap(), 1, "even below the default")
    ProtectionConfig(closing_cap=1).validate()
    ProtectionConfig(closing_cap=MAX_CLOSING_CAP).validate()
    print("PASS: test_closing_cap_scales_with_conn_cap")


def main() raises:
    test_closing_cap_scales_with_conn_cap()
    test_defaults_match_the_table()
    test_validate_rejects_disabling_values()
    test_budgets_are_shared_not_copied()
    test_stats_start_at_zero()
