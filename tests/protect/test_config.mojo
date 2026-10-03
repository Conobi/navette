"""ProtectionConfig defaults and validation; ProtectionStats starts at zero."""

from navette.protect.config import ProtectionConfig, ProtectionStats, MIN_CONN_CAP, MAX_CONN_CAP
from tests._test_util import assert_true, assert_equal_int


def test_defaults_validate() raises:
    var c = ProtectionConfig()
    assert_equal_int(c.conn_cap, 4096, "conn_cap")
    c.validate()
    ProtectionConfig(conn_cap=MIN_CONN_CAP).validate()
    ProtectionConfig(conn_cap=MAX_CONN_CAP).validate()
    print("PASS: test_defaults_validate")


def test_validate_rejects_out_of_range_conn_cap() raises:
    var bad = List[Int]()
    bad.append(MIN_CONN_CAP - 1)
    bad.append(MAX_CONN_CAP + 1)
    bad.append(Int.MAX - 100)
    bad.append(-10000)
    for i in range(len(bad)):
        var raised = False
        try:
            ProtectionConfig(conn_cap=bad[i]).validate()
        except:
            raised = True
        assert_true(raised, "conn_cap " + String(bad[i]) + " rejected")
    print("PASS: test_validate_rejects_out_of_range_conn_cap")


def test_max_queue_delay_dial() raises:
    """Default 5 ms; 0 (off) and the 1 ms .. 10 s range validate, anything else in between raises."""
    assert_true(ProtectionConfig().max_queue_delay_us == 5_000, "default 5 ms")
    for ok in [UInt64(0), UInt64(1_000), UInt64(10_000_000)]:
        ProtectionConfig(max_queue_delay_us=ok).validate()
    for bad in [UInt64(1), UInt64(999), UInt64(10_000_001), UInt64.MAX]:
        var raised = False
        try:
            ProtectionConfig(max_queue_delay_us=bad).validate()
        except:
            raised = True
        assert_true(raised, "max_queue_delay_us " + String(bad) + " rejected")
    print("PASS: test_max_queue_delay_dial")


def test_stats_start_at_zero() raises:
    var s = ProtectionStats()
    assert_true(s.retry_sent == 0 and s.cap_rejections == 0 and s.unvalidated_handshaking_peak == 0, "zeroed")
    print("PASS: test_stats_start_at_zero")


def main() raises:
    test_defaults_validate()
    test_validate_rejects_out_of_range_conn_cap()
    test_max_queue_delay_dial()
    test_stats_start_at_zero()
