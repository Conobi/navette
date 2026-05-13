from mojo_net.quic.cc.pacing import Pacer
from std.testing import assert_true

def test_pacer_init_defaults() raises:
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    assert_true(p.enabled, "enabled by default")
    assert_true(p.tokens == UInt64(0), "starts with zero tokens")
    assert_true(p.max_datagram_size == UInt64(1200), "MDS stored")
    print("PASS: test_pacer_init_defaults")

def test_pacer_disabled_returns_none() raises:
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    p.enabled = False
    var r = p.next_send_time(UInt64(1_000_000), UInt64(0))
    assert_true(not r, "disabled pacer returns None")
    print("PASS: test_pacer_disabled_returns_none")

def test_pacer_zero_rate_returns_none() raises:
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    var r = p.next_send_time(UInt64(0), UInt64(0))
    assert_true(not r, "zero rate treated as unpaced")
    print("PASS: test_pacer_zero_rate_returns_none")

def test_pacer_update_capacity_clamp_min() raises:
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    # Tiny cwnd/srtt combination → capacity clamps to 10 * MDS = 12000.
    p.update_capacity(cwnd=UInt64(100), smoothed_rtt_us=UInt64(1_000_000))
    assert_true(p.capacity == UInt64(12000), "clamped to min 10 MTU")
    print("PASS: test_pacer_update_capacity_clamp_min")

def test_pacer_update_capacity_clamp_max() raises:
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    # Huge cwnd/tiny srtt → capacity clamps to 128 * MDS = 153600.
    p.update_capacity(cwnd=UInt64(10_000_000), smoothed_rtt_us=UInt64(1000))
    assert_true(p.capacity == UInt64(153_600), "clamped to max 128 MTU")
    print("PASS: test_pacer_update_capacity_clamp_max")

def test_pacer_tokens_cap_at_capacity() raises:
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    p.update_capacity(cwnd=UInt64(1_200_000), smoothed_rtt_us=UInt64(10_000))
    # capacity = (1_200_000 * 1000) / 10_000 = 120_000; clamped within [12000, 153_600] → 120_000.
    var ok = p.refill_and_check(pacing_rate_bps=UInt64(100_000_000), now=UInt64(10_000_000))
    # huge time elapsed since last_sched_time=0 → tokens saturate at capacity.
    assert_true(ok, "can send after saturation")
    assert_true(p.tokens <= p.capacity, "tokens don't exceed capacity")
    print("PASS: test_pacer_tokens_cap_at_capacity")

def test_pacer_refill_and_check_returns_true_when_enough() raises:
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    p.update_capacity(cwnd=UInt64(12_000), smoothed_rtt_us=UInt64(1000))
    # rate = 12_000_000 bytes/sec, elapsed = 1ms → refill = 12000 bytes ≥ 1200 MDS.
    var ok = p.refill_and_check(pacing_rate_bps=UInt64(12_000_000), now=UInt64(1000))
    assert_true(ok, "1ms at 12MB/s accrues 12000 bytes >= MDS")
    print("PASS: test_pacer_refill_and_check_returns_true_when_enough")

def test_pacer_next_send_time_pure() raises:
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    # tokens = 0, rate = 1_200_000 bytes/sec, need 1200 bytes → need 1ms.
    p.last_sched_time = UInt64(0)
    var r = p.next_send_time(pacing_rate_bps=UInt64(1_200_000), now=UInt64(0))
    assert_true(Bool(r), "some deadline returned")
    # Purity: state must NOT mutate.
    assert_true(p.last_sched_time == UInt64(0), "last_sched_time unchanged (pure)")
    assert_true(p.tokens == UInt64(0), "tokens unchanged (pure)")
    print("PASS: test_pacer_next_send_time_pure")

def test_pacer_on_sent_saturating() raises:
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    p.tokens = UInt64(500)
    p.on_sent(UInt64(1000))  # overconsume
    assert_true(p.tokens == UInt64(0), "saturating subtract to zero, no underflow")
    print("PASS: test_pacer_on_sent_saturating")

def main() raises:
    test_pacer_init_defaults()
    test_pacer_disabled_returns_none()
    test_pacer_zero_rate_returns_none()
    test_pacer_update_capacity_clamp_min()
    test_pacer_update_capacity_clamp_max()
    test_pacer_tokens_cap_at_capacity()
    test_pacer_refill_and_check_returns_true_when_enough()
    test_pacer_next_send_time_pure()
    test_pacer_on_sent_saturating()
    print("All pacing tests passed.")
