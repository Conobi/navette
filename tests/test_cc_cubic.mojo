# tests/test_cc_cubic.mojo
# CUBIC congestion controller tests per spec §9.1 (RFC 9438).

from src.quic.cc.cubic import Cubic, _cube_root_u64
from src.quic.cc.cc_trait import AckedPacket, LostPacket, INITIAL_WINDOW_BYTES_CAP
from std.testing import assert_true

comptime MDS: UInt64 = 1200


def test_cubic_init_initial_window() raises:
    var c = Cubic(max_datagram_size=MDS)
    var expected = min(UInt64(10) * MDS, INITIAL_WINDOW_BYTES_CAP)
    assert_true(c.cwnd() == expected, "initial window per RFC 9002 §7.2")
    assert_true(c.ssthresh > c.cwnd(), "ssthresh starts unlimited-ish")
    print("PASS: test_cubic_init_initial_window")


def test_cubic_slow_start_growth() raises:
    var c = Cubic(max_datagram_size=MDS)
    var start = c.cwnd()
    var pkt = AckedPacket(pkt_num=UInt64(1), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(1000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(1000), now=UInt64(1000))
    assert_true(c.cwnd() == start + MDS, "slow-start adds MDS per ACK")
    print("PASS: test_cubic_slow_start_growth")


def test_cubic_enters_ca_after_loss() raises:
    var c = Cubic(max_datagram_size=MDS)
    c._cwnd_value = UInt64(100_000)
    c.ssthresh = UInt64(200_000)
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=UInt64(1), size=MDS, time_sent=UInt64(0)))
    c.on_packets_lost(lost, smoothed_rtt_us=UInt64(50_000),
                       now=UInt64(100_000), persistent=False)
    assert_true(c.cwnd() < UInt64(100_000), "cwnd reduced after loss")
    assert_true(c.cwnd() >= UInt64(2) * MDS, "cwnd >= min_cwnd after loss")
    assert_true(c.ssthresh == c.cwnd(), "ssthresh = new cwnd after congestion event")
    print("PASS: test_cubic_enters_ca_after_loss")


def test_cubic_beta_0_7() raises:
    var c = Cubic(max_datagram_size=MDS)
    c._cwnd_value = UInt64(100_000)
    c.ssthresh = UInt64(200_000)
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=UInt64(1), size=MDS, time_sent=UInt64(0)))
    c.on_packets_lost(lost, smoothed_rtt_us=UInt64(50_000),
                       now=UInt64(100_000), persistent=False)
    # beta = 0.7 → new cwnd = 70_000
    assert_true(c.cwnd() == UInt64(70_000), "cwnd = old * 0.7")
    print("PASS: test_cubic_beta_0_7")


def test_cubic_persistent_resets_to_min() raises:
    var c = Cubic(max_datagram_size=MDS)
    c._cwnd_value = UInt64(500_000)
    c.ssthresh = UInt64(400_000)
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=UInt64(1), size=MDS, time_sent=UInt64(0)))
    c.on_packets_lost(lost, smoothed_rtt_us=UInt64(50_000),
                       now=UInt64(100_000), persistent=True)
    assert_true(c.cwnd() == UInt64(2) * MDS, "persistent resets cwnd to min (2*MDS)")
    assert_true(c.w_max == UInt64(0), "w_max cleared on persistent")
    print("PASS: test_cubic_persistent_resets_to_min")


def test_cubic_pacing_slow_start_2x_gain() raises:
    var c = Cubic(max_datagram_size=MDS)
    # cwnd < ssthresh → slow-start → gain 2.0
    var rate = c.pacing_rate(smoothed_rtt_us=UInt64(100_000))
    var expected = UInt64(2) * c.cwnd() * UInt64(1_000_000) // UInt64(100_000)
    assert_true(rate == expected, "SS gain 2.0")
    print("PASS: test_cubic_pacing_slow_start_2x_gain")


def test_cubic_pacing_ca_1_25x_gain() raises:
    var c = Cubic(max_datagram_size=MDS)
    c._cwnd_value = UInt64(100_000)
    c.ssthresh = UInt64(50_000)  # force CA
    var rate = c.pacing_rate(smoothed_rtt_us=UInt64(100_000))
    var expected = UInt64(5) * c.cwnd() * UInt64(1_000_000) // (UInt64(4) * UInt64(100_000))
    assert_true(rate == expected, "CA gain 1.25")
    print("PASS: test_cubic_pacing_ca_1_25x_gain")


def test_cubic_pacing_zero_srtt_guarded() raises:
    var c = Cubic(max_datagram_size=MDS)
    var rate = c.pacing_rate(smoothed_rtt_us=UInt64(0))  # would divide by zero naively
    assert_true(rate > UInt64(0), "no division by zero; rate finite")
    print("PASS: test_cubic_pacing_zero_srtt_guarded")


def test_cubic_suppress_double_loss_within_rtt() raises:
    var c = Cubic(max_datagram_size=MDS)
    c._cwnd_value = UInt64(100_000)
    c.ssthresh = UInt64(200_000)
    var lost1 = List[LostPacket]()
    lost1.append(LostPacket(pkt_num=UInt64(1), size=MDS, time_sent=UInt64(0)))
    c.on_packets_lost(lost1, smoothed_rtt_us=UInt64(50_000),
                       now=UInt64(100_000), persistent=False)
    var after_first = c.cwnd()
    var lost2 = List[LostPacket]()
    lost2.append(LostPacket(pkt_num=UInt64(2), size=MDS, time_sent=UInt64(0)))
    # now = 110_000 < 100_000 + 1*50_000 = 150_000 → suppressed
    c.on_packets_lost(lost2, smoothed_rtt_us=UInt64(50_000),
                       now=UInt64(110_000), persistent=False)
    assert_true(c.cwnd() == after_first, "suppressed; cwnd unchanged")
    print("PASS: test_cubic_suppress_double_loss_within_rtt")


def test_cubic_fast_convergence() raises:
    var c = Cubic(max_datagram_size=MDS)
    c._cwnd_value = UInt64(200_000)
    c.ssthresh = UInt64(300_000)
    c.w_last_max = UInt64(300_000)  # prior max larger than current cwnd → fast convergence
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=UInt64(1), size=MDS, time_sent=UInt64(0)))
    c.on_packets_lost(lost, smoothed_rtt_us=UInt64(50_000),
                       now=UInt64(100_000), persistent=False)
    # w_last_max updated, w_max = cwnd * (1 + beta) / 2 = 200_000 * 17/20 = 170_000
    assert_true(c.w_max == UInt64(170_000), "fast convergence w_max")
    print("PASS: test_cubic_fast_convergence")


def test_cubic_reno_friendly_w_est_tracks() raises:
    var c = Cubic(max_datagram_size=MDS)
    c._cwnd_value = UInt64(100_000)
    c.ssthresh = UInt64(50_000)  # CA
    c.w_est = UInt64(100_000)
    var pkt = AckedPacket(pkt_num=UInt64(1), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(1000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(1000), now=UInt64(1000))
    assert_true(c.w_est > UInt64(100_000), "w_est grew with AIMD rule")
    print("PASS: test_cubic_reno_friendly_w_est_tracks")


def test_cubic_copy_semantics() raises:
    var c = Cubic(max_datagram_size=MDS)
    c._cwnd_value = UInt64(50_000)
    var c2 = c
    assert_true(c2.cwnd() == UInt64(50_000), "copy preserves cwnd")
    c._cwnd_value = UInt64(70_000)
    assert_true(c2.cwnd() == UInt64(50_000), "copy is independent")
    print("PASS: test_cubic_copy_semantics")


def test_cube_root_newton_correct() raises:
    """Integer cube root helper correctness on edge cases."""
    assert_true(_cube_root_u64(UInt64(0)) == UInt64(0), "cbrt(0)=0")
    assert_true(_cube_root_u64(UInt64(1)) == UInt64(1), "cbrt(1)=1")
    assert_true(_cube_root_u64(UInt64(8)) == UInt64(2), "cbrt(8)=2")
    assert_true(_cube_root_u64(UInt64(27)) == UInt64(3), "cbrt(27)=3")
    assert_true(
        _cube_root_u64(UInt64(1_000_000_000_000)) == UInt64(10_000),
        "cbrt(1e12)=1e4",
    )
    print("PASS: test_cube_root_newton_correct")


def test_cubic_overflow_clamp_not_hit_normal_rtt() raises:
    """With normal RTT (100ms, 1s), cubic curve doesn't trip MAX_CWND clamp."""
    var c = Cubic(max_datagram_size=MDS)
    c._cwnd_value = UInt64(500_000)
    c.ssthresh = UInt64(400_000)
    c.w_max = UInt64(500_000)
    c.epoch_start = UInt64(1_000_000)
    # Simulate 1 second past epoch.
    var pkt = AckedPacket(pkt_num=UInt64(1), size=MDS,
                           time_sent=UInt64(1_000_000),
                           time_acked=UInt64(2_000_000),
                           rtt_sample=UInt64(100_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(100_000), now=UInt64(2_000_000))
    assert_true(c.cwnd() < UInt64(1_073_741_824), "cwnd below 1 GiB clamp for normal RTT")
    print("PASS: test_cubic_overflow_clamp_not_hit_normal_rtt")


def main() raises:
    test_cubic_init_initial_window()
    test_cubic_slow_start_growth()
    test_cubic_enters_ca_after_loss()
    test_cubic_beta_0_7()
    test_cubic_persistent_resets_to_min()
    test_cubic_pacing_slow_start_2x_gain()
    test_cubic_pacing_ca_1_25x_gain()
    test_cubic_pacing_zero_srtt_guarded()
    test_cubic_suppress_double_loss_within_rtt()
    test_cubic_fast_convergence()
    test_cubic_reno_friendly_w_est_tracks()
    test_cubic_copy_semantics()
    test_cube_root_newton_correct()
    test_cubic_overflow_clamp_not_hit_normal_rtt()
    print("All cubic tests passed.")
