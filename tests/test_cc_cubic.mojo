# tests/test_cc_cubic.mojo
# CUBIC congestion controller tests per spec §9.1 (RFC 9438).

from navette.quic.cc.cubic import (Cubic, _cube_root_u64,
    HS_STATE_SS, HS_STATE_CSS, HS_STATE_DONE)
from navette.quic.cc.cc_trait import AckedPacket, LostPacket, INITIAL_WINDOW_BYTES_CAP
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


def test_hystart_initial_state() raises:
    var c = Cubic(max_datagram_size=MDS)
    assert_true(c.hs_state == HS_STATE_SS, "starts in SS")
    assert_true(c.hs_window_end_pn == UInt64(0), "window end starts at 0")
    print("PASS: test_hystart_initial_state")


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


def test_congestion_event_reduces_cwnd() raises:
    var c = Cubic(max_datagram_size=MDS)
    # Force into CA (above ssthresh).
    c._cwnd_value = UInt64(100_000)
    c.ssthresh = UInt64(50_000)
    var before = c.cwnd()
    c._on_congestion_event(smoothed_rtt=UInt64(50_000), now=UInt64(200_000))
    assert_true(c.cwnd() < before, "CE mark reduces cwnd")
    assert_true(c.hs_state == HS_STATE_DONE, "CE disables HyStart++")
    print("PASS: test_congestion_event_reduces_cwnd")


def test_congestion_event_suppressed_within_rtt() raises:
    var c = Cubic(max_datagram_size=MDS)
    c._cwnd_value = UInt64(100_000)
    c.ssthresh = UInt64(50_000)
    c._on_congestion_event(smoothed_rtt=UInt64(50_000), now=UInt64(200_000))
    var after_first = c.cwnd()
    # Second event within 1 RTT (now < 200_000 + 50_000 = 250_000).
    c._on_congestion_event(smoothed_rtt=UInt64(50_000), now=UInt64(220_000))
    assert_true(c.cwnd() == after_first, "second CE within RTT is suppressed")
    print("PASS: test_congestion_event_suppressed_within_rtt")


# ── HyStart++ tests (RFC 9406 §4) ────────────────────────────────────────────

def test_hystart_no_exit_before_min_samples() raises:
    """Round with fewer than 8 samples never triggers CSS."""
    var c = Cubic(max_datagram_size=MDS)
    c.hs_last_round_min_rtt = UInt64(10_000)   # 10ms baseline
    c.hs_window_end_pn = UInt64(5)
    # Only 4 samples collected — below HYSTART_MIN_SAMPLES (8).
    c.hs_rtt_sample_count = 4
    c.hs_current_round_min_rtt = UInt64(25_000)  # would trigger if count were 8
    var pkt = AckedPacket(pkt_num=UInt64(5), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(25_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(1000))
    assert_true(c.hs_state == HS_STATE_SS, "< 8 samples: stays in SS")
    print("PASS: test_hystart_no_exit_before_min_samples")


def test_hystart_enters_css_on_rtt_increase() raises:
    """If current round min RTT > last round min RTT + thresh → enter CSS."""
    var c = Cubic(max_datagram_size=MDS)
    c.hs_last_round_min_rtt = UInt64(10_000)  # 10ms last round
    # thresh = max(10000/8, 4000) = max(1250, 4000) = 4000us
    # current = 22000 >= 10000 + 4000 = 14000 → CSS
    c.hs_current_round_min_rtt = UInt64(22_000)
    c.hs_rtt_sample_count = 8   # already at minimum samples
    c.hs_window_end_pn = UInt64(5)
    var pkt = AckedPacket(pkt_num=UInt64(5), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(22_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(1000))
    assert_true(c.hs_state == HS_STATE_CSS, "RTT increase → CSS")
    assert_true(c.hs_css_rounds == 0, "CSS rounds reset to 0")
    print("PASS: test_hystart_enters_css_on_rtt_increase")


def test_hystart_css_growth_is_quartered() raises:
    """In CSS, cwnd grows by acked/4, not acked."""
    var c = Cubic(max_datagram_size=MDS)
    c.hs_state = HS_STATE_CSS
    var before = c.cwnd()
    var pkt = AckedPacket(pkt_num=UInt64(1), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(10_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(1000))
    var expected_inc = MDS // UInt64(4)
    assert_true(c.cwnd() == before + expected_inc, "CSS growth = acked/4")
    print("PASS: test_hystart_css_growth_is_quartered")


def test_hystart_exits_after_css_rounds() raises:
    """After HYSTART_CSS_ROUNDS (5) CSS rounds, set ssthresh = cwnd, state = DONE."""
    var c = Cubic(max_datagram_size=MDS)
    c.hs_state = HS_STATE_CSS
    c.hs_css_rounds = 4   # one more round will hit HYSTART_CSS_ROUNDS = 5
    c.hs_last_round_min_rtt = UInt64(10_000)
    c.hs_current_round_min_rtt = UInt64(11_000)
    c.hs_rtt_sample_count = 8
    c.hs_window_end_pn = UInt64(5)
    var pkt = AckedPacket(pkt_num=UInt64(5), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(11_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(1000))
    assert_true(c.hs_state == HS_STATE_DONE, "exits to DONE after 5 CSS rounds")
    assert_true(c.ssthresh <= c.cwnd(), "ssthresh set from cwnd at CSS exit")
    print("PASS: test_hystart_exits_after_css_rounds")


def test_hystart_no_reentry_after_loss() raises:
    """Loss transitions to HS_STATE_DONE; subsequent rounds stay DONE."""
    var c = Cubic(max_datagram_size=MDS)
    assert_true(c.hs_state == HS_STATE_SS, "starts SS")
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=UInt64(1), size=MDS, time_sent=UInt64(0)))
    c.on_packets_lost(lost, smoothed_rtt_us=UInt64(10_000),
                       now=UInt64(50_000), persistent=False)
    assert_true(c.hs_state == HS_STATE_DONE, "loss → DONE")
    c.hs_current_round_min_rtt = UInt64(22_000)
    c.hs_rtt_sample_count = 8
    c.hs_window_end_pn = UInt64(10)
    var pkt = AckedPacket(pkt_num=UInt64(10), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(2000),
                           rtt_sample=UInt64(22_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(2000))
    assert_true(c.hs_state == HS_STATE_DONE, "stays DONE after loss")
    print("PASS: test_hystart_no_reentry_after_loss")


def test_hystart_stable_rtt_stays_in_ss() raises:
    """Flat RTT (no increase beyond threshold) never triggers CSS."""
    var c = Cubic(max_datagram_size=MDS)
    c.hs_last_round_min_rtt = UInt64(10_000)  # 10ms baseline
    # thresh = 4ms; current = 11ms < 10ms + 4ms = 14ms → stays SS
    c.hs_current_round_min_rtt = UInt64(11_000)
    c.hs_rtt_sample_count = 8
    c.hs_window_end_pn = UInt64(5)
    var pkt = AckedPacket(pkt_num=UInt64(5), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(11_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(1000))
    assert_true(c.hs_state == HS_STATE_SS, "stable RTT stays in SS")
    print("PASS: test_hystart_stable_rtt_stays_in_ss")


def test_hystart_thresh_clamped() raises:
    """Threshold is clamped to [4ms, 16ms]."""
    var c = Cubic(max_datagram_size=MDS)

    # Fast path: last_min_rtt = 10ms → raw = 10000/8 = 1250us < 4000us → thresh = 4ms.
    c.hs_last_round_min_rtt = UInt64(10_000)
    c.hs_current_round_min_rtt = UInt64(14_100)  # just above 14000
    c.hs_rtt_sample_count = 8
    c.hs_window_end_pn = UInt64(1)
    var pkt = AckedPacket(pkt_num=UInt64(1), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(14_100))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(1000))
    assert_true(c.hs_state == HS_STATE_CSS, "fast path: thresh clamped to 4ms")

    # Slow path: last_min_rtt = 200ms → raw = 200000/8 = 25000 > 16000 → thresh = 16ms.
    var c2 = Cubic(max_datagram_size=MDS)
    c2.hs_last_round_min_rtt = UInt64(200_000)
    c2.hs_current_round_min_rtt = UInt64(216_100)
    c2.hs_rtt_sample_count = 8
    c2.hs_window_end_pn = UInt64(1)
    var pkt2 = AckedPacket(pkt_num=UInt64(1), size=MDS,
                            time_sent=UInt64(0), time_acked=UInt64(1000),
                            rtt_sample=UInt64(216_100))
    c2.on_packet_acked(pkt2, smoothed_rtt_us=UInt64(200_000), now=UInt64(1000))
    assert_true(c2.hs_state == HS_STATE_CSS, "slow path: thresh clamped to 16ms")
    print("PASS: test_hystart_thresh_clamped")


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
    test_hystart_initial_state()
    test_cubic_overflow_clamp_not_hit_normal_rtt()
    test_congestion_event_reduces_cwnd()
    test_congestion_event_suppressed_within_rtt()
    test_hystart_no_exit_before_min_samples()
    test_hystart_enters_css_on_rtt_increase()
    test_hystart_css_growth_is_quartered()
    test_hystart_exits_after_css_rounds()
    test_hystart_no_reentry_after_loss()
    test_hystart_stable_rtt_stays_in_ss()
    test_hystart_thresh_clamped()
    print("All cubic tests passed.")
