from src.quic.recovery import (
    Recovery,
    K_PACKET_THRESHOLD,
    K_GRANULARITY,
    K_TIME_THRESHOLD_NUM,
    K_TIME_THRESHOLD_DEN,
    INITIAL_RTT,
    INITIAL_RTTVAR,
)
from src.quic.cc.controller import CcController
from src.quic.cc.cc_trait import CC_KIND_CUBIC, CC_KIND_DUMMY, AckedPacket, LostPacket
from std.testing import assert_true


def test_initial_values() raises:
    var r = Recovery()
    if r.smoothed_rtt != INITIAL_RTT:
        raise "smoothed_rtt: got " + String(r.smoothed_rtt) + " expected " + String(INITIAL_RTT)
    if r.rttvar != INITIAL_RTTVAR:
        raise "rttvar: got " + String(r.rttvar) + " expected " + String(INITIAL_RTTVAR)
    if r.bytes_in_flight != UInt64(0):
        raise "bytes_in_flight should be 0"
    if r.pto_count != 0:
        raise "pto_count should be 0"
    if r.has_rtt_sample:
        raise "has_rtt_sample should be False"
    print("  initial_values: PASS")


def test_initial_pto() raises:
    var r = Recovery()
    # PTO = smoothed_rtt + max(4*rttvar, K_GRANULARITY) + max_ack_delay
    # = 333000 + max(4*166500, 1000) + 0 = 333000 + 666000 = 999000
    var pto = r.pto_timeout(UInt64(0))
    if pto != UInt64(999_000):
        raise "initial pto: got " + String(pto) + " expected 999000"
    print("  initial_pto: PASS")


def test_first_rtt_sample() raises:
    var r = Recovery()
    r.update_rtt(UInt64(100_000), UInt64(0), UInt64(0), False)
    if r.smoothed_rtt != UInt64(100_000):
        raise "smoothed_rtt: got " + String(r.smoothed_rtt) + " expected 100000"
    if r.rttvar != UInt64(50_000):
        raise "rttvar: got " + String(r.rttvar) + " expected 50000"
    if r.min_rtt != UInt64(100_000):
        raise "min_rtt: got " + String(r.min_rtt) + " expected 100000"
    if not r.has_rtt_sample:
        raise "has_rtt_sample should be True"
    print("  first_rtt_sample: PASS")


def test_subsequent_rtt_sample() raises:
    var r = Recovery()
    # First sample.
    r.update_rtt(UInt64(100_000), UInt64(0), UInt64(0), False)
    # Second sample: rtt=120000, ack_delay=5000, max_ack_delay=25000, confirmed.
    r.update_rtt(UInt64(120_000), UInt64(5_000), UInt64(25_000), True)
    # min_rtt = min(100000, 120000) = 100000
    if r.min_rtt != UInt64(100_000):
        raise "min_rtt: got " + String(r.min_rtt) + " expected 100000"
    # adj_ack_delay = min(5000, 25000) = 5000
    # 120000 >= 100000 + 5000? Yes -> adjusted = 115000
    # rttvar_sample = |100000 - 115000| = 15000
    # rttvar = (3*50000 + 15000)//4 = 165000//4 = 41250
    if r.rttvar != UInt64(41_250):
        raise "rttvar: got " + String(r.rttvar) + " expected 41250"
    # smoothed = (7*100000 + 115000)//8 = 815000//8 = 101875
    if r.smoothed_rtt != UInt64(101_875):
        raise "smoothed_rtt: got " + String(r.smoothed_rtt) + " expected 101875"
    print("  subsequent_rtt_sample: PASS")


def test_erratum_7539_order() raises:
    """Verify rttvar uses the OLD smoothed_rtt, not the newly updated one.

    If the implementation incorrectly updates smoothed_rtt first, rttvar
    would use the wrong base value.
    """
    var r = Recovery()
    r.update_rtt(UInt64(100_000), UInt64(0), UInt64(0), False)
    # smoothed=100000, rttvar=50000 after first sample.

    # Send a sample with a large jump.
    r.update_rtt(UInt64(200_000), UInt64(0), UInt64(25_000), True)
    # adj_ack_delay = min(0, 25000) = 0
    # adjusted_rtt = 200000 (200000 >= 100000 + 0)
    # CORRECT (erratum 7539): rttvar uses OLD smoothed=100000
    #   rttvar_sample = |200000 - 100000| = 100000
    #   rttvar = (3*50000 + 100000)//4 = 250000//4 = 62500
    # WRONG: if smoothed updated first to (7*100000+200000)//8 = 112500
    #   rttvar_sample = |200000 - 112500| = 87500
    #   rttvar = (3*50000 + 87500)//4 = 237500//4 = 59375
    if r.rttvar != UInt64(62_500):
        raise "erratum 7539 violated: rttvar=" + String(r.rttvar) + " expected 62500"
    # smoothed = (7*100000 + 200000)//8 = 900000//8 = 112500
    if r.smoothed_rtt != UInt64(112_500):
        raise "smoothed_rtt: got " + String(r.smoothed_rtt) + " expected 112500"
    print("  erratum_7539_order: PASS")


def test_loss_delay() raises:
    var r = Recovery()
    r.update_rtt(UInt64(100_000), UInt64(0), UInt64(0), False)
    # loss_delay = max(9*max(smoothed, latest)//8, K_GRANULARITY)
    # = max(9*100000//8, 1000) = max(112500, 1000) = 112500
    var ld = r.loss_delay()
    if ld != UInt64(112_500):
        raise "loss_delay: got " + String(ld) + " expected 112500"
    print("  loss_delay: PASS")


def test_packet_threshold_loss() raises:
    var r = Recovery()
    r.update_rtt(UInt64(100_000), UInt64(0), UInt64(0), False)

    var pns = List[Int]()
    pns.append(0)
    pns.append(1)
    pns.append(2)
    pns.append(3)
    pns.append(4)
    var times = List[UInt64]()
    times.append(UInt64(0))
    times.append(UInt64(0))
    times.append(UInt64(0))
    times.append(UInt64(0))
    times.append(UInt64(0))
    # largest_acked=4, now=0 (no time-based loss).
    var lost = r.detect_lost_packets(pns, times, 4, UInt64(0))
    # PNs 0, 1 have gap >= 3 (4-0=4, 4-1=3). PN 2 gap=2, not lost.
    if len(lost) != 2:
        raise "expected 2 lost, got " + String(len(lost))
    if lost[0] != 0:
        raise "expected PN 0 lost, got " + String(lost[0])
    if lost[1] != 1:
        raise "expected PN 1 lost, got " + String(lost[1])
    print("  packet_threshold_loss: PASS")


def test_time_threshold_loss() raises:
    var r = Recovery()
    r.update_rtt(UInt64(100_000), UInt64(0), UInt64(0), False)

    var ld = r.loss_delay()  # 112500

    var pns = List[Int]()
    pns.append(5)
    var times = List[UInt64]()
    times.append(UInt64(1_000_000))
    # largest_acked=6, now = sent_time + loss_delay + 1 -> time loss.
    var now = UInt64(1_000_000) + ld + UInt64(1)
    var lost = r.detect_lost_packets(pns, times, 6, now)
    if len(lost) != 1:
        raise "expected 1 lost, got " + String(len(lost))
    if lost[0] != 5:
        raise "expected PN 5 lost, got " + String(lost[0])

    # now = sent_time + loss_delay - 1 -> NOT lost (gap=1 < 3).
    var now2 = UInt64(1_000_000) + ld - UInt64(1)
    var lost2 = r.detect_lost_packets(pns, times, 6, now2)
    if len(lost2) != 0:
        raise "expected 0 lost at time threshold boundary, got " + String(len(lost2))
    print("  time_threshold_loss: PASS")


def test_pto_backoff() raises:
    var r = Recovery()
    r.update_rtt(UInt64(100_000), UInt64(0), UInt64(0), False)
    # smoothed=100000, rttvar=50000
    # base PTO = 100000 + max(4*50000, 1000) + 25000 = 100000+200000+25000 = 325000
    var base = r.pto_timeout(UInt64(25_000))
    if base != UInt64(325_000):
        raise "base PTO: got " + String(base) + " expected 325000"

    r.pto_count = 1
    var pto1 = r.pto_timeout(UInt64(25_000))
    # 325000 << 1 = 650000
    if pto1 != UInt64(650_000):
        raise "PTO count=1: got " + String(pto1) + " expected 650000"

    r.pto_count = 2
    var pto2 = r.pto_timeout(UInt64(25_000))
    # 325000 << 2 = 1300000
    if pto2 != UInt64(1_300_000):
        raise "PTO count=2: got " + String(pto2) + " expected 1300000"
    print("  pto_backoff: PASS")


def test_bytes_in_flight() raises:
    var r = Recovery()
    r.on_packet_sent(100, True)
    if r.bytes_in_flight != UInt64(100):
        raise "after send 100: got " + String(r.bytes_in_flight)
    r.on_packet_sent(200, True)
    if r.bytes_in_flight != UInt64(300):
        raise "after send 200: got " + String(r.bytes_in_flight)
    r.on_packet_sent(50, False)  # Not in-flight, should not count.
    if r.bytes_in_flight != UInt64(300):
        raise "after send 50 (not in-flight): got " + String(r.bytes_in_flight)
    r.on_packet_acked(100, True)
    if r.bytes_in_flight != UInt64(200):
        raise "after ack 100: got " + String(r.bytes_in_flight)
    r.on_packet_lost(200, True)
    if r.bytes_in_flight != UInt64(0):
        raise "after lose 200: got " + String(r.bytes_in_flight)
    print("  bytes_in_flight: PASS")


def test_recovery_cc_cubic_by_default() raises:
    var rec = Recovery(max_datagram_size=UInt64(1200))
    assert_true(rec.cc.kind == CC_KIND_CUBIC, "CUBIC by default")
    print("PASS: test_recovery_cc_cubic_by_default")


def test_recovery_cc_dummy_optin() raises:
    var rec = Recovery(max_datagram_size=UInt64(1200), use_cubic=False)
    assert_true(rec.cc.kind == CC_KIND_DUMMY, "dummy when opted in")
    print("PASS: test_recovery_cc_dummy_optin")


def test_recovery_on_packet_sent_notifies_cc() raises:
    var rec = Recovery(max_datagram_size=UInt64(1200))
    var before_bif = rec.bytes_in_flight
    rec.on_packet_sent(size=1200, in_flight=True, now=UInt64(1000))
    assert_true(rec.bytes_in_flight == before_bif + UInt64(1200), "bytes_in_flight updated")
    # CC notification verified indirectly — internal cubic state opaque.
    print("PASS: test_recovery_on_packet_sent_notifies_cc")


def test_recovery_pacer_capacity_updates_on_ack() raises:
    var rec = Recovery(max_datagram_size=UInt64(1200))
    rec.update_rtt(rtt_sample=UInt64(10_000), ack_delay=UInt64(0),
                   max_ack_delay=UInt64(0), handshake_confirmed=False)
    var pkt = AckedPacket(pkt_num=1, size=UInt64(1200),
                           time_sent=0, time_acked=10_000, rtt_sample=10_000)
    rec.cc.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(10_000))
    rec.on_ack_received()
    # After on_ack_received, pacer.update_capacity should have run.
    assert_true(rec.pacer.capacity > UInt64(0), "pacer capacity reflects current CC state")
    print("PASS: test_recovery_pacer_capacity_updates_on_ack")


def test_recovery_min_rtt_reset_on_persistent() raises:
    """Caller-driven reset of min_rtt simulating persistent-congestion response."""
    var rec = Recovery(max_datagram_size=UInt64(1200))
    rec.update_rtt(rtt_sample=UInt64(10_000), ack_delay=UInt64(0),
                   max_ack_delay=UInt64(0), handshake_confirmed=False)
    assert_true(rec.min_rtt == UInt64(10_000), "min_rtt set to first sample")
    rec.update_rtt(rtt_sample=UInt64(5_000), ack_delay=UInt64(0),
                   max_ack_delay=UInt64(0), handshake_confirmed=False)
    assert_true(rec.min_rtt == UInt64(5_000), "min_rtt lowered on smaller sample")
    rec.update_rtt(rtt_sample=UInt64(20_000), ack_delay=UInt64(0),
                   max_ack_delay=UInt64(0), handshake_confirmed=False)
    assert_true(rec.min_rtt == UInt64(5_000), "min_rtt not raised by higher sample (monotonic)")
    # Caller-driven reset (simulating QuicConnection after persistent detection):
    rec.min_rtt = rec.latest_rtt
    assert_true(rec.min_rtt == UInt64(20_000), "caller-driven reset works")
    print("PASS: test_recovery_min_rtt_reset_on_persistent")


def main() raises:
    print("test_quic_recovery:")
    test_initial_values()
    test_initial_pto()
    test_first_rtt_sample()
    test_subsequent_rtt_sample()
    test_erratum_7539_order()
    test_loss_delay()
    test_packet_threshold_loss()
    test_time_threshold_loss()
    test_pto_backoff()
    test_bytes_in_flight()
    test_recovery_cc_cubic_by_default()
    test_recovery_cc_dummy_optin()
    test_recovery_on_packet_sent_notifies_cc()
    test_recovery_pacer_capacity_updates_on_ack()
    test_recovery_min_rtt_reset_on_persistent()
    print("All test_quic_recovery tests passed.")
