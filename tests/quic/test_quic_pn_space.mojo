# tests/test_quic_pn_space.mojo
# Tests for PacketNumberSpace: PN allocation, ACK tracking, SentPacket records.

from navette.quic.frame import AckFrame, AckRange, Frame
from navette.quic.packet import PacketType
from navette.quic.pn_space import (
    EncryptionLevel,
    PacketNumberSpace,
    SentPacket,
    AckRangeEntry,
    packet_type_to_space,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _assert_eq(got: Int, expected: Int, msg: String) raises:
    if got != expected:
        raise msg + ": got " + String(got) + " expected " + String(expected)


def _assert_eq_u64(got: UInt64, expected: UInt64, msg: String) raises:
    if got != expected:
        raise msg + ": got " + String(Int(got)) + " expected " + String(Int(expected))


def _assert_true(cond: Bool, msg: String) raises:
    if not cond:
        raise msg


def _assert_false(cond: Bool, msg: String) raises:
    if cond:
        raise msg


def _make_sent_packet(pn: UInt64, ack_eliciting: Bool) -> SentPacket:
    return SentPacket(
        pn=pn,
        time_sent=UInt64(1000) + pn * 100,
        ack_eliciting=ack_eliciting,
        in_flight=True,
        size=1200,
        frames=List[Frame](),
    )


# ── Tests ────────────────────────────────────────────────────────────


def test_pn_allocation() raises:
    """Alloc 3 PNs, verify 0, 1, 2."""
    var space = PacketNumberSpace(EncryptionLevel.initial())
    _assert_eq_u64(space.alloc_pn(), UInt64(0), "first PN")
    _assert_eq_u64(space.alloc_pn(), UInt64(1), "second PN")
    _assert_eq_u64(space.alloc_pn(), UInt64(2), "third PN")
    print("    PASS test_pn_allocation")


def test_packet_type_to_space() raises:
    """INITIAL->0, HANDSHAKE->1, ZERO_RTT->2, ONE_RTT->2, RETRY->-1."""
    _assert_eq(packet_type_to_space(PacketType.initial()), 0, "INITIAL")
    _assert_eq(packet_type_to_space(PacketType.handshake()), 1, "HANDSHAKE")
    _assert_eq(packet_type_to_space(PacketType.zero_rtt()), 2, "ZERO_RTT")
    _assert_eq(packet_type_to_space(PacketType.one_rtt()), 2, "ONE_RTT")
    _assert_eq(packet_type_to_space(PacketType.retry()), -1, "RETRY")
    _assert_eq(packet_type_to_space(PacketType.version_negotiation()), -1, "VN")
    print("    PASS test_packet_type_to_space")


def test_ack_range_insert() raises:
    """Receive PNs 0, 1, 3, 5, 6; verify 3 ranges: [5,6], [3,3], [0,1]."""
    var space = PacketNumberSpace(EncryptionLevel.initial())
    space.on_packet_received(UInt64(0), False)
    space.on_packet_received(UInt64(1), False)
    space.on_packet_received(UInt64(3), False)
    space.on_packet_received(UInt64(5), False)
    space.on_packet_received(UInt64(6), False)

    _assert_eq(len(space.ack_ranges), 3, "range count")
    # Ranges sorted by .end descending.
    _assert_eq_u64(space.ack_ranges[0].start, UInt64(5), "r0.start")
    _assert_eq_u64(space.ack_ranges[0].end, UInt64(6), "r0.end")
    _assert_eq_u64(space.ack_ranges[1].start, UInt64(3), "r1.start")
    _assert_eq_u64(space.ack_ranges[1].end, UInt64(3), "r1.end")
    _assert_eq_u64(space.ack_ranges[2].start, UInt64(0), "r2.start")
    _assert_eq_u64(space.ack_ranges[2].end, UInt64(1), "r2.end")
    print("    PASS test_ack_range_insert")


def test_ack_immediate_handshake() raises:
    """Initial level, receive 1 ack-eliciting; ack_needed=True immediately."""
    var space = PacketNumberSpace(EncryptionLevel.initial())
    space.on_packet_received(UInt64(0), True)
    _assert_true(space.ack_needed, "ack_needed after 1 ack-eliciting in Initial")

    # Same for Handshake level.
    var hs = PacketNumberSpace(EncryptionLevel.handshake())
    hs.on_packet_received(UInt64(0), True)
    _assert_true(hs.ack_needed, "ack_needed after 1 ack-eliciting in Handshake")
    print("    PASS test_ack_immediate_handshake")


def test_ack_delayed_application() raises:
    """Application level, 1 ack-eliciting -> not needed. 2nd -> needed."""
    var space = PacketNumberSpace(EncryptionLevel.application())
    space.on_packet_received(UInt64(0), True)
    _assert_false(space.ack_needed, "ack_needed should be False after 1 ack-eliciting in App")

    space.on_packet_received(UInt64(1), True)
    _assert_true(space.ack_needed, "ack_needed should be True after 2 ack-eliciting in App")
    print("    PASS test_ack_delayed_application")


def test_build_ack_frame() raises:
    """Receive PNs 0,1,3,5,6 (last at t=1000); peek at t=1800 with exponent 3
    yields largest=6, delay=100, first_range=1, ranges gap=1/ack=0 then
    gap=1/ack=1. Peeking is non-mutating; mark_ack_sent resets the state."""
    var space = PacketNumberSpace(EncryptionLevel.initial())
    space.on_packet_received(UInt64(0), True, UInt64(100))
    space.on_packet_received(UInt64(1), True, UInt64(200))
    space.on_packet_received(UInt64(3), True, UInt64(300))
    space.on_packet_received(UInt64(5), True, UInt64(400))
    space.on_packet_received(UInt64(6), True, UInt64(1000))

    var maybe_ack = space.peek_ack_frame(UInt64(1800), UInt64(3))
    _assert_true(maybe_ack.__bool__(), "ACK frame should be present")
    var ack = maybe_ack.value().copy()

    _assert_eq_u64(ack.largest_ack, UInt64(6), "largest_ack")
    _assert_eq_u64(ack.ack_delay, UInt64(100), "ack_delay = (1800-1000) >> 3")
    _assert_eq_u64(ack.first_ack_range, UInt64(1), "first_ack_range")  # [5,6] -> 6-5=1

    _assert_eq(len(ack.ranges), 2, "additional ranges count")
    # Range 1: gap between [5,6] and [3,3] -> gap = (5-1)-3 = 1, ack_range = 3-3 = 0
    _assert_eq_u64(ack.ranges[0].gap, UInt64(1), "range[0].gap")
    _assert_eq_u64(ack.ranges[0].ack_range, UInt64(0), "range[0].ack_range")
    # Range 2: gap between [3,3] and [0,1] -> gap = (3-1)-1 = 1, ack_range = 1-0 = 1
    _assert_eq_u64(ack.ranges[1].gap, UInt64(1), "range[1].gap")
    _assert_eq_u64(ack.ranges[1].ack_range, UInt64(1), "range[1].ack_range")

    # Peeking must not touch scheduling state.
    _assert_true(space.ack_needed, "ack_needed intact after peek")
    _assert_eq(space.ack_eliciting_since_last_ack, 5, "count intact after peek")

    space.mark_ack_sent()
    _assert_false(space.ack_needed, "ack_needed reset")
    _assert_eq(space.ack_eliciting_since_last_ack, 0, "ack_eliciting_since_last_ack reset")
    _assert_false(Bool(space.ack_deadline), "ack_deadline cleared")
    _assert_false(Bool(space.peek_ack_frame(UInt64(1800), UInt64(3))), "nothing to peek after commit")
    print("    PASS test_build_ack_frame")


def test_ack_deadline_armed_once() raises:
    """First non-immediate application packet arms now + max_ack_delay; later
    packets do not move it; the threshold clears it."""
    var space = PacketNumberSpace(EncryptionLevel.application())
    space.on_packet_received(UInt64(0), True, UInt64(5_000), UInt64(25_000))
    _assert_false(space.ack_needed, "one packet does not need an ACK yet")
    _assert_true(Bool(space.ack_deadline), "deadline armed by first packet")
    _assert_eq_u64(space.ack_deadline.value(), UInt64(30_000), "deadline = now + max_ack_delay")
    # A non-ack-eliciting packet neither arms nor moves the deadline.
    space.on_packet_received(UInt64(1), False, UInt64(9_000), UInt64(25_000))
    _assert_eq_u64(space.ack_deadline.value(), UInt64(30_000), "deadline unchanged")
    # Second ack-eliciting packet: threshold reached, deadline cleared.
    space.on_packet_received(UInt64(2), True, UInt64(9_500), UInt64(25_000))
    _assert_true(space.ack_needed, "threshold sets ack_needed")
    _assert_false(Bool(space.ack_deadline), "threshold clears the deadline")

    # max_ack_delay_us == 0 arms Some(now).
    var zero = PacketNumberSpace(EncryptionLevel.application())
    zero.on_packet_received(UInt64(0), True, UInt64(77), UInt64(0))
    _assert_eq_u64(zero.ack_deadline.value(), UInt64(77), "zero delay arms now")
    print("    PASS test_ack_deadline_armed_once")


def test_ack_out_of_order_immediate() raises:
    """A PN below the largest ack-eliciting one, or more than one above it,
    sets ack_needed at once; the -1 sentinel makes PN >= 1 immediate."""
    var gap = PacketNumberSpace(EncryptionLevel.application())
    gap.on_packet_received(UInt64(0), True, UInt64(0))
    _assert_false(gap.ack_needed, "PN 0 first: not immediate")
    gap.on_packet_received(UInt64(1), False, UInt64(0))
    gap.mark_ack_sent()
    gap.on_packet_received(UInt64(3), True, UInt64(0))
    _assert_true(gap.ack_needed, "PN 3 after largest AE 0: gap -> immediate")
    _assert_eq(gap.largest_rx_ack_eliciting_pn, 3, "largest AE tracked")

    var reorder = PacketNumberSpace(EncryptionLevel.application())
    reorder.on_packet_received(UInt64(5), True, UInt64(0))
    _assert_true(reorder.ack_needed, "first AE with PN >= 1 is immediate")
    reorder.mark_ack_sent()
    reorder.on_packet_received(UInt64(4), True, UInt64(0))
    _assert_true(reorder.ack_needed, "PN below largest AE: immediate")
    _assert_eq(reorder.largest_rx_ack_eliciting_pn, 5, "largest AE never lowered")

    var contiguous = PacketNumberSpace(EncryptionLevel.application())
    contiguous.on_packet_received(UInt64(0), True, UInt64(0))
    contiguous.mark_ack_sent()
    contiguous.on_packet_received(UInt64(1), True, UInt64(0))
    _assert_false(contiguous.ack_needed, "next PN in order: delayed")
    print("    PASS test_ack_out_of_order_immediate")


def test_peek_ack_bundle() raises:
    """`bundle=True` yields a frame while an ack-eliciting packet is unacked even
    though ack_needed is false; nothing when nothing is owed."""
    var space = PacketNumberSpace(EncryptionLevel.application())
    _assert_false(Bool(space.peek_ack_frame(UInt64(0), UInt64(3), bundle=True)), "empty space: no frame")
    space.on_packet_received(UInt64(0), True, UInt64(0))
    _assert_true(space.has_unacked_ack_eliciting(), "one AE unacked")
    _assert_false(Bool(space.peek_ack_frame(UInt64(0), UInt64(3))), "not needed without bundle")
    _assert_true(Bool(space.peek_ack_frame(UInt64(0), UInt64(3), bundle=True)), "bundled")
    space.mark_ack_sent()
    _assert_false(space.has_unacked_ack_eliciting(), "count reset")
    space.on_packet_received(UInt64(1), False, UInt64(0))
    _assert_false(Bool(space.peek_ack_frame(UInt64(0), UInt64(3), bundle=True)), "non-AE only: no bundle")
    print("    PASS test_peek_ack_bundle")


def test_ack_delay_field() raises:
    """`ack_delay` is (now - largest_rx_pkt_time) >> exponent, 0 when unknown or
    when the clock went backwards; largest_rx_pkt_time follows largest_recv_pn."""
    var space = PacketNumberSpace(EncryptionLevel.application())
    _assert_eq_u64(space.ack_delay_field(UInt64(500), UInt64(3)), UInt64(0), "no packet yet")
    space.on_packet_received(UInt64(2), False, UInt64(1_000))
    _assert_eq_u64(space.largest_rx_pkt_time.value(), UInt64(1_000), "time of largest")
    space.on_packet_received(UInt64(1), False, UInt64(2_000))
    _assert_eq_u64(space.largest_rx_pkt_time.value(), UInt64(1_000), "older PN does not move it")
    _assert_eq_u64(space.ack_delay_field(UInt64(1_800), UInt64(3)), UInt64(100), "(1800-1000)>>3")
    _assert_eq_u64(space.ack_delay_field(UInt64(900), UInt64(3)), UInt64(0), "clock backwards -> 0")
    print("    PASS test_ack_delay_field")


def test_pn_space_discard_resets_scheduling() raises:
    """`discard()` clears ack_needed, ack_deadline, probe_pending,
    time_of_last_ae_sent and the ack-eliciting count."""
    var space = PacketNumberSpace(EncryptionLevel.handshake())
    space.on_packet_received(UInt64(0), True, UInt64(10))
    space.ack_deadline = Optional[UInt64](UInt64(99))
    space.probe_pending = True
    space.on_packet_sent(_make_sent_packet(space.alloc_pn(), True))
    _assert_true(Bool(space.time_of_last_ae_sent), "AE send time set on commit")
    _ = space.discard()
    _assert_false(space.ack_needed, "ack_needed reset")
    _assert_false(Bool(space.ack_deadline), "ack_deadline reset")
    _assert_false(space.probe_pending, "probe_pending reset")
    _assert_false(Bool(space.time_of_last_ae_sent), "time_of_last_ae_sent reset")
    _assert_eq(space.ack_eliciting_since_last_ack, 0, "count reset")
    print("    PASS test_pn_space_discard_resets_scheduling")


def test_time_of_last_ae_sent_tracking() raises:
    """Commit-time semantics: set by an ack-eliciting send, untouched by an
    ACK-only send, cleared (with probe_pending) once no AE packet remains."""
    var space = PacketNumberSpace(EncryptionLevel.application())
    space.on_packet_sent(_make_sent_packet(space.alloc_pn(), False))
    _assert_false(Bool(space.time_of_last_ae_sent), "ACK-only send does not arm")
    space.on_packet_sent(_make_sent_packet(space.alloc_pn(), True))   # pn 1, t=1100
    space.on_packet_sent(_make_sent_packet(space.alloc_pn(), True))   # pn 2, t=1200
    _assert_eq_u64(space.time_of_last_ae_sent.value(), UInt64(1200), "latest commit time")
    space.probe_pending = True
    # ACK pn 2 only: pn 1 still in flight, no rollback to its send time.
    var ack = AckFrame()
    ack.largest_ack = UInt64(2)
    ack.first_ack_range = UInt64(0)
    _ = space.on_ack_received(ack)
    _assert_eq_u64(space.time_of_last_ae_sent.value(), UInt64(1200), "no rollback")
    _assert_true(space.probe_pending, "probe still pending with AE in flight")
    # ACK pn 1: nothing ack-eliciting remains (pn 0 is ACK-only).
    var ack2 = AckFrame()
    ack2.largest_ack = UInt64(1)
    ack2.first_ack_range = UInt64(0)
    _ = space.on_ack_received(ack2)
    _assert_false(Bool(space.time_of_last_ae_sent), "cleared once nothing AE in flight")
    _assert_false(space.probe_pending, "probe cleared with it")
    print("    PASS test_time_of_last_ae_sent_tracking")


def test_ack_validation_reject_future() raises:
    """Send 3 packets (PNs 0,1,2), receive ACK with largest=5; verify raises."""
    var space = PacketNumberSpace(EncryptionLevel.initial())

    # Send 3 packets.
    space.on_packet_sent(_make_sent_packet(space.alloc_pn(), True))
    space.on_packet_sent(_make_sent_packet(space.alloc_pn(), True))
    space.on_packet_sent(_make_sent_packet(space.alloc_pn(), True))

    # Forge an ACK claiming PN 5 was received.
    var bad_ack = AckFrame()
    bad_ack.largest_ack = UInt64(5)
    bad_ack.first_ack_range = UInt64(0)  # Just PN 5

    var raised = False
    try:
        _ = space.on_ack_received(bad_ack)
    except:
        raised = True

    _assert_true(raised, "should raise for ACK of unsent PN")
    print("    PASS test_ack_validation_reject_future")


def test_space_discard() raises:
    """Send 3 packets, discard; verify empty sent_packets, returned list size=3."""
    var space = PacketNumberSpace(EncryptionLevel.initial())

    space.on_packet_sent(_make_sent_packet(space.alloc_pn(), True))
    space.on_packet_sent(_make_sent_packet(space.alloc_pn(), True))
    space.on_packet_sent(_make_sent_packet(space.alloc_pn(), True))

    _assert_eq(len(space.sent_packets), 3, "sent_packets before discard")

    var discarded = space.discard()
    _assert_eq(len(discarded), 3, "discarded count")
    _assert_eq(len(space.sent_packets), 0, "sent_packets after discard")
    _assert_eq(Int(space.keys_handle), -1, "keys_handle after discard")
    print("    PASS test_space_discard")


def test_on_ack_received() raises:
    """Send PNs 0-4, ACK [2,4]; verify returned 3 packets, 2 remain."""
    var space = PacketNumberSpace(EncryptionLevel.initial())

    for _ in range(5):
        space.on_packet_sent(_make_sent_packet(space.alloc_pn(), True))

    # ACK for PNs 2,3,4 -> largest=4, first_ack_range=2 (4-2=2).
    var ack = AckFrame()
    ack.largest_ack = UInt64(4)
    ack.first_ack_range = UInt64(2)

    var acked = space.on_ack_received(ack)
    _assert_eq(len(acked), 3, "acked count")
    _assert_eq(len(space.sent_packets), 2, "remaining sent_packets")
    _assert_eq(space.largest_acked_pn, 4, "largest_acked_pn")
    print("    PASS test_on_ack_received")


def test_duplicate_pn_ignored() raises:
    """Receiving the same PN twice should not create duplicate ranges."""
    var space = PacketNumberSpace(EncryptionLevel.initial())
    space.on_packet_received(UInt64(5), False)
    space.on_packet_received(UInt64(5), False)  # Duplicate
    _assert_eq(len(space.ack_ranges), 1, "range count after duplicate")
    _assert_eq_u64(space.ack_ranges[0].start, UInt64(5), "start")
    _assert_eq_u64(space.ack_ranges[0].end, UInt64(5), "end")
    print("    PASS test_duplicate_pn_ignored")


def test_ack_range_merge() raises:
    """Receiving PNs that fill a gap should merge ranges."""
    var space = PacketNumberSpace(EncryptionLevel.initial())
    space.on_packet_received(UInt64(0), False)
    space.on_packet_received(UInt64(2), False)
    _assert_eq(len(space.ack_ranges), 2, "ranges before merge")

    # Fill the gap.
    space.on_packet_received(UInt64(1), False)
    _assert_eq(len(space.ack_ranges), 1, "ranges after merge")
    _assert_eq_u64(space.ack_ranges[0].start, UInt64(0), "merged start")
    _assert_eq_u64(space.ack_ranges[0].end, UInt64(2), "merged end")
    print("    PASS test_ack_range_merge")


def test_pn_space_last_ae_acked_initially_zero() raises:
    """last_ae_acked_time_sent starts at 0."""
    var sp = PacketNumberSpace(EncryptionLevel.application())
    _assert_eq_u64(sp.last_ae_acked_time_sent, UInt64(0), "initial 0")
    print("    PASS test_pn_space_last_ae_acked_initially_zero")


def test_pn_space_any_ae_acked_in_range_boundaries() raises:
    """any_ae_acked_in_range: unset→False, in-range→True, before→False, past→True."""
    var sp = PacketNumberSpace(EncryptionLevel.application())
    # zero → no evidence
    _assert_false(sp.any_ae_acked_in_range(UInt64(100), UInt64(200)),
                  "unset → False")
    sp.last_ae_acked_time_sent = UInt64(150)
    # in range
    _assert_true(sp.any_ae_acked_in_range(UInt64(100), UInt64(200)),
                 "in-range tracker → True")
    sp.last_ae_acked_time_sent = UInt64(50)
    # before range
    _assert_false(sp.any_ae_acked_in_range(UInt64(100), UInt64(200)),
                  "before range → False")
    sp.last_ae_acked_time_sent = UInt64(300)
    # past range — conservative True
    _assert_true(sp.any_ae_acked_in_range(UInt64(100), UInt64(200)),
                 "past range → conservative True")
    print("    PASS test_pn_space_any_ae_acked_in_range_boundaries")


def test_pn_space_last_ae_acked_monotonic() raises:
    """last_ae_acked_time_sent is not lowered by a smaller value."""
    var sp = PacketNumberSpace(EncryptionLevel.application())
    sp.last_ae_acked_time_sent = UInt64(100)
    var t1 = UInt64(50)
    if t1 > sp.last_ae_acked_time_sent:
        sp.last_ae_acked_time_sent = t1
    _assert_eq_u64(sp.last_ae_acked_time_sent, UInt64(100), "monotonic (not lowered)")
    var t2 = UInt64(200)
    if t2 > sp.last_ae_acked_time_sent:
        sp.last_ae_acked_time_sent = t2
    _assert_eq_u64(sp.last_ae_acked_time_sent, UInt64(200), "advanced to later time")
    print("    PASS test_pn_space_last_ae_acked_monotonic")


def test_pn_skip_gap_inserted() raises:
    """PN skip fires when next_pn reaches pn_skip_next, creating a gap."""
    var space = PacketNumberSpace(EncryptionLevel.application())
    # Set nonzero RNG seed and trigger point at PN 3
    space.pn_skip_rng = UInt64(0x123456789ABCDEF0)
    space.pn_skip_next = UInt64(3)

    # PNs 0, 1, 2 allocated normally (before trigger)
    _assert_true(space.alloc_pn() == 0, "pn skip gap: pn 0")
    _assert_true(space.alloc_pn() == 1, "pn skip gap: pn 1")
    _assert_true(space.alloc_pn() == 2, "pn skip gap: pn 2")

    # At next_pn=3, trigger fires: gap inserted, first allocated PN > 3
    var pn3 = space.alloc_pn()
    _assert_true(pn3 >= 4, "pn skip gap: first post-skip pn >= 4 (gap of 1-8 inserted)")

    # pn_skip_next rescheduled to at least current next_pn + 199
    _assert_true(space.pn_skip_next >= space.next_pn + 199,
                 "pn skip gap: pn_skip_next rescheduled >= next_pn + 200")

    print("    PASS test_pn_skip_gap_inserted")


def test_pn_skip_disabled_when_rng_zero() raises:
    """Default pn_skip_rng=0 → alloc_pn produces contiguous sequence."""
    var space = PacketNumberSpace(EncryptionLevel.application())
    # Default: pn_skip_rng=0 (disabled), pn_skip_next=UInt64.MAX
    for i in range(600):
        var pn = space.alloc_pn()
        _assert_true(pn == UInt64(i),
                     "pn skip disabled: pn must equal index")
    print("    PASS test_pn_skip_disabled_when_rng_zero")


def test_pn_skip_initial_handshake_spaces_unaffected() raises:
    """Initial and Handshake spaces always produce contiguous PNs (rng stays 0)."""
    var init_space = PacketNumberSpace(EncryptionLevel.initial())
    var hs_space = PacketNumberSpace(EncryptionLevel.handshake())

    # init and handshake must have rng=0 always
    _assert_true(init_space.pn_skip_rng == 0, "initial space: pn_skip_rng starts at 0")
    _assert_true(hs_space.pn_skip_rng == 0, "handshake space: pn_skip_rng starts at 0")

    for i in range(100):
        _assert_true(init_space.alloc_pn() == UInt64(i), "initial space contiguous pn")
        _assert_true(hs_space.alloc_pn() == UInt64(i), "handshake space contiguous pn")
    print("    PASS test_pn_skip_initial_handshake_spaces_unaffected")


# ── Main ─────────────────────────────────────────────────────────────


def main() raises:
    print("test_quic_pn_space:")

    test_pn_allocation()
    test_packet_type_to_space()
    test_ack_range_insert()
    test_ack_immediate_handshake()
    test_ack_delayed_application()
    test_build_ack_frame()
    test_ack_deadline_armed_once()
    test_ack_out_of_order_immediate()
    test_peek_ack_bundle()
    test_ack_delay_field()
    test_pn_space_discard_resets_scheduling()
    test_time_of_last_ae_sent_tracking()
    test_ack_validation_reject_future()
    test_space_discard()
    test_on_ack_received()
    test_duplicate_pn_ignored()
    test_ack_range_merge()
    test_pn_space_last_ae_acked_initially_zero()
    test_pn_space_any_ae_acked_in_range_boundaries()
    test_pn_space_last_ae_acked_monotonic()
    test_pn_skip_gap_inserted()
    test_pn_skip_disabled_when_rng_zero()
    test_pn_skip_initial_handshake_spaces_unaffected()

    print("All test_quic_pn_space tests passed.")
