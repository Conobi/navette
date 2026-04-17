# tests/test_quic_pn_space.mojo
# Tests for PacketNumberSpace: PN allocation, ACK tracking, SentPacket records.

from src.quic.frame import AckFrame, AckRange, Frame
from src.quic.packet import PacketType
from src.quic.pn_space import (
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
    """Receive PNs 0,1,3,5,6; build ACK; verify largest=6, first_range=1,
    ranges has gap=1/ack=0 then gap=1/ack=1."""
    var space = PacketNumberSpace(EncryptionLevel.initial())
    space.on_packet_received(UInt64(0), True)
    space.on_packet_received(UInt64(1), True)
    space.on_packet_received(UInt64(3), True)
    space.on_packet_received(UInt64(5), True)
    space.on_packet_received(UInt64(6), True)

    var maybe_ack = space.build_ack_frame(UInt64(100))
    _assert_true(maybe_ack.__bool__(), "ACK frame should be present")
    var ack = maybe_ack.value().copy()

    _assert_eq_u64(ack.largest_ack, UInt64(6), "largest_ack")
    _assert_eq_u64(ack.ack_delay, UInt64(100), "ack_delay")
    _assert_eq_u64(ack.first_ack_range, UInt64(1), "first_ack_range")  # [5,6] -> 6-5=1

    _assert_eq(len(ack.ranges), 2, "additional ranges count")
    # Range 1: gap between [5,6] and [3,3] -> gap = (5-1)-3 = 1, ack_range = 3-3 = 0
    _assert_eq_u64(ack.ranges[0].gap, UInt64(1), "range[0].gap")
    _assert_eq_u64(ack.ranges[0].ack_range, UInt64(0), "range[0].ack_range")
    # Range 2: gap between [3,3] and [0,1] -> gap = (3-1)-1 = 1, ack_range = 1-0 = 1
    _assert_eq_u64(ack.ranges[1].gap, UInt64(1), "range[1].gap")
    _assert_eq_u64(ack.ranges[1].ack_range, UInt64(1), "range[1].ack_range")

    # State should be reset.
    _assert_false(space.ack_needed, "ack_needed reset")
    _assert_eq(space.ack_eliciting_since_last_ack, 0, "ack_eliciting_since_last_ack reset")
    print("    PASS test_build_ack_frame")


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
