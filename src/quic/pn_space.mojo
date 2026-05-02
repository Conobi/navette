# src/quic/pn_space.mojo
# QUIC Packet Number Space — per-space PN counters, ACK tracking, SentPacket records.
# RFC 9000 Section 17.2.2 (PN spaces), Appendix B (ACK generation).

from src.quic.ecn import EcnCounts, ECN_NOT_ECT, ECN_ECT0
from src.quic.frame import AckFrame, AckRange, Frame
from src.quic.packet import PacketType

# ── Constants ────────────────────────────────────────────────────────

comptime MAX_ACK_RANGE_ENTRIES: Int = 32


# ── EncryptionLevel ──────────────────────────────────────────────────


struct EncryptionLevel(ImplicitlyCopyable, Equatable):
    var _value: UInt8

    comptime INITIAL: UInt8 = 0
    comptime HANDSHAKE: UInt8 = 1
    comptime APPLICATION: UInt8 = 2

    def __init__(out self, value: UInt8):
        self._value = value

    def __init__(out self, *, other: Self):
        self._value = other._value

    def __init__(out self, *, deinit take: Self):
        self._value = take._value

    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    def __ne__(self, other: Self) -> Bool:
        return self._value != other._value

    @staticmethod
    def initial() -> EncryptionLevel:
        return EncryptionLevel(EncryptionLevel.INITIAL)

    @staticmethod
    def handshake() -> EncryptionLevel:
        return EncryptionLevel(EncryptionLevel.HANDSHAKE)

    @staticmethod
    def application() -> EncryptionLevel:
        return EncryptionLevel(EncryptionLevel.APPLICATION)


# ── packet_type_to_space ─────────────────────────────────────────────


def packet_type_to_space(pt: PacketType) -> Int:
    """Map a PacketType to its PN space index (0=Initial, 1=Handshake, 2=Application).
    Returns -1 for packet types that have no PN space (VN, Retry)."""
    if pt == PacketType.initial():
        return 0
    if pt == PacketType.handshake():
        return 1
    if pt == PacketType.zero_rtt():
        return 2
    if pt == PacketType.one_rtt():
        return 2
    return -1  # VN, Retry — no PN space


# ── AckRangeEntry ────────────────────────────────────────────────────


struct AckRangeEntry(ImplicitlyCopyable):
    """A contiguous range of received packet numbers [start, end] inclusive."""
    var start: UInt64  # Lowest PN (inclusive)
    var end: UInt64    # Highest PN (inclusive)

    def __init__(out self, start: UInt64, end: UInt64):
        self.start = start
        self.end = end

    def __init__(out self, *, other: Self):
        self.start = other.start
        self.end = other.end

    def __init__(out self, *, deinit take: Self):
        self.start = take.start
        self.end = take.end


# ── SentPacket ───────────────────────────────────────────────────────


struct SentPacket(Copyable, Movable):
    """Record of a sent packet, kept until ACKed or declared lost."""
    var pn: UInt64
    var time_sent: UInt64       # Microseconds monotonic
    var ack_eliciting: Bool
    var in_flight: Bool         # True if counts toward bytes_in_flight
    var size: Int               # Bytes in UDP datagram
    var frames: List[Frame]     # For CRYPTO retransmission
    var ecn_mark: UInt8          # IP ECN codepoint used when this packet was sent (0 = NOT_ECT)

    def __init__(
        out self,
        pn: UInt64,
        time_sent: UInt64,
        ack_eliciting: Bool,
        in_flight: Bool,
        size: Int,
        frames: List[Frame],
        ecn_mark: UInt8 = UInt8(0),
    ):
        self.pn = pn
        self.time_sent = time_sent
        self.ack_eliciting = ack_eliciting
        self.in_flight = in_flight
        self.size = size
        self.frames = List[Frame](copy=frames)
        self.ecn_mark = ecn_mark

    def __init__(out self, *, other: Self):
        self.pn = other.pn
        self.time_sent = other.time_sent
        self.ack_eliciting = other.ack_eliciting
        self.in_flight = other.in_flight
        self.size = other.size
        self.frames = List[Frame](copy=other.frames)
        self.ecn_mark = other.ecn_mark

    def __init__(out self, *, deinit take: Self):
        self.pn = take.pn
        self.time_sent = take.time_sent
        self.ack_eliciting = take.ack_eliciting
        self.in_flight = take.in_flight
        self.size = take.size
        self.frames = take.frames^
        self.ecn_mark = take.ecn_mark


# ── PacketNumberSpace ────────────────────────────────────────────────


struct PacketNumberSpace(Copyable, Movable):
    """Per-encryption-level PN space with send/receive tracking."""
    var level: EncryptionLevel
    var next_pn: UInt64                    # Starts at 0
    var largest_recv_pn: Int               # -1 = none received
    var largest_acked_pn: Int              # -1 = no ACK from peer
    var ack_ranges: List[AckRangeEntry]    # Recv ranges, max 32
    var ack_eliciting_since_last_ack: Int
    var ack_needed: Bool
    var sent_packets: Dict[Int, SentPacket]
    var keys_handle: Int32                 # -1 = no keys
    var last_ae_acked_time_sent: UInt64    # time_sent of latest ACKed ack-eliciting pkt; 0 = none
    var recv_ecn: EcnCounts       # ECN marks observed on packets received in this space
    var last_ack_ecn: EcnCounts   # ECN counts from the last ACK frame we sent (for CE delta tracking)
    var ect0_in_flight: UInt64    # O(1) count of in-flight ECT(0)-marked packets
    var pn_skip_rng: UInt64    # Xorshift64 state; 0 = disabled (Initial + Handshake)
    var pn_skip_next: UInt64   # PN at which the next gap is inserted

    def __init__(out self, level: EncryptionLevel):
        self.level = level
        self.next_pn = UInt64(0)
        self.largest_recv_pn = -1
        self.largest_acked_pn = -1
        self.ack_ranges = List[AckRangeEntry]()
        self.ack_eliciting_since_last_ack = 0
        self.ack_needed = False
        self.sent_packets = Dict[Int, SentPacket]()
        self.keys_handle = Int32(-1)
        self.last_ae_acked_time_sent = UInt64(0)
        self.recv_ecn = EcnCounts()
        self.last_ack_ecn = EcnCounts()
        self.ect0_in_flight = UInt64(0)
        self.pn_skip_rng  = UInt64(0)
        self.pn_skip_next = UInt64(0xFFFFFFFFFFFFFFFF)

    def __init__(out self, *, other: Self):
        self.level = EncryptionLevel(other=other.level)
        self.next_pn = other.next_pn
        self.largest_recv_pn = other.largest_recv_pn
        self.largest_acked_pn = other.largest_acked_pn
        self.ack_ranges = List[AckRangeEntry](copy=other.ack_ranges)
        self.ack_eliciting_since_last_ack = other.ack_eliciting_since_last_ack
        self.ack_needed = other.ack_needed
        self.sent_packets = other.sent_packets.copy()
        self.keys_handle = other.keys_handle
        self.last_ae_acked_time_sent = other.last_ae_acked_time_sent
        self.recv_ecn = EcnCounts(other=other.recv_ecn)
        self.last_ack_ecn = EcnCounts(other=other.last_ack_ecn)
        self.ect0_in_flight = other.ect0_in_flight
        self.pn_skip_rng  = other.pn_skip_rng
        self.pn_skip_next = other.pn_skip_next

    def __init__(out self, *, deinit take: Self):
        self.level = take.level
        self.next_pn = take.next_pn
        self.largest_recv_pn = take.largest_recv_pn
        self.largest_acked_pn = take.largest_acked_pn
        self.ack_ranges = take.ack_ranges^
        self.ack_eliciting_since_last_ack = take.ack_eliciting_since_last_ack
        self.ack_needed = take.ack_needed
        self.sent_packets = take.sent_packets^
        self.keys_handle = take.keys_handle
        self.last_ae_acked_time_sent = take.last_ae_acked_time_sent
        self.recv_ecn = take.recv_ecn^
        self.last_ack_ecn = take.last_ack_ecn^
        self.ect0_in_flight = take.ect0_in_flight
        self.pn_skip_rng  = take.pn_skip_rng
        self.pn_skip_next = take.pn_skip_next

    # ── PN allocation ────────────────────────────────────────────────

    def alloc_pn(mut self) -> UInt64:
        """Allocate and return the next packet number.

        When pn_skip_rng is non-zero (Application space after handshake),
        randomly skips 1-8 PNs every 200-499 allocations via Xorshift64.
        Skipped PNs are never in sent_packets — pre-crafted ACKs for them
        produce no RTT sample (CVE-2025-4820 defense).
        """
        if self.pn_skip_rng != 0 and self.next_pn >= self.pn_skip_next:
            # Xorshift64 step
            self.pn_skip_rng ^= self.pn_skip_rng << 13
            self.pn_skip_rng ^= self.pn_skip_rng >> 7
            self.pn_skip_rng ^= self.pn_skip_rng << 17
            var gap = (self.pn_skip_rng & 7) + 1                    # 1-8 skipped PNs
            self.next_pn += gap
            # Schedule next gap: 200-499 packets from now
            self.pn_skip_next = self.next_pn + 200 + (self.pn_skip_rng % 300)
        var pn = self.next_pn
        self.next_pn += 1
        return pn

    # ── Receive tracking ─────────────────────────────────────────────

    def on_packet_received(mut self, pn: UInt64, ack_eliciting: Bool):
        """Record receipt of a packet. Updates largest_recv_pn, inserts PN into
        ack_ranges, and determines whether an ACK is needed."""
        # Update largest received.
        var pn_int = Int(pn)
        if pn_int > self.largest_recv_pn:
            self.largest_recv_pn = pn_int

        # Insert PN into ack_ranges.
        self._insert_ack_range(pn)

        # ACK generation policy.
        if ack_eliciting:
            self.ack_eliciting_since_last_ack += 1
            if self.level == EncryptionLevel.initial() or self.level == EncryptionLevel.handshake():
                # Initial/Handshake: ACK immediately for every ack-eliciting packet.
                self.ack_needed = True
            else:
                # Application: ACK after 2 ack-eliciting packets.
                if self.ack_eliciting_since_last_ack >= 2:
                    self.ack_needed = True

    def _insert_ack_range(mut self, pn: UInt64):
        """Insert a PN into ack_ranges, maintaining sorted-descending order by .end.
        Merges adjacent ranges and caps at MAX_ACK_RANGE_ENTRIES."""
        # Check if PN extends an existing range.
        var merged_idx = -1
        for i in range(len(self.ack_ranges)):
            # PN extends the high end.
            if pn == self.ack_ranges[i].end + 1:
                self.ack_ranges[i] = AckRangeEntry(self.ack_ranges[i].start, pn)
                merged_idx = i
                break
            # PN extends the low end.
            if self.ack_ranges[i].start >= 1 and pn == self.ack_ranges[i].start - 1:
                self.ack_ranges[i] = AckRangeEntry(pn, self.ack_ranges[i].end)
                merged_idx = i
                break
            # PN already in range.
            if pn >= self.ack_ranges[i].start and pn <= self.ack_ranges[i].end:
                return  # Duplicate, ignore.

        if merged_idx >= 0:
            # Check if we can merge with the adjacent range.
            self._try_merge_adjacent(merged_idx)
            # Re-sort after merge (the end value may have changed).
            self._sort_ack_ranges()
            return

        # No existing range to extend — insert new single-PN range.
        self.ack_ranges.append(AckRangeEntry(pn, pn))
        self._sort_ack_ranges()

        # Cap at MAX_ACK_RANGE_ENTRIES.
        while len(self.ack_ranges) > MAX_ACK_RANGE_ENTRIES:
            _ = self.ack_ranges.pop()

    def _try_merge_adjacent(mut self, idx: Int):
        """After extending range at idx, check if it now touches a neighbor and merge.
        Ranges are sorted by .end descending. Two ranges are adjacent when the
        lower range's end + 1 >= upper range's start."""
        # Check merge with the range below (lower .end, at idx+1).
        if idx < len(self.ack_ranges) - 1:
            var nxt = idx + 1
            # nxt has lower .end; adjacent if nxt.end + 1 >= idx.start
            if self.ack_ranges[nxt].end + 1 >= self.ack_ranges[idx].start:
                var new_start = self.ack_ranges[nxt].start if self.ack_ranges[nxt].start < self.ack_ranges[idx].start else self.ack_ranges[idx].start
                var new_end = self.ack_ranges[idx].end if self.ack_ranges[idx].end > self.ack_ranges[nxt].end else self.ack_ranges[nxt].end
                self.ack_ranges[idx] = AckRangeEntry(new_start, new_end)
                var new_ranges = List[AckRangeEntry]()
                for i in range(len(self.ack_ranges)):
                    if i != nxt:
                        new_ranges.append(AckRangeEntry(other=self.ack_ranges[i]))
                self.ack_ranges = new_ranges^

        # Check merge with the range above (higher .end, at idx-1).
        # Note: idx may have shifted after the previous merge, so re-check bounds.
        if idx > 0 and idx <= len(self.ack_ranges):
            var prev = idx - 1
            # idx has lower .end; adjacent if idx.end + 1 >= prev.start
            if prev < len(self.ack_ranges) and idx < len(self.ack_ranges):
                if self.ack_ranges[idx].end + 1 >= self.ack_ranges[prev].start:
                    var new_start = self.ack_ranges[idx].start if self.ack_ranges[idx].start < self.ack_ranges[prev].start else self.ack_ranges[prev].start
                    var new_end = self.ack_ranges[prev].end if self.ack_ranges[prev].end > self.ack_ranges[idx].end else self.ack_ranges[idx].end
                    self.ack_ranges[prev] = AckRangeEntry(new_start, new_end)
                    var new_ranges = List[AckRangeEntry]()
                    for i in range(len(self.ack_ranges)):
                        if i != idx:
                            new_ranges.append(AckRangeEntry(other=self.ack_ranges[i]))
                    self.ack_ranges = new_ranges^

    def _sort_ack_ranges(mut self):
        """Sort ack_ranges by .end descending (insertion sort, small list)."""
        for i in range(1, len(self.ack_ranges)):
            var key = AckRangeEntry(other=self.ack_ranges[i])
            var j = i - 1
            while j >= 0 and self.ack_ranges[j].end < key.end:
                self.ack_ranges[j + 1] = AckRangeEntry(other=self.ack_ranges[j])
                j -= 1
            self.ack_ranges[j + 1] = key

    # ── ACK frame building ───────────────────────────────────────────

    def build_ack_frame(mut self, ack_delay: UInt64) -> Optional[AckFrame]:
        """Build an AckFrame from current ack_ranges if an ACK is needed.
        Resets ack_needed and ack_eliciting_since_last_ack on success."""
        if not self.ack_needed or len(self.ack_ranges) == 0:
            return None

        var ack = AckFrame()
        ack.largest_ack = self.ack_ranges[0].end
        ack.ack_delay = ack_delay
        ack.first_ack_range = self.ack_ranges[0].end - self.ack_ranges[0].start

        var ranges = List[AckRange]()
        for i in range(1, len(self.ack_ranges)):
            var prev_start = self.ack_ranges[i - 1].start
            var curr_end = self.ack_ranges[i].end
            # gap = (prev_range.start - 1) - curr_range.end
            var gap = (prev_start - 1) - curr_end
            var ack_range = self.ack_ranges[i].end - self.ack_ranges[i].start
            ranges.append(AckRange(gap, ack_range))
        ack.ranges = ranges^

        # Include ECN counts when we've received ECN-marked packets (RFC 9000 §13.4.3).
        if not self.recv_ecn.is_zero():
            ack.has_ecn = True
            ack.ecn_ect0 = self.recv_ecn.ect0
            ack.ecn_ect1 = self.recv_ecn.ect1
            ack.ecn_ce = self.recv_ecn.ce

        # Reset ACK state.
        self.ack_needed = False
        self.ack_eliciting_since_last_ack = 0

        return ack^

    # ── Send tracking ────────────────────────────────────────────────

    def on_packet_sent(mut self, pkt: SentPacket):
        """Record a sent packet for ACK/loss tracking."""
        self.sent_packets[Int(pkt.pn)] = SentPacket(other=pkt)

    # ── ACK processing ───────────────────────────────────────────────

    def on_ack_received(mut self, ack: AckFrame) raises -> List[SentPacket]:
        """Process an incoming ACK frame: decode ranges into PN sets, find
        matching sent_packets, remove them, return newly acked list.
        Raises if any ACKed PN >= next_pn (security check)."""
        var acked = List[SentPacket]()
        var acked_pns = List[Int]()

        # Decode the ACK frame into PN ranges.
        # First range: [largest_ack - first_ack_range, largest_ack]
        var largest = ack.largest_ack
        var smallest = largest - ack.first_ack_range

        # Security: reject if largest ACKed PN >= next_pn.
        if Int(largest) >= Int(self.next_pn):
            raise "ACK for unsent packet: largest_ack=" + String(Int(largest)) + " >= next_pn=" + String(Int(self.next_pn))

        # Collect PNs from first range.
        var pn = smallest
        while pn <= largest:
            acked_pns.append(Int(pn))
            pn += 1

        # Process additional ranges.
        var prev_smallest = smallest
        for i in range(len(ack.ranges)):
            var gap = ack.ranges[i].gap
            var ack_range = ack.ranges[i].ack_range
            # gap+2 unacknowledged packets after prev_smallest
            if prev_smallest < gap + 2:
                raise "ACK range underflow"
            largest = prev_smallest - gap - 2
            if ack_range > largest:
                raise "ACK range exceeds available PNs"
            smallest = largest - ack_range
            pn = smallest
            while pn <= largest:
                acked_pns.append(Int(pn))
                pn += 1
            prev_smallest = smallest

        # Update largest_acked_pn.
        var ack_largest_int = Int(ack.largest_ack)
        if ack_largest_int > self.largest_acked_pn:
            self.largest_acked_pn = ack_largest_int

        # Remove acked packets from sent_packets and collect them via
        # Dict.pop (returns by-move). Was copy-then-pop, which cloned the
        # SentPacket (+ its frames Vec) only to free the original.
        for i in range(len(acked_pns)):
            var key = acked_pns[i]
            if key in self.sent_packets:
                acked.append(self.sent_packets.pop(key))

        return acked^

    # ── Space discard ────────────────────────────────────────────────

    def discard(mut self) raises -> List[SentPacket]:
        """Remove all sent_packets and return them for bytes_in_flight accounting.
        Sets keys_handle = -1."""
        var result = List[SentPacket]()
        var keys = List[Int]()
        for key in self.sent_packets.keys():
            keys.append(key)
        for i in range(len(keys)):
            result.append(SentPacket(other=self.sent_packets[keys[i]]))
            _ = self.sent_packets.pop(keys[i])
        self.keys_handle = Int32(-1)
        return result^

    # ── Persistent-congestion helper ─────────────────────────────────

    def any_ae_acked_in_range(self, earliest: UInt64, latest: UInt64) -> Bool:
        """Conservative query: True if we have evidence an ack-eliciting packet
        whose time_sent falls in [earliest, latest] was ACKed, OR if the tracker
        has advanced past latest (earlier range-ACKs may have been overwritten).
        Returns False if last_ae_acked_time_sent == 0 (no AE ACK ever received)
        or if it predates earliest.
        Used by persistent-congestion detection (Task 9 / M4a §5.4)."""
        if self.last_ae_acked_time_sent == UInt64(0):
            return False   # no AE ACK ever received in this space
        if self.last_ae_acked_time_sent >= earliest:
            return True    # in-range (definite) OR past latest (conservative)
        return False       # last AE ACK predates range — no evidence
