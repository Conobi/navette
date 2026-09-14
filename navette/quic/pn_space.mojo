# src/quic/pn_space.mojo
# QUIC Packet Number Space — per-space PN counters, ACK tracking, SentPacket records.
# RFC 9000 Section 17.2.2 (PN spaces), Appendix B (ACK generation).

from navette.quic.ecn import EcnCounts, ECN_NOT_ECT, ECN_ECT0
from navette.quic.frame import AckFrame, AckRange, Frame
from navette.quic.packet import PacketType

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

    def __init__(out self, *, copy: Self):
        self._value = copy._value

    def __init__(out self, *, deinit move: Self):
        self._value = move._value

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

    def __init__(out self, *, copy: Self):
        self.start = copy.start
        self.end = copy.end

    def __init__(out self, *, deinit move: Self):
        self.start = move.start
        self.end = move.end


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
        var frames: List[Frame],
        ecn_mark: UInt8 = UInt8(0),
    ):
        self.pn = pn
        self.time_sent = time_sent
        self.ack_eliciting = ack_eliciting
        self.in_flight = in_flight
        self.size = size
        self.frames = frames^
        self.ecn_mark = ecn_mark

    def __init__(out self, *, copy: Self):
        self.pn = copy.pn
        self.time_sent = copy.time_sent
        self.ack_eliciting = copy.ack_eliciting
        self.in_flight = copy.in_flight
        self.size = copy.size
        self.frames = List[Frame](copy=copy.frames)
        self.ecn_mark = copy.ecn_mark

    def __init__(out self, *, deinit move: Self):
        self.pn = move.pn
        self.time_sent = move.time_sent
        self.ack_eliciting = move.ack_eliciting
        self.in_flight = move.in_flight
        self.size = move.size
        self.frames = move.frames^
        self.ecn_mark = move.ecn_mark


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
    # ACK scheduling (RFC 9000 §13.2). `Optional` sentinels rather than 0 so a
    # clock starting at 0 and max_ack_delay == 0 cannot collide with "unarmed".
    var largest_rx_pkt_time: Optional[UInt64]   # arrival time of largest_recv_pn
    var ack_deadline: Optional[UInt64]          # absolute µs by which an ACK MUST go out
    var largest_rx_ack_eliciting_pn: Int        # -1 = none
    # PTO state (RFC 9002 §6.2). `time_of_last_ae_sent` has commit-time
    # semantics: set when an ack-eliciting packet is committed here, never
    # rolled back to an older packet's time, None once no ack-eliciting
    # packet remains in sent_packets. `probe_pending` means the PTO fired and
    # the next packet in this space bypasses the congestion gate.
    var probe_pending: Bool
    var time_of_last_ae_sent: Optional[UInt64]
    # Count of ack-eliciting entries in sent_packets; every removal path
    # (`on_ack_received`, `forget_sent`, `discard`) keeps it in step.
    var ae_in_flight: Int
    # Pre-allocated scratch buffers reused across calls to avoid per-call heap allocs.
    var _scratch_pns: List[Int]
    var _scratch_ranges: List[AckRange]

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
        self.largest_rx_pkt_time = None
        self.ack_deadline = None
        self.largest_rx_ack_eliciting_pn = -1
        self.probe_pending = False
        self.time_of_last_ae_sent = None
        self.ae_in_flight = 0
        self._scratch_pns = List[Int](capacity=256)
        self._scratch_ranges = List[AckRange](capacity=64)

    def __init__(out self, *, copy: Self):
        self.level = EncryptionLevel(copy=copy.level)
        self.next_pn = copy.next_pn
        self.largest_recv_pn = copy.largest_recv_pn
        self.largest_acked_pn = copy.largest_acked_pn
        self.ack_ranges = List[AckRangeEntry](copy=copy.ack_ranges)
        self.ack_eliciting_since_last_ack = copy.ack_eliciting_since_last_ack
        self.ack_needed = copy.ack_needed
        self.sent_packets = copy.sent_packets.copy()
        self.keys_handle = copy.keys_handle
        self.last_ae_acked_time_sent = copy.last_ae_acked_time_sent
        self.recv_ecn = EcnCounts(copy=copy.recv_ecn)
        self.last_ack_ecn = EcnCounts(copy=copy.last_ack_ecn)
        self.ect0_in_flight = copy.ect0_in_flight
        self.pn_skip_rng  = copy.pn_skip_rng
        self.pn_skip_next = copy.pn_skip_next
        self.largest_rx_pkt_time = copy.largest_rx_pkt_time.copy()
        self.ack_deadline = copy.ack_deadline.copy()
        self.largest_rx_ack_eliciting_pn = copy.largest_rx_ack_eliciting_pn
        self.probe_pending = copy.probe_pending
        self.time_of_last_ae_sent = copy.time_of_last_ae_sent.copy()
        self.ae_in_flight = copy.ae_in_flight
        self._scratch_pns = List[Int](capacity=256)
        self._scratch_ranges = List[AckRange](capacity=64)

    def __init__(out self, *, deinit move: Self):
        self.level = move.level
        self.next_pn = move.next_pn
        self.largest_recv_pn = move.largest_recv_pn
        self.largest_acked_pn = move.largest_acked_pn
        self.ack_ranges = move.ack_ranges^
        self.ack_eliciting_since_last_ack = move.ack_eliciting_since_last_ack
        self.ack_needed = move.ack_needed
        self.sent_packets = move.sent_packets^
        self.keys_handle = move.keys_handle
        self.last_ae_acked_time_sent = move.last_ae_acked_time_sent
        self.recv_ecn = move.recv_ecn^
        self.last_ack_ecn = move.last_ack_ecn^
        self.ect0_in_flight = move.ect0_in_flight
        self.pn_skip_rng  = move.pn_skip_rng
        self.pn_skip_next = move.pn_skip_next
        self.largest_rx_pkt_time = move.largest_rx_pkt_time^
        self.ack_deadline = move.ack_deadline^
        self.largest_rx_ack_eliciting_pn = move.largest_rx_ack_eliciting_pn
        self.probe_pending = move.probe_pending
        self.time_of_last_ae_sent = move.time_of_last_ae_sent^
        self.ae_in_flight = move.ae_in_flight
        self._scratch_pns = move._scratch_pns^
        self._scratch_ranges = move._scratch_ranges^

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

    def on_packet_received(
        mut self,
        pn: UInt64,
        ack_eliciting: Bool,
        now: UInt64 = UInt64(0),
        max_ack_delay_us: UInt64 = UInt64(25_000),
    ):
        """Record receipt and decide when the ACK is owed (RFC 9000 §13.2.1).

        Initial/Handshake acknowledge every ack-eliciting packet at once. The
        Application space acknowledges immediately on the second ack-eliciting
        packet since the last ACK, or on an out-of-order one (PN below the
        largest ack-eliciting PN seen, or more than one above it); otherwise
        the first such packet arms `ack_deadline = now + max_ack_delay_us`,
        which later packets never move.
        """
        var pn_int = Int(pn)
        if pn_int > self.largest_recv_pn:
            self.largest_recv_pn = pn_int
            self.largest_rx_pkt_time = Optional[UInt64](now)

        self._insert_ack_range(pn)

        if not ack_eliciting:
            return
        self.ack_eliciting_since_last_ack += 1
        if self.level == EncryptionLevel.initial() or self.level == EncryptionLevel.handshake():
            self.ack_needed = True
            return

        var immediate = self.ack_eliciting_since_last_ack >= 2
        if pn_int < self.largest_rx_ack_eliciting_pn or pn_int > self.largest_rx_ack_eliciting_pn + 1:
            immediate = True
        if pn_int > self.largest_rx_ack_eliciting_pn:
            self.largest_rx_ack_eliciting_pn = pn_int
        if immediate:
            self.ack_needed = True
            self.ack_deadline = None
        elif not self.ack_deadline:
            self.ack_deadline = Optional[UInt64](now + max_ack_delay_us)

    def has_unacked_ack_eliciting(self) -> Bool:
        """True while an ack-eliciting packet received here awaits an ACK."""
        return self.ack_eliciting_since_last_ack > 0

    def ack_delay_field(self, now: UInt64, ack_delay_exponent: UInt64) -> UInt64:
        """ACK Delay field value: time since the largest PN arrived, scaled by
        the local exponent; 0 before any packet or if the clock went backwards."""
        if not self.largest_rx_pkt_time:
            return UInt64(0)
        var t = self.largest_rx_pkt_time.value()
        if now < t:
            return UInt64(0)
        return (now - t) >> ack_delay_exponent

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
                # In-place removal of nxt: shift subsequent elements left, pop tail.
                for j in range(nxt, len(self.ack_ranges) - 1):
                    self.ack_ranges[j] = AckRangeEntry(copy=self.ack_ranges[j + 1])
                _ = self.ack_ranges.pop()

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
                    # In-place removal of idx: shift subsequent elements left, pop tail.
                    for j in range(idx, len(self.ack_ranges) - 1):
                        self.ack_ranges[j] = AckRangeEntry(copy=self.ack_ranges[j + 1])
                    _ = self.ack_ranges.pop()

    def _sort_ack_ranges(mut self):
        """Sort ack_ranges by .end descending (insertion sort, small list)."""
        for i in range(1, len(self.ack_ranges)):
            var key = AckRangeEntry(copy=self.ack_ranges[i])
            var j = i - 1
            while j >= 0 and self.ack_ranges[j].end < key.end:
                self.ack_ranges[j + 1] = AckRangeEntry(copy=self.ack_ranges[j])
                j -= 1
            self.ack_ranges[j + 1] = key

    # ── ACK frame building ───────────────────────────────────────────

    def peek_ack_frame(
        self, now: UInt64, ack_delay_exponent: UInt64, *, bundle: Bool = False
    ) -> Optional[AckFrame]:
        """Non-mutating ACK candidate.

        Returns a frame when ranges exist and either an ACK is owed
        (`ack_needed`) or `bundle` is set and an ack-eliciting packet is
        unacknowledged (piggyback on a packet that goes out anyway). The
        caller commits with `mark_ack_sent()` once the frame is in the packet.
        """
        if len(self.ack_ranges) == 0:
            return None
        if not self.ack_needed and not (bundle and self.has_unacked_ack_eliciting()):
            return None

        var ack = AckFrame()
        ack.largest_ack = self.ack_ranges[0].end
        ack.ack_delay = self.ack_delay_field(now, ack_delay_exponent)
        ack.first_ack_range = self.ack_ranges[0].end - self.ack_ranges[0].start

        var ranges = List[AckRange](capacity=len(self.ack_ranges))
        for i in range(1, len(self.ack_ranges)):
            var prev_start = self.ack_ranges[i - 1].start
            var curr_end = self.ack_ranges[i].end
            var gap = prev_start - curr_end - 2
            var ack_range = self.ack_ranges[i].end - self.ack_ranges[i].start
            ranges.append(AckRange(gap, ack_range))
        ack.ranges = ranges^

        # Include ECN counts when we've received ECN-marked packets (RFC 9000 §13.4.3).
        if not self.recv_ecn.is_zero():
            ack.has_ecn = True
            ack.ecn_ect0 = self.recv_ecn.ect0
            ack.ecn_ect1 = self.recv_ecn.ect1
            ack.ecn_ce = self.recv_ecn.ce

        return ack^

    def mark_ack_sent(mut self):
        """Commit the peeked ACK: nothing is owed until the next packet."""
        self.ack_needed = False
        self.ack_eliciting_since_last_ack = 0
        self.ack_deadline = None

    # ── Send tracking ────────────────────────────────────────────────

    def on_packet_sent(mut self, var pkt: SentPacket) raises:
        """Record a sent packet; an ack-eliciting one re-arms the PTO base."""
        var key = Int(pkt.pn)
        if key in self.sent_packets:
            if self.sent_packets[key].ack_eliciting:
                self.ae_in_flight -= 1
        var ae = pkt.ack_eliciting
        var ts = pkt.time_sent
        self.sent_packets[key] = pkt^
        if ae:
            self.ae_in_flight += 1
            self.time_of_last_ae_sent = Optional[UInt64](ts)
            self.probe_pending = False

    def forget_sent(mut self, pn: Int) raises -> Optional[SentPacket]:
        """Remove and return a sent record (loss or discard path), keeping the
        ack-eliciting count and the PTO base in step."""
        try:
            var pkt = self.sent_packets.pop(pn)
            if pkt.ack_eliciting:
                self.ae_in_flight -= 1
            self.sync_ae_tracking()
            return pkt^
        except:
            return None

    def has_ack_eliciting_in_flight(self) -> Bool:
        """True while any ack-eliciting packet remains unacknowledged."""
        return self.ae_in_flight > 0

    def sync_ae_tracking(mut self):
        """Disarm the PTO base and any pending probe once no ack-eliciting
        packet remains in `sent_packets` (after ACK or loss removal)."""
        if self.ae_in_flight <= 0:
            self.ae_in_flight = 0
            self.time_of_last_ae_sent = None
            self.probe_pending = False

    # ── ACK processing ───────────────────────────────────────────────

    def on_ack_received(mut self, ref ack: AckFrame) raises -> List[SentPacket]:
        """Process an incoming ACK frame: decode ranges into PN sets, find
        matching sent_packets, remove them, return newly acked list.
        Raises if any ACKed PN >= next_pn (security check)."""
        var acked = List[SentPacket](capacity=16)
        self._scratch_pns.clear()

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
            self._scratch_pns.append(Int(pn))
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
                self._scratch_pns.append(Int(pn))
                pn += 1
            prev_smallest = smallest

        # Update largest_acked_pn.
        var ack_largest_int = Int(ack.largest_ack)
        if ack_largest_int > self.largest_acked_pn:
            self.largest_acked_pn = ack_largest_int

        # Remove acked packets from sent_packets and collect them.
        # Single pop per PN: avoids the old in + [] + copy + pop (4 lookups).
        for i in range(len(self._scratch_pns)):
            var key = self._scratch_pns[i]
            try:
                var pkt = self.sent_packets.pop(key)
                if pkt.ack_eliciting:
                    self.ae_in_flight -= 1
                acked.append(pkt^)
            except:
                pass  # PN not in sent_packets — already removed or never tracked

        if len(acked) > 0:
            self.sync_ae_tracking()
        return acked^

    # ── Space discard ────────────────────────────────────────────────

    def discard(mut self) raises -> List[SentPacket]:
        """Remove all sent_packets and return them for bytes_in_flight accounting.

        Sets keys_handle = -1 and resets every ACK/PTO scheduling field so a
        discarded space can neither report a deadline nor be considered
        sendable.
        """
        var result = List[SentPacket]()
        var keys = List[Int]()
        for key in self.sent_packets.keys():
            keys.append(key)
        for i in range(len(keys)):
            result.append(self.sent_packets.pop(keys[i]))
        self.keys_handle = Int32(-1)
        self.ack_needed = False
        self.ack_deadline = None
        self.ack_eliciting_since_last_ack = 0
        self.probe_pending = False
        self.time_of_last_ae_sent = None
        self.ae_in_flight = 0
        return result^

    # ── Persistent-congestion helper ─────────────────────────────────

    def any_ae_acked_in_range(self, earliest: UInt64, latest: UInt64) -> Bool:
        """Conservative query: True if we have evidence an ack-eliciting packet
        whose time_sent falls in [earliest, latest] was ACKed, OR if the tracker
        has advanced past latest (earlier range-ACKs may have been overwritten).
        Returns False if last_ae_acked_time_sent == 0 (no AE ACK ever received)
        or if it predates earliest.
        Used by persistent-congestion detection (RFC 9002 §7.6)."""
        if self.last_ae_acked_time_sent == UInt64(0):
            return False   # no AE ACK ever received in this space
        if self.last_ae_acked_time_sent >= earliest:
            return True    # in-range (definite) OR past latest (conservative)
        return False       # last AE ACK predates range — no evidence
