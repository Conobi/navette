# src/quic/stream.mojo
# QUIC per-stream building blocks — RFC 9000 §2, §3.
# State machine constants, RecvBuf (reassembly), SendBuf (outgoing),
# and the Stream struct that composes them.

from navette.quic.flow_control import FlowControl, STREAM_FC_MAX_WINDOW
from navette.quic.frame import StreamFrame

# ── Send-side states (RFC 9000 §3.1) ─────────────────────────────────────────


@fieldwise_init
struct SendState(Equatable, ImplicitlyCopyable):
    """Send-side stream state machine (RFC 9000, Section 3.1)."""

    var _value: UInt8

    comptime READY       = SendState(0)
    comptime SEND        = SendState(1)
    comptime DATA_SENT   = SendState(2)
    comptime DATA_RECVD  = SendState(3)   # terminal
    comptime RESET_SENT  = SendState(4)
    comptime RESET_RECVD = SendState(5)   # terminal

    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    def __ne__(self, other: Self) -> Bool:
        return self._value != other._value

    def is_terminal(self) -> Bool:
        """True for DATA_RECVD and RESET_RECVD."""
        return self == Self.DATA_RECVD or self == Self.RESET_RECVD


# ── Recv-side states (RFC 9000 §3.2) ─────────────────────────────────────────


@fieldwise_init
struct RecvState(Equatable, ImplicitlyCopyable):
    """Recv-side stream state machine (RFC 9000, Section 3.2)."""

    var _value: UInt8

    comptime RECV              = RecvState(0)
    comptime SIZE_KNOWN        = RecvState(1)
    comptime DATA_RECVD        = RecvState(2)
    comptime DATA_READ         = RecvState(3)   # terminal
    comptime STOP_SENDING_SENT = RecvState(4)
    comptime RESET_RECVD       = RecvState(5)
    comptime RESET_READ        = RecvState(6)   # terminal

    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    def __ne__(self, other: Self) -> Bool:
        return self._value != other._value

    def is_terminal(self) -> Bool:
        """True for DATA_READ and RESET_READ."""
        return self == Self.DATA_READ or self == Self.RESET_READ


# ── Helper functions ──────────────────────────────────────────────────────────


def stream_is_bidi(id: UInt64) -> Bool:
    """True if stream ID refers to a bidirectional stream (bit 1 = 0)."""
    return (id & UInt64(0x02)) == 0


def stream_is_local(id: UInt64, is_server: Bool) -> Bool:
    """True if this stream was initiated by the local endpoint."""
    return ((id & UInt64(0x01)) != 0) == is_server


def stream_is_client_initiated(id: UInt64) -> Bool:
    """True if stream ID was initiated by the client (bit 0 = 0)."""
    return (id & UInt64(0x01)) == 0


def send_state_is_terminal(state: SendState) -> Bool:
    """True for send-side terminal states (DATA_RECVD, RESET_RECVD)."""
    return state.is_terminal()


def recv_state_is_terminal(state: RecvState) -> Bool:
    """True for recv-side terminal states (DATA_READ, RESET_READ)."""
    return state.is_terminal()


# ── RecvBuf ───────────────────────────────────────────────────────────────────


struct RecvBuf(Copyable, Movable):
    """Receive-side reassembly buffer for QUIC STREAM frames.

    Handles out-of-order, overlapping, and gapped deliveries.
    Stores segments as (offset, assembled_bytes) pairs, kept sorted.
    Accept-first-copy: overlapping writes do not overwrite existing data.
    """

    # Each segment: seg_offsets[i] is the absolute start offset;
    # seg_data[i] is the assembled bytes for that contiguous run.
    # Segments are kept sorted by seg_offsets and never overlap.
    var seg_offsets: List[UInt64]
    var seg_data: List[List[Byte]]
    var read_offset: UInt64             # next byte to deliver
    var max_gaps: UInt64                # gap count limit
    var total_received: UInt64          # total distinct bytes received (no gaps)

    def __init__(out self, recv_window: UInt64):
        self.seg_offsets = List[UInt64]()
        self.seg_data = List[List[Byte]]()
        self.read_offset = UInt64(0)
        self.total_received = UInt64(0)
        # max_gaps = max(64, recv_window // 512)
        var computed = recv_window // UInt64(512)
        if computed > UInt64(64):
            self.max_gaps = computed
        else:
            self.max_gaps = UInt64(64)

    def _seg_end(self, i: Int) -> UInt64:
        """Return the exclusive end offset of segment i."""
        return self.seg_offsets[i] + UInt64(len(self.seg_data[i]))

    def _num_gaps(self) -> Int:
        """Count gaps in segment list, including gap from read_offset to first segment."""
        var n = len(self.seg_offsets)
        if n == 0:
            return 0
        var gaps = 0
        # Count leading gap (from read_offset to first segment)
        if self.seg_offsets[0] > self.read_offset:
            gaps += 1
        # Count gaps between consecutive segments
        for i in range(1, n):
            if self.seg_offsets[i] > self._seg_end(i - 1):
                gaps += 1
        return gaps

    def write(
        mut self,
        offset: UInt64,
        data: Span[Byte, _],
        fin: Bool,
        mut fin_offset: Optional[UInt64],
    ) raises -> UInt64:
        """Insert data at the given offset into the reassembly buffer.

        Returns the number of new (non-duplicate) bytes written.
        Raises FINAL_SIZE_ERROR or PROTOCOL_VIOLATION on invariant violations.
        """
        var data_len = UInt64(len(data))
        var end_offset = offset + data_len

        # ── Check 1: FIN consistency ────────────────────────────────────────
        if fin:
            var this_fin = end_offset
            if fin_offset:
                if fin_offset.value() != this_fin:
                    raise "FINAL_SIZE_ERROR: FIN offset mismatch"
            else:
                fin_offset = this_fin

        # ── Check 2: data must not extend past established final size ───────
        if fin_offset:
            if end_offset > fin_offset.value():
                raise "FINAL_SIZE_ERROR: data extends past final size"

        # ── Compute new bytes before inserting ───────────────────────────────
        var new_bytes = self._count_new_bytes(offset, end_offset)

        # ── Check 3: gap limit ───────────────────────────────────────────────
        if data_len > 0:
            if self._would_create_gap(offset, end_offset):
                var current_gaps = self._num_gaps()
                if UInt64(current_gaps + 1) > self.max_gaps:
                    raise "PROTOCOL_VIOLATION: too many gaps in recv stream"

        # ── Insert data ──────────────────────────────────────────────────────
        if data_len > 0:
            self._insert(offset, data)

        self.total_received += new_bytes
        return new_bytes

    def _count_new_bytes(self, offset: UInt64, end_offset: UInt64) -> UInt64:
        """Count bytes in [offset, end_offset) not covered by existing segments.

        Bytes below read_offset are already consumed and treated as covered.
        """
        if offset >= end_offset:
            return UInt64(0)
        # Entirely below read_offset: already consumed, no new bytes
        if end_offset <= self.read_offset:
            return UInt64(0)
        var new_bytes = UInt64(0)
        # Clamp start to read_offset (treat already-read bytes as covered)
        var cur = offset
        if self.read_offset > cur:
            cur = self.read_offset
        for i in range(len(self.seg_offsets)):
            var rs = self.seg_offsets[i]
            var re = self._seg_end(i)
            if re <= cur:
                continue
            if rs >= end_offset:
                break
            if cur < rs:
                new_bytes += rs - cur
                cur = rs
            if re > cur:
                cur = re
            if cur >= end_offset:
                break
        if cur < end_offset:
            new_bytes += end_offset - cur
        return new_bytes

    def _would_create_gap(self, offset: UInt64, end_offset: UInt64) -> Bool:
        """True if inserting [offset, end_offset) would create a new gap.

        read_offset acts as the implicit left boundary of already-received data,
        so no gap is created if the incoming range abuts or overlaps read_offset.
        """
        # Clamp the effective start to read_offset (bytes below are already covered)
        var eff_start = offset
        if self.read_offset > eff_start:
            eff_start = self.read_offset
        if len(self.seg_offsets) == 0:
            return eff_start > self.read_offset
        for i in range(len(self.seg_offsets)):
            var rs = self.seg_offsets[i]
            var re = self._seg_end(i)
            # Adjacent or overlapping (using clamped start)
            if eff_start <= re and end_offset >= rs:
                return False
        # Check adjacency with read_offset itself
        if eff_start <= self.read_offset:
            return False
        return True

    def _insert(mut self, offset: UInt64, data: Span[Byte, _]):
        """Insert [offset, offset+len(data)) with accept-first-copy semantics.

        Merges overlapping and adjacent segments, preserving existing data.
        Bytes below read_offset are never inserted (already consumed).
        """
        if len(data) == 0:
            return

        var end = offset + UInt64(len(data))
        # Entirely below read_offset: nothing to store
        if end <= self.read_offset:
            return

        # Clamp start to read_offset, trimming already-consumed prefix
        var new_start = offset
        var data_skip = Int(0)
        if self.read_offset > new_start:
            data_skip = Int(self.read_offset - new_start)
            new_start = self.read_offset
        var new_end = end
        # Use a clamped view of data (skip already-consumed prefix bytes)
        var clamped = data[data_skip:]

        # Fast path: contiguous append to the last (or only) segment.
        # This is the steady-state case for in-order delivery.
        if len(self.seg_offsets) > 0:
            var last_idx = len(self.seg_offsets) - 1
            var last_end = self._seg_end(last_idx)
            if new_start == last_end and new_end >= last_end:
                self.seg_data[last_idx].extend(clamped)
                return
            # Also handle append to segment 0 when there's only 1 segment
            if len(self.seg_offsets) == 1:
                var seg0_end = self._seg_end(0)
                if new_start >= self.seg_offsets[0] and new_start <= seg0_end:
                    # Overlapping or adjacent — extend in place
                    if new_end > seg0_end:
                        var skip = Int(seg0_end - new_start)
                        self.seg_data[0].extend(clamped[skip:])
                    return
        elif len(self.seg_offsets) == 0:
            # Empty buffer — first segment
            var new_seg = List[Byte](capacity=len(clamped))
            new_seg.extend(clamped)
            self.seg_offsets.append(new_start)
            self.seg_data.append(new_seg^)
            return

        # Find all segments that overlap or are adjacent to [new_start, new_end)
        var first_affected = -1
        var last_affected = -1
        for i in range(len(self.seg_offsets)):
            var rs = self.seg_offsets[i]
            var re = self._seg_end(i)
            if rs <= new_end and re >= new_start:
                if first_affected == -1:
                    first_affected = i
                last_affected = i

        if first_affected == -1:
            self._insert_gap(new_start, clamped)
        else:
            self._insert_merge(new_start, new_end, clamped, first_affected, last_affected)

    def _insert_gap(mut self, new_start: UInt64, data: Span[Byte, _]):
        """Insert non-overlapping segment at sorted position."""
        var new_seg = List[Byte](capacity=len(data))
        new_seg.extend(data)
        var insert_pos = len(self.seg_offsets)
        for i in range(len(self.seg_offsets)):
            if new_start < self.seg_offsets[i]:
                insert_pos = i
                break
        var new_offsets = List[UInt64]()
        var new_segs = List[List[Byte]]()
        for i in range(len(self.seg_offsets)):
            if i == insert_pos:
                new_offsets.append(new_start)
                new_segs.append(new_seg^)
                new_seg = List[Byte]()
            new_offsets.append(self.seg_offsets[i])
            new_segs.append(List[Byte](copy=self.seg_data[i]))
        if insert_pos == len(self.seg_offsets):
            new_offsets.append(new_start)
            new_segs.append(new_seg^)
        self.seg_offsets = new_offsets^
        self.seg_data = new_segs^

    def _insert_merge(
        mut self,
        new_start: UInt64,
        new_end: UInt64,
        data: Span[Byte, _],
        first_affected: Int,
        last_affected: Int,
    ):
        """Merge overlapping segments with accept-first-copy semantics."""
        var merged_start = new_start
        if self.seg_offsets[first_affected] < merged_start:
            merged_start = self.seg_offsets[first_affected]
        var merged_end = new_end
        if self._seg_end(last_affected) > merged_end:
            merged_end = self._seg_end(last_affected)

        var merged_len = Int(merged_end - merged_start)
        var merged = List[Byte](capacity=merged_len)
        merged.resize(merged_len, Byte(0))

        # Lay down new data as the base.
        var dst_base = Int(new_start - merged_start)
        for j in range(len(data)):
            var dst_idx = dst_base + j
            if dst_idx >= 0 and dst_idx < merged_len:
                merged[dst_idx] = data[j]

        # Overlay existing segment data (takes priority).
        for i in range(first_affected, last_affected + 1):
            var seg_off = self.seg_offsets[i]
            var dst_start = Int(seg_off - merged_start)
            for j in range(len(self.seg_data[i])):
                merged[dst_start + j] = self.seg_data[i][j]

        # Rebuild seg lists replacing first..last with the merged segment.
        var new_offsets = List[UInt64]()
        var new_segs = List[List[Byte]]()
        for i in range(len(self.seg_offsets)):
            if i < first_affected:
                new_offsets.append(self.seg_offsets[i])
                new_segs.append(List[Byte](copy=self.seg_data[i]))
            elif i == first_affected:
                new_offsets.append(merged_start)
                new_segs.append(merged^)
                merged = List[Byte]()
            elif i > last_affected:
                new_offsets.append(self.seg_offsets[i])
                new_segs.append(List[Byte](copy=self.seg_data[i]))
        self.seg_offsets = new_offsets^
        self.seg_data = new_segs^

    def read(mut self, fin_offset: Optional[UInt64]) -> Tuple[List[Byte], Bool]:
        """Drain the contiguous segment at read_offset, moving its List out.

        Returns (bytes, fin_reached). fin_reached is True once read_offset has
        reached fin_offset. The segment is copied only when its head was
        already consumed, which `_insert`'s clamp to read_offset rules out.
        """
        var result = List[Byte]()
        if len(self.seg_offsets) > 0 and self.seg_offsets[0] <= self.read_offset:
            var skip = Int(self.read_offset - self.seg_offsets[0])
            self.read_offset = self._seg_end(0)
            _ = self.seg_offsets.pop(0)
            result = self.seg_data.pop(0)
            if skip > 0:
                var tail = List[Byte](capacity=len(result) - skip)
                tail.extend(Span(result)[skip:])
                result = tail^
        var fin_reached = Bool(fin_offset) and self.read_offset >= fin_offset.value()
        return (result^, fin_reached)

    def is_complete(self, fin_offset: Optional[UInt64]) -> Bool:
        """True if fin_offset is set and we have received all bytes up to it.

        Uses total_received to remain correct after partial reads consume segments.
        """
        if not fin_offset:
            return False
        return self.total_received >= fin_offset.value()

    def has_readable(self) -> Bool:
        """True if there are bytes ready to deliver starting at read_offset."""
        if len(self.seg_offsets) == 0:
            return False
        return self.seg_offsets[0] <= self.read_offset


# ── SendBuf ───────────────────────────────────────────────────────────────────


struct SendBuf(Copyable, Movable):
    """Send-side data buffer for a QUIC stream.

    Tracks outgoing data, framing progress, and acknowledgement.
    `acked_offset` is the contiguous acked prefix; ACKed ranges above it
    are parked in `acked_above` (sorted, disjoint, all starting past
    `acked_offset`) until the gap fills. They cannot be dropped: each
    packet's stream records are consumed when its ACK is processed, so a
    discarded range is never re-delivered and the stream would never
    reach fully-acked.
    """

    var data: List[Byte]
    var offset: UInt64              # byte offset of data[0] in the stream
    var unsent_offset: UInt64       # first unsent byte (absolute)
    var highest_sent_offset: UInt64  # end of the furthest byte ever framed
    var acked_offset: UInt64        # contiguous ACKed bytes from stream start
    var acked_above: List[Tuple[UInt64, UInt64]]  # [start, end) acked past a gap
    var fin: Bool                       # FIN requested by the application
    var fin_offset: Optional[UInt64]    # set when FIN framed, cleared on its loss
    var fin_acked: Bool
    var read_cursor: Int

    def __init__(out self):
        self.data = List[Byte]()
        self.offset = UInt64(0)
        self.unsent_offset = UInt64(0)
        self.highest_sent_offset = UInt64(0)
        self.acked_offset = UInt64(0)
        self.acked_above = List[Tuple[UInt64, UInt64]]()
        self.fin = False
        self.fin_offset = None
        self.fin_acked = False
        self.read_cursor = 0

    def write(mut self, new_data: Span[Byte, _], set_fin: Bool) raises:
        """Append data to the outgoing buffer and optionally set the FIN flag."""
        if self.fin and len(new_data) > 0:
            raise "STREAM_STATE_ERROR: write after FIN queued"
        self.data.extend(new_data)
        if set_fin:
            self.fin = True

    def has_pending(self) -> Bool:
        """True if there is unsent data or an unsent FIN."""
        var total_data_end = self.offset + UInt64(len(self.data) - self.read_cursor)
        if self.unsent_offset < total_data_end:
            return True
        # FIN pending: fin is set but not yet framed (fin_offset not set)
        if self.fin and not self.fin_offset:
            return True
        return False

    def pending_len(self) -> UInt64:
        """Number of bytes not yet framed."""
        var total_data_end = self.offset + UInt64(len(self.data) - self.read_cursor)
        if self.unsent_offset >= total_data_end:
            return UInt64(0)
        return total_data_end - self.unsent_offset

    def make_frame(mut self, stream_id: UInt64, max_bytes: Int) -> Optional[StreamFrame]:
        """Create a STREAM frame from unsent data up to max_bytes.

        Returns None if no data or FIN to send.
        Prefer prepare_frame + data_span for the hot send path to avoid
        the intermediate List allocation.
        """
        var meta = self.prepare_frame(max_bytes)
        if not meta:
            return None
        var t = meta.value()
        var frame_start = t[0]
        var chunk_size = t[1]
        var include_fin = t[2]

        var buf_start = self.read_cursor + Int(frame_start - self.offset)
        var frame_data = List[Byte](capacity=chunk_size)
        frame_data.extend(Span(self.data)[buf_start : buf_start + chunk_size])

        var frame = StreamFrame(stream_id, frame_start, frame_data^, include_fin)
        return frame^

    def prepare_frame(mut self, max_bytes: Int) -> Optional[Tuple[UInt64, Int, Bool]]:
        """Advance the send cursor and return (offset, chunk_size, fin).

        Unlike make_frame, does NOT copy data — the caller reads the
        chunk via data_span() after this returns. Every STREAM frame,
        first send or retransmission, is cut here, so this is the one
        place that raises highest_sent_offset.
        """
        var total_data_end = self.offset + UInt64(len(self.data) - self.read_cursor)

        var frame_start = self.unsent_offset
        var available = Int(0)
        if total_data_end > frame_start:
            available = Int(total_data_end - frame_start)
        var chunk_size = available
        if chunk_size > max_bytes:
            chunk_size = max_bytes

        var include_fin = False
        if self.fin and not self.fin_offset:
            if frame_start + UInt64(chunk_size) >= total_data_end:
                include_fin = True

        if chunk_size == 0 and not include_fin:
            return None

        if include_fin and not self.fin_offset:
            self.fin_offset = frame_start + UInt64(chunk_size)

        self.unsent_offset = frame_start + UInt64(chunk_size)
        if self.unsent_offset > self.highest_sent_offset:
            self.highest_sent_offset = self.unsent_offset

        return Tuple(frame_start, chunk_size, include_fin)

    def data_span(self, frame_offset: UInt64, chunk_size: Int) -> Span[Byte, origin_of(self.data)]:
        """Return a view of the send buffer for the given frame region.

        Call after prepare_frame to read data without copying.
        """
        var buf_start = self.read_cursor + Int(frame_offset - self.offset)
        return Span(self.data)[buf_start : buf_start + chunk_size]

    def on_ack(mut self, ack_off: UInt64, ack_len: UInt64):
        """Handle acknowledgment of [ack_off, ack_off+ack_len) bytes.

        A range starting past acked_offset is parked in acked_above and
        absorbed once the gap below it is acked. If the ack range extends the
        contiguous acked_offset, advances the read cursor past consumed
        bytes (O(1) instead of reallocating) and
        floors unsent_offset at acked_offset so acked bytes are never
        retransmitted (guards the on_loss-then-late-ACK spurious-loss race).
        Bare-FIN ACKs (ack_len == 0) are handled by checking if all data was
        already acked (acked_offset >= fin_offset).
        """
        if ack_len == 0:
            # Bare-FIN ACK: set fin_acked if all preceding data was already acked
            if self.fin_offset:
                if self.acked_offset >= self.fin_offset.value():
                    self.fin_acked = True
            return

        var ack_end = ack_off + ack_len

        if ack_off > self.acked_offset:
            self._park_acked_range(ack_off, ack_end)
        elif ack_end > self.acked_offset:
            self.acked_offset = ack_end
            # Absorb parked ranges the new prefix now reaches.
            var absorbed = 0
            for ref r in self.acked_above:
                if r[0] > self.acked_offset:
                    break
                if r[1] > self.acked_offset:
                    self.acked_offset = r[1]
                absorbed += 1
            if absorbed > 0:
                var rest = List[Tuple[UInt64, UInt64]]()
                for i in range(absorbed, len(self.acked_above)):
                    rest.append(self.acked_above[i])
                self.acked_above = rest^

            # A prior on_loss may have rewound unsent_offset below bytes this
            # ACK now covers (spurious loss / reordered ACK). Acked bytes must
            # never be retransmitted, so keep the send cursor at or above
            # acked_offset — the mirror of the floor in on_loss. Without this,
            # the trim below advances self.offset past unsent_offset and the
            # next make_frame indexes before data[0].
            if self.unsent_offset < self.acked_offset:
                self.unsent_offset = self.acked_offset

            # Advance read cursor instead of physically trimming.
            var trim = Int(self.acked_offset - self.offset)
            var live = len(self.data) - self.read_cursor
            if trim > live:
                trim = live
            if trim > 0:
                self.read_cursor += trim
                self.offset = self.offset + UInt64(trim)

        # Check fin_acked
        if self.fin_offset:
            if self.acked_offset >= self.fin_offset.value():
                self.fin_acked = True

    def _park_acked_range(mut self, start: UInt64, end: UInt64):
        """Insert [start, end) into acked_above, merging overlapping or adjacent ranges."""
        var new_start = start
        var new_end = end
        var merged = List[Tuple[UInt64, UInt64]](capacity=len(self.acked_above) + 1)
        var placed = False
        for ref r in self.acked_above:
            if r[1] < new_start:
                merged.append(r)
            elif r[0] > new_end:
                if not placed:
                    merged.append((new_start, new_end))
                    placed = True
                merged.append(r)
            else:
                new_start = min(new_start, r[0])
                new_end = max(new_end, r[1])
        if not placed:
            merged.append((new_start, new_end))
        self.acked_above = merged^

    def on_loss(mut self, lost_off: UInt64, lost_len: UInt64):
        """Handle loss of [lost_off, lost_off+lost_len) bytes.

        Resets unsent_offset to trigger retransmission, floored at acked_offset.
        If the lost range covers the FIN, clears fin_offset so make_frame will
        re-include the FIN flag on the next retransmission.
        """
        if lost_len == 0:
            return

        # Reset unsent_offset = min(unsent_offset, lost_off)
        if lost_off < self.unsent_offset:
            self.unsent_offset = lost_off

        # Floor at acked_offset (never retransmit already-acked data)
        if self.unsent_offset < self.acked_offset:
            self.unsent_offset = self.acked_offset

        # If the lost range covers the FIN byte, clear fin_offset so that
        # make_frame will re-include the FIN on the retransmit.
        if self.fin_offset:
            var lost_end = lost_off + lost_len
            if lost_end >= self.fin_offset.value():
                self.fin_offset = None
                self.fin_acked = False

    def reset_final_size(self) -> UInt64:
        """Final size for a RESET_STREAM (RFC 9000 Section 4.5): the highest
        offset ever sent, which loss never lowers.

        unsent_offset is wrong here: on_loss rewinds it, and a final size
        below bytes the peer already received is a FINAL_SIZE_ERROR.
        """
        if self.fin_offset:
            return max(self.highest_sent_offset, self.fin_offset.value())
        return self.highest_sent_offset

    def is_fully_acked(self) -> Bool:
        """True when all data and FIN have been acknowledged."""
        if not self.fin_offset:
            return False
        return self.acked_offset >= self.fin_offset.value() and self.fin_acked


# ── Stream struct ─────────────────────────────────────────────────────────────


struct Stream(Copyable, Movable):
    """A single QUIC stream with send and/or recv sides.

    The presence of send_state/recv_state indicates whether the stream has
    a send or recv side. For unidirectional streams, one side is None.
    """

    var id: UInt64
    var is_bidi: Bool
    var is_local: Bool
    var send_state: Optional[SendState]
    var recv_state: Optional[RecvState]
    var send_buf: Optional[SendBuf]
    var recv_buf: Optional[RecvBuf]
    var fc_send: Optional[FlowControl]
    var fc_recv: Optional[FlowControl]
    var fin_offset: Optional[UInt64]           # recv-side final size
    var recv_highest_offset: UInt64
    var send_fin_offset: Optional[UInt64]
    var reset_error: Optional[UInt64]
    var stop_error: Optional[UInt64]
    var needs_max_stream_data: Bool
    var needs_reset_stream: Bool
    var needs_stop_sending: Bool
    var reset_stream_final_size: UInt64
    var reset_stream_error: UInt64
    var stop_sending_error: UInt64
    var urgency: UInt8
    var incremental: Bool
    # True iff the stream was FIRST created (key inserted into
    # `StreamMap.streams`) while the connection was dispatching frames
    # from a 0-RTT-decrypted packet. Tagged ONCE at insertion-time by
    # `QuicConnection._handle_stream_frame` via the connection-level
    # transient `_current_space_idx` (sentinel index 3 — see
    # `feedback_zero_rtt_space_idx_vs_pn_space.md`). Never re-tagged on
    # subsequent STREAM frames; the monotonic-once invariant lets the
    # H3 layer route the stream's first request via the early-data
    # filter even after the handshake completes and subsequent body
    # bytes arrive in 1-RTT (RFC 9001 §4.6, RFC 8470).
    var is_zero_rtt: Bool

    def __init__(out self, id: UInt64, is_bidi: Bool, is_local: Bool):
        """Base constructor — creates a skeleton Stream with no send/recv sides."""
        self.id = id
        self.is_bidi = is_bidi
        self.is_local = is_local
        self.send_state = None
        self.recv_state = None
        self.send_buf = None
        self.recv_buf = None
        self.fc_send = None
        self.fc_recv = None
        self.fin_offset = None
        self.recv_highest_offset = UInt64(0)
        self.send_fin_offset = None
        self.reset_error = None
        self.stop_error = None
        self.needs_max_stream_data = False
        self.needs_reset_stream = False
        self.needs_stop_sending = False
        self.reset_stream_final_size = UInt64(0)
        self.reset_stream_error = UInt64(0)
        self.stop_sending_error = UInt64(0)
        self.urgency = UInt8(127)
        self.incremental = False
        self.is_zero_rtt = False

    # ── Factory methods ───────────────────────────────────────────────────────

    @staticmethod
    def new_local_bidi(
        id: UInt64,
        fc_send_limit: UInt64,
        fc_recv_limit: UInt64,
        fc_recv_window: UInt64,
    ) -> Stream:
        """Create a local bidirectional stream (both send and recv sides)."""
        return Stream._new_bidi(id, True, fc_send_limit, fc_recv_limit, fc_recv_window)

    @staticmethod
    def new_remote_bidi(
        id: UInt64,
        fc_send_limit: UInt64,
        fc_recv_limit: UInt64,
        fc_recv_window: UInt64,
    ) -> Stream:
        """Create a remote bidirectional stream (both send and recv sides)."""
        return Stream._new_bidi(id, False, fc_send_limit, fc_recv_limit, fc_recv_window)

    @staticmethod
    def _new_bidi(
        id: UInt64,
        is_local: Bool,
        fc_send_limit: UInt64,
        fc_recv_limit: UInt64,
        fc_recv_window: UInt64,
    ) -> Stream:
        """Shared bidirectional stream constructor."""
        var s = Stream(id, True, is_local)
        s.send_state = SendState.READY
        s.recv_state = RecvState.RECV
        s.send_buf = SendBuf()
        s.recv_buf = RecvBuf(fc_recv_window)
        s.fc_send = FlowControl(fc_send_limit, fc_send_limit)
        s.fc_recv = FlowControl(fc_recv_limit, fc_recv_window, STREAM_FC_MAX_WINDOW)
        return s^

    @staticmethod
    def new_local_uni(id: UInt64, fc_send_limit: UInt64) -> Stream:
        """Create a local unidirectional stream (send-side only)."""
        var s = Stream(id, False, True)
        s.send_state = SendState.READY
        s.send_buf = SendBuf()
        s.fc_send = FlowControl(fc_send_limit, fc_send_limit)
        return s^

    @staticmethod
    def new_remote_uni(
        id: UInt64,
        fc_recv_limit: UInt64,
        fc_recv_window: UInt64,
    ) -> Stream:
        """Create a remote unidirectional stream (recv-side only)."""
        var s = Stream(id, False, False)
        s.recv_state = RecvState.RECV
        s.recv_buf = RecvBuf(fc_recv_window)
        s.fc_recv = FlowControl(fc_recv_limit, fc_recv_window, STREAM_FC_MAX_WINDOW)
        return s^

    def is_fully_closed(self) -> Bool:
        """True if all present sides of the stream are in a terminal state."""
        if self.is_bidi:
            # Both sides must be terminal (or absent)
            var send_ok = True
            if self.send_state:
                send_ok = send_state_is_terminal(self.send_state.value())
            var recv_ok = True
            if self.recv_state:
                recv_ok = recv_state_is_terminal(self.recv_state.value())
            return send_ok and recv_ok
        else:
            # Unidirectional: check whichever side is present
            if self.is_local:
                if self.send_state:
                    return send_state_is_terminal(self.send_state.value())
                return True
            else:
                if self.recv_state:
                    return recv_state_is_terminal(self.recv_state.value())
                return True
