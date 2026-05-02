# src/quic/stream.mojo
# QUIC per-stream building blocks — RFC 9000 §2, §3.
# State machine constants, RecvBuf (reassembly), SendBuf (outgoing),
# and the Stream struct that composes them.

from src.quic.flow_control import FlowControl, STREAM_FC_MAX_WINDOW
from src.quic.frame import StreamFrame

# ── Send-side states (RFC 9000 §3.1) ─────────────────────────────────────────

comptime SEND_READY: UInt8 = 0
comptime SEND_SEND: UInt8 = 1
comptime SEND_DATA_SENT: UInt8 = 2
comptime SEND_DATA_RECVD: UInt8 = 3     # terminal
comptime SEND_RESET_SENT: UInt8 = 4
comptime SEND_RESET_RECVD: UInt8 = 5    # terminal

# ── Recv-side states (RFC 9000 §3.2) ─────────────────────────────────────────

comptime RECV_RECV: UInt8 = 0
comptime RECV_SIZE_KNOWN: UInt8 = 1
comptime RECV_DATA_RECVD: UInt8 = 2
comptime RECV_DATA_READ: UInt8 = 3      # terminal
comptime RECV_STOP_SENDING_SENT: UInt8 = 4
comptime RECV_RESET_RECVD: UInt8 = 5
comptime RECV_RESET_READ: UInt8 = 6     # terminal

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


def send_state_is_terminal(state: UInt8) -> Bool:
    """True for send-side terminal states (DATA_RECVD, RESET_RECVD)."""
    return state == SEND_DATA_RECVD or state == SEND_RESET_RECVD


def recv_state_is_terminal(state: UInt8) -> Bool:
    """True for recv-side terminal states (DATA_READ, RESET_READ)."""
    return state == RECV_DATA_READ or state == RECV_RESET_READ


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
    var seg_data: List[List[UInt8]]
    var read_offset: UInt64             # next byte to deliver
    var max_gaps: UInt64                # gap count limit
    var total_received: UInt64          # total distinct bytes received (no gaps)

    def __init__(out self, recv_window: UInt64):
        self.seg_offsets = List[UInt64]()
        self.seg_data = List[List[UInt8]]()
        self.read_offset = UInt64(0)
        self.total_received = UInt64(0)
        # max_gaps = max(64, recv_window // 512)
        var computed = recv_window // UInt64(512)
        if computed > UInt64(64):
            self.max_gaps = computed
        else:
            self.max_gaps = UInt64(64)

    def __init__(out self, *, other: Self):
        self.seg_offsets = List[UInt64](copy=other.seg_offsets)
        self.seg_data = List[List[UInt8]](copy=other.seg_data)
        self.read_offset = other.read_offset
        self.max_gaps = other.max_gaps
        self.total_received = other.total_received

    def __init__(out self, *, deinit take: Self):
        self.seg_offsets = take.seg_offsets^
        self.seg_data = take.seg_data^
        self.read_offset = take.read_offset
        self.max_gaps = take.max_gaps
        self.total_received = take.total_received

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
        data: Span[UInt8, _],
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

    def _insert(mut self, offset: UInt64, data: Span[UInt8, _]):
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
            # No overlap: insert as a new segment at sorted position
            var new_seg = List[UInt8](capacity=len(clamped))
            new_seg.extend(Span(clamped))
            # Fast path: empty seg list (typical at start of each request
            # at long-conn — drain just consumed all prior segments).
            if len(self.seg_offsets) == 0:
                self.seg_offsets.append(new_start)
                self.seg_data.append(new_seg^)
            else:
                # Find insertion point
                var insert_pos = len(self.seg_offsets)
                for i in range(len(self.seg_offsets)):
                    if new_start < self.seg_offsets[i]:
                        insert_pos = i
                        break
                # Append-tail fast path: insertion at end, no rebuild needed.
                if insert_pos == len(self.seg_offsets):
                    self.seg_offsets.append(new_start)
                    self.seg_data.append(new_seg^)
                else:
                    # Rebuild with new segment inserted at sorted position
                    var new_offsets = List[UInt64]()
                    var new_segs = List[List[UInt8]]()
                    for i in range(len(self.seg_offsets)):
                        if i == insert_pos:
                            new_offsets.append(new_start)
                            new_segs.append(new_seg^)
                            new_seg = List[UInt8]()  # clear after move
                        new_offsets.append(self.seg_offsets[i])
                        new_segs.append(List[UInt8](copy=self.seg_data[i]))
                    self.seg_offsets = new_offsets^
                    self.seg_data = new_segs^
        else:
            # Merge: build a new merged segment
            # The merged region spans from merged_start to merged_end
            var merged_start = new_start
            if self.seg_offsets[first_affected] < merged_start:
                merged_start = self.seg_offsets[first_affected]
            var merged_end = new_end
            if self._seg_end(last_affected) > merged_end:
                merged_end = self._seg_end(last_affected)

            var merged_len = Int(merged_end - merged_start)
            var merged = List[UInt8](capacity=merged_len)
            for _ in range(merged_len):
                merged.append(UInt8(0))

            # Track which bytes have been written
            var written = List[Bool](capacity=merged_len)
            for _ in range(merged_len):
                written.append(False)

            # First: copy all existing segment data (they take priority)
            for i in range(first_affected, last_affected + 1):
                var seg_off = self.seg_offsets[i]
                var dst_start = Int(seg_off - merged_start)
                for j in range(len(self.seg_data[i])):
                    merged[dst_start + j] = self.seg_data[i][j]
                    written[dst_start + j] = True

            # Then: copy new data only for positions not yet written
            var dst_base = Int(new_start - merged_start)
            for j in range(len(clamped)):
                var dst_idx = dst_base + j
                if dst_idx >= 0 and dst_idx < merged_len and not written[dst_idx]:
                    merged[dst_idx] = clamped[j]
                    written[dst_idx] = True

            # Rebuild seg lists replacing first..last with the merged segment
            var new_offsets = List[UInt64]()
            var new_segs = List[List[UInt8]]()
            for i in range(len(self.seg_offsets)):
                if i < first_affected:
                    new_offsets.append(self.seg_offsets[i])
                    new_segs.append(List[UInt8](copy=self.seg_data[i]))
                elif i == first_affected:
                    new_offsets.append(merged_start)
                    new_segs.append(merged^)
                    merged = List[UInt8]()  # clear after move
                elif i > last_affected:
                    new_offsets.append(self.seg_offsets[i])
                    new_segs.append(List[UInt8](copy=self.seg_data[i]))
                # else: skip merged segments (first_affected < i <= last_affected)
            self.seg_offsets = new_offsets^
            self.seg_data = new_segs^

    def read_into(mut self, fin_offset: Optional[UInt64], mut data_out: List[UInt8]) -> Bool:
        """Drain contiguous bytes into the caller's `data_out` list. Returns
        fin_reached. Avoids the Tuple[List, Bool] boxing of `read()` and the
        attendant per-call .copy() on the data list — Mojo 0.26.2 cannot
        move out of a tuple element. Hot-path callers (recv_stream_data)
        should prefer this; tests use the tuple form via `read()`."""
        if len(self.seg_offsets) == 0:
            if fin_offset:
                if self.read_offset >= fin_offset.value():
                    return True
            return False

        # Check if the first segment covers read_offset
        if self.seg_offsets[0] > self.read_offset:
            if fin_offset:
                if self.read_offset >= fin_offset.value():
                    return True
            return False

        # Deliver bytes from read_offset to end of first segment
        var deliver_end = self._seg_end(0)
        var skip = Int(self.read_offset - self.seg_offsets[0])
        var n = Int(deliver_end - self.read_offset)
        data_out.extend(Span(self.seg_data[0])[skip:skip + n])

        self.read_offset = deliver_end

        # Remove the consumed segment.
        # Fast path: single-segment case (typical for 1-packet requests at
        # long-conn). Avoids the new-list build + move + per-segment .copy()
        # loop that the multi-segment path requires.
        if len(self.seg_offsets) == 1:
            self.seg_offsets.clear()
            self.seg_data.clear()
        else:
            var new_offsets = List[UInt64]()
            var new_segs = List[List[UInt8]]()
            for i in range(1, len(self.seg_offsets)):
                new_offsets.append(self.seg_offsets[i])
                new_segs.append(List[UInt8](copy=self.seg_data[i]))
            self.seg_offsets = new_offsets^
            self.seg_data = new_segs^

        if fin_offset:
            if self.read_offset >= fin_offset.value():
                return True
        return False

    def read(mut self, fin_offset: Optional[UInt64]) -> Tuple[List[UInt8], Bool]:
        """Drain contiguous bytes starting from read_offset.

        Returns (bytes, fin_reached). fin_reached is True when all bytes up to
        fin_offset have been delivered and read_offset == fin_offset.
        """
        var result = List[UInt8]()

        if len(self.seg_offsets) == 0:
            if fin_offset:
                if self.read_offset >= fin_offset.value():
                    return (result^, True)
            return (result^, False)

        # Check if the first segment covers read_offset
        if self.seg_offsets[0] > self.read_offset:
            if fin_offset:
                if self.read_offset >= fin_offset.value():
                    return (result^, True)
            return (result^, False)

        # Deliver bytes from read_offset to end of first segment
        var deliver_end = self._seg_end(0)
        var skip = Int(self.read_offset - self.seg_offsets[0])
        var n = Int(deliver_end - self.read_offset)

        result = List[UInt8](capacity=n)
        result.extend(Span(self.seg_data[0])[skip:skip + n])

        self.read_offset = deliver_end

        # Remove the consumed segment
        var new_offsets = List[UInt64]()
        var new_segs = List[List[UInt8]]()
        for i in range(1, len(self.seg_offsets)):
            new_offsets.append(self.seg_offsets[i])
            new_segs.append(List[UInt8](copy=self.seg_data[i]))
        self.seg_offsets = new_offsets^
        self.seg_data = new_segs^

        # Check fin
        var fin_reached = False
        if fin_offset:
            if self.read_offset >= fin_offset.value():
                fin_reached = True

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
    """

    var data: List[UInt8]
    var offset: UInt64              # byte offset of data[0] in the stream
    var unsent_offset: UInt64       # first unsent byte (absolute)
    var acked_offset: UInt64        # contiguous ACKed bytes from stream start
    var fin: Bool
    var fin_offset: Optional[UInt64]    # set when FIN first framed
    var fin_acked: Bool

    def __init__(out self):
        self.data = List[UInt8]()
        self.offset = UInt64(0)
        self.unsent_offset = UInt64(0)
        self.acked_offset = UInt64(0)
        self.fin = False
        self.fin_offset = None
        self.fin_acked = False

    def __init__(out self, *, other: Self):
        self.data = List[UInt8](copy=other.data)
        self.offset = other.offset
        self.unsent_offset = other.unsent_offset
        self.acked_offset = other.acked_offset
        self.fin = other.fin
        self.fin_offset = Optional[UInt64](copy=other.fin_offset)
        self.fin_acked = other.fin_acked

    def __init__(out self, *, deinit take: Self):
        self.data = take.data^
        self.offset = take.offset
        self.unsent_offset = take.unsent_offset
        self.acked_offset = take.acked_offset
        self.fin = take.fin
        self.fin_offset = take.fin_offset^
        self.fin_acked = take.fin_acked

    def write(mut self, new_data: Span[UInt8, _], set_fin: Bool) raises:
        """Append data to the outgoing buffer and optionally set the FIN flag."""
        if self.fin and len(new_data) > 0:
            raise "STREAM_STATE_ERROR: write after FIN queued"
        self.data.extend(new_data)
        if set_fin:
            self.fin = True

    def has_pending(self) -> Bool:
        """True if there is unsent data or an unsent FIN."""
        var total_data_end = self.offset + UInt64(len(self.data))
        if self.unsent_offset < total_data_end:
            return True
        # FIN pending: fin is set but not yet framed (fin_offset not set)
        if self.fin and not self.fin_offset:
            return True
        return False

    def pending_len(self) -> UInt64:
        """Number of bytes not yet framed."""
        var total_data_end = self.offset + UInt64(len(self.data))
        if self.unsent_offset >= total_data_end:
            return UInt64(0)
        return total_data_end - self.unsent_offset

    def make_frame(mut self, stream_id: UInt64, max_bytes: Int) -> Optional[StreamFrame]:
        """Create a STREAM frame from unsent data up to max_bytes.

        Returns None if no data or FIN to send.
        """
        var total_data_end = self.offset + UInt64(len(self.data))

        # Calculate how many bytes to include
        var frame_start = self.unsent_offset
        var available = Int(0)
        if total_data_end > frame_start:
            available = Int(total_data_end - frame_start)
        var chunk_size = available
        if chunk_size > max_bytes:
            chunk_size = max_bytes

        var include_fin = False
        if self.fin and not self.fin_offset:
            # Include FIN only if we've reached the end of the data
            if frame_start + UInt64(chunk_size) >= total_data_end:
                include_fin = True

        if chunk_size == 0 and not include_fin:
            return None

        # Build frame data
        var frame_data = List[UInt8](capacity=chunk_size)
        var buf_start = Int(frame_start - self.offset)
        frame_data.extend(Span(self.data)[buf_start:buf_start + chunk_size])

        # Record fin_offset when FIN is first included
        if include_fin and not self.fin_offset:
            self.fin_offset = frame_start + UInt64(chunk_size)

        self.unsent_offset = frame_start + UInt64(chunk_size)

        var frame = StreamFrame(stream_id, frame_start, frame_data^, include_fin)
        return frame^

    def on_ack(mut self, ack_off: UInt64, ack_len: UInt64):
        """Handle acknowledgment of [ack_off, ack_off+ack_len) bytes.

        If the ack range extends the contiguous acked_offset, trims buffer front.
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

        # Only process if this extends the contiguous acked region
        if ack_off <= self.acked_offset and ack_end > self.acked_offset:
            self.acked_offset = ack_end

            # Trim buffer front: remove bytes [offset, acked_offset)
            var trim = Int(self.acked_offset - self.offset)
            if trim > len(self.data):
                trim = len(self.data)
            if trim > 0:
                var new_data = List[UInt8](capacity=len(self.data) - trim)
                new_data.extend(Span(self.data)[trim:])
                self.data = new_data^
                self.offset = self.offset + UInt64(trim)

        # Check fin_acked
        if self.fin_offset:
            if self.acked_offset >= self.fin_offset.value():
                self.fin_acked = True

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
    var send_state: Optional[UInt8]
    var recv_state: Optional[UInt8]
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

    def __init__(out self, *, other: Self):
        self.id = other.id
        self.is_bidi = other.is_bidi
        self.is_local = other.is_local
        self.send_state = Optional[UInt8](copy=other.send_state)
        self.recv_state = Optional[UInt8](copy=other.recv_state)
        self.send_buf = Optional[SendBuf](copy=other.send_buf)
        self.recv_buf = Optional[RecvBuf](copy=other.recv_buf)
        self.fc_send = Optional[FlowControl](copy=other.fc_send)
        self.fc_recv = Optional[FlowControl](copy=other.fc_recv)
        self.fin_offset = Optional[UInt64](copy=other.fin_offset)
        self.recv_highest_offset = other.recv_highest_offset
        self.send_fin_offset = Optional[UInt64](copy=other.send_fin_offset)
        self.reset_error = Optional[UInt64](copy=other.reset_error)
        self.stop_error = Optional[UInt64](copy=other.stop_error)
        self.needs_max_stream_data = other.needs_max_stream_data
        self.needs_reset_stream = other.needs_reset_stream
        self.needs_stop_sending = other.needs_stop_sending
        self.reset_stream_final_size = other.reset_stream_final_size
        self.reset_stream_error = other.reset_stream_error
        self.stop_sending_error = other.stop_sending_error
        self.urgency = other.urgency
        self.incremental = other.incremental

    def __init__(out self, *, deinit take: Self):
        self.id = take.id
        self.is_bidi = take.is_bidi
        self.is_local = take.is_local
        self.send_state = take.send_state^
        self.recv_state = take.recv_state^
        self.send_buf = take.send_buf^
        self.recv_buf = take.recv_buf^
        self.fc_send = take.fc_send^
        self.fc_recv = take.fc_recv^
        self.fin_offset = take.fin_offset^
        self.recv_highest_offset = take.recv_highest_offset
        self.send_fin_offset = take.send_fin_offset^
        self.reset_error = take.reset_error^
        self.stop_error = take.stop_error^
        self.needs_max_stream_data = take.needs_max_stream_data
        self.needs_reset_stream = take.needs_reset_stream
        self.needs_stop_sending = take.needs_stop_sending
        self.reset_stream_final_size = take.reset_stream_final_size
        self.reset_stream_error = take.reset_stream_error
        self.stop_sending_error = take.stop_sending_error
        self.urgency = take.urgency
        self.incremental = take.incremental

    # ── Factory methods ───────────────────────────────────────────────────────

    @staticmethod
    def new_local_bidi(
        id: UInt64,
        fc_send_limit: UInt64,
        fc_recv_limit: UInt64,
        fc_recv_window: UInt64,
    ) -> Stream:
        """Create a local bidirectional stream (both send and recv sides)."""
        var s = Stream(id, True, True)
        s.send_state = SEND_READY
        s.recv_state = RECV_RECV
        s.send_buf = SendBuf()
        s.recv_buf = RecvBuf(fc_recv_window)
        s.fc_send = FlowControl(fc_send_limit, fc_send_limit)
        s.fc_recv = FlowControl(fc_recv_limit, fc_recv_window, STREAM_FC_MAX_WINDOW)
        return s^

    @staticmethod
    def new_remote_bidi(
        id: UInt64,
        fc_send_limit: UInt64,
        fc_recv_limit: UInt64,
        fc_recv_window: UInt64,
    ) -> Stream:
        """Create a remote bidirectional stream (both send and recv sides)."""
        var s = Stream(id, True, False)
        s.send_state = SEND_READY
        s.recv_state = RECV_RECV
        s.send_buf = SendBuf()
        s.recv_buf = RecvBuf(fc_recv_window)
        s.fc_send = FlowControl(fc_send_limit, fc_send_limit)
        s.fc_recv = FlowControl(fc_recv_limit, fc_recv_window, STREAM_FC_MAX_WINDOW)
        return s^

    @staticmethod
    def new_local_uni(id: UInt64, fc_send_limit: UInt64) -> Stream:
        """Create a local unidirectional stream (send-side only)."""
        var s = Stream(id, False, True)
        s.send_state = SEND_READY
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
        s.recv_state = RECV_RECV
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
