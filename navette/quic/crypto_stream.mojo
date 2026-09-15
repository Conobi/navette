# src/quic/crypto_stream.mojo
# Ordered byte reassembly for QUIC CRYPTO frames (RFC 9000 Section 19.6).
# Buffers (offset, data) fragments and produces contiguous byte ranges
# for feeding to the TLS state machine.

from navette.quic.frame import CryptoFrame

# Cap on concurrently-buffered out-of-order CRYPTO fragments. TLS handshake
# flights arrive in a handful of packets; 8 pending fragments is generous
# headroom while keeping CryptoStream's storage fixed-capacity (no heap
# allocation for the reassembly bookkeeping itself).
comptime MAX_PENDING_FRAGMENTS: Int = 8


struct CryptoFragment(Copyable, Movable):
    var offset: UInt64
    var data: List[UInt8]

    def __init__(out self, offset: UInt64, data: List[UInt8]):
        self.offset = offset
        self.data = List[UInt8](copy=data)

    def __init__(out self, *, copy: Self):
        self.offset = copy.offset
        self.data = List[UInt8](copy=copy.data)

    def __init__(out self, *, deinit move: Self):
        self.offset = move.offset
        self.data = move.data^


struct CryptoStream(Copyable, Movable):
    """Reassembles inbound CRYPTO data and stages outbound CRYPTO data.

    Send side: `send_buf[0]` sits at stream offset `send_offset`; bytes below
    `sent_cursor` have been emitted by `next_crypto_frame` and are kept only
    until the cursor reaches the end (or a `requeue`), when the buffer is
    compacted. This keeps a multi-packet flight linear instead of rebuilding
    the buffer per frame.
    """
    var recv_offset: UInt64
    var recv_buf: List[UInt8]
    # Out-of-order fragments awaiting a contiguous predecessor, fixed
    # capacity; `pending_fragments_len` tracks the valid prefix.
    var pending_fragments: InlineArray[CryptoFragment, MAX_PENDING_FRAGMENTS]
    var pending_fragments_len: Int
    var send_offset: UInt64
    var send_buf: List[UInt8]
    var sent_cursor: Int

    def __init__(out self):
        self.recv_offset = UInt64(0)
        self.recv_buf = List[UInt8]()
        self.pending_fragments = InlineArray[CryptoFragment, MAX_PENDING_FRAGMENTS](
            fill=CryptoFragment(UInt64(0), List[UInt8]())
        )
        self.pending_fragments_len = 0
        self.send_offset = UInt64(0)
        self.send_buf = List[UInt8]()
        self.sent_cursor = 0

    def __init__(out self, *, copy: Self):
        self.recv_offset = copy.recv_offset
        self.recv_buf = List[UInt8](copy=copy.recv_buf)
        self.pending_fragments = InlineArray[CryptoFragment, MAX_PENDING_FRAGMENTS](
            copy=copy.pending_fragments
        )
        self.pending_fragments_len = copy.pending_fragments_len
        self.send_offset = copy.send_offset
        self.send_buf = List[UInt8](copy=copy.send_buf)
        self.sent_cursor = copy.sent_cursor

    def __init__(out self, *, deinit move: Self):
        self.recv_offset = move.recv_offset
        self.recv_buf = move.recv_buf^
        self.pending_fragments = move.pending_fragments^
        self.pending_fragments_len = move.pending_fragments_len
        self.send_offset = move.send_offset
        self.send_buf = move.send_buf^
        self.sent_cursor = move.sent_cursor

    def receive(mut self, offset: UInt64, data: Span[UInt8, _]) raises:
        """Reassemble incoming CRYPTO frame data at the given offset."""
        var data_len = UInt64(len(data))
        if data_len == 0:
            return

        var buf_end = self.recv_offset + UInt64(len(self.recv_buf))

        # CVE-2024-1765 mitigation: reject offsets too far ahead.
        # Use recv_offset (not buf_end) so the window doesn't grow with buffered data.
        if offset > self.recv_offset + 16384:
            raise "CRYPTO offset exceeds window"

        # Duplicate: entire range already covered.
        if offset + data_len <= buf_end:
            return

        # Contiguous or overlapping with recv_buf.
        if offset <= buf_end:
            var skip = Int(buf_end - offset)
            for j in range(skip, len(data)):
                self.recv_buf.append(data[j])
            # After extending recv_buf, try to merge pending fragments.
            self._merge_pending()
            return

        # Out-of-order: store as pending fragment.
        if self.pending_fragments_len >= MAX_PENDING_FRAGMENTS:
            raise "CRYPTO pending fragment buffer full"
        var frag_data = List[UInt8](capacity=len(data))
        for i in range(len(data)):
            frag_data.append(data[i])
        self.pending_fragments[self.pending_fragments_len] = CryptoFragment(offset, frag_data^)
        self.pending_fragments_len += 1
        self._merge_pending()

    def _merge_pending(mut self):
        """Merge pending fragments that are now contiguous with recv_buf."""
        while self.pending_fragments_len > 0:
            var merged = False
            for i in range(self.pending_fragments_len):
                var buf_end = self.recv_offset + UInt64(len(self.recv_buf))
                if self.pending_fragments[i].offset <= buf_end:
                    var frag_end = self.pending_fragments[i].offset + UInt64(
                        len(self.pending_fragments[i].data)
                    )
                    if frag_end > buf_end:
                        var skip = Int(buf_end - self.pending_fragments[i].offset)
                        for j in range(skip, len(self.pending_fragments[i].data)):
                            self.recv_buf.append(self.pending_fragments[i].data[j])
                    # Remove this fragment in place: shift subsequent entries left, shrink length.
                    for k in range(i, self.pending_fragments_len - 1):
                        self.pending_fragments[k] = CryptoFragment(copy=self.pending_fragments[k + 1])
                    self.pending_fragments_len -= 1
                    merged = True
                    break
            if not merged:
                break

    def drain(mut self) -> List[UInt8]:
        """Return and consume contiguous bytes from recv_buf."""
        var result = self.recv_buf^
        self.recv_buf = List[UInt8]()
        self.recv_offset += UInt64(len(result))
        return result^

    def has_pending(self) -> Bool:
        """True if there are contiguous bytes ready to drain."""
        return len(self.recv_buf) > 0

    def write(mut self, data: Span[UInt8, _]):
        """Append data to the outgoing send buffer for CRYPTO frames."""
        for i in range(len(data)):
            self.send_buf.append(data[i])

    def _compact_sent(mut self):
        """Drop the already-emitted prefix so `send_buf[0]` is the first unsent byte."""
        if self.sent_cursor == 0:
            return
        var remaining = len(self.send_buf) - self.sent_cursor
        var new_buf = List[UInt8](capacity=remaining)
        for i in range(self.sent_cursor, len(self.send_buf)):
            new_buf.append(self.send_buf[i])
        self.send_buf = new_buf^
        self.send_offset += UInt64(self.sent_cursor)
        self.sent_cursor = 0

    def has_unsent(self) -> Bool:
        """Send side: bytes staged but not yet emitted (distinct from the
        receive-side `has_pending`)."""
        return self.sent_cursor < len(self.send_buf)

    def next_crypto_frame(mut self, max_data: Int) -> Optional[CryptoFrame]:
        """Emit one CRYPTO frame of at most `max_data` bytes and advance the cursor.

        The buffer is not rebuilt per call; it is compacted once the cursor
        reaches its end. Returns None when nothing is unsent or `max_data <= 0`.
        """
        if not self.has_unsent() or max_data <= 0:
            return None
        var avail = len(self.send_buf) - self.sent_cursor
        var chunk_size = avail if avail < max_data else max_data
        var chunk = List[UInt8](capacity=chunk_size)
        for i in range(chunk_size):
            chunk.append(self.send_buf[self.sent_cursor + i])
        var frame = CryptoFrame(self.send_offset + UInt64(self.sent_cursor), chunk^)
        self.sent_cursor += chunk_size
        if self.sent_cursor == len(self.send_buf):
            self.send_offset += UInt64(self.sent_cursor)
            self.send_buf = List[UInt8]()
            self.sent_cursor = 0
        return frame^

    def requeue(mut self, offset: UInt64, data: Span[UInt8, _]):
        """Re-queue CRYPTO data for retransmission at its original offset.

        Compacts the emitted prefix first. If send_buf is then empty, sets
        send_offset to the given offset and places data in send_buf; otherwise
        appends contiguous data, or replaces the buffer when the new range
        starts before the current send_offset.
        """
        self._compact_sent()
        if len(self.send_buf) == 0:
            self.send_offset = offset
            self.send_buf = List[UInt8](capacity=len(data))
            for i in range(len(data)):
                self.send_buf.append(data[i])
            return

        # Already have data queued.  If new offset is before current
        # send_offset, reset; otherwise extend if contiguous.
        var current_end = self.send_offset + UInt64(len(self.send_buf))
        if offset < self.send_offset:
            # New data starts earlier -- replace entirely.
            self.send_offset = offset
            self.send_buf = List[UInt8](capacity=len(data))
            for i in range(len(data)):
                self.send_buf.append(data[i])
        elif offset <= current_end:
            # Contiguous or overlapping: append only the new portion.
            var skip = Int(current_end - offset)
            for i in range(skip, len(data)):
                self.send_buf.append(data[i])

    def pending_crypto_frames(self, max_frame_size: Int) -> List[CryptoFrame]:
        """Fragment the unsent part of send_buf into frames of at most
        max_frame_size bytes, without advancing anything."""
        var frames = List[CryptoFrame]()
        var pos = self.sent_cursor
        var offset = self.send_offset + UInt64(self.sent_cursor)
        while pos < len(self.send_buf):
            var chunk_size = len(self.send_buf) - pos
            if chunk_size > max_frame_size:
                chunk_size = max_frame_size
            var chunk = List[UInt8](capacity=chunk_size)
            for i in range(chunk_size):
                chunk.append(self.send_buf[pos + i])
            frames.append(CryptoFrame(offset, chunk^))
            offset += UInt64(chunk_size)
            pos += chunk_size
        return frames^

    def advance_send(mut self, bytes: UInt64):
        """Drop `bytes` from the front of the unsent data (rebuilds the buffer)."""
        self._compact_sent()
        var advance = Int(bytes)
        if advance > len(self.send_buf):
            advance = len(self.send_buf)
        var new_buf = List[UInt8](capacity=len(self.send_buf) - advance)
        for i in range(advance, len(self.send_buf)):
            new_buf.append(self.send_buf[i])
        self.send_buf = new_buf^
        self.send_offset += UInt64(advance)
