# src/quic/crypto_stream.mojo
# Ordered byte reassembly for QUIC CRYPTO frames (RFC 9000 Section 19.6).
# Buffers (offset, data) fragments and produces contiguous byte ranges
# for feeding to the TLS state machine.

from navette.quic.frame import CryptoFrame


struct CryptoFragment(Copyable, Movable):
    var offset: UInt64
    var data: List[UInt8]

    def __init__(out self, offset: UInt64, data: List[UInt8]):
        self.offset = offset
        self.data = List[UInt8](copy=data)

    def __init__(out self, *, other: Self):
        self.offset = other.offset
        self.data = List[UInt8](copy=other.data)

    def __init__(out self, *, deinit take: Self):
        self.offset = take.offset
        self.data = take.data^


struct CryptoStream(Copyable, Movable):
    var recv_offset: UInt64
    var recv_buf: List[UInt8]
    var pending_fragments: List[CryptoFragment]
    var send_offset: UInt64
    var send_buf: List[UInt8]

    def __init__(out self):
        self.recv_offset = UInt64(0)
        self.recv_buf = List[UInt8]()
        self.pending_fragments = List[CryptoFragment]()
        self.send_offset = UInt64(0)
        self.send_buf = List[UInt8]()

    def __init__(out self, *, other: Self):
        self.recv_offset = other.recv_offset
        self.recv_buf = List[UInt8](copy=other.recv_buf)
        self.pending_fragments = List[CryptoFragment](copy=other.pending_fragments)
        self.send_offset = other.send_offset
        self.send_buf = List[UInt8](copy=other.send_buf)

    def __init__(out self, *, deinit take: Self):
        self.recv_offset = take.recv_offset
        self.recv_buf = take.recv_buf^
        self.pending_fragments = take.pending_fragments^
        self.send_offset = take.send_offset
        self.send_buf = take.send_buf^

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
        var frag_data = List[UInt8](capacity=len(data))
        for i in range(len(data)):
            frag_data.append(data[i])
        self.pending_fragments.append(CryptoFragment(offset, frag_data^))
        self._merge_pending()

    def _merge_pending(mut self):
        """Merge pending fragments that are now contiguous with recv_buf."""
        while len(self.pending_fragments) > 0:
            var merged = False
            for i in range(len(self.pending_fragments)):
                var buf_end = self.recv_offset + UInt64(len(self.recv_buf))
                if self.pending_fragments[i].offset <= buf_end:
                    var frag_end = self.pending_fragments[i].offset + UInt64(
                        len(self.pending_fragments[i].data)
                    )
                    if frag_end > buf_end:
                        var skip = Int(buf_end - self.pending_fragments[i].offset)
                        for j in range(skip, len(self.pending_fragments[i].data)):
                            self.recv_buf.append(self.pending_fragments[i].data[j])
                    # Remove this fragment: rebuild list without index i.
                    var new_frags = List[CryptoFragment]()
                    for k in range(len(self.pending_fragments)):
                        if k != i:
                            new_frags.append(CryptoFragment(other=self.pending_fragments[k]))
                    self.pending_fragments = new_frags^
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

    def requeue(mut self, offset: UInt64, data: Span[UInt8, _]):
        """Re-queue CRYPTO data for retransmission at its original offset.

        If send_buf is empty, sets send_offset to the given offset and
        places data in send_buf.  If send_buf already has data (from a
        prior requeue call), appends contiguous data or replaces if the
        new range starts before the current send_offset.
        """
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
        """Fragment send_buf into CryptoFrame list, each at most max_frame_size bytes."""
        var frames = List[CryptoFrame]()
        var pos = 0
        var offset = self.send_offset
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
        """Advance send_offset after frames are acknowledged/sent."""
        var advance = Int(bytes)
        if advance > len(self.send_buf):
            advance = len(self.send_buf)
        # Remove consumed bytes from front of send_buf.
        var new_buf = List[UInt8](capacity=len(self.send_buf) - advance)
        for i in range(advance, len(self.send_buf)):
            new_buf.append(self.send_buf[i])
        self.send_buf = new_buf^
        self.send_offset += UInt64(advance)
