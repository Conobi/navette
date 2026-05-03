# src/h3/connection.mojo
#
# H3Connection — sans-I/O HTTP/3 state machine wrapping a QuicConnection.
# H3Event — flat-tag event struct emitted to callers.
# _H3StreamBuf — per-stream byte accumulator.

from std.collections import Dict, Optional
from std.collections.deque import Deque
from std.memory import Span, UnsafePointer

from src.quic.connection import QuicConnection, QuicEvent
from src.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode
from src.quic.profile import AcceptProfile, monotonic_us, PROFILE_ACCEPT
from src.h3.frame import (
    H3RawFrame,
    DataFrame,
    HeadersFrame,
    SettingsFrame,
    SettingsPair,
    H3_FRAME_DATA,
    H3_FRAME_HEADERS,
    H3_FRAME_SETTINGS,
    H3_FRAME_GOAWAY,
    SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    SETTINGS_MAX_FIELD_SECTION_SIZE,
    parse_h3_frame,
)
from src.h3.error import (
    H3_MISSING_SETTINGS,
    H3_GENERAL_PROTOCOL_ERROR,
    H3_FRAME_UNEXPECTED,
    H3_STREAM_CREATION_ERROR,
)
from src.h3.qpack import QpackEncoder, QpackDecoder, QpackHeaderField, HuffDecodeTable, QpackSharedTables
from src.http.headers import Headers


# ---------------------------------------------------------------------------
# H3Event — flat-tag event emitted by H3Connection
# ---------------------------------------------------------------------------


struct H3Event(Copyable, Movable):
    """Event emitted by H3Connection for the application layer."""

    comptime HANDSHAKE_COMPLETE: UInt8 = 1
    comptime SETTINGS_RECEIVED:  UInt8 = 2
    comptime HEADERS_RECEIVED:   UInt8 = 3
    comptime DATA_RECEIVED:      UInt8 = 4
    comptime STREAM_ENDED:       UInt8 = 5
    comptime STREAM_RESET:       UInt8 = 6
    comptime GOAWAY_RECEIVED:    UInt8 = 7
    comptime CONNECTION_CLOSED:  UInt8 = 8

    var kind:          UInt8
    var stream_id:     UInt64
    var fields:        List[QpackHeaderField]
    var data:          List[UInt8]
    var fin:           Bool
    var error_code:    UInt64
    var reason:        String
    var last_stream_id: UInt64

    def __init__(out self, kind: UInt8):
        self.kind = kind
        self.stream_id = UInt64(0)
        self.fields = List[QpackHeaderField]()
        self.data = List[UInt8]()
        self.fin = False
        self.error_code = UInt64(0)
        self.reason = String("")
        self.last_stream_id = UInt64(0)

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.stream_id = other.stream_id
        self.fields = List[QpackHeaderField](copy=other.fields)
        self.data = List[UInt8](copy=other.data)
        self.fin = other.fin
        self.error_code = other.error_code
        self.reason = other.reason
        self.last_stream_id = other.last_stream_id

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.stream_id = take.stream_id
        self.fields = take.fields^
        self.data = take.data^
        self.fin = take.fin
        self.error_code = take.error_code
        self.reason = take.reason^
        self.last_stream_id = take.last_stream_id

    def consume_data(deinit self) -> List[UInt8]:
        return self.data^

    def consume_fields(deinit self) -> List[QpackHeaderField]:
        return self.fields^


# ---------------------------------------------------------------------------
# _H3StreamBuf — per-stream byte accumulator (Copyable for Dict storage)
# ---------------------------------------------------------------------------


struct _H3StreamBuf(Copyable, Movable):
    var buf:       List[UInt8]
    var type_byte: Optional[UInt8]
    var is_uni:    Bool

    def __init__(out self):
        self.buf = List[UInt8]()
        self.type_byte = Optional[UInt8]()
        self.is_uni = False

    def __init__(out self, *, other: Self):
        self.buf = List[UInt8](copy=other.buf)
        self.type_byte = other.type_byte.copy()
        self.is_uni = other.is_uni

    def __init__(out self, *, deinit take: Self):
        self.buf = take.buf^
        self.type_byte = take.type_byte^
        self.is_uni = take.is_uni


# ---------------------------------------------------------------------------
# H3Connection — state machine
# ---------------------------------------------------------------------------


struct H3Connection(Movable):
    var _quic:                       QuicConnection
    var _is_server:                  Bool
    var _stream_bufs:                Dict[Int, _H3StreamBuf]
    var _h3_events:                  Deque[H3Event]
    var _local_ctrl_sid:             Optional[UInt64]
    var _local_qenc_sid:             Optional[UInt64]
    var _local_qdec_sid:             Optional[UInt64]
    var _init_done:                  Bool
    var _peer_ctrl_sid:              Optional[UInt64]
    var _peer_qenc_sid:              Optional[UInt64]
    var _peer_qdec_sid:              Optional[UInt64]
    var _peer_ctrl_first_frame_seen: Bool
    var _peer_ctrl_settings:         Bool
    var _goaway_sent:                Optional[UInt64]
    var _peer_goaway_sid:            Optional[UInt64]
    var _enc:                        QpackEncoder
    var _dec:                        QpackDecoder
    var profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]

    def __init__(
        out self,
        var quic: QuicConnection,
        is_server: Bool,
        shared_qpack_tables: UnsafePointer[QpackSharedTables, MutAnyOrigin] = UnsafePointer[QpackSharedTables, MutAnyOrigin](),
    ):
        self._quic = quic^
        self._is_server = is_server
        self._stream_bufs = Dict[Int, _H3StreamBuf]()
        self._h3_events = Deque[H3Event]()
        self._local_ctrl_sid = Optional[UInt64]()
        self._local_qenc_sid = Optional[UInt64]()
        self._local_qdec_sid = Optional[UInt64]()
        self._init_done = False
        self._peer_ctrl_sid = Optional[UInt64]()
        self._peer_qenc_sid = Optional[UInt64]()
        self._peer_qdec_sid = Optional[UInt64]()
        self._peer_ctrl_first_frame_seen = False
        self._peer_ctrl_settings = False
        self._goaway_sent = Optional[UInt64]()
        self._peer_goaway_sid = Optional[UInt64]()
        if Int(shared_qpack_tables) != 0:
            self._enc = QpackEncoder(False, shared=shared_qpack_tables)
            self._dec = QpackDecoder(shared=shared_qpack_tables)
        else:
            self._enc = QpackEncoder(False)
            self._dec = QpackDecoder()
        self.profile_ptr = UnsafePointer[AcceptProfile, MutAnyOrigin]()

    def __init__(out self, *, deinit take: Self):
        self._quic = take._quic^
        self._is_server = take._is_server
        self._stream_bufs = take._stream_bufs^
        self._h3_events = take._h3_events^
        self._local_ctrl_sid = take._local_ctrl_sid^
        self._local_qenc_sid = take._local_qenc_sid^
        self._local_qdec_sid = take._local_qdec_sid^
        self._init_done = take._init_done
        self._peer_ctrl_sid = take._peer_ctrl_sid^
        self._peer_qenc_sid = take._peer_qenc_sid^
        self._peer_qdec_sid = take._peer_qdec_sid^
        self._peer_ctrl_first_frame_seen = take._peer_ctrl_first_frame_seen
        self._peer_ctrl_settings = take._peer_ctrl_settings
        self._goaway_sent = take._goaway_sent^
        self._peer_goaway_sid = take._peer_goaway_sid^
        self._enc = take._enc^
        self._dec = take._dec^
        self.profile_ptr = take.profile_ptr

    @staticmethod
    def server(
        var quic: QuicConnection,
        shared_qpack_tables: UnsafePointer[QpackSharedTables, MutAnyOrigin] = UnsafePointer[QpackSharedTables, MutAnyOrigin](),
    ) raises -> H3Connection:
        """Wrap a server-side QuicConnection. If `shared_qpack_tables` is
        non-null, the QPACK encoder + decoder skip their per-instance
        builds (HuffDecodeTable, Huffman encode, static table) and
        use the externally-allocated tables. Meaningful at connection-
        creation rates (short-conn) where these builds dominate."""
        return H3Connection(quic^, True, shared_qpack_tables)

    @staticmethod
    def client(
        var quic: QuicConnection,
        shared_qpack_tables: UnsafePointer[QpackSharedTables, MutAnyOrigin] = UnsafePointer[QpackSharedTables, MutAnyOrigin](),
    ) raises -> H3Connection:
        """Wrap a client-side QuicConnection. See `server` for shared_qpack_tables."""
        return H3Connection(quic^, False, shared_qpack_tables)

    def is_established(self) -> Bool:
        return self._quic.is_established()

    def is_closed(self) -> Bool:
        return self._quic.is_closed()

    def _is_peer_initiated(self, stream_id: UInt64) -> Bool:
        if self._is_server:
            return (stream_id & UInt64(1)) == 0
        else:
            return (stream_id & UInt64(1)) == 1

    def _is_request_stream(self, stream_id: UInt64) -> Bool:
        return (stream_id & UInt64(0x02)) == 0

    def poll_event(mut self) raises -> Optional[H3Event]:
        """Return the next pending H3Event in FIFO order. O(1) via Deque
        popleft — was O(N) per call (N² to drain) when backed by List."""
        if len(self._h3_events) == 0:
            return Optional[H3Event]()
        var ev = self._h3_events.popleft()
        return Optional[H3Event](ev^)

    # --- Transport API -------------------------------------------------------

    def feed_datagram(mut self, data: Span[UInt8, _], now: UInt64) raises:
        """Feed one inbound QUIC datagram; translate QuicEvents to H3Events."""
        self._quic.recv(data, now)
        while True:
            var ev_opt = self._quic.poll()
            if not ev_opt:
                break
            var ev = ev_opt.unsafe_take()
            if ev.type_id == QuicEvent.HANDSHAKE_COMPLETE:
                if not self._init_done:
                    self._init_done = True
                    self._bootstrap_local_streams(now)
                var h3ev = H3Event(H3Event.HANDSHAKE_COMPLETE)
                self._h3_events.append(h3ev^)
            elif ev.type_id == QuicEvent.STREAM_OPENED:
                if self._is_peer_initiated(ev.stream_id):
                    var sbuf = _H3StreamBuf()
                    sbuf.is_uni = (ev.stream_id & UInt64(0x02)) != 0
                    self._stream_bufs[Int(ev.stream_id)] = sbuf^
            elif ev.type_id == QuicEvent.STREAM_READABLE:
                try:
                    self._drain_stream(ev.stream_id, now)
                except:
                    pass
            elif ev.type_id == QuicEvent.STREAM_RESET:
                if self._is_request_stream(ev.stream_id):
                    var h3ev = H3Event(H3Event.STREAM_RESET)
                    h3ev.stream_id = ev.stream_id
                    h3ev.error_code = ev.error_code
                    self._h3_events.append(h3ev^)
            elif ev.type_id == QuicEvent.CONNECTION_CLOSED:
                var h3ev = H3Event(H3Event.CONNECTION_CLOSED)
                h3ev.error_code = ev.error_code
                h3ev.reason = ev.reason
                self._h3_events.append(h3ev^)

    def feed_datagram_from_buffer(
        mut self,
        buf: UnsafePointer[UInt8, MutAnyOrigin],
        buf_len: Int,
        now: UInt64,
    ) raises:
        """Feed one inbound QUIC datagram from a mutable buffer pointer.
        Zero-copy variant — buffer is modified in-place."""
        self._quic.recv_from_buffer(buf, buf_len, now)

        # Bracket the post-recv tail (timeout + poll-loop including _drain_stream).
        # record_pkt at connection.mojo:890 fires INSIDE recv_from_buffer's
        # coalesced-packet for-loop and is bounded by it; this bracket covers
        # the disjoint H3-application-event-drain phase. Single-pair clock-read
        # with hoisted t_start (sub-leg pass T4 lesson — Mojo lexical scope).
        var t_start: UInt64 = 0
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                t_start = monotonic_us()

        while True:
            var ev_opt = self._quic.poll()
            if not ev_opt:
                break
            var ev = ev_opt.unsafe_take()
            if ev.type_id == QuicEvent.HANDSHAKE_COMPLETE:
                if not self._init_done:
                    self._init_done = True
                    self._bootstrap_local_streams(now)
                var h3ev = H3Event(H3Event.HANDSHAKE_COMPLETE)
                self._h3_events.append(h3ev^)
            elif ev.type_id == QuicEvent.STREAM_OPENED:
                if self._is_peer_initiated(ev.stream_id):
                    var sbuf = _H3StreamBuf()
                    sbuf.is_uni = (ev.stream_id & UInt64(0x02)) != 0
                    self._stream_bufs[Int(ev.stream_id)] = sbuf^
            elif ev.type_id == QuicEvent.STREAM_READABLE:
                try:
                    self._drain_stream(ev.stream_id, now)
                except:
                    pass
            elif ev.type_id == QuicEvent.STREAM_RESET:
                if self._is_request_stream(ev.stream_id):
                    var h3ev = H3Event(H3Event.STREAM_RESET)
                    h3ev.stream_id = ev.stream_id
                    h3ev.error_code = ev.error_code
                    self._h3_events.append(h3ev^)
            elif ev.type_id == QuicEvent.CONNECTION_CLOSED:
                var h3ev = H3Event(H3Event.CONNECTION_CLOSED)
                h3ev.error_code = ev.error_code
                h3ev.reason = ev.reason
                self._h3_events.append(h3ev^)

        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                self.profile_ptr[].record_quic_post_recv(monotonic_us() - t_start)

    def drain_datagrams(mut self, now: UInt64) raises -> List[List[UInt8]]:
        """Drain outbound QUIC datagrams. Returns list of UDP payloads."""
        return self._quic.send(now)

    # --- Send API ------------------------------------------------------------

    def send_headers(
        mut self, stream_id: UInt64, fields: List[QpackHeaderField], fin: Bool
    ) raises:
        """QPACK-encode fields → H3 wire frame → send_stream_data.

        Builds the wire bytes directly via ByteWriter, bypassing the
        HeadersFrame intermediate (saves 2 List[UInt8] copies per call:
        HeadersFrame.__init__ and H3RawFrame.__init__).
        """
        var encoded = self._enc.encode(fields)
        var w = ByteWriter()
        varint_encode(w, H3_FRAME_HEADERS)
        varint_encode(w, UInt64(len(encoded)))
        w.write_bytes(Span(encoded))
        var wire = w.finish()
        self._quic.send_stream_data(stream_id, Span(wire), fin)

    def send_trailers(
        mut self,
        stream_id: UInt64,
        trailers: Headers,
        fin: Bool,
    ) raises:
        """Encode trailing headers directly into a HEADERS frame without
        building a List[QpackHeaderField] intermediate. No :status — RFC
        9114 §4.1 forbids pseudo-headers in trailers.

        Two-span send: prefix + encoded into SendBuf with no wire-buffer
        intermediate copy. Same sourcing as send_response_headers."""
        var encoded = List[UInt8]()
        encoded.append(0x00)
        encoded.append(0x00)
        for j in range(len(trailers)):
            self._enc._encode_field_into(trailers.name_at(j), trailers.value_at(j), encoded)
        var pw = ByteWriter()
        varint_encode(pw, H3_FRAME_HEADERS)
        varint_encode(pw, UInt64(len(encoded)))
        var prefix = pw.finish()
        self._quic.send_stream_data_2(stream_id, Span(prefix), Span(encoded), fin)

    def send_response_headers(
        mut self,
        stream_id: UInt64,
        status_code: Int,
        headers: Headers,
        fin: Bool,
    ) raises:
        """Encode :status + headers directly into a HEADERS frame without
        building a List[QpackHeaderField] intermediate. Per response this
        saves ~2 String auto-copies per header (the var-binding copies
        that QpackHeaderField construction triggers when fed name_at/value_at
        refs). Borrowed-name encode path inside QpackEncoder._encode_field
        already takes name + value by-borrow.

        Sends `prefix + encoded` as two spans into SendBuf via
        send_stream_data_2 — drops the wire-buffer intermediate that
        previously double-copied the encoded headers."""
        var encoded = List[UInt8]()
        encoded.append(0x00)  # Required Insert Count = 0
        encoded.append(0x00)  # S = 0, Delta Base = 0
        # :status pseudo-field first (RFC 9114 §4.3.1).
        var status_str = String(status_code)
        self._enc._encode_field_into(":status", status_str, encoded)
        # User headers — name_at/value_at return refs, no per-field copy.
        for j in range(len(headers)):
            self._enc._encode_field_into(headers.name_at(j), headers.value_at(j), encoded)
        # Build the H3 frame prefix into a tiny ByteWriter (varint type +
        # varint length, ≤8 bytes total). Avoids re-extending `encoded`.
        var pw = ByteWriter()
        varint_encode(pw, H3_FRAME_HEADERS)
        varint_encode(pw, UInt64(len(encoded)))
        var prefix = pw.finish()
        self._quic.send_stream_data_2(stream_id, Span(prefix), Span(encoded), fin)

    def send_data(
        mut self, stream_id: UInt64, data: List[UInt8], fin: Bool
    ) raises:
        """Build H3 DATA wire frame → send_stream_data. Empty data + fin=True sends FIN only.

        Two-span variant of the wire build: hand the (frame prefix, body)
        pair to send_stream_data_2 instead of building a wire-buffer
        intermediate. Saves one full body memcpy per send — sourced by
        h3_phases_us.drain_resp = 18.8% of run wall-clock.
        """
        if len(data) == 0 and fin:
            var empty = List[UInt8]()
            self._quic.send_stream_data(stream_id, Span(empty), True)
            return
        if len(data) == 0:
            return
        var pw = ByteWriter()
        varint_encode(pw, H3_FRAME_DATA)
        varint_encode(pw, UInt64(len(data)))
        var prefix = pw.finish()
        self._quic.send_stream_data_2(stream_id, Span(prefix), Span(data), fin)

    def send_goaway(mut self, last_stream_id: UInt64) raises:
        """Write GOAWAY frame to local control stream."""
        if not self._init_done:
            raise "H3: not established"
        if not self._local_ctrl_sid:
            raise "H3: no local control stream"
        var w = ByteWriter()
        varint_encode(w, last_stream_id)
        var payload = w.finish()
        var raw = H3RawFrame(H3_FRAME_GOAWAY, payload^)
        var wire = raw.encode()
        self._quic.send_stream_data(self._local_ctrl_sid.value(), Span(wire), False)
        self._goaway_sent = Optional[UInt64](last_stream_id)

    def reset_stream(mut self, stream_id: UInt64, error_code: UInt64) raises:
        """Send RESET_STREAM via QUIC."""
        self._quic.reset_stream(stream_id, error_code)

    def open_bidi_stream(mut self) raises -> UInt64:
        """Open a client-initiated bidi stream."""
        var sid = self._quic.open_stream(True)
        var sbuf = _H3StreamBuf()
        sbuf.is_uni = False
        self._stream_bufs[Int(sid)] = sbuf^
        return sid

    # --- Internal: bootstrap -------------------------------------------------

    def _bootstrap_local_streams(mut self, now: UInt64) raises:
        """Open 3 uni streams, write type varints, send SETTINGS. Guarded by _init_done."""
        var ctrl_sid = self._quic.open_stream(False)
        self._local_ctrl_sid = Optional[UInt64](ctrl_sid)
        var qenc_sid = self._quic.open_stream(False)
        self._local_qenc_sid = Optional[UInt64](qenc_sid)
        var qdec_sid = self._quic.open_stream(False)
        self._local_qdec_sid = Optional[UInt64](qdec_sid)

        # Write stream type varint to each (single byte: 0x00, 0x02, 0x03)
        var ctrl_type = List[UInt8]()
        ctrl_type.append(UInt8(0x00))
        self._quic.send_stream_data(ctrl_sid, Span(ctrl_type), False)
        var qenc_type = List[UInt8]()
        qenc_type.append(UInt8(0x02))
        self._quic.send_stream_data(qenc_sid, Span(qenc_type), False)
        var qdec_type = List[UInt8]()
        qdec_type.append(UInt8(0x03))
        self._quic.send_stream_data(qdec_sid, Span(qdec_type), False)

        # Send SETTINGS on control stream (RFC 9114 §7.2.4)
        var pairs = List[SettingsPair]()
        pairs.append(SettingsPair(SETTINGS_QPACK_MAX_TABLE_CAPACITY, UInt64(0)))
        pairs.append(SettingsPair(SETTINGS_MAX_FIELD_SECTION_SIZE, UInt64(0x7FFFFFFF)))
        var sf = SettingsFrame(pairs)
        var settings_wire = sf.encode()
        self._quic.send_stream_data(ctrl_sid, Span(settings_wire), False)

    # --- Internal: stream drain + frame parse --------------------------------

    def _drain_stream(mut self, stream_id: UInt64, now: UInt64) raises:
        """Read bytes from QUIC, accumulate in _stream_bufs, parse frames."""
        var key = Int(stream_id)
        if key not in self._stream_bufs:
            return  # locally-initiated stream or unknown — ignore

        # Hoisted clock-read state for B1 (parent), B2 (recv_ffi), B3a (buf_accumulate).
        # Single-pair pattern per Q1 lessons (sub-leg pass T4 — Mojo lexical scope).
        var t_start_drain: UInt64 = 0
        var t_start_ffi: UInt64 = 0
        var t_start_buf: UInt64 = 0
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                t_start_drain = monotonic_us()

        # B2 entry — wrap the FFI recv_stream_data call.
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                t_start_ffi = monotonic_us()
        var recv_result = self._quic.recv_stream_data(stream_id)
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                self.profile_ptr[].record_drain_recv_ffi(monotonic_us() - t_start_ffi)

        # B3a entry — wrap from recv_result.copy() through the bidi-check exit.
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                t_start_buf = monotonic_us()

        var fin = recv_result[1]

        # Mutate the stream buf in place via Dict ref binding — was
        # previously a copy + write-back round trip that cloned the
        # entire _H3StreamBuf (including its List[UInt8] buf). Sourced
        # by buf_accumulate_us 12.9% long-conn / 14.7% short-conn.
        # Ref's last use is just before _parse_frames_from_buf (which
        # also mutates _stream_bufs[key]), so ASAP-destruction releases
        # the borrow in time.
        ref sbuf = self._stream_bufs[key]
        sbuf.buf.extend(Span(recv_result[0]))

        # Handle unidirectional stream type byte (first byte = stream type)
        if sbuf.is_uni:
            if not sbuf.type_byte:
                if len(sbuf.buf) == 0:
                    # B3a + B1 exit (return path 1 — UNI empty buf).
                    @parameter
                    if PROFILE_ACCEPT:
                        if Int(self.profile_ptr) != 0:
                            self.profile_ptr[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                            self.profile_ptr[].record_drain_stream(monotonic_us() - t_start_drain)
                    return
                var type_byte = sbuf.buf[0]
                var new_buf = List[UInt8]()
                new_buf.extend(Span(sbuf.buf)[1:])
                sbuf.buf = new_buf^
                sbuf.type_byte = Optional[UInt8](type_byte)
                if type_byte == UInt8(0x00):
                    self._peer_ctrl_sid = Optional[UInt64](stream_id)
                elif type_byte == UInt8(0x02):
                    self._peer_qenc_sid = Optional[UInt64](stream_id)
                elif type_byte == UInt8(0x03):
                    self._peer_qdec_sid = Optional[UInt64](stream_id)
                else:
                    # B3a + B1 exit (return path 2 — unknown UNI type).
                    @parameter
                    if PROFILE_ACCEPT:
                        if Int(self.profile_ptr) != 0:
                            self.profile_ptr[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                            self.profile_ptr[].record_drain_stream(monotonic_us() - t_start_drain)
                    return

        # Reject server-initiated bidi from peer (RFC 9114 §6.1)
        if not sbuf.is_uni and self._is_peer_initiated(stream_id) and not self._is_server:
            self._quic.close(H3_STREAM_CREATION_ERROR, "server-initiated bidi not supported", now)
            # B3a + B1 exit (return path 3 — bidi rejection).
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    self.profile_ptr[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                    self.profile_ptr[].record_drain_stream(monotonic_us() - t_start_drain)
            return

        # Determine if this is the peer control stream
        var is_ctrl = False
        if self._peer_ctrl_sid:
            if self._peer_ctrl_sid.value() == stream_id:
                is_ctrl = True

        # B3a exit — buf_accumulate phase ends BEFORE parse-loop entry.
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                self.profile_ptr[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)

        self._parse_frames_from_buf(stream_id, is_ctrl, now)

        # FIN on bidi request stream → STREAM_ENDED event.
        # Read-only Dict access via ref — no clone of the _H3StreamBuf.
        ref sbuf4 = self._stream_bufs[key]
        if not sbuf4.is_uni and fin:
            var h3ev = H3Event(H3Event.STREAM_ENDED)
            h3ev.stream_id = stream_id
            self._h3_events.append(h3ev^)

        # B1 exit (fall-through path 4).
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                self.profile_ptr[].record_drain_stream(monotonic_us() - t_start_drain)

    def _parse_frames_from_buf(mut self, stream_id: UInt64, is_ctrl: Bool, now: UInt64) raises:
        """Parse H3 frames from accumulated bytes. Consumes one frame per iteration.

        Per-iteration ref binding into self._stream_bufs[key] — same
        sourcing as _drain_stream's prologue: buf_accumulate_us 12.9%
        long-conn / 14.7% short-conn. The handler calls below
        (_handle_control_frame, _handle_request_frame) don't touch
        _stream_bufs themselves, so the ref's borrow extends safely
        across them when a frame was successfully parsed.
        """
        var key = Int(stream_id)
        # Hoisted per-iter clock-read state (Q1 lesson: hoist to function scope, reassign per iter).
        var t_start_parse: UInt64 = 0
        var t_start_buf: UInt64 = 0
        while True:
            ref sbuf = self._stream_bufs[key]
            if len(sbuf.buf) == 0:
                break
            var ok = True
            var frame = H3RawFrame(UInt64(0), List[UInt8]())
            var consumed = 0
            # B4 entry — wrap parse_h3_frame only.
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    t_start_parse = monotonic_us()
            try:
                # ByteReader Span borrow ends with the try-block scope below;
                # `parse_h3_frame.read_bytes` already extends into a fresh
                # List, so the borrow on sbuf.buf is short-lived.
                var r = ByteReader(Span(sbuf.buf))
                frame = parse_h3_frame(r)
                consumed = r.pos
            except:
                ok = False
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    self.profile_ptr[].record_drain_frame_parse(monotonic_us() - t_start_parse)
            if not ok:
                break
            # B3b entry — wrap residual rebuild via in-place mutation.
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    t_start_buf = monotonic_us()
            # Remove consumed bytes from front of buf — in place.
            var new_buf = List[UInt8]()
            new_buf.extend(Span(sbuf.buf)[consumed:])
            sbuf.buf = new_buf^
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    self.profile_ptr[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
            if is_ctrl:
                self._handle_control_frame(stream_id, frame, now)
            else:
                self._handle_request_frame(stream_id, frame^, now)

    def _handle_control_frame(mut self, stream_id: UInt64, frame: H3RawFrame, now: UInt64) raises:
        """Process one frame received on the peer control stream."""
        # RFC 9114 §6.2.1: first frame on peer control stream MUST be SETTINGS
        if not self._peer_ctrl_first_frame_seen:
            self._peer_ctrl_first_frame_seen = True
            if frame.frame_type != H3_FRAME_SETTINGS:
                self._quic.close(H3_MISSING_SETTINGS, "first ctrl frame must be SETTINGS", now)
                return

        if frame.frame_type == H3_FRAME_SETTINGS:
            if self._peer_ctrl_settings:
                self._quic.close(H3_GENERAL_PROTOCOL_ERROR, "duplicate SETTINGS", now)
                return
            self._peer_ctrl_settings = True
            _ = SettingsFrame.decode(frame.payload)
            var h3ev = H3Event(H3Event.SETTINGS_RECEIVED)
            self._h3_events.append(h3ev^)

        elif frame.frame_type == H3_FRAME_GOAWAY:
            var r = ByteReader(Span(frame.payload))
            var last_sid = varint_decode(r)
            self._peer_goaway_sid = Optional[UInt64](last_sid)
            var h3ev = H3Event(H3Event.GOAWAY_RECEIVED)
            h3ev.last_stream_id = last_sid
            self._h3_events.append(h3ev^)

        elif frame.frame_type == H3_FRAME_DATA or frame.frame_type == H3_FRAME_HEADERS:
            # RFC 9114 §7.2.1 / §7.2.2: DATA and HEADERS forbidden on control streams
            self._quic.close(H3_FRAME_UNEXPECTED, "DATA/HEADERS on control stream", now)

        # else: unknown frame types are ignored (RFC 9114 §7.2.8)

    def _handle_request_frame(mut self, stream_id: UInt64, var frame: H3RawFrame, now: UInt64) raises:
        """Process one frame received on a request/response bidi stream."""
        var t_start_qpack: UInt64 = 0
        if frame.frame_type == H3_FRAME_HEADERS:
            # B5 — wrap QPACK decode only.
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    t_start_qpack = monotonic_us()
            var fields = self._dec.decode(frame.payload)
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    self.profile_ptr[].record_drain_qpack_decode(monotonic_us() - t_start_qpack)
            var h3ev = H3Event(H3Event.HEADERS_RECEIVED)
            h3ev.stream_id = stream_id
            h3ev.fields = fields^
            self._h3_events.append(h3ev^)

        elif frame.frame_type == H3_FRAME_DATA:
            var h3ev = H3Event(H3Event.DATA_RECEIVED)
            h3ev.stream_id = stream_id
            h3ev.data = frame^.consume_payload()
            self._h3_events.append(h3ev^)

        elif frame.frame_type == H3_FRAME_SETTINGS or frame.frame_type == H3_FRAME_GOAWAY:
            # Forbidden on request streams (RFC 9114 §7.2.5)
            self._quic.close(H3_FRAME_UNEXPECTED, "SETTINGS/GOAWAY on request stream", now)
        # else: unknown, ignore
