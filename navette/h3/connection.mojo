# src/h3/connection.mojo
#
# H3Connection — sans-I/O HTTP/3 state machine wrapping a QuicConnection.
# H3Event — flat-tag event struct emitted to callers.
# _H3StreamBuf — per-stream byte accumulator.

from std.collections import Dict, Optional
from std.memory import Span, UnsafePointer

from navette.quic.connection import (
    QuicConnection,
    QuicEvent,
    CONN_CLOSING,
    CONN_DRAINING,
    CONN_CLOSED,
)
from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode
from navette.quic.path_validator import PathKey
from navette.quic.profile import AcceptProfile, monotonic_us, PROFILE_ACCEPT
from navette.h3.frame import (
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
    SETTINGS_H3_DATAGRAM,
    parse_h3_frame,
)
from navette.h3.error import (
    H3_MISSING_SETTINGS,
    H3_GENERAL_PROTOCOL_ERROR,
    H3_FRAME_UNEXPECTED,
    H3_STREAM_CREATION_ERROR,
)
from navette.h3.qpack import QpackEncoder, QpackDecoder, QpackHeaderField
from navette.h3.guard_predicates import (
    H3StreamCtx,
    predicate_f31_data_before_headers,
    predicate_f32_first_control_not_settings,
    predicate_f33_data_on_control,
    predicate_f34_headers_on_control,
    predicate_f35_second_settings,
    predicate_f36_cancel_push_on_request,
)


# HTTP/3 CANCEL_PUSH frame type (RFC 9114 §7.2.3 — type 0x03).
comptime H3_FRAME_CANCEL_PUSH: UInt64 = 0x03


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
    # RFC 9297 §2 — an H3-framed datagram has been received. `stream_id`
    # carries the associated request stream id (quarter_id * 4); `data`
    # holds the payload bytes following the quarter-stream-ID varint.
    comptime DATAGRAM_RECEIVED:  UInt8 = 9

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
    var _h3_events:                  List[H3Event]
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
    # Per-request-stream HEADERS-seen flag, feeding the F31 (DATA-before-
    # HEADERS) and F36 (CANCEL_PUSH-on-request) predicate inputs.
    var _request_headers_seen:       Dict[Int, Bool]
    # RFC 9297 §2.2 — both endpoints MUST advertise SETTINGS_H3_DATAGRAM=1
    # before H3 datagrams may flow. `_local_h3_datagram_enabled` controls
    # what THIS connection emits in its own SETTINGS frame; the field
    # defaults False so existing tests/examples stay byte-for-byte
    # compatible. `_peer_h3_datagram_enabled` is set when the peer's
    # SETTINGS frame is received with H3_DATAGRAM=1.
    var _local_h3_datagram_enabled:  Bool
    var _peer_h3_datagram_enabled:   Bool
    var profile_ptr: Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]]

    def __init__(out self, var quic: QuicConnection, is_server: Bool):
        self._quic = quic^
        self._is_server = is_server
        self._stream_bufs = Dict[Int, _H3StreamBuf]()
        self._h3_events = List[H3Event]()
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
        self._enc = QpackEncoder(False)
        self._dec = QpackDecoder()
        self._request_headers_seen = Dict[Int, Bool]()
        self._local_h3_datagram_enabled = False
        self._peer_h3_datagram_enabled = False
        self.profile_ptr = None

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
        self._request_headers_seen = take._request_headers_seen^
        self._local_h3_datagram_enabled = take._local_h3_datagram_enabled
        self._peer_h3_datagram_enabled = take._peer_h3_datagram_enabled
        self.profile_ptr = take.profile_ptr

    @staticmethod
    def server(var quic: QuicConnection) raises -> H3Connection:
        """Wrap a server-side QuicConnection."""
        return H3Connection(quic^, True)

    @staticmethod
    def client(var quic: QuicConnection) raises -> H3Connection:
        """Wrap a client-side QuicConnection."""
        return H3Connection(quic^, False)

    def is_established(self) -> Bool:
        return self._quic.is_established()

    def enable_h3_datagrams(mut self):
        """RFC 9297 §2.2 — opt this connection into emitting H3 datagrams.

        MUST be called BEFORE the handshake completes (i.e. before
        `_bootstrap_local_streams` writes the local SETTINGS frame).
        Toggles SETTINGS_H3_DATAGRAM=1 in the local advertisement;
        sending H3 datagrams additionally requires the peer's SETTINGS
        to carry the same flag and the QUIC layer to have negotiated
        max_datagram_frame_size > 0 via RFC 9221.
        """
        self._local_h3_datagram_enabled = True

    def peer_h3_datagrams_enabled(self) -> Bool:
        """True iff the peer advertised SETTINGS_H3_DATAGRAM=1.

        Returns the cached flag set during the peer-SETTINGS handler;
        before peer SETTINGS arrival the value is False (matching the
        "datagrams refused" semantic).
        """
        return self._peer_h3_datagram_enabled

    def is_closed(self) -> Bool:
        return self._quic.is_closed()

    fn peer_max_bidi_streams_raw(self) -> UInt64:
        """Return the peer's QUIC MAX_STREAMS (bidirectional) limit.

        Thin chain to `QuicConnection.peer_max_bidi_streams_raw()` that
        preserves `H3Connection._quic` encapsulation. Reads a single
        `UInt64` field without copying any `StreamMap` snapshot, so it is
        safe for hot-path use by `H3Session.peer_max_bidi_streams()`.
        """
        return self._quic.peer_max_bidi_streams_raw()

    # --- Path-validation pass-through (RFC 9000 §8 + §9) ---------------------

    def on_ingress_from(
        mut self, var from_addr: PathKey, datagram_len: Int, now: UInt64
    ) raises:
        """Forward per-datagram path-change + anti-amp credit to the QUIC layer.

        See `QuicConnection.on_ingress_from` for the contract. Exposed at
        the H3 boundary so the UDP server can drive it without depending
        on the inner QuicConnection field. Called BEFORE `feed_datagram*`.
        """
        self._quic.on_ingress_from(from_addr^, datagram_len, now)

    def set_current_recv_addr(mut self, var addr: PathKey):
        """Stamp the per-receive source-addr cursor on the QUIC layer."""
        self._quic.set_current_recv_addr(addr^)

    def bootstrap_peer_addr(mut self, var addr: PathKey):
        """Seed `peer_addr` on a freshly-accepted connection."""
        self._quic.bootstrap_peer_addr(addr^)

    def can_send_to(self, target: PathKey, n_bytes: Int) -> Bool:
        """Anti-amp gate (RFC 9000 §8.1) for outbound bytes to `target`."""
        return self._quic.can_send_to(target, n_bytes)

    def record_send_to(mut self, target: PathKey, n_bytes: Int):
        """Credit `n_bytes` to the per-path bytes_sent counter."""
        self._quic.record_send_to(target, n_bytes)

    def peer_addr_copy(self) -> PathKey:
        """Return a copy of the currently-validated peer 4-tuple.

        Read-only — the bench server uses this to route validated-path
        outbound traffic. Mutation goes through `bootstrap_peer_addr`
        (handshake seeding) or `on_path_response_received` (post-migration
        promotion); both live on the QUIC layer.
        """
        return PathKey(other=self._quic.peer_addr)

    def _is_peer_initiated(self, stream_id: UInt64) -> Bool:
        if self._is_server:
            return (stream_id & UInt64(1)) == 0
        else:
            return (stream_id & UInt64(1)) == 1

    def _is_request_stream(self, stream_id: UInt64) -> Bool:
        return (stream_id & UInt64(0x02)) == 0

    def poll_event(mut self) -> Optional[H3Event]:
        """Return the next pending H3Event, or None if the queue is empty."""
        if len(self._h3_events) == 0:
            return Optional[H3Event]()
        var ev = H3Event(other=self._h3_events[0])
        var rest = List[H3Event]()
        for i in range(1, len(self._h3_events)):
            rest.append(H3Event(other=self._h3_events[i]))
        self._h3_events = rest^
        return Optional[H3Event](ev^)

    # --- Transport API -------------------------------------------------------

    def feed_datagram(mut self, data: Span[UInt8, _], now: UInt64) raises:
        """Feed one inbound QUIC datagram; translate QuicEvents to H3Events."""
        self._quic.recv(data, now)
        _ = self._quic.timeout(now)
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
            elif ev.type_id == QuicEvent.DATAGRAM_RECEIVED:
                self._dispatch_quic_datagram(ev.datagram_payload)

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
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                t_start = monotonic_us()

        _ = self._quic.timeout(now)
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
            elif ev.type_id == QuicEvent.DATAGRAM_RECEIVED:
                self._dispatch_quic_datagram(ev.datagram_payload)

        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_quic_post_recv(monotonic_us() - t_start)

    def drain_datagrams(mut self, now: UInt64) raises -> List[List[UInt8]]:
        """Drain outbound QUIC datagrams. Returns list of UDP payloads."""
        return self._quic.send(now)

    # --- Send API ------------------------------------------------------------

    def send_headers(
        mut self, stream_id: UInt64, fields: List[QpackHeaderField], fin: Bool
    ) raises:
        """QPACK-encode fields → HeadersFrame → send_stream_data."""
        var encoded = self._enc.encode(fields)
        var hf = HeadersFrame(encoded)
        var wire = hf.encode()
        self._quic.send_stream_data(stream_id, Span(wire), fin)

    def send_data(
        mut self, stream_id: UInt64, data: List[UInt8], fin: Bool
    ) raises:
        """Encode as DataFrame → send_stream_data. Empty data + fin=True sends FIN only."""
        if len(data) == 0 and fin:
            var empty = List[UInt8]()
            self._quic.send_stream_data(stream_id, Span(empty), True)
            return
        if len(data) == 0:
            return
        var df = DataFrame(data)
        var wire = df.encode()
        self._quic.send_stream_data(stream_id, Span(wire), fin)

    def send_goaway(mut self, last_stream_id: UInt64) raises:
        """Write GOAWAY frame to local control stream."""
        if not self._init_done:
            raise "H3: not established"
        if not self._local_ctrl_sid:
            raise "H3: no local control stream"
        var w = ByteWriter()
        varint_encode(w, last_stream_id)
        var payload = w.finish()
        var raw = H3RawFrame(H3_FRAME_GOAWAY, payload)
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

    def send_datagram(
        mut self, stream_id: UInt64, payload: Span[UInt8, _]
    ) raises -> Bool:
        """RFC 9297 §2.1 — send an H3 datagram associated with `stream_id`.

        Encodes `quarter_stream_id (= stream_id / 4)` as a varint prefix
        followed by the application payload, then hands the combined bytes
        to `QuicConnection.send_datagram`. Returns False if H3 datagrams
        are not negotiated (peer SETTINGS missing H3_DATAGRAM=1) OR the
        underlying QUIC layer refuses (peer max_datagram_frame_size = 0,
        cap exceeded, connection closing/draining).

        Raises only on the structural precondition that `stream_id` MUST
        be client-initiated bidirectional (i.e. `stream_id % 4 == 0`).
        Per RFC 9297 §2.1, H3 datagrams associate to client-initiated
        bidi streams; any other id is a usage error rather than a
        wire-protocol violation, so it surfaces as a Mojo raise.
        """
        if not self._peer_h3_datagram_enabled:
            return False
        if stream_id & UInt64(3) != UInt64(0):
            raise "H3 datagrams: stream_id must be client-initiated bidi (% 4 == 0)"
        var quarter_id = stream_id / UInt64(4)
        var w = ByteWriter()
        varint_encode(w, quarter_id)
        var prefix = w.finish()
        # Coalesce the quarter-id prefix and the application payload into
        # a single buffer so the QUIC layer sees one DATAGRAM frame.
        var buf = List[UInt8]()
        for i in range(len(prefix)):
            buf.append(prefix[i])
        for i in range(len(payload)):
            buf.append(payload[i])
        return self._quic.send_datagram(Span(buf))

    # --- Internal: bootstrap -------------------------------------------------

    def _dispatch_quic_datagram(mut self, payload: List[UInt8]):
        """RFC 9297 §2.1 — decode an H3 datagram from a QUIC DATAGRAM payload.

        Each inbound QUIC DATAGRAM carries `varint(quarter_stream_id) + bytes`.
        We decode the prefix, expand it to the associated request stream id
        (`quarter_id * 4` per §2.1), and emit an H3Event so the caller can
        demux. Malformed varints (truncated, or with a value that overflows
        the stream-id space) are silently dropped — H3 datagrams are an
        application-controlled side channel and dropping mirrors the loss
        semantics of the underlying QUIC layer (RFC 9221 §5.4).

        We do NOT gate on `_local_h3_datagram_enabled` here: by the time
        the peer's DATAGRAM reached us the QUIC layer already accepted it,
        and per §2.2 the local endpoint MAY choose to dispatch even if it
        did not advertise H3_DATAGRAM (the negotiated property is a SHOULD
        for sending, not for receiving).
        """
        # Empty payload cannot carry a quarter-stream-ID; silently drop.
        if len(payload) == 0:
            return
        var r = ByteReader(Span(payload))
        var quarter_id: UInt64
        try:
            quarter_id = varint_decode(r)
        except:
            return
        # Saturating multiply check: stream-id space is 62-bit (RFC 9000
        # §2.1). quarter_id * 4 cannot overflow 64 bits in any plausible
        # sender, but be defensive.
        if quarter_id > UInt64(0x3FFFFFFFFFFFFFFF):
            return
        var stream_id = quarter_id * UInt64(4)
        var rest = List[UInt8]()
        for i in range(r.pos, len(payload)):
            rest.append(payload[i])
        var h3ev = H3Event(H3Event.DATAGRAM_RECEIVED)
        h3ev.stream_id = stream_id
        h3ev.data = rest^
        self._h3_events.append(h3ev^)

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
        # RFC 9297 §2.2 — only advertise H3_DATAGRAM if the caller opted in
        # via `enable_h3_datagrams()`. Default-off keeps SETTINGS wire-byte
        # compatibility with non-MASQUE/WebTransport tests.
        if self._local_h3_datagram_enabled:
            pairs.append(SettingsPair(SETTINGS_H3_DATAGRAM, UInt64(1)))
        var sf = SettingsFrame(pairs)
        var settings_wire = sf.encode()
        self._quic.send_stream_data(ctrl_sid, Span(settings_wire), False)

    # --- Internal: stream drain + frame parse --------------------------------

    def _close_duplicate_uni_stream(
        mut self,
        var existing: Optional[UInt64],
        label: String,
        now: UInt64,
        t_start_buf: UInt64,
        t_start_drain: UInt64,
    ) -> Bool:
        """Return True (and queue a CONNECTION_CLOSE_APP) if `existing` is set.

        Used to detect a second peer-initiated unidirectional control /
        QPACK encoder / QPACK decoder stream per RFC 9114 §6.2.1 and
        RFC 9204 §4.2. Centralises the existence-check + close + profile
        bookkeeping common to all three well-known unidirectional types so
        a future fourth type doesn't re-introduce the same copy-paste.

        `label` is interpolated as `"duplicate " + label + " stream"` into
        the CONNECTION_CLOSE reason field. `t_start_buf` and `t_start_drain`
        are the monotonic-µs stamps captured at the top of `_drain_stream`
        used by the PROFILE_ACCEPT comptime sidecar.
        """
        if not existing:
            return False
        self._quic.close_app(H3_STREAM_CREATION_ERROR, "duplicate " + label + " stream", now)
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                self.profile_ptr.value()[].record_drain_stream(monotonic_us() - t_start_drain)
        return True

    def _drain_stream(mut self, stream_id: UInt64, now: UInt64) raises:
        """Read bytes from QUIC, accumulate in _stream_bufs, parse frames."""
        # RFC 9000 §10.2.1: once CLOSING/DRAINING/CLOSED, drop further inbound
        # stream data — no more frames flow on this connection.
        if (self._quic.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
            return
        var key = Int(stream_id)
        if key not in self._stream_bufs:
            return  # locally-initiated stream or unknown — ignore

        # Hoisted clock-read state for B1 (parent), B2 (recv_ffi), B3a (buf_accumulate).
        # Single-pair pattern per Q1 lessons (sub-leg pass T4 — Mojo lexical scope):
        # `comptime if` introduces its own scope, so we hoist these to function scope.
        # The `comptime if not PROFILE_ACCEPT` discards below silence the "init never
        # used" warning on default builds (the comptime profile branches vanish).
        var t_start_drain: UInt64 = 0
        var t_start_ffi: UInt64 = 0
        var t_start_buf: UInt64 = 0
        comptime if not PROFILE_ACCEPT:
            _ = t_start_drain
            _ = t_start_ffi
            _ = t_start_buf
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                t_start_drain = monotonic_us()

        # B2 entry — wrap the FFI recv_stream_data call.
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                t_start_ffi = monotonic_us()
        var recv_result = self._quic.recv_stream_data(stream_id)
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_drain_recv_ffi(monotonic_us() - t_start_ffi)

        # B3a entry — wrap from recv_result.copy() through the bidi-check exit.
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                t_start_buf = monotonic_us()

        var new_bytes = recv_result[0].copy()
        var fin = recv_result[1]

        # Append new bytes to accumulator
        var sbuf = self._stream_bufs[key].copy()
        for i in range(len(new_bytes)):
            sbuf.buf.append(new_bytes[i])
        self._stream_bufs[key] = sbuf^

        # Handle unidirectional stream type byte (first byte = stream type)
        var sbuf2 = self._stream_bufs[key].copy()
        if sbuf2.is_uni:
            if not sbuf2.type_byte:
                if len(sbuf2.buf) == 0:
                    self._stream_bufs[key] = sbuf2^
                    # B3a + B1 exit (return path 1 — UNI empty buf).
                    comptime if PROFILE_ACCEPT:
                        if self.profile_ptr is not None:
                            self.profile_ptr.value()[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                            self.profile_ptr.value()[].record_drain_stream(monotonic_us() - t_start_drain)
                    return
                var type_byte = sbuf2.buf[0]
                var new_buf = List[UInt8]()
                for i in range(1, len(sbuf2.buf)):
                    new_buf.append(sbuf2.buf[i])
                sbuf2.buf = new_buf^
                sbuf2.type_byte = Optional[UInt8](type_byte)
                self._stream_bufs[key] = sbuf2^
                if type_byte == UInt8(0x00):
                    # RFC 9114 §6.2.1: at most one control stream per peer.
                    var existing_ctrl = self._peer_ctrl_sid.copy()
                    if self._close_duplicate_uni_stream(existing_ctrl^, "control", now, t_start_buf, t_start_drain):
                        return
                    self._peer_ctrl_sid = Optional[UInt64](stream_id)
                elif type_byte == UInt8(0x02):
                    # RFC 9204 §4.2: at most one QPACK encoder stream per peer.
                    var existing_qenc = self._peer_qenc_sid.copy()
                    if self._close_duplicate_uni_stream(existing_qenc^, "qpack encoder", now, t_start_buf, t_start_drain):
                        return
                    self._peer_qenc_sid = Optional[UInt64](stream_id)
                elif type_byte == UInt8(0x03):
                    # RFC 9204 §4.2: at most one QPACK decoder stream per peer.
                    var existing_qdec = self._peer_qdec_sid.copy()
                    if self._close_duplicate_uni_stream(existing_qdec^, "qpack decoder", now, t_start_buf, t_start_drain):
                        return
                    self._peer_qdec_sid = Optional[UInt64](stream_id)
                else:
                    # B3a + B1 exit (return path 2 — unknown UNI type).
                    comptime if PROFILE_ACCEPT:
                        if self.profile_ptr is not None:
                            self.profile_ptr.value()[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                            self.profile_ptr.value()[].record_drain_stream(monotonic_us() - t_start_drain)
                    return
            else:
                self._stream_bufs[key] = sbuf2^

        # Reject server-initiated bidi from peer (RFC 9114 §6.1)
        var sbuf3 = self._stream_bufs[key].copy()
        if not sbuf3.is_uni and self._is_peer_initiated(stream_id) and not self._is_server:
            self._stream_bufs[key] = sbuf3^
            self._quic.close_app(H3_STREAM_CREATION_ERROR, "server-initiated bidi not supported", now)
            # B3a + B1 exit (return path 3 — bidi rejection).
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    self.profile_ptr.value()[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                    self.profile_ptr.value()[].record_drain_stream(monotonic_us() - t_start_drain)
            return
        self._stream_bufs[key] = sbuf3^

        # Determine if this is the peer control stream
        var is_ctrl = False
        if self._peer_ctrl_sid:
            if self._peer_ctrl_sid.value() == stream_id:
                is_ctrl = True

        # B3a exit — buf_accumulate phase ends BEFORE parse-loop entry.
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)

        self._parse_frames_from_buf(stream_id, is_ctrl, now)

        # FIN on bidi request stream → STREAM_ENDED event
        var sbuf4 = self._stream_bufs[key].copy()
        if not sbuf4.is_uni and fin:
            var h3ev = H3Event(H3Event.STREAM_ENDED)
            h3ev.stream_id = stream_id
            self._h3_events.append(h3ev^)
        self._stream_bufs[key] = sbuf4^

        # B1 exit (fall-through path 4).
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_drain_stream(monotonic_us() - t_start_drain)

    def _parse_frames_from_buf(mut self, stream_id: UInt64, is_ctrl: Bool, now: UInt64) raises:
        """Parse H3 frames from accumulated bytes. Consumes one frame per iteration."""
        var key = Int(stream_id)
        # Hoisted per-iter clock-read state (Q1 lesson: hoist to function scope, reassign per iter).
        var t_start_parse: UInt64 = 0
        var t_start_buf: UInt64 = 0
        comptime if not PROFILE_ACCEPT:
            _ = t_start_parse
            _ = t_start_buf
        while True:
            var sbuf = self._stream_bufs[key].copy()
            if len(sbuf.buf) == 0:
                self._stream_bufs[key] = sbuf^
                break
            # Make a separate copy for ByteReader (avoids lifetime conflict)
            var buf_copy = List[UInt8](copy=sbuf.buf)
            var r = ByteReader(Span(buf_copy))
            var ok = True
            var frame = H3RawFrame(UInt64(0), List[UInt8]())
            var consumed = 0
            # B4 entry — wrap parse_h3_frame only.
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    t_start_parse = monotonic_us()
            try:
                frame = parse_h3_frame(r)
                consumed = r.pos
            except:
                ok = False
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    self.profile_ptr.value()[].record_drain_frame_parse(monotonic_us() - t_start_parse)
            if not ok:
                self._stream_bufs[key] = sbuf^
                break
            # B3b entry — wrap residual rebuild + Dict reassign.
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    t_start_buf = monotonic_us()
            # Remove consumed bytes from front of buf
            var new_buf = List[UInt8]()
            for i in range(consumed, len(sbuf.buf)):
                new_buf.append(sbuf.buf[i])
            sbuf.buf = new_buf^
            self._stream_bufs[key] = sbuf^
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    self.profile_ptr.value()[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
            if is_ctrl:
                self._handle_control_frame(stream_id, frame, now)
            else:
                self._handle_request_frame(stream_id, frame, now)

    def _handle_control_frame(mut self, stream_id: UInt64, frame: H3RawFrame, now: UInt64) raises:
        """Process one frame received on the peer control stream."""
        # F32 — first frame on the peer ctrl stream MUST be SETTINGS
        # (RFC 9114 §6.2.1). Tracks first-frame state via the existing
        # `_peer_ctrl_first_frame_seen` flag.
        if not self._peer_ctrl_first_frame_seen:
            self._peer_ctrl_first_frame_seen = True
            var _f32_ctx = H3StreamCtx(
                kind=UInt8(1), headers_seen=False,
                settings_seen=self._peer_ctrl_settings,
                first_frame_seen=False,
            )
            var _f32_v = predicate_f32_first_control_not_settings(frame.frame_type, _f32_ctx)
            if _f32_v:
                var v = _f32_v.value().copy()
                self._quic.close_app(v.error_code, v.tag, now)
                return

        if frame.frame_type == H3_FRAME_SETTINGS:
            # F35 — second SETTINGS on the peer ctrl stream is
            # H3_FRAME_UNEXPECTED (RFC 9114 §7.2.4). Replaces the legacy
            # H3_GENERAL_PROTOCOL_ERROR + "duplicate SETTINGS" close.
            var _f35_ctx = H3StreamCtx(
                kind=UInt8(1), headers_seen=False,
                settings_seen=self._peer_ctrl_settings,
                first_frame_seen=self._peer_ctrl_first_frame_seen,
            )
            var _f35_v = predicate_f35_second_settings(frame.frame_type, _f35_ctx)
            if _f35_v:
                var v = _f35_v.value().copy()
                self._quic.close_app(v.error_code, v.tag, now)
                return
            self._peer_ctrl_settings = True
            var peer_settings = SettingsFrame.decode(frame.payload)
            # RFC 9297 §2.2: detect H3_DATAGRAM=1 in the peer's SETTINGS
            # so subsequent send_datagram calls can gate on the negotiated
            # flag. Values other than 0/1 are reserved but the only
            # observable semantic is "non-zero == enabled"; we mirror that.
            var peer_h3d = peer_settings.get(SETTINGS_H3_DATAGRAM)
            if peer_h3d:
                if peer_h3d.value() != UInt64(0):
                    self._peer_h3_datagram_enabled = True
            var h3ev = H3Event(H3Event.SETTINGS_RECEIVED)
            self._h3_events.append(h3ev^)

        elif frame.frame_type == H3_FRAME_GOAWAY:
            var r = ByteReader(Span(frame.payload))
            var last_sid = varint_decode(r)
            self._peer_goaway_sid = Optional[UInt64](last_sid)
            var h3ev = H3Event(H3Event.GOAWAY_RECEIVED)
            h3ev.last_stream_id = last_sid
            self._h3_events.append(h3ev^)

        else:
            # F33 — DATA on the peer ctrl stream (RFC 9114 §7.2.1).
            # F34 — HEADERS on the peer ctrl stream (RFC 9114 §7.2.2).
            var _ctrl_ctx = H3StreamCtx(
                kind=UInt8(1), headers_seen=False,
                settings_seen=self._peer_ctrl_settings,
                first_frame_seen=self._peer_ctrl_first_frame_seen,
            )
            var _f33_v = predicate_f33_data_on_control(frame.frame_type, _ctrl_ctx)
            if _f33_v:
                var v = _f33_v.value().copy()
                self._quic.close_app(v.error_code, v.tag, now)
                return
            var _f34_v = predicate_f34_headers_on_control(frame.frame_type, _ctrl_ctx)
            if _f34_v:
                var v = _f34_v.value().copy()
                self._quic.close_app(v.error_code, v.tag, now)
                return

        # else: unknown frame types are ignored (RFC 9114 §7.2.8)

    def _handle_request_frame(mut self, stream_id: UInt64, frame: H3RawFrame, now: UInt64) raises:
        """Process one frame received on a request/response bidi stream."""
        # F31 — DATA before HEADERS on a request-bidi stream is illegal
        # (RFC 9114 §4.1). The predicate keys on (frame_type, headers_seen)
        # so dispatch order in this function is irrelevant — see the
        # cohort exclusivity tests.
        var _headers_seen = self._request_headers_seen.get(Int(stream_id), False)
        var _f31_ctx = H3StreamCtx(
            kind=UInt8(0),
            headers_seen=_headers_seen,
            settings_seen=False,
        )
        var _f31_verdict = predicate_f31_data_before_headers(frame.frame_type, _f31_ctx)
        if _f31_verdict:
            var v = _f31_verdict.value().copy()
            self._quic.close_app(v.error_code, v.tag, now)
            return

        # F36 — CANCEL_PUSH is illegal on request streams (RFC 9114 §7.2.5).
        var _f36_ctx = H3StreamCtx(
            kind=UInt8(0),
            headers_seen=_headers_seen,
            settings_seen=False,
        )
        var _f36_verdict = predicate_f36_cancel_push_on_request(frame.frame_type, _f36_ctx)
        if _f36_verdict:
            var v = _f36_verdict.value().copy()
            self._quic.close_app(v.error_code, v.tag, now)
            return

        var t_start_qpack: UInt64 = 0
        comptime if not PROFILE_ACCEPT:
            _ = t_start_qpack
        if frame.frame_type == H3_FRAME_HEADERS:
            # B5 — wrap QPACK decode only.
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    t_start_qpack = monotonic_us()
            var fields = self._dec.decode(frame.payload)
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    self.profile_ptr.value()[].record_drain_qpack_decode(monotonic_us() - t_start_qpack)
            self._request_headers_seen[Int(stream_id)] = True
            var h3ev = H3Event(H3Event.HEADERS_RECEIVED)
            h3ev.stream_id = stream_id
            h3ev.fields = fields^
            self._h3_events.append(h3ev^)

        elif frame.frame_type == H3_FRAME_DATA:
            var h3ev = H3Event(H3Event.DATA_RECEIVED)
            h3ev.stream_id = stream_id
            h3ev.data = List[UInt8](copy=frame.payload)
            self._h3_events.append(h3ev^)

        elif frame.frame_type == H3_FRAME_SETTINGS or frame.frame_type == H3_FRAME_GOAWAY:
            # Forbidden on request streams (RFC 9114 §7.2.5)
            self._quic.close_app(H3_FRAME_UNEXPECTED, "SETTINGS/GOAWAY on request stream", now)
        # else: unknown, ignore
