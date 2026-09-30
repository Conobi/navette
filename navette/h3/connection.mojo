# src/h3/connection.mojo
#
# H3Connection — sans-I/O HTTP/3 state machine wrapping a QuicConnection.
# H3Event — flat-tag event struct emitted to callers.
# _H3StreamBuf — per-stream byte accumulator.

from std.collections import Dict, Optional
from std.memory import Pointer, UnsafePointer
from std.collections import Span

from navette.quic.connection import (
    QuicConnection,
    CONN_CLOSING,
    CONN_DRAINING,
    CONN_CLOSED,
)
from navette.quic.event import (
    QuicEvent, ConnectionClosedPayload, StreamResetPayload,
)
from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode
from navette.quic.path import PathKey
from navette.quic.profile import AcceptProfile, monotonic_us, PROFILE_ACCEPT, rdtsc, CallId
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
    H3_FRAME_ERROR,
    H3_EXCESSIVE_LOAD,
    H3_CLOSED_CRITICAL_STREAM,
    H3_ID_ERROR,
    H3_INTERNAL_ERROR,
    QPACK_DECOMPRESSION_FAILED,
)
from navette.h3.qpack import (
    QpackEncoder,
    QpackDecoder,
    QpackHeaderField,
    QpackCodecTables,
)
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
# Upper bound on datagrams collected by one `drain_datagrams` call. Bounds
# egress work per connection per flush (fairness across connections) and
# guarantees termination independently of the frame builder.
comptime MAX_DATAGRAMS_PER_DRAIN: Int = 64

comptime H3_FRAME_CANCEL_PUSH: UInt64 = 0x03
comptime _H3_FRAME_PUSH_PROMISE: UInt64 = 0x05
comptime _H3_FRAME_MAX_PUSH_ID: UInt64 = 0x0D

# SETTINGS_MAX_FIELD_SECTION_SIZE we advertise and enforce on decoded
# header and trailer sections (RFC 9114 Section 4.2.2). 32 KiB matches the
# quiche default and nginx's HTTP/3 header limit.
comptime H3_MAX_FIELD_SECTION_SIZE: Int = 32 * 1024
# Largest HEADERS payload buffered before decoding: Huffman coding can
# make an encoded section larger than its decoded size, so allow 1.5x
# (quiche's rule). Larger frames close the connection with
# H3_EXCESSIVE_LOAD before any payload is buffered.
comptime _H3_MAX_HEADERS_PAYLOAD: Int = H3_MAX_FIELD_SECTION_SIZE + H3_MAX_FIELD_SECTION_SIZE // 2
# SETTINGS payload cap (quiche MAX_SETTINGS_PAYLOAD_SIZE).
comptime _H3_MAX_SETTINGS_PAYLOAD: Int = 256
# GOAWAY, CANCEL_PUSH and MAX_PUSH_ID carry a single varint.
comptime _H3_MAX_VARINT_FRAME_PAYLOAD: Int = 8

@always_inline
def _is_http2_frame_type(frame_type: UInt64) -> Bool:
    """HTTP/2 PRIORITY, PING, WINDOW_UPDATE and CONTINUATION types.

    Reserved in HTTP/3; receiving one is H3_FRAME_UNEXPECTED
    (RFC 9114 Section 7.2.8).
    """
    return (
        frame_type == 0x02 or frame_type == 0x06
        or frame_type == 0x08 or frame_type == 0x09
    )


def _single_varint(payload: List[Byte]) -> Optional[UInt64]:
    """The payload's value if it is exactly one varint, else None.

    GOAWAY, CANCEL_PUSH and MAX_PUSH_ID carry one varint; missing or
    extra bytes are H3_FRAME_ERROR (RFC 9114 Section 7.1).
    """
    try:
        var r = ByteReader(Span(payload))
        var v = varint_decode(r)
        if r.pos == len(payload):
            return v
    except:
        pass
    return None


# How `_parse_frames` treats a frame payload once its header is read.
comptime _PAYLOAD_BUFFER: UInt8 = 0  # wait for the whole (capped) payload
comptime _PAYLOAD_STREAM: UInt8 = 1  # DATA: deliver bytes as they arrive
comptime _PAYLOAD_SKIP: UInt8 = 2    # dispatch the type, discard the payload
comptime _PAYLOAD_REJECT: UInt8 = 3  # connection closed on the header alone


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
    var data:          List[Byte]
    var fin:           Bool
    var error_code:    UInt64
    var reason:        String
    var last_stream_id: UInt64

    def __init__(out self, kind: UInt8):
        self.kind = kind
        self.stream_id = UInt64(0)
        self.fields = List[QpackHeaderField]()
        self.data = List[Byte]()
        self.fin = False
        self.error_code = UInt64(0)
        self.reason = String("")
        self.last_stream_id = UInt64(0)

    def __init__(out self, *, copy: Self):
        self.kind = copy.kind
        self.stream_id = copy.stream_id
        self.fields = List[QpackHeaderField](copy=copy.fields)
        self.data = List[Byte](copy=copy.data)
        self.fin = copy.fin
        self.error_code = copy.error_code
        self.reason = copy.reason
        self.last_stream_id = copy.last_stream_id


# ---------------------------------------------------------------------------
# _H3StreamBuf — per-stream byte accumulator (Copyable for Dict storage)
# ---------------------------------------------------------------------------


struct _H3StreamBuf(Copyable, Movable):
    """Receive-side framing state of one peer stream, kept between drains.

    `buf` holds only bytes a drain could not parse yet: a partial frame
    header or a partial capped frame, so at most one frame header plus
    `_H3_MAX_HEADERS_PAYLOAD` bytes. DATA and skipped payloads never wait
    in it; `payload_remaining` tracks them and they are consumed as they
    arrive, because QUIC has already returned their flow-control credit.
    """

    var buf:       List[Byte]
    var type_byte: Optional[UInt8]
    var is_uni:    Bool
    # Bytes of the current streamed (DATA) or skipped frame payload still
    # to come; 0 when the next byte starts a frame header.
    var payload_remaining: Int
    var skipping:  Bool
    # Unknown or QPACK uni stream: every received byte is dropped.
    var discard:   Bool

    def __init__(out self):
        self.buf = List[Byte]()
        self.type_byte = Optional[UInt8]()
        self.is_uni = False
        self.payload_remaining = 0
        self.skipping = False
        self.discard = False


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
    var profile_ptr: Optional[Pointer[AcceptProfile, MutUntrackedOrigin]]
    # Read cursor into `_h3_events`; entries below it are consumed. Reset
    # to 0 (with the list cleared) once every event has been popped.
    var _h3_events_head:             Int
    # True when the last `drain_datagrams` stopped at MAX_DATAGRAMS_PER_DRAIN
    # rather than because `send()` ran dry; the server treats such a
    # connection as due for another drain right now.
    var egress_capped:               Bool
    # Reusable out-parameter for `QuicConnection.send`, which emits at most
    # one datagram per call; `drain_datagrams` calls it in a loop and moves
    # each result into its own accumulator, so this buffer amortizes the
    # outer List allocation across every `send()` call instead of just
    # across one `drain_datagrams` invocation.
    var _send_scratch:               List[List[Byte]]
    # Reusable scratch buffer for frame encoding in send_headers / send_goaway /
    # _bootstrap_local_streams — avoids a fresh allocation per call.
    var _wire_scratch:               List[Byte]

    def __init__(
        out self,
        var quic: QuicConnection,
        is_server: Bool,
        codec_tables: Optional[Pointer[QpackCodecTables, MutUntrackedOrigin]] = None,
    ):
        self._quic = quic^
        self._is_server = is_server
        self._stream_bufs = Dict[Int, _H3StreamBuf]()
        self._h3_events = List[H3Event]()
        self._h3_events_head = 0
        self.egress_capped = False
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
        if codec_tables:
            self._enc = QpackEncoder(False, codec_tables.value())
            self._dec = QpackDecoder(codec_tables.value())
        else:
            self._enc = QpackEncoder(False)
            self._dec = QpackDecoder()
        self._request_headers_seen = Dict[Int, Bool]()
        self._local_h3_datagram_enabled = False
        self._peer_h3_datagram_enabled = False
        self.profile_ptr = None
        self._send_scratch = List[List[Byte]](capacity=1)
        self._wire_scratch = List[Byte](capacity=256)

    @staticmethod
    def server(
        var quic: QuicConnection,
        codec_tables: Optional[Pointer[QpackCodecTables, MutUntrackedOrigin]] = None,
    ) raises -> H3Connection:
        """Wrap a server-side QuicConnection."""
        return H3Connection(quic^, True, codec_tables)

    @staticmethod
    def client(
        var quic: QuicConnection,
        codec_tables: Optional[Pointer[QpackCodecTables, MutUntrackedOrigin]] = None,
    ) raises -> H3Connection:
        """Wrap a client-side QuicConnection."""
        return H3Connection(quic^, False, codec_tables)

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

    def is_closing_or_draining(self) -> Bool:
        """True once the connection is CLOSING, DRAINING or CLOSED.

        Servers freeze the peer address in these states so a reflected
        CONNECTION_CLOSE can only go to the address the peer was using
        before the close began.
        """
        return (
            self._quic.is_closing()
            or self._quic.is_draining()
            or self._quic.is_closed()
        )

    def timeout(self, now: UInt64) -> Optional[UInt64]:
        """Earliest absolute deadline (µs) the QUIC layer needs servicing at."""
        return self._quic.timeout(now)

    def has_pending_egress(self) -> Bool:
        """True when the last drain hit the cap and datagrams are still owed."""
        return self.egress_capped

    def peer_max_bidi_streams_raw(self) -> UInt64:
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
        return PathKey(copy=self._quic.path.peer_addr)

    def _is_peer_initiated(self, stream_id: UInt64) -> Bool:
        if self._is_server:
            return (stream_id & UInt64(1)) == 0
        else:
            return (stream_id & UInt64(1)) == 1

    def _is_request_stream(self, stream_id: UInt64) -> Bool:
        return (stream_id & UInt64(0x02)) == 0

    def poll_event(mut self) -> Optional[H3Event]:
        """Return the next pending H3Event, or None if the queue is empty.

        O(1): advances a head cursor instead of rebuilding the list; the
        list is cleared once the cursor reaches its end.
        """
        if self._h3_events_head >= len(self._h3_events):
            self._h3_events.clear()
            self._h3_events_head = 0
            return Optional[H3Event]()
        var ev = H3Event(copy=self._h3_events[self._h3_events_head])
        self._h3_events_head += 1
        if self._h3_events_head >= len(self._h3_events):
            self._h3_events.clear()
            self._h3_events_head = 0
        return Optional[H3Event](ev^)

    # --- Transport API -------------------------------------------------------

    def feed_datagram(mut self, data: Span[Byte, _], now: UInt64) raises:
        """Feed one inbound QUIC datagram; translate QuicEvents to H3Events."""
        self._quic.recv(data, now)
        self._poll_quic_events(now)

    def feed_datagram_from_buffer(
        mut self,
        buf: Pointer[UInt8, MutUntrackedOrigin],
        buf_len: Int,
        now: UInt64,
        ecn_mark: UInt8 = UInt8(0),
    ) raises:
        """Feed one inbound QUIC datagram from a mutable buffer pointer.
        Zero-copy variant — buffer is modified in-place."""
        self._quic.recv_from_buffer(buf, buf_len, now, ecn_mark)

        # Bracket the post-recv tail (timeout + poll-loop including _drain_stream).
        # record_pkt at connection.mojo:890 fires INSIDE recv_from_buffer's
        # coalesced-packet for-loop and is bounded by it; this bracket covers
        # the disjoint H3-application-event-drain phase.
        comptime if PROFILE_ACCEPT:
            var t_start: UInt64 = 0
            if self.profile_ptr is not None:
                t_start = monotonic_us()
            self._poll_quic_events(now)
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_quic_post_recv(monotonic_us() - t_start)
        else:
            self._poll_quic_events(now)

    def _poll_quic_events(mut self, now: UInt64) raises:
        """Process pending QUIC timeout and drain application events."""
        var _ct_start = UInt64(0)
        comptime if PROFILE_ACCEPT:
            _ct_start = rdtsc()
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
                var stream_id = ev.payload.unsafe_get[UInt64]()
                if self._is_peer_initiated(stream_id):
                    var sbuf = _H3StreamBuf()
                    sbuf.is_uni = (stream_id & UInt64(0x02)) != 0
                    self._stream_bufs[Int(stream_id)] = sbuf^
            elif ev.type_id == QuicEvent.STREAM_READABLE:
                var stream_id = ev.payload.unsafe_get[UInt64]()
                try:
                    self._drain_stream(stream_id, now)
                except:
                    # Frame parsing and handlers cannot raise (protocol
                    # errors close with their own code), so this is a
                    # broken internal invariant: fail closed rather than
                    # leave the stream half-parsed.
                    self._quic.close_app(H3_INTERNAL_ERROR, "internal error", now)
            elif ev.type_id == QuicEvent.STREAM_RESET:
                ref rst = ev.payload.unsafe_get[StreamResetPayload]()
                self._release_stream(rst.stream_id, now)
                if self._is_request_stream(rst.stream_id):
                    var h3ev = H3Event(H3Event.STREAM_RESET)
                    h3ev.stream_id = rst.stream_id
                    h3ev.error_code = rst.error_code
                    self._h3_events.append(h3ev^)
            elif ev.type_id == QuicEvent.CONNECTION_CLOSED:
                ref cc = ev.payload.unsafe_get[ConnectionClosedPayload]()
                var h3ev = H3Event(H3Event.CONNECTION_CLOSED)
                h3ev.error_code = cc.error_code
                h3ev.reason = cc.reason
                self._h3_events.append(h3ev^)
            elif ev.type_id == QuicEvent.DATAGRAM_RECEIVED:
                self._dispatch_quic_datagram(ev.payload.unsafe_get[List[Byte]]())
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].call_tracker.record(CallId.POLL_QUIC_EVENTS, rdtsc() - _ct_start)

    def drain_datagrams(mut self, now: UInt64) raises -> List[List[Byte]]:
        """Collect UDP payloads until `send()` runs dry or the drain cap hits.

        `QuicConnection.send` emits at most one datagram per call; this
        loop keeps calling it, so a whole response leaves in one drain
        instead of one datagram per received packet. Stopping at
        `MAX_DATAGRAMS_PER_DRAIN` sets `egress_capped`, which the server
        reads through `has_pending_egress()` to schedule the remainder.
        A closing connection yields its CLOSE and nothing more.

        If `send()` raises mid-loop the datagrams already collected are
        dropped: their packets are recorded in the PN spaces and loss
        detection retransmits them, exactly as a single dropped datagram.
        """
        var out = List[List[Byte]](capacity=MAX_DATAGRAMS_PER_DRAIN)
        while len(out) < MAX_DATAGRAMS_PER_DRAIN:
            var n = self._quic.send(now, self._send_scratch)
            if n == 0:
                self.egress_capped = False
                return out^
            for bi in range(n):
                var dg = List[Byte]()
                swap(dg, self._send_scratch[bi])
                out.append(dg^)
            if self._quic.is_closing():
                # One CLOSE per trigger; nothing else may follow it.
                self.egress_capped = False
                return out^
        self.egress_capped = True
        return out^

    # --- Send API ------------------------------------------------------------

    def send_headers(
        mut self, stream_id: UInt64, fields: List[QpackHeaderField], fin: Bool
    ) raises:
        """QPACK-encode fields → HeadersFrame → send_stream_data."""
        var encoded = List[Byte](capacity=len(fields) * 32)
        self._enc.encode(encoded, fields)
        var hf = HeadersFrame(encoded^)
        self._wire_scratch.clear()
        hf.encode(self._wire_scratch)
        self._quic.send_stream_data(stream_id, Span(self._wire_scratch), fin)

    def send_data(
        mut self, stream_id: UInt64, data: List[Byte], fin: Bool
    ) raises:
        """Fuse H3 DATA header with payload in a single QUIC stream write. Empty data + fin=True sends FIN only."""
        if len(data) == 0 and fin:
            var empty = List[Byte]()
            self._quic.send_stream_data(stream_id, Span(empty), True)
            return
        if len(data) == 0:
            return
        self._quic.send_h3_data(stream_id, data, fin)

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
        self._wire_scratch.clear()
        raw.encode(self._wire_scratch)
        self._quic.send_stream_data(self._local_ctrl_sid.value(), Span(self._wire_scratch), False)
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
        mut self, stream_id: UInt64, payload: Span[Byte, _]
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
        var buf = List[Byte](capacity=len(prefix) + len(payload))
        for ref byte in prefix:
            buf.append(byte)
        for ref byte in payload:
            buf.append(byte)
        return self._quic.send_datagram(Span(buf))

    # --- Internal: bootstrap -------------------------------------------------

    def _dispatch_quic_datagram(mut self, payload: List[Byte]):
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
        var rest = List[Byte](capacity=len(payload) - r.pos)
        rest.extend(Span(payload)[r.pos:])
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
        var ctrl_type: List[Byte] = [UInt8(0x00)]
        self._quic.send_stream_data(ctrl_sid, Span(ctrl_type), False)
        var qenc_type: List[Byte] = [UInt8(0x02)]
        self._quic.send_stream_data(qenc_sid, Span(qenc_type), False)
        var qdec_type: List[Byte] = [UInt8(0x03)]
        self._quic.send_stream_data(qdec_sid, Span(qdec_type), False)

        # Send SETTINGS on control stream (RFC 9114 §7.2.4)
        var pairs = List[SettingsPair]()
        pairs.append(SettingsPair(SETTINGS_QPACK_MAX_TABLE_CAPACITY, UInt64(0)))
        pairs.append(SettingsPair(SETTINGS_MAX_FIELD_SECTION_SIZE, UInt64(H3_MAX_FIELD_SECTION_SIZE)))
        # RFC 9297 §2.2 — only advertise H3_DATAGRAM if the caller opted in
        # via `enable_h3_datagrams()`. Default-off keeps SETTINGS wire-byte
        # compatibility with non-MASQUE/WebTransport tests.
        if self._local_h3_datagram_enabled:
            pairs.append(SettingsPair(SETTINGS_H3_DATAGRAM, UInt64(1)))
        var sf = SettingsFrame(pairs^)
        self._wire_scratch.clear()
        sf.encode(self._wire_scratch)
        self._quic.send_stream_data(ctrl_sid, Span(self._wire_scratch), False)

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
        """Read newly contiguous bytes from QUIC and dispatch the frames they complete.

        Work per drain is linear in the bytes drained: frames are parsed
        in place and only an unparsed partial frame is kept (see
        `_H3StreamBuf`). FIN releases the stream's state; FIN inside a
        frame is H3_FRAME_ERROR.
        """
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
        var recv_result: Tuple[List[Byte], Bool]
        try:
            recv_result = self._quic.recv_stream_data(stream_id)
        except:
            # QUIC already reaped the stream: a RESET_STREAM processed after
            # this readable event was queued. Its STREAM_RESET event
            # releases the H3 state.
            return
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_drain_recv_ffi(monotonic_us() - t_start_ffi)

        # B3a entry — wrap from recv_result.copy() through the bidi-check exit.
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                t_start_buf = monotonic_us()

        var new_bytes = List[Byte]()
        swap(new_bytes, recv_result[0])
        var fin = recv_result[1]

        # RFC 9114 Section 6.2: unknown uni stream types are discarded; the
        # QPACK streams carry nothing we act on with a zero-capacity
        # dynamic table. Their bytes are dropped, never buffered.
        if self._stream_bufs[key].discard:
            if fin:
                self._release_stream(stream_id, now)
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    self.profile_ptr.value()[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                    self.profile_ptr.value()[].record_drain_stream(monotonic_us() - t_start_drain)
            return

        # Parse straight out of the received bytes; only a leftover partial
        # frame from the previous drain is prepended.
        var buf = List[Byte]()
        swap(buf, self._stream_bufs[key].buf)
        if len(buf) == 0:
            swap(buf, new_bytes)
        else:
            buf.extend(Span(new_bytes))
        var pos = 0

        # Handle unidirectional stream type byte (first byte = stream type)
        if self._stream_bufs[key].is_uni:
            if not self._stream_bufs[key].type_byte:
                if len(buf) == 0:
                    if fin:
                        self._release_stream(stream_id, now)
                    # B3a + B1 exit (return path 1 — UNI empty buf).
                    comptime if PROFILE_ACCEPT:
                        if self.profile_ptr is not None:
                            self.profile_ptr.value()[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                            self.profile_ptr.value()[].record_drain_stream(monotonic_us() - t_start_drain)
                    return
                var type_byte = buf[0]
                pos = 1
                self._stream_bufs[key].type_byte = Optional[UInt8](type_byte)
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
                    self._stream_bufs[key].discard = True
                elif type_byte == UInt8(0x03):
                    # RFC 9204 §4.2: at most one QPACK decoder stream per peer.
                    var existing_qdec = self._peer_qdec_sid.copy()
                    if self._close_duplicate_uni_stream(existing_qdec^, "qpack decoder", now, t_start_buf, t_start_drain):
                        return
                    self._peer_qdec_sid = Optional[UInt64](stream_id)
                    self._stream_bufs[key].discard = True
                else:
                    self._stream_bufs[key].discard = True
                if self._stream_bufs[key].discard:
                    if fin:
                        self._release_stream(stream_id, now)
                    # B3a + B1 exit (return path 2 — discarded UNI type).
                    comptime if PROFILE_ACCEPT:
                        if self.profile_ptr is not None:
                            self.profile_ptr.value()[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                            self.profile_ptr.value()[].record_drain_stream(monotonic_us() - t_start_drain)
                    return

        # Reject server-initiated bidi from peer (RFC 9114 §6.1)
        if not self._stream_bufs[key].is_uni and self._is_peer_initiated(stream_id) and not self._is_server:
            self._quic.close_app(H3_STREAM_CREATION_ERROR, "server-initiated bidi not supported", now)
            # B3a + B1 exit (return path 3 — bidi rejection).
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    self.profile_ptr.value()[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                    self.profile_ptr.value()[].record_drain_stream(monotonic_us() - t_start_drain)
            return

        # Determine if this is the peer control stream
        var is_ctrl = False
        if self._peer_ctrl_sid:
            if self._peer_ctrl_sid.value() == stream_id:
                is_ctrl = True

        # B3a exit — buf_accumulate phase ends BEFORE parse-loop entry.
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)

        var remaining = self._stream_bufs[key].payload_remaining
        var skipping = self._stream_bufs[key].skipping
        pos = self._parse_frames(stream_id, is_ctrl, buf, pos, remaining, skipping, now)

        # Keep only the unparsed tail. It lies inside one frame that began
        # in this drain or is the previous tail, so copying it is bounded by
        # the bytes drained now.
        var open = (self._quic.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) == 0
        var mid_frame = remaining > 0 or pos < len(buf)
        if open:
            ref sb = self._stream_bufs[key]
            sb.payload_remaining = remaining
            sb.skipping = skipping
            if pos == 0:
                swap(sb.buf, buf)
            elif pos < len(buf):
                sb.buf = List[Byte](capacity=len(buf) - pos)
                sb.buf.extend(Span(buf)[pos:])

        if fin:
            if open and mid_frame:
                # RFC 9114 Section 7.1: a truncated last frame is a
                # connection error, not a complete message.
                self._quic.close_app(H3_FRAME_ERROR, "stream ended inside a frame", now)
            elif open and not self._stream_bufs[key].is_uni:
                var h3ev = H3Event(H3Event.STREAM_ENDED)
                h3ev.stream_id = stream_id
                self._h3_events.append(h3ev^)
            self._release_stream(stream_id, now)

        # B1 exit (fall-through path 4).
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_drain_stream(monotonic_us() - t_start_drain)

    def _release_stream(mut self, stream_id: UInt64, now: UInt64):
        """Forget a stream's receive state once the peer finished or reset it.

        No-op for streams already released. Ending a peer control or QPACK
        stream is a connection error (RFC 9114 Section 6.2.1, RFC 9204
        Section 4.2).
        """
        var key = Int(stream_id)
        _ = self._stream_bufs.pop(key, _H3StreamBuf())
        _ = self._request_headers_seen.pop(key, False)
        if (
            (self._peer_ctrl_sid and self._peer_ctrl_sid.value() == stream_id)
            or (self._peer_qenc_sid and self._peer_qenc_sid.value() == stream_id)
            or (self._peer_qdec_sid and self._peer_qdec_sid.value() == stream_id)
        ):
            self._quic.close_app(H3_CLOSED_CRITICAL_STREAM, "critical stream closed", now)

    def _parse_frames(
        mut self,
        stream_id: UInt64,
        is_ctrl: Bool,
        mut buf: List[Byte],
        start: Int,
        mut remaining: Int,
        mut skipping: Bool,
        now: UInt64,
    ) -> Int:
        """Dispatch every frame `buf[start:]` completes; return the new read position.

        One pass with a read cursor, so the cost is linear in `len(buf)`
        however small the frames. Each header is classified by
        `_payload_action` before any payload is kept: capped frames are
        dispatched once whole, DATA payloads are handed on in chunks as
        they arrive, skipped payloads are dropped, and a rejected header
        closes the connection. Stops at the first incomplete header or
        capped frame, or once the connection starts closing.

        `remaining` / `skipping` carry a streamed or skipped payload across
        drains. When one DATA chunk spans all of `buf`, its storage moves
        into the event and `buf` is left empty (position 0).
        """
        var _ct_start = UInt64(0)
        comptime if PROFILE_ACCEPT:
            _ct_start = rdtsc()
        # Hoisted per-iter clock-read state (Q1 lesson: hoist to function scope, reassign per iter).
        var t_start_parse: UInt64 = 0
        comptime if not PROFILE_ACCEPT:
            _ = t_start_parse
        var pos = start
        while True:
            if (self._quic.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
                break
            var avail = len(buf) - pos
            if avail == 0:
                break

            # Continue a streamed DATA or skipped payload.
            if remaining > 0:
                var n = min(remaining, avail)
                remaining -= n
                if skipping:
                    pos += n
                    continue
                var chunk = List[Byte]()
                if pos == 0 and n == len(buf):
                    swap(chunk, buf)  # whole drain is payload: no copy
                else:
                    chunk.reserve(n)
                    chunk.extend(Span(buf)[pos : pos + n])
                    pos += n
                self._handle_request_frame(stream_id, H3RawFrame(H3_FRAME_DATA, chunk^), now)
                continue

            # B4 entry — wrap the frame-header parse.
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    t_start_parse = monotonic_us()
            var frame_type = UInt64(0)
            var length = UInt64(0)
            var hdr_len = 0
            var ok = True
            try:
                var r = ByteReader(Span(buf)[pos:])
                frame_type = varint_decode(r)
                length = varint_decode(r)
                hdr_len = r.pos
            except:
                ok = False
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    self.profile_ptr.value()[].record_drain_frame_parse(monotonic_us() - t_start_parse)
            if not ok:
                break  # header incomplete

            var action = self._payload_action(frame_type, length, is_ctrl, now)
            if action == _PAYLOAD_REJECT:
                break  # closing: the rest is never parsed
            if action == _PAYLOAD_BUFFER:
                # Capped above, so the Int conversion and sum are safe.
                var n = Int(length)
                if avail - hdr_len < n:
                    break  # payload incomplete
                var payload = List[Byte](capacity=n)
                payload.extend(Span(buf)[pos + hdr_len : pos + hdr_len + n])
                pos += hdr_len + n
                self._dispatch_frame(stream_id, is_ctrl, H3RawFrame(frame_type, payload^), now)
                continue

            # _PAYLOAD_STREAM / _PAYLOAD_SKIP: length is a varint (< 2^62).
            pos += hdr_len
            remaining = Int(length)
            skipping = action == _PAYLOAD_SKIP
            if skipping or length == 0:
                # Skipped frames still reach the handler (type-only checks
                # such as "first control frame must be SETTINGS").
                self._dispatch_frame(stream_id, is_ctrl, H3RawFrame(frame_type, List[Byte]()), now)
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].call_tracker.record(CallId.PARSE_FRAMES, rdtsc() - _ct_start)
        return pos

    def _payload_action(
        mut self, frame_type: UInt64, length: UInt64, is_ctrl: Bool, now: UInt64
    ) -> UInt8:
        """Classify a frame by its header, closing the connection on a bad one.

        Everything decidable from type and length is rejected here, before
        any payload is buffered. Caps mirror quiche: HEADERS above
        `_H3_MAX_HEADERS_PAYLOAD` is H3_EXCESSIVE_LOAD; SETTINGS above 256
        bytes and single-varint frames outside 1..8 bytes are
        H3_FRAME_ERROR. PUSH_PROMISE is never acceptable: servers must not
        receive it, and this client never sends MAX_PUSH_ID. HTTP/2-only
        types are H3_FRAME_UNEXPECTED. HEADERS and DATA on the control
        stream, and unknown types, are skipped: the handler still sees the
        type and rejects the control-stream ones from it alone.
        """
        if frame_type == H3_FRAME_DATA:
            return _PAYLOAD_SKIP if is_ctrl else _PAYLOAD_STREAM
        if frame_type == H3_FRAME_HEADERS:
            if is_ctrl:
                return _PAYLOAD_SKIP
            if length > UInt64(_H3_MAX_HEADERS_PAYLOAD):
                self._quic.close_app(H3_EXCESSIVE_LOAD, "field section too large", now)
                return _PAYLOAD_REJECT
            return _PAYLOAD_BUFFER
        if frame_type == _H3_FRAME_PUSH_PROMISE:
            if self._is_server or is_ctrl:
                self._quic.close_app(H3_FRAME_UNEXPECTED, "PUSH_PROMISE not allowed", now)
            else:
                # RFC 9114 Section 7.2.5: no MAX_PUSH_ID sent, so any push ID is too large.
                self._quic.close_app(H3_ID_ERROR, "PUSH_PROMISE without MAX_PUSH_ID", now)
            return _PAYLOAD_REJECT
        if _is_http2_frame_type(frame_type):
            self._quic.close_app(H3_FRAME_UNEXPECTED, "HTTP/2 frame type", now)
            return _PAYLOAD_REJECT
        if frame_type == H3_FRAME_SETTINGS:
            if length > UInt64(_H3_MAX_SETTINGS_PAYLOAD):
                self._quic.close_app(H3_FRAME_ERROR, "SETTINGS frame too large", now)
                return _PAYLOAD_REJECT
            return _PAYLOAD_BUFFER
        if (
            frame_type == H3_FRAME_GOAWAY
            or frame_type == H3_FRAME_CANCEL_PUSH
            or frame_type == _H3_FRAME_MAX_PUSH_ID
        ):
            if length == 0 or length > UInt64(_H3_MAX_VARINT_FRAME_PAYLOAD):
                self._quic.close_app(H3_FRAME_ERROR, "bad varint frame length", now)
                return _PAYLOAD_REJECT
            return _PAYLOAD_BUFFER
        return _PAYLOAD_SKIP

    def _dispatch_frame(
        mut self, stream_id: UInt64, is_ctrl: Bool, var frame: H3RawFrame, now: UInt64
    ):
        """Route a whole frame to the control- or request-stream handler."""
        if is_ctrl:
            self._handle_control_frame(stream_id, frame^, now)
        else:
            self._handle_request_frame(stream_id, frame^, now)

    def _handle_control_frame(mut self, stream_id: UInt64, var frame: H3RawFrame, now: UInt64):
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
            var peer_settings: SettingsFrame
            try:
                peer_settings = SettingsFrame.decode(frame.payload)
            except:
                self._quic.close_app(H3_FRAME_ERROR, "malformed SETTINGS", now)
                return
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

        elif (
            frame.frame_type == H3_FRAME_GOAWAY
            or frame.frame_type == H3_FRAME_CANCEL_PUSH
            or frame.frame_type == _H3_FRAME_MAX_PUSH_ID
        ):
            var value = _single_varint(frame.payload)
            if not value:
                self._quic.close_app(H3_FRAME_ERROR, "malformed frame payload", now)
                return
            if frame.frame_type == _H3_FRAME_MAX_PUSH_ID and not self._is_server:
                # RFC 9114 Section 7.2.7: only clients send MAX_PUSH_ID.
                self._quic.close_app(H3_FRAME_UNEXPECTED, "MAX_PUSH_ID sent by server", now)
                return
            if frame.frame_type != H3_FRAME_GOAWAY:
                return  # push is never enabled: nothing to cancel or grant
            var last_sid = value.value()
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

    def _handle_request_frame(mut self, stream_id: UInt64, var frame: H3RawFrame, now: UInt64):
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
            var decoded: Optional[List[QpackHeaderField]]
            try:
                decoded = self._dec.decode_bounded(frame.payload, H3_MAX_FIELD_SECTION_SIZE)
            except:
                # RFC 9204 Section 2.2.3 (quiche closes the same way).
                self._quic.close_app(QPACK_DECOMPRESSION_FAILED, "QPACK decompression failed", now)
                return
            if not decoded:
                # RFC 9114 Section 4.2.2 limit we advertised; quiche closes
                # with H3_EXCESSIVE_LOAD too.
                self._quic.close_app(H3_EXCESSIVE_LOAD, "field section too large", now)
                return
            var fields = decoded.unsafe_take()
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
            swap(h3ev.data, frame.payload)
            self._h3_events.append(h3ev^)

        elif (
            frame.frame_type == H3_FRAME_SETTINGS
            or frame.frame_type == H3_FRAME_GOAWAY
            or frame.frame_type == _H3_FRAME_MAX_PUSH_ID
        ):
            # Control-stream only (RFC 9114 Sections 7.2.4, 7.2.6, 7.2.7).
            self._quic.close_app(H3_FRAME_UNEXPECTED, "control frame on request stream", now)
        # else: unknown, ignore
