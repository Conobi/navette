# src/quic/connection.mojo
#
# QuicConnection — sans-I/O QUIC state machine.
#
# Orchestrates packet protection, packet number spaces, loss recovery,
# crypto streams, and the TLS handshake via FFI into librustls_mojo.
#
# Usage:
#   var conn = QuicConnection.client(lib, cfg, "example.com", tp, now)
#   var datagrams = conn.send(now)       # Initial with ClientHello
#   conn.recv(response_bytes, now)       # Feed server reply
#   var ev = conn.poll()                 # HANDSHAKE_COMPLETE, etc.

from std.collections import Dict, Optional
from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.tls.lib import SharedLibrary
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.tls.early_data_store import (
    InMemoryEarlyDataStore, ReplayDecision,
)
from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode, varint_len
from navette.quic.error import QuicTransportError, NO_ERROR, PROTOCOL_VIOLATION, APPLICATION_ERROR
from navette.quic.profile import AcceptProfile, PROFILE_ACCEPT, monotonic_us
from navette.quic.frame import (
    Frame,
    AckFrame,
    CryptoFrame,
    ConnectionCloseFrame,
    StreamFrame,
    ResetStreamFrame,
    StopSendingFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    NewConnectionIdFrame,
    StreamDataBlockedFrame,
    StreamsBlockedFrame,
    parse_frames,
    serialize_frames,
    FRAME_PADDING,
    FRAME_PING,
    FRAME_ACK,
    FRAME_ACK_ECN,
    FRAME_CRYPTO,
    FRAME_CONNECTION_CLOSE_TRANSPORT,
    FRAME_CONNECTION_CLOSE_APP,
    FRAME_HANDSHAKE_DONE,
    FRAME_NEW_TOKEN,
    FRAME_NEW_CONNECTION_ID,
    FRAME_RETIRE_CONNECTION_ID,
    FRAME_STREAM_BASE,
    FRAME_RESET_STREAM,
    FRAME_STOP_SENDING,
    FRAME_MAX_DATA,
    FRAME_MAX_STREAM_DATA,
    FRAME_MAX_STREAMS_BIDI,
    FRAME_MAX_STREAMS_UNI,
    FRAME_DATA_BLOCKED,
    FRAME_STREAM_DATA_BLOCKED,
    FRAME_STREAMS_BLOCKED_BIDI,
    FRAME_STREAMS_BLOCKED_UNI,
)
from navette.quic.stream_map import StreamMap
from navette.quic.guard_predicates import (
    check_long_reserved_bits,
    check_max_streams_value,
    check_new_connection_id_length,
    check_new_connection_id_retire_prior,
    check_streams_blocked_value,
    check_short_reserved_bits,
    stream_offset_exceeds_fc,
    is_client_only_frame_on_server,
    is_path_challenge_in_handshake,
    is_datagram_in_handshake,
    is_crypto_in_zero_rtt,
    is_ack_in_zero_rtt,
    is_unknown_frame_type,
    predicate_f11_no_frames,
    predicate_f15_reset_on_server_uni,
    predicate_f16_stop_sending_local_not_created,
    predicate_f18_f19_max_stream_data,
    MaxStreamDataCtx,
    QuicResetCtx,
    QuicStopSendingCtx,
    ZERO_RTT_SPACE_IDX,
)
from navette.quic.guard_tags import (
    GUARD_TAG_UNKNOWN_FRAME,
    GUARD_TAG_PATH_CHALLENGE_HS,
    GUARD_TAG_DATAGRAM_HS,
    GUARD_TAG_MIGRATION_DISABLED,
    GUARD_TAG_NEW_TOKEN_SERVER,
    GUARD_TAG_HANDSHAKE_DONE_SERVER,
    GUARD_TAG_STREAM_LARGE_OFFSET,
    GUARD_TAG_CRYPTO_IN_ZERO_RTT,
    GUARD_TAG_ACK_IN_ZERO_RTT,
)
from navette.quic.cid import CidManager, CidEntry, CID_ACTIVE, CID_PENDING_RETIRE, CID_RETIRED
from navette.quic.path_validator import PathValidator, PathKey
from navette.quic.stream import (
    Stream, SendBuf, RecvBuf,
    SEND_READY, SEND_SEND, SEND_DATA_SENT, SEND_DATA_RECVD, SEND_RESET_SENT, SEND_RESET_RECVD,
    RECV_RECV, RECV_SIZE_KNOWN, RECV_DATA_RECVD, RECV_DATA_READ, RECV_STOP_SENDING_SENT, RECV_RESET_RECVD, RECV_RESET_READ,
    send_state_is_terminal, recv_state_is_terminal,
    stream_is_bidi, stream_is_local, stream_is_client_initiated,
)
from navette.quic.flow_control import FlowControl
from navette.quic.packet import (
    PacketType,
    PacketHeader,
    parse_packet_header,
    serialize_long_header,
    serialize_short_header,
    pn_decode,
    pn_truncate,
    pn_encode_length,
    MIN_INITIAL_PACKET_SIZE,
)
from navette.quic.trans_param import (
    TransportParams,
    parse_transport_params,
    serialize_transport_params,
    validate_client_transport_params,
)
from navette.tls.guard_tags import (
    GUARD_TAG_TLS_KEYUPDATE_HANDSHAKE,
    GUARD_TAG_TLS_KEYUPDATE_1RTT,
    GUARD_TAG_TLS_NO_ALPN,
    GUARD_TAG_TLS_END_OF_EARLY_DATA,
)
from navette.quic.pn_space import (
    EncryptionLevel,
    packet_type_to_space,
    PacketNumberSpace,
    SentPacket,
)
from navette.quic.recovery import Recovery, K_GRANULARITY
from navette.quic.crypto_stream import CryptoStream
from navette.quic.packet_protect import PacketProtect, ZERO_RTT_KEY_SLOT_IDX
from navette.quic.cc.cc_trait import AckedPacket, LostPacket, PERSISTENT_CONG_THRESHOLD
from navette.quic.ecn import (
    EcnCounts, ECN_NOT_ECT, ECN_ECT0, ECN_ECT1, ECN_CE,
    ECN_STATE_PROBING, ECN_STATE_CAPABLE, ECN_STATE_DISABLED,
)

# ── Connection state bitflags ────────────────────────────────────────

comptime CONN_HANDSHAKING: UInt8 = 0x01
comptime CONN_ESTABLISHED: UInt8 = 0x02
comptime CONN_ADDR_VALIDATED: UInt8 = 0x04
comptime CONN_INITIAL_DISCARDED: UInt8 = 0x08
comptime CONN_HS_DISCARDED: UInt8 = 0x10
comptime CONN_CLOSING: UInt8 = 0x20
comptime CONN_DRAINING: UInt8 = 0x40
comptime CONN_CLOSED: UInt8 = 0x80

# ── Constants ────────────────────────────────────────────────────────

comptime _AEAD_TAG_LEN: Int = 16
comptime _MAX_PN_LEN: Int = 4   # maximum packet-number length (bytes)
comptime _HP_SAMPLE_LEN: Int = 16  # header-protection sample length
comptime ANTI_AMP_HEADER_FUDGE: UInt64 = 100
comptime _WRITE_HS_BUF_SIZE: Int = 4096
comptime _TP_BUF_SIZE: Int = 1024
comptime _MAX_CRYPTO_FRAME_SIZE: Int = 1200

# RFC 9001 §5.7 buffer caps. Per-connection. If a 0-RTT packet would
# exceed either cap, the packet is dropped (§5.7 allows the server
# to discard; no protocol violation).
comptime ZERO_RTT_BUFFER_MAX_PKTS: Int = 16
comptime ZERO_RTT_BUFFER_MAX_BYTES: Int = 32 * 1024  # 32 KiB


# ── TLS alert -> guard-tag mapping ───────────────────────────────────


def _tls_guard_tag_for(
    alert: Int32,
    current_level: Int,
    handshake_confirmed: Bool,
    fallback: String,
) -> String:
    """Map a rustls QUIC alert byte to the matching `GUARD_TAG_TLS_*` token.

    The four C6 scenarios (F25/F26/F27/F29) each have an allowed alert-set
    per the v3.1 spec alert table:

      * F25 (KeyUpdate-in-Handshake) — exact alert 10 (unexpected_message).
      * F26 (KeyUpdate-in-1-RTT) — alert 47 (illegal_parameter) or 50 fallback.
      * F27 (no ALPN) — alert 120 (no_application_protocol) or 50 fallback.
      * F29 (EndOfEarlyData rejection) — alert 10 or 50 fallback.

    Alerts 10 and 50 are ambiguous between two C6 rows, so the helper
    disambiguates by the connection's `current_level` (0=Initial, 1=Handshake,
    2=Application) and the `handshake_confirmed` flag. The mapping is:

      * alert == 120          → NO_ALPN (unique).
      * alert == 47           → KEYUPDATE_1RTT (unique).
      * alert == 10           → KEYUPDATE_HANDSHAKE if Handshake-level,
                                else END_OF_EARLY_DATA.
      * alert == 50 fallback  → KEYUPDATE_HANDSHAKE if Handshake-level,
                                END_OF_EARLY_DATA if handshake_confirmed,
                                else `fallback`.
      * any other alert       → `fallback` (best-effort default).

    `fallback` is passed in by the caller — typically
    `String(GUARD_TAG_TLS_KEYUPDATE_1RTT)` — so the close_transport call
    site keeps the literal token visible for grep-based audits without
    re-exporting every comptime guard tag from this module's helpers.

    The returned `String` is wrapped from the `comptime` literal so callers
    can pass it through `close_transport`'s `reason: String` parameter
    without an extra conversion.
    """
    if alert == Int32(120):
        return String(GUARD_TAG_TLS_NO_ALPN)
    if alert == Int32(47):
        return String(GUARD_TAG_TLS_KEYUPDATE_1RTT)
    if alert == Int32(10):
        if current_level == 1:
            return String(GUARD_TAG_TLS_KEYUPDATE_HANDSHAKE)
        return String(GUARD_TAG_TLS_END_OF_EARLY_DATA)
    # alert == 50 (decode_error) fallback path — pick by level/state.
    if current_level == 1:
        return String(GUARD_TAG_TLS_KEYUPDATE_HANDSHAKE)
    if handshake_confirmed:
        return String(GUARD_TAG_TLS_END_OF_EARLY_DATA)
    return fallback


# ── SentStreamFrame ──────────────────────────────────────────────────
#
# Per-packet record of stream/flow-control/CID frames sent in the Application
# space, used for ACK and loss processing.  STREAM/CRYPTO retransmission
# for Initial/Handshake is still handled via SentPacket.frames.

comptime SSF_STREAM: UInt8 = 0
comptime SSF_RESET_STREAM: UInt8 = 1
comptime SSF_STOP_SENDING: UInt8 = 2
comptime SSF_MAX_DATA: UInt8 = 3
comptime SSF_MAX_STREAM_DATA: UInt8 = 4
comptime SSF_MAX_STREAMS_BIDI: UInt8 = 5
comptime SSF_MAX_STREAMS_UNI: UInt8 = 6
comptime SSF_NEW_CID: UInt8 = 7
comptime SSF_RETIRE_CID: UInt8 = 8


struct SentStreamFrame(Copyable, Movable):
    """Record of a stream-layer frame sent in the Application space.

    Used to re-apply state on ACK (confirm transitions, release FC credit)
    and on loss (re-queue data, clear `advertised`/`needs_*` flags).
    """

    var kind: UInt8
    var stream_id: UInt64
    var offset: UInt64
    var length: UInt64
    var fin: Bool
    var cid_seq: UInt64

    def __init__(out self):
        self.kind = UInt8(0)
        self.stream_id = UInt64(0)
        self.offset = UInt64(0)
        self.length = UInt64(0)
        self.fin = False
        self.cid_seq = UInt64(0)

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.stream_id = other.stream_id
        self.offset = other.offset
        self.length = other.length
        self.fin = other.fin
        self.cid_seq = other.cid_seq

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.stream_id = take.stream_id
        self.offset = take.offset
        self.length = take.length
        self.fin = take.fin
        self.cid_seq = take.cid_seq


# ── QuicEvent ────────────────────────────────────────────────────────


struct QuicEvent(Copyable, Movable):
    """Event emitted by QuicConnection for the application layer."""

    comptime HANDSHAKE_COMPLETE: UInt8 = 1
    comptime CONNECTION_CLOSED: UInt8 = 2
    comptime PEER_TRANSPORT_PARAMS: UInt8 = 3
    comptime STREAM_READABLE: UInt8 = 5
    comptime STREAM_WRITABLE: UInt8 = 6
    comptime STREAM_RESET: UInt8 = 7
    comptime STREAM_STOPPED: UInt8 = 8
    comptime STREAM_OPENED: UInt8 = 9
    # RFC 9221 §5: a QUIC DATAGRAM frame was received and decoded. The
    # payload bytes are owned by the event (in `datagram_payload`) so the
    # caller can drain QuicEvent without re-borrowing into the connection.
    comptime DATAGRAM_RECEIVED: UInt8 = 10

    var type_id: UInt8
    var error_code: UInt64
    var reason: String
    var transport_params: Optional[TransportParams]
    var stream_id: UInt64
    var final_size: UInt64
    # Owned DATAGRAM payload (RFC 9221 §5 received-frame path). Only
    # populated when type_id == DATAGRAM_RECEIVED; the field stays an empty
    # List for every other event kind to keep the struct copyable without
    # an Optional branch in the hot path.
    var datagram_payload: List[UInt8]

    def __init__(out self, type_id: UInt8):
        self.type_id = type_id
        self.error_code = UInt64(0)
        self.reason = String("")
        self.transport_params = None
        self.stream_id = UInt64(0)
        self.final_size = UInt64(0)
        self.datagram_payload = List[UInt8]()

    def __init__(out self, *, other: Self):
        self.type_id = other.type_id
        self.error_code = other.error_code
        self.reason = other.reason
        self.transport_params = other.transport_params.copy()
        self.stream_id = other.stream_id
        self.final_size = other.final_size
        self.datagram_payload = List[UInt8](copy=other.datagram_payload)

    def __init__(out self, *, deinit take: Self):
        self.type_id = take.type_id
        self.error_code = take.error_code
        self.reason = take.reason^
        self.transport_params = take.transport_params^
        self.stream_id = take.stream_id
        self.final_size = take.final_size
        self.datagram_payload = take.datagram_payload^

    @staticmethod
    def handshake_complete() -> QuicEvent:
        return QuicEvent(QuicEvent.HANDSHAKE_COMPLETE)

    @staticmethod
    def connection_closed(error_code: UInt64, reason: String) -> QuicEvent:
        var ev = QuicEvent(QuicEvent.CONNECTION_CLOSED)
        ev.error_code = error_code
        ev.reason = reason
        return ev^

    @staticmethod
    def peer_transport_params(params: TransportParams) -> QuicEvent:
        var ev = QuicEvent(QuicEvent.PEER_TRANSPORT_PARAMS)
        ev.transport_params = TransportParams(other=params)
        return ev^

    @staticmethod
    def stream_readable(stream_id: UInt64) -> QuicEvent:
        var ev = QuicEvent(QuicEvent.STREAM_READABLE)
        ev.stream_id = stream_id
        return ev^

    @staticmethod
    def stream_writable(stream_id: UInt64) -> QuicEvent:
        var ev = QuicEvent(QuicEvent.STREAM_WRITABLE)
        ev.stream_id = stream_id
        return ev^

    @staticmethod
    def stream_reset(stream_id: UInt64, error_code: UInt64, final_size: UInt64) -> QuicEvent:
        var ev = QuicEvent(QuicEvent.STREAM_RESET)
        ev.stream_id = stream_id
        ev.error_code = error_code
        ev.final_size = final_size
        return ev^

    @staticmethod
    def stream_stopped(stream_id: UInt64, error_code: UInt64) -> QuicEvent:
        var ev = QuicEvent(QuicEvent.STREAM_STOPPED)
        ev.stream_id = stream_id
        ev.error_code = error_code
        return ev^

    @staticmethod
    def stream_opened(stream_id: UInt64) -> QuicEvent:
        var ev = QuicEvent(QuicEvent.STREAM_OPENED)
        ev.stream_id = stream_id
        return ev^

    @staticmethod
    def datagram_received(payload: List[UInt8]) -> QuicEvent:
        """RFC 9221 §5 — a peer-sent QUIC DATAGRAM has been parsed.

        `payload` carries the inner bytes of the DATAGRAM frame (no length
        prefix). The event owns its copy of the payload so the caller can
        drain QuicEvent independently from the QuicConnection's frame
        ownership lifetime.
        """
        var ev = QuicEvent(QuicEvent.DATAGRAM_RECEIVED)
        ev.datagram_payload = List[UInt8](copy=payload)
        return ev^


# ── QuicConnection ───────────────────────────────────────────────────


struct QuicConnection(Movable):
    """Sans-I/O QUIC connection state machine.

    Call `send()` to get datagrams to transmit, `recv()` to feed incoming
    datagrams, and `poll()` to retrieve events. Use `timeout()` to
    determine when to next call `send()`.
    """

    var is_server: Bool
    var state: UInt8
    var spaces: List[PacketNumberSpace]
    var crypto_streams: List[CryptoStream]
    var recovery: Recovery
    var protect: PacketProtect
    var conn_handle: Int32
    var _lib: SharedLibrary
    var local_params: TransportParams
    var peer_params: Optional[TransportParams]
    var local_cid: List[UInt8]
    var peer_cid: List[UInt8]
    var initial_dcid: List[UInt8]
    var bytes_received: UInt64
    var bytes_sent: UInt64
    var events: List[QuicEvent]
    var pending_close: Optional[ConnectionCloseFrame]
    var close_timer: UInt64
    var drain_timer: UInt64
    var idle_timer: UInt64
    var handshake_confirmed: Bool
    var current_level: Int
    var send_handshake_done: Bool
    var last_ack_eliciting_send_time: UInt64
    var stream_map: StreamMap
    var cid_mgr: CidManager
    # RFC 9000 §8/§9 path validation state. Holds in-flight PATH_CHALLENGE
    # tokens + the currently validated path.
    var path_validator: PathValidator
    # Pending PATH_CHALLENGE tokens received from the peer that we still
    # need to echo back as PATH_RESPONSE in the next 1-RTT flush. Each
    # entry is the 8-byte data field copied verbatim from the incoming
    # PATH_CHALLENGE; emission + drain happens in `emit_path_response_frames`.
    var pending_path_responses: List[List[UInt8]]
    # RFC 9221 §5 — outbound DATAGRAM frame queue. Each entry is one
    # complete payload (no header bytes). Drained in the 1-RTT branch of
    # `_build_frames_for_space` into DATAGRAM_LEN (0x31) frames so each
    # entry composes cleanly with ACK/STREAM/etc. Per RFC §5.4 entries are
    # NOT retransmitted on loss — once a packet carrying a DATAGRAM is
    # declared lost, the payload is gone (callers MUST handle reliability
    # themselves if they need it).
    var pending_outbound_datagrams: List[List[UInt8]]
    # Current validated peer 4-tuple (RFC 9000 §9). Updated ONLY inside
    # `on_path_response_received` after a verified PATH_RESPONSE token+addr
    # match. The bench-server receive site MUST NOT mutate it
    # directly; all outbound traffic targets this address unless an active
    # validation is rerouting via `path_validator.pending`.
    var peer_addr: PathKey
    # Per-receive cursor: the bench server stamps this with the source
    # address of the datagram currently being fed into `recv_from_buffer`,
    # so `_dispatch_frame` can pass `from_addr` to `on_path_response_received`
    # without changing the recv ABI. Reset semantics are intentionally
    # absent — the value is overwritten on every datagram and read only
    # during PATH_RESPONSE handling.
    var _current_recv_addr: PathKey
    # One-shot guard for the initial NEW_CONNECTION_ID burst (RFC 9000
    # §5.1.1): on the first 1-RTT _build_frames_for_space call after the
    # connection becomes CONN_ESTABLISHED, fill `cid_mgr.local_cids` up
    # to `peer_active_limit`. Subsequent flushes drain
    # `pending_new_cid_entries` normally without re-issuing.
    var initial_cids_emitted: Bool
    # Maps Application-space packet number -> list of stream-layer frames
    # sent in that packet, for ACK/loss processing.
    var app_frames_sent: Dict[Int, List[SentStreamFrame]]
    # ECN path validation state (RFC 9000 §13.4.2, RFC 9002 §7.9).
    var ecn_state: UInt8           # ECN_STATE_PROBING / ECN_STATE_CAPABLE / ECN_STATE_DISABLED
    var ecn_probe_pkts_needed: Int # probe this many ECT(0) packets before validation check
    var ecn_probe_pkts_sent: Int   # ECT(0) packets sent during probing phase
    var ecn_probe_first_pn: UInt64 # PN of first ECT(0) probe packet

    # ── Profile instrumentation (always present; off-build = dead) ──
    #
    # A small struct-layout cost is accepted here. The profile_ptr field
    # is null for non-bench callers (client tests, conformance suite). Server
    # constructors stamp profile_first_initial_us before any FFI call so
    # handshake-latency does not under-report by Initial-key-derivation cost.
    #
    # First-iteration bleed-in semantic: profile_first_iter_done starts False.
    # Iter 1 of recv_from_buffer does NOT reset profile_rustls_us_accum at
    # its top — it inherits the constructor's accumulator (zero for server,
    # Initial-key-derivation cost for client). Iter 2+ resets at top.
    var profile_ptr: Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]]
    var profile_first_initial_us: UInt64
    var profile_rustls_us_accum: UInt64
    var profile_first_iter_done: Bool
    # Non-resetting per-conn FFI accumulator. Increments at the same 3 FFI
    # bracket sites as profile_rustls_us_accum but is NEVER reset at iter
    # boundaries — captures the SUM of all FFI work across the conn up to
    # handshake-complete.
    var fresh_conn_ffi_us_total: UInt64

    # Per-conn read_hs FFI call count. Non-resetting; recorded once at
    # _on_handshake_complete server-side. Distinct from fresh_conn_ffi_us_total
    # (which sums all FFI sub-legs); this counts ONLY read_hs invocations.
    var read_hs_call_count: UInt64

    # Per-conn read_hs sub-leg µs accumulators. Non-resetting; gated by
    # PROFILE_ACCEPT + profile_ptr != 0 at the bracket site. Sums across
    # all read_hs calls in the conn lifetime. output_marshalling is
    # zero-by-design for read_hs (returns status only); slot reserved for
    # future symmetric write_hs/take_keys reuse.
    var read_hs_input_marshalling_us_total: UInt64
    var read_hs_state_machine_us_total: UInt64
    var read_hs_output_alloc_us_total: UInt64
    var read_hs_output_marshalling_us_total: UInt64

    # Per-FD cold-handshake CPU vs wait breakdown.
    var accept_us: UInt64         # server-side conn creation timestamp; 0 for client
    var hs_cpu_us_total: UInt64   # sum of _drive_handshake body µs across conn lifetime
    var hs_wait_us_total: UInt64  # computed once at _on_handshake_complete

    # 0-RTT cached opt-in signal — set once in QuicConnection.server(...)
    # from QuicServerConfig.max_early_data(). False = rejection-mode
    # (Path C in the coalesce loop). Per-packet check reads this Bool
    # instead of crossing the FFI.
    var zero_rtt_enabled: Bool

    # RFC 9001 §5.7 reorder buffer for 0-RTT packets that arrive ahead
    # of the Initial that derives their keys. Bounded by
    # ZERO_RTT_BUFFER_MAX_PKTS (16) AND ZERO_RTT_BUFFER_MAX_BYTES
    # (32 KiB), whichever fills first. Per-connection, not global.
    var zero_rtt_buffer: List[List[UInt8]]
    var zero_rtt_buffer_bytes: Int

    # Set True for the duration of _drain_zero_rtt_buffer. While True,
    # the decrypt-path's Path B fail branch DROPS instead of re-buffering,
    # to prevent unbounded re-entry through the same fail path when rustls
    # still has no early-data secret.
    var _draining_zero_rtt: Bool

    # Tristate that captures the once-per-connection replay decision.
    #   0 = unchecked (initial state)
    #   1 = accepted (allow 0-RTT data through dispatch)
    #   2 = rejected (silent-drop all subsequent 0-RTT; conn stays alive)
    # Production code transitions 0 -> 1 OR 0 -> 2 exactly once. 1 -> x
    # and 2 -> x transitions never occur — committed state is sticky.
    var _zero_rtt_replay_decision: UInt8

    # Optional[UInt64] now-millis override for unit tests. Production
    # callers leave this None; the integration site reads
    # `monotonic_us() // 1000` inline when this field is None. Tests
    # inject deterministic timestamps via direct assignment. A static
    # check in `scripts/check_integrations.sh` asserts assignment to this
    # field never appears outside `tests/`.
    var _zero_rtt_now_ms_override: Optional[UInt64]

    # Optional pointer to the InMemoryEarlyDataStore owned by the
    # QuicServerConfig that birthed this connection. None for clients
    # AND for rejection-mode servers. The pointer is valid for the
    # connection's lifetime because the public surface (H3UdpHandler etc.)
    # keeps the config alive across all conns that reference it. A
    # follow-up change abstracts this via a trait object or
    # tagged-variant wrapper when the public API exposes
    # `EarlyDataPolicy::Custom(store)`.
    var _early_data_store_ptr: Optional[
        UnsafePointer[InMemoryEarlyDataStore, MutAnyOrigin]
    ]

    # Transient: the dispatch-loop space_idx of the packet currently
    # being processed. Set by the per-packet frame-dispatch loop to one
    # of {0=Initial, 1=Handshake, 2=Application/1-RTT, 3=0-RTT sentinel}
    # BEFORE each `_dispatch_frame` call, then reset to -1 AFTER the
    # per-packet frame loop completes. Consumed by `_handle_stream_frame`
    # to tag freshly-created peer-initiated streams with `is_zero_rtt`.
    # Resetting between packets guarantees no per-packet state leaks
    # across packets. NOTE: value 3 is a dispatch sentinel only — do NOT
    # use this field to index `self.spaces[]` (which has 3 entries; see
    # `feedback_zero_rtt_space_idx_vs_pn_space.md`).
    var _current_space_idx: Int

    # ── Move constructor ─────────────────────────────────────────────

    def __init__(out self, *, deinit take: Self):
        self.is_server = take.is_server
        self.state = take.state
        self.spaces = take.spaces^
        self.crypto_streams = take.crypto_streams^
        self.recovery = take.recovery^
        self.protect = take.protect^
        self.conn_handle = take.conn_handle
        self._lib = take._lib^
        self.local_params = take.local_params^
        self.peer_params = take.peer_params^
        self.local_cid = take.local_cid^
        self.peer_cid = take.peer_cid^
        self.initial_dcid = take.initial_dcid^
        self.bytes_received = take.bytes_received
        self.bytes_sent = take.bytes_sent
        self.events = take.events^
        self.pending_close = take.pending_close^
        self.close_timer = take.close_timer
        self.drain_timer = take.drain_timer
        self.idle_timer = take.idle_timer
        self.handshake_confirmed = take.handshake_confirmed
        self.current_level = take.current_level
        self.send_handshake_done = take.send_handshake_done
        self.last_ack_eliciting_send_time = take.last_ack_eliciting_send_time
        self.stream_map = take.stream_map^
        self.cid_mgr = take.cid_mgr^
        self.path_validator = take.path_validator^
        self.pending_path_responses = take.pending_path_responses^
        self.pending_outbound_datagrams = take.pending_outbound_datagrams^
        self.peer_addr = take.peer_addr^
        self._current_recv_addr = take._current_recv_addr^
        self.initial_cids_emitted = take.initial_cids_emitted
        self.app_frames_sent = take.app_frames_sent^
        self.ecn_state = take.ecn_state
        self.ecn_probe_pkts_needed = take.ecn_probe_pkts_needed
        self.ecn_probe_pkts_sent = take.ecn_probe_pkts_sent
        self.ecn_probe_first_pn = take.ecn_probe_first_pn
        self.profile_ptr = take.profile_ptr
        self.profile_first_initial_us = take.profile_first_initial_us
        self.profile_rustls_us_accum = take.profile_rustls_us_accum
        self.profile_first_iter_done = take.profile_first_iter_done
        self.fresh_conn_ffi_us_total = take.fresh_conn_ffi_us_total
        self.read_hs_call_count = take.read_hs_call_count
        self.read_hs_input_marshalling_us_total = take.read_hs_input_marshalling_us_total
        self.read_hs_state_machine_us_total = take.read_hs_state_machine_us_total
        self.read_hs_output_alloc_us_total = take.read_hs_output_alloc_us_total
        self.read_hs_output_marshalling_us_total = take.read_hs_output_marshalling_us_total
        self.accept_us = take.accept_us
        self.hs_cpu_us_total = take.hs_cpu_us_total
        self.hs_wait_us_total = take.hs_wait_us_total
        self.zero_rtt_enabled = take.zero_rtt_enabled
        self.zero_rtt_buffer = take.zero_rtt_buffer^
        self.zero_rtt_buffer_bytes = take.zero_rtt_buffer_bytes
        self._draining_zero_rtt = take._draining_zero_rtt
        self._zero_rtt_replay_decision = take._zero_rtt_replay_decision
        self._zero_rtt_now_ms_override = take._zero_rtt_now_ms_override^
        self._early_data_store_ptr = take._early_data_store_ptr^
        self._current_space_idx = take._current_space_idx

    # ── Private constructor (used by factory methods) ────────────────

    def __init__(
        out self,
        is_server: Bool,
        lib: SharedLibrary,
        conn_handle: Int32,
        local_params: TransportParams,
        local_cid: List[UInt8],
        peer_cid: List[UInt8],
        initial_dcid: List[UInt8],
        now: UInt64,
    ) raises:
        self.is_server = is_server
        self.state = CONN_HANDSHAKING
        self.spaces = List[PacketNumberSpace](capacity=3)
        self.spaces.append(PacketNumberSpace(EncryptionLevel.initial()))
        self.spaces.append(PacketNumberSpace(EncryptionLevel.handshake()))
        self.spaces.append(PacketNumberSpace(EncryptionLevel.application()))
        self.crypto_streams = List[CryptoStream](capacity=3)
        self.crypto_streams.append(CryptoStream())
        self.crypto_streams.append(CryptoStream())
        self.crypto_streams.append(CryptoStream())
        self.recovery = Recovery()
        self.protect = PacketProtect(lib)
        self.conn_handle = conn_handle
        self._lib = SharedLibrary(other=lib)
        self.local_params = TransportParams(other=local_params)
        self.peer_params = None
        self.local_cid = List[UInt8](copy=local_cid)
        self.peer_cid = List[UInt8](copy=peer_cid)
        self.initial_dcid = List[UInt8](copy=initial_dcid)
        self.bytes_received = UInt64(0)
        self.bytes_sent = UInt64(0)
        self.events = List[QuicEvent]()
        self.pending_close = None
        self.close_timer = UInt64(0)
        self.drain_timer = UInt64(0)
        self.idle_timer = now
        self.handshake_confirmed = False
        self.current_level = 0
        self.send_handshake_done = False
        self.last_ack_eliciting_send_time = UInt64(0)
        self.ecn_state = ECN_STATE_PROBING
        self.ecn_probe_pkts_needed = 10
        self.ecn_probe_pkts_sent = 0
        self.ecn_probe_first_pn = UInt64(0)
        self.profile_ptr = None
        self.profile_first_initial_us = UInt64(0)
        self.profile_rustls_us_accum = UInt64(0)
        self.profile_first_iter_done = False
        self.fresh_conn_ffi_us_total = UInt64(0)
        self.read_hs_call_count = UInt64(0)
        self.read_hs_input_marshalling_us_total = UInt64(0)
        self.read_hs_state_machine_us_total = UInt64(0)
        self.read_hs_output_alloc_us_total = UInt64(0)
        self.read_hs_output_marshalling_us_total = UInt64(0)
        self.accept_us = UInt64(0)
        self.hs_cpu_us_total = UInt64(0)
        self.hs_wait_us_total = UInt64(0)
        # 0-RTT defaults: rejection-mode (False) until the server factory
        # promotes via QuicServerConfig.max_early_data(). Clients never
        # enable today. Buffer is empty; not draining.
        self.zero_rtt_enabled = False
        self.zero_rtt_buffer = List[List[UInt8]]()
        self.zero_rtt_buffer_bytes = 0
        self._draining_zero_rtt = False
        # Anti-replay tristate defaults: 0 = unchecked. Time-override seam
        # and store pointer default to None — the server factory promotes
        # the store pointer when 0-RTT is opted-in.
        self._zero_rtt_replay_decision = UInt8(0)
        self._zero_rtt_now_ms_override = None
        self._early_data_store_ptr = None
        # Transient packet-dispatch space index; -1 outside the
        # frame-dispatch loop. Bookended by set/reset in the loop body
        # so 0-RTT-origin tagging fires only for streams created from
        # actual 0-RTT-decrypted packets (RFC 9001 §4.6).
        self._current_space_idx = -1
        self.stream_map = StreamMap(
            is_server=is_server,
            conn_recv_limit=local_params.initial_max_data,
            conn_recv_window=local_params.initial_max_data,
            conn_send_limit=UInt64(0),
            local_max_streams_bidi=local_params.initial_max_streams_bidi,
            local_max_streams_uni=local_params.initial_max_streams_uni,
            local_window_bidi_local=local_params.initial_max_stream_data_bidi_local,
            local_window_bidi_remote=local_params.initial_max_stream_data_bidi_remote,
            local_window_uni=local_params.initial_max_stream_data_uni,
        )
        self.cid_mgr = CidManager(
            lib=self._lib,
            initial_local_cid=List[UInt8](copy=local_cid),
            initial_remote_cid=List[UInt8](copy=peer_cid),
            local_active_limit=UInt64(2),
            peer_active_limit=UInt64(2),
        )
        self.path_validator = PathValidator()
        self.pending_path_responses = List[List[UInt8]]()
        self.pending_outbound_datagrams = List[List[UInt8]]()
        # Sentinel zero PathKey — overwritten by the bench server on the
        # first ingress datagram (and on every PATH_RESPONSE-validated
        # migration). family=0 never matches AF_INET (2) or AF_INET6 (10),
        # so the first observed source addr always lights up the
        # address-change branch in the receive site (which then promotes
        # `peer_addr` via the validation path, not direct mutation).
        self.peer_addr = PathKey.zero()
        self._current_recv_addr = PathKey.zero()
        self.initial_cids_emitted = False
        self.app_frames_sent = Dict[Int, List[SentStreamFrame]]()

    # ── Destructor ───────────────────────────────────────────────────

    def __del__(deinit self):
        if self.conn_handle >= 0:
            _ = self._lib.inner_ptr()[].quic_conn_free(self.conn_handle)
        # PacketProtect.__del__ handles key cleanup.

    # ── Static factory methods ───────────────────────────────────────

    @staticmethod
    def client(
        lib: SharedLibrary,
        ref config: QuicClientConfig,
        server_name: String,
        local_params: TransportParams,
        now: UInt64,
    ) raises -> QuicConnection:
        """Create a QUIC client connection.

        Derives initial keys, creates TLS connection, and drives the
        initial write_hs to generate ClientHello CRYPTO data.
        """
        var config_handle = config.handle()
        # 1. Generate random 8-byte DCID and local CID.
        var dcid = _generate_random_cid()
        var local_cid = _generate_random_cid()

        # 2. Serialize local transport params.
        var tp_writer = ByteWriter()
        var params_copy = TransportParams(other=local_params)
        params_copy.initial_scid = List[UInt8](copy=local_cid)
        _apply_m3c_defaults(params_copy)
        serialize_transport_params(params_copy, tp_writer)
        var tp_bytes = tp_writer.finish()

        # 3. Create QUIC client TLS connection.
        var sni_bytes = server_name.as_bytes()
        var sni_len = len(sni_bytes)
        var sni_buf = _heap_alloc[UInt8](sni_len).as_unsafe_any_origin()
        for i in range(sni_len):
            sni_buf[i] = sni_bytes[i]

        var tp_len = len(tp_bytes)
        var tp_buf = _heap_alloc[UInt8](tp_len).as_unsafe_any_origin()
        for i in range(tp_len):
            tp_buf[i] = tp_bytes[i]

        var out_handle = _heap_alloc[Int32](1).as_unsafe_any_origin()
        out_handle[0] = Int32(-1)

        var rlib = lib.inner_ptr()
        var rc = rlib[].quic_client_conn_new(
            config_handle,
            Int32(1),  # QUIC version 1
            sni_buf,
            Int32(sni_len),
            tp_buf,
            Int32(tp_len),
            out_handle,
        )

        sni_buf.free()
        tp_buf.free()

        if rc < 0:
            var err = rlib[].last_error()
            out_handle.free()
            raise "quic_client_conn_new failed: " + err

        var conn_handle = out_handle[0]
        out_handle.free()

        if conn_handle < 0:
            raise "quic_client_conn_new returned invalid handle"

        # 4. Build connection object.
        var conn = QuicConnection(
            is_server=False,
            lib=lib,
            conn_handle=conn_handle,
            local_params=params_copy,
            local_cid=local_cid,
            peer_cid=dcid,
            initial_dcid=dcid,
            now=now,
        )

        # 5. Derive initial keys from DCID (client side).
        conn.protect.derive_initial_keys(Span(dcid), is_client=True)

        # 6. Drive initial write_hs to get ClientHello CRYPTO data.
        conn._drive_handshake(now)

        return conn^

    @staticmethod
    def server(
        lib: SharedLibrary,
        ref config: QuicServerConfig,
        local_params: TransportParams,
        orig_dcid: Span[UInt8, _],
        client_dcid: Span[UInt8, _],
        now: UInt64,
        profile_ptr: Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]] = None,
    ) raises -> QuicConnection:
        """Create a QUIC server connection.

        Derives initial keys from the client's DCID and waits for
        the client Initial to drive the handshake.
        """
        var config_handle = config.handle()
        # Stamp arrival timestamp BEFORE any FFI call so that
        # handshake-latency does not under-report by Initial-key-derivation.
        # The stamp is unconditional (8 bytes).
        var profile_arrival_us = monotonic_us()

        # 1. Generate random 8-byte local CID (server's SCID).
        var local_cid = _generate_random_cid()

        # 2. Serialize local transport params.
        var tp_writer = ByteWriter()
        var params_copy = TransportParams(other=local_params)
        params_copy.initial_scid = List[UInt8](copy=local_cid)
        _apply_m3c_defaults(params_copy)
        # Server sets original_dcid to prove it received the client's Initial.
        var orig_dcid_list = List[UInt8](capacity=len(orig_dcid))
        for i in range(len(orig_dcid)):
            orig_dcid_list.append(orig_dcid[i])
        params_copy.original_dcid = orig_dcid_list^
        serialize_transport_params(params_copy, tp_writer)
        var tp_bytes = tp_writer.finish()

        # 3. Create QUIC server TLS connection.
        var tp_len = len(tp_bytes)
        var tp_buf = _heap_alloc[UInt8](tp_len).as_unsafe_any_origin()
        for i in range(tp_len):
            tp_buf[i] = tp_bytes[i]

        var out_handle = _heap_alloc[Int32](1).as_unsafe_any_origin()
        out_handle[0] = Int32(-1)

        var rlib = lib.inner_ptr()
        # alloc_tls_handle_us bracket — rustls TLS session alloc FFI call.
        var t_tls_start: UInt64 = 0
        comptime if PROFILE_ACCEPT:
            t_tls_start = monotonic_us()
        var rc = rlib[].quic_server_conn_new(
            config_handle,
            Int32(1),  # QUIC version 1
            tp_buf,
            Int32(tp_len),
            out_handle,
        )
        comptime if PROFILE_ACCEPT:
            if profile_ptr is not None:
                profile_ptr.value()[].record_alloc_tls_handle_us(monotonic_us() - t_tls_start)

        tp_buf.free()

        if rc < 0:
            var err = rlib[].last_error()
            out_handle.free()
            raise "quic_server_conn_new failed: " + err

        var conn_handle = out_handle[0]
        out_handle.free()

        if conn_handle < 0:
            raise "quic_server_conn_new returned invalid handle"

        # 4. Build peer_cid from orig_dcid.
        var peer_cid = List[UInt8](capacity=len(orig_dcid))
        for i in range(len(orig_dcid)):
            peer_cid.append(orig_dcid[i])

        # 5. Build initial_dcid from client_dcid.
        var initial_dcid = List[UInt8](capacity=len(client_dcid))
        for i in range(len(client_dcid)):
            initial_dcid.append(client_dcid[i])

        # 6. Build connection object.
        var conn = QuicConnection(
            is_server=True,
            lib=lib,
            conn_handle=conn_handle,
            local_params=params_copy,
            local_cid=local_cid,
            peer_cid=peer_cid,
            initial_dcid=initial_dcid,
            now=now,
        )


        # Plan B: thread profile_ptr + stamp arrival timestamp into the
        # newly-constructed connection.
        conn.profile_ptr = profile_ptr
        conn.profile_first_initial_us = profile_arrival_us
        conn.accept_us = profile_arrival_us  # reuse already-stamped arrival time; is_server=True

        # Cache the server config's 0-RTT opt-in signal once. The per-packet
        # decrypt path reads `conn.zero_rtt_enabled` instead of re-crossing
        # the FFI on every datagram. rustls QUIC constrains the value to
        # {0, 0xFFFFFFFF}; any non-zero value means "0-RTT opt-in".
        conn.zero_rtt_enabled = (config.max_early_data() != UInt32(0))

        # Promote the QuicServerConfig._early_data_store handle into a raw
        # pointer the decrypt path can call into without crossing the FFI.
        # The pointer is valid for the connection's lifetime because
        # QuicConnection.server(...) takes `ref config` and the public
        # surface keeps the config alive across all connections that
        # reference it. `rebind` lifts the inferred config-bound origin to
        # `MutAnyOrigin` so the pointer can be stored in the connection's
        # erased field (matches the existing `profile_ptr` shape).
        if config._early_data_store is not None:
            var store_ptr = rebind[
                UnsafePointer[InMemoryEarlyDataStore, MutAnyOrigin]
            ](UnsafePointer(to=config._early_data_store.value()))
            conn._early_data_store_ptr = Optional[
                UnsafePointer[InMemoryEarlyDataStore, MutAnyOrigin]
            ](store_ptr)

        comptime if PROFILE_ACCEPT:
            if profile_ptr is not None:
                profile_ptr.value()[].record_handshake_arrival()

        # 7. Derive initial keys from client's DCID (server side).
        conn.protect.derive_initial_keys(client_dcid, is_client=False)

        # 8. Server address validation deferred until Handshake decrypt.

        return conn^

    # ── Receive path ─────────────────────────────────────────────────

    def recv(mut self, datagram: Span[UInt8, _], now: UInt64,
             ecn_mark: UInt8 = UInt8(0)) raises:
        """Process an incoming UDP datagram (Span convenience wrapper)."""
        var n = len(datagram)
        if n == 0:
            return
        var buf = _heap_alloc[UInt8](n).as_unsafe_any_origin()
        for i in range(n):
            buf[i] = datagram[i]
        try:
            self.recv_from_buffer(buf, n, now, ecn_mark)
        except e:
            buf.free()
            raise e.copy()
        buf.free()

    def recv_from_buffer(
        mut self,
        buf: UnsafePointer[UInt8, MutAnyOrigin],
        buf_len: Int,
        now: UInt64,
        ecn_mark: UInt8 = UInt8(0),
    ) raises:
        """Process an incoming UDP datagram from a mutable buffer.

        Zero-copy variant: operates directly on the caller's buffer for
        header unprotection and payload decryption, eliminating intermediate
        copies where possible.
        """
        # Plan B: per-iteration phase timestamps. Always-declared in
        # off-build (compiler folds unused locals); only written by
        # the @parameter if PROFILE_ACCEPT branches.
        var t_iter_start = UInt64(0)
        var ph_header_parse_us = UInt64(0)
        var ph_hp_us = UInt64(0)
        var ph_aead_us = UInt64(0)
        var ph_frame_parse_us = UInt64(0)
        var ph_sm_us = UInt64(0)

        self.bytes_received += UInt64(buf_len)
        self.idle_timer = now

        # Track the lowest encryption level at which we process a packet
        # in this datagram, used for implicit CRYPTO retransmission below.
        var lowest_recv_space = 3  # sentinel: nothing processed yet

        var offset = 0
        while offset < buf_len:
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    t_iter_start = monotonic_us()
                    if self.profile_first_iter_done:
                        self.profile_rustls_us_accum = UInt64(0)
                    # Iter 1: do NOT reset; bleed in constructor cost.


            # Skip datagram-level zero padding (RFC 9000 §12.4).
            # A zero first byte is never a valid QUIC packet (long headers
            # require bit 7, short headers require bit 6).
            if buf[offset] == 0:
                break

            var remaining_len = buf_len - offset
            var remaining_ptr = buf + offset

            # 2. Parse packet header from a Span backed by the caller's
            # buffer directly. The prior implementation copied
            # `remaining_ptr[0..remaining_len]` into a `List[UInt8]` to
            # construct a Span — once per coalesced QUIC packet. Eliminated
            # via `Span[UInt8, MutAnyOrigin](ptr=remaining_ptr, length=remaining_len)`
            # since `parse_packet_header` only reads the buffer.
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    ph_header_parse_us = monotonic_us()
            var header_result = parse_packet_header(
                Span[UInt8, MutAnyOrigin](ptr=remaining_ptr, length=remaining_len),
                len(self.local_cid),
            )
            var header = header_result[0].copy()
            var header_end = header_result[1]
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    ph_header_parse_us = monotonic_us() - ph_header_parse_us

            # 2b. Adopt peer's SCID as peer_cid (RFC 9000 §7.2).
            if header.is_long_header and len(header.scid) > 0:
                if header.packet_type == PacketType.initial():
                    self.peer_cid = List[UInt8](copy=header.scid)

            # 2c. 0-RTT detection — runs BEFORE packet_type_to_space() so
            # we can override space_idx with ZERO_RTT_SPACE_IDX on every
            # 0-RTT path. The F30 guard (CRYPTO-in-0-RTT →
            # PROTOCOL_VIOLATION) fires off space_idx regardless of
            # whether the decrypt itself succeeded.
            #
            # Three paths (RFC 9001 §4.2, §4.6, §5.5, §5.7):
            #   A. Slot 3 keys already installed — fall through to the
            #      standard decrypt continuation with space_idx =
            #      ZERO_RTT_SPACE_IDX (3, NOT the Application PN space 2;
            #      the dispatch sentinel is what makes the F30 guard fire
            #      on CRYPTO frames in 0-RTT).
            #   B. Slot 3 empty AND 0-RTT enabled by config — lazy-install
            #      via the server FFI. On success: fall through. On
            #      failure (rc=1 keys-not-yet-available, or an rc=-1 FFI
            #      raise — both folded into the same path): buffer the
            #      packet (unless we are already draining, in which case
            #      silent-drop) and skip ahead.
            #   C. 0-RTT disabled by config (max_early_data == 0) —
            #      rejection mode: skip past the packet boundary so
            #      coalesced packets after it are still processed.
            var space_idx: Int = -1
            if header.is_long_header and header.packet_type == PacketType.zero_rtt():
                var skip = header.pn_offset + Int(header.payload_length)
                if skip > remaining_len:
                    break  # Truncated

                if self.protect.has_keys(ZERO_RTT_KEY_SLOT_IDX):
                    # Keys installed; decrypt through slot 3.
                    space_idx = ZERO_RTT_SPACE_IDX
                elif self._zero_rtt_enabled():
                    # Path B — lazy install. Buffer-or-drop on fail.
                    # An rc=-1 FFI raise (anomalous handle/state) folds
                    # into the same failure handling as the rc=1
                    # keys-not-yet-available return: no exception from
                    # 0-RTT key installation propagates out of
                    # recv_from_buffer, and non-0-RTT coalesced packets
                    # in the same datagram keep processing.
                    var ok = False
                    try:
                        ok = self.protect.install_zero_rtt_read_keys(
                            self.conn_handle
                        )
                    except:
                        # ok keeps its False initializer — failure path.
                        pass
                    comptime if PROFILE_ACCEPT:
                        if self.profile_ptr is not None:
                            self.profile_ptr.value()[].record_zero_rtt_install(ok)
                    if ok:
                        space_idx = ZERO_RTT_SPACE_IDX
                    else:
                        if not self._draining_zero_rtt:
                            var pkt_bytes = Span[UInt8, MutAnyOrigin](
                                ptr=remaining_ptr,
                                length=skip,
                            )
                            _ = self._buffer_zero_rtt_or_drop(pkt_bytes)
                        # drain-mode: silent drop.
                        offset += skip
                        continue
                else:
                    # Path C — 0-RTT disabled. Preserve rejection-mode skip.
                    offset += skip
                    continue

                # ──────────────────────────────────────────────────────
                # Anti-replay check (RFC 9001 §9.2 + RFC 8446 §8).
                # Fires AT MOST ONCE per connection; the tristate guards
                # subsequent 0-RTT packets so each one inherits the
                # decision without re-crossing the FFI or store.
                # ──────────────────────────────────────────────────────
                if self._zero_rtt_replay_decision == UInt8(0):
                    var auth_buf = InlineArray[UInt8, 32](fill=UInt8(0))
                    var auth_len = UInt(0)
                    var rc = self._invoke_replay_authenticator_ffi(
                        auth_buf, auth_len,
                    )

                    if rc != Int32(0):
                        # FFI anomaly: 0-RTT keys installed but no
                        # authenticator reachable. Fail closed without
                        # discarding the keys — subsequent 0-RTT packets
                        # short-circuit through Path A.
                        self._zero_rtt_replay_decision = UInt8(2)
                        self._record_replay_reject_no_authenticator()
                    elif self._early_data_store_ptr is None:
                        # 0-RTT enabled at config level but the store
                        # pointer never got promoted (defensive — should
                        # not occur). Fail closed.
                        self._zero_rtt_replay_decision = UInt8(2)
                        self._record_replay_reject_no_authenticator()
                    else:
                        var auth_span = Span[UInt8, MutAnyOrigin](
                            ptr=auth_buf.unsafe_ptr(), length=32,
                        )
                        var now_ms: UInt64
                        if self._zero_rtt_now_ms_override is not None:
                            now_ms = self._zero_rtt_now_ms_override.value()
                        else:
                            now_ms = monotonic_us() // UInt64(1_000)
                        var raised = False
                        var decision = ReplayDecision.accept()
                        try:
                            var store_ptr = self._early_data_store_ptr.value()
                            decision = store_ptr[].check_and_record(
                                auth_span, now_ms
                            )
                        except:
                            raised = True
                        if raised:
                            self._zero_rtt_replay_decision = UInt8(2)
                            self._record_replay_reject_no_authenticator()
                        elif decision.is_accept():
                            self._zero_rtt_replay_decision = UInt8(1)
                            self._record_replay_accept()
                        elif decision.is_duplicate():
                            self._zero_rtt_replay_decision = UInt8(2)
                            self._record_replay_reject_duplicate()
                        elif decision.is_per_key_quota():
                            self._zero_rtt_replay_decision = UInt8(2)
                            self._record_replay_reject_per_key_quota()
                        else:  # is_global_ceiling
                            self._zero_rtt_replay_decision = UInt8(2)
                            self._record_replay_reject_global_ceiling()

                if self._zero_rtt_replay_decision == UInt8(2):
                    # Silent-drop: advance past this 0-RTT packet, keep
                    # the connection alive (RFC 9001 §4.1). We do NOT
                    # call _discard_zero_rtt_keys here; the slot stays
                    # populated so subsequent 0-RTT packets short-circuit
                    # through Path A and never repopulate
                    # `zero_rtt_install_successes`. HANDSHAKE_DONE clears
                    # the slot via `_discard_zero_rtt_keys`.
                    offset += skip
                    continue
                # else: tristate == 1 (accept) — fall through to the
                # standard decrypt continuation below.
            else:
                # 3. Map to PN space (non-0-RTT path).
                space_idx = packet_type_to_space(header.packet_type)

            if space_idx < 0:
                break  # VN, Retry — skip (no packet-number space)

            # Explicit dispatch-space → key-slot mapping. The 0-RTT
            # dispatch sentinel (ZERO_RTT_SPACE_IDX) and the 0-RTT key
            # slot (ZERO_RTT_KEY_SLOT_IDX) are independent constants
            # that happen to share the value 3 today; mapping by
            # identity (never by numeric coincidence) means either
            # constant can move without silently breaking the other.
            var key_slot: Int
            if space_idx == ZERO_RTT_SPACE_IDX:
                key_slot = ZERO_RTT_KEY_SLOT_IDX
            else:
                key_slot = space_idx

            if not self.protect.has_keys(key_slot):
                # No keys for this level. For long-header packets we can
                # compute the packet boundary and skip to the next coalesced
                # packet (RFC 9000 §12.2). Short headers consume the rest.
                if header.is_long_header:
                    var skip = header.pn_offset + Int(header.payload_length)
                    if skip > remaining_len:
                        break  # Truncated
                    offset += skip
                    continue
                break

            # 4. Determine packet boundary.
            var pkt_len: Int
            if header.is_long_header:
                pkt_len = header.pn_offset + Int(header.payload_length)
            else:
                pkt_len = remaining_len

            if pkt_len > remaining_len:
                break  # Truncated packet

            # 5. Use buffer directly — no pkt_buf copy needed.
            var pkt_ptr = remaining_ptr

            # 6-12. Decrypt and process. On failure, stop processing
            # remaining coalesced packets (RFC 9000 §12.2).
            var decrypt_ok = True
            try:
                # 6. Unprotect header in-place (zero-copy).
                comptime if PROFILE_ACCEPT:
                    if self.profile_ptr is not None:
                        ph_hp_us = monotonic_us()
                var hp_result = self.protect.unprotect_header_ptr(
                    key_slot, pkt_ptr, pkt_len, header.pn_offset
                )
                comptime if PROFILE_ACCEPT:
                    if self.profile_ptr is not None:
                        ph_hp_us = monotonic_us() - ph_hp_us
                var first_byte = hp_result[0]
                var pn_length = hp_result[1]

                # F12 / F14 — RFC 9000 §17.2 / §17.3.1: header reserved
                # bits MUST be 0 after header protection is removed. Long
                # headers use mask 0x0C; 1-RTT (short) headers use mask
                # 0x18. Close with PROTOCOL_VIOLATION on any set bit; the
                # outer try/except would otherwise swallow a raise.
                if header.is_long_header:
                    var _f12_verdict = check_long_reserved_bits(first_byte)
                    if _f12_verdict:
                        var _v12 = _f12_verdict.value().copy()
                        self.close_transport(_v12.error_code, _v12.tag, now)
                        return
                else:
                    var _f14_verdict = check_short_reserved_bits(first_byte)
                    if _f14_verdict:
                        var _v14 = _f14_verdict.value().copy()
                        self.close_transport(_v14.error_code, _v14.tag, now)
                        return

                # 7. Decode packet number.
                # `space_idx` is the DISPATCH sentinel for 0-RTT. RFC
                # 9000 §12.3 places 0-RTT and 1-RTT in the same Application
                # PN space, so the PN bookkeeping uses index 2 for both.
                # `pn_space_idx` is the valid `self.spaces[]` index; only
                # the F30-dispatch code path keeps the sentinel value.
                # Identity comparison, not magnitude — the sentinel's
                # numeric value is free as long as it avoids 0..2.
                var pn_space_idx = 2 if space_idx == ZERO_RTT_SPACE_IDX else space_idx
                var truncated_pn = UInt64(0)
                for i in range(pn_length):
                    truncated_pn = (truncated_pn << 8) | UInt64(
                        pkt_ptr[header.pn_offset + i]
                    )
                var largest = UInt64(0)
                if self.spaces[pn_space_idx].largest_recv_pn >= 0:
                    largest = UInt64(self.spaces[pn_space_idx].largest_recv_pn)
                var full_pn = pn_decode(truncated_pn, pn_length, largest)

                # 8. Decrypt payload in-place (zero-copy).
                var header_len = header.pn_offset + pn_length
                comptime if PROFILE_ACCEPT:
                    if self.profile_ptr is not None:
                        ph_aead_us = monotonic_us()
                var plaintext_len = self.protect.decrypt_payload_in_place(
                    key_slot, full_pn, header_len, pkt_ptr, pkt_len
                )
                comptime if PROFILE_ACCEPT:
                    if self.profile_ptr is not None:
                        ph_aead_us = monotonic_us() - ph_aead_us

                # 9. Server validates address on first Handshake decrypt.
                if self.is_server and space_idx == 1 and (self.state & CONN_ADDR_VALIDATED) == 0:
                    self.state = self.state | CONN_ADDR_VALIDATED

                # 10. Parse and dispatch frames from a Span backed by the
                # caller's buffer directly. The prior implementation copied
                # `pkt_ptr[header_len .. header_len+plaintext_len]` into a
                # `List[UInt8]` — once per coalesced QUIC packet. Eliminated
                # via `Span[UInt8, MutAnyOrigin](ptr=pkt_ptr+header_len, length=plaintext_len)`
                # since ByteReader / parse_frames are generic over origin.
                comptime if PROFILE_ACCEPT:
                    if self.profile_ptr is not None:
                        ph_frame_parse_us = monotonic_us()
                var reader = ByteReader(
                    Span[UInt8, MutAnyOrigin](ptr=pkt_ptr + header_len, length=plaintext_len)
                )
                # F10 — RFC 9000 §12.4: any parse failure inside a packet
                # already authenticated by AEAD is FRAME_ENCODING_ERROR.
                # Without this inner try/except, the outer catch swallows
                # the raise and the server silently drops the packet; the
                # peer keeps the connection alive expecting a CC.
                var frames = List[Frame]()
                var _f10_parse_failed = False
                try:
                    frames = parse_frames(reader)
                except:
                    _f10_parse_failed = True
                if _f10_parse_failed:
                    self.close_transport(
                        UInt64(0x07), String(GUARD_TAG_UNKNOWN_FRAME), now
                    )
                    return
                # F11 — RFC 9000 §12.4: a packet containing no frames is a
                # PROTOCOL_VIOLATION. Use close_transport instead of raising
                # so the connection-level CONNECTION_CLOSE is queued; the
                # outer for-loop over coalesced packets is aborted via the
                # existing `decrypt_ok = False` short-circuit at line ~1005.
                var _f11_verdict = predicate_f11_no_frames(len(frames))
                if _f11_verdict:
                    var _v11 = _f11_verdict.value().copy()
                    self.close_transport(_v11.error_code, _v11.tag, now)
                    return
                var ack_eliciting = False
                # Bookend the per-packet space_idx around the per-frame
                # loop. `_handle_stream_frame` (invoked deep inside
                # `_dispatch_frame`) consumes this to tag newly-created
                # peer-initiated streams at insertion-time. Resetting AFTER
                # the loop guarantees no per-packet state leaks into the
                # next packet's dispatch.
                self._current_space_idx = space_idx
                for i in range(len(frames)):
                    if frames[i].is_ack_eliciting():
                        ack_eliciting = True
                    self._dispatch_frame(frames[i], space_idx, now)
                self._current_space_idx = -1
                comptime if PROFILE_ACCEPT:
                    if self.profile_ptr is not None:
                        ph_frame_parse_us = monotonic_us() - ph_frame_parse_us

                # 11. Update PN space — `pn_space_idx` collapses the 0-RTT
                # dispatch sentinel (3) onto the Application PN space (2)
                # per RFC 9000 §12.3.
                self.spaces[pn_space_idx].on_packet_received(full_pn, ack_eliciting)

                # ECN accounting: count marks seen on received packets.
                if self.ecn_state != ECN_STATE_DISABLED:
                    if ecn_mark == ECN_CE:
                        self.spaces[pn_space_idx].recv_ecn.ce += UInt64(1)
                    elif ecn_mark == ECN_ECT0:
                        self.spaces[pn_space_idx].recv_ecn.ect0 += UInt64(1)
                    elif ecn_mark == ECN_ECT1:
                        self.spaces[pn_space_idx].recv_ecn.ect1 += UInt64(1)

                # Track lowest processed space for retransmission logic.
                # Use `pn_space_idx` so 0-RTT (sentinel 3) doesn't widen
                # the tracker beyond the valid Application PN space.
                if pn_space_idx < lowest_recv_space:
                    lowest_recv_space = pn_space_idx
            except e:
                # Decryption or frame processing failed for this packet.
                # Per RFC 9000 §12.2, stop processing remaining coalesced
                # packets (they may use keys we don't have yet).
                _ = e
                decrypt_ok = False

            # 12. Drive handshake OUTSIDE try/except so TLS errors
            # propagate to the caller (they are fatal, not recoverable).
            if decrypt_ok:
                comptime if PROFILE_ACCEPT:
                    if self.profile_ptr is not None:
                        ph_sm_us = monotonic_us()
                self._drive_handshake(now)
                # RFC 9001 §5.7 — replay any 0-RTT packets that arrived
                # ahead of the Initial that derives their keys.
                # Idempotent (empty-buffer no-op); the re-entry guard
                # inside the drain prevents Path B from re-buffering its
                # own drained packets.
                self._drain_zero_rtt_buffer(now, ecn_mark)
                comptime if PROFILE_ACCEPT:
                    if self.profile_ptr is not None:
                        ph_sm_us = monotonic_us() - ph_sm_us

            if not decrypt_ok:
                break  # Stop processing coalesced packets

            # Plan B: emit per-packet record at iteration end. Bleed-in:
            # iter 1 inherits constructor's profile_rustls_us_accum.
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    var t_iter_end = monotonic_us()
                    var total_us = t_iter_end - t_iter_start
                    self.profile_ptr.value()[].record_pkt(
                        total_us=total_us,
                        ffi_us=self.profile_rustls_us_accum,
                        hp_us=ph_hp_us,
                        aead_us=ph_aead_us,
                        header_parse_us=ph_header_parse_us,
                        frame_parse_us=ph_frame_parse_us,
                        sm_us=ph_sm_us,
                    )
                    self.profile_first_iter_done = True

            offset += pkt_len

        # Implicit CRYPTO retransmission (RFC 9002 §6.2.4 spirit).
        # When we receive a packet at a lower encryption level than one
        # where we have unacked CRYPTO, the peer likely did not get our
        # higher-level response.  Re-queue unacked CRYPTO data so the
        # next send() retransmits it.  This is critical for the server
        # which cannot PTO while amplification-limited.
        if lowest_recv_space < 3:
            for s in range(lowest_recv_space + 1, 3):
                if not self.protect.has_keys(s):
                    continue
                if len(self.crypto_streams[s].send_buf) > 0:
                    continue
                if len(self.spaces[s].sent_packets) == 0:
                    continue
                for entry in self.spaces[s].sent_packets.items():
                    for fi in range(len(entry.value.frames)):
                        if entry.value.frames[fi].is_crypto():
                            if entry.value.frames[fi]._crypto:
                                var cf = entry.value.frames[fi]._crypto.value().copy()
                                self.crypto_streams[s].requeue(
                                    cf.offset, Span(cf.data)
                                )

    # ── Stream frame handlers ────────────────────────────────────────

    def _handle_stream_frame(mut self, stream_frame: StreamFrame) raises:
        """Process an incoming STREAM frame (RFC 9000 §19.8)."""
        var stream_id = stream_frame.stream_id
        var offset = stream_frame.offset
        var data_len = UInt64(len(stream_frame.data))
        var fin = stream_frame.fin

        # 1. Create peer stream if needed.
        var key = Int(stream_id)
        if key not in self.stream_map.streams:
            if stream_is_local(stream_id, self.is_server):
                raise "PROTOCOL_VIOLATION: frame for unknown locally-initiated stream"
            var new_ids = self.stream_map.get_or_create_peer_stream(stream_id)
            # Tag every freshly-created peer-initiated stream with the
            # current packet's dispatch space_idx. `_current_space_idx`
            # is bookended by the per-packet dispatch loop; this branch
            # only runs the FIRST time a key appears in `streams`, so
            # `is_zero_rtt` is set ONCE at insertion-time and the
            # monotonic-once invariant holds for the stream's lifetime
            # (existing streams skip this branch entirely on subsequent
            # STREAM frames). RFC 9001 §4.6 / RFC 8470.
            var is_zr = (self._current_space_idx == ZERO_RTT_SPACE_IDX)
            for i in range(len(new_ids)):
                self.events.append(QuicEvent.stream_opened(new_ids[i]))
                var nkey = Int(new_ids[i])
                if nkey in self.stream_map.streams:
                    var s = Stream(other=self.stream_map.streams[nkey])
                    s.is_zero_rtt = is_zr
                    self.stream_map.streams[nkey] = s^

        # 2. Get stream (returns a copy).
        var stream = self.stream_map.get_stream(key)

        # 3. Validate direction: no incoming STREAM on a local uni stream.
        if not stream.is_bidi and stream.is_local:
            raise "STREAM_STATE_ERROR: incoming STREAM frame on local uni stream"

        # 4. Validate recv state: must be in RECV or SIZE_KNOWN.
        if not stream.recv_state:
            raise "STREAM_STATE_ERROR: no recv state"
        var rs = stream.recv_state.value()
        if rs != RECV_RECV and rs != RECV_SIZE_KNOWN:
            # Terminal or post-reset — silently drop.
            return

        # 5. Per-stream flow-control enforcement.
        if not stream.fc_recv:
            raise "internal: missing fc_recv"
        var fc_r = stream.fc_recv.value().copy()
        # F01 — RFC 9000 §4.1: a STREAM frame whose offset+data_len
        # exceeds the per-stream flow-control window MUST close the
        # connection with FLOW_CONTROL_ERROR. Saturating-overflow inputs
        # (`offset + data_len < offset`) are also covered by the
        # predicate.
        if stream_offset_exceeds_fc(offset, data_len, fc_r.limit):
            self.close_transport(
                UInt64(0x03),  # FLOW_CONTROL_ERROR
                String(GUARD_TAG_STREAM_LARGE_OFFSET),
                monotonic_us(),
            )
            return

        # 6. Write to the receive buffer (may update stream.fin_offset).
        if not stream.recv_buf:
            raise "internal: missing recv_buf"
        var rb = stream.recv_buf.value().copy()
        var new_bytes = rb.write(
            offset, Span(stream_frame.data), fin, stream.fin_offset
        )

        # 7. Track highest offset observed on this stream.
        var prev_highest = stream.recv_highest_offset
        if offset + data_len > prev_highest:
            stream.recv_highest_offset = offset + data_len

        # 8. Connection-level flow-control check.
        if not self.stream_map.conn_fc_recv.check_limit(new_bytes):
            raise "FLOW_CONTROL_ERROR: connection FC exceeded"

        # 9. Bump FC counters.
        fc_r.add_received(new_bytes)
        self.stream_map.conn_fc_recv.add_received(new_bytes)

        # 10. Emit readable event if data is now deliverable.
        var had_readable = rb.has_readable()
        stream.recv_buf = rb^
        stream.fc_recv = fc_r^

        if had_readable:
            self.events.append(QuicEvent.stream_readable(stream_id))

        # 11. Recv-state transitions on FIN.
        if fin:
            if rs == RECV_RECV:
                stream.recv_state = Optional[UInt8](RECV_SIZE_KNOWN)
                rs = RECV_SIZE_KNOWN
            if rs == RECV_SIZE_KNOWN:
                # rb is already the pre-write reference reassigned above;
                # use stream.recv_buf to check completeness.
                if stream.recv_buf.value().is_complete(stream.fin_offset):
                    stream.recv_state = Optional[UInt8](RECV_DATA_RECVD)

        self.stream_map.set_stream(key, stream^)

    def _handle_reset_stream(mut self, reset_frame: ResetStreamFrame) raises:
        """Process an incoming RESET_STREAM frame (RFC 9000 §19.4)."""
        # F15 — RESET on a server-uni stream is illegal: the peer cannot
        # RESET a stream where this endpoint is the sender (§19.4 + §3.2).
        var _f15_ctx = QuicResetCtx(
            stream_id=reset_frame.stream_id,
            local_uni_opened=self.stream_map.local_opened_uni,
            local_bidi_opened=self.stream_map.local_opened_bidi,
        )
        var _f15_verdict = predicate_f15_reset_on_server_uni(_f15_ctx)
        if _f15_verdict:
            var v = _f15_verdict.value().copy()
            self.close_transport(v.error_code, v.tag, monotonic_us())
            return

        var stream_id = reset_frame.stream_id
        var error_code = reset_frame.error_code
        var final_size = reset_frame.final_size

        var key = Int(stream_id)
        if key not in self.stream_map.streams:
            if stream_is_local(stream_id, self.is_server):
                raise "PROTOCOL_VIOLATION: RESET for unknown local stream"
            var new_ids = self.stream_map.get_or_create_peer_stream(stream_id)
            for i in range(len(new_ids)):
                self.events.append(QuicEvent.stream_opened(new_ids[i]))

        var stream = self.stream_map.get_stream(key)
        if not stream.recv_state:
            raise "STREAM_STATE_ERROR: RESET on non-recv stream"

        # Validate final_size invariants.
        if final_size < stream.recv_highest_offset:
            raise "FINAL_SIZE_ERROR: final_size < received"
        if stream.fin_offset:
            if final_size != stream.fin_offset.value():
                raise "FINAL_SIZE_ERROR: final_size differs from FIN"

        if stream.fc_recv:
            if final_size > stream.fc_recv.value().limit:
                raise "FLOW_CONTROL_ERROR: RESET final_size exceeds stream limit"

        var rs = stream.recv_state.value()
        var was_complete = (rs == RECV_DATA_RECVD or rs == RECV_DATA_READ)

        # Account phantom bytes at connection level (bytes the peer implicitly
        # "sent" by claiming final_size without delivering them).
        var phantom = final_size - stream.recv_highest_offset
        if phantom > 0:
            if not self.stream_map.conn_fc_recv.check_limit(phantom):
                raise "FLOW_CONTROL_ERROR: conn FC exceeded on phantom bytes"
            self.stream_map.conn_fc_recv.add_received(phantom)
            self.stream_map.conn_fc_recv.add_consumed(phantom)

        if not stream.fin_offset:
            stream.fin_offset = Optional[UInt64](final_size)

        # Suppress RESET state transition when DATA_RECVD: RFC 9000 §3.2 lets
        # us keep delivering the fully-received stream to the application.
        if not was_complete:
            stream.recv_state = Optional[UInt8](RECV_RESET_RECVD)
            stream.reset_error = Optional[UInt64](error_code)

        self.events.append(
            QuicEvent.stream_reset(stream_id, error_code, final_size)
        )
        self.stream_map.set_stream(key, stream^)
        _ = self.stream_map.maybe_cleanup(key)

    def _handle_stop_sending(mut self, stop_frame: StopSendingFrame) raises:
        """Process an incoming STOP_SENDING frame (RFC 9000 §19.5)."""
        # F16 — STOP_SENDING for an uncreated locally-initiated stream is
        # STREAM_STATE_ERROR. Predicate keys on the stream-id suffix and
        # the local-opened watermarks for each (uni, bidi) class.
        var _f16_ctx = QuicStopSendingCtx(
            stream_id=stop_frame.stream_id,
            local_uni_opened=self.stream_map.local_opened_uni,
            local_bidi_opened=self.stream_map.local_opened_bidi,
        )
        var _f16_verdict = predicate_f16_stop_sending_local_not_created(_f16_ctx)
        if _f16_verdict:
            var v = _f16_verdict.value().copy()
            self.close_transport(v.error_code, v.tag, monotonic_us())
            return

        var stream_id = stop_frame.stream_id
        var error_code = stop_frame.error_code

        var key = Int(stream_id)
        if key not in self.stream_map.streams:
            if stream_is_local(stream_id, self.is_server):
                raise "PROTOCOL_VIOLATION: STOP_SENDING for unknown local stream"
            var new_ids = self.stream_map.get_or_create_peer_stream(stream_id)
            for i in range(len(new_ids)):
                self.events.append(QuicEvent.stream_opened(new_ids[i]))

        var stream = self.stream_map.get_stream(key)
        if not stream.send_state:
            raise "STREAM_STATE_ERROR: STOP_SENDING targets non-send side"

        var ss = stream.send_state.value()
        if ss == SEND_RESET_SENT or ss == SEND_RESET_RECVD or ss == SEND_DATA_RECVD:
            self.stream_map.set_stream(key, stream^)
            return

        # Transition to RESET_SENT and queue a RESET_STREAM for the send path.
        stream.send_state = Optional[UInt8](SEND_RESET_SENT)
        stream.stop_error = Optional[UInt64](error_code)
        stream.needs_reset_stream = True
        stream.reset_stream_error = error_code
        var final_size: UInt64 = 0
        if stream.send_buf:
            var sb = stream.send_buf.value().copy()
            if sb.fin_offset:
                final_size = sb.fin_offset.value()
            else:
                final_size = sb.unsent_offset
        stream.reset_stream_final_size = final_size

        self.stream_map.remove_sendable(key)

        self.events.append(QuicEvent.stream_stopped(stream_id, error_code))
        self.stream_map.set_stream(key, stream^)
        _ = self.stream_map.maybe_cleanup(key)

    # ── Path validation RX handlers ──────────────────────────────────

    def on_path_challenge_received(
        mut self, data: Span[UInt8, _], now: UInt64
    ):
        """Stash the 8-byte challenge to echo back as PATH_RESPONSE next flush.

        RFC 9000 §8.2: a PATH_RESPONSE MUST be sent on the same path the
        PATH_CHALLENGE was received, with the same 8-byte data. A later
        commit drains `pending_path_responses` during 1-RTT emission;
        this RX-only commit just records the pending response.
        """
        var copy = List[UInt8](capacity=len(data))
        for i in range(len(data)):
            copy.append(data[i])
        self.pending_path_responses.append(copy^)

    def on_path_response_received(
        mut self, data: Span[UInt8, _], var from_addr: PathKey, now: UInt64
    ) raises:
        """Validate a PATH_RESPONSE and, on match, swap the validated path.

        RFC 9000 §8.2: the 8-byte data MUST match a pending challenge AND
        the response MUST arrive from the address the challenge targeted.
        Non-matches are silently dropped (no error, no state change).

        On a successful match `path_validator.on_response` removes the
        challenge from the pending list and records the new `current`
        ValidatedPath. RFC 9000 §9.5 then MANDATES that the server switch
        to a fresh DCID on the new path — reusing the same DCID across
        paths makes the connection trivially linkable. We therefore call
        `_rotate_to_spare_remote_cid` to advance `cid_mgr.remote_active_cid_seq`
        to an unused Active remote CID (queuing RETIRE_CONNECTION_ID for
        the previous sequence). If no spare exists, the validation result
        is deferred: `peer_addr` does NOT swap, and the client
        must issue a NEW_CONNECTION_ID before the migration can complete.
        """
        var maybe = self.path_validator.on_response(
            data, PathKey(other=from_addr), now
        )
        if not Bool(maybe):
            return  # silent drop — RFC 9000 §8.2 token/addr mismatch.

        # CID rotation per RFC 9000 §9.5 (MUST NOT reuse DCID on different
        # paths). Failure to find a spare defers the validation: the new
        # path is held back until the peer supplies a fresh NEW_CID.
        var rotated = self._rotate_to_spare_remote_cid(now)
        if not rotated:
            return

        # Promotion: the validated path is now the active peer addr. This
        # is the ONLY site that mutates `peer_addr`.
        self.peer_addr = from_addr^

    def _rotate_to_spare_remote_cid(mut self, now: UInt64) raises -> Bool:
        """Switch to a spare Active remote CID and queue RETIRE_CID for the old one.

        Walks `cid_mgr.remote_cids` for an Active entry whose sequence
        differs from the currently-active one. On success, updates
        `remote_active_cid_seq` and re-queues the previous sequence via
        `requeue_retire` (which respects `retire_queue_cap`). Returns
        True iff a spare was found.

        Caller: `on_path_response_received` after a verified match.
        """
        var current_seq = self.cid_mgr.remote_active_cid_seq
        for i in range(len(self.cid_mgr.remote_cids)):
            ref entry = self.cid_mgr.remote_cids[i]
            if entry.state == CID_ACTIVE and entry.sequence != current_seq:
                self.cid_mgr.remote_active_cid_seq = entry.sequence
                # Queue RETIRE_CONNECTION_ID for the OLD seq so the peer
                # can free the slot. requeue_retire respects the cap.
                self.cid_mgr.requeue_retire(current_seq)
                return True
        return False

    # ── Path validation TX (emission) ────────────────────────────────

    def emit_path_response_frames(mut self) raises -> List[Frame]:
        """Drain `pending_path_responses` into PATH_RESPONSE frames.

        RFC 9000 §8.2: a PATH_RESPONSE MUST be sent on the same path the
        PATH_CHALLENGE was received with the same 8-byte data. Called by
        the 1-RTT frame builder; one frame per pending response. The
        queue is fully drained on each call — the caller is responsible
        for queueing for retransmission if loss is detected (PATH_RESPONSE
        is not ack-eliciting per §13.2.1 footnote but practical stacks
        re-emit on no-progress).
        """
        var out = List[Frame]()
        for i in range(len(self.pending_path_responses)):
            var data = List[UInt8](copy=self.pending_path_responses[i])
            out.append(Frame.path_response(data^))
        # Drain the queue: every pending response was just turned into a
        # frame, so the queue is empty until the next inbound challenge.
        self.pending_path_responses = List[List[UInt8]]()
        return out^

    def emit_path_challenge_frames(mut self, now: UInt64) raises -> List[Frame]:
        """Build PATH_CHALLENGE frames for every pending challenge.

        For C3 we emit one frame per pending challenge per flush,
        regardless of `attempts`; retransmission timing + the §8.2 cap
        of 3 attempts land in C5 alongside the loss-detector wiring.
        The caller is expected to have just appended a fresh challenge
        via `start_path_challenge` (or the future address-change site).
        """
        var out = List[Frame]()
        for i in range(len(self.path_validator.pending)):
            var token = List[UInt8](copy=self.path_validator.pending[i].token)
            out.append(Frame.path_challenge(token^))
        return out^

    def start_path_challenge(
        mut self, var target: PathKey, now: UInt64
    ) raises:
        """Begin path validation for `target`.

        Generates an 8-byte token via `PathValidator.start_challenge`; the
        next 1-RTT flush emits a PATH_CHALLENGE frame with that token.
        The bench receive site calls this on detected address-change for
        any source addr that does not already have a pending challenge.
        """
        _ = self.path_validator.start_challenge(target^, now)

    def has_pending_path_challenge(self, target: PathKey) -> Bool:
        """True iff a PathChallenge with `target == target` is in `pending`.

        Used by the bench receive site to suppress duplicate challenges
        on rapid-fire packets from the same unvalidated address.
        """
        for i in range(len(self.path_validator.pending)):
            var t = PathKey(other=self.path_validator.pending[i].target)
            if t == target:
                return True
        return False

    def set_current_recv_addr(mut self, var addr: PathKey):
        """Stamp the per-receive source-address cursor before feeding a datagram.

        The bench server's UDP receive site calls this immediately before
        `feed_datagram_from_buffer`, so the connection's PATH_RESPONSE
        handler (invoked from `_dispatch_frame`) can match the response
        token against the address that carried the response. Decoupled
        from the recv ABI to avoid threading PathKey through every layer
        of `recv_from_buffer` -> `_dispatch_frame`.
        """
        self._current_recv_addr = addr^

    def on_ingress_from(
        mut self, var from_addr: PathKey, datagram_len: Int, now: UInt64
    ) raises:
        """Handle the per-datagram address-change + anti-amp bookkeeping.

        Called by the bench receive site BEFORE feeding the datagram into
        `recv_from_buffer`. Three responsibilities:

          1. **Path-change detection** (RFC 9000 §9). If the source addr
             differs from the currently validated `peer_addr` AND the
             server advertised `disable_active_migration=True`, close
             with PROTOCOL_VIOLATION per §9 ¶last (no silent drop — that
             strands the connection on a dead path).

          2. **Path-challenge initiation**. If migration is allowed and
             no challenge is already pending for this addr, generate one;
             the next 1-RTT flush emits the PATH_CHALLENGE.

          3. **Per-path anti-amp accounting** (RFC 9000 §8.1). If this
             addr has a pending challenge, credit the received bytes to
             its `bytes_received` so subsequent sends can stay within the
             3× budget. (The validated path has no per-path counter.)

        `set_current_recv_addr` must be called separately so the inner
        `_dispatch_frame` can match PATH_RESPONSE arrivals; this method
        focuses on the ingress-side bookkeeping that runs before recv.

        Returns immediately if the connection is already closing /
        draining / closed (no point starting a new challenge on a dying
        conn).
        """
        if (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
            return

        # 1. Address change vs the currently validated path. The sentinel
        # zero PathKey (family=0) never matches a real peer (family=2 or
        # 10), so the very first ingress from a fresh server connection
        # looks like an address change. To avoid spurious challenges
        # mid-handshake, we only honour migration after CONN_ESTABLISHED
        # (per spec non-goal: mid-handshake migration drops to current
        # behaviour). Before establishment the bench server stamps the
        # peer addr directly via `bootstrap_peer_addr` instead.
        if not (from_addr == self.peer_addr):
            if (self.state & CONN_ESTABLISHED) == 0:
                # Pre-handshake: silently track the addr via the cursor
                # only. `bootstrap_peer_addr` is what promotes it.
                pass
            elif self.local_params.disable_active_migration:
                # RFC 9000 §9 ¶last: any address change on a connection
                # that advertised `disable_active_migration=True` is a
                # PROTOCOL_VIOLATION (0x0A). Close instead of silently
                # dropping (which would strand the connection on a dead
                # path).
                self.close_transport(
                    UInt64(0x0A),
                    String(GUARD_TAG_MIGRATION_DISABLED),
                    now,
                )
                return
            else:
                # Active migration allowed: initiate path validation for
                # the new addr unless we already have a challenge in
                # flight for it.
                var probe = PathKey(other=from_addr)
                if not self.has_pending_path_challenge(probe):
                    self.start_path_challenge(probe^, now)

        # 2. Per-path anti-amp credit. record_received_bytes is a no-op
        # if `from_addr` has no pending challenge (i.e. it IS the
        # validated path); the validated path is not anti-amp constrained.
        self.path_validator.record_received_bytes(from_addr, datagram_len)

    def bootstrap_peer_addr(mut self, var addr: PathKey):
        """Seed `peer_addr` to the first observed source address.

        Called by the bench server exactly once per connection — when a
        new conn slot is allocated for an incoming Initial — so the
        sentinel `PathKey.zero()` is replaced with a real 4-tuple before
        any address-change check runs. This is the ONLY caller path that
        sets `peer_addr` outside of `on_path_response_received`; this is
        permitted because the "validated path" at handshake start is
        defined as the address that carried the client's Initial (the
        connection IS that path until migration begins).
        """
        self.peer_addr = addr^

    def can_send_to(self, target: PathKey, n_bytes: Int) -> Bool:
        """Anti-amp gate (RFC 9000 §8.1) for outbound traffic to `target`.

        Returns True if the connection may emit `n_bytes` more on the
        path to `target`. Delegates to `PathValidator.can_send_bytes`:

          * Pending (unvalidated) paths use the per-path 3× budget.
          * The validated path (and any addr unknown to the validator)
            returns True — no anti-amp gate.

        Caller (the bench flusher) MUST follow a successful send with
        `record_send_to` so the per-path counter advances.
        """
        return self.path_validator.can_send_bytes(target, n_bytes)

    def record_send_to(mut self, target: PathKey, n_bytes: Int):
        """Credit `n_bytes` to the per-path `bytes_sent` counter for `target`.

        See `can_send_to`. No-op if `target` has no pending challenge.
        """
        self.path_validator.record_sent_bytes(target, n_bytes)

    # ── Frame dispatch ───────────────────────────────────────────────

    def _dispatch_frame(
        mut self, frame: Frame, space_idx: Int, now: UInt64
    ) raises:
        """Route a parsed frame to its handler."""
        var tid = frame.type_id

        # F13 — RFC 9000 §17.2.4: PATH_CHALLENGE / PATH_RESPONSE are only
        # permitted in 1-RTT (space 2). In Initial/Handshake epochs the
        # peer MUST not send them; close with PROTOCOL_VIOLATION. This is
        # placed before the per-frame dispatch arms because PATH_CHALLENGE
        # currently falls through to the trailing silent-drop.
        if is_path_challenge_in_handshake(tid, space_idx):
            self.close_transport(
                UInt64(0x0A), String(GUARD_TAG_PATH_CHALLENGE_HS), now
            )
            return

        # RFC 9221 §5: DATAGRAM (0x30) / DATAGRAM_LEN (0x31) are 1-RTT only.
        # Receipt in Initial (0) or Handshake (1) is PROTOCOL_VIOLATION.
        # Placed alongside the path-challenge gate because the DATAGRAM
        # parse arms below assume 1-RTT space.
        if is_datagram_in_handshake(tid, space_idx):
            self.close_transport(
                UInt64(0x0A), String(GUARD_TAG_DATAGRAM_HS), now
            )
            return

        # F30 — RFC 9001 §8.3: CRYPTO frames MUST NOT be sent in 0-RTT.
        # The shared Application PN space (RFC 9000 §12.3) means the 0-RTT
        # epoch is signalled to dispatch via the `ZERO_RTT_SPACE_IDX`
        # sentinel rather than the regular 0/1/2 space index — see
        # `guard_predicates.is_crypto_in_zero_rtt`. CRYPTO frames in
        # 1-RTT (space 2) remain legal (e.g. NewSessionTicket).
        if is_crypto_in_zero_rtt(tid, space_idx):
            self.close_transport(
                UInt64(0x0A), String(GUARD_TAG_CRYPTO_IN_ZERO_RTT), now
            )
            return

        # RFC 9000 §12.4 (Table 3): ACK / ACK_ECN are forbidden in 0-RTT
        # packets. Must fire before the ACK dispatch arm below — without
        # this guard `_handle_ack` would index `spaces[]` with the
        # `ZERO_RTT_SPACE_IDX` sentinel, out of bounds.
        if is_ack_in_zero_rtt(tid, space_idx):
            self.close_transport(
                UInt64(0x0A), String(GUARD_TAG_ACK_IN_ZERO_RTT), now
            )
            return

        # PADDING: no-op
        if tid == FRAME_PADDING:
            return

        # PING: no-op (ack_eliciting tracked by caller)
        if tid == FRAME_PING:
            return

        # ACK
        if tid == FRAME_ACK or tid == FRAME_ACK_ECN:
            if frame._ack:
                var ack_frame = frame._ack.value().copy()
                self._handle_ack(ack_frame, space_idx, now)
            return

        # CRYPTO
        if tid == FRAME_CRYPTO:
            if frame._crypto:
                var cf = frame._crypto.value().copy()
                self.crypto_streams[space_idx].receive(
                    cf.offset, Span(cf.data)
                )
            return

        # CONNECTION_CLOSE
        if tid == FRAME_CONNECTION_CLOSE_TRANSPORT or tid == FRAME_CONNECTION_CLOSE_APP:
            if frame._conn_close:
                var cc = frame._conn_close.value().copy()
                self.state = self.state | CONN_DRAINING
                # Start drain timer: 3 * PTO.
                var pto = self.recovery.pto_timeout(
                    self.local_params.max_ack_delay * 1000
                )
                self.drain_timer = now + 3 * pto
                # Build reason string from bytes.
                var reason = String("")
                for i in range(len(cc.reason)):
                    reason += chr(Int(cc.reason[i]))
                self.events.append(
                    QuicEvent.connection_closed(cc.error_code, reason)
                )
            return

        # HANDSHAKE_DONE (client receives from server)
        # F24 — RFC 9000 §19.20: HANDSHAKE_DONE is server-to-client only.
        # A server receiving it MUST close with PROTOCOL_VIOLATION.
        if tid == FRAME_HANDSHAKE_DONE:
            if self.is_server:
                self.close_transport(
                    UInt64(0x0A), String(GUARD_TAG_HANDSHAKE_DONE_SERVER), now
                )
                return
            self.handshake_confirmed = True
            self.state = self.state | CONN_ESTABLISHED
            self._discard_handshake_space()
            # RFC 9001 §4.1.2 / §4.1.3 — HANDSHAKE_DONE confirms the handshake
            # on the client side WITHOUT going through _on_handshake_complete,
            # so the client-arm discard hook there is unreachable on this
            # (primary) client trajectory. Wire the discard here too. No-op
            # on the client today because slot 3 is unpopulated on clients;
            # required for symmetry with the decrypt-path discard if a
            # future client-side install ever lands.
            self._discard_zero_rtt_keys()
            self.events.append(QuicEvent.handshake_complete())
            return

        # NEW_TOKEN: minimal handling on client (ignored).
        # F17 — RFC 9000 §19.7: NEW_TOKEN is server-to-client only. A server
        # receiving NEW_TOKEN MUST close with PROTOCOL_VIOLATION.
        if tid == FRAME_NEW_TOKEN:
            if self.is_server:
                self.close_transport(
                    UInt64(0x0A), String(GUARD_TAG_NEW_TOKEN_SERVER), now
                )
                return
            return

        # NEW_CONNECTION_ID: validate encoding, then hand off to CidManager.
        if tid == FRAME_NEW_CONNECTION_ID:
            if frame._new_cid:
                var nc = frame._new_cid.value().copy()
                # F22 — RFC 9000 §19.15: `retire_prior_to` MUST NOT exceed
                # `sequence`. Close with FRAME_ENCODING_ERROR (0x07).
                var _v_cid_rpt = check_new_connection_id_retire_prior(
                    nc.sequence, nc.retire_prior_to
                )
                if _v_cid_rpt:
                    var _vv = _v_cid_rpt.value().copy()
                    self.close_transport(_vv.error_code, _vv.tag, now)
                    return
                # F23 — RFC 9000 §19.15: connection id `Length` MUST be in
                # 1..20. A zero-length CID is FRAME_ENCODING_ERROR (0x07).
                var _v_cid_len = check_new_connection_id_length(
                    UInt64(len(nc.cid))
                )
                if _v_cid_len:
                    var _vv2 = _v_cid_len.value().copy()
                    self.close_transport(_vv2.error_code, _vv2.tag, now)
                    return
                self.cid_mgr.on_new_connection_id(
                    nc.sequence,
                    nc.retire_prior_to,
                    List[UInt8](copy=nc.cid),
                    List[UInt8](copy=nc.stateless_reset_token),
                )
            return

        # RETIRE_CONNECTION_ID: hand off to CidManager.
        if tid == FRAME_RETIRE_CONNECTION_ID:
            if frame._retire_cid:
                self.cid_mgr.on_retire_connection_id(frame._retire_cid.value())
            return

        # STREAM frames (0x08-0x0F).
        if tid >= FRAME_STREAM_BASE and tid <= FRAME_STREAM_BASE + UInt64(7):
            if frame._stream:
                var sf = frame._stream.value().copy()
                self._handle_stream_frame(sf)
            return

        if tid == FRAME_RESET_STREAM:
            if frame._reset_stream:
                var rf = frame._reset_stream.value().copy()
                self._handle_reset_stream(rf)
            return

        if tid == FRAME_STOP_SENDING:
            if frame._stop_sending:
                var ssf = frame._stop_sending.value().copy()
                self._handle_stop_sending(ssf)
            return

        if tid == FRAME_MAX_DATA:
            if frame._max_data:
                self.stream_map.conn_fc_send.ensure_limit(frame._max_data.value())
                # Reset blocked_at so we can emit DATA_BLOCKED again at the new limit.
                self.stream_map.conn_fc_send.blocked_at = UInt64(0)
            return

        if tid == FRAME_MAX_STREAM_DATA:
            if frame._max_stream_data:
                var msd = frame._max_stream_data.value().copy()
                var key = Int(msd.stream_id)
                # F18 / F19 — RFC 9000 §19.10: MAX_STREAM_DATA must target a
                # stream the recipient sends on. Unknown stream id → F18;
                # known but recv-only stream → F19. Both are
                # STREAM_STATE_ERROR. Computed before any state mutation.
                var _exists = key in self.stream_map.streams
                var _has_send = stream_is_bidi(msd.stream_id) or stream_is_local(
                    msd.stream_id, self.is_server
                )
                var _ctx_msd = MaxStreamDataCtx(
                    stream_id=msd.stream_id,
                    exists=_exists,
                    has_send_side=_has_send,
                )
                var _verdict_msd = predicate_f18_f19_max_stream_data(_ctx_msd)
                if _verdict_msd:
                    var _v_msd = _verdict_msd.value().copy()
                    self.close_transport(_v_msd.error_code, _v_msd.tag, now)
                    return
                var stream = self.stream_map.get_stream(key)
                if stream.fc_send:
                    var fc = stream.fc_send.value().copy()
                    var old_limit = fc.limit
                    fc.ensure_limit(msd.maximum)
                    var grew = fc.limit > old_limit
                    if grew:
                        fc.blocked_at = UInt64(0)   # allow re-emission at new limit
                    stream.fc_send = fc^
                    self.stream_map.set_stream(key, stream^)
                    if grew:
                        self.events.append(QuicEvent.stream_writable(msd.stream_id))
            return

        if tid == FRAME_MAX_STREAMS_BIDI:
            if frame._max_streams:
                var ms = frame._max_streams.value().copy()
                # F20 — RFC 9000 §19.11: a MAX_STREAMS value > 2^60 cannot
                # encode a valid stream id. Close with FRAME_ENCODING_ERROR.
                var _v_ms_bidi = check_max_streams_value(ms.maximum)
                if _v_ms_bidi:
                    var _vv = _v_ms_bidi.value().copy()
                    self.close_transport(_vv.error_code, _vv.tag, now)
                    return
                if ms.maximum > self.stream_map.peer_max_streams_bidi:
                    self.stream_map.peer_max_streams_bidi = ms.maximum
                    # Peer granted more streams; reset dedup so we re-notify if we hit the new limit.
                    self.stream_map.needs_streams_blocked_bidi = False
                    self.stream_map.streams_blocked_at_bidi = UInt64(0)
            return

        if tid == FRAME_MAX_STREAMS_UNI:
            if frame._max_streams:
                var ms = frame._max_streams.value().copy()
                var _v_ms_uni = check_max_streams_value(ms.maximum)
                if _v_ms_uni:
                    var _vv = _v_ms_uni.value().copy()
                    self.close_transport(_vv.error_code, _vv.tag, now)
                    return
                if ms.maximum > self.stream_map.peer_max_streams_uni:
                    self.stream_map.peer_max_streams_uni = ms.maximum
                    self.stream_map.needs_streams_blocked_uni = False
                    self.stream_map.streams_blocked_at_uni = UInt64(0)
            return

        # *_BLOCKED frames: informational only. STREAMS_BLOCKED
        # carries a stream-count field with the same 2^60 cap as
        # MAX_STREAMS (RFC 9000 §19.14). F21 — close with
        # FRAME_ENCODING_ERROR on overflow before treating the frame as
        # informational.
        if (tid == FRAME_STREAMS_BLOCKED_BIDI
                or tid == FRAME_STREAMS_BLOCKED_UNI):
            if frame._max_streams:
                var sb = frame._max_streams.value().copy()
                var _v_sb = check_streams_blocked_value(sb.maximum)
                if _v_sb:
                    var _vv = _v_sb.value().copy()
                    self.close_transport(_vv.error_code, _vv.tag, now)
                    return
            return
        if (tid == FRAME_DATA_BLOCKED
                or tid == FRAME_STREAM_DATA_BLOCKED):
            return

        # PATH_CHALLENGE (0x1A) — RFC 9000 §8.2. Reaches this point in
        # 1-RTT (space_idx == 2) or in the 0-RTT sentinel space
        # (space_idx == ZERO_RTT_SPACE_IDX == 3): F13
        # (is_path_challenge_in_handshake) only fires for space_idx 0 or
        # 1, so a PATH_CHALLENGE arriving with the 0-RTT sentinel falls
        # through here and is processed permissively. This is a §12.4
        # violation (PATH_CHALLENGE is forbidden in 0-RTT); the full
        # 0-RTT frame-table audit is deferred to the conformance harness.
        # Neither path is memory-unsafe: on_path_challenge_received only
        # appends to pending_path_responses and does not index spaces[].
        # Stash the 8-byte token so the next 1-RTT flush emits the
        # matching PATH_RESPONSE.
        if frame.is_path_challenge():
            ref data = frame.as_path_data()
            self.on_path_challenge_received(Span(data), now)
            return

        # PATH_RESPONSE (0x1B) — RFC 9000 §8.2. The token-vs-addr match
        # requires the source addr of the carrying datagram, which the
        # bench receive site stamps into `_current_recv_addr` before
        # feeding the buffer; using a per-conn cursor keeps the `recv`
        # ABI unchanged. Non-matches are silently dropped inside
        # `on_path_response_received` per the §8.2 edge case.
        if frame.is_path_response():
            ref data = frame.as_path_data()
            var from_addr = PathKey(other=self._current_recv_addr)
            self.on_path_response_received(Span(data), from_addr^, now)
            return

        # DATAGRAM / DATAGRAM_LEN (RFC 9221 §5) — 1-RTT only, gated above.
        # Surface the payload to the application via QuicEvent so H3 (or
        # raw MASQUE/CONNECT-UDP callers) can demux. Frames carry no
        # reliability state (RFC 9221 §5.4) so we do not record them in
        # `app_frames_sent` or otherwise track for retransmission.
        if frame.is_datagram():
            ref payload = frame.as_datagram_payload()
            self.events.append(
                QuicEvent.datagram_received(List[UInt8](copy=payload))
            )
            return

        # F10 — RFC 9000 §12.4: unknown frame type. Close with
        # FRAME_ENCODING_ERROR (0x07). `parse_frame` returns the
        # `Frame.unknown(type_id)` sentinel for any out-of-range type id;
        # the predicate keeps the closed-set definition single-source.
        if is_unknown_frame_type(tid):
            self.close_transport(
                UInt64(0x07), String(GUARD_TAG_UNKNOWN_FRAME), now
            )
            return

    # ── ACK handling ─────────────────────────────────────────────────

    def _handle_ack(
        mut self, ack_frame: AckFrame, space_idx: Int, now: UInt64
    ) raises:
        """Process an ACK frame: update recovery, detect losses."""
        # Get newly acked packets.
        var acked = self.spaces[space_idx].on_ack_received(ack_frame)

        if len(acked) == 0:
            return

        # Process stream-layer frames for acked Application-space packets.
        if space_idx == 2:
            for i in range(len(acked)):
                self._on_app_pkt_acked(Int(acked[i].pn))

        # Update RTT from the largest newly acked packet.
        var largest_acked_pn = ack_frame.largest_ack
        # Find the sent packet matching largest_ack for RTT.
        for i in range(len(acked)):
            if acked[i].pn == largest_acked_pn:
                var rtt_sample = now - acked[i].time_sent
                if now >= acked[i].time_sent:
                    # Convert ack_delay using peer's exponent when available.
                    var ade = self.local_params.ack_delay_exponent
                    var mad = self.local_params.max_ack_delay
                    if self.peer_params:
                        ade = self.peer_params.value().ack_delay_exponent
                        mad = self.peer_params.value().max_ack_delay
                    var ack_delay_us = ack_frame.ack_delay * (
                        UInt64(1) << ade
                    )
                    var max_ack_delay_us = mad * 1000
                    self.recovery.update_rtt(
                        rtt_sample,
                        ack_delay_us,
                        max_ack_delay_us,
                        self.handshake_confirmed,
                    )
                break

        # Release bytes for acked packets and fan out to congestion controller.
        # Also advance the per-space last_ae_acked_time_sent tracker used by
        # persistent-congestion detection (RFC 9002 §7.6).
        var ect0_acked_count = UInt64(0)
        for i in range(len(acked)):
            # Decrement ECT(0) in-flight counter on ACK (O(1)).
            if acked[i].ecn_mark == ECN_ECT0:
                ect0_acked_count += UInt64(1)
                if self.spaces[space_idx].ect0_in_flight > UInt64(0):
                    self.spaces[space_idx].ect0_in_flight -= UInt64(1)
            self.recovery.on_packet_acked(acked[i].size, acked[i].in_flight)
            if acked[i].ack_eliciting:
                if (
                    acked[i].time_sent
                    > self.spaces[space_idx].last_ae_acked_time_sent
                ):
                    self.spaces[space_idx].last_ae_acked_time_sent = (
                        acked[i].time_sent
                    )
            var ap = AckedPacket(
                pkt_num=acked[i].pn,
                size=UInt64(acked[i].size),
                time_sent=acked[i].time_sent,
                time_acked=now,
                rtt_sample=self.recovery.latest_rtt,
            )
            self.recovery.cc.on_packet_acked(
                ap, self.recovery.smoothed_rtt, now
            )

        # Reset PTO count and refresh pacer capacity.
        self.recovery.on_ack_received()

        # Client confirms handshake when it receives ACK for 1-RTT packet.
        if not self.is_server and space_idx == 2 and not self.handshake_confirmed:
            self._on_handshake_complete(now)

        # Detect lost packets (also runs persistent-congestion detection and
        # fans out to cc.on_packets_lost).
        self._detect_losses(space_idx, now)

        # ECN feedback processing (after loss detection).
        # Call whenever ECN state is active (PROBING or CAPABLE):
        # - PROBING: always, so we detect the no-ECN-counts case (path bleaches
        #   marks → DISABLED).
        # - CAPABLE: always, so we can detect bleaching (ECT0 in-flight but ACK
        #   has no ECN counts) and CE increments for congestion signaling.
        if self.ecn_state != ECN_STATE_DISABLED:
            self._process_ecn_feedback(space_idx, ack_frame, ect0_acked_count, now)

    # ── Loss detection ───────────────────────────────────────────────

    def _detect_losses(mut self, space_idx: Int, now: UInt64) raises:
        """Check for lost packets in the given PN space."""
        if self.spaces[space_idx].largest_acked_pn < 0:
            return

        # Collect sent packet info for loss detection.
        var sent_pns = List[Int]()
        var sent_times = List[UInt64]()
        var sent_in_flight = List[Bool]()

        for entry in self.spaces[space_idx].sent_packets.items():
            sent_pns.append(entry.key)
            sent_times.append(entry.value.time_sent)
            sent_in_flight.append(entry.value.in_flight)

        var lost_pns = self.recovery.detect_lost_packets(
            sent_pns,
            sent_times,
            sent_in_flight,
            self.spaces[space_idx].largest_acked_pn,
            now,
        )

        if len(lost_pns) == 0:
            return

        # Evaluate persistent-congestion *before* popping lost packets, since
        # the detector reads sent_packets[pn].ack_eliciting / .time_sent.
        var peer_mad_us: UInt64 = UInt64(0)
        if self.peer_params:
            peer_mad_us = self.peer_params.value().max_ack_delay * 1000
        var persistent = self._detect_persistent_congestion(
            space_idx, lost_pns, peer_mad_us, now
        )

        # Build the LostPacket list for CC before teardown.
        var lost_records = List[LostPacket]()
        for i in range(len(lost_pns)):
            var pn_key = lost_pns[i]
            if pn_key in self.spaces[space_idx].sent_packets:
                var sp_pn = self.spaces[space_idx].sent_packets[pn_key].pn
                var sp_size = self.spaces[space_idx].sent_packets[pn_key].size
                var sp_ts = self.spaces[space_idx].sent_packets[pn_key].time_sent
                lost_records.append(
                    LostPacket(
                        pkt_num=sp_pn,
                        size=UInt64(sp_size),
                        time_sent=sp_ts,
                    )
                )

        # Process lost packets (teardown + retransmission hooks).
        for i in range(len(lost_pns)):
            var pn_key = lost_pns[i]
            if pn_key in self.spaces[space_idx].sent_packets:
                var lost_pkt = SentPacket(
                    other=self.spaces[space_idx].sent_packets[pn_key]
                )
                # Decrement ECT(0) in-flight on loss.
                if lost_pkt.ecn_mark == ECN_ECT0:
                    if self.spaces[space_idx].ect0_in_flight > UInt64(0):
                        self.spaces[space_idx].ect0_in_flight -= UInt64(1)
                self.recovery.on_packet_lost(lost_pkt.size, lost_pkt.in_flight)

                # Re-queue CRYPTO frames for retransmission at their
                # original offset so the peer receives correct offsets.
                for f in range(len(lost_pkt.frames)):
                    if lost_pkt.frames[f].is_crypto():
                        if lost_pkt.frames[f]._crypto:
                            var cf = lost_pkt.frames[f]._crypto.value().copy()
                            self.crypto_streams[space_idx].requeue(
                                cf.offset, Span(cf.data)
                            )

                # Re-apply stream-layer loss handling for Application space.
                if space_idx == 2:
                    self._on_app_pkt_lost(pn_key)

                _ = self.spaces[space_idx].sent_packets.pop(pn_key)

        # Fan out to CC. `persistent=True` triggers cwnd reset to min_cwnd.
        self.recovery.cc.on_packets_lost(
            lost_records, self.recovery.smoothed_rtt, now, persistent
        )
        if persistent:
            # RFC 9002 §5.2: reset min_rtt after persistent congestion so the
            # next RTT sample re-seeds the estimator.
            self.recovery.min_rtt = self.recovery.latest_rtt
        # Refresh pacer capacity since cwnd may have changed.
        self.recovery.pacer.update_capacity(
            self.recovery.cc.cwnd(), self.recovery.smoothed_rtt
        )

    # ── Persistent-congestion detection (RFC 9002 §7.6.2) ────────────

    def _detect_persistent_congestion(
        self,
        space_id: Int,
        newly_lost_pns: List[Int],
        peer_max_ack_delay_us: UInt64,
        now: UInt64,
    ) raises -> Bool:
        """RFC 9002 §7.6.2 + §5.2. Return True when persistent congestion is
        declared in `space_id`.

        The caller is responsible for:
          - Invoking `cc.on_packets_lost(..., persistent=True)` on True.
          - Resetting `recovery.min_rtt = recovery.latest_rtt` (RFC 9002 §5.2).

        Filtering to ack-eliciting packets is inline: the check
        looks up each lost PN in `sent_packets` and uses its `ack_eliciting`
        flag to decide whether it contributes to the span.

        `max_ack_delay` contributes unconditionally — regardless of which
        packet number space — per research §4.2 (contrasts with PTO §6.2.1).
        """
        if not self.recovery.has_rtt_sample:
            return False   # RFC 9002 §7.6.2: MUST NOT declare before first RTT sample
        if len(newly_lost_pns) < 2:
            return False

        # Track earliest/latest time_sent across ack-eliciting lost packets.
        var earliest: UInt64 = UInt64.MAX
        var latest: UInt64 = UInt64(0)
        var ae_count: Int = 0
        for i in range(len(newly_lost_pns)):
            var pn = newly_lost_pns[i]
            if pn not in self.spaces[space_id].sent_packets:
                continue   # already removed; defensive
            var sp_ts = self.spaces[space_id].sent_packets[pn].time_sent
            var sp_ae = self.spaces[space_id].sent_packets[pn].ack_eliciting
            if not sp_ae:
                continue
            ae_count += 1
            if sp_ts < earliest:
                earliest = sp_ts
            if sp_ts > latest:
                latest = sp_ts

        if ae_count < 2:
            return False

        # Congestion period: PERSISTENT_CONG_THRESHOLD × (srtt + 4*rttvar + max_ack_delay).
        var rttvar_scaled: UInt64 = UInt64(4) * self.recovery.rttvar
        if rttvar_scaled < K_GRANULARITY:
            rttvar_scaled = K_GRANULARITY
        var congestion_period = (
            self.recovery.smoothed_rtt + rttvar_scaled + peer_max_ack_delay_us
        ) * PERSISTENT_CONG_THRESHOLD

        if latest - earliest < congestion_period:
            return False

        # RFC: declare persistent iff no ack-eliciting packet with
        # earliest <= time_sent <= latest in this space was acknowledged.
        # The per-space single-UInt64 tracker gives a conservative answer.
        return not self.spaces[space_id].any_ae_acked_in_range(
            earliest, latest
        )

    def _process_ecn_feedback(
        mut self, space_idx: Int, ack: AckFrame, ect0_acked: UInt64, now: UInt64
    ):
        """Process ECN counts from an ACK frame (RFC 9000 §13.4.2 + RFC 9002 §7.9).

        Validates the path (PROBING→CAPABLE or PROBING→DISABLED) and triggers
        a congestion event on CE increment.

        ect0_acked: number of ECT(0)-marked packets covered by this ACK batch
        (captured before the in-flight counter was decremented)."""
        var prev_ce = self.spaces[space_idx].last_ack_ecn.ce

        # Update stored last-seen ECN counts.
        self.spaces[space_idx].last_ack_ecn = EcnCounts(
            ack.ecn_ect0, ack.ecn_ect1, ack.ecn_ce
        )

        # --- Path validation (PROBING phase) ---
        if self.ecn_state == ECN_STATE_PROBING:
            if (self.ecn_probe_pkts_sent >= self.ecn_probe_pkts_needed
                    and ack.largest_ack >= self.ecn_probe_first_pn):
                if ack.ecn_ect0 == UInt64(0) and ack.ecn_ect1 == UInt64(0) and ack.ecn_ce == UInt64(0):
                    # Peer sees no ECN counts → path strips ECN marks.
                    self.ecn_state = ECN_STATE_DISABLED
                    return
                else:
                    self.ecn_state = ECN_STATE_CAPABLE

        # --- Bleaching / remarking checks (RFC 9000 §13.4.2, only after CAPABLE) ---
        # These checks only apply once ECN is confirmed (CAPABLE).  During
        # PROBING the path validation logic above is the gating mechanism.
        if self.ecn_state == ECN_STATE_CAPABLE:
            var in_flight_ect0 = self.spaces[space_idx].ect0_in_flight
            # Remarking: peer reports more ECN-marked packets than we sent.
            if ack.ecn_ect0 + ack.ecn_ect1 + ack.ecn_ce > in_flight_ect0 + UInt64(1):
                self.ecn_state = ECN_STATE_DISABLED
                return
            # Bleaching: we sent ECT(0)-marked packets in this batch but peer
            # reports no ECN counts → path strips ECN codepoints.
            if (ect0_acked > UInt64(0)
                    and ack.ecn_ect0 == UInt64(0)
                    and ack.ecn_ect1 == UInt64(0)
                    and ack.ecn_ce == UInt64(0)):
                self.ecn_state = ECN_STATE_DISABLED
                return

        # --- CE delta → congestion event (RFC 9002 §7.9) ---
        if ack.ecn_ce > prev_ce:
            self.recovery.cc.on_congestion_event(self.recovery.smoothed_rtt, now)
            # Refresh pacer after cwnd may have changed.
            self.recovery.pacer.update_capacity(
                self.recovery.cc.cwnd(), self.recovery.smoothed_rtt
            )

    # ── Handshake driver ─────────────────────────────────────────────

    def _drive_handshake(mut self, now: UInt64) raises:
        """Drain crypto data and feed/read from TLS state machine."""
        if self.conn_handle < 0:
            return

        # _drive_handshake body-time bracket: capture start + bump
        # active_drive_count. Closing bracket fires at fall-through end.
        var t_drive_start: UInt64 = 0
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                t_drive_start = monotonic_us()
                self.profile_ptr.value()[].active_drive_count = self.profile_ptr.value()[].active_drive_count + UInt32(1)

        var lib = self._lib.inner_ptr()

        # 1. Drain contiguous CRYPTO bytes from each space's crypto_stream
        #    and feed them to the TLS engine.
        for level in range(3):
            if self.crypto_streams[level].has_pending():
                var crypto_data = self.crypto_streams[level].drain()
                if len(crypto_data) > 0:
                    # Mojo-side input-marshalling timer wraps the heap alloc
                    # + per-byte copy loop (the FFI input ABI marshalling).
                    var t_input_start: UInt64 = 0
                    comptime if PROFILE_ACCEPT:
                        if self.profile_ptr is not None:
                            t_input_start = monotonic_us()
                    var data_buf = _heap_alloc[UInt8](
                        len(crypto_data)
                    ).as_unsafe_any_origin()
                    for i in range(len(crypto_data)):
                        data_buf[i] = crypto_data[i]
                    var input_marshalling_us: UInt64 = 0
                    comptime if PROFILE_ACCEPT:
                        if self.profile_ptr is not None:
                            input_marshalling_us = monotonic_us() - t_input_start

                    var t_start: UInt64 = 0
                    comptime if PROFILE_ACCEPT:
                        if self.profile_ptr is not None:
                            t_start = monotonic_us()
                            self.profile_rustls_us_accum -= t_start
                    # out-param locals always declared (zero-cost; comptime
                    # branch chooses 5-arg wired call vs legacy 3-arg below).
                    # Slot order matches src/tls/lib.mojo:499 quic_conn_read_hs:
                    #   slot 1: out_state_machine_us (rustls read_hs body µs)
                    #   slot 2: out_handle_lookup_us (with_mut handle-table lookup µs)
                    var rc: Int32 = Int32(0)
                    var out_sm_us: UInt64 = UInt64(0)
                    var out_lookup_us: UInt64 = UInt64(0)
                    comptime if PROFILE_ACCEPT:
                        if self.profile_ptr is not None:
                            rc = lib[].quic_conn_read_hs(
                                self.conn_handle,
                                data_buf,
                                Int32(len(crypto_data)),
                                UnsafePointer(to=out_sm_us),
                                UnsafePointer(to=out_lookup_us),
                            )
                        else:
                            rc = lib[].quic_conn_read_hs(
                                self.conn_handle,
                                data_buf,
                                Int32(len(crypto_data)),
                            )
                    else:
                        rc = lib[].quic_conn_read_hs(
                            self.conn_handle,
                            data_buf,
                            Int32(len(crypto_data)),
                        )
                    comptime if PROFILE_ACCEPT:
                        if self.profile_ptr is not None:
                            var t_end = monotonic_us()
                            self.profile_rustls_us_accum += t_end
                            self.profile_ptr.value()[].record_ffi_read_hs(t_end - t_start)
                            self.fresh_conn_ffi_us_total = self.fresh_conn_ffi_us_total + (t_end - t_start)
                            # Per-conn read_hs call count + per-call duration.
                            self.read_hs_call_count = self.read_hs_call_count + UInt64(1)
                            self.profile_ptr.value()[].record_read_hs_us_per_call(t_end - t_start)
                            # Per-call read_hs sub-leg accumulation + histograms.
                            # output_marshalling is zero-by-design for read_hs
                            # (returns status only); slot reserved for future
                            # symmetric write_hs/take_keys reuse.
                            self.read_hs_input_marshalling_us_total = self.read_hs_input_marshalling_us_total + input_marshalling_us
                            self.read_hs_state_machine_us_total = self.read_hs_state_machine_us_total + out_sm_us
                            self.read_hs_output_alloc_us_total = self.read_hs_output_alloc_us_total + out_lookup_us
                            self.read_hs_output_marshalling_us_total = self.read_hs_output_marshalling_us_total + UInt64(0)
                            self.profile_ptr.value()[].record_read_hs_input_marshalling_us(input_marshalling_us)
                            self.profile_ptr.value()[].record_read_hs_state_machine_us(out_sm_us)
                            self.profile_ptr.value()[].record_read_hs_output_alloc_us(out_lookup_us)
                            self.profile_ptr.value()[].record_read_hs_output_marshalling_us(UInt64(0))
                    data_buf.free()

                    if rc < 0:
                        # Close + return on the TLS-error path. The I/O loop's
                        # catch-all would swallow a raise here, leaving the
                        # connection stuck in CONN_HANDSHAKING; instead we
                        # surface the rustls alert as a CRYPTO_ERROR
                        # CONNECTION_CLOSE (RFC 9001 §4.8: 0x0100 | alert).
                        # `_tls_guard_tag_for` disambiguates the 10/50 alert
                        # codes between F25 (Handshake KeyUpdate) and F29
                        # (1-RTT EndOfEarlyData) by encryption level; the
                        # `fallback` argument is the GUARD-TAG used when the
                        # alert byte isn't in {10, 47, 50, 120}, kept visible
                        # at the call site for grep-traceability.
                        var alert_code = lib[].quic_conn_alert(self.conn_handle)
                        var crypto_error = UInt64(0x0100) | UInt64(alert_code)
                        self.close_transport(crypto_error, _tls_guard_tag_for(alert_code, self.current_level, self.handshake_confirmed, String(GUARD_TAG_TLS_KEYUPDATE_1RTT)), now)
                        return

        # 2. Loop write_hs to drain TLS output.
        var out_buf = _heap_alloc[UInt8](_WRITE_HS_BUF_SIZE).as_unsafe_any_origin()
        var out_written = _heap_alloc[Int32](1).as_unsafe_any_origin()
        var out_kc = _heap_alloc[UInt8](1).as_unsafe_any_origin()

        while True:
            out_written[0] = Int32(0)
            out_kc[0] = UInt8(0)

            var t_start: UInt64 = 0
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    t_start = monotonic_us()
                    self.profile_rustls_us_accum -= t_start
            var rc = lib[].quic_conn_write_hs(
                self.conn_handle,
                out_buf,
                Int32(_WRITE_HS_BUF_SIZE),
                out_written,
                out_kc,
            )
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    var t_end = monotonic_us()
                    self.profile_rustls_us_accum += t_end
                    self.profile_ptr.value()[].record_ffi_write_hs(t_end - t_start)
                    self.fresh_conn_ffi_us_total = self.fresh_conn_ffi_us_total + (t_end - t_start)

            if rc < 0:
                var err = lib[].last_error()
                out_buf.free()
                out_written.free()
                out_kc.free()
                raise "quic_conn_write_hs failed: " + err

            var kc = out_kc[0]
            var written = Int(out_written[0])

            # The data output in this write_hs call belongs to the CURRENT
            # level (before any key change). Capture it first, then install
            # new keys.
            #
            # kc: 0=none, 1=Handshake keys ready, 2=1-RTT keys ready.

            # Write TLS bytes at the CURRENT level before advancing.
            if written > 0:
                var target_level = self.current_level
                var tls_data = List[UInt8](capacity=written)
                for i in range(written):
                    tls_data.append(out_buf[i])
                self.crypto_streams[target_level].write(Span(tls_data))

            # Now handle key change AFTER writing data.
            if kc != UInt8(0):
                var keys_handle_buf = _heap_alloc[Int32](1).as_unsafe_any_origin()
                keys_handle_buf[0] = Int32(-1)

                var t_start: UInt64 = 0
                comptime if PROFILE_ACCEPT:
                    if self.profile_ptr is not None:
                        t_start = monotonic_us()
                        self.profile_rustls_us_accum -= t_start
                var take_rc = lib[].quic_conn_take_keys(
                    self.conn_handle, keys_handle_buf
                )
                comptime if PROFILE_ACCEPT:
                    if self.profile_ptr is not None:
                        var t_end = monotonic_us()
                        self.profile_rustls_us_accum += t_end
                        self.profile_ptr.value()[].record_ffi_take_keys(t_end - t_start)
                        self.fresh_conn_ffi_us_total = self.fresh_conn_ffi_us_total + (t_end - t_start)

                if take_rc < 0:
                    var err = lib[].last_error()
                    keys_handle_buf.free()
                    out_buf.free()
                    out_written.free()
                    out_kc.free()
                    raise "quic_conn_take_keys failed: " + err

                var new_keys = keys_handle_buf[0]
                keys_handle_buf.free()

                if kc == UInt8(1):
                    # Handshake keys.
                    self.protect.set_keys(1, new_keys)
                    self.current_level = 1
                elif kc == UInt8(2):
                    # 1-RTT (Application) keys.
                    self.protect.set_keys(2, new_keys)
                    self.current_level = 2

            if written == 0 and kc == UInt8(0):
                break  # No more TLS output and no key change

        out_buf.free()
        out_written.free()
        out_kc.free()

        # 3. Check if handshake is complete.
        var hs_state = lib[].quic_conn_is_handshaking(self.conn_handle)
        if hs_state == Int32(0):
            # Handshake complete.
            self._on_handshake_complete(now)

        # Exit bracket: accumulate _drive_handshake body µs into
        # hs_cpu_us_total and decrement active_drive_count. Mirrors the
        # entry bracket above. raise paths leave the bracket unbalanced
        # but those terminate the connection so the imbalance is moot.
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None and t_drive_start > UInt64(0):
                var delta = monotonic_us() - t_drive_start
                self.hs_cpu_us_total = self.hs_cpu_us_total + delta
                if self.profile_ptr.value()[].active_drive_count > UInt32(0):
                    self.profile_ptr.value()[].active_drive_count = self.profile_ptr.value()[].active_drive_count - UInt32(1)

    def _on_handshake_complete(mut self, now: UInt64) raises:
        """Called when TLS reports handshake is complete."""
        if (self.state & CONN_ESTABLISHED) != 0:
            return  # Already processed

        # Plan B: record handshake latency on the SERVER side. Clients
        # have profile_first_initial_us = 0 (default) and are skipped.
        comptime if PROFILE_ACCEPT:
            if self.is_server and self.profile_ptr is not None:
                if self.profile_first_initial_us > UInt64(0):
                    var latency_us = now - self.profile_first_initial_us
                    self.profile_ptr.value()[].record_handshake_complete(latency_us)

        # Increment full/resumed counter exactly once per server connection.
        # Runtime gate only (not @parameter if PROFILE_ACCEPT:) so the test
        # build (PROFILE_ACCEPT=False) can verify the increment by attaching a
        # profile_ptr directly.
        # profile_ptr is null when PROFILE_ACCEPT=False (no bench attachment),
        # so the runtime branch is paid at most once per server handshake.
        if self.is_server and self.profile_ptr is not None:
            var hs_kind = self._lib.inner_ptr()[].quic_conn_handshake_kind(self.conn_handle)
            if hs_kind == Int32(1) or hs_kind == Int32(3):
                self.profile_ptr.value()[].record_handshake_full()
            elif hs_kind == Int32(2):
                self.profile_ptr.value()[].record_handshake_resumed()
            elif hs_kind == Int32(0):
                raise (
                    "_on_handshake_complete: handshake_kind=0 with "
                    + "is_handshaking==false (rustls state-machine "
                    + "invariant broken)"
                )
            # hs_kind == -2 (client path) or -1 (invalid handle): no-op.
            # is_server gate above already excludes client; -1 means the conn
            # handle was freed mid-call (should never happen in practice).

            # Record per-fresh-conn FFI total at handshake-complete.
            # Fires once per server connection regardless of resumption
            # status, gated by is_server (runtime) + profile_ptr != 0 (runtime).
            # Under PROFILE_ACCEPT=False, fresh_conn_ffi_us_total stays 0
            # (no increments in the comptime-gated bracket sites) but the
            # record still fires — bucket[0] gets 1 sample (value=0 maps
            # to bucket index 0 in _per_pkt_bucket).
            self.profile_ptr.value()[].record_fresh_conn_ffi_us(self.fresh_conn_ffi_us_total)
            # Record per-handshake read_hs call count.
            self.profile_ptr.value()[].record_read_hs_per_handshake_count(Int(self.read_hs_call_count))
            # Per-FD wait vs CPU breakdown.
            if self.accept_us > UInt64(0):
                var now_hs = monotonic_us()
                var wall_us = now_hs - self.accept_us
                if wall_us >= self.hs_cpu_us_total:
                    self.hs_wait_us_total = wall_us - self.hs_cpu_us_total
                else:
                    self.hs_wait_us_total = UInt64(0)
                self.profile_ptr.value()[].record_hs_cpu_us_per_handshake(self.hs_cpu_us_total)
                self.profile_ptr.value()[].record_hs_wait_us_per_handshake(self.hs_wait_us_total)

        # Clear HANDSHAKING flag.
        self.state = self.state & ~CONN_HANDSHAKING

        # Read peer transport params.
        var tp_buf = _heap_alloc[UInt8](_TP_BUF_SIZE).as_unsafe_any_origin()
        var tp_written = _heap_alloc[Int32](1).as_unsafe_any_origin()
        tp_written[0] = Int32(0)

        var lib = self._lib.inner_ptr()
        var rc = lib[].quic_conn_transport_params(
            self.conn_handle,
            tp_buf,
            Int32(_TP_BUF_SIZE),
            tp_written,
        )

        if rc == Int32(0) and Int(tp_written[0]) > 0:
            var tp_len = Int(tp_written[0])
            var tp_bytes = List[UInt8](capacity=tp_len)
            for i in range(tp_len):
                tp_bytes.append(tp_buf[i])

            # Parse the peer's transport parameters. The parser raises with a
            # GUARD_TAG_TP_* bracketed prefix on §18.2 range violations
            # (F07/F08/F09); any other parse error here is still a
            # TRANSPORT_PARAMETER_ERROR per RFC 9000 §20.1. We follow the
            # "close + return" model: queue a transport CONNECTION_CLOSE
            # (0x1c) with error_code 0x08 and the raised string as the
            # reason, then return without raising so the I/O loop does not
            # swallow this on its catch-all path.
            var peer_tp = TransportParams()
            try:
                peer_tp = parse_transport_params(Span(tp_bytes))
            except e:
                tp_buf.free()
                tp_written.free()
                self.close_transport(UInt64(0x08), String(e), now)
                return

            # Server-side §7.3 + §18.2 validation: required ISCID (F02) and
            # forbidden server-only fields (F03-F06). Each violation raises
            # with the matching GUARD_TAG_TP_* prefix, which we propagate
            # verbatim through close_transport so the out-of-process
            # scenarios can grep the reason phrase.
            if self.is_server:
                try:
                    validate_client_transport_params(peer_tp)
                except e:
                    tp_buf.free()
                    tp_written.free()
                    self.close_transport(UInt64(0x08), String(e), now)
                    return

            self.peer_params = TransportParams(other=peer_tp)
            self.events.append(QuicEvent.peer_transport_params(peer_tp))

            # Propagate peer limits into StreamMap and CidManager.
            var peer = self.peer_params.value().copy()
            self.stream_map.set_peer_limits(
                max_streams_bidi=peer.initial_max_streams_bidi,
                max_streams_uni=peer.initial_max_streams_uni,
                stream_fc_bidi_local=peer.initial_max_stream_data_bidi_local,
                stream_fc_bidi_remote=peer.initial_max_stream_data_bidi_remote,
                stream_fc_uni=peer.initial_max_stream_data_uni,
                conn_fc_send_limit=peer.initial_max_data,
            )
            self.cid_mgr.peer_active_limit = peer.active_connection_id_limit
            self.cid_mgr.retire_queue_cap = Int(peer.active_connection_id_limit) * 8

            # Issue a spare local CID (seq=1) so the peer has a backup.
            _ = self.cid_mgr.issue_new_cid()

        tp_buf.free()
        tp_written.free()

        # Seed Application-space PN skip RNG from local_cid (per-connection).
        # Initial and Handshake spaces retain pn_skip_rng=0 (skip disabled).
        var pn_skip_seed = UInt64(0)
        for i in range(min(Int(8), Int(len(self.local_cid)))):
            pn_skip_seed = (pn_skip_seed << 8) | UInt64(self.local_cid[i])
        if pn_skip_seed == 0:
            pn_skip_seed = UInt64(0xDEADBEEFCAFEB00F)  # degenerate fallback (1-in-2^64)
        self.spaces[2].pn_skip_rng  = pn_skip_seed
        self.spaces[2].pn_skip_next = 200 + (pn_skip_seed % 300)

        if self.is_server:
            # Server: set ESTABLISHED, discard Initial & Handshake, queue HANDSHAKE_DONE.
            self.state = self.state | CONN_ESTABLISHED
            self.handshake_confirmed = True
            self._discard_initial_space()
            self._discard_handshake_space()
            # RFC 9001 §4.1.3 — discard 0-RTT decrypt keys at handshake-complete.
            # Placed AFTER CONN_ESTABLISHED is set so re-entry is blocked by the
            # early-return; BEFORE any subsequent control flow that could exit
            # without firing the discard.
            self._discard_zero_rtt_keys()
            self.send_handshake_done = True
            self.events.append(QuicEvent.handshake_complete())
        else:
            # Client: discard Initial. If handshake_confirmed (via 1-RTT ACK),
            # also set ESTABLISHED and discard Handshake.
            self._discard_initial_space()
            if self.handshake_confirmed:
                self.state = self.state | CONN_ESTABLISHED
                self._discard_handshake_space()
                # RFC 9001 §4.1.3 — discard 0-RTT keys at handshake-complete.
                # No-op on the client side because slot 3 is unpopulated on
                # clients today; wired here for symmetry so a future
                # client-side install (if one is ever added) is also covered.
                self._discard_zero_rtt_keys()
                self.events.append(QuicEvent.handshake_complete())

    # ── Space discard helpers ────────────────────────────────────────

    def _discard_initial_space(mut self) raises:
        """Discard Initial packet number space and keys."""
        if (self.state & CONN_INITIAL_DISCARDED) != 0:
            return
        self.state = self.state | CONN_INITIAL_DISCARDED

        var discarded = self.spaces[0].discard()
        for i in range(len(discarded)):
            self.recovery.on_packet_lost(discarded[i].size, discarded[i].in_flight)

        self.protect.discard_keys(0)

    def _discard_handshake_space(mut self) raises:
        """Discard Handshake packet number space and keys."""
        if (self.state & CONN_HS_DISCARDED) != 0:
            return
        self.state = self.state | CONN_HS_DISCARDED

        var discarded = self.spaces[1].discard()
        for i in range(len(discarded)):
            self.recovery.on_packet_lost(
                discarded[i].size, discarded[i].in_flight
            )

        self.protect.discard_keys(1)

    def _discard_zero_rtt_keys(mut self):
        """RFC 9001 §4.1.3 — discard server-side 0-RTT decrypt keys at
        handshake-complete.

        Idempotent by construction:
          (a) `_on_handshake_complete` early-returns when CONN_ESTABLISHED is
              already set, so this helper cannot be called twice per connection
              from the handshake-complete path.
          (b) `PacketProtect.discard_keys(level)` is itself a no-op on an
              empty slot.
          (c) Clearing the reorder buffer is a no-op on an already-empty list,
              so repeated calls from handshake-complete + HANDSHAKE_DONE
              never double-free.

        Dead in production today (no install call site outside tests).
        Wired now so the decrypt-path change is purely additive;
        forgetting it later would be a CVE.
        """
        self.protect.discard_keys(ZERO_RTT_KEY_SLOT_IDX)
        # RFC 9001 §5.7 reorder buffer is meaningful only while 0-RTT keys
        # exist; once they're gone the buffered ciphertext is undecryptable
        # forever, so free it eagerly. Helper stays non-raising — replacing
        # a Mojo List does not throw.
        self.zero_rtt_buffer = List[List[UInt8]]()
        self.zero_rtt_buffer_bytes = 0

    def _zero_rtt_enabled(self) -> Bool:
        """True if the server config opted into 0-RTT (max_early_data != 0).
        Reads the cached field — no FFI crossing per packet."""
        return self.zero_rtt_enabled

    def _buffer_zero_rtt_or_drop(mut self, packet: Span[UInt8, _]) -> Bool:
        """Buffer a 0-RTT packet for later retry after rustls derives the
        early-data secret. Returns True if buffered, False if dropped
        (cap exceeded — RFC 9001 §5.7 allows discard).

        Bounded by ZERO_RTT_BUFFER_MAX_PKTS AND ZERO_RTT_BUFFER_MAX_BYTES;
        whichever cap a new packet would exceed first, drops it.
        """
        if len(self.zero_rtt_buffer) >= ZERO_RTT_BUFFER_MAX_PKTS:
            return False
        if self.zero_rtt_buffer_bytes + len(packet) > ZERO_RTT_BUFFER_MAX_BYTES:
            return False
        var copy = List[UInt8](capacity=len(packet))
        for b in packet:
            copy.append(b)
        self.zero_rtt_buffer.append(copy^)
        self.zero_rtt_buffer_bytes += len(packet)
        return True

    def _drain_zero_rtt_buffer(mut self, now: UInt64, ecn_mark: UInt8) raises:
        """Replay buffered 0-RTT packets through the production coalesce
        path now that rustls has had a chance to derive the early-data
        secret. Idempotent (empty-buffer no-op). Re-entry into
        recv_from_buffer is guarded by self._draining_zero_rtt = True,
        which makes the decrypt-path's Path B fail branch drop instead
        of re-buffer (preventing unbounded re-entry).

        Each buffered packet replays inside its own per-packet
        containment: a packet that raises is dropped (counted via
        `zero_rtt_drain_dropped`) and the drain continues with the
        remaining packets.
        """
        if len(self.zero_rtt_buffer) == 0:
            return
        var pending = self.zero_rtt_buffer^
        self.zero_rtt_buffer = List[List[UInt8]]()
        self.zero_rtt_buffer_bytes = 0
        self._draining_zero_rtt = True
        try:
            for pkt in pending:
                var buf_ptr = _heap_alloc[UInt8](len(pkt)).as_unsafe_any_origin()
                for i in range(len(pkt)):
                    buf_ptr[i] = pkt[i]
                # NOTE: flat try/except/finally — Mojo 1.0.0b1 cannot
                # parse a bare nested try/except as the body of a
                # try/finally (the parser binds the except to the outer
                # try). Semantics are identical: except contains the
                # per-packet raise, finally always frees the buffer.
                try:
                    self.recv_from_buffer(buf_ptr, len(pkt), now, ecn_mark)
                except e:
                    # Defense-in-depth against unclassified raises
                    # (internal errors, future bugs): 0-RTT install
                    # raises are folded at their Path B call site
                    # inside recv_from_buffer and no longer reach
                    # this except. A raise mid-drain is scoped to
                    # one buffered packet — drop it, count it, and
                    # keep draining the rest.
                    # Drop-and-continue over close_transport: the
                    # failure scope is one buffered packet, and
                    # connection-fatal protocol errors on this path
                    # use the explicit close_transport + return
                    # idiom, not raises.
                    # This is the sans-I/O QUIC core: the protocol
                    # layer carries no I/O imports, so there is no
                    # stderr print here (unlike the I/O-layer
                    # _flush_impl catch). Observability is provided
                    # by the `comptime`-gated `zero_rtt_drain_dropped`
                    # counter (live in PROFILE_ACCEPT builds); human-
                    # facing traces are the responsibility of the
                    # I/O-layer caller that drives recv_from_buffer.
                    _ = e
                    self._record_zero_rtt_drain_dropped()
                finally:
                    buf_ptr.free()
        finally:
            self._draining_zero_rtt = False

    # ── 0-RTT anti-replay recorder wrappers ──────────────────────────
    #
    # Five PROFILE_ACCEPT-gated thin wrappers that route the tristate
    # decision to the matching `AcceptProfile.record_zero_rtt_replay_*`
    # counter. Dead-stripped at off-profile builds. Each name mirrors
    # the decision branch in the decrypt-path integration so a `grep
    # _record_replay_` shows the full counter wiring at a glance.

    def _record_replay_accept(mut self):
        """Bump `zero_rtt_replay_accept` on the accept branch."""
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_zero_rtt_replay_accept()

    def _record_replay_reject_duplicate(mut self):
        """Bump `zero_rtt_replay_reject_duplicate` on the duplicate branch."""
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_zero_rtt_replay_reject_duplicate()

    def _record_replay_reject_per_key_quota(mut self):
        """Bump `zero_rtt_replay_reject_per_key_quota` on the
        per-key-quota-exhausted branch."""
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_zero_rtt_replay_reject_per_key_quota()

    def _record_replay_reject_global_ceiling(mut self):
        """Bump `zero_rtt_replay_reject_global_ceiling` on the
        global-ceiling-exhausted branch."""
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_zero_rtt_replay_reject_global_ceiling()

    def _record_replay_reject_no_authenticator(mut self):
        """Bump `zero_rtt_replay_reject_no_authenticator` on FFI anomaly
        or store-raise — the two paths that do NOT produce a
        `ReplayDecision`."""
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_zero_rtt_replay_reject_no_authenticator()

    def _record_zero_rtt_drain_dropped(mut self):
        """Bump `zero_rtt_drain_dropped` on each buffered packet whose
        replay raised mid-drain and was dropped by the per-packet
        containment in `_drain_zero_rtt_buffer`."""
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_zero_rtt_drain_dropped()

    def _invoke_replay_authenticator_ffi(
        mut self,
        mut out_buf: InlineArray[UInt8, 32],
        mut out_len: UInt,
    ) -> Int32:
        """Call `rlsm_quic_server_conn_replay_authenticator`. Returns the
        FFI rc (0=success, 1=no random captured, -1=anomaly).

        `out_len` is `*mut usize` on the Rust side; the wrapper passes
        Mojo's `UInt` (which is `usize`-sized on all supported targets).
        """
        var rlib = self._lib.inner_ptr()
        return rlib[].quic_server_conn_replay_authenticator(
            self.conn_handle,
            out_buf.unsafe_ptr(),
            UnsafePointer(to=out_len),
        )

    def _drive_replay_check_for_test(
        mut self,
        simulated_rc: Int32,
        simulated_decision_kind: UInt8,
        simulated_raises: Bool,
    ) raises:
        """Test-only entry point that mirrors the integration block's
        EXTERNALLY-OBSERVABLE transitions (the resulting
        `_zero_rtt_replay_decision` value + the recorded counter) for
        every reachable branch. The production block has one additional
        defensive `_early_data_store_ptr is None` fallback that the
        helper does not model independently — it collapses onto the
        same `no_authenticator` outcome as `simulated_rc != 0`, so the
        observable behaviour is identical. Production refactors that
        change observable transitions in the integration block MUST
        update this helper too; the byte-for-byte branching is a
        maintenance contract, not a structural invariant.

        A static check in `scripts/check_integrations.sh §3.8` enforces
        this method is callable only from `tests/` — production callers
        must take the integration path.

        Parameters:
            simulated_rc: FFI return code to simulate (0=success,
                1=no authenticator captured, -1=anomaly). rc != 0
                takes the no_authenticator branch.
            simulated_decision_kind: ReplayDecision.kind to simulate
                when rc == 0 and not raises (0=accept, 1=duplicate,
                2=per_key_quota, 3=global_ceiling).
            simulated_raises: True to simulate `store.check_and_record`
                raising; overrides simulated_decision_kind and takes
                the no_authenticator branch.
        """
        # Mirror the integration's idempotency guard: a committed
        # decision (1 or 2) is sticky.
        if self._zero_rtt_replay_decision != UInt8(0):
            return

        if simulated_rc != Int32(0):
            self._zero_rtt_replay_decision = UInt8(2)
            self._record_replay_reject_no_authenticator()
            return

        if simulated_raises:
            self._zero_rtt_replay_decision = UInt8(2)
            self._record_replay_reject_no_authenticator()
            return

        if simulated_decision_kind == UInt8(0):
            # accept
            self._zero_rtt_replay_decision = UInt8(1)
            self._record_replay_accept()
        elif simulated_decision_kind == UInt8(1):
            # duplicate
            self._zero_rtt_replay_decision = UInt8(2)
            self._record_replay_reject_duplicate()
        elif simulated_decision_kind == UInt8(2):
            # per_key_quota
            self._zero_rtt_replay_decision = UInt8(2)
            self._record_replay_reject_per_key_quota()
        else:
            # global_ceiling (kind == 3)
            self._zero_rtt_replay_decision = UInt8(2)
            self._record_replay_reject_global_ceiling()

    # ── Send path ────────────────────────────────────────────────────

    def send(mut self, now: UInt64) raises -> List[List[UInt8]]:
        """Build and return datagrams to send.

        Coalesces packets from multiple encryption levels into a single
        datagram when possible. Pads Initial datagrams to 1200 bytes.
        """
        var datagrams = List[List[UInt8]]()

        # Check timers first — drain/close timers must fire even when
        # the connection is draining (otherwise we never reach CLOSED).
        self._check_timers(now)

        if (self.state & CONN_DRAINING) != 0 or (self.state & CONN_CLOSED) != 0:
            return datagrams^

        # CC window + pacer gate: if we can't even fit one minimum-size packet, skip.
        # Anti-amplification is also re-checked per-space below.
        if not self._can_send(UInt64(1200), now):
            return datagrams^

        # Build one datagram with coalesced packets.
        var datagram = List[UInt8]()

        for space_idx in range(3):
            if not self.protect.has_keys(space_idx):
                continue

            # Anti-amplification check (server only, before address validated).
            if not self._anti_amp_ok(UInt64(len(datagram))):
                break

            var sent_records = List[SentStreamFrame]()
            var frames = self._build_frames_for_space(space_idx, now, sent_records)
            if len(frames) == 0:
                continue

            # Pad client long-header datagrams to 1200 bytes during handshake.
            # Initial: required by RFC 9000 §14.1.
            # Handshake: not strictly required, but necessary in practice —
            # some server stacks (Cloudflare/quiche) drop undersized client
            # datagrams during handshake due to anti-amplification accounting.
            if (space_idx == 0 or space_idx == 1) and not self.is_server:
                if (self.state & CONN_ESTABLISHED) == 0:
                    var hdr_overhead = 7 + len(self.peer_cid) + len(self.local_cid) + 2
                    var pn_est = 4  # max PN length
                    var tag_len = _AEAD_TAG_LEN

                    var est_writer = ByteWriter()
                    serialize_frames(frames, est_writer)
                    var est_payload = est_writer.finish()
                    var current_total = hdr_overhead + pn_est + len(est_payload) + tag_len + len(datagram)

                    if current_total < 1200:
                        var pad_needed = 1200 - current_total
                        for _ in range(pad_needed):
                            frames.append(Frame.padding())

            # Serialize frames.
            var writer = ByteWriter()
            serialize_frames(frames, writer)
            var payload = writer.finish()

            # Encode PN.
            var pn = self.spaces[space_idx].alloc_pn()
            var largest_acked = UInt64(0)
            if self.spaces[space_idx].largest_acked_pn >= 0:
                largest_acked = UInt64(self.spaces[space_idx].largest_acked_pn)
            var pn_len = pn_encode_length(pn, largest_acked)

            # Build header + encrypt + protect.
            var pkt = self._build_packet(space_idx, pn, pn_len, payload)
            var pkt_size = len(pkt)

            datagram.extend(pkt^)

            # NOTE: Initial discard deferred to _on_handshake_complete so the
            # client can coalesce Initial ACK + Handshake in the same datagram
            # (required by some server stacks for proper routing).

            # Record sent packet with ECN mark.
            var is_ack_eliciting = _has_ack_eliciting(frames)
            var ect = self.ecn_mark()
            var sent = SentPacket(
                pn=pn,
                time_sent=now,
                ack_eliciting=is_ack_eliciting,
                in_flight=True,
                size=pkt_size,
                frames=frames,
                ecn_mark=ect,
            )
            self.spaces[space_idx].on_packet_sent(sent)
            # Track ECT(0) in-flight count for bleaching check.
            if ect == ECN_ECT0:
                self.spaces[space_idx].ect0_in_flight += UInt64(1)
                if self.ecn_probe_pkts_sent == 0:
                    self.ecn_probe_first_pn = pn
                self.ecn_probe_pkts_sent += 1
            self.recovery.on_packet_sent(pkt_size, True, pn, now)
            # Commit pacer token for this packet — App-space only; matches
            # the gate bypass in _can_send and the deadline bypass in _next_timeout.
            if space_idx == 2:
                var _pace_rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
                _ = self.recovery.pacer.refill_and_check(_pace_rate, now)
                self.recovery.pacer.on_sent(UInt64(pkt_size))

            # Register stream-layer frame records for this Application-space packet
            # so ACK / loss handlers can re-apply state.
            if space_idx == 2 and len(sent_records) > 0:
                self.app_frames_sent[Int(pn)] = sent_records^

            # Track last ack-eliciting send time for PTO.
            if is_ack_eliciting:
                self.last_ack_eliciting_send_time = now

        if len(datagram) > 0:
            self.bytes_sent += UInt64(len(datagram))
            datagrams.append(datagram^)

        return datagrams^

    # ── Frame building ───────────────────────────────────────────────

    def _build_frames_for_space(
        mut self, space_idx: Int, now: UInt64,
        mut sent_records: List[SentStreamFrame],
    ) raises -> List[Frame]:
        """Collect frames to send for a given PN space.

        `sent_records` is populated for Application-space stream-layer frames
        (STREAM/RESET/STOP/MAX_*/NEW_CID/RETIRE_CID) so the caller can track
        them by packet number for ACK/loss processing.
        """
        var frames = List[Frame]()

        # When CLOSING, only send CONNECTION_CLOSE (RFC 9000 §10.2.1).
        if (self.state & CONN_CLOSING) != 0 and self.pending_close:
            # RFC 9000 §10.2.3: a CONNECTION_CLOSE of type 0x1d
            # (application namespace) MUST be replaced with a 0x1c
            # CONNECTION_CLOSE when emitted in Initial or Handshake
            # packets — application error codes have no meaning in those
            # spaces, so we re-pack as a transport-close carrying
            # APPLICATION_ERROR (0x0c) and drop the original code.
            if not self.pending_close.value().is_transport and space_idx != 2:
                var cc_to_emit = ConnectionCloseFrame()
                cc_to_emit.is_transport = True
                cc_to_emit.error_code = APPLICATION_ERROR
                cc_to_emit.frame_type = UInt64(0)
                cc_to_emit.reason = List[UInt8](copy=self.pending_close.value().reason)
                frames.append(Frame.connection_close(cc_to_emit))
            else:
                frames.append(
                    Frame.connection_close(self.pending_close.value())
                )
            return frames^

        # ACK frame (if needed).
        var maybe_ack = self.spaces[space_idx].build_ack_frame(UInt64(0))
        if maybe_ack:
            frames.append(Frame.ack(maybe_ack.value()))

        # CRYPTO frames from the crypto stream's send_buf.
        var crypto_frames = self.crypto_streams[space_idx].pending_crypto_frames(
            _MAX_CRYPTO_FRAME_SIZE
        )
        for i in range(len(crypto_frames)):
            frames.append(Frame.crypto(crypto_frames[i]))

        # Advance send offset for queued crypto data.
        if len(crypto_frames) > 0:
            var total_crypto = UInt64(0)
            for i in range(len(crypto_frames)):
                total_crypto += UInt64(len(crypto_frames[i].data))
            self.crypto_streams[space_idx].advance_send(total_crypto)

        # HANDSHAKE_DONE (server, Application space, once).
        if self.send_handshake_done and space_idx == 2 and self.is_server:
            frames.append(Frame.handshake_done())
            self.send_handshake_done = False

        # Application-space stream-layer frames.
        if space_idx == 2:
            # RFC 9000 §5.1.1: initial NEW_CONNECTION_ID burst. On the first
            # 1-RTT flush after CONN_ESTABLISHED, fill `local_cids` up to
            # `peer_active_limit` so the peer has spare CIDs for migration.
            # `_build_app_frames` below drains the resulting unadvertised
            # entries into NEW_CONNECTION_ID frames in this same flight —
            # alongside HANDSHAKE_DONE on the server's very first 1-RTT
            # packet (per RFC 9000 §5.1.1 SHOULD).
            if (
                self.is_server
                and not self.initial_cids_emitted
                and (self.state & CONN_ESTABLISHED) != 0
            ):
                var limit = Int(self.cid_mgr.peer_active_limit)
                while self.cid_mgr.active_local_count() < limit:
                    var issued = self.cid_mgr.issue_new_cid()
                    if not Bool(issued):
                        break
                self.initial_cids_emitted = True

            self._build_app_frames(frames, sent_records)

            # RFC 9000 §8.2 / §17.2.4: PATH_RESPONSE and PATH_CHALLENGE are
            # 1-RTT-only (F13 already closes Initial/Handshake at RX). Drain
            # any pending echoes first, then any freshly-queued challenges.
            var path_responses = self.emit_path_response_frames()
            for i in range(len(path_responses)):
                ref pr = path_responses[i]
                frames.append(pr.copy())
            var path_challenges = self.emit_path_challenge_frames(now)
            for i in range(len(path_challenges)):
                ref pc = path_challenges[i]
                frames.append(pc.copy())

            # RFC 9221 §5: drain outbound DATAGRAM payloads into 1-RTT
            # DATAGRAM_LEN (0x31) frames so they compose with stream/ACK
            # frames in the same packet. The Mojo `List` has no pop_front,
            # so we rebuild the queue from index 1 — acceptable because
            # the queue is short-lived (drained every flush) and each
            # element is itself a small List[UInt8]. Crucially, we do NOT
            # append entries to `sent_records`: DATAGRAMs are not retransmitted
            # on loss (RFC 9221 §5.4), so loss-recovery must treat the
            # carrying packet's DATAGRAMs as discarded rather than queued.
            while len(self.pending_outbound_datagrams) > 0:
                var head = List[UInt8](copy=self.pending_outbound_datagrams[0])
                var rest = List[List[UInt8]]()
                for i in range(1, len(self.pending_outbound_datagrams)):
                    rest.append(List[UInt8](copy=self.pending_outbound_datagrams[i]))
                self.pending_outbound_datagrams = rest^
                frames.append(Frame.datagram_with_len(head^))

        return frames^

    def _build_app_frames(
        mut self,
        mut frames: List[Frame],
        mut sent_records: List[SentStreamFrame],
    ) raises:
        """Append Application-space stream / FC / CID frames and record them."""

        # 1. NEW_CONNECTION_ID frames for unadvertised local CIDs.
        var pending_new = self.cid_mgr.pending_new_cid_entries()
        for i in range(len(pending_new)):
            var entry = CidEntry(other=pending_new[i])
            var ncid = NewConnectionIdFrame()
            ncid.sequence = entry.sequence
            ncid.retire_prior_to = self.cid_mgr.local_retire_prior_to
            ncid.cid = List[UInt8](copy=entry.cid)
            ncid.stateless_reset_token = List[UInt8](copy=entry.reset_token)
            frames.append(Frame.new_connection_id(ncid))
            var rec = SentStreamFrame()
            rec.kind = SSF_NEW_CID
            rec.cid_seq = entry.sequence
            sent_records.append(rec^)
            self.cid_mgr.mark_advertised(entry.sequence)

        # 2. RETIRE_CONNECTION_ID frames drain cid_mgr's retirement queue.
        # Safety invariant: pending_retire_frames() drains the queue here, before
        # the packet is committed.  This is safe because no code path between this
        # call and on_packet_sent can raise — so the drain is always paired with a
        # committed packet.  If a lost packet is detected later, _on_app_pkt_lost
        # re-appends the seq numbers to retire_queue so they are retransmitted.
        var pending_retire = self.cid_mgr.pending_retire_frames()
        for i in range(len(pending_retire)):
            var seq = pending_retire[i]
            frames.append(Frame.retire_connection_id(seq))
            var rec = SentStreamFrame()
            rec.kind = SSF_RETIRE_CID
            rec.cid_seq = seq
            sent_records.append(rec^)

        # 3. Connection-level MAX_DATA.
        if self.stream_map.conn_fc_recv.should_update() or self.stream_map.needs_max_data:
            var new_limit = self.stream_map.conn_fc_recv.update_limit()
            frames.append(Frame.max_data(new_limit))
            self.stream_map.needs_max_data = False
            var rec = SentStreamFrame()
            rec.kind = SSF_MAX_DATA
            sent_records.append(rec^)

        # 4. MAX_STREAMS (bidi / uni).
        if self.stream_map.needs_max_streams_bidi:
            var ms = MaxStreamsFrame(self.stream_map.local_max_streams_bidi, True)
            frames.append(Frame.max_streams(ms))
            self.stream_map.needs_max_streams_bidi = False
            var rec = SentStreamFrame()
            rec.kind = SSF_MAX_STREAMS_BIDI
            sent_records.append(rec^)
        if self.stream_map.needs_max_streams_uni:
            var ms = MaxStreamsFrame(self.stream_map.local_max_streams_uni, False)
            frames.append(Frame.max_streams(ms))
            self.stream_map.needs_max_streams_uni = False
            var rec = SentStreamFrame()
            rec.kind = SSF_MAX_STREAMS_UNI
            sent_records.append(rec^)

        # 5. Per-stream control frames (MAX_STREAM_DATA, RESET_STREAM, STOP_SENDING).
        # Snapshot stream IDs so we can safely mutate the Dict while iterating.
        var all_ids = List[Int]()
        for key in self.stream_map.streams.keys():
            all_ids.append(key)
        for i in range(len(all_ids)):
            var sid = all_ids[i]
            if sid not in self.stream_map.streams:
                continue
            var stream = self.stream_map.get_stream(sid)
            var changed = False

            # MAX_STREAM_DATA
            if stream.needs_max_stream_data and stream.fc_recv:
                var fc = stream.fc_recv.value().copy()
                var new_limit = fc.update_limit()
                stream.fc_recv = fc^
                stream.needs_max_stream_data = False
                frames.append(Frame.max_stream_data(MaxStreamDataFrame(stream.id, new_limit)))
                var rec = SentStreamFrame()
                rec.kind = SSF_MAX_STREAM_DATA
                rec.stream_id = stream.id
                sent_records.append(rec^)
                changed = True

            # RESET_STREAM
            if stream.needs_reset_stream:
                var rs_f = ResetStreamFrame(
                    stream.id,
                    stream.reset_stream_error,
                    stream.reset_stream_final_size,
                )
                frames.append(Frame.reset_stream(rs_f))
                stream.needs_reset_stream = False
                var rec = SentStreamFrame()
                rec.kind = SSF_RESET_STREAM
                rec.stream_id = stream.id
                sent_records.append(rec^)
                changed = True

            # STOP_SENDING
            if stream.needs_stop_sending:
                var ss_f = StopSendingFrame(stream.id, stream.stop_sending_error)
                frames.append(Frame.stop_sending(ss_f))
                stream.needs_stop_sending = False
                var rec = SentStreamFrame()
                rec.kind = SSF_STOP_SENDING
                rec.stream_id = stream.id
                sent_records.append(rec^)
                changed = True

            if changed:
                self.stream_map.set_stream(sid, stream^)

        # 6. STREAM frames from sendable streams (round-robin snapshot).
        # Snapshot sendable IDs to avoid mutation-during-iteration.
        var sendable = List[Int]()
        for i in range(len(self.stream_map.sendable_ids)):
            sendable.append(self.stream_map.sendable_ids[i])

        var max_bytes_per_frame = 1200
        var n = len(sendable)
        # Rotate starting point for fairness: low-ID streams don't always win.
        var start = 0
        if n > 0:
            start = self.stream_map.send_index % n
            self.stream_map.send_index = (self.stream_map.send_index + 1) % n
        for i in range(n):
            var conn_avail = self.stream_map.conn_fc_send.available()
            if conn_avail == 0:
                break
            var idx = (start + i) % n
            var sid = sendable[idx]
            if sid not in self.stream_map.streams:
                continue
            var stream = self.stream_map.get_stream(sid)
            if not stream.send_state or not stream.send_buf or not stream.fc_send:
                continue
            var ss = stream.send_state.value()
            if ss != SEND_READY and ss != SEND_SEND:
                continue
            var sb = stream.send_buf.value().copy()
            var fc = stream.fc_send.value().copy()
            var stream_avail = fc.available()
            if stream_avail == 0 and not (sb.fin and not sb.fin_offset):
                continue
            var limit = Int(conn_avail)
            if Int(stream_avail) < limit:
                limit = Int(stream_avail)
            if max_bytes_per_frame < limit:
                limit = max_bytes_per_frame
            # If the only work is a standalone FIN, limit can be 0: make_frame
            # handles this via fin-only emission.
            var maybe_frame = sb.make_frame(stream.id, limit)
            if not maybe_frame:
                # Nothing to send from this stream; drop from sendable list.
                stream.send_buf = sb^
                stream.fc_send = fc^
                self.stream_map.set_stream(sid, stream^)
                self.stream_map.remove_sendable(sid)
                continue
            var sf = maybe_frame.value().copy()
            var frame_len = UInt64(len(sf.data))
            var frame_offset = sf.offset
            var frame_fin = sf.fin
            frames.append(Frame._stream_move(sf))
            # Flow-control accounting (only "new" bytes past received mark).
            var prev_end = frame_offset + frame_len
            if prev_end > fc.received:
                var delta = prev_end - fc.received
                fc.add_received(delta)
                self.stream_map.conn_fc_send.add_received(delta)
            # Send-state transitions.
            if ss == SEND_READY:
                stream.send_state = Optional[UInt8](SEND_SEND)
            if frame_fin and sb.fin_offset:
                stream.send_state = Optional[UInt8](SEND_DATA_SENT)
            stream.send_buf = sb^
            stream.fc_send = fc^
            var rec = SentStreamFrame()
            rec.kind = SSF_STREAM
            rec.stream_id = stream.id
            rec.offset = frame_offset
            rec.length = frame_len
            rec.fin = frame_fin
            sent_records.append(rec^)
            var still_pending = stream.send_buf.value().has_pending()
            self.stream_map.set_stream(sid, stream^)
            if not still_pending:
                self.stream_map.remove_sendable(sid)

        # 7. DATA_BLOCKED (RFC 9000 §4.1) — connection-level FC exhausted.
        var conn_limit = self.stream_map.conn_fc_send.limit
        if (self.stream_map.conn_fc_send.received >= conn_limit
                and self.stream_map.conn_fc_send.blocked_at != conn_limit):
            frames.append(Frame.data_blocked(conn_limit))
            self.stream_map.conn_fc_send.blocked_at = conn_limit

        # 8. STREAM_DATA_BLOCKED (RFC 9000 §4.1) — per-stream FC exhausted.
        var blocked_ids = List[Int]()
        for key in self.stream_map.streams.keys():
            blocked_ids.append(key)
        for i in range(len(blocked_ids)):
            var sid = blocked_ids[i]
            if sid not in self.stream_map.streams:
                continue
            var stream = self.stream_map.get_stream(sid)
            if not stream.fc_send:
                continue
            var fc = stream.fc_send.value().copy()
            var stream_limit = fc.limit
            if fc.available() == UInt64(0) and fc.blocked_at != stream_limit and stream_limit > UInt64(0):
                frames.append(Frame.stream_data_blocked(StreamDataBlockedFrame(stream.id, stream_limit)))
                fc.blocked_at = stream_limit
                stream.fc_send = fc^
                self.stream_map.set_stream(sid, stream^)

        # 9. STREAMS_BLOCKED (RFC 9000 §4.6) — local stream count at peer concurrency limit.
        if self.stream_map.needs_streams_blocked_bidi:
            var bidi_limit = self.stream_map.peer_max_streams_bidi
            if self.stream_map.streams_blocked_at_bidi != bidi_limit:
                frames.append(
                    Frame.streams_blocked(StreamsBlockedFrame(bidi_limit, True))
                )
                self.stream_map.streams_blocked_at_bidi = bidi_limit
        if self.stream_map.needs_streams_blocked_uni:
            var uni_limit = self.stream_map.peer_max_streams_uni
            if self.stream_map.streams_blocked_at_uni != uni_limit:
                frames.append(
                    Frame.streams_blocked(StreamsBlockedFrame(uni_limit, False))
                )
                self.stream_map.streams_blocked_at_uni = uni_limit

    # ── Packet building ──────────────────────────────────────────────

    def _build_packet(
        mut self,
        space_idx: Int,
        pn: UInt64,
        pn_len: Int,
        payload: List[UInt8],
    ) raises -> List[UInt8]:
        """Build a complete encrypted QUIC packet.

        1. Serialize header.
        2. Write PN bytes.
        3. AEAD encrypt the frame payload.
        4. Apply header protection.
        """
        var payload_ciphertext_len = len(payload) + _AEAD_TAG_LEN

        if space_idx == 0 or space_idx == 1:
            # Long header (Initial or Handshake).
            var header = PacketHeader()
            header.is_long_header = True
            header.version = UInt32(1)
            header.dcid = List[UInt8](copy=self.peer_cid)
            header.scid = List[UInt8](copy=self.local_cid)

            if space_idx == 0:
                header.packet_type = PacketType.initial()
                # Token is empty (no retry support yet).
                header.token = List[UInt8]()
            else:
                header.packet_type = PacketType.handshake()

            # payload_length = pn_len + ciphertext + tag.
            header.payload_length = UInt64(pn_len + payload_ciphertext_len)

            # Serialize header.
            var hw = ByteWriter()
            serialize_long_header(header, hw)
            var header_bytes = hw.finish()

            # Set PN length in the first byte (lower 2 bits = pn_len - 1).
            header_bytes[0] = (header_bytes[0] & 0xFC) | UInt8(pn_len - 1)

            # Record pn_offset (where PN bytes start).
            var pn_offset = len(header_bytes)

            # Append PN bytes.
            var truncated = pn_truncate(pn, pn_len)
            for i in range(pn_len):
                var shift = UInt64((pn_len - 1 - i) * 8)
                header_bytes.append(UInt8((truncated >> shift) & 0xFF))

            # Encrypt + protect in a single buffer (zero-copy).
            # Append payload to header_bytes.
            for i in range(len(payload)):
                header_bytes.append(payload[i])
            # Append zero space for AEAD tag.
            for _ in range(_AEAD_TAG_LEN):
                header_bytes.append(UInt8(0))

            # header_bytes is now: [header | PN | payload | tag_space]
            var total_len = len(header_bytes)
            var pkt_ptr = header_bytes.unsafe_ptr().unsafe_mut_cast[True]().as_unsafe_any_origin()

            # Encrypt payload region in-place.
            var header_len = pn_offset + pn_len
            _ = self.protect.encrypt_payload_in_place(
                space_idx, pn, pkt_ptr, header_len,
                len(payload), total_len,
            )

            # Protect header in-place.
            self.protect.protect_header_ptr(
                space_idx, pkt_ptr, total_len, pn_offset, pn_len,
            )

            return header_bytes^

        else:
            # Short header (1-RTT / Application).
            var hw = ByteWriter()
            serialize_short_header(Span(self.peer_cid), hw)
            var header_bytes = hw.finish()

            # Set PN length in the first byte (lower 2 bits = pn_len - 1).
            header_bytes[0] = (header_bytes[0] & 0xFC) | UInt8(pn_len - 1)

            # Record pn_offset.
            var pn_offset = len(header_bytes)

            # Append PN bytes.
            var truncated = pn_truncate(pn, pn_len)
            for i in range(pn_len):
                var shift = UInt64((pn_len - 1 - i) * 8)
                header_bytes.append(UInt8((truncated >> shift) & 0xFF))

            # Header-protection requires the ciphertext to be at least
            # _MAX_PN_LEN + _HP_SAMPLE_LEN = 20 bytes after pn_offset.
            # ciphertext = payload + AEAD_TAG(16), so payload must be >= 4
            # for a 1-byte PN.  Pad with QUIC PADDING (0x00) if needed.
            # Pad payload to minimum size for HP sample.
            var min_payload_len = _MAX_PN_LEN
            for i in range(len(payload)):
                header_bytes.append(payload[i])
            var current_payload_len = len(payload)
            while current_payload_len < min_payload_len:
                header_bytes.append(UInt8(0))
                current_payload_len += 1

            # Append zero space for AEAD tag.
            for _ in range(_AEAD_TAG_LEN):
                header_bytes.append(UInt8(0))

            var total_len = len(header_bytes)
            var pkt_ptr = header_bytes.unsafe_ptr().unsafe_mut_cast[True]().as_unsafe_any_origin()

            # Encrypt payload region in-place.
            var header_len = pn_offset + pn_len
            _ = self.protect.encrypt_payload_in_place(
                space_idx, pn, pkt_ptr, header_len,
                current_payload_len, total_len,
            )

            # Protect header in-place.
            self.protect.protect_header_ptr(
                space_idx, pkt_ptr, total_len, pn_offset, pn_len,
            )

            return header_bytes^

    # ── Application-space frame ACK/loss handling ─────────────

    def _on_app_pkt_acked(mut self, pn: Int) raises:
        """Apply ACK side-effects for stream-layer frames in the acked packet."""
        if pn not in self.app_frames_sent:
            return
        var records = self.app_frames_sent[pn].copy()
        _ = self.app_frames_sent.pop(pn)
        for i in range(len(records)):
            var rec = SentStreamFrame(other=records[i])
            if rec.kind == SSF_STREAM:
                var key = Int(rec.stream_id)
                if key not in self.stream_map.streams:
                    continue
                var stream = self.stream_map.get_stream(key)
                if stream.send_buf:
                    var sb = stream.send_buf.value().copy()
                    sb.on_ack(rec.offset, rec.length)
                    var fully = sb.is_fully_acked()
                    stream.send_buf = sb^
                    if fully and stream.send_state:
                        var ss = stream.send_state.value()
                        if ss == SEND_DATA_SENT:
                            stream.send_state = Optional[UInt8](SEND_DATA_RECVD)
                    self.stream_map.set_stream(key, stream^)
                    _ = self.stream_map.maybe_cleanup(key)
                else:
                    self.stream_map.set_stream(key, stream^)
            elif rec.kind == SSF_RESET_STREAM:
                var key = Int(rec.stream_id)
                if key not in self.stream_map.streams:
                    continue
                var stream = self.stream_map.get_stream(key)
                if stream.send_state:
                    var ss = stream.send_state.value()
                    if ss == SEND_RESET_SENT:
                        stream.send_state = Optional[UInt8](SEND_RESET_RECVD)
                self.stream_map.set_stream(key, stream^)
                _ = self.stream_map.maybe_cleanup(key)
            elif rec.kind == SSF_STOP_SENDING:
                # STOP_SENDING ACK does not change recv state; peer must send
                # RESET_STREAM for that. Nothing to do.
                pass
            elif rec.kind == SSF_MAX_DATA:
                pass
            elif rec.kind == SSF_MAX_STREAM_DATA:
                pass
            elif rec.kind == SSF_MAX_STREAMS_BIDI:
                pass
            elif rec.kind == SSF_MAX_STREAMS_UNI:
                pass
            elif rec.kind == SSF_NEW_CID:
                pass
            elif rec.kind == SSF_RETIRE_CID:
                pass

    def _on_app_pkt_lost(mut self, pn: Int) raises:
        """Re-queue stream-layer frames for retransmission on packet loss."""
        if pn not in self.app_frames_sent:
            return
        var records = self.app_frames_sent[pn].copy()
        _ = self.app_frames_sent.pop(pn)
        for i in range(len(records)):
            var rec = SentStreamFrame(other=records[i])
            if rec.kind == SSF_STREAM:
                var key = Int(rec.stream_id)
                if key not in self.stream_map.streams:
                    continue
                var stream = self.stream_map.get_stream(key)
                if stream.send_buf:
                    var sb = stream.send_buf.value().copy()
                    sb.on_loss(rec.offset, rec.length)
                    var has_pending = sb.has_pending()
                    stream.send_buf = sb^
                    self.stream_map.set_stream(key, stream^)
                    if has_pending:
                        self.stream_map.add_sendable(key)
                else:
                    self.stream_map.set_stream(key, stream^)
            elif rec.kind == SSF_RESET_STREAM:
                var key = Int(rec.stream_id)
                if key in self.stream_map.streams:
                    var stream = self.stream_map.get_stream(key)
                    stream.needs_reset_stream = True
                    self.stream_map.set_stream(key, stream^)
            elif rec.kind == SSF_STOP_SENDING:
                var key = Int(rec.stream_id)
                if key in self.stream_map.streams:
                    var stream = self.stream_map.get_stream(key)
                    stream.needs_stop_sending = True
                    self.stream_map.set_stream(key, stream^)
            elif rec.kind == SSF_MAX_DATA:
                self.stream_map.needs_max_data = True
            elif rec.kind == SSF_MAX_STREAM_DATA:
                var key = Int(rec.stream_id)
                if key in self.stream_map.streams:
                    var stream = self.stream_map.get_stream(key)
                    stream.needs_max_stream_data = True
                    self.stream_map.set_stream(key, stream^)
            elif rec.kind == SSF_MAX_STREAMS_BIDI:
                self.stream_map.needs_max_streams_bidi = True
            elif rec.kind == SSF_MAX_STREAMS_UNI:
                self.stream_map.needs_max_streams_uni = True
            elif rec.kind == SSF_NEW_CID:
                # Clear advertised flag so the CID is re-queued for a new
                # NEW_CONNECTION_ID frame on the next send opportunity.
                self.cid_mgr.clear_advertised(rec.cid_seq)
            elif rec.kind == SSF_RETIRE_CID:
                # Re-queue the retirement if possible (respects cap).
                self.cid_mgr.requeue_retire(rec.cid_seq)

    # ── Timers ───────────────────────────────────────────────────────

    def timeout(self, now: UInt64) -> Optional[UInt64]:
        """Return the earliest deadline among PTO, idle, close/drain, and pacer timers.

        Returns None if no timer is active.
        """
        var earliest = Optional[UInt64](None)

        # PTO timer — skip when server is amplification-limited (M7).
        if not (self.is_server and (self.state & CONN_ADDR_VALIDATED) == 0):
            # Only arm PTO if we have sent ack-eliciting packets.
            if self.last_ack_eliciting_send_time > 0:
                var max_ack_delay_us = self.local_params.max_ack_delay * 1000
                var pto = self.recovery.pto_timeout(max_ack_delay_us)
                var pto_deadline = self.last_ack_eliciting_send_time + pto
                earliest = pto_deadline
            elif not self.is_server:
                # Client anti-deadlock: arm PTO from idle_timer even without sends.
                var max_ack_delay_us = self.local_params.max_ack_delay * 1000
                var pto = self.recovery.pto_timeout(max_ack_delay_us)
                var pto_deadline = self.idle_timer + pto
                earliest = pto_deadline

        # Idle timer — use effective min(local, peer) (M8).
        var idle_effective = self._effective_idle_timeout()
        if idle_effective > 0:
            var idle_deadline = self.idle_timer + idle_effective * 1000
            if earliest:
                if idle_deadline < earliest.value():
                    earliest = idle_deadline
            else:
                earliest = idle_deadline

        # Close timer.
        if self.close_timer > 0:
            if earliest:
                if self.close_timer < earliest.value():
                    earliest = self.close_timer
            else:
                earliest = self.close_timer

        # Drain timer.
        if self.drain_timer > 0:
            if earliest:
                if self.drain_timer < earliest.value():
                    earliest = self.drain_timer
            else:
                earliest = self.drain_timer

        # --- Pacer branch ---
        # Pacer deadlines do not gate handshake-space sends (see _can_send).
        if self.is_established():
            var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
            var pacer_deadline = self.recovery.pacer.next_send_time(rate, now)
            if pacer_deadline:
                if earliest:
                    if pacer_deadline.value() < earliest.value():
                        earliest = pacer_deadline
                else:
                    earliest = pacer_deadline

        return earliest^

    def _effective_idle_timeout(self) -> UInt64:
        """Compute effective idle timeout per RFC 9000 §10.1."""
        var local_idle = self.local_params.max_idle_timeout
        var peer_idle = UInt64(0)
        if self.peer_params:
            peer_idle = self.peer_params.value().max_idle_timeout
        if local_idle == 0 and peer_idle == 0:
            return UInt64(0)
        if local_idle == 0:
            return peer_idle
        if peer_idle == 0:
            return local_idle
        if peer_idle < local_idle:
            return peer_idle
        return local_idle

    def _check_timers(mut self, now: UInt64):
        """Check and handle expired timers."""
        # Drain timer.
        if self.drain_timer > 0 and now >= self.drain_timer:
            self.state = self.state | CONN_CLOSED
            self.drain_timer = UInt64(0)
            return

        # Close timer.
        if self.close_timer > 0 and now >= self.close_timer:
            self.state = self.state | CONN_CLOSED
            self.close_timer = UInt64(0)
            return

        # Idle timeout — use effective min(local, peer).
        var idle_effective = self._effective_idle_timeout()
        if idle_effective > 0:
            var idle_deadline = self.idle_timer + idle_effective * 1000
            if now >= idle_deadline:
                self.state = self.state | CONN_CLOSED
                self.events.append(
                    QuicEvent.connection_closed(UInt64(0), String("idle timeout"))
                )
                return

        # PTO fire: resend CRYPTO or send PING.
        if (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
            return
        # Skip PTO when server is amplification-limited.
        if self.is_server and (self.state & CONN_ADDR_VALIDATED) == 0:
            return
        var max_ack_delay_us = UInt64(0)
        if self.handshake_confirmed:
            max_ack_delay_us = self.local_params.max_ack_delay * 1000
        var pto = self.recovery.pto_timeout(max_ack_delay_us)
        var pto_deadline = self.last_ack_eliciting_send_time + pto
        # Client anti-deadlock: arm PTO even with no in-flight packets.
        if not self.is_server and self.recovery.bytes_in_flight == 0 and (self.state & CONN_HANDSHAKING) != 0:
            pto_deadline = self.idle_timer + pto
        if self.last_ack_eliciting_send_time > 0 or (not self.is_server and (self.state & CONN_HANDSHAKING) != 0):
            if now >= pto_deadline:
                self.recovery.pto_count += 1
                # Re-queue CRYPTO frames from unacked sent_packets for
                # retransmission.  advance_send() already consumed the
                # original send_buf bytes after the first send(), so we
                # must copy CRYPTO data back from the SentPacket records.
                var pto_space = -1
                for s in range(3):
                    if not self.protect.has_keys(s):
                        continue
                    # First check if send_buf already has data.
                    if len(self.crypto_streams[s].send_buf) > 0:
                        pto_space = s
                        continue
                    # Otherwise recover CRYPTO from unacked packets.
                    var requeued = False
                    for entry in self.spaces[s].sent_packets.items():
                        for fi in range(len(entry.value.frames)):
                            if entry.value.frames[fi].is_crypto():
                                if entry.value.frames[fi]._crypto:
                                    var cf = entry.value.frames[fi]._crypto.value().copy()
                                    self.crypto_streams[s].requeue(
                                        cf.offset, Span(cf.data)
                                    )
                                    requeued = True
                    if requeued:
                        pto_space = s
                if pto_space >= 0:
                    # CRYPTO data is now in send_buf; next
                    # _build_frames_for_space will pick it up.
                    pass
                else:
                    # Send PING in highest available space.
                    for s in range(2, -1, -1):
                        if self.protect.has_keys(s):
                            self.spaces[s].ack_needed = True  # Force a packet
                            break

    # ── Public API ───────────────────────────────────────────────────

    def poll(mut self) -> Optional[QuicEvent]:
        """Return the next pending event, or None."""
        if len(self.events) > 0:
            # Pop the first event.
            var ev = self.events[0].copy()
            var new_events = List[QuicEvent]()
            for i in range(1, len(self.events)):
                new_events.append(self.events[i].copy())
            self.events = new_events^
            return ev^
        return None

    def close_transport(mut self, error_code: UInt64, reason: String, now: UInt64):
        """Initiate a graceful CONNECTION_CLOSE (RFC 9000 §19.19 frame type 0x1c).

        Use this for transport-layer error codes per RFC 9000 §20.1.
        Application-namespace errors must use `close_app` instead so that
        the correct frame type and error-code namespace are emitted.
        """
        self._close_impl(error_code, reason, now, is_app=False)

    def close_app(mut self, error_code: UInt64, reason: String, now: UInt64):
        """Initiate a graceful CONNECTION_CLOSE_APP (RFC 9000 §19.19 frame type 0x1d).

        Use this for application-layer error codes — for navette today
        that means the HTTP/3 codes in RFC 9114 §8.1 and the QPACK codes
        in RFC 9204 §7. Transport-namespace errors must use
        `close_transport` instead.
        """
        self._close_impl(error_code, reason, now, is_app=True)

    def _close_impl(mut self, error_code: UInt64, reason: String, now: UInt64, is_app: Bool):
        """Shared implementation for `close_transport` and `close_app`.

        Idempotent: subsequent calls after CLOSING/DRAINING/CLOSED is set
        are no-ops. Builds the appropriate `ConnectionCloseFrame` (transport
        or application) and queues it as `pending_close`; arms the 3*PTO
        close timer so the loss recovery layer can finalize teardown.
        """
        if (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
            return
        self.state = self.state | CONN_CLOSING
        # Set close timer: 3 * PTO.
        var max_ack_delay_us = self.local_params.max_ack_delay * 1000
        var pto = self.recovery.pto_timeout(max_ack_delay_us)
        self.close_timer = now + 3 * pto
        var reason_bytes = List[UInt8]()
        var reason_str_bytes = reason.as_bytes()
        for i in range(len(reason_str_bytes)):
            reason_bytes.append(reason_str_bytes[i])
        var cc = ConnectionCloseFrame()
        cc.is_transport = not is_app
        cc.error_code = error_code
        cc.frame_type = UInt64(0)
        cc.reason = reason_bytes^
        self.pending_close = cc^

    def is_established(self) -> Bool:
        """True if the handshake is complete and the connection is usable."""
        return (self.state & CONN_ESTABLISHED) != 0

    def is_expected_dcid(self, dcid: Span[UInt8, _]) -> Bool:
        """True if `dcid` matches either initial_dcid or local_cid.

        - `initial_dcid` is the client's random Initial DCID, used for
          Initial-key derivation. Valid pre-handshake and during the brief
          post-handshake transition before the client switches over.
        - `local_cid` is the server's chosen SCID (or, on a client conn,
          the locally-chosen SCID). The peer uses it as DCID after the
          first server Initial.

        Connection migration is a v1 non-goal. Once
        NEW_CONNECTION_ID emission lands, expand this accessor to a set
        membership over all active local CIDs.
        """
        if len(dcid) == len(self.initial_dcid):
            var match_initial = True
            for i in range(len(dcid)):
                if dcid[i] != self.initial_dcid[i]:
                    match_initial = False
                    break
            if match_initial:
                return True
        if len(dcid) == len(self.local_cid):
            var match_local = True
            for i in range(len(dcid)):
                if dcid[i] != self.local_cid[i]:
                    match_local = False
                    break
            if match_local:
                return True
        return False

    def is_closed(self) -> Bool:
        """True if the connection has fully terminated."""
        return (self.state & CONN_CLOSED) != 0

    def is_draining(self) -> Bool:
        """True if the connection is in the draining state."""
        return (self.state & CONN_DRAINING) != 0

    def peer_max_bidi_streams_raw(self) -> UInt64:
        """Return the peer's MAX_STREAMS (bidirectional) limit without copying.

        Reads `self.stream_map.peer_max_streams_bidi` directly. Intended for
        hot-path consumers (e.g. requette's connection pool calling on every
        acquire) that only need the bidirectional concurrency ceiling and
        must avoid copying any `StreamMap` snapshot.
        """
        return self.stream_map.peer_max_streams_bidi

    # ── Stream public API ──────────────────────────────────────

    def open_stream(mut self, bidi: Bool) raises -> UInt64:
        """Open a new locally-initiated stream.  Returns the stream ID."""
        if (self.state & CONN_CLOSING) != 0 or (self.state & CONN_CLOSED) != 0:
            raise "connection closing/closed"
        if (self.state & CONN_DRAINING) != 0:
            raise "connection draining"
        return self.stream_map.open_stream(bidi)

    def send_stream_data(
        mut self, stream_id: UInt64, data: Span[UInt8, _], fin: Bool
    ) raises:
        """Queue data for sending on a stream (and optionally mark FIN)."""
        var key = Int(stream_id)
        if key not in self.stream_map.streams:
            raise "unknown stream"
        var stream = self.stream_map.get_stream(key)
        if not stream.send_state or not stream.send_buf:
            raise "STREAM_STATE_ERROR: no send side"
        var ss = stream.send_state.value()
        if (ss == SEND_DATA_SENT or ss == SEND_DATA_RECVD
                or ss == SEND_RESET_SENT or ss == SEND_RESET_RECVD):
            raise "STREAM_STATE_ERROR: send side terminal or FIN already queued"
        var sb = stream.send_buf.value().copy()
        sb.write(data, fin)
        var has_pending = sb.has_pending()
        stream.send_buf = sb^
        self.stream_map.set_stream(key, stream^)
        if has_pending:
            self.stream_map.add_sendable(key)

    def recv_stream_data(
        mut self, stream_id: UInt64
    ) raises -> Tuple[List[UInt8], Bool]:
        """Read available contiguous bytes from a stream's recv buffer.

        Returns (bytes, fin_reached). Consumes FC credit for the drained bytes
        and flags MAX_DATA / MAX_STREAM_DATA updates as needed.
        """
        var key = Int(stream_id)
        if key not in self.stream_map.streams:
            raise "unknown stream"
        var stream = self.stream_map.get_stream(key)
        if not stream.recv_buf or not stream.fc_recv:
            raise "STREAM_STATE_ERROR: no recv side"
        var rb = stream.recv_buf.value().copy()
        var result = rb.read(stream.fin_offset)
        var data = result[0].copy()
        var fin_reached = result[1]
        var drained = UInt64(len(data))
        var fc = stream.fc_recv.value().copy()
        if drained > 0:
            fc.add_consumed(drained)
            self.stream_map.conn_fc_recv.add_consumed(drained)
        if fc.should_update():
            stream.needs_max_stream_data = True
        if self.stream_map.conn_fc_recv.should_update():
            self.stream_map.needs_max_data = True
        stream.recv_buf = rb^
        stream.fc_recv = fc^
        if stream.recv_state:
            var rs = stream.recv_state.value()
            if rs == RECV_DATA_RECVD and fin_reached:
                stream.recv_state = Optional[UInt8](RECV_DATA_READ)
        self.stream_map.set_stream(key, stream^)
        _ = self.stream_map.maybe_cleanup(key)
        return (data^, fin_reached)

    def reset_stream(mut self, stream_id: UInt64, error_code: UInt64) raises:
        """Abort the send side of a stream with the given error code."""
        var key = Int(stream_id)
        if key not in self.stream_map.streams:
            raise "unknown stream"
        var stream = self.stream_map.get_stream(key)
        if not stream.send_state:
            raise "STREAM_STATE_ERROR: no send side"
        var ss = stream.send_state.value()
        if (ss == SEND_DATA_RECVD or ss == SEND_RESET_SENT
                or ss == SEND_RESET_RECVD):
            self.stream_map.set_stream(key, stream^)
            return
        var final_size: UInt64 = 0
        if stream.send_buf:
            var sb = stream.send_buf.value().copy()
            if sb.fin_offset:
                final_size = sb.fin_offset.value()
            else:
                final_size = sb.unsent_offset
        stream.send_state = Optional[UInt8](SEND_RESET_SENT)
        stream.needs_reset_stream = True
        stream.reset_stream_error = error_code
        stream.reset_stream_final_size = final_size
        self.stream_map.remove_sendable(key)
        self.stream_map.set_stream(key, stream^)

    def send_datagram(mut self, payload: Span[UInt8, _]) raises -> Bool:
        """RFC 9221 §5 — enqueue a QUIC DATAGRAM frame for the next 1-RTT flush.

        Returns True on enqueue success; False if any of the following hold:
          * the peer omitted `max_datagram_frame_size` from its transport
            parameters or advertised 0 — meaning it cannot receive DATAGRAMs,
          * the payload exceeds the peer-advertised cap (RFC 9221 §3),
          * the connection is closing/draining (no 1-RTT flush will occur).

        On True, the payload is copied onto `pending_outbound_datagrams`
        and drained by the 1-RTT branch of `_build_frames_for_space` as
        DATAGRAM_LEN (0x31). False is a non-fatal signal — the caller is
        expected to surface a "cannot send" status to its own consumer.

        DATAGRAMs are NOT subject to congestion control, flow control, or
        retransmission (RFC 9221 §5.4): if the packet carrying this
        DATAGRAM is lost, the payload is gone. Callers that need
        reliability MUST use STREAM frames.
        """
        # Closing/draining ⇒ no flush will happen; refuse early so the
        # caller learns the queue is closed.
        if (self.state & CONN_CLOSING) != 0 or (self.state & CONN_CLOSED) != 0:
            return False
        if (self.state & CONN_DRAINING) != 0:
            return False
        # Pre-handshake the peer's transport parameters are not yet known.
        # Per RFC 9221 §5 a DATAGRAM may only ride in 1-RTT, so refuse
        # until the peer's TPs are in hand.
        if not Bool(self.peer_params):
            return False
        var peer_max = self.peer_params.value().max_datagram_frame_size
        if peer_max == UInt64(0):
            return False
        if UInt64(len(payload)) > peer_max:
            return False
        # Copy the payload so the caller's Span lifetime does not constrain
        # ours — outbound queues survive across `send()` boundaries.
        var copy = List[UInt8]()
        for i in range(len(payload)):
            copy.append(payload[i])
        self.pending_outbound_datagrams.append(copy^)
        return True

    def stop_sending(mut self, stream_id: UInt64, error_code: UInt64) raises:
        """Request the peer to stop sending on a stream."""
        var key = Int(stream_id)
        if key not in self.stream_map.streams:
            raise "unknown stream"
        var stream = self.stream_map.get_stream(key)
        if not stream.recv_state:
            raise "STREAM_STATE_ERROR: no recv side"
        var rs = stream.recv_state.value()
        if (rs == RECV_DATA_READ or rs == RECV_RESET_READ
                or rs == RECV_RESET_RECVD):
            self.stream_map.set_stream(key, stream^)
            return
        stream.recv_state = Optional[UInt8](RECV_STOP_SENDING_SENT)
        stream.needs_stop_sending = True
        stream.stop_sending_error = error_code
        self.stream_map.set_stream(key, stream^)

    # ── Internal helpers ─────────────────────────────────────────────

    def _anti_amp_ok(self, datagram_size: UInt64) -> Bool:
        """Server-side 3x anti-amplification check (RFC 9000 §8.1).
        Only applies to unvalidated servers. ANTI_AMP_HEADER_FUDGE accounts for
        UDP/IP overhead and preserves the original inline check's behavior."""
        if not self.is_server:
            return True
        if self._addr_validated():
            return True
        return self.bytes_sent + datagram_size + ANTI_AMP_HEADER_FUDGE <= 3 * self.bytes_received

    def _can_send(self, size: UInt64, now: UInt64) -> Bool:
        """Composite send gate: anti-amplification + CC window + pacer (non-mutating).
        Token consumption happens via Pacer.refill_and_check at the actual send site.

        The pacer is bypassed for connections that have not yet reached
        is_established(). Anti-amplification and CC cwnd remain the safety
        floors during handshake. RFC 9002 §7 requires "pace OR limit bursts
        to the initial congestion window" — the retained anti-amp + cwnd
        checks satisfy the latter clause for handshake-space sends.
        Reference impls split: picoquic ships this design; quinn / TQUIC /
        ngtcp2 / quiche pace every encryption level.
        """
        if not self._anti_amp_ok(size):
            return False
        if self.recovery.cc.cwnd() < self.recovery.bytes_in_flight + size:
            return False
        if not self.is_established():
            return True
        var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
        if self.recovery.pacer.next_send_time(rate, now):
            return False
        return True

    def ecn_mark(self) -> UInt8:
        """Return the ECN codepoint to apply to outgoing datagrams.

        Returns ECN_ECT0 while probing or confirmed capable; ECN_NOT_ECT when
        the path is known to strip/corrupt ECN marks."""
        if self.ecn_state == ECN_STATE_DISABLED:
            return ECN_NOT_ECT
        return ECN_ECT0

    def _addr_validated(self) -> Bool:
        """True if the peer address has been validated."""
        return (self.state & CONN_ADDR_VALIDATED) != 0



# ── Module-level helpers ─────────────────────────────────────────────


def _generate_random_cid() raises -> List[UInt8]:
    """Generate a random 8-byte connection ID via getrandom(2)."""
    var buf = _heap_alloc[UInt8](8).as_unsafe_any_origin()
    var rc = external_call["getrandom", Int](buf, UInt64(8), UInt32(0))
    if rc != 8:
        buf.free()
        raise "getrandom failed"
    var cid = List[UInt8](capacity=8)
    for i in range(8):
        cid.append(buf[i])
    buf.free()
    return cid^


def _has_ack_eliciting(frames: List[Frame]) -> Bool:
    """Check if any frame in the list is ack-eliciting."""
    for i in range(len(frames)):
        if frames[i].is_ack_eliciting():
            return True
    return False


def _apply_m3c_defaults(mut params: TransportParams):
    """Set flow-control / stream-limit defaults if not already set."""
    if params.initial_max_data == 0:
        params.initial_max_data = UInt64(10485760)  # 10 MiB
    if params.initial_max_stream_data_bidi_local == 0:
        params.initial_max_stream_data_bidi_local = UInt64(1048576)  # 1 MiB
    if params.initial_max_stream_data_bidi_remote == 0:
        params.initial_max_stream_data_bidi_remote = UInt64(1048576)
    if params.initial_max_stream_data_uni == 0:
        params.initial_max_stream_data_uni = UInt64(1048576)
    if params.initial_max_streams_bidi == 0:
        params.initial_max_streams_bidi = UInt64(100)
    if params.initial_max_streams_uni == 0:
        params.initial_max_streams_uni = UInt64(100)
