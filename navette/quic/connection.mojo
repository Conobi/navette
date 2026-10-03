# src/quic/connection.mojo
#
# QuicConnection — sans-I/O QUIC state machine.
#
# Orchestrates packet protection, packet number spaces, loss recovery,
# crypto streams, and the TLS handshake via FFI into librustls_mojo.
#
# Usage:
#   var conn = QuicConnection.client(lib, cfg, "example.com", tp, now)
#   var datagrams = List[List[Byte]](capacity=1)
#   _ = conn.send(now, datagrams)        # Initial with ClientHello
#   conn.recv(response_bytes, now)       # Feed server reply
#   var ev = conn.poll()                 # HANDSHAKE_COMPLETE, etc.

from std.collections import Dict, Optional
from std.ffi import external_call
from std.memory import Pointer, UnsafePointer
from std.collections import Span
from std.utils import Variant
from navette.util.owned_alloc import Owned
from navette.util.secure_random import fill_random
from navette.quic.event import (
    QuicEvent, QuicEventPayload,
    ConnectionClosedPayload, StreamResetPayload, StreamStoppedPayload,
)

from navette.tls.lib import SharedLibrary, RustlsLibrary
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.tls.early_data_store import (
    InMemoryEarlyDataStore, ReplayDecision,
)
from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_encode_at, varint_decode, varint_len
from navette.quic.cid_buf import CidBuf
from navette.quic.error import (
    QuicTransportError, NO_ERROR, PROTOCOL_VIOLATION, APPLICATION_ERROR,
    FINAL_SIZE_ERROR, FLOW_CONTROL_ERROR,
)
from navette.quic.profile import AcceptProfile, CounterId, PROFILE_ACCEPT, monotonic_us, ProfileState, rdtsc, CallId
from navette.quic.zero_rtt import (
    ZeroRttState, ZERO_RTT_BUFFER_MAX_PKTS, ZERO_RTT_BUFFER_MAX_BYTES,
    invoke_replay_authenticator_ffi, drive_replay_check_for_test,
)
from navette.quic.packet_builder import (
    SentStreamFrame,
    PacketPlan,
    SSF_STREAM, SSF_RESET_STREAM, SSF_STOP_SENDING, SSF_MAX_DATA,
    SSF_MAX_STREAM_DATA, SSF_MAX_STREAMS_BIDI, SSF_MAX_STREAMS_UNI,
    SSF_NEW_CID, SSF_RETIRE_CID, SSF_HANDSHAKE_DONE,
    SSF_DATA_BLOCKED, SSF_STREAM_DATA_BLOCKED,
    SSF_STREAMS_BLOCKED_BIDI, SSF_STREAMS_BLOCKED_UNI,
    AEAD_TAG_LEN, MAX_PN_LEN, MIN_PLAINTEXT_LEN, MAX_DATAGRAM_SIZE,
    SCRATCH_PAYLOAD_CAP, SCRATCH_WRITER_CAP,
    ANTI_AMP_HEADER_FUDGE,
    datagram_budget, amp_allowance, header_len,
    build_packet, seal_packet,
    emit_stream_frames, emit_one_stream_frame,
    drain_max_stream_data_frames, drain_reset_stream_frames,
    drain_stop_sending_frames, emit_blocked_frames,
)
from navette.quic.frame import (
    Frame,
    MAX_CLOSE_REASON_BYTES,
    FrameCursor,
    AckFrame,
    AckRange,
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
    serialize_frame,
    write_ack_frame_direct,
    write_crypto_frame_direct,
    write_stream_frame_direct,
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
    FRAME_PATH_CHALLENGE,
    FRAME_PATH_RESPONSE,
    FRAME_DATAGRAM,
    FRAME_DATAGRAM_LEN,
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
    GUARD_TAG_NEW_TOKEN_SERVER,
    GUARD_TAG_HANDSHAKE_DONE_SERVER,
    GUARD_TAG_STREAM_LARGE_OFFSET,
    GUARD_TAG_CRYPTO_IN_ZERO_RTT,
    GUARD_TAG_ACK_IN_ZERO_RTT,
    GUARD_TAG_STREAM_LOCAL_NOT_CREATED,
)
from navette.quic.cid import CidManager, CidEntry, CID_ACTIVE, CID_PENDING_RETIRE, CID_RETIRED, clamp_local_active_limit
from navette.quic.path import PathValidator, PathKey, PathState, MAX_PENDING_CHALLENGES
from navette.quic.stream import (
    Stream, SendBuf, RecvBuf,
    SendState, RecvState,
    send_state_is_terminal, recv_state_is_terminal,
    stream_is_bidi, stream_is_local, stream_is_client_initiated,
)
from navette.quic.flow_control import FlowControl
from navette.quic.packet import (
    PacketType,
    PacketHeader,
    parse_packet_header,
    serialize_long_header,
    serialize_long_header_into,
    serialize_short_header,
    serialize_short_header_into,
    pn_decode,
    pn_truncate,
    pn_encode_length,
    MIN_INITIAL_PACKET_SIZE,
    RETRY_INTEGRITY_TAG_LEN,
)
from navette.quic.retry import compute_retry_integrity_tag
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
from navette.quic.recovery import Recovery, K_GRANULARITY, K_PACKET_THRESHOLD, INITIAL_RTT
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

comptime _WRITE_HS_BUF_SIZE: Int = 4096
comptime _TP_BUF_SIZE: Int = 1024
# A server connection not established this long after it was created is
# dropped silently: a spoofer can keep the idle timer alive by trickling
# Initials, so idle alone does not bound an abandoned handshake.
comptime HANDSHAKE_TIMEOUT_US: UInt64 = 10_000_000
# Close reasons for a server's CID transport parameters that fail RFC 9000
# Section 7.3 on a client.
comptime _REASON_ORIGINAL_DCID = "original_destination_connection_id does not match our first DCID"
comptime _REASON_RETRY_SCID = "retry_source_connection_id does not match the Retry followed"
comptime _REASON_INITIAL_SCID = "initial_source_connection_id does not match the peer's first Initial SCID"
# Close reason for an optimistic ACK (a skipped or never-sent packet number).
comptime _REASON_ACK_UNSENT = "ACK of a packet number never sent"
# Close reasons for stream frames that break RFC 9000 Sections 4 and 19.
comptime _REASON_WRONG_DIRECTION = "frame for the stream side we do not have"
comptime _REASON_STREAM_LIMIT = "peer stream beyond our MAX_STREAMS"
comptime _REASON_FINAL_SIZE = "STREAM data contradicts the final size"
comptime _REASON_CONN_FLOW = "STREAM data beyond the connection flow-control limit"
comptime _REASON_RECV_GAPS = "too many gaps in a stream's receive buffer"



# ── TLS alert -> guard-tag mapping ───────────────────────────────────


def _create_server_tls_conn(
    lib: SharedLibrary,
    config_handle: Int32,
    tp_bytes: List[Byte],
    profile_ptr: Optional[Pointer[AcceptProfile, MutUntrackedOrigin]],
) raises -> Int32:
    """Create a QUIC server TLS connection via FFI, return conn handle."""
    var tp_len = len(tp_bytes)
    var tp_buf_buf = Owned[UInt8](tp_len)
    var tp_buf = tp_buf_buf.ptr()
    for i in range(tp_len):
        tp_buf[unsafe_offset=i] = tp_bytes[i]
    var out_handle_buf = Owned[Int32](1)
    var out_handle = out_handle_buf.ptr()
    out_handle[unsafe_offset=0] = Int32(-1)
    var rlib = lib.inner_ptr()
    var t_tls_start: UInt64 = 0
    comptime if PROFILE_ACCEPT:
        t_tls_start = monotonic_us()
    var rc = rlib[].quic_server_conn_new(
        config_handle, Int32(1), tp_buf, Int32(tp_len), out_handle,
    )
    comptime if PROFILE_ACCEPT:
        if profile_ptr is not None:
            profile_ptr.value()[].record_alloc_tls_handle_us(monotonic_us() - t_tls_start)
    if rc < 0:
        var err = rlib[].last_error()
        raise "quic_server_conn_new failed: " + err
    var conn_handle = out_handle[unsafe_offset=0]
    _ = out_handle_buf
    if conn_handle < 0:
        raise "quic_server_conn_new returned invalid handle"
    return conn_handle


def _create_client_tls_conn(
    lib: SharedLibrary,
    config_handle: Int32,
    server_name: String,
    tp_bytes: List[Byte],
) raises -> Int32:
    """Create a QUIC client TLS connection via FFI, return conn handle."""
    var sni_bytes = server_name.as_bytes()
    var sni_len = len(sni_bytes)
    var sni_buf_buf = Owned[UInt8](sni_len)
    var sni_buf = sni_buf_buf.ptr()
    for i in range(sni_len):
        sni_buf[unsafe_offset=i] = sni_bytes[i]
    var tp_len = len(tp_bytes)
    var tp_buf_buf = Owned[UInt8](tp_len)
    var tp_buf = tp_buf_buf.ptr()
    for i in range(tp_len):
        tp_buf[unsafe_offset=i] = tp_bytes[i]
    var out_handle_buf = Owned[Int32](1)
    var out_handle = out_handle_buf.ptr()
    out_handle[unsafe_offset=0] = Int32(-1)
    var rlib = lib.inner_ptr()
    var rc = rlib[].quic_client_conn_new(
        config_handle, Int32(1), sni_buf, Int32(sni_len),
        tp_buf, Int32(tp_len), out_handle,
    )
    if rc < 0:
        var err = rlib[].last_error()
        raise "quic_client_conn_new failed: " + err
    var conn_handle = out_handle[unsafe_offset=0]
    _ = out_handle_buf
    if conn_handle < 0:
        raise "quic_client_conn_new returned invalid handle"
    return conn_handle


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


@always_inline
def _is_ack_eliciting_tid(tid: UInt64) -> Bool:
    """ACK-eliciting: everything except PADDING, ACK/ACK_ECN, CONNECTION_CLOSE."""
    if tid == FRAME_PADDING:
        return False
    if tid == FRAME_ACK or tid == FRAME_ACK_ECN:
        return False
    if tid == FRAME_CONNECTION_CLOSE_TRANSPORT or tid == FRAME_CONNECTION_CLOSE_APP:
        return False
    return True


@always_inline
def _is_probing_tid(tid: UInt64) -> Bool:
    """Probing frames (RFC 9000 Section 9.1): a packet of only these never moves the peer's address."""
    return (
        tid == FRAME_PADDING
        or tid == FRAME_NEW_CONNECTION_ID
        or tid == FRAME_PATH_CHALLENGE
        or tid == FRAME_PATH_RESPONSE
    )


# ── SentStreamFrame ──────────────────────────────────────────────────
#
# Per-packet record of stream/flow-control/CID frames sent in the Application
# space, used for ACK and loss processing.  STREAM/CRYPTO retransmission
# for Initial/Handshake is still handled via SentPacket.frames.




# ── CloseState ──────────────────────────────────────────────────────


@fieldwise_init
struct CloseState(Movable):
    """Connection close/drain lifecycle state."""

    var pending: Optional[ConnectionCloseFrame]
    var owed: Bool
    var last_sent: UInt64
    var timer: UInt64
    var drain_timer: UInt64


# ── EcnProbe ────────────────────────────────────────────────────────


@fieldwise_init
struct EcnProbe(Copyable, Movable):
    """ECN path validation probing state (RFC 9000, Section 13.4.2)."""

    var state: UInt8
    var pkts_needed: Int
    var pkts_sent: Int
    var first_pn: UInt64


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
    var local_cid: CidBuf
    var peer_cid: CidBuf
    # The SCID of the first Initial that authenticated; None until then.
    var _initial_peer_scid: Optional[CidBuf]
    # Whether any packet of the last datagram given to `recv` decrypted:
    # path bookkeeping must act only on authenticated datagrams.
    var last_datagram_authenticated: Bool
    # Whether the last datagram given to `recv` carried a new 1-RTT packet
    # with a non-probing frame and the space's highest packet number yet:
    # the only packet allowed to move the peer's address (RFC 9000
    # Section 9.3). Implies `last_datagram_authenticated`.
    var last_datagram_may_migrate: Bool
    # Set by `_parse_and_dispatch_frames`: the packet held a non-probing frame.
    var _pkt_non_probing: Bool
    # The client's original DCID on a client (it keys the Retry integrity
    # tag and must come back as original_destination_connection_id), the
    # DCID the Initial keys derive from on a server.
    var initial_dcid: CidBuf
    # Client only: the token and SCID of the one Retry followed (RFC 9000
    # Section 17.2.5.2). The token rides on every later Initial; the SCID
    # must come back as retry_source_connection_id.
    var _retry_token: List[Byte]
    var _retry_scid: Optional[CidBuf]
    var bytes_received: UInt64
    var bytes_sent: UInt64
    var events: List[QuicEvent]
    # `poll()` pops from `events[_events_head]`; both reset once drained.
    var _events_head: Int
    var close: CloseState
    var idle_timer: UInt64
    var created_us: UInt64
    var handshake_confirmed: Bool
    var current_level: Int
    var send_handshake_done: Bool
    var stream_map: StreamMap
    var cid_mgr: CidManager
    # RFC 9000 Sec. 8/9 path validation + address tracking state, grouped
    # into PathState: validator, pending_responses, peer_addr,
    # current_recv_addr.
    var path: PathState
    # RFC 9221 §5 — outbound DATAGRAM frame queue. Each entry is one
    # complete payload (no header bytes). Drained in the 1-RTT branch of
    # `_build_frames_for_space` into DATAGRAM_LEN (0x31) frames so each
    # entry composes cleanly with ACK/STREAM/etc. Per RFC §5.4 entries are
    # NOT retransmitted on loss — once a packet carrying a DATAGRAM is
    # declared lost, the payload is gone (callers MUST handle reliability
    # themselves if they need it). Drained from `_outbound_dg_head`; the
    # list is reset once every entry has been emitted.
    var pending_outbound_datagrams: List[List[Byte]]
    var _outbound_dg_head: Int
    # One-shot guard for the initial NEW_CONNECTION_ID burst (RFC 9000
    # §5.1.1): on the first 1-RTT _build_frames_for_space call after the
    # connection becomes CONN_ESTABLISHED, fill `cid_mgr.local_cids` up
    # to `cid_mgr.issue_limit()`. Subsequent flushes drain
    # `pending_new_cid_entries` normally without re-issuing.
    var initial_cids_emitted: Bool
    # Maps Application-space packet number -> list of stream-layer frames
    # sent in that packet, for ACK/loss processing.
    var app_frames_sent: Dict[Int, List[SentStreamFrame]]
    var pkt_buf: List[Byte]
    var ecn: EcnProbe

    var prof: ProfileState

    var zrtt: ZeroRttState

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
    # DCID of the packet being dispatched, so RETIRE_CONNECTION_ID can
    # refuse to retire the CID it arrived on (RFC 9000 Section 19.16).
    var _current_dcid: CidBuf

    # Pre-allocated scratch buffers reused across send()/loss calls to
    # avoid per-call heap allocations; .clear()'d before use.
    var _scratch_lost_pns: List[Int]
    var _scratch_frames: List[Frame]
    var _scratch_sent_records: List[SentStreamFrame]
    var _scratch_payload: List[Byte]
    var _scratch_datagram: List[Byte]
    var _scratch_plans: List[PacketPlan]
    var _scratch_writer_buf: List[Byte]

    # ── Private constructor (used by factory methods) ────────────────

    def __init__(
        out self,
        is_server: Bool,
        lib: SharedLibrary,
        conn_handle: Int32,
        local_params: TransportParams,
        local_cid: CidBuf,
        peer_cid: CidBuf,
        initial_dcid: CidBuf,
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
        self._lib = SharedLibrary(copy=lib)
        self.local_params = TransportParams(copy=local_params)
        self.peer_params = None
        self.local_cid = CidBuf(copy=local_cid)
        self.peer_cid = CidBuf(copy=peer_cid)
        self._initial_peer_scid = None
        self.last_datagram_authenticated = False
        self.last_datagram_may_migrate = False
        self._pkt_non_probing = False
        self.initial_dcid = CidBuf(copy=initial_dcid)
        self._retry_token = List[Byte]()
        self._retry_scid = None
        self.bytes_received = UInt64(0)
        self.bytes_sent = UInt64(0)
        self.events = List[QuicEvent]()
        self._events_head = 0
        self.close = CloseState(
            pending=None,
            owed=False,
            last_sent=UInt64(0),
            timer=UInt64(0),
            drain_timer=UInt64(0),
        )
        self.idle_timer = now
        self.created_us = now
        self.handshake_confirmed = False
        self.current_level = 0
        self.send_handshake_done = False
        self.ecn = EcnProbe(
            state=ECN_STATE_PROBING,
            pkts_needed=10,
            pkts_sent=0,
            first_pn=UInt64(0),
        )
        self.prof = ProfileState(
            ptr=None,
            first_initial_us=UInt64(0),
            rustls_us_accum=UInt64(0),
            first_iter_done=False,
            fresh_conn_ffi_us_total=UInt64(0),
            read_hs_call_count=UInt64(0),
            read_hs_input_marshalling_us_total=UInt64(0),
            read_hs_state_machine_us_total=UInt64(0),
            read_hs_output_alloc_us_total=UInt64(0),
            read_hs_output_marshalling_us_total=UInt64(0),
            accept_us=UInt64(0),
            hs_cpu_us_total=UInt64(0),
            hs_wait_us_total=UInt64(0),
        )
        self.zrtt = ZeroRttState(
            enabled=False,
            buffer=List[List[Byte]](),
            buffer_bytes=0,
            draining=False,
            replay_decision=UInt8(0),
            now_ms_override=None,
            early_data_store_ptr=None,
        )
        # Transient packet-dispatch space index; -1 outside the
        # frame-dispatch loop. Bookended by set/reset in the loop body
        # so 0-RTT-origin tagging fires only for streams created from
        # actual 0-RTT-decrypted packets (RFC 9001 §4.6).
        self._current_space_idx = -1
        self._current_dcid = CidBuf.empty()
        self._scratch_lost_pns = List[Int](capacity=64)
        self._scratch_frames = List[Frame](capacity=8)
        self._scratch_sent_records = List[SentStreamFrame](capacity=8)
        self._scratch_payload = List[Byte](capacity=SCRATCH_PAYLOAD_CAP)
        self._scratch_datagram = List[Byte](capacity=MAX_DATAGRAM_SIZE)
        self._scratch_plans = List[PacketPlan](capacity=3)
        self._scratch_writer_buf = List[Byte](capacity=SCRATCH_WRITER_CAP)
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
            initial_local_cid=List[Byte](local_cid.as_span()),
            initial_remote_cid=List[Byte](peer_cid.as_span()),
            local_active_limit=local_params.active_connection_id_limit,
            peer_active_limit=UInt64(2),
        )
        self.path = PathState()
        self.pending_outbound_datagrams = List[List[Byte]]()
        self._outbound_dg_head = 0
        self.initial_cids_emitted = False
        self.app_frames_sent = Dict[Int, List[SentStreamFrame]](capacity=128)
        self.pkt_buf = List[Byte](capacity=1350)

    # ── Destructor ───────────────────────────────────────────────────

    def __deinit__(deinit self):
        """Free the rustls QUIC connection handle.

        A destructor may not raise. `quic_conn_free` can, but only from
        the symbol lookup — an unknown handle returns -1 on the Rust
        side and that status is already discarded. A lookup failure
        means the loaded librustls_mojo.so does not export
        `rlsm_quic_conn_free`, so the connection cannot be reached;
        swallowing it leaks one QUIC_CONN_TABLE entry (and the TLS
        session it holds) instead of aborting the process while a
        connection closes. `deinit self` consumes the connection, so
        this runs once per handle and cannot double free.

        Key material is not touched here: `PacketProtect`'s own
        destructor frees the keys handles.
        """
        if self.conn_handle >= 0:
            try:
                _ = self._lib.inner_ptr()[].quic_conn_free(self.conn_handle)
            except:
                pass
        # Anchor: `inner_ptr()` returns an untracked pointer, so the checker
        # cannot see that the call above depends on `_lib`. Without a later
        # reference, ASAP destruction frees `_lib` at that line -- closing the
        # dylib -- and the FFI call runs through a null handle.
        _ = self._lib.inner_ptr()

    # ── Static factory methods ───────────────────────────────────────

    @staticmethod
    def client(
        lib: SharedLibrary,
        ref config: QuicClientConfig,
        server_name: String,
        local_params: TransportParams,
        now: UInt64,
    ) raises -> QuicConnection:
        """Create a QUIC client connection."""
        var config_handle = config.handle()
        var dcid = _generate_random_cid()
        var local_cid = _generate_random_cid()
        var tp_writer = ByteWriter()
        var params_copy = TransportParams(copy=local_params)
        params_copy.initial_scid = List[Byte](copy=local_cid)
        _apply_m3c_defaults(params_copy)
        serialize_transport_params(params_copy, tp_writer)
        var tp_bytes = tp_writer.finish()
        var conn_handle = _create_client_tls_conn(
            lib, config_handle, server_name, tp_bytes,
        )
        var conn = QuicConnection(
            is_server=False, lib=lib, conn_handle=conn_handle,
            local_params=params_copy, local_cid=CidBuf.from_span(Span(local_cid)),
            peer_cid=CidBuf.from_span(Span(dcid)),
            initial_dcid=CidBuf.from_span(Span(dcid)), now=now,
        )
        conn.protect.derive_initial_keys(Span(dcid), is_client=True)
        conn._drive_handshake(now)
        return conn^

    @staticmethod
    def server(
        lib: SharedLibrary,
        ref config: QuicServerConfig,
        local_params: TransportParams,
        orig_dcid: Span[Byte, _],
        client_dcid: Span[Byte, _],
        now: UInt64,
        profile_ptr: Optional[Pointer[AcceptProfile, MutUntrackedOrigin]] = None,
        retry_scid: List[Byte] = List[Byte](),
        stream_window: UInt64 = UInt64.MAX,
    ) raises -> QuicConnection:
        """Create a QUIC server connection.

        A `stream_window` below `initial_max_streams_bidi` (CAP) is advertised instead (at least 1) and the
        connection declines 0-RTT, as RFC 9000 Section 7.4.1 requires when lowering remembered limits; CAP stays
        the re-grant ceiling, so the window can be raised back later.

        After a Retry, `orig_dcid` is the DCID of the client's first
        Initial (recovered from the token), `client_dcid` the DCID of the
        Initial that carried the token, and `retry_scid` the SCID our
        Retry used (normally equal to `client_dcid`); the client rejects
        the handshake unless both come back as transport parameters (RFC
        9000 Section 7.3). Leave `retry_scid` empty when no Retry was sent.
        """
        # RFC 9000 caps CIDs at 20 bytes. `CidBuf.from_span` aborts the
        # whole process on an over-length span, so an unvalidated caller
        # (or a wire-derived DCID that skipped `extract_dcid`'s clamp)
        # must be rejected here via `raise` instead of reaching that
        # abort — a remote DoS otherwise.
        if len(orig_dcid) > 20:
            raise "QuicConnection.server: orig_dcid exceeds 20 bytes"
        if len(client_dcid) > 20:
            raise "QuicConnection.server: client_dcid exceeds 20 bytes"
        if len(retry_scid) > 20:
            raise "QuicConnection.server: retry_scid exceeds 20 bytes"
        var config_handle = config.handle()
        var profile_arrival_us = monotonic_us()
        var local_cid = _generate_random_cid()
        var tp_writer = ByteWriter()
        var params_copy = TransportParams(copy=local_params)
        params_copy.initial_scid = List[Byte](copy=local_cid)
        _apply_m3c_defaults(params_copy)
        var cap = params_copy.initial_max_streams_bidi
        var narrow = stream_window < cap
        params_copy.initial_max_streams_bidi = max(UInt64(1), min(cap, stream_window))
        var orig_dcid_list = List[Byte](capacity=len(orig_dcid))
        for ref byte in orig_dcid:
            orig_dcid_list.append(byte)
        params_copy.original_dcid = orig_dcid_list^
        if len(retry_scid) > 0:
            params_copy.retry_scid = retry_scid.copy()
        serialize_transport_params(params_copy, tp_writer)
        var tp_bytes = tp_writer.finish()
        var conn_handle = _create_server_tls_conn(
            lib, config_handle, tp_bytes, profile_ptr,
        )
        var conn = QuicConnection(
            is_server=True, lib=lib, conn_handle=conn_handle,
            local_params=params_copy, local_cid=CidBuf.from_span(Span(local_cid)),
            peer_cid=CidBuf.from_span(orig_dcid),
            initial_dcid=CidBuf.from_span(client_dcid), now=now,
        )
        conn.prof.ptr = profile_ptr
        conn.prof.first_initial_us = profile_arrival_us
        conn.prof.accept_us = profile_arrival_us
        conn.stream_map.initial_max_streams_bidi = cap
        if narrow and lib.inner_ptr()[].quic_server_conn_reject_early_data(conn.conn_handle) != 0:
            raise "QuicConnection.server: could not decline 0-RTT"
        conn.zrtt.enabled = (config.max_early_data() != UInt32(0)) and not narrow
        var store_opt = config.early_data_store()
        if store_opt is not None:
            var store_ptr = store_opt.value().unsafe_origin_cast[MutUntrackedOrigin]()
            conn.zrtt.early_data_store_ptr = Optional[
                Pointer[InMemoryEarlyDataStore, MutUntrackedOrigin]
            ](store_ptr)
        conn.prof.record_handshake_arrival()
        conn.protect.derive_initial_keys(client_dcid, is_client=False)
        return conn^

    # ── Receive path ─────────────────────────────────────────────────

    def recv(mut self, datagram: Span[Byte, _], now: UInt64,
             ecn_mark: UInt8 = UInt8(0)) raises:
        """Process an incoming UDP datagram (Span convenience wrapper)."""
        var n = len(datagram)
        if n == 0:
            return
        var buf_owned = Owned[UInt8](n)
        var buf = buf_owned.ptr()
        for i in range(n):
            buf[unsafe_offset=i] = datagram[i]
        self.recv_from_buffer(buf, n, now, ecn_mark)

    def recv_from_buffer(
        mut self,
        buf: Pointer[mut=True, T=UInt8, origin=_],
        buf_len: Int,
        now: UInt64,
        ecn_mark: UInt8 = UInt8(0),
    ) raises:
        """Process an incoming UDP datagram from a mutable buffer."""
        var _ct_start = UInt64(0)
        comptime if PROFILE_ACCEPT:
            _ct_start = rdtsc()
        var t_iter = UInt64(0)
        var ph_hdr = UInt64(0)
        var ph_hp = UInt64(0)
        var ph_ae = UInt64(0)
        var ph_fp = UInt64(0)
        var ph_sm = UInt64(0)
        self.bytes_received += UInt64(buf_len)
        self.last_datagram_authenticated = False
        self.last_datagram_may_migrate = False
        if (self.state & (CONN_DRAINING | CONN_CLOSED)) != 0:
            comptime if PROFILE_ACCEPT:
                if self.prof.ptr is not None:
                    self.prof.ptr.value()[].call_tracker.record(CallId.RECV_FROM_BUFFER, rdtsc() - _ct_start)
            return
        var closing = (self.state & CONN_CLOSING) != 0
        if closing:
            if now >= self.close.last_sent + self._pto_interval():
                self.close.owed = True
        else:
            self.idle_timer = now
        var lowest_recv_space = 3
        var offset = 0
        # RFC 9000 Section 12.2: every packet of a datagram carries the
        # first packet's DCID; one that does not belongs to another
        # connection (or an injector) and ends the datagram.
        var first_dcid = CidBuf.empty()
        var have_first_dcid = False
        while offset < buf_len:
            if (self.state & (CONN_DRAINING | CONN_CLOSED)) != 0:
                break
            t_iter = self.prof.begin_iter()
            if buf[unsafe_offset=offset] == 0:
                break
            var remaining_len = buf_len - offset
            var remaining_ptr = buf.unsafe_offset(offset)
            ph_hdr = self.prof.stamp()
            var hr = parse_packet_header(
                Span(unsafe_ptr=remaining_ptr, length=remaining_len),
                len(self.local_cid),
            )
            var header = PacketHeader()
            swap(header, hr[0])
            ph_hdr = self.prof.elapsed(ph_hdr)
            if have_first_dcid:
                if header.dcid != first_dcid:
                    break
            else:
                first_dcid = CidBuf(copy=header.dcid)
                have_first_dcid = True
            if header.is_long_header and header.packet_type == PacketType.retry():
                # A Retry fills the rest of the datagram; a server never gets one.
                if not self.is_server:
                    self._on_retry(header, Span(unsafe_ptr=remaining_ptr, length=remaining_len))
                break
            var classify = self._classify_recv_packet(
                header, remaining_ptr, remaining_len,
            )
            if classify[0] == 2:
                break
            if classify[0] == 1:
                offset += classify[3]
                continue
            var space_idx = classify[1]
            var key_slot = classify[2]
            var pkt_len = classify[3]
            if self._is_long_from_other_scid(header) or self._is_small_datagram_initial(header, buf_len):
                offset += pkt_len
                continue
            var decrypt_ok = True
            try:
                var result = self._decrypt_and_dispatch_packet(
                    header, remaining_ptr, pkt_len, space_idx,
                    key_slot, closing, now, ecn_mark,
                )
                ph_hp = result[1]
                ph_ae = result[2]
                ph_fp = result[3]
                if result[0] < 0:
                    # Already processed (RFC 9000 Section 12.3): dropped
                    # unread, so it neither authenticates the datagram
                    # nor owes an ACK.
                    offset += pkt_len
                    continue
                if not closing and result[0] < lowest_recv_space:
                    lowest_recv_space = result[0]
            except:
                if (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
                    comptime if PROFILE_ACCEPT:
                        if self.prof.ptr is not None:
                            self.prof.ptr.value()[].call_tracker.record(CallId.RECV_FROM_BUFFER, rdtsc() - _ct_start)
                    return
                decrypt_ok = False
            if not decrypt_ok:
                break
            self.last_datagram_authenticated = True
            if (
                not self._initial_peer_scid
                and header.is_long_header
                and header.packet_type == PacketType.initial()
            ):
                self._adopt_initial_peer_scid(header.scid)
            if not closing:
                ph_sm = self.prof.stamp()
                self._drive_handshake(now)
                self._drain_zero_rtt_buffer(now, ecn_mark)
                ph_sm = self.prof.elapsed(ph_sm)
            self.prof.end_iter(t_iter, ph_hp, ph_ae, ph_hdr, ph_fp, ph_sm)
            offset += pkt_len
        self._retransmit_crypto_if_needed(lowest_recv_space, closing)
        comptime if PROFILE_ACCEPT:
            if self.prof.ptr is not None:
                self.prof.ptr.value()[].call_tracker.record(CallId.RECV_FROM_BUFFER, rdtsc() - _ct_start)

    def _on_retry(mut self, ref header: PacketHeader, packet: Span[Byte, _]) raises:
        """Restart the handshake towards the Retry's SCID, carrying its token (RFC 9000 Section 17.2.5.2).

        Ignored unless it is the first Retry, no server Initial has
        authenticated yet, it is addressed to our SCID, it carries a token,
        its SCID differs from our original DCID, and its integrity tag
        verifies under that DCID (RFC 9001 Section 5.8): anything else is
        stale, duplicated or forged. A Retry whose CRYPTO data cannot be
        rewound, or whose keys cannot be derived, is ignored with no state
        changed. Packets already sent in the Initial
        space are forgotten, not declared lost (the server discarded them
        unread), and their CRYPTO data is queued again from offset 0 under
        Initial keys derived from the new DCID. Packet numbers keep
        increasing (RFC 9000 Section 17.2.5.3).
        """
        if Bool(self._retry_scid) or Bool(self._initial_peer_scid):
            return
        if header.version != UInt32(1) or header.token_len == 0:
            return
        if header.dcid != self.local_cid or header.scid == self.initial_dcid:
            return
        var tag = List[Byte](capacity=RETRY_INTEGRITY_TAG_LEN)
        compute_retry_integrity_tag(
            tag, self._lib, self.initial_dcid.as_span(), packet[: len(packet) - RETRY_INTEGRITY_TAG_LEN]
        )
        var diff = UInt8(0)
        ref want = header.retry_integrity_tag
        for i in range(RETRY_INTEGRITY_TAG_LEN):
            diff |= tag[i] ^ want[i]
        if diff != 0:
            return
        # Everything that can fail runs before anything is changed: the
        # CRYPTO rewind goes into a copy and the new Initial keys are
        # derived first, so a Retry that cannot be followed is ignored
        # whole instead of leaving the handshake half-restarted.
        var pns = List[Int](capacity=len(self.spaces[0].sent_packets))
        for pn in self.spaces[0].sent_packets.keys():
            pns.append(pn)
        sort(pns)
        var crypto = List[CryptoFrame]()
        for pn in pns:
            var pkt = self.spaces[0].sent_packets.find(pn)
            if not pkt:
                continue
            for ref frame in pkt.value().frames:
                if frame.is_crypto():
                    crypto.append(frame.as_crypto().copy())
        var rewound = self.crypto_streams[0].copy()
        try:
            rewound.rewind(crypto)
            self.protect.derive_initial_keys(header.scid.as_span(), is_client=True)
        except:
            return
        self._retry_token = List[Byte](header.token_span())
        self._retry_scid = Optional[CidBuf](CidBuf(copy=header.scid))
        self.peer_cid = CidBuf(copy=header.scid)
        for ref e in self.cid_mgr.remote_cids:
            if e.sequence == UInt64(0):
                e.cid = List[Byte](header.scid.as_span())
                break
        for ref pkt in self.spaces[0].reset_for_retry():
            self.recovery.on_packet_lost(pkt.size, pkt.in_flight)
        self.crypto_streams[0] = rewound^

    @always_inline
    def _is_small_datagram_initial(self, ref header: PacketHeader, datagram_len: Int) -> Bool:
        """On a server, an Initial in a datagram under 1,200 bytes: skipped, coalesced or not (RFC 9000 Section 14.1)."""
        return (
            self.is_server
            and datagram_len < MIN_INITIAL_PACKET_SIZE
            and header.is_long_header
            and header.packet_type == PacketType.initial()
        )

    @always_inline
    def _is_long_from_other_scid(self, ref header: PacketHeader) -> Bool:
        """True for an Initial or Handshake packet whose SCID differs from
        the one we adopted (a zero-length one included); such packets are
        discarded unprocessed (RFC 9000 Section 7.2)."""
        if not self._initial_peer_scid:
            return False
        if not header.is_long_header or (
            header.packet_type != PacketType.initial() and header.packet_type != PacketType.handshake()
        ):
            return False
        return header.scid != self._initial_peer_scid.value()

    def _adopt_initial_peer_scid(mut self, scid: CidBuf):
        """Address the peer by the SCID of its first authenticated Initial.

        Called only after the packet decrypted, so random corruption or an
        off-path sender cannot redirect our packets; an on-path attacker
        can still forge one, since Initial keys derive from the DCID in
        clear. The sequence-0 remote CID is overwritten too: it was seeded
        with a placeholder (our Initial DCID on the client, the client's
        original DCID on the server), and must hold the CID the peer
        actually chose so a later `_sync_peer_cid` back to it, or its
        retirement, names the right CID.
        """
        self._initial_peer_scid = Optional[CidBuf](CidBuf(copy=scid))
        self.peer_cid = CidBuf(copy=scid)
        for ref e in self.cid_mgr.remote_cids:
            if e.sequence == UInt64(0):
                e.cid = List[Byte](scid.as_span())
                break

    def _classify_recv_packet(
        mut self,
        ref header: PacketHeader,
        remaining_ptr: Pointer[mut=True, T=UInt8, origin=_],
        remaining_len: Int,
    ) raises -> Tuple[Int, Int, Int, Int]:
        """Classify a packet: 0-RTT detection, space mapping, key check.

        Returns (action, space_idx, key_slot, pkt_len).
        action: 0=proceed, 1=skip pkt_len bytes, 2=break.
        """
        var space_idx: Int = -1
        if header.is_long_header and header.packet_type == PacketType.zero_rtt():
            var r = self._handle_zero_rtt_detection(
                header, remaining_ptr, remaining_len,
            )
            if r[1] > 0:
                return (1, -1, -1, r[1])
            if r[0] < 0:
                return (2, -1, -1, 0)
            space_idx = r[0]
        else:
            space_idx = packet_type_to_space(header.packet_type)
        if space_idx < 0:
            return (2, -1, -1, 0)
        var key_slot = ZERO_RTT_KEY_SLOT_IDX if space_idx == ZERO_RTT_SPACE_IDX else space_idx
        if not self.protect.has_keys(key_slot):
            if header.is_long_header:
                var skip = header.pn_offset + Int(header.payload_length)
                if skip > remaining_len:
                    return (2, -1, -1, 0)
                return (1, -1, -1, skip)
            return (2, -1, -1, 0)
        var pkt_len = header.pn_offset + Int(header.payload_length) if header.is_long_header else remaining_len
        if pkt_len > remaining_len:
            return (2, -1, -1, 0)
        return (0, space_idx, key_slot, pkt_len)

    def _run_anti_replay_check(mut self) raises:
        """Execute the one-shot anti-replay check against the early data store."""
        var auth_buf = InlineArray[UInt8, 32](fill=Byte(0))
        var auth_len = UInt(0)
        var rc = self._invoke_replay_authenticator_ffi(auth_buf, auth_len)
        if rc != Int32(0):
            self.zrtt.replay_decision = UInt8(2)
            self.prof.record_counter(CounterId.ZERO_RTT_REPLAY_REJECT_NO_AUTHENTICATOR)
            return
        if self.zrtt.early_data_store_ptr is None:
            self.zrtt.replay_decision = UInt8(2)
            self.prof.record_counter(CounterId.ZERO_RTT_REPLAY_REJECT_NO_AUTHENTICATOR)
            return
        var auth_span = Span(unsafe_ptr=auth_buf.unsafe_ptr(), length=32)
        var now_ms: UInt64
        if self.zrtt.now_ms_override is not None:
            now_ms = self.zrtt.now_ms_override.value()
        else:
            now_ms = monotonic_us() // UInt64(1_000)
        var raised = False
        var decision = ReplayDecision.accept()
        try:
            var store_ptr = self.zrtt.early_data_store_ptr.value()
            decision = store_ptr[].check_and_record(auth_span, now_ms)
        except:
            raised = True
        if raised:
            self.zrtt.replay_decision = UInt8(2)
            self.prof.record_counter(CounterId.ZERO_RTT_REPLAY_REJECT_NO_AUTHENTICATOR)
        elif decision.is_accept():
            self.zrtt.replay_decision = UInt8(1)
            self.prof.record_counter(CounterId.ZERO_RTT_REPLAY_ACCEPT)
        elif decision.is_duplicate():
            self.zrtt.replay_decision = UInt8(2)
            self.prof.record_counter(CounterId.ZERO_RTT_REPLAY_REJECT_DUPLICATE)
        elif decision.is_per_key_quota():
            self.zrtt.replay_decision = UInt8(2)
            self.prof.record_counter(CounterId.ZERO_RTT_REPLAY_REJECT_PER_KEY_QUOTA)
        else:
            self.zrtt.replay_decision = UInt8(2)
            self.prof.record_counter(CounterId.ZERO_RTT_REPLAY_REJECT_GLOBAL_CEILING)

    @always_inline
    def _parse_and_dispatch_frames(
        mut self,
        pkt_ptr: Pointer[mut=True, T=UInt8, origin=_],
        header_len: Int,
        plaintext_len: Int,
        space_idx: Int,
        closing: Bool,
        now: UInt64,
    ) raises -> Bool:
        """Parse frames via FrameCursor and dispatch each. Returns ack_eliciting; sets `_pkt_non_probing`."""
        var cursor = FrameCursor(
            Span(unsafe_ptr=pkt_ptr.unsafe_offset(header_len), length=plaintext_len)
        )
        var parse_failed = False
        var ack_eliciting = False
        self._pkt_non_probing = False
        self._current_space_idx = space_idx
        while True:
            var maybe_tid = Optional[UInt64]()
            try:
                maybe_tid = cursor.next()
            except:
                parse_failed = True
                break
            if not maybe_tid:
                break
            var tid = maybe_tid.value()
            if closing and tid != FRAME_CONNECTION_CLOSE_TRANSPORT and tid != FRAME_CONNECTION_CLOSE_APP:
                continue
            if _is_ack_eliciting_tid(tid):
                ack_eliciting = True
            if not _is_probing_tid(tid):
                self._pkt_non_probing = True
            self._dispatch_frame(cursor, space_idx, now)
        self._current_space_idx = -1
        if parse_failed:
            self.close_transport(UInt64(0x07), String(GUARD_TAG_UNKNOWN_FRAME), now)
            raise Error("frame parse")
        var _f11_verdict = predicate_f11_no_frames(cursor.count())
        if _f11_verdict:
            var _v11 = _f11_verdict.take()
            self.close_transport(_v11.error_code, _v11.tag, now)
            raise Error("no frames")
        return ack_eliciting

    def _handle_zero_rtt_detection(
        mut self,
        ref header: PacketHeader,
        remaining_ptr: Pointer[mut=True, T=UInt8, origin=_],
        remaining_len: Int,
    ) raises -> Tuple[Int, Int]:
        """Detect and handle a 0-RTT packet: key install, anti-replay.

        Returns (space_idx, skip). space_idx=ZERO_RTT_SPACE_IDX on
        success; space_idx=-1 with skip>0 means advance offset; skip=0
        with space_idx=-1 means break (truncated).
        """
        var skip = header.pn_offset + Int(header.payload_length)
        if skip > remaining_len:
            return (-1, 0)

        if self.protect.has_keys(ZERO_RTT_KEY_SLOT_IDX):
            pass  # Path A — keys installed, fall through.
        elif self._zero_rtt_enabled():
            # Path B — lazy install. Buffer-or-drop on fail.
            var ok = False
            try:
                ok = self.protect.install_zero_rtt_read_keys(
                    self.conn_handle
                )
            except:
                pass
            self.prof.record_zero_rtt_install(ok)
            if not ok:
                if not self.zrtt.draining:
                    var pkt_bytes = Span(
                        unsafe_ptr=remaining_ptr, length=skip,
                    )
                    _ = self._buffer_zero_rtt_or_drop(pkt_bytes)
                return (-1, skip)
        else:
            # Path C — 0-RTT disabled.
            return (-1, skip)

        if self.zrtt.replay_decision == UInt8(0):
            self._run_anti_replay_check()

        if self.zrtt.replay_decision == UInt8(2):
            return (-1, skip)
        return (ZERO_RTT_SPACE_IDX, 0)

    @always_inline
    def _decrypt_and_dispatch_packet(
        mut self,
        ref header: PacketHeader,
        pkt_ptr: Pointer[mut=True, T=UInt8, origin=_],
        pkt_len: Int,
        space_idx: Int,
        key_slot: Int,
        closing: Bool,
        now: UInt64,
        ecn_mark: UInt8,
    ) raises -> Tuple[Int, UInt64, UInt64, UInt64]:
        """Decrypt, parse frames, dispatch, update PN/ECN state.

        Returns (pn_space_idx, hp_us, aead_us, frame_parse_us), with
        pn_space_idx = -1 for a packet number already processed (RFC 9000
        Section 12.3), which is dropped before the AEAD runs. Raises on
        decrypt failure or after close_transport. Sets
        `last_datagram_may_migrate` for a new 1-RTT packet carrying a
        non-probing frame whose number is the space's highest yet.
        """
        var ph_hp_us = self.prof.stamp()
        var hp_result = self.protect.unprotect_header_ptr(
            key_slot, pkt_ptr, pkt_len, header.pn_offset
        )
        ph_hp_us = self.prof.elapsed(ph_hp_us)
        var first_byte = hp_result[0]
        var pn_length = hp_result[1]

        var pn_space_idx = 2 if space_idx == ZERO_RTT_SPACE_IDX else space_idx
        var truncated_pn = UInt64(0)
        for i in range(pn_length):
            truncated_pn = (truncated_pn << 8) | UInt64(
                pkt_ptr[unsafe_offset=header.pn_offset + i]
            )
        var largest = UInt64(0)
        if self.spaces[pn_space_idx].largest_recv_pn >= 0:
            largest = UInt64(self.spaces[pn_space_idx].largest_recv_pn)
        var full_pn = pn_decode(truncated_pn, pn_length, largest)
        if self.spaces[pn_space_idx].was_received(full_pn):
            return (-1, ph_hp_us, UInt64(0), UInt64(0))
        var newest = Int(full_pn) > self.spaces[pn_space_idx].largest_recv_pn

        var header_len = header.pn_offset + pn_length
        var ph_aead_us = self.prof.stamp()
        var plaintext_len = self.protect.decrypt_payload_in_place(
            key_slot, full_pn, header_len, pkt_ptr, pkt_len
        )
        ph_aead_us = self.prof.elapsed(ph_aead_us)

        # RFC 9000 Section 17.2 / 17.3.1: reserved bits count only once both
        # protections are removed. Before the AEAD verifies, a forged
        # packet's unmasked bits are random, and closing on them let anyone
        # knowing the DCID kill the connection.
        if header.is_long_header:
            var _f12_verdict = check_long_reserved_bits(first_byte)
            if _f12_verdict:
                var _v12 = _f12_verdict.take()
                self.close_transport(_v12.error_code, _v12.tag, now)
                raise Error("reserved bits")
        else:
            var _f14_verdict = check_short_reserved_bits(first_byte)
            if _f14_verdict:
                var _v14 = _f14_verdict.take()
                self.close_transport(_v14.error_code, _v14.tag, now)
                raise Error("reserved bits")

        if self.is_server and space_idx == 1 and (self.state & CONN_ADDR_VALIDATED) == 0:
            self.state = self.state | CONN_ADDR_VALIDATED

        var ph_frame_parse_us = self.prof.stamp()
        self._current_dcid = header.dcid.copy()
        var ack_eliciting = self._parse_and_dispatch_frames(
            pkt_ptr, header_len, plaintext_len, space_idx, closing, now,
        )
        ph_frame_parse_us = self.prof.elapsed(ph_frame_parse_us)

        if not closing and newest and self._pkt_non_probing and not header.is_long_header:
            self.last_datagram_may_migrate = True
        if not closing:
            self.spaces[pn_space_idx].on_packet_received(
                full_pn, ack_eliciting, now,
                self.local_params.max_ack_delay * 1000,
            )
            if self.ecn.state != ECN_STATE_DISABLED:
                if ecn_mark == ECN_CE:
                    self.spaces[pn_space_idx].recv_ecn.ce += UInt64(1)
                elif ecn_mark == ECN_ECT0:
                    self.spaces[pn_space_idx].recv_ecn.ect0 += UInt64(1)
                elif ecn_mark == ECN_ECT1:
                    self.spaces[pn_space_idx].recv_ecn.ect1 += UInt64(1)

        return (pn_space_idx, ph_hp_us, ph_aead_us, ph_frame_parse_us)

    def _retransmit_crypto_if_needed(mut self, lowest_recv_space: Int, closing: Bool) raises:
        """Re-queue unacked CRYPTO when receiving at a lower encryption level."""
        if lowest_recv_space >= 3 or closing:
            return
        for s in range(lowest_recv_space + 1, 3):
            if not self.protect.has_keys(s):
                continue
            if self.crypto_streams[s].has_unsent():
                continue
            if len(self.spaces[s].sent_packets) == 0:
                continue
            for entry in self.spaces[s].sent_packets.items():
                for ref frame in entry.value.frames:
                    if frame.is_crypto():
                        ref cf = frame.as_crypto()
                        self.crypto_streams[s].requeue(
                            cf.offset, Span(cf.data)
                        )

    # ── Stream frame handlers ────────────────────────────────────────

    def _handle_stream_frame(mut self, ref stream_frame: StreamFrame, stream_data: Span[Byte, _]) raises:
        """`_handle_stream_frame_from_cursor` for a decoded `StreamFrame` (tests drive this entry)."""
        self._handle_stream_frame_from_cursor(
            stream_frame.stream_id, stream_frame.offset, stream_frame.fin, stream_data
        )

    def _resolve_frame_stream(mut self, stream_id: UInt64, needs_send: Bool) raises -> Bool:
        """Find, or implicitly open, the stream a STREAM, RESET_STREAM or
        STOP_SENDING frame addresses; False means the caller drops the frame.

        `needs_send` names the side of the stream the frame acts on from
        our point of view (STOP_SENDING: our send side; STREAM and
        RESET_STREAM: our receive side). A unidirectional stream lacking
        that side closes the connection with STREAM_STATE_ERROR (RFC 9000
        Sections 19.4, 19.5, 19.8), whether or not it is still in the map.
        An absent id its initiator already opened belongs to a stream that
        was closed and freed: late or duplicate frames for it are ignored
        (RFC 9000 Section 3). Raising instead would discard the whole packet
        unacknowledged, so the peer would retransmit it forever. An absent
        locally-initiated id we never opened closes the connection with
        STREAM_STATE_ERROR, and a peer id beyond our MAX_STREAMS with
        STREAM_LIMIT_ERROR (RFC 9000 Section 4.6).
        """
        if not stream_is_bidi(stream_id) and stream_is_local(stream_id, self.is_server) != needs_send:
            self.close_transport(UInt64(0x05), String(_REASON_WRONG_DIRECTION), monotonic_us())
            return False
        if Int(stream_id) in self.stream_map.streams:
            return True
        if self.stream_map.was_opened(stream_id):
            return False
        if stream_is_local(stream_id, self.is_server):
            self.close_transport(
                UInt64(0x05), String(GUARD_TAG_STREAM_LOCAL_NOT_CREATED),
                monotonic_us(),
            )
            return False
        var new_ids: List[UInt64]
        try:
            new_ids = self.stream_map.get_or_create_peer_stream(stream_id)
        except:
            # Local ids returned above, so the limit is the only failure.
            self.close_transport(UInt64(0x04), String(_REASON_STREAM_LIMIT), monotonic_us())
            return False
        var is_zr = (self._current_space_idx == ZERO_RTT_SPACE_IDX)
        for ref new_id in new_ids:
            self.events.append(QuicEvent.stream_opened(new_id))
            var nkey = Int(new_id)
            if nkey in self.stream_map.streams:
                self.stream_map.streams[nkey][].is_zero_rtt = is_zr
        return True

    def _handle_reset_stream(mut self, reset_frame: ResetStreamFrame) raises:
        """Process an incoming RESET_STREAM frame (RFC 9000 Section 19.4).

        Idempotent: a repeat with the same final size changes nothing. A
        final size that contradicts what was received, or exceeds flow
        control, closes the connection (FINAL_SIZE_ERROR or
        FLOW_CONTROL_ERROR) instead of raising.
        """
        # F15 — RESET on a server-uni stream is illegal: the peer cannot
        # RESET a stream where this endpoint is the sender (§19.4 + §3.2).
        var _f15_ctx = QuicResetCtx(
            stream_id=reset_frame.stream_id,
            local_uni_opened=self.stream_map.local_opened_uni,
            local_bidi_opened=self.stream_map.local_opened_bidi,
            is_server=self.is_server,
        )
        var _f15_verdict = predicate_f15_reset_on_server_uni(_f15_ctx)
        if _f15_verdict:
            var v = _f15_verdict.take()
            self.close_transport(v.error_code, v.tag, monotonic_us())
            return

        var stream_id = reset_frame.stream_id
        var error_code = reset_frame.error_code
        var final_size = reset_frame.final_size

        var key = Int(stream_id)
        if not self._resolve_frame_stream(stream_id, needs_send=False):
            return
        var p = self.stream_map.stream_ptr(key)

        # Validate final_size invariants. Violations close the connection
        # rather than raise: a raise drops the packet unacknowledged, so
        # the peer would retransmit it forever.
        if final_size < p[].recv_highest_offset:
            self.close_transport(
                FINAL_SIZE_ERROR, "RESET_STREAM final size below data received",
                monotonic_us(),
            )
            return
        if p[].fin_offset:
            if final_size != p[].fin_offset.value():
                self.close_transport(
                    FINAL_SIZE_ERROR, "RESET_STREAM final size changed",
                    monotonic_us(),
                )
                return

        if p[].fc_recv:
            if final_size > p[].fc_recv.value().limit:
                self.close_transport(
                    FLOW_CONTROL_ERROR,
                    "RESET_STREAM final size exceeds stream limit",
                    monotonic_us(),
                )
                return

        var rs = p[].recv_state.value()
        # A repeat (retransmitted, or the stream outlived the first one
        # waiting on our own RESET's ACK) with the same final size: already
        # accounted and reported, and Reset Read must not regress.
        if rs == RecvState.RESET_RECVD or rs == RecvState.RESET_READ:
            return
        var was_complete = (rs == RecvState.DATA_RECVD or rs == RecvState.DATA_READ)

        # Account phantom bytes at connection level (bytes the peer implicitly
        # "sent" by claiming final_size without delivering them). Raising
        # recv_highest_offset to final_size records them as counted.
        var phantom = final_size - p[].recv_highest_offset
        if phantom > 0:
            if not self.stream_map.conn_fc_recv.check_limit(phantom):
                self.close_transport(
                    FLOW_CONTROL_ERROR,
                    "RESET_STREAM final size exceeds connection limit",
                    monotonic_us(),
                )
                return
            self.stream_map.conn_fc_recv.add_received(phantom)
            self.stream_map.conn_fc_recv.add_consumed(phantom)
            p[].recv_highest_offset = final_size

        if not p[].fin_offset:
            p[].fin_offset = Optional[UInt64](final_size)

        # Suppress RESET state transition when DATA_RECVD: RFC 9000 §3.2 lets
        # us keep delivering the fully-received stream to the application.
        if not was_complete:
            p[].recv_state = Optional[RecvState](RecvState.RESET_RECVD)
            p[].reset_error = Optional[UInt64](error_code)

        self.events.append(
            QuicEvent.stream_reset(stream_id, error_code, final_size)
        )
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
            is_server=self.is_server,
        )
        var _f16_verdict = predicate_f16_stop_sending_local_not_created(_f16_ctx)
        if _f16_verdict:
            var v = _f16_verdict.take()
            self.close_transport(v.error_code, v.tag, monotonic_us())
            return

        var stream_id = stop_frame.stream_id
        var error_code = stop_frame.error_code

        var key = Int(stream_id)
        if not self._resolve_frame_stream(stream_id, needs_send=True):
            return
        var p = self.stream_map.stream_ptr(key)

        var ss = p[].send_state.value()
        if ss == SendState.RESET_SENT or ss == SendState.RESET_RECVD or ss == SendState.DATA_RECVD:
            return

        # Transition to RESET_SENT and queue a RESET_STREAM for the send path.
        p[].send_state = Optional[SendState](SendState.RESET_SENT)
        p[].stop_error = Optional[UInt64](error_code)
        p[].needs_reset_stream = True
        p[].reset_stream_error = error_code
        var final_size: UInt64 = 0
        if p[].send_buf:
            final_size = p[].send_buf.value().reset_final_size()
        p[].reset_stream_final_size = final_size

        self.stream_map.remove_sendable(key)

        self.events.append(QuicEvent.stream_stopped(stream_id, error_code))
        self.stream_map.mark_reset(key)
        _ = self.stream_map.maybe_cleanup(key)

    # ── Path validation RX handlers ──────────────────────────────────

    def on_path_challenge_received(
        mut self, data: Span[Byte, _], now: UInt64
    ):
        """Stash the 8-byte challenge to echo back as PATH_RESPONSE."""
        self.path.on_challenge_received(data)

    def on_path_response_received(
        mut self, data: Span[Byte, _], var from_addr: PathKey, now: UInt64
    ) raises:
        """Validate a PATH_RESPONSE and, on match, make its address the peer address.

        RFC 9000 Section 8.2: the 8-byte data MUST match a pending challenge
        AND the response MUST arrive from the address the challenge
        targeted. Non-matches are silently dropped (no error, no state
        change).

        A match always promotes `peer_addr`: the challenge was popped, so
        holding the address back would leave it neither validated nor
        under validation, and the default-deny send gate would stall the
        connection. The DCID is rotated to a spare when one exists
        (RFC 9000 Section 9.5, unlinkability); without one (none issued,
        all retired, or zero-length CIDs) the current CID is kept, which
        Section 9.5 allows for a peer-initiated address change such as a
        NAT rebinding.
        """
        var maybe = self.path.validator.on_response(
            data, PathKey(copy=from_addr), now
        )
        if not Bool(maybe):
            return  # silent drop — RFC 9000 Section 8.2 token/addr mismatch.
        _ = self._rotate_to_spare_remote_cid(now)
        # The only site that moves `peer_addr` after the handshake.
        self.path.peer_addr = from_addr^

    def _rotate_to_spare_remote_cid(mut self, now: UInt64) raises -> Bool:
        """Switch to a spare Active remote CID and queue RETIRE_CID for the old one.

        Walks `cid_mgr.remote_cids` for an Active entry whose sequence
        differs from the currently-active one. On success, updates
        `remote_active_cid_seq` and retires the previous CID via
        `retire_remote`. Returns False when no spare exists or the retire
        backlog is full.

        Caller: `on_path_response_received` after a verified match; a
        False return keeps the current CID.
        """
        var current_seq = self.cid_mgr.remote_active_cid_seq
        for i in range(len(self.cid_mgr.remote_cids)):
            ref entry = self.cid_mgr.remote_cids[i]
            if entry.state == CID_ACTIVE and entry.sequence != current_seq:
                var next_seq = entry.sequence
                # Queue RETIRE_CONNECTION_ID for the OLD seq so the peer
                # can free the slot; a full retire backlog defers rotation.
                if not self.cid_mgr.retire_remote(current_seq):
                    return False
                self.cid_mgr.remote_active_cid_seq = next_seq
                self._sync_peer_cid()
                return True
        return False

    def _sync_peer_cid(mut self):
        """Address outgoing packets to the active remote CID.

        Call whenever `cid_mgr.remote_active_cid_seq` changes: packets are
        built from `peer_cid`, and RFC 9000 Section 5.1.2 forbids sending
        to a CID once we have retired it. Safe in both roles: the
        sequence-0 entry holds the SCID adopted from the peer's first
        Initial, the same CID `peer_cid` was set to.
        """
        var seq = self.cid_mgr.remote_active_cid_seq
        for ref e in self.cid_mgr.remote_cids:
            if e.sequence == seq:
                self.peer_cid = CidBuf.from_span(Span(e.cid))
                return

    # ── Path validation TX (emission) ────────────────────────────────

    def emit_path_response_frames(mut self) raises -> List[Frame]:
        """Drain pending PATH_RESPONSE frames."""
        return self.path.emit_response_frames()

    def emit_path_challenge_frames(mut self, now: UInt64) raises -> List[Frame]:
        """The send destination's PATH_CHALLENGE if due, recording the send; see `PathState.emit_challenge_frames`."""
        return self.path.emit_challenge_frames(now, self._challenge_interval())

    def start_path_challenge(
        mut self, var target: PathKey, now: UInt64
    ) raises -> Bool:
        """Begin path validation for `target`; False when `MAX_PENDING_CHALLENGES` are pending."""
        return self.path.begin_challenge(target^, now)

    def has_pending_path_challenge(self, target: PathKey) -> Bool:
        """True iff a challenge for `target` is already pending."""
        return self.path.has_pending_challenge(target)

    def set_current_recv_addr(mut self, var addr: PathKey):
        """Stamp the per-receive source-address cursor."""
        self.path.stamp_recv_addr(addr^)

    def should_drop_from(self, from_addr: PathKey) -> Bool:
        """True when a datagram from `from_addr` must be dropped unread: side-effect free.

        That is an established connection receiving from an address
        other than `peer_addr` when either it advertised
        `disable_active_migration`, or the address has no pending
        challenge and `MAX_PENDING_CHALLENGES` already are (quiche drops
        on its path limit too). RFC 9000 Section 9 lets it drop such
        packets; closing instead would let anyone who can spoof a source
        address with a valid DCID (or a NAT rebinding) kill the
        connection, and processing one at the cap would leave a path we
        cannot validate. The check runs before the datagram is
        decrypted, so it must not change any state.
        """
        if (self.state & CONN_ESTABLISHED) == 0:
            return False
        if (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
            return False
        if from_addr == self.path.peer_addr:
            return False
        if self.local_params.disable_active_migration:
            return True
        return (
            len(self.path.validator.pending) >= MAX_PENDING_CHALLENGES
            and not self.has_pending_path_challenge(from_addr)
        )

    def note_authenticated_ingress(
        mut self, var from_addr: PathKey, datagram_len: Int, now: UInt64
    ) raises:
        """Path bookkeeping for a datagram that authenticated, moving the send destination to `from_addr` when allowed.

        Call it only after the datagram decrypted: an unauthenticated
        datagram must not start a challenge or credit a path. On an
        established connection an address other than `peer_addr` starts
        path validation (RFC 9000 Section 9) unless a challenge for it is
        pending, and the datagram's bytes are credited to that address's
        anti-amplification budget (RFC 9000 Section 8.1). An address that
        could not get a challenge (`MAX_PENDING_CHALLENGES` pending,
        migration disabled, not yet established) is never a destination:
        the send gate would have no budget to hold it to. The destination
        moves only for `last_datagram_may_migrate` (RFC 9000 Section 9.3),
        to `peer_addr` or an address under validation, so `send()` sizes,
        charges and fills (PATH_CHALLENGE) datagrams for the address the
        driver sends them to. Nothing moves once closing, draining or
        closed.
        """
        if (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
            return
        if not (from_addr == self.path.peer_addr):
            if (self.state & CONN_ESTABLISHED) == 0 or self.local_params.disable_active_migration:
                return
            if not self.has_pending_path_challenge(from_addr):
                if not self.start_path_challenge(PathKey(copy=from_addr), now):
                    return
            self.path.validator.record_received_bytes(from_addr, datagram_len)
        if self.last_datagram_may_migrate:
            self.path.dest = from_addr^

    def _challenge_interval(self) -> UInt64:
        """Base Application PTO, without backoff: the first PATH_CHALLENGE retransmit delay (each later one doubles)."""
        var mad = UInt64(0)
        if self.handshake_confirmed and self.peer_params:
            mad = self.peer_params.value().max_ack_delay * 1000
        return self.recovery.base_pto(mad)

    def _path_validation_pto(self) -> UInt64:
        """PTO a path challenge's 3x timeout scales: the larger of the current one and kInitialRtt's (RFC 9000 Section 8.2.4).

        The current PTO is taken without backoff: an unanswered challenge
        is itself ack-eliciting, so its PTOs back off, and a backed-off
        PTO would push the challenge's own expiry out indefinitely.
        """
        return max(self._challenge_interval(), INITIAL_RTT * UInt64(3))

    def bootstrap_peer_addr(mut self, var addr: PathKey):
        """Seed peer_addr to the first observed source address."""
        self.path.seed_peer_addr(addr^)

    def send_destination(self) -> PathKey:
        """Where the datagrams `send()` builds are meant to go: an address under validation that sent the newest non-probing packet, else `peer_addr`.

        `send()` sizes each datagram to that address's anti-amplification
        budget and charges it there, so a driver must send to exactly this
        address.
        """
        if not self.path.has_pending():
            return PathKey(copy=self.path.peer_addr)
        return self.path.send_dest()

    def can_send_to(self, target: PathKey, n_bytes: Int) -> Bool:
        """Anti-amp gate for outbound traffic to `target`."""
        return self.path.can_send(target, n_bytes)

    def record_send_to(mut self, target: PathKey, n_bytes: Int):
        """Credit `n_bytes` to the per-path bytes_sent counter for `target`."""
        self.path.record_send(target, n_bytes)

    # ── Frame dispatch ───────────────────────────────────────────────

    @always_inline
    def _dispatch_frame(
        mut self, ref cursor: FrameCursor[_],
        space_idx: Int, now: UInt64,
    ) raises:
        """Route a parsed frame to its handler using cursor scalar fields."""
        var tid = cursor.type_id
        if self._check_epoch_guards(tid, space_idx, now):
            return
        if tid == FRAME_PADDING or tid == FRAME_PING:
            return
        if tid == FRAME_ACK or tid == FRAME_ACK_ECN:
            var ack = AckFrame()
            ack.largest_ack = cursor.largest_ack
            ack.ack_delay = cursor.ack_delay
            ack.first_ack_range = cursor.first_ack_range
            ack.has_ecn = cursor.has_ecn
            ack.ecn_ect0 = cursor.ecn_ect0
            ack.ecn_ect1 = cursor.ecn_ect1
            ack.ecn_ce = cursor.ecn_ce
            var ack_span = cursor.ack_ranges_span()
            self._handle_ack(ack, ack_span, space_idx, now)
            return
        if tid == FRAME_CRYPTO:
            var data_span = cursor.byte_data_span()
            self.crypto_streams[space_idx].receive(cursor.offset, data_span)
            return
        if tid == FRAME_CONNECTION_CLOSE_TRANSPORT or tid == FRAME_CONNECTION_CLOSE_APP:
            var reason_bytes = cursor.byte_data_span()
            self._on_connection_close(cursor.error_code, reason_bytes, now)
            return
        if tid == FRAME_HANDSHAKE_DONE:
            self._on_handshake_done(now); return
        if tid == FRAME_NEW_TOKEN:
            self._on_new_token(now); return
        if tid == FRAME_NEW_CONNECTION_ID:
            var cid_len = Int(cursor.offset)
            var data_span = cursor.byte_data_span()
            self._on_new_cid_from_cursor(
                cursor.sequence, cursor.retire_prior_to,
                data_span, cid_len, now,
            )
            return
        if tid == FRAME_RETIRE_CONNECTION_ID:
            self._on_retire_cid(cursor.sequence, now); return
        if tid >= FRAME_STREAM_BASE and tid <= FRAME_STREAM_BASE + UInt64(7):
            var data_span = cursor.byte_data_span()
            self._handle_stream_frame_from_cursor(
                cursor.stream_id, cursor.offset, cursor.fin, data_span,
            )
            return
        if tid == FRAME_RESET_STREAM:
            self._handle_reset_stream(ResetStreamFrame(
                cursor.stream_id, cursor.error_code, cursor.final_size,
            ))
            return
        if tid == FRAME_STOP_SENDING:
            self._handle_stop_sending(StopSendingFrame(
                cursor.stream_id, cursor.error_code,
            ))
            return
        if tid == FRAME_MAX_DATA:
            self.stream_map.conn_fc_send.ensure_limit(cursor.maximum)
            self.stream_map.conn_fc_send.blocked_at = UInt64(0)
            return
        if tid == FRAME_MAX_STREAM_DATA:
            self._on_max_stream_data_from_cursor(
                cursor.stream_id, cursor.maximum, now,
            )
            return
        if tid == FRAME_MAX_STREAMS_BIDI:
            self._on_max_streams_from_cursor(cursor.maximum, True, now)
            return
        if tid == FRAME_MAX_STREAMS_UNI:
            self._on_max_streams_from_cursor(cursor.maximum, False, now)
            return
        if tid == FRAME_STREAMS_BLOCKED_BIDI or tid == FRAME_STREAMS_BLOCKED_UNI:
            self._on_streams_blocked_from_cursor(cursor.maximum, now)
            return
        if tid == FRAME_DATA_BLOCKED or tid == FRAME_STREAM_DATA_BLOCKED:
            return
        if tid == FRAME_PATH_CHALLENGE:
            var data_span = cursor.byte_data_span()
            self.on_path_challenge_received(data_span, now)
            return
        if tid == FRAME_PATH_RESPONSE:
            var data_span = cursor.byte_data_span()
            var from_addr = PathKey(copy=self.path.current_recv_addr)
            self.on_path_response_received(data_span, from_addr^, now)
            return
        if tid == FRAME_DATAGRAM or tid == FRAME_DATAGRAM_LEN:
            var data_span = cursor.byte_data_span()
            self.events.append(QuicEvent.datagram_received(List[Byte](data_span)))
            return
        if is_unknown_frame_type(tid):
            self.close_transport(UInt64(0x07), String(GUARD_TAG_UNKNOWN_FRAME), now)
            return

    # ── Per-type frame handlers ─────────────────────────────────────

    @always_inline
    def _check_epoch_guards(
        mut self, tid: UInt64, space_idx: Int, now: UInt64
    ) raises -> Bool:
        """PROTOCOL_VIOLATION guards for frames in wrong epoch.

        Returns True if a guard fired (caller must return immediately).
        """
        if is_path_challenge_in_handshake(tid, space_idx):
            self.close_transport(UInt64(0x0A), String(GUARD_TAG_PATH_CHALLENGE_HS), now)
            return True
        if is_datagram_in_handshake(tid, space_idx):
            self.close_transport(UInt64(0x0A), String(GUARD_TAG_DATAGRAM_HS), now)
            return True
        if is_crypto_in_zero_rtt(tid, space_idx):
            self.close_transport(UInt64(0x0A), String(GUARD_TAG_CRYPTO_IN_ZERO_RTT), now)
            return True
        if is_ack_in_zero_rtt(tid, space_idx):
            self.close_transport(UInt64(0x0A), String(GUARD_TAG_ACK_IN_ZERO_RTT), now)
            return True
        return False

    def _on_connection_close(
        mut self, error_code: UInt64, reason_bytes: Span[Byte, _], now: UInt64,
    ) raises:
        """Handle CONNECTION_CLOSE: enter draining state, emit event."""
        self.state = self.state | CONN_DRAINING
        self.close.drain_timer = now + 3 * self._pto_interval()
        var reason = String("")
        for ref byte in reason_bytes:
            reason += chr(Int(byte))
        self.events.append(QuicEvent.connection_closed(error_code, reason))

    def _on_handshake_done(mut self, now: UInt64) raises:
        """Handle HANDSHAKE_DONE (client-side only)."""
        if self.is_server:
            self.close_transport(
                UInt64(0x0A), String(GUARD_TAG_HANDSHAKE_DONE_SERVER), now
            )
            return
        self.handshake_confirmed = True
        self.state = self.state | CONN_ESTABLISHED
        self._discard_handshake_space()
        self._discard_zero_rtt_keys()
        self.events.append(QuicEvent.handshake_complete())

    def _on_new_token(mut self, now: UInt64) raises:
        """Handle NEW_TOKEN (client no-op; server → PROTOCOL_VIOLATION)."""
        if self.is_server:
            self.close_transport(
                UInt64(0x0A), String(GUARD_TAG_NEW_TOKEN_SERVER), now
            )

    def _on_new_cid(
        mut self, ref frame: Frame, now: UInt64
    ) raises:
        """Handle NEW_CONNECTION_ID: validate and register with CidManager."""
        ref nc = frame.as_new_connection_id()
        var _v_cid_rpt = check_new_connection_id_retire_prior(
            nc.sequence, nc.retire_prior_to
        )
        if _v_cid_rpt:
            var _vv = _v_cid_rpt.take()
            self.close_transport(_vv.error_code, _vv.tag, now)
            return
        var _v_cid_len = check_new_connection_id_length(
            UInt64(len(nc.cid))
        )
        if _v_cid_len:
            var _vv2 = _v_cid_len.take()
            self.close_transport(_vv2.error_code, _vv2.tag, now)
            return
        var _prev_active = self.cid_mgr.remote_active_cid_seq
        var _v_cid = self.cid_mgr.on_new_connection_id(
            nc.sequence,
            nc.retire_prior_to,
            List[Byte](nc.cid.as_span()),
            List[Byte](nc.stateless_reset_token.as_span()),
        )
        if self.cid_mgr.remote_active_cid_seq != _prev_active:
            self._sync_peer_cid()
        if _v_cid:
            var _vv3 = _v_cid.take()
            self.close_transport(_vv3.error_code, _vv3.tag, now)

    def _on_max_stream_data(
        mut self, ref frame: Frame, now: UInt64
    ) raises:
        """`_on_max_stream_data_from_cursor` for a decoded `Frame`."""
        ref msd = frame.as_max_stream_data()
        self._on_max_stream_data_from_cursor(msd.stream_id, msd.maximum, now)

    def _on_max_streams(
        mut self, ref frame: Frame, is_bidi: Bool, now: UInt64
    ) raises:
        """Handle MAX_STREAMS (bidi or uni): validate and update limit."""
        ref ms = frame.as_max_streams()
        var _v_ms = check_max_streams_value(ms.maximum)
        if _v_ms:
            var _vv = _v_ms.take()
            self.close_transport(_vv.error_code, _vv.tag, now)
            return
        if is_bidi:
            if ms.maximum > self.stream_map.peer_max_streams_bidi:
                self.stream_map.peer_max_streams_bidi = ms.maximum
                self.stream_map.needs_streams_blocked_bidi = False
                self.stream_map.streams_blocked_at_bidi = UInt64(0)
        else:
            if ms.maximum > self.stream_map.peer_max_streams_uni:
                self.stream_map.peer_max_streams_uni = ms.maximum
                self.stream_map.needs_streams_blocked_uni = False
                self.stream_map.streams_blocked_at_uni = UInt64(0)

    def _on_streams_blocked(
        mut self, ref frame: Frame, now: UInt64
    ) raises:
        """Handle STREAMS_BLOCKED: validate limit value."""
        ref sb = frame.as_max_streams()
        var _v_sb = check_streams_blocked_value(sb.maximum)
        if _v_sb:
            var _vv = _v_sb.take()
            self.close_transport(_vv.error_code, _vv.tag, now)

    @always_inline
    def _handle_stream_frame_from_cursor(
        mut self, stream_id: UInt64, offset: UInt64, fin: Bool,
        stream_data: Span[Byte, _],
    ) raises:
        """Process STREAM frame from cursor scalars (no StreamFrame alloc)."""
        var data_len = UInt64(len(stream_data))
        var key = Int(stream_id)
        if not self._resolve_frame_stream(stream_id, needs_send=False):
            return
        var p = self.stream_map.stream_ptr(key)
        if not p[].recv_state:
            raise "internal: receivable stream without recv state"
        # RFC 9000 Section 4.5: a known final size never changes, and no
        # data lies beyond it; checked in every state, a retransmission
        # after DATA_RECVD included.
        var end = offset + data_len
        if p[].fin_offset:
            if end > p[].fin_offset.value() or (fin and end != p[].fin_offset.value()):
                self.close_transport(FINAL_SIZE_ERROR, String(_REASON_FINAL_SIZE), monotonic_us())
                return
        elif fin and end < p[].recv_highest_offset:
            self.close_transport(FINAL_SIZE_ERROR, String(_REASON_FINAL_SIZE), monotonic_us())
            return
        var rs = p[].recv_state.value()
        if rs != RecvState.RECV and rs != RecvState.SIZE_KNOWN and rs != RecvState.STOP_SENDING_SENT:
            return
        if not p[].fc_recv:
            raise "internal: missing fc_recv"
        if stream_offset_exceeds_fc(offset, data_len, p[].fc_recv.value().limit):
            self.close_transport(UInt64(0x03), String(GUARD_TAG_STREAM_LARGE_OFFSET), monotonic_us())
            return
        if rs == RecvState.STOP_SENDING_SENT:
            self._discard_recv(key, end, fin)
            return
        if not p[].recv_buf:
            raise "internal: missing recv_buf"
        # Final size is checked above, so the only refusal left is the
        # reassembly gap cap.
        var new_bytes: UInt64
        try:
            new_bytes = p[].recv_buf.value().write(
                offset, stream_data, fin, p[].fin_offset
            )
        except:
            self.close_transport(PROTOCOL_VIOLATION, String(_REASON_RECV_GAPS), monotonic_us())
            return
        if end > p[].recv_highest_offset:
            p[].recv_highest_offset = end
        if not self.stream_map.conn_fc_recv.check_limit(new_bytes):
            self.close_transport(FLOW_CONTROL_ERROR, String(_REASON_CONN_FLOW), monotonic_us())
            return
        p[].fc_recv.value().add_received(new_bytes)
        self.stream_map.conn_fc_recv.add_received(new_bytes)
        var readable = p[].recv_buf.value().has_readable()
        if fin:
            if rs == RecvState.RECV:
                p[].recv_state = Optional[RecvState](RecvState.SIZE_KNOWN)
                rs = RecvState.SIZE_KNOWN
            if rs == RecvState.SIZE_KNOWN:
                if p[].recv_buf.value().is_complete(p[].fin_offset):
                    p[].recv_state = Optional[RecvState](RecvState.DATA_RECVD)
                    # The stream's end is news even with no new bytes (a
                    # bare FIN after the data was read): without an event
                    # the application never learns the stream ended. Once
                    # DATA_RECVD, later frames return above, so this fires
                    # once.
                    readable = True
        if readable:
            self.events.append(QuicEvent.stream_readable(stream_id))

    @always_inline
    def _on_new_cid_from_cursor(
        mut self,
        sequence: UInt64, retire_prior_to: UInt64,
        data: Span[Byte, _], cid_len: Int,
        now: UInt64,
    ) raises:
        """Handle NEW_CONNECTION_ID from cursor scalar fields.

        `data` holds [cid_bytes (cid_len) | stateless_reset_token (16)].
        """
        var _v_cid_rpt = check_new_connection_id_retire_prior(
            sequence, retire_prior_to
        )
        if _v_cid_rpt:
            var _vv = _v_cid_rpt.take()
            self.close_transport(_vv.error_code, _vv.tag, now)
            return
        var _v_cid_len = check_new_connection_id_length(UInt64(cid_len))
        if _v_cid_len:
            var _vv2 = _v_cid_len.take()
            self.close_transport(_vv2.error_code, _vv2.tag, now)
            return
        var cid_span = data[:cid_len]
        var token_span = data[cid_len:]
        var _prev_active = self.cid_mgr.remote_active_cid_seq
        var _v_cid = self.cid_mgr.on_new_connection_id(
            sequence,
            retire_prior_to,
            List[Byte](cid_span),
            List[Byte](token_span),
        )
        if self.cid_mgr.remote_active_cid_seq != _prev_active:
            self._sync_peer_cid()
        if _v_cid:
            var _vv3 = _v_cid.take()
            self.close_transport(_vv3.error_code, _vv3.tag, now)

    def _on_retire_cid(mut self, sequence: UInt64, now: UInt64) raises:
        """Handle RETIRE_CONNECTION_ID; closes on a PROTOCOL_VIOLATION verdict."""
        var _v_ret = self.cid_mgr.on_retire_connection_id(
            sequence, self._current_dcid.as_span()
        )
        if _v_ret:
            var _vv = _v_ret.take()
            self.close_transport(_vv.error_code, _vv.tag, now)

    @always_inline
    def _on_max_stream_data_from_cursor(
        mut self, stream_id: UInt64, maximum: UInt64, now: UInt64,
    ) raises:
        """Handle MAX_STREAM_DATA from cursor scalars."""
        var key = Int(stream_id)
        var p_opt = self.stream_map.try_stream_ptr(key)
        var _has_send = stream_is_bidi(stream_id) or stream_is_local(
            stream_id, self.is_server
        )
        # A freed stream we send on: late frame, ignore (RFC 9000 Section
        # 3). A freed receive-only one still exists for F19: the frame is
        # a STREAM_STATE_ERROR whenever it arrives (Section 19.10).
        var _freed = not p_opt and self.stream_map.was_opened(stream_id)
        if _freed and _has_send:
            return
        var _exists = Bool(p_opt) or _freed
        var _ctx_msd = MaxStreamDataCtx(
            stream_id=stream_id,
            exists=_exists,
            has_send_side=_has_send,
        )
        var _verdict_msd = predicate_f18_f19_max_stream_data(_ctx_msd)
        if _verdict_msd:
            var _v_msd = _verdict_msd.take()
            self.close_transport(_v_msd.error_code, _v_msd.tag, now)
            return
        var p = p_opt.value()
        if p[].fc_send:
            var old_limit = p[].fc_send.value().limit
            p[].fc_send.value().ensure_limit(maximum)
            var grew = p[].fc_send.value().limit > old_limit
            if grew:
                p[].fc_send.value().blocked_at = UInt64(0)
            var _has_pending = False
            if p[].send_buf:
                _has_pending = p[].send_buf.value().has_pending()
            if grew:
                self.events.append(QuicEvent.stream_writable(stream_id))
                if _has_pending:
                    self.stream_map.add_sendable(key)

    @always_inline
    def _on_max_streams_from_cursor(
        mut self, maximum: UInt64, is_bidi: Bool, now: UInt64,
    ) raises:
        """Handle MAX_STREAMS from cursor scalars."""
        var _v_ms = check_max_streams_value(maximum)
        if _v_ms:
            var _vv = _v_ms.take()
            self.close_transport(_vv.error_code, _vv.tag, now)
            return
        if is_bidi:
            if maximum > self.stream_map.peer_max_streams_bidi:
                self.stream_map.peer_max_streams_bidi = maximum
                self.stream_map.needs_streams_blocked_bidi = False
                self.stream_map.streams_blocked_at_bidi = UInt64(0)
        else:
            if maximum > self.stream_map.peer_max_streams_uni:
                self.stream_map.peer_max_streams_uni = maximum
                self.stream_map.needs_streams_blocked_uni = False
                self.stream_map.streams_blocked_at_uni = UInt64(0)

    @always_inline
    def _on_streams_blocked_from_cursor(
        mut self, maximum: UInt64, now: UInt64,
    ) raises:
        """Handle STREAMS_BLOCKED from cursor scalars."""
        var _v_sb = check_streams_blocked_value(maximum)
        if _v_sb:
            var _vv = _v_sb.take()
            self.close_transport(_vv.error_code, _vv.tag, now)

    # ── ACK handling ─────────────────────────────────────────────────

    @always_inline
    def _handle_ack(
        mut self, ref ack_frame: AckFrame,
        ack_ranges: Span[AckRange, _],
        space_idx: Int, now: UInt64,
    ) raises:
        """Process an ACK frame: update recovery, detect losses.

        An ACK of a PN we never sent (skipped, or not yet allocated) is an
        optimistic ACK: PROTOCOL_VIOLATION (RFC 9000 Section 13.1).
        """
        var acked = self.spaces[space_idx].on_ack_received(ack_frame, ack_ranges)
        if self.spaces[space_idx].ack_violation:
            self.close_transport(PROTOCOL_VIOLATION, String(_REASON_ACK_UNSENT), now)
            return

        if len(acked) == 0:
            return

        # Process stream-layer frames for acked Application-space packets.
        if space_idx == 2:
            for ref pkt in acked:
                self._on_app_pkt_acked(Int(pkt.pn))

        self._update_rtt_from_ack(acked, ack_frame, now)

        # Release bytes for acked packets and fan out to congestion controller.
        # Also advance the per-space last_ae_acked_time_sent tracker used by
        # persistent-congestion detection (RFC 9002 §7.6).
        var ect0_acked_count = UInt64(0)
        for ref pkt_info in acked:
            # Decrement ECT(0) in-flight counter on ACK (O(1)).
            if pkt_info.ecn_mark == ECN_ECT0:
                ect0_acked_count += UInt64(1)
                if self.spaces[space_idx].ect0_in_flight > UInt64(0):
                    self.spaces[space_idx].ect0_in_flight -= UInt64(1)
            self.recovery.on_packet_acked(pkt_info.size, pkt_info.in_flight)
            if pkt_info.ack_eliciting:
                if (
                    pkt_info.time_sent
                    > self.spaces[space_idx].last_ae_acked_time_sent
                ):
                    self.spaces[space_idx].last_ae_acked_time_sent = (
                        pkt_info.time_sent
                    )
            var ap = AckedPacket(
                pkt_num=pkt_info.pn,
                size=UInt64(pkt_info.size),
                time_sent=pkt_info.time_sent,
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
        if self.ecn.state != ECN_STATE_DISABLED:
            self._process_ecn_feedback(space_idx, ack_frame, ect0_acked_count, now)

    def _update_rtt_from_ack(
        mut self, acked: List[SentPacket], ref ack_frame: AckFrame, now: UInt64,
    ):
        """Update RTT estimate from the largest newly acked packet."""
        var largest_acked_pn = ack_frame.largest_ack
        for ref pkt_info in acked:
            if pkt_info.pn == largest_acked_pn:
                if now >= pkt_info.time_sent:
                    var rtt_sample = now - pkt_info.time_sent
                    var ade = self.local_params.ack_delay_exponent
                    var mad = self.local_params.max_ack_delay
                    if self.peer_params:
                        ade = self.peer_params.value().ack_delay_exponent
                        mad = self.peer_params.value().max_ack_delay
                    var ack_delay_us = ack_frame.ack_delay * (UInt64(1) << ade)
                    self.recovery.update_rtt(
                        rtt_sample, ack_delay_us, mad * 1000, self.handshake_confirmed,
                    )
                break

    # ── Loss detection ───────────────────────────────────────────────

    def _detect_losses(mut self, space_idx: Int, now: UInt64) raises:
        """Check for lost packets in the given PN space."""
        if self.spaces[space_idx].largest_acked_pn < 0:
            return

        # Detect lost packets by iterating sent_packets in-place, avoiding
        # materialization of 3 parallel lists.
        var largest_acked = self.spaces[space_idx].largest_acked_pn
        var ld = self.recovery.loss_delay()
        self._scratch_lost_pns.clear()
        for entry in self.spaces[space_idx].sent_packets.items():
            var pn = entry.key
            if pn > largest_acked:
                continue
            if largest_acked - pn >= K_PACKET_THRESHOLD:
                self._scratch_lost_pns.append(pn)
                continue
            if now >= entry.value.time_sent + ld:
                self._scratch_lost_pns.append(pn)

        if len(self._scratch_lost_pns) == 0:
            return

        # Swap scratch out so the borrow checker sees separate variables.
        var lost_pns = List[Int]()
        swap(lost_pns, self._scratch_lost_pns)

        # Evaluate persistent-congestion *before* popping lost packets, since
        # the detector reads sent_packets[pn].ack_eliciting / .time_sent.
        var peer_mad_us: UInt64 = UInt64(0)
        if self.peer_params:
            peer_mad_us = self.peer_params.value().max_ack_delay * 1000
        var persistent = self._detect_persistent_congestion(
            space_idx, lost_pns, peer_mad_us, now
        )

        # Build the LostPacket list for CC — single Dict access per PN.
        var lost_records = List[LostPacket](capacity=len(lost_pns))
        for ref pn_key in lost_pns:
            if pn_key in self.spaces[space_idx].sent_packets:
                ref sp = self.spaces[space_idx].sent_packets[pn_key]
                lost_records.append(
                    LostPacket(
                        pkt_num=sp.pn,
                        size=UInt64(sp.size),
                        time_sent=sp.time_sent,
                    )
                )

        self._process_lost_packets(space_idx, lost_pns)

        # Recapture the buffer so its capacity is reused next call.
        self._scratch_lost_pns = lost_pns^

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

    def _process_lost_packets(mut self, space_idx: Int, lost_pns: List[Int]) raises:
        """Teardown lost packets: release bytes, requeue CRYPTO, notify streams."""
        for ref pn_key in lost_pns:
            var maybe_lost = self.spaces[space_idx].forget_sent(pn_key)
            if maybe_lost:
                var lost_pkt = maybe_lost.take()
                if lost_pkt.ecn_mark == ECN_ECT0:
                    if self.spaces[space_idx].ect0_in_flight > UInt64(0):
                        self.spaces[space_idx].ect0_in_flight -= UInt64(1)
                self.recovery.on_packet_lost(lost_pkt.size, lost_pkt.in_flight)
                for ref frame in lost_pkt.frames:
                    if frame.is_crypto():
                        ref cf = frame.as_crypto()
                        self.crypto_streams[space_idx].requeue(
                            cf.offset, Span(cf.data)
                        )
                if space_idx == 2:
                    self._on_app_pkt_lost(pn_key)

    def _detect_persistent_congestion(
        self,
        space_id: Int,
        ref newly_lost_pns: List[Int],
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
        for ref pn in newly_lost_pns:
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
        if self.ecn.state == ECN_STATE_PROBING:
            if (self.ecn.pkts_sent >= self.ecn.pkts_needed
                    and ack.largest_ack >= self.ecn.first_pn):
                if ack.ecn_ect0 == UInt64(0) and ack.ecn_ect1 == UInt64(0) and ack.ecn_ce == UInt64(0):
                    # Peer sees no ECN counts → path strips ECN marks.
                    self.ecn.state = ECN_STATE_DISABLED
                    return
                else:
                    self.ecn.state = ECN_STATE_CAPABLE

        # --- Bleaching / remarking checks (RFC 9000 §13.4.2, only after CAPABLE) ---
        # These checks only apply once ECN is confirmed (CAPABLE).  During
        # PROBING the path validation logic above is the gating mechanism.
        if self.ecn.state == ECN_STATE_CAPABLE:
            var in_flight_ect0 = self.spaces[space_idx].ect0_in_flight
            # Remarking: peer reports more ECN-marked packets than we sent.
            if ack.ecn_ect0 + ack.ecn_ect1 + ack.ecn_ce > in_flight_ect0 + UInt64(1):
                self.ecn.state = ECN_STATE_DISABLED
                return
            # Bleaching: we sent ECT(0)-marked packets in this batch but peer
            # reports no ECN counts → path strips ECN codepoints.
            if (ect0_acked > UInt64(0)
                    and ack.ecn_ect0 == UInt64(0)
                    and ack.ecn_ect1 == UInt64(0)
                    and ack.ecn_ce == UInt64(0)):
                self.ecn.state = ECN_STATE_DISABLED
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
        """Drain crypto data and feed/read from TLS state machine.

        On established connections with no pending crypto data, the TLS
        engine has nothing to process — skip the FFI round-trip and the
        three Owned buffer allocations inside _drain_tls_output.
        """
        if self.conn_handle < 0:
            return
        if self.handshake_confirmed:
            var has_crypto = False
            for level in range(3):
                if self.crypto_streams[level].has_pending():
                    has_crypto = True
                    break
            if not has_crypto:
                return
        var t_drive_start = self.prof.begin_drive()
        var lib = self._lib.inner_ptr()
        self._feed_crypto_to_tls(lib, now)
        self._drain_tls_output(lib)
        var hs_state = lib[].quic_conn_is_handshaking(self.conn_handle)
        if hs_state == Int32(0):
            self._on_handshake_complete(now)
        self.prof.end_drive(t_drive_start)

    def _feed_crypto_to_tls(
        mut self,
        lib: Pointer[mut=True, T=RustlsLibrary, origin=_],
        now: UInt64,
    ) raises:
        """Feed pending CRYPTO bytes from each space to the TLS engine."""
        var crypto_data = List[Byte]()
        for level in range(3):
            if not self.crypto_streams[level].has_pending():
                continue
            crypto_data.clear()
            self.crypto_streams[level].drain(crypto_data)
            if len(crypto_data) == 0:
                continue
            var t_input_start = self.prof.stamp()
            var data_buf_owned = Owned[UInt8](len(crypto_data))
            var data_buf = data_buf_owned.ptr()
            for i in range(len(crypto_data)):
                data_buf[unsafe_offset=i] = crypto_data[i]
            var input_marshalling_us = self.prof.elapsed(t_input_start)
            var t_start = self.prof.stamp_ffi()
            var rc: Int32 = Int32(0)
            var out_sm_us: UInt64 = UInt64(0)
            var out_lookup_us: UInt64 = UInt64(0)
            comptime if PROFILE_ACCEPT:
                if self.prof.is_active():
                    rc = lib[].quic_conn_read_hs(
                        self.conn_handle, data_buf,
                        Int32(len(crypto_data)),
                        Pointer(to=out_sm_us), Pointer(to=out_lookup_us),
                    )
                else:
                    rc = lib[].quic_conn_read_hs(
                        self.conn_handle, data_buf, Int32(len(crypto_data)),
                    )
            else:
                rc = lib[].quic_conn_read_hs(
                    self.conn_handle, data_buf, Int32(len(crypto_data)),
                )
            self.prof.record_ffi_read_hs_end(
                t_start, input_marshalling_us, out_sm_us, out_lookup_us,
            )
            if rc < 0:
                var alert_code = lib[].quic_conn_alert(self.conn_handle)
                var crypto_error = UInt64(0x0100) | UInt64(alert_code)
                self.close_transport(crypto_error, _tls_guard_tag_for(alert_code, self.current_level, self.handshake_confirmed, String(GUARD_TAG_TLS_KEYUPDATE_1RTT)), now)
                return

    def _drain_tls_output(
        mut self,
        lib: Pointer[mut=True, T=RustlsLibrary, origin=_],
    ) raises:
        """Loop write_hs to drain TLS output and install new keys."""
        var out_buf_owned = Owned[UInt8](_WRITE_HS_BUF_SIZE)
        var out_buf = out_buf_owned.ptr()
        var out_written_owned = Owned[Int32](1)
        var out_written = out_written_owned.ptr()
        var out_kc_owned = Owned[UInt8](1)
        var out_kc = out_kc_owned.ptr()
        while True:
            out_written[unsafe_offset=0] = Int32(0)
            out_kc[unsafe_offset=0] = UInt8(0)
            var t_start = self.prof.stamp_ffi()
            var rc = lib[].quic_conn_write_hs(
                self.conn_handle, out_buf,
                Int32(_WRITE_HS_BUF_SIZE), out_written, out_kc,
            )
            self.prof.record_ffi_write_hs_end(t_start)
            if rc < 0:
                var err = lib[].last_error()
                raise "quic_conn_write_hs failed: " + err
            var kc = out_kc[unsafe_offset=0]
            var written = Int(out_written[unsafe_offset=0])
            if written > 0:
                var target_level = self.current_level
                var tls_data = List[Byte](capacity=written)
                for i in range(written):
                    tls_data.append(out_buf[unsafe_offset=i])
                self.crypto_streams[target_level].write(Span(tls_data))
            if kc != UInt8(0):
                self._install_new_keys(lib, kc)
            if written == 0 and kc == UInt8(0):
                break

    def _install_new_keys(
        mut self,
        lib: Pointer[mut=True, T=RustlsLibrary, origin=_],
        kc: UInt8,
    ) raises:
        """Take keys from TLS and install at the appropriate level."""
        var keys_handle_buf_owned = Owned[Int32](1)
        var keys_handle_buf = keys_handle_buf_owned.ptr()
        keys_handle_buf[unsafe_offset=0] = Int32(-1)
        var t_start = self.prof.stamp_ffi()
        var take_rc = lib[].quic_conn_take_keys(
            self.conn_handle, keys_handle_buf
        )
        self.prof.record_ffi_take_keys_end(t_start)
        if take_rc < 0:
            var err = lib[].last_error()
            raise "quic_conn_take_keys failed: " + err
        var new_keys = keys_handle_buf[unsafe_offset=0]
        _ = keys_handle_buf_owned
        if kc == UInt8(1):
            self.protect.set_keys(1, new_keys)
            self.current_level = 1
        elif kc == UInt8(2):
            self.protect.set_keys(2, new_keys)
            self.current_level = 2

    def _on_handshake_complete(mut self, now: UInt64) raises:
        """Called when TLS reports handshake is complete.

        A transport-parameter check that fails closes the connection; it
        is then never promoted (no ESTABLISHED, no HANDSHAKE_DONE, no
        handshake_complete event), so nothing treats a closing peer as
        usable or validated; later calls on a closing connection return
        at once.
        """
        if (self.state & (CONN_ESTABLISHED | CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
            return
        if self.is_server:
            self.prof.record_hs_complete(now)
        self._record_handshake_profile_stats()
        self.state = self.state & ~CONN_HANDSHAKING
        self._apply_peer_transport_params(now)
        if (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
            return
        # Seed Application-space PN skipping from the CSPRNG: a seed the
        # peer can derive (it used to be our SCID) lets it predict every
        # skipped PN and ACK optimistically without tripping the check.
        var seed_bytes = InlineArray[UInt8, 8](fill=UInt8(0))
        fill_random(Span(seed_bytes))
        var pn_skip_seed = UInt64(0)
        for i in range(8):
            pn_skip_seed = (pn_skip_seed << 8) | UInt64(seed_bytes[i])
        if pn_skip_seed == 0:  # xorshift's fixed point
            pn_skip_seed = UInt64(0xDEADBEEFCAFEB00F)
        self.spaces[2].pn_skip_rng  = pn_skip_seed
        self.spaces[2].pn_skip_next = 200 + (pn_skip_seed % 300)
        self._promote_to_established()

    def _record_handshake_profile_stats(mut self) raises:
        """Record handshake kind, FFI totals, and CPU/wait breakdown."""
        if not self.is_server or self.prof.ptr is None:
            return
        var hs_kind = self._lib.inner_ptr()[].quic_conn_handshake_kind(self.conn_handle)
        if hs_kind == Int32(1) or hs_kind == Int32(3):
            self.prof.ptr.value()[].record_handshake_full()
        elif hs_kind == Int32(2):
            self.prof.ptr.value()[].record_handshake_resumed()
        elif hs_kind == Int32(0):
            raise (
                "_on_handshake_complete: handshake_kind=0 with "
                + "is_handshaking==false (rustls state-machine "
                + "invariant broken)"
            )
        self.prof.ptr.value()[].record_fresh_conn_ffi_us(self.prof.fresh_conn_ffi_us_total)
        self.prof.ptr.value()[].record_read_hs_per_handshake_count(Int(self.prof.read_hs_call_count))
        if self.prof.accept_us > UInt64(0):
            var now_hs = monotonic_us()
            var wall_us = now_hs - self.prof.accept_us
            if wall_us >= self.prof.hs_cpu_us_total:
                self.prof.hs_wait_us_total = wall_us - self.prof.hs_cpu_us_total
            else:
                self.prof.hs_wait_us_total = UInt64(0)
            self.prof.ptr.value()[].record_hs_cpu_us_per_handshake(self.prof.hs_cpu_us_total)
            self.prof.ptr.value()[].record_hs_wait_us_per_handshake(self.prof.hs_wait_us_total)

    def _apply_peer_transport_params(mut self, now: UInt64) raises:
        """Read, parse, validate, and apply peer transport parameters."""
        var tp_buf_owned = Owned[UInt8](_TP_BUF_SIZE)
        var tp_buf = tp_buf_owned.ptr()
        var tp_written_owned = Owned[Int32](1)
        var tp_written = tp_written_owned.ptr()
        tp_written[unsafe_offset=0] = Int32(0)
        var lib = self._lib.inner_ptr()
        var rc = lib[].quic_conn_transport_params(
            self.conn_handle, tp_buf, Int32(_TP_BUF_SIZE), tp_written,
        )
        if rc != Int32(0) or Int(tp_written[unsafe_offset=0]) <= 0:
            return
        var tp_len = Int(tp_written[unsafe_offset=0])
        var tp_bytes = List[Byte](capacity=tp_len)
        for i in range(tp_len):
            tp_bytes.append(tp_buf[unsafe_offset=i])
        _ = tp_written_owned
        _ = tp_buf_owned
        var peer_tp: TransportParams
        try:
            peer_tp = parse_transport_params(Span(tp_bytes))
        except e:
            self.close_transport(UInt64(0x08), String(e), now)
            return
        if self.is_server:
            try:
                validate_client_transport_params(peer_tp)
            except e:
                self.close_transport(UInt64(0x08), String(e), now)
                return
        else:
            var why = self._server_cid_params_error(peer_tp)
            if why:
                self.close_transport(UInt64(0x08), why, now)
                return
        var scid_why = self._initial_scid_error(peer_tp)
        if scid_why:
            self.close_transport(UInt64(0x08), scid_why, now)
            return
        self.peer_params = TransportParams(copy=peer_tp)
        self.events.append(QuicEvent.peer_transport_params(peer_tp))
        var peer = self.peer_params.value().copy()
        self.stream_map.set_peer_limits(
            max_streams_bidi=peer.initial_max_streams_bidi,
            max_streams_uni=peer.initial_max_streams_uni,
            stream_fc_bidi_local=peer.initial_max_stream_data_bidi_local,
            stream_fc_bidi_remote=peer.initial_max_stream_data_bidi_remote,
            stream_fc_uni=peer.initial_max_stream_data_uni,
            conn_fc_send_limit=peer.initial_max_data,
        )
        self.cid_mgr.set_peer_active_limit(peer.active_connection_id_limit)
        _ = self.cid_mgr.issue_new_cid()

    def _initial_scid_error(self, ref tp: TransportParams) -> String:
        """Why the peer's initial_source_connection_id fails RFC 9000 Section 7.3, empty if it passes.

        Both roles: it MUST be present and equal the SCID of the peer's
        first authenticated Initial (`_initial_peer_scid`), zero-length
        included; otherwise the Initial SCID was altered on the path.
        """
        if not tp.initial_scid or not self._initial_peer_scid:
            return String(_REASON_INITIAL_SCID)
        if Span(tp.initial_scid.value()) != self._initial_peer_scid.value().as_span():
            return String(_REASON_INITIAL_SCID)
        return String()

    def _server_cid_params_error(self, ref tp: TransportParams) -> String:
        """Why the server's CID transport parameters fail RFC 9000 Section 7.3 on a client, empty if they pass.

        original_destination_connection_id must echo our first DCID, and
        retry_source_connection_id must name the Retry we followed, or be
        absent if we followed none: a mismatch means an attacker injected
        or replayed the Retry, or the Initial path was tampered with.
        """
        if not tp.original_dcid or Span(tp.original_dcid.value()) != self.initial_dcid.as_span():
            return String(_REASON_ORIGINAL_DCID)
        if self._retry_scid:
            if not tp.retry_scid or Span(tp.retry_scid.value()) != self._retry_scid.value().as_span():
                return String(_REASON_RETRY_SCID)
        elif tp.retry_scid:
            return String(_REASON_RETRY_SCID)
        return String()

    def _promote_to_established(mut self) raises:
        """Transition to ESTABLISHED, discard handshake keys, queue event."""
        if self.is_server:
            self.state = self.state | CONN_ESTABLISHED
            self.handshake_confirmed = True
            self._discard_initial_space()
            self._discard_handshake_space()
            self._discard_zero_rtt_keys()
            self.send_handshake_done = True
            self.events.append(QuicEvent.handshake_complete())
        else:
            self._discard_initial_space()
            if self.handshake_confirmed:
                self.state = self.state | CONN_ESTABLISHED
                self._discard_handshake_space()
                self._discard_zero_rtt_keys()
                self.events.append(QuicEvent.handshake_complete())

    # ── Space discard helpers ────────────────────────────────────────

    def _discard_initial_space(mut self) raises:
        """Discard Initial packet number space and keys."""
        if (self.state & CONN_INITIAL_DISCARDED) != 0:
            return
        self.state = self.state | CONN_INITIAL_DISCARDED

        var discarded = self.spaces[0].discard()
        for ref pkt in discarded:
            self.recovery.on_packet_lost(pkt.size, pkt.in_flight)

        self.protect.discard_keys(0)

    def _discard_handshake_space(mut self) raises:
        """Discard Handshake packet number space and keys."""
        if (self.state & CONN_HS_DISCARDED) != 0:
            return
        self.state = self.state | CONN_HS_DISCARDED

        var discarded = self.spaces[1].discard()
        for ref pkt in discarded:
            self.recovery.on_packet_lost(
                pkt.size, pkt.in_flight
            )

        self.protect.discard_keys(1)

    def _discard_zero_rtt_keys(mut self) raises:
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
        self.zrtt.buffer = List[List[Byte]]()
        self.zrtt.buffer_bytes = 0

    def _zero_rtt_enabled(self) -> Bool:
        """True if 0-RTT is enabled by server config."""
        return self.zrtt.is_enabled()

    def _buffer_zero_rtt_or_drop(mut self, packet: Span[Byte, _]) -> Bool:
        """Buffer a 0-RTT packet for later replay. Delegates to ZeroRttState."""
        return self.zrtt.buffer_or_drop(packet)

    def _drain_zero_rtt_buffer(mut self, now: UInt64, ecn_mark: UInt8) raises:
        """Replay buffered 0-RTT packets through the production coalesce
        path now that rustls has had a chance to derive the early-data
        secret. Idempotent (empty-buffer no-op). Re-entry into
        recv_from_buffer is guarded by self.zrtt.draining = True,
        which makes the decrypt-path's Path B fail branch drop instead
        of re-buffer (preventing unbounded re-entry).

        Each buffered packet replays inside its own per-packet
        containment: a packet that raises is dropped (counted via
        `zero_rtt_drain_dropped`) and the drain continues with the
        remaining packets.
        """
        if len(self.zrtt.buffer) == 0:
            return
        var pending = self.zrtt.buffer^
        self.zrtt.buffer = List[List[Byte]]()
        self.zrtt.buffer_bytes = 0
        self.zrtt.draining = True
        try:
            for pkt in pending:
                var buf_ptr_owned = Owned[UInt8](len(pkt))
                var buf_ptr = buf_ptr_owned.ptr()
                for i in range(len(pkt)):
                    buf_ptr[unsafe_offset=i] = pkt[i]
                # The Owned wrapper frees `buf_ptr_owned` on every path —
                # normal loop-iteration exit AND the per-packet raise
                # unwind — so no `finally` free is needed. The except below
                # is retained purely for the drop-and-continue semantics
                # (count the dropped packet, keep draining the rest).
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
                    self.prof.record_counter(CounterId.ZERO_RTT_DRAIN_DROPPED)
                # Keep `buf_ptr_owned` alive to the end of the iteration (its
                # `.ptr()` borrow feeds recv_from_buffer above), and ensure the
                # inner try/except is NOT the for-body's final statement: Mojo
                # 1.0.0b2's parser rejects an outer try/finally whose for-loop
                # body ends in an inner try/except (no inner finally).
                _ = buf_ptr_owned
        finally:
            self.zrtt.draining = False

    def _invoke_replay_authenticator_ffi(
        mut self,
        mut out_buf: InlineArray[UInt8, 32],
        mut out_len: UInt,
    ) -> Int32:
        """Delegate to zero_rtt.invoke_replay_authenticator_ffi."""
        return invoke_replay_authenticator_ffi(
            self._lib, self.conn_handle, out_buf, out_len,
        )

    def _drive_replay_check_for_test(
        mut self,
        simulated_rc: Int32,
        simulated_decision_kind: UInt8,
        simulated_raises: Bool,
    ) raises:
        """Test-only delegate to zero_rtt.drive_replay_check_for_test."""
        drive_replay_check_for_test(
            self.zrtt, self.prof,
            simulated_rc, simulated_decision_kind, simulated_raises,
        )

    # ── Send path ────────────────────────────────────────────────────

    def send(mut self, now: UInt64, mut out: List[List[Byte]]) raises -> Int:
        """Build at most one datagram into `out`; returns 0 or 1.

        `out` is cleared (length reset, capacity kept) and reused across
        calls so the caller amortizes the outer List allocation instead of
        getting a fresh one back on every call.
        """
        var _ct_start = UInt64(0)
        comptime if PROFILE_ACCEPT:
            _ct_start = rdtsc()
        out.clear()
        self._check_timers(now)
        if (self.state & (CONN_DRAINING | CONN_CLOSED)) != 0:
            comptime if PROFILE_ACCEPT:
                if self.prof.ptr is not None:
                    self.prof.ptr.value()[].call_tracker.record(CallId.SEND, rdtsc() - _ct_start)
            return 0
        var closing = (self.state & CONN_CLOSING) != 0
        if closing and not self.close.owed:
            comptime if PROFILE_ACCEPT:
                if self.prof.ptr is not None:
                    self.prof.ptr.value()[].call_tracker.record(CallId.SEND, rdtsc() - _ct_start)
            return 0
        var budget = self._datagram_budget()
        if self.is_server and not self._addr_validated():
            var allowance = self._amp_allowance()
            if allowance < budget:
                budget = allowance
        # An address under validation gets 3x what it sent (RFC 9000
        # Section 8.1): size the datagram to fit rather than build one the
        # driver's gate would drop.
        # With no validation in flight the destination is `peer_addr`,
        # whose allowance is unbounded: skip the lookup.
        if self.path.has_pending():
            var path_allowance = self.path.send_allowance()
            if path_allowance < budget:
                budget = path_allowance
        var server_initial_deferred = self.is_server and budget < MAX_DATAGRAM_SIZE
        var ade = self.local_params.ack_delay_exponent
        var plans = List[PacketPlan]()
        swap(plans, self._scratch_plans)
        plans.clear()
        var used = 0
        var all_close_committed = True
        var end_assembly = False
        for space_idx in range(3):
            if end_assembly:
                break
            if not self.protect.has_keys(space_idx):
                continue
            var overhead = self._header_len(space_idx) + MAX_PN_LEN + AEAD_TAG_LEN
            var remaining = budget - used
            if remaining < overhead + MIN_PLAINTEXT_LEN:
                if closing:
                    all_close_committed = False
                continue
            var payload_budget = remaining - overhead
            var r = self._plan_space_packet(
                space_idx, closing, server_initial_deferred,
                ade, payload_budget, overhead, now,
            )
            if not r[0]:
                if closing:
                    all_close_committed = False
                if r[1]:
                    end_assembly = True
                continue
            var plan = r[0].take()
            var plaintext = len(plan.payload)
            if plaintext < MIN_PLAINTEXT_LEN:
                plaintext = MIN_PLAINTEXT_LEN
            used += overhead + plaintext
            plans.append(plan^)
            if r[1]:
                end_assembly = True
        if len(plans) == 0:
            comptime if PROFILE_ACCEPT:
                if self.prof.ptr is not None:
                    self.prof.ptr.value()[].call_tracker.record(CallId.SEND, rdtsc() - _ct_start)
            return 0
        var result = self._commit_plans_to_datagram(
            plans, budget, closing, all_close_committed, now,
        )
        self._scratch_plans = plans^
        for i in range(len(result)):
            var dg = List[Byte]()
            swap(dg, result[i])
            if self.path.has_pending():
                self.path.record_dest_send(len(dg))
            out.append(dg^)
        comptime if PROFILE_ACCEPT:
            if self.prof.ptr is not None:
                self.prof.ptr.value()[].call_tracker.record(CallId.SEND, rdtsc() - _ct_start)
        return len(out)

    def _plan_space_packet(
        mut self,
        space_idx: Int,
        closing: Bool,
        server_initial_deferred: Bool,
        ade: UInt64,
        payload_budget: Int,
        overhead: Int,
        now: UInt64,
    ) raises -> Tuple[Optional[PacketPlan], Bool]:
        """Plan one packet for a PN space.

        Returns (plan, should_end_assembly). Plan is None if nothing to send.
        """
        var frames = List[Frame]()
        swap(frames, self._scratch_frames)
        frames.clear()
        var sent_records = List[SentStreamFrame]()
        swap(sent_records, self._scratch_sent_records)
        sent_records.clear()
        var stream_payload = List[Byte]()
        swap(stream_payload, self._scratch_payload)
        stream_payload.clear()
        var ack_reserve = 0
        var has_stream_data = False
        var ack_committed = False
        var should_end = False
        if closing:
            var cf = self._close_frame_for_space(space_idx)
            if cf.wire_len() > payload_budget:
                return (None, False)
            frames.append(cf^)
        else:
            var deferred = server_initial_deferred and space_idx == 0
            var may_bundle = (not deferred) and self._space_has_other_sendable(space_idx, now)
            var maybe_ack = self.spaces[space_idx].peek_ack_frame(
                now, ade, bundle=may_bundle
            )
            var reserve = 0
            var has_ack = False
            if maybe_ack:
                ref ack_ref = maybe_ack.value()
                ack_reserve = write_ack_frame_direct(stream_payload, payload_budget, ack_ref)
                reserve = ack_reserve
                if reserve <= 0:
                    return (None, False)
                has_ack = True
            var base = len(frames)
            var gate_open = self.spaces[space_idx].probe_pending or self._cc_open(
                now, space_idx, overhead + MIN_PLAINTEXT_LEN
            )
            if gate_open and not deferred:
                self._build_frames_for_space(
                    space_idx, now, frames, sent_records, stream_payload,
                    payload_budget - reserve,
                )
                if (self.spaces[space_idx].probe_pending
                        and not _has_ack_eliciting(frames)
                        and len(stream_payload) == ack_reserve
                        and reserve + 1 <= payload_budget):
                    frames.append(Frame.ping())
            has_stream_data = len(stream_payload) > ack_reserve
            if len(frames) > base or has_stream_data:
                ack_committed = has_ack
            elif has_ack and self.spaces[space_idx].ack_needed:
                ack_committed = True
            else:
                if deferred and self.crypto_streams[0].has_unsent():
                    should_end = True
                return (None, should_end)
            if deferred and self.crypto_streams[0].has_unsent():
                should_end = True
        var plan = self._finalize_packet_plan(
            space_idx, frames^, sent_records^, stream_payload^,
            ack_committed, has_stream_data,
        )
        return (Optional[PacketPlan](plan^), should_end)

    def _finalize_packet_plan(
        mut self,
        space_idx: Int,
        var frames: List[Frame],
        var sent_records: List[SentStreamFrame],
        var stream_payload: List[Byte],
        ack_committed: Bool,
        has_stream_data: Bool,
    ) raises -> PacketPlan:
        """Serialize control frames and assemble a PacketPlan."""
        var has_control = False
        for ref frame in frames:
            if not frame.is_crypto():
                has_control = True
                break
        if has_control:
            var wbuf = List[Byte]()
            swap(wbuf, self._scratch_writer_buf)
            wbuf.clear()
            var writer = ByteWriter()
            swap(writer.buf, wbuf)
            for ref frame in frames:
                if not frame.is_crypto():
                    serialize_frame(frame, writer)
            stream_payload.extend(Span(writer.buf))
            swap(self._scratch_writer_buf, writer.buf)
        return PacketPlan(
            space_idx, frames^, sent_records^, stream_payload^,
            ack_committed, has_stream_data,
        )

    @always_inline
    def _commit_plans_to_datagram(
        mut self,
        mut plans: List[PacketPlan],
        budget: Int,
        closing: Bool,
        all_close_committed: Bool,
        now: UInt64,
    ) raises -> List[List[Byte]]:
        """Allocate PNs, build+encrypt packets, coalesce into a datagram."""
        var pad_to = 0
        for ref plan in plans:
            var s = plan.space_idx
            if self.is_server:
                if s == 0 and _has_ack_eliciting(plan.frames):
                    pad_to = MAX_DATAGRAM_SIZE
            elif (s == 0 or s == 1) and (self.state & CONN_ESTABLISHED) == 0:
                pad_to = MAX_DATAGRAM_SIZE
        debug_assert(pad_to <= budget, "padding target exceeds the datagram budget")
        var datagram = List[Byte]()
        swap(datagram, self._scratch_datagram)
        datagram.clear()
        for i in range(len(plans)):
            var space_idx = plans[i].space_idx
            var pn = self.spaces[space_idx].alloc_pn()
            var largest_acked = UInt64(0)
            if self.spaces[space_idx].largest_acked_pn >= 0:
                largest_acked = UInt64(self.spaces[space_idx].largest_acked_pn)
            var pn_len = pn_encode_length(pn, largest_acked)
            var padding = 0
            if i == len(plans) - 1 and pad_to > 0:
                var hdr = self._header_len(space_idx) - MAX_PN_LEN + pn_len
                var unpadded = len(datagram) + hdr + len(plans[i].payload) + AEAD_TAG_LEN
                if unpadded < pad_to:
                    padding = pad_to - unpadded
            self._build_packet(space_idx, pn, pn_len, plans[i].payload, padding)
            swap(self._scratch_payload, plans[i].payload)
            var pkt_size = len(self.pkt_buf)
            datagram.extend(Span(self.pkt_buf))
            if plans[i].ack_committed:
                self.spaces[space_idx].mark_ack_sent()
            var is_ack_eliciting = _has_ack_eliciting(plans[i].frames) or plans[i].has_stream_data
            var in_flight = is_ack_eliciting or padding > 0
            var ect = self.ecn_mark()
            var crypto_frames = List[Frame]()
            for ref frame in plans[i].frames:
                if frame.is_crypto():
                    crypto_frames.append(Frame(copy=frame))
            var sent = SentPacket(
                pn=pn, time_sent=now, ack_eliciting=is_ack_eliciting,
                in_flight=in_flight, size=pkt_size,
                frames=crypto_frames^, ecn_mark=ect,
            )
            self.spaces[space_idx].on_packet_sent(sent^)
            if ect == ECN_ECT0:
                self.spaces[space_idx].ect0_in_flight += UInt64(1)
                if self.ecn.pkts_sent == 0:
                    self.ecn.first_pn = pn
                self.ecn.pkts_sent += 1
            self.recovery.on_packet_sent(pkt_size, in_flight, pn, now)
            if space_idx == 2 and is_ack_eliciting:
                var _pace_rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
                _ = self.recovery.pacer.refill_and_check(_pace_rate, now)
                self.recovery.pacer.on_sent(UInt64(pkt_size))
            if space_idx == 2 and len(plans[i].sent_records) > 0:
                var moved_records = List[SentStreamFrame]()
                swap(moved_records, plans[i].sent_records)
                self.app_frames_sent[Int(pn)] = moved_records^
            swap(self._scratch_frames, plans[i].frames)
        if closing and all_close_committed:
            self.close.owed = False
            self.close.last_sent = now
        debug_assert(len(datagram) <= budget, "datagram exceeds its budget")
        self.bytes_sent += UInt64(len(datagram))
        var datagrams = List[List[Byte]](capacity=1)
        datagrams.append(datagram^)
        return datagrams^

    def _datagram_budget(self) -> Int:
        """Delegate to packet_builder.datagram_budget."""
        return datagram_budget()

    def _amp_allowance(self) -> Int:
        """Delegate to packet_builder.amp_allowance."""
        return amp_allowance(self.bytes_received, self.bytes_sent)

    def _header_len(self, space_idx: Int) -> Int:
        """Delegate to packet_builder.header_len."""
        return header_len(space_idx, len(self.local_cid), len(self.peer_cid), len(self._retry_token))

    def _cc_open(self, now: UInt64, space_idx: Int, min_cost: Int) -> Bool:
        """Congestion gate: cwnd has room for a minimum packet and, in the
        Application space once established, the pacer has a token."""
        if self.recovery.bytes_in_flight + UInt64(min_cost) > self.recovery.cc.cwnd():
            return False
        if space_idx == 2 and self.is_established():
            var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
            if self.recovery.pacer.next_send_time(rate, now):
                return False
        return True

    def _close_frame_for_space(self, space_idx: Int) -> Frame:
        """The pending CLOSE as emitted in `space_idx`: RFC 9000 §10.2.3
        re-packs an application close (0x1d) as a transport close (0x1c,
        APPLICATION_ERROR) in Initial and Handshake packets."""
        if not self.close.pending.value().is_transport and space_idx != 2:
            var cc = ConnectionCloseFrame()
            cc.is_transport = True
            cc.error_code = APPLICATION_ERROR
            cc.frame_type = UInt64(0)
            cc.reason = self.close.pending.value().reason.copy()
            return Frame.connection_close(cc)
        return Frame.connection_close(self.close.pending.value())

    @always_inline
    def _space_has_other_sendable(self, space_idx: Int, now: UInt64) -> Bool:
        """Non-mutating bundle predicate: one clause per builder that could
        emit a non-ACK frame in this space. May be conservatively true, never
        false when a builder would produce a frame."""
        if self.crypto_streams[space_idx].has_unsent():
            return True
        if self.spaces[space_idx].probe_pending:
            return True
        if space_idx != 2:
            return False
        if self.send_handshake_done and self.is_server:
            return True
        if self.is_server and not self.initial_cids_emitted and (self.state & CONN_ESTABLISHED) != 0:
            return True
        if self.cid_mgr.has_unadvertised() or self.cid_mgr.has_pending_retire():
            return True
        if len(self.stream_map.sendable_set) > 0:
            return True
        if (self.stream_map.conn_fc_recv.should_update() or self.stream_map.needs_max_data
                or self.stream_map.needs_max_streams_bidi or self.stream_map.needs_max_streams_uni
                or self.stream_map.needs_streams_blocked_bidi or self.stream_map.needs_streams_blocked_uni):
            return True
        var conn_limit = self.stream_map.conn_fc_send.limit
        if (self.stream_map.conn_fc_send.received >= conn_limit
                and self.stream_map.conn_fc_send.blocked_at != conn_limit):
            return True
        if (len(self.stream_map.control_max_stream_data) > 0
                or len(self.stream_map.control_reset) > 0
                or len(self.stream_map.control_stop_sending) > 0):
            return True
        if len(self.path.pending_responses) > 0 or self.path.challenge_due(now):
            return True
        if self._outbound_dg_head < len(self.pending_outbound_datagrams):
            return True
        return False

    # ── Frame building ───────────────────────────────────────────────

    def _build_frames_for_space(
        mut self, space_idx: Int, now: UInt64,
        mut frames: List[Frame],
        mut sent_records: List[SentStreamFrame],
        mut stream_payload: List[Byte],
        budget: Int,
    ) raises:
        """Append the non-ACK frames for one PN space within `budget` bytes.

        Runs only when the packet will be emitted: every builder here mutates
        state (crypto cursor, `needs_*` flags, `mark_advertised`, FC windows).
        `sent_records` receives the Application-space stream-layer frames so
        ACK/loss handlers can re-apply state by packet number.  CRYPTO and
        STREAM frame bytes are written directly into `stream_payload`,
        bypassing Frame allocation and serialize_frame dispatch; CRYPTO
        Frames are still appended to `frames` for loss-recovery requeue.
        All other frames go into `frames` for serialize_frames.
        """
        var used = 0

        # CRYPTO: one frame per packet, sized to what is left. The length
        # varint is charged at 2 bytes (valid for any chunk < 16384).
        if self.crypto_streams[space_idx].has_unsent():
            var off = self.crypto_streams[space_idx].send_offset + UInt64(
                self.crypto_streams[space_idx].sent_cursor
            )
            var charge = 1 + varint_len(off) + 2
            var max_data = budget - used - charge
            if max_data > 0:
                var maybe = self.crypto_streams[space_idx].next_crypto_frame(max_data)
                if maybe:
                    var cf = maybe.take()
                    var written = write_crypto_frame_direct(
                        stream_payload, budget - used, cf.offset, Span(cf.data)
                    )
                    # Frame kept in `frames` for CRYPTO loss tracking;
                    # wire bytes already in stream_payload — serialize
                    # skips CRYPTO frames to avoid duplication.
                    frames.append(Frame.crypto(cf))
                    used += written

        # HANDSHAKE_DONE (server, Application space); recorded so a loss
        # re-queues it until acknowledged (RFC 9000 Section 13.3).
        if self.send_handshake_done and space_idx == 2 and self.is_server and used + 1 <= budget:
            frames.append(Frame.handshake_done())
            self.send_handshake_done = False
            used += 1
            var hd_rec = SentStreamFrame()
            hd_rec.kind = SSF_HANDSHAKE_DONE
            sent_records.append(hd_rec^)

        # Application-space stream-layer frames.
        if space_idx == 2:
            # RFC 9000 §5.1.1: initial NEW_CONNECTION_ID burst. On the first
            # 1-RTT flush after CONN_ESTABLISHED, fill `local_cids` up to
            # `cid_mgr.issue_limit()` (the peer's limit clamped to
            # MAX_ISSUED_CIDS) so the peer has spare CIDs for migration.
            # `_build_app_frames` below drains the resulting unadvertised
            # entries into NEW_CONNECTION_ID frames in this same flight —
            # alongside HANDSHAKE_DONE on the server's very first 1-RTT
            # packet (per RFC 9000 §5.1.1 SHOULD).
            if (
                self.is_server
                and not self.initial_cids_emitted
                and (self.state & CONN_ESTABLISHED) != 0
            ):
                var limit = self.cid_mgr.issue_limit()
                while self.cid_mgr.active_local_count() < limit:
                    var issued = self.cid_mgr.issue_new_cid()
                    if not Bool(issued):
                        break
                self.initial_cids_emitted = True

            # Path frames first: on an address under validation the 3x
            # budget may fit little else, and the challenge is what lifts it.
            self._build_path_frames(frames, used, budget, now)
            self._build_app_frames(frames, sent_records, stream_payload, budget, used)
            self._build_datagram_frames(frames, used, budget)

    def _max_app_payload(self) -> Int:
        """Largest plaintext a 1-RTT packet can carry in an empty datagram."""
        return MAX_DATAGRAM_SIZE - self._header_len(2) - AEAD_TAG_LEN

    def _build_path_frames(
        mut self, mut frames: List[Frame], mut used: Int, budget: Int, now: UInt64,
    ) raises:
        """Append PATH_RESPONSEs (as many as fit, 9 bytes each; the rest stay
        queued) and the destination's PATH_CHALLENGE when due."""
        if len(self.path.pending_responses) > 0 and budget - used >= 9:
            var path_responses = self.path.emit_response_frames((budget - used) // 9)
            for ref pr in path_responses:
                frames.append(pr.copy())
            used += 9 * len(path_responses)
        if used + 9 <= budget and self.path.challenge_due(now):
            var path_challenges = self.emit_path_challenge_frames(now)
            for ref pc in path_challenges:
                frames.append(pc.copy())
            used += 9 * len(path_challenges)

    def _build_datagram_frames(
        mut self, mut frames: List[Frame], mut used: Int, budget: Int,
    ) raises:
        """Append queued DATAGRAM frames in order while they fit."""
        while self._outbound_dg_head < len(self.pending_outbound_datagrams):
            var dl = len(self.pending_outbound_datagrams[self._outbound_dg_head])
            var wl = 1 + varint_len(UInt64(dl)) + dl
            if used + wl > budget:
                if wl > self._max_app_payload():
                    raise "DATAGRAM frame of " + String(wl) + " bytes can never fit a packet"
                break
            var head = List[Byte](copy=self.pending_outbound_datagrams[self._outbound_dg_head])
            self._outbound_dg_head += 1
            frames.append(Frame.datagram_with_len(head^))
            used += wl
        if self._outbound_dg_head >= len(self.pending_outbound_datagrams):
            self.pending_outbound_datagrams = List[List[Byte]]()
            self._outbound_dg_head = 0

    def _build_app_frames(
        mut self,
        mut frames: List[Frame],
        mut sent_records: List[SentStreamFrame],
        mut stream_payload: List[Byte],
        budget: Int,
        mut used: Int,
    ) raises:
        """Append Application-space stream / FC / CID frames within budget."""
        self._emit_cid_and_fc_frames(frames, sent_records, budget, used)
        drain_max_stream_data_frames(self.stream_map, frames, sent_records, budget, used)
        drain_reset_stream_frames(self.stream_map, frames, sent_records, budget, used)
        drain_stop_sending_frames(self.stream_map, frames, sent_records, budget, used)
        emit_stream_frames(self.stream_map, sent_records, stream_payload, budget, used)
        emit_blocked_frames(self.stream_map, frames, sent_records, budget, used)

    def _emit_cid_and_fc_frames(
        mut self,
        mut frames: List[Frame],
        mut sent_records: List[SentStreamFrame],
        budget: Int,
        mut used: Int,
    ) raises:
        """Emit NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, MAX_DATA, MAX_STREAMS."""
        var pending_new = self.cid_mgr.pending_new_cid_entries()
        for ref pending_entry in pending_new:
            var entry = CidEntry(copy=pending_entry)
            var ncid = NewConnectionIdFrame()
            ncid.sequence = entry.sequence
            ncid.retire_prior_to = self.cid_mgr.local_retire_prior_to
            ncid.cid = CidBuf.from_span(Span(entry.cid))
            ncid.stateless_reset_token.extend(Span(entry.reset_token))
            var f = Frame.new_connection_id(ncid)
            var wl = f.wire_len()
            if used + wl > budget:
                break
            frames.append(f^)
            used += wl
            var rec = SentStreamFrame()
            rec.kind = SSF_NEW_CID
            rec.cid_seq = entry.sequence
            sent_records.append(rec^)
            self.cid_mgr.mark_advertised(entry.sequence)
        var pending_retire = self.cid_mgr.pending_retire_frames()
        for ref seq in pending_retire:
            var wl = 1 + varint_len(seq)
            if used + wl > budget:
                self.cid_mgr.requeue_retire(seq)
                continue
            frames.append(Frame.retire_connection_id(seq))
            used += wl
            var rec = SentStreamFrame()
            rec.kind = SSF_RETIRE_CID
            rec.cid_seq = seq
            sent_records.append(rec^)
        if self.stream_map.conn_fc_recv.should_update() or self.stream_map.needs_max_data:
            var wl = 1 + varint_len(self.stream_map.conn_fc_recv.next_limit())
            if used + wl <= budget:
                var new_limit = self.stream_map.conn_fc_recv.update_limit()
                var f = Frame.max_data(new_limit)
                used += f.wire_len()
                frames.append(f^)
                self.stream_map.needs_max_data = False
                var rec = SentStreamFrame()
                rec.kind = SSF_MAX_DATA
                sent_records.append(rec^)
        if self.stream_map.needs_max_streams_bidi:
            var f = Frame.max_streams(MaxStreamsFrame(self.stream_map.local_max_streams_bidi, True))
            var wl = f.wire_len()
            if used + wl <= budget:
                frames.append(f^)
                used += wl
                self.stream_map.needs_max_streams_bidi = False
                var rec = SentStreamFrame()
                rec.kind = SSF_MAX_STREAMS_BIDI
                sent_records.append(rec^)
        if self.stream_map.needs_max_streams_uni:
            var f = Frame.max_streams(MaxStreamsFrame(self.stream_map.local_max_streams_uni, False))
            var wl = f.wire_len()
            if used + wl <= budget:
                frames.append(f^)
                used += wl
                self.stream_map.needs_max_streams_uni = False
                var rec = SentStreamFrame()
                rec.kind = SSF_MAX_STREAMS_UNI
                sent_records.append(rec^)

    # ── Packet building ──────────────────────────────────────────────

    def _build_packet(
        mut self,
        space_idx: Int,
        pn: UInt64,
        pn_len: Int,
        payload: List[Byte],
        padding: Int = 0,
    ) raises:
        """Delegate to packet_builder.build_packet."""
        build_packet(
            self.pkt_buf, self.protect,
            self.peer_cid.as_span(), self.local_cid.as_span(), Span(self._retry_token),
            space_idx, pn, pn_len, payload,
            self._header_len(space_idx), padding,
        )

    # ── Application-space frame ACK/loss handling ─────────────

    def _on_app_pkt_acked(mut self, pn: Int) raises:
        """Apply ACK side-effects for stream-layer frames in the acked packet."""
        if pn not in self.app_frames_sent:
            return
        var records = self.app_frames_sent.pop(pn)
        for ref rec in records:
            if rec.kind == SSF_RETIRE_CID:
                self.cid_mgr.on_retire_acked(rec.cid_seq)
            elif rec.kind == SSF_STREAM:
                var key = Int(rec.stream_id)
                var p = self.stream_map.try_stream_ptr(key)
                if not p:
                    continue
                var ptr = p.value()
                if ptr[].send_buf:
                    ptr[].send_buf.value().on_ack(rec.offset, rec.length)
                    var fully = ptr[].send_buf.value().is_fully_acked()
                    if fully and ptr[].send_state:
                        var ss = ptr[].send_state.value()
                        if ss == SendState.DATA_SENT:
                            ptr[].send_state = Optional[SendState](SendState.DATA_RECVD)
                    _ = self.stream_map.maybe_cleanup(key)
            elif rec.kind == SSF_RESET_STREAM:
                var key = Int(rec.stream_id)
                var p = self.stream_map.try_stream_ptr(key)
                if not p:
                    continue
                var ptr = p.value()
                if ptr[].send_state:
                    var ss = ptr[].send_state.value()
                    if ss == SendState.RESET_SENT:
                        ptr[].send_state = Optional[SendState](SendState.RESET_RECVD)
                _ = self.stream_map.maybe_cleanup(key)

    def _on_app_pkt_lost(mut self, pn: Int) raises:
        """Re-queue stream-layer frames for retransmission on packet loss."""
        if pn not in self.app_frames_sent:
            return
        var records = self.app_frames_sent.pop(pn)
        for ref rec in records:
            if rec.kind == SSF_STREAM:
                var key = Int(rec.stream_id)
                var p = self.stream_map.try_stream_ptr(key)
                if not p:
                    continue
                var ptr = p.value()
                if ptr[].send_buf:
                    ptr[].send_buf.value().on_loss(rec.offset, rec.length)
                    var has_pending = ptr[].send_buf.value().has_pending()
                    if has_pending:
                        self.stream_map.add_sendable(key)
            elif rec.kind == SSF_RESET_STREAM:
                var key = Int(rec.stream_id)
                var p = self.stream_map.try_stream_ptr(key)
                if p:
                    var ptr = p.value()
                    ptr[].needs_reset_stream = True
                    self.stream_map.mark_reset(key)
            elif rec.kind == SSF_STOP_SENDING:
                var key = Int(rec.stream_id)
                var p = self.stream_map.try_stream_ptr(key)
                if p:
                    var ptr = p.value()
                    ptr[].needs_stop_sending = True
                    self.stream_map.mark_stop_sending(key)
            elif rec.kind == SSF_MAX_DATA:
                self.stream_map.needs_max_data = True
            elif rec.kind == SSF_MAX_STREAM_DATA:
                var key = Int(rec.stream_id)
                var p = self.stream_map.try_stream_ptr(key)
                if p:
                    var ptr = p.value()
                    ptr[].needs_max_stream_data = True
                    self.stream_map.mark_max_stream_data(key)
            elif rec.kind == SSF_MAX_STREAMS_BIDI:
                self.stream_map.needs_max_streams_bidi = True
            elif rec.kind == SSF_MAX_STREAMS_UNI:
                self.stream_map.needs_max_streams_uni = True
            elif rec.kind == SSF_NEW_CID:
                # Clear advertised flag so the CID is re-queued for a new
                # NEW_CONNECTION_ID frame on the next send opportunity.
                self.cid_mgr.clear_advertised(rec.cid_seq)
            elif rec.kind == SSF_RETIRE_CID:
                # Re-queue unless the retirement was acked meanwhile.
                self.cid_mgr.requeue_retire(rec.cid_seq)
            elif rec.kind == SSF_HANDSHAKE_DONE:
                self.send_handshake_done = True
            # A lost *_BLOCKED frame is re-armed only if it is still the
            # latest announcement; the emitter re-checks that we are still
            # blocked and sends the limit current then.
            elif rec.kind == SSF_DATA_BLOCKED:
                if self.stream_map.conn_fc_send.blocked_at == rec.offset:
                    self.stream_map.conn_fc_send.blocked_at = UInt64(0)
            elif rec.kind == SSF_STREAM_DATA_BLOCKED:
                var p = self.stream_map.try_stream_ptr(Int(rec.stream_id))
                if p and p.value()[].fc_send:
                    if p.value()[].fc_send.value().blocked_at == rec.offset:
                        p.value()[].fc_send.value().blocked_at = UInt64(0)
            elif rec.kind == SSF_STREAMS_BLOCKED_BIDI:
                if self.stream_map.streams_blocked_at_bidi == rec.offset:
                    self.stream_map.streams_blocked_at_bidi = UInt64(0)
            elif rec.kind == SSF_STREAMS_BLOCKED_UNI:
                if self.stream_map.streams_blocked_at_uni == rec.offset:
                    self.stream_map.streams_blocked_at_uni = UInt64(0)

    # ── Timers ───────────────────────────────────────────────────────

    def _pto_interval(self, space_idx: Int = 2) -> UInt64:
        """Current PTO period (RFC 9002 §6.2.1): srtt + max(4·rttvar, 1 ms)
        + the PEER's max_ack_delay, the latter only for the Application space
        once the handshake is confirmed; backed off by `pto_count`."""
        var mad = UInt64(0)
        if space_idx == 2 and self.handshake_confirmed and self.peer_params:
            mad = self.peer_params.value().max_ack_delay * 1000
        return self.recovery.pto_timeout(mad)

    def _highest_keyed_space(self) -> Int:
        """Index of the highest space with keys, -1 if none."""
        for s in range(2, -1, -1):
            if self.protect.has_keys(s):
                return s
        return -1

    @always_inline
    def _pto_deadline(self, space_idx: Int) -> Optional[UInt64]:
        """Single source of truth for one space's PTO deadline.

        None while closing/draining/closed, on an amplification-limited
        server (RFC 9002 §6.2.2.1), for a keyless space, or while this space's
        probe is already pending (delivered by the next `send()`). Otherwise
        `time_of_last_ae_sent + PTO`. A handshaking client with nothing
        ack-eliciting in flight anywhere arms `idle_timer + PTO` on its
        highest keyed space so it cannot deadlock (RFC 9002 §6.2.2.1).
        """
        if (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
            return None
        if self.is_server and not self._addr_validated():
            return None
        if not self.protect.has_keys(space_idx):
            return None
        if self.spaces[space_idx].probe_pending:
            return None
        if self.spaces[space_idx].time_of_last_ae_sent:
            return Optional[UInt64](
                self.spaces[space_idx].time_of_last_ae_sent.value() + self._pto_interval(space_idx)
            )
        if not self.is_server and (self.state & CONN_HANDSHAKING) != 0:
            if space_idx == self._highest_keyed_space():
                var any_ae = False
                for s in range(3):
                    if self.spaces[s].time_of_last_ae_sent:
                        any_ae = True
                if not any_ae:
                    return Optional[UInt64](self.idle_timer + self._pto_interval(space_idx))
        return None

    def timeout(self, now: UInt64) -> Optional[UInt64]:
        """Earliest deadline the caller must wake `send()` for, or None.

        Sources: per-space PTO and ACK deadlines, path-validation expiry
        and a server's handshake deadline (omitted while
        closing/draining/closed), idle, close and drain timers, and, on an
        established non-terminal connection, the pacer wait — folded only
        when it is earlier than the rest and Application data is actually
        waiting, so the stream walk is skipped otherwise.
        Pure in connection state and `now`. After `send(now)` this is None or
        strictly greater than `now`, except for an idle deadline that expired
        in that call.
        """
        var earliest = Optional[UInt64](None)
        var terminal = (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0

        if not terminal:
            for s in range(3):
                _min_deadline(earliest, self._pto_deadline(s))
                _min_deadline(earliest, self.spaces[s].ack_deadline)
            _min_deadline(earliest, self.path.validator.next_expiry(self._path_validation_pto()))
            if self.is_server and not self.is_established():
                _min_deadline(earliest, Optional[UInt64](self.created_us + HANDSHAKE_TIMEOUT_US))
            # A challenge that came due but could not go out (congestion or
            # anti-amplification limited) waits for the ACK or datagram that
            # lifts the limit, not for a timer that would spin.
            var chal_at = self.path.next_challenge_at()
            if chal_at and chal_at.value() > now:
                _min_deadline(earliest, chal_at)

        # Idle timer — use effective min(local, peer).
        var idle_effective = self._effective_idle_timeout()
        if idle_effective > 0:
            _min_deadline(earliest, Optional[UInt64](self.idle_timer + idle_effective * 1000))

        if self.close.timer > 0:
            _min_deadline(earliest, Optional[UInt64](self.close.timer))
        if self.close.drain_timer > 0:
            _min_deadline(earliest, Optional[UInt64](self.close.drain_timer))

        # Pacer: a wake-up source only when Application data is waiting on
        # a token. The wait is computed first (pure, O(1)) and the stream
        # walk is the last operand, so an unpaced or already-later wait
        # never pays for `_space_has_other_sendable`.
        if not terminal and self.is_established():
            var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
            var wait = self.recovery.pacer.next_send_time(rate, now)
            if wait and (earliest is None or wait.value() < earliest.value()) and self._space_has_other_sendable(2, now):
                earliest = wait

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

    def _check_timers(mut self, now: UInt64) raises:
        """Check and handle expired timers."""
        # Drain timer.
        if self.close.drain_timer > 0 and now >= self.close.drain_timer:
            self.state = self.state | CONN_CLOSED
            self.close.drain_timer = UInt64(0)
            return

        # Close timer.
        if self.close.timer > 0 and now >= self.close.timer:
            self.state = self.state | CONN_CLOSED
            self.close.timer = UInt64(0)
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

        if (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
            return

        # An expired server handshake closes silently: no closing state and
        # no CONNECTION_CLOSE toward an address that may be spoofed (RFC
        # 9000 Section 10.2).
        if self.is_server and not self.is_established() and now >= self.created_us + HANDSHAKE_TIMEOUT_US:
            self.state = self.state | CONN_CLOSED
            return

        # Abandon path validations older than 3 PTOs (RFC 9000 Section
        # 8.2.4); the sender then falls back to `peer_addr`. `settle_dest`
        # stays unconditional: a PATH_RESPONSE can empty the pending list
        # while `dest` still names the previous address.
        if self.path.has_pending():
            self.path.validator.gc_expired(now, self._path_validation_pto())
        self.path.settle_dest()

        # Delayed-ACK deadlines: the ACK goes out in this same send() since
        # ACK-only packets bypass the congestion gate.
        for s in range(3):
            if self.spaces[s].ack_deadline:
                if self.spaces[s].ack_deadline.value() <= now:
                    self.spaces[s].ack_needed = True
                    self.spaces[s].ack_deadline = None

        # PTO (RFC 9002 §6.2.4). Deadlines are snapshotted for all spaces
        # before anything mutates, then every expired space fires and
        # pto_count is incremented exactly once — the backoff must not hide a
        # second expired space behind the first one's doubled interval.
        var d0 = self._pto_deadline(0)
        var d1 = self._pto_deadline(1)
        var d2 = self._pto_deadline(2)
        var fire0 = d0.__bool__() and d0.value() <= now
        var fire1 = d1.__bool__() and d1.value() <= now
        var fire2 = d2.__bool__() and d2.value() <= now
        if not (fire0 or fire1 or fire2):
            return
        for s in range(3):
            var should_fire = fire0 if s == 0 else (fire1 if s == 1 else fire2)
            if not should_fire:
                continue
            # Re-queue this space's unacknowledged CRYPTO data (the cursor
            # already consumed the original bytes) unless some is still
            # staged; the probe is then that retransmission, else a PING.
            if not self.crypto_streams[s].has_unsent():
                for entry in self.spaces[s].sent_packets.items():
                    for ref frame in entry.value.frames:
                        if frame.is_crypto():
                            ref cf = frame.as_crypto()
                            self.crypto_streams[s].requeue(
                                cf.offset, Span(cf.data)
                            )
            self.spaces[s].probe_pending = True
        self.recovery.pto_count += 1

    # ── Public API ───────────────────────────────────────────────────

    def poll(mut self) -> Optional[QuicEvent]:
        """Next pending event in append order; O(1) via a head index, the
        list is reset (not rebuilt) once drained.

        Handing out a STREAM_RESET event is what informs the application
        of the reset, so the stream's receive side moves to Reset Read
        here and the stream is reaped if its send side is done too.
        """
        if self._events_head >= len(self.events):
            if len(self.events) > 0:
                self.events.clear()
            self._events_head = 0
            return None
        var ev = QuicEvent(UInt8(0), QuicEventPayload(NoneType()))
        swap(ev, self.events[self._events_head])
        self._events_head += 1
        if self._events_head >= len(self.events):
            self.events.clear()
            self._events_head = 0
        if ev.type_id == QuicEvent.STREAM_RESET:
            self._on_reset_delivered(
                ev.payload.unsafe_get[StreamResetPayload]().stream_id
            )
        return ev^

    def _on_reset_delivered(mut self, stream_id: UInt64):
        """Reset Recvd -> Reset Read (RFC 9000 Section 3.2), then reap.

        Without this a peer-reset stream never reaches a terminal receive
        state: it is never freed and its MAX_STREAMS credit never returns.
        A stream already reaped, or whose data was fully received before
        the reset (it stays Data Recvd), is left alone.
        """
        var key = Int(stream_id)
        var p_opt = self.stream_map.try_stream_ptr(key)
        if not p_opt:
            return
        var p = p_opt.value()
        if not p[].recv_state or p[].recv_state.value() != RecvState.RESET_RECVD:
            return
        p[].recv_state = Optional[RecvState](RecvState.RESET_READ)
        try:
            _ = self.stream_map.maybe_cleanup(key)
        except:
            # Only the sendable-set bookkeeping can raise; the stream stays
            # terminal and is reaped when its send side finishes.
            pass

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
        are no-ops. Queues the `ConnectionCloseFrame` as `close.pending` with
        the reason truncated to MAX_CLOSE_REASON_BYTES, owes one CLOSE
        datagram, drops any pending delayed ACK, and arms the 3*PTO close
        timer (RFC 9000 §10.2).
        """
        if (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
            return
        self.state = self.state | CONN_CLOSING
        self.close.timer = now + 3 * self._pto_interval()
        self.close.owed = True
        for s in range(3):
            self.spaces[s].ack_deadline = None
        var cc = ConnectionCloseFrame()
        cc.is_transport = not is_app
        cc.error_code = error_code
        cc.frame_type = UInt64(0)
        _ = cc.reason.extend_truncated(reason.as_bytes())
        self.close.pending = cc^

    def is_established(self) -> Bool:
        """True if the handshake is complete and the connection is usable."""
        return (self.state & CONN_ESTABLISHED) != 0

    def is_expected_dcid(self, dcid: Span[Byte, _]) -> Bool:
        """True if `dcid` is one of our live CIDs.

        Live means `local_cid`, the client's Initial DCID and any active
        CID we issued: the H3 server's demux keys.
        """
        if dcid == self.local_cid.as_span():
            return True
        if dcid == self.initial_dcid.as_span():
            return True
        for ref e in self.cid_mgr.local_cids:
            if dcid == Span(e.cid):
                return True
        return False

    def is_closing(self) -> Bool:
        """True if the connection is in the closing state."""
        return (self.state & CONN_CLOSING) != 0

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
        mut self, stream_id: UInt64, data: Span[Byte, _], fin: Bool
    ) raises:
        """Queue data for sending on a stream (and optionally mark FIN)."""
        var key = Int(stream_id)
        var p_opt = self.stream_map.try_stream_ptr(key)
        if not p_opt:
            raise "unknown stream"
        var p = p_opt.value()
        if not p[].send_state or not p[].send_buf:
            raise "STREAM_STATE_ERROR: no send side"
        var ss = p[].send_state.value()
        if (ss == SendState.DATA_SENT or ss == SendState.DATA_RECVD
                or ss == SendState.RESET_SENT or ss == SendState.RESET_RECVD):
            raise "STREAM_STATE_ERROR: send side terminal or FIN already queued"
        p[].send_buf.value().write(data, fin)
        var has_pending = p[].send_buf.value().has_pending()
        if has_pending:
            self.stream_map.add_sendable(key)

    def send_h3_data(
        mut self,
        stream_id: UInt64,
        app_payload: List[Byte],
        fin: Bool,
    ) raises:
        """Write H3 DATA header + application payload as a single stream write.

        Fuses the H3 DATA frame header (type 0x00 + varint length) with the
        application payload into one buffer, avoiding the intermediate
        H3RawFrame.encode allocation that the H3 layer would otherwise
        perform.
        """
        var payload_len = len(app_payload)
        var hdr_len = 1 + varint_len(UInt64(payload_len))
        var combined = List[Byte](capacity=hdr_len + payload_len)
        # H3 DATA frame type = 0x00.
        combined.append(0x00)
        # Varint-encode the payload length directly into the buffer.
        var vl_size = varint_len(UInt64(payload_len))
        var vl_base = len(combined)
        combined.resize(vl_base + vl_size, Byte(0))
        _ = varint_encode_at(combined, vl_base, UInt64(payload_len))
        # Bulk-copy the application payload.
        combined.extend(Span(app_payload))
        self.send_stream_data(stream_id, Span(combined), fin)

    def recv_stream_data(
        mut self, stream_id: UInt64
    ) raises -> Tuple[List[Byte], Bool]:
        """Read available contiguous bytes from a stream's recv buffer.

        Returns (bytes, fin_reached). Consumes FC credit for the drained bytes
        and flags MAX_DATA / MAX_STREAM_DATA updates as needed.
        """
        var key = Int(stream_id)
        var p_opt = self.stream_map.try_stream_ptr(key)
        if not p_opt:
            raise "unknown stream"
        var p = p_opt.value()
        if not p[].recv_buf or not p[].fc_recv:
            raise "STREAM_STATE_ERROR: no recv side"
        var result = p[].recv_buf.value().read(p[].fin_offset)
        var data = List[Byte]()
        swap(data, result[0])
        var fin_reached = result[1]
        var drained = UInt64(len(data))
        if drained > 0:
            p[].fc_recv.value().add_consumed(drained)
            self.stream_map.conn_fc_recv.add_consumed(drained)
        var _needs_msd = p[].fc_recv.value().should_update()
        if _needs_msd:
            p[].needs_max_stream_data = True
        if self.stream_map.conn_fc_recv.should_update():
            self.stream_map.needs_max_data = True
        if p[].recv_state:
            var rs = p[].recv_state.value()
            if rs == RecvState.DATA_RECVD and fin_reached:
                p[].recv_state = Optional[RecvState](RecvState.DATA_READ)
        if _needs_msd:
            self.stream_map.mark_max_stream_data(key)
        _ = self.stream_map.maybe_cleanup(key)
        return (data^, fin_reached)

    def reset_stream(mut self, stream_id: UInt64, error_code: UInt64) raises:
        """Abort the send side of a stream with the given error code."""
        var key = Int(stream_id)
        var p_opt = self.stream_map.try_stream_ptr(key)
        if not p_opt:
            raise "unknown stream"
        var p = p_opt.value()
        if not p[].send_state:
            raise "STREAM_STATE_ERROR: no send side"
        var ss = p[].send_state.value()
        if (ss == SendState.DATA_RECVD or ss == SendState.RESET_SENT
                or ss == SendState.RESET_RECVD):
            return
        var final_size: UInt64 = 0
        if p[].send_buf:
            final_size = p[].send_buf.value().reset_final_size()
        p[].send_state = Optional[SendState](SendState.RESET_SENT)
        p[].needs_reset_stream = True
        p[].reset_stream_error = error_code
        p[].reset_stream_final_size = final_size
        self.stream_map.remove_sendable(key)
        self.stream_map.mark_reset(key)

    def reset_unfinished_stream(mut self, stream_id: UInt64, error_code: UInt64):
        """Reset our send side unless it has already ended (FIN queued or
        reset) or does not exist; a no-op for an already-freed stream.

        For an application abandoning a stream the peer reset: a send side
        left open keeps the stream from ever being freed. A FIN counts as
        queued from the moment the application asks for it, framed or not
        and even if lost: a complete response must still be delivered
        (RFC 9114 Section 4.1.2).
        """
        var p_opt = self.stream_map.try_stream_ptr(Int(stream_id))
        if not p_opt:
            return
        var p = p_opt.value()
        if not p[].send_state:
            return
        var ss = p[].send_state.value()
        if ss != SendState.READY and ss != SendState.SEND:
            return
        # `fin`, not `fin_offset`: the latter is only set once the FIN is
        # framed and is cleared again when that frame is lost.
        if p[].send_buf and p[].send_buf.value().fin:
            return
        try:
            self.reset_stream(stream_id, error_code)
        except:
            pass  # unreachable: the stream and its send side exist

    def send_datagram(mut self, payload: Span[Byte, _]) raises -> Bool:
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
        var copy = List[Byte](capacity=len(payload))
        for ref byte in payload:
            copy.append(byte)
        self.pending_outbound_datagrams.append(copy^)
        return True

    def stop_sending(mut self, stream_id: UInt64, error_code: UInt64) raises:
        """Request the peer to stop sending on a stream."""
        var key = Int(stream_id)
        var p_opt = self.stream_map.try_stream_ptr(key)
        if not p_opt:
            raise "unknown stream"
        var p = p_opt.value()
        if not p[].recv_state:
            raise "STREAM_STATE_ERROR: no recv side"
        var rs = p[].recv_state.value()
        if (rs == RecvState.DATA_READ or rs == RecvState.RESET_READ
                or rs == RecvState.RESET_RECVD):
            return
        p[].recv_state = Optional[RecvState](RecvState.STOP_SENDING_SENT)
        if p[].fin_offset:  # the peer has sent everything: nothing to stop
            self._discard_recv(key, p[].fin_offset.value(), True)
            return
        p[].needs_stop_sending = True
        p[].stop_sending_error = error_code
        self.stream_map.mark_stop_sending(key)

    def _discard_recv(mut self, key: Int, end: UInt64, fin: Bool) raises:
        """Receive side after our STOP_SENDING, which leaves its state machine running (RFC 9000 Section 3.5).

        Payload is dropped but bytes up to `end` count as received and read, so flow control still binds and the
        credit comes back; the final size (`fin`) completes the stream to Data Read and frees it. Without this a FIN
        crossing our STOP_SENDING leaves the stream, and its MAX_STREAMS credit, held forever.
        """
        var p = self.stream_map.stream_ptr(key)
        var grow = end - min(end, p[].recv_highest_offset)
        if not self.stream_map.conn_fc_recv.check_limit(grow):
            self.close_transport(FLOW_CONTROL_ERROR, String(_REASON_CONN_FLOW), monotonic_us())
            return
        ref conn_fc = self.stream_map.conn_fc_recv
        p[].recv_highest_offset += grow
        ref fc = p[].fc_recv.value()
        fc.add_received(grow)
        conn_fc.add_received(grow)
        conn_fc.add_consumed(fc.received - fc.consumed)
        fc.add_consumed(fc.received - fc.consumed)
        self.stream_map.needs_max_data = self.stream_map.needs_max_data or conn_fc.should_update()
        if fin:
            p[].fin_offset = Optional[UInt64](end)
            p[].recv_state = Optional[RecvState](RecvState.DATA_READ)
            _ = self.stream_map.maybe_cleanup(key)

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
        if self.ecn.state == ECN_STATE_DISABLED:
            return ECN_NOT_ECT
        return ECN_ECT0

    def _addr_validated(self) -> Bool:
        """True if the peer address has been validated."""
        return (self.state & CONN_ADDR_VALIDATED) != 0



# ── Module-level helpers ─────────────────────────────────────────────


def _generate_random_cid() raises -> List[Byte]:
    """Generate a random 8-byte connection ID via getrandom(2)."""
    var buf_owned = Owned[UInt8](8)
    var buf = buf_owned.ptr()
    var rc = external_call["getrandom", Int](buf, UInt64(8), UInt32(0))
    if rc != 8:
        raise "getrandom failed"
    var cid = List[Byte](capacity=8)
    for i in range(8):
        cid.append(buf[unsafe_offset=i])
    # Keep buf_owned alive across the post-FFI `buf[i]` copy loop above.
    _ = buf_owned
    return cid^


def _has_ack_eliciting(ref frames: List[Frame]) -> Bool:
    """Check if any frame in the list is ack-eliciting."""
    for ref frame in frames:
        if frame.is_ack_eliciting():
            return True
    return False


def _min_deadline(mut earliest: Optional[UInt64], candidate: Optional[UInt64]):
    """Fold `candidate` into `earliest` (None never wins)."""
    if not candidate:
        return
    if not earliest or candidate.value() < earliest.value():
        earliest = Optional[UInt64](candidate.value())


def _apply_m3c_defaults(mut params: TransportParams):
    """Set flow-control / stream-limit defaults if not already set, and
    clamp active_connection_id_limit to the value CidManager enforces."""
    params.active_connection_id_limit = clamp_local_active_limit(
        params.active_connection_id_limit
    )
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
