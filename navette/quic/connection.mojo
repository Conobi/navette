# src/quic/connection.mojo
#
# QuicConnection — sans-I/O QUIC state machine.
#
# Orchestrates packet protection, packet number spaces, loss recovery,
# crypto streams, and the TLS handshake via FFI into librustls_mojo.
#
# Usage:
#   var conn = QuicConnection.client(lib, cfg, "example.com", tp, now)
#   var datagrams = List[List[UInt8]](capacity=1)
#   _ = conn.send(now, datagrams)        # Initial with ClientHello
#   conn.recv(response_bytes, now)       # Feed server reply
#   var ev = conn.poll()                 # HANDSHAKE_COMPLETE, etc.

from std.collections import Dict, Optional
from std.ffi import external_call
from std.memory import Pointer, UnsafePointer
from std.collections import Span
from std.utils import Variant
from navette.util.owned_alloc import Owned
from navette.quic.event import (
    QuicEvent, QuicEventPayload,
    ConnectionClosedPayload, StreamResetPayload, StreamStoppedPayload,
)

from navette.tls.lib import SharedLibrary, RustlsLibrary
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.tls.early_data_store import (
    InMemoryEarlyDataStore, ReplayDecision,
)
from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_encode_raw, varint_decode, varint_len
from navette.quic.cid_buf import CidBuf
from navette.quic.error import QuicTransportError, NO_ERROR, PROTOCOL_VIOLATION, APPLICATION_ERROR
from navette.quic.profile import AcceptProfile, PROFILE_ACCEPT, monotonic_us, ProfileState
from navette.quic.zero_rtt import (
    ZeroRttState, ZERO_RTT_BUFFER_MAX_PKTS, ZERO_RTT_BUFFER_MAX_BYTES,
    invoke_replay_authenticator_ffi, drive_replay_check_for_test,
)
from navette.quic.packet_builder import (
    SentStreamFrame,
    PacketPlan,
    SSF_STREAM, SSF_RESET_STREAM, SSF_STOP_SENDING, SSF_MAX_DATA,
    SSF_MAX_STREAM_DATA, SSF_MAX_STREAMS_BIDI, SSF_MAX_STREAMS_UNI,
    SSF_NEW_CID, SSF_RETIRE_CID,
    AEAD_TAG_LEN, MAX_PN_LEN, MIN_PLAINTEXT_LEN, MAX_DATAGRAM_SIZE,
    MAX_CLOSE_REASON_BYTES, ANTI_AMP_HEADER_FUDGE,
    datagram_budget, amp_allowance, header_len,
    build_packet, seal_packet,
)
from navette.quic.frame import (
    Frame,
    FrameCursor,
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
from navette.quic.path import PathValidator, PathKey, PathState
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
from navette.quic.recovery import Recovery, K_GRANULARITY, K_PACKET_THRESHOLD
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



# ── TLS alert -> guard-tag mapping ───────────────────────────────────


def _create_server_tls_conn(
    lib: SharedLibrary,
    config_handle: Int32,
    tp_bytes: List[UInt8],
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
    tp_bytes: List[UInt8],
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
    var spaces: InlineArray[PacketNumberSpace, 3]
    var crypto_streams: InlineArray[CryptoStream, 3]
    var recovery: Recovery
    var protect: PacketProtect
    var conn_handle: Int32
    var _lib: SharedLibrary
    var local_params: TransportParams
    var peer_params: Optional[TransportParams]
    var local_cid: CidBuf
    var peer_cid: CidBuf
    var initial_dcid: CidBuf
    var bytes_received: UInt64
    var bytes_sent: UInt64
    var events: List[QuicEvent]
    # `poll()` pops from `events[_events_head]`; both reset once drained.
    var _events_head: Int
    var close: CloseState
    var idle_timer: UInt64
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
    var pending_outbound_datagrams: List[List[UInt8]]
    var _outbound_dg_head: Int
    # One-shot guard for the initial NEW_CONNECTION_ID burst (RFC 9000
    # §5.1.1): on the first 1-RTT _build_frames_for_space call after the
    # connection becomes CONN_ESTABLISHED, fill `cid_mgr.local_cids` up
    # to `peer_active_limit`. Subsequent flushes drain
    # `pending_new_cid_entries` normally without re-issuing.
    var initial_cids_emitted: Bool
    # Maps Application-space packet number -> list of stream-layer frames
    # sent in that packet, for ACK/loss processing.
    var app_frames_sent: Dict[Int, List[SentStreamFrame]]
    var pkt_buf: List[UInt8]
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

    # Pre-allocated scratch buffers reused across send()/loss calls to
    # avoid per-call heap allocations; .clear()'d before use.
    var _scratch_lost_pns: List[Int]
    var _scratch_frames: List[Frame]
    var _scratch_sent_records: List[SentStreamFrame]
    var _scratch_payload: List[UInt8]
    var _scratch_datagram: List[UInt8]
    var _scratch_plans: List[PacketPlan]
    var _scratch_writer_buf: List[UInt8]

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
        self.spaces = [
            PacketNumberSpace(EncryptionLevel.initial()),
            PacketNumberSpace(EncryptionLevel.handshake()),
            PacketNumberSpace(EncryptionLevel.application()),
        ]
        self.crypto_streams = [CryptoStream(), CryptoStream(), CryptoStream()]
        self.recovery = Recovery()
        self.protect = PacketProtect(lib)
        self.conn_handle = conn_handle
        self._lib = SharedLibrary(copy=lib)
        self.local_params = TransportParams(copy=local_params)
        self.peer_params = None
        self.local_cid = CidBuf(copy=local_cid)
        self.peer_cid = CidBuf(copy=peer_cid)
        self.initial_dcid = CidBuf(copy=initial_dcid)
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
            buffer=List[List[UInt8]](),
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
        self._scratch_lost_pns = List[Int](capacity=64)
        self._scratch_frames = List[Frame](capacity=8)
        self._scratch_sent_records = List[SentStreamFrame](capacity=8)
        self._scratch_payload = List[UInt8](capacity=6144)
        self._scratch_datagram = List[UInt8](capacity=MAX_DATAGRAM_SIZE)
        self._scratch_plans = List[PacketPlan](capacity=3)
        self._scratch_writer_buf = List[UInt8](capacity=256)
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
            initial_local_cid=List[UInt8](local_cid.as_span()),
            initial_remote_cid=List[UInt8](peer_cid.as_span()),
            local_active_limit=UInt64(2),
            peer_active_limit=UInt64(2),
        )
        self.path = PathState(
            validator=PathValidator(),
            pending_responses=List[List[UInt8]](),
            peer_addr=PathKey.zero(),
            current_recv_addr=PathKey.zero(),
        )
        self.pending_outbound_datagrams = List[List[UInt8]]()
        self._outbound_dg_head = 0
        self.initial_cids_emitted = False
        self.app_frames_sent = Dict[Int, List[SentStreamFrame]](capacity=128)
        self.pkt_buf = List[UInt8](capacity=1350)

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
        params_copy.initial_scid = List[UInt8](copy=local_cid)
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
        orig_dcid: Span[UInt8, _],
        client_dcid: Span[UInt8, _],
        now: UInt64,
        profile_ptr: Optional[Pointer[AcceptProfile, MutUntrackedOrigin]] = None,
    ) raises -> QuicConnection:
        """Create a QUIC server connection."""
        # RFC 9000 caps CIDs at 20 bytes. `CidBuf.from_span` aborts the
        # whole process on an over-length span, so an unvalidated caller
        # (or a wire-derived DCID that skipped `extract_dcid`'s clamp)
        # must be rejected here via `raise` instead of reaching that
        # abort — a remote DoS otherwise.
        if len(orig_dcid) > 20:
            raise "QuicConnection.server: orig_dcid exceeds 20 bytes"
        if len(client_dcid) > 20:
            raise "QuicConnection.server: client_dcid exceeds 20 bytes"
        var config_handle = config.handle()
        var profile_arrival_us = monotonic_us()
        var local_cid = _generate_random_cid()
        var tp_writer = ByteWriter()
        var params_copy = TransportParams(copy=local_params)
        params_copy.initial_scid = List[UInt8](copy=local_cid)
        _apply_m3c_defaults(params_copy)
        var orig_dcid_list = List[UInt8](capacity=len(orig_dcid))
        for i in range(len(orig_dcid)):
            orig_dcid_list.append(orig_dcid[i])
        params_copy.original_dcid = orig_dcid_list^
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
        conn.zrtt.enabled = (config.max_early_data() != UInt32(0))
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

    def recv(mut self, datagram: Span[UInt8, _], now: UInt64,
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
        var t_iter = UInt64(0)
        var ph_hdr = UInt64(0)
        var ph_hp = UInt64(0)
        var ph_ae = UInt64(0)
        var ph_fp = UInt64(0)
        var ph_sm = UInt64(0)
        self.bytes_received += UInt64(buf_len)
        if (self.state & (CONN_DRAINING | CONN_CLOSED)) != 0:
            return
        var closing = (self.state & CONN_CLOSING) != 0
        if closing:
            if now >= self.close.last_sent + self._pto_interval():
                self.close.owed = True
        else:
            self.idle_timer = now
        var lowest_recv_space = 3
        var offset = 0
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
            if header.is_long_header and len(header.scid) > 0:
                if header.packet_type == PacketType.initial():
                    self.peer_cid = CidBuf(copy=header.scid)
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
            var decrypt_ok = True
            try:
                var result = self._decrypt_and_dispatch_packet(
                    header, remaining_ptr, pkt_len, space_idx,
                    key_slot, closing, now, ecn_mark,
                )
                ph_hp = result[1]
                ph_ae = result[2]
                ph_fp = result[3]
                if not closing and result[0] < lowest_recv_space:
                    lowest_recv_space = result[0]
            except:
                if (self.state & (CONN_CLOSING | CONN_DRAINING | CONN_CLOSED)) != 0:
                    return
                decrypt_ok = False
            if not decrypt_ok:
                break
            if not closing:
                ph_sm = self.prof.stamp()
                self._drive_handshake(now)
                self._drain_zero_rtt_buffer(now, ecn_mark)
                ph_sm = self.prof.elapsed(ph_sm)
            self.prof.end_iter(t_iter, ph_hp, ph_ae, ph_hdr, ph_fp, ph_sm)
            offset += pkt_len
        self._retransmit_crypto_if_needed(lowest_recv_space, closing)

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
        var auth_buf = InlineArray[UInt8, 32](fill=UInt8(0))
        var auth_len = UInt(0)
        var rc = self._invoke_replay_authenticator_ffi(auth_buf, auth_len)
        if rc != Int32(0):
            self.zrtt.replay_decision = UInt8(2)
            self.prof.record_replay_reject_no_authenticator()
            return
        if self.zrtt.early_data_store_ptr is None:
            self.zrtt.replay_decision = UInt8(2)
            self.prof.record_replay_reject_no_authenticator()
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
            self.prof.record_replay_reject_no_authenticator()
        elif decision.is_accept():
            self.zrtt.replay_decision = UInt8(1)
            self.prof.record_replay_accept()
        elif decision.is_duplicate():
            self.zrtt.replay_decision = UInt8(2)
            self.prof.record_replay_reject_duplicate()
        elif decision.is_per_key_quota():
            self.zrtt.replay_decision = UInt8(2)
            self.prof.record_replay_reject_per_key_quota()
        else:
            self.zrtt.replay_decision = UInt8(2)
            self.prof.record_replay_reject_global_ceiling()

    def _parse_and_dispatch_frames(
        mut self,
        pkt_ptr: Pointer[mut=True, T=UInt8, origin=_],
        header_len: Int,
        plaintext_len: Int,
        space_idx: Int,
        closing: Bool,
        now: UInt64,
    ) raises -> Bool:
        """Parse frames via FrameCursor and dispatch each. Returns ack_eliciting."""
        var cursor = FrameCursor(
            Span(unsafe_ptr=pkt_ptr.unsafe_offset(header_len), length=plaintext_len)
        )
        var parse_failed = False
        var ack_eliciting = False
        self._current_space_idx = space_idx
        while True:
            var maybe_frame = Optional[Frame]()
            try:
                maybe_frame = cursor.next()
            except:
                parse_failed = True
                break
            if not maybe_frame:
                break
            var frame = maybe_frame.take()
            if closing and not frame.is_connection_close():
                continue
            if frame.is_ack_eliciting():
                ack_eliciting = True
            self._dispatch_frame(frame^, space_idx, now)
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

        Returns (pn_space_idx, hp_us, aead_us, frame_parse_us).
        Raises on decrypt failure or after close_transport.
        """
        var ph_hp_us = self.prof.stamp()
        var hp_result = self.protect.unprotect_header_ptr(
            key_slot, pkt_ptr, pkt_len, header.pn_offset
        )
        ph_hp_us = self.prof.elapsed(ph_hp_us)
        var first_byte = hp_result[0]
        var pn_length = hp_result[1]

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

        var header_len = header.pn_offset + pn_length
        var ph_aead_us = self.prof.stamp()
        var plaintext_len = self.protect.decrypt_payload_in_place(
            key_slot, full_pn, header_len, pkt_ptr, pkt_len
        )
        ph_aead_us = self.prof.elapsed(ph_aead_us)

        if self.is_server and space_idx == 1 and (self.state & CONN_ADDR_VALIDATED) == 0:
            self.state = self.state | CONN_ADDR_VALIDATED

        var ph_frame_parse_us = self.prof.stamp()
        var ack_eliciting = self._parse_and_dispatch_frames(
            pkt_ptr, header_len, plaintext_len, space_idx, closing, now,
        )
        ph_frame_parse_us = self.prof.elapsed(ph_frame_parse_us)

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
                for fi in range(len(entry.value.frames)):
                    if entry.value.frames[fi].is_crypto():
                        ref cf = entry.value.frames[fi].as_crypto()
                        self.crypto_streams[s].requeue(
                            cf.offset, Span(cf.data)
                        )

    # ── Stream frame handlers ────────────────────────────────────────

    def _handle_stream_frame(mut self, ref stream_frame: StreamFrame) raises:
        """Process an incoming STREAM frame (RFC 9000 §19.8)."""
        var stream_id = stream_frame.stream_id
        var offset = stream_frame.offset
        var data_len = UInt64(len(stream_frame.data))
        var fin = stream_frame.fin
        var key = Int(stream_id)
        self._ensure_peer_stream_exists(key, stream_id)
        var p = self.stream_map.stream_ptr(key)
        if not p[].is_bidi and p[].is_local:
            raise "STREAM_STATE_ERROR: incoming STREAM frame on local uni stream"
        if not p[].recv_state:
            raise "STREAM_STATE_ERROR: no recv state"
        var rs = p[].recv_state.value()
        if rs != RecvState.RECV and rs != RecvState.SIZE_KNOWN:
            return
        if not p[].fc_recv:
            raise "internal: missing fc_recv"
        if stream_offset_exceeds_fc(offset, data_len, p[].fc_recv.value().limit):
            self.close_transport(UInt64(0x03), String(GUARD_TAG_STREAM_LARGE_OFFSET), monotonic_us())
            return
        if not p[].recv_buf:
            raise "internal: missing recv_buf"
        var new_bytes = p[].recv_buf.value().write(
            offset, Span(stream_frame.data), fin, p[].fin_offset
        )
        if offset + data_len > p[].recv_highest_offset:
            p[].recv_highest_offset = offset + data_len
        if not self.stream_map.conn_fc_recv.check_limit(new_bytes):
            raise "FLOW_CONTROL_ERROR: connection FC exceeded"
        p[].fc_recv.value().add_received(new_bytes)
        self.stream_map.conn_fc_recv.add_received(new_bytes)
        if p[].recv_buf.value().has_readable():
            self.events.append(QuicEvent.stream_readable(stream_id))
        if fin:
            if rs == RecvState.RECV:
                p[].recv_state = Optional[RecvState](RecvState.SIZE_KNOWN)
                rs = RecvState.SIZE_KNOWN
            if rs == RecvState.SIZE_KNOWN:
                if p[].recv_buf.value().is_complete(p[].fin_offset):
                    p[].recv_state = Optional[RecvState](RecvState.DATA_RECVD)

    def _ensure_peer_stream_exists(mut self, key: Int, stream_id: UInt64) raises:
        """Create a peer-initiated stream if it doesn't exist yet."""
        if key in self.stream_map.streams:
            return
        if stream_is_local(stream_id, self.is_server):
            raise "PROTOCOL_VIOLATION: frame for unknown locally-initiated stream"
        var new_ids = self.stream_map.get_or_create_peer_stream(stream_id)
        var is_zr = (self._current_space_idx == ZERO_RTT_SPACE_IDX)
        for i in range(len(new_ids)):
            self.events.append(QuicEvent.stream_opened(new_ids[i]))
            var nkey = Int(new_ids[i])
            if nkey in self.stream_map.streams:
                self.stream_map.streams[nkey][].is_zero_rtt = is_zr

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
            var v = _f15_verdict.take()
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

        var p = self.stream_map.stream_ptr(key)
        if not p[].recv_state:
            raise "STREAM_STATE_ERROR: RESET on non-recv stream"

        # Validate final_size invariants.
        if final_size < p[].recv_highest_offset:
            raise "FINAL_SIZE_ERROR: final_size < received"
        if p[].fin_offset:
            if final_size != p[].fin_offset.value():
                raise "FINAL_SIZE_ERROR: final_size differs from FIN"

        if p[].fc_recv:
            if final_size > p[].fc_recv.value().limit:
                raise "FLOW_CONTROL_ERROR: RESET final_size exceeds stream limit"

        var rs = p[].recv_state.value()
        var was_complete = (rs == RecvState.DATA_RECVD or rs == RecvState.DATA_READ)

        # Account phantom bytes at connection level (bytes the peer implicitly
        # "sent" by claiming final_size without delivering them).
        var phantom = final_size - p[].recv_highest_offset
        if phantom > 0:
            if not self.stream_map.conn_fc_recv.check_limit(phantom):
                raise "FLOW_CONTROL_ERROR: conn FC exceeded on phantom bytes"
            self.stream_map.conn_fc_recv.add_received(phantom)
            self.stream_map.conn_fc_recv.add_consumed(phantom)

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
        )
        var _f16_verdict = predicate_f16_stop_sending_local_not_created(_f16_ctx)
        if _f16_verdict:
            var v = _f16_verdict.take()
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

        var p = self.stream_map.stream_ptr(key)
        if not p[].send_state:
            raise "STREAM_STATE_ERROR: STOP_SENDING targets non-send side"

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
            ref sb = p[].send_buf.value()
            if sb.fin_offset:
                final_size = sb.fin_offset.value()
            else:
                final_size = sb.unsent_offset
        p[].reset_stream_final_size = final_size

        self.stream_map.remove_sendable(key)

        self.events.append(QuicEvent.stream_stopped(stream_id, error_code))
        self.stream_map.mark_reset(key)
        _ = self.stream_map.maybe_cleanup(key)

    # ── Path validation RX handlers ──────────────────────────────────

    def on_path_challenge_received(
        mut self, data: Span[UInt8, _], now: UInt64
    ):
        """Stash the 8-byte challenge to echo back as PATH_RESPONSE."""
        self.path.on_challenge_received(data)

    def on_path_response_received(
        mut self, data: Span[UInt8, _], var from_addr: PathKey, now: UInt64
    ) raises:
        """Validate a PATH_RESPONSE and, on match, swap the validated path.

        RFC 9000 §8.2: the 8-byte data MUST match a pending challenge AND
        the response MUST arrive from the address the challenge targeted.
        Non-matches are silently dropped (no error, no state change).

        On a successful match `path.validator.on_response` removes the
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
        var maybe = self.path.validator.on_response(
            data, PathKey(copy=from_addr), now
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
        self.path.peer_addr = from_addr^

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
        """Drain pending PATH_RESPONSE frames."""
        return self.path.emit_response_frames()

    def emit_path_challenge_frames(mut self, now: UInt64) raises -> List[Frame]:
        """Build PATH_CHALLENGE frames for every pending challenge."""
        return self.path.emit_challenge_frames()

    def start_path_challenge(
        mut self, var target: PathKey, now: UInt64
    ) raises:
        """Begin path validation for `target`."""
        self.path.begin_challenge(target^, now)

    def has_pending_path_challenge(self, target: PathKey) -> Bool:
        """True iff a challenge for `target` is already pending."""
        return self.path.has_pending_challenge(target)

    def set_current_recv_addr(mut self, var addr: PathKey):
        """Stamp the per-receive source-address cursor."""
        self.path.stamp_recv_addr(addr^)

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
        if not (from_addr == self.path.peer_addr):
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
                var probe = PathKey(copy=from_addr)
                if not self.has_pending_path_challenge(probe):
                    self.start_path_challenge(probe^, now)

        # 2. Per-path anti-amp credit. record_received_bytes is a no-op
        # if `from_addr` has no pending challenge (i.e. it IS the
        # validated path); the validated path is not anti-amp constrained.
        self.path.validator.record_received_bytes(from_addr, datagram_len)

    def bootstrap_peer_addr(mut self, var addr: PathKey):
        """Seed peer_addr to the first observed source address."""
        self.path.seed_peer_addr(addr^)

    def can_send_to(self, target: PathKey, n_bytes: Int) -> Bool:
        """Anti-amp gate for outbound traffic to `target`."""
        return self.path.can_send(target, n_bytes)

    def record_send_to(mut self, target: PathKey, n_bytes: Int):
        """Credit `n_bytes` to the per-path bytes_sent counter for `target`."""
        self.path.record_send(target, n_bytes)

    # ── Frame dispatch ───────────────────────────────────────────────

    def _dispatch_frame(
        mut self, var frame: Frame, space_idx: Int, now: UInt64
    ) raises:
        """Route a parsed frame to its per-type handler."""
        var tid = frame.type_id
        if self._check_epoch_guards(tid, space_idx, now):
            return
        if tid == FRAME_PADDING or tid == FRAME_PING:
            return
        if tid == FRAME_ACK or tid == FRAME_ACK_ECN:
            self._handle_ack(frame.as_ack(), space_idx, now)
            return
        if tid == FRAME_CRYPTO:
            ref cf = frame.as_crypto()
            self.crypto_streams[space_idx].receive(cf.offset, Span(cf.data))
            return
        if tid == FRAME_CONNECTION_CLOSE_TRANSPORT or tid == FRAME_CONNECTION_CLOSE_APP:
            self._on_connection_close(frame, now)
            return
        if tid == FRAME_HANDSHAKE_DONE:
            self._on_handshake_done(now); return
        if tid == FRAME_NEW_TOKEN:
            self._on_new_token(now); return
        if tid == FRAME_NEW_CONNECTION_ID:
            self._on_new_cid(frame, now); return
        if tid == FRAME_RETIRE_CONNECTION_ID:
            self.cid_mgr.on_retire_connection_id(frame.as_retire_connection_id()); return
        if tid >= FRAME_STREAM_BASE and tid <= FRAME_STREAM_BASE + UInt64(7):
            self._handle_stream_frame(frame.as_stream())
            return
        if tid == FRAME_RESET_STREAM:
            self._handle_reset_stream(frame.as_reset_stream())
            return
        if tid == FRAME_STOP_SENDING:
            self._handle_stop_sending(frame.as_stop_sending())
            return
        if tid == FRAME_MAX_DATA:
            self.stream_map.conn_fc_send.ensure_limit(frame.as_max_data())
            self.stream_map.conn_fc_send.blocked_at = UInt64(0)
            return
        if tid == FRAME_MAX_STREAM_DATA:
            self._on_max_stream_data(frame, now)
            return
        if tid == FRAME_MAX_STREAMS_BIDI:
            self._on_max_streams(frame, True, now)
            return
        if tid == FRAME_MAX_STREAMS_UNI:
            self._on_max_streams(frame, False, now)
            return
        if tid == FRAME_STREAMS_BLOCKED_BIDI or tid == FRAME_STREAMS_BLOCKED_UNI:
            self._on_streams_blocked(frame, now)
            return
        if tid == FRAME_DATA_BLOCKED or tid == FRAME_STREAM_DATA_BLOCKED:
            return
        if frame.is_path_challenge():
            self.on_path_challenge_received(Span(frame.as_path_data()), now)
            return
        if frame.is_path_response():
            var from_addr = PathKey(copy=self.path.current_recv_addr)
            self.on_path_response_received(Span(frame.as_path_data()), from_addr^, now)
            return
        if frame.is_datagram():
            self.events.append(QuicEvent.datagram_received(List[UInt8](copy=frame.as_datagram_payload())))
            return
        if is_unknown_frame_type(tid):
            self.close_transport(UInt64(0x07), String(GUARD_TAG_UNKNOWN_FRAME), now)
            return

    # ── Per-type frame handlers ─────────────────────────────────────

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
        mut self, ref frame: Frame, now: UInt64
    ) raises:
        """Handle CONNECTION_CLOSE: enter draining state, emit event."""
        ref cc = frame.as_connection_close()
        self.state = self.state | CONN_DRAINING
        self.close.drain_timer = now + 3 * self._pto_interval()
        var reason = String("")
        for i in range(len(cc.reason)):
            reason += chr(Int(cc.reason[i]))
        self.events.append(QuicEvent.connection_closed(cc.error_code, reason))

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
        self.cid_mgr.on_new_connection_id(
            nc.sequence,
            nc.retire_prior_to,
            List[UInt8](nc.cid.as_span()),
            List[UInt8](copy=nc.stateless_reset_token),
        )

    def _on_max_stream_data(
        mut self, ref frame: Frame, now: UInt64
    ) raises:
        """Handle MAX_STREAM_DATA: validate, update FC, re-queue sendable."""
        ref msd = frame.as_max_stream_data()
        var key = Int(msd.stream_id)
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
            var _v_msd = _verdict_msd.take()
            self.close_transport(_v_msd.error_code, _v_msd.tag, now)
            return
        var p = self.stream_map.stream_ptr(key)
        if p[].fc_send:
            var old_limit = p[].fc_send.value().limit
            p[].fc_send.value().ensure_limit(msd.maximum)
            var grew = p[].fc_send.value().limit > old_limit
            if grew:
                p[].fc_send.value().blocked_at = UInt64(0)
            var _has_pending = False
            if p[].send_buf:
                _has_pending = p[].send_buf.value().has_pending()
            if grew:
                self.events.append(QuicEvent.stream_writable(msd.stream_id))
                if _has_pending:
                    self.stream_map.add_sendable(key)

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

    # ── ACK handling ─────────────────────────────────────────────────

    def _handle_ack(
        mut self, ref ack_frame: AckFrame, space_idx: Int, now: UInt64
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

        self._update_rtt_from_ack(acked, ack_frame, now)

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
        if self.ecn.state != ECN_STATE_DISABLED:
            self._process_ecn_feedback(space_idx, ack_frame, ect0_acked_count, now)

    def _update_rtt_from_ack(
        mut self, acked: List[SentPacket], ref ack_frame: AckFrame, now: UInt64,
    ):
        """Update RTT estimate from the largest newly acked packet."""
        var largest_acked_pn = ack_frame.largest_ack
        for i in range(len(acked)):
            if acked[i].pn == largest_acked_pn:
                if now >= acked[i].time_sent:
                    var rtt_sample = now - acked[i].time_sent
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
        for i in range(len(lost_pns)):
            var pn_key = lost_pns[i]
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
        for i in range(len(lost_pns)):
            var pn_key = lost_pns[i]
            var maybe_lost = self.spaces[space_idx].forget_sent(pn_key)
            if maybe_lost:
                var lost_pkt = maybe_lost.take()
                if lost_pkt.ecn_mark == ECN_ECT0:
                    if self.spaces[space_idx].ect0_in_flight > UInt64(0):
                        self.spaces[space_idx].ect0_in_flight -= UInt64(1)
                self.recovery.on_packet_lost(lost_pkt.size, lost_pkt.in_flight)
                for f in range(len(lost_pkt.frames)):
                    if lost_pkt.frames[f].is_crypto():
                        ref cf = lost_pkt.frames[f].as_crypto()
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
        """Drain crypto data and feed/read from TLS state machine."""
        if self.conn_handle < 0:
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
        for level in range(3):
            if not self.crypto_streams[level].has_pending():
                continue
            var crypto_data = self.crypto_streams[level].drain()
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
                var tls_data = List[UInt8](capacity=written)
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
        """Called when TLS reports handshake is complete."""
        if (self.state & CONN_ESTABLISHED) != 0:
            return
        if self.is_server:
            self.prof.record_hs_complete(now)
        self._record_handshake_profile_stats()
        self.state = self.state & ~CONN_HANDSHAKING
        self._apply_peer_transport_params(now)
        # Seed Application-space PN skip RNG from local_cid.
        var pn_skip_seed = UInt64(0)
        var local_cid_span = self.local_cid.as_span()
        for i in range(min(Int(8), Int(len(local_cid_span)))):
            pn_skip_seed = (pn_skip_seed << 8) | UInt64(local_cid_span[i])
        if pn_skip_seed == 0:
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
        var tp_bytes = List[UInt8](capacity=tp_len)
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
        self.cid_mgr.peer_active_limit = peer.active_connection_id_limit
        self.cid_mgr.retire_queue_cap = Int(peer.active_connection_id_limit) * 8
        _ = self.cid_mgr.issue_new_cid()

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
        self.zrtt.buffer = List[List[UInt8]]()
        self.zrtt.buffer_bytes = 0

    def _zero_rtt_enabled(self) -> Bool:
        """True if 0-RTT is enabled by server config."""
        return self.zrtt.is_enabled()

    def _buffer_zero_rtt_or_drop(mut self, packet: Span[UInt8, _]) -> Bool:
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
        self.zrtt.buffer = List[List[UInt8]]()
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
                    self.prof.record_zero_rtt_drain_dropped()
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

    def send(mut self, now: UInt64, mut out: List[List[UInt8]]) raises -> Int:
        """Build at most one datagram into `out`; returns 0 or 1.

        `out` is cleared (length reset, capacity kept) and reused across
        calls so the caller amortizes the outer List allocation instead of
        getting a fresh one back on every call.
        """
        out.clear()
        self._check_timers(now)
        if (self.state & (CONN_DRAINING | CONN_CLOSED)) != 0:
            return 0
        var closing = (self.state & CONN_CLOSING) != 0
        if closing and not self.close.owed:
            return 0
        var budget = self._datagram_budget()
        if self.is_server and not self._addr_validated():
            var allowance = self._amp_allowance()
            if allowance < budget:
                budget = allowance
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
            return 0
        var result = self._commit_plans_to_datagram(
            plans, budget, closing, all_close_committed, now,
        )
        self._scratch_plans = plans^
        for i in range(len(result)):
            var dg = List[UInt8]()
            swap(dg, result[i])
            out.append(dg^)
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
        var stream_payload = List[UInt8]()
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
            var may_bundle = (not deferred) and self._space_has_other_sendable(space_idx)
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
        var stream_payload: List[UInt8],
        ack_committed: Bool,
        has_stream_data: Bool,
    ) raises -> PacketPlan:
        """Serialize control frames and assemble a PacketPlan."""
        var has_control = False
        for fi in range(len(frames)):
            if not frames[fi].is_crypto():
                has_control = True
                break
        if has_control:
            var wbuf = List[UInt8]()
            swap(wbuf, self._scratch_writer_buf)
            wbuf.clear()
            var writer = ByteWriter()
            swap(writer.buf, wbuf)
            for fi in range(len(frames)):
                if not frames[fi].is_crypto():
                    serialize_frame(frames[fi], writer)
            stream_payload.extend(Span(writer.buf))
            swap(self._scratch_writer_buf, writer.buf)
        return PacketPlan(
            space_idx, frames^, sent_records^, stream_payload^,
            ack_committed, has_stream_data,
        )

    def _commit_plans_to_datagram(
        mut self,
        mut plans: List[PacketPlan],
        budget: Int,
        closing: Bool,
        all_close_committed: Bool,
        now: UInt64,
    ) raises -> List[List[UInt8]]:
        """Allocate PNs, build+encrypt packets, coalesce into a datagram."""
        var pad_to = 0
        for i in range(len(plans)):
            var s = plans[i].space_idx
            if self.is_server:
                if s == 0 and _has_ack_eliciting(plans[i].frames):
                    pad_to = MAX_DATAGRAM_SIZE
            elif (s == 0 or s == 1) and (self.state & CONN_ESTABLISHED) == 0:
                pad_to = MAX_DATAGRAM_SIZE
        debug_assert(pad_to <= budget, "padding target exceeds the datagram budget")
        var datagram = List[UInt8]()
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
            for fi in range(len(plans[i].frames)):
                if plans[i].frames[fi].is_crypto():
                    crypto_frames.append(Frame(copy=plans[i].frames[fi]))
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
        var datagrams = List[List[UInt8]](capacity=1)
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
        return header_len(space_idx, len(self.local_cid), len(self.peer_cid))

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
            cc.reason = List[UInt8](copy=self.close.pending.value().reason)
            return Frame.connection_close(cc)
        return Frame.connection_close(self.close.pending.value())

    def _space_has_other_sendable(self, space_idx: Int) -> Bool:
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
        if len(self.path.pending_responses) > 0 or len(self.path.validator.pending) > 0:
            return True
        if self._outbound_dg_head < len(self.pending_outbound_datagrams):
            return True
        return False

    # ── Frame building ───────────────────────────────────────────────

    def _build_frames_for_space(
        mut self, space_idx: Int, now: UInt64,
        mut frames: List[Frame],
        mut sent_records: List[SentStreamFrame],
        mut stream_payload: List[UInt8],
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

        # HANDSHAKE_DONE (server, Application space, once).
        if self.send_handshake_done and space_idx == 2 and self.is_server and used + 1 <= budget:
            frames.append(Frame.handshake_done())
            self.send_handshake_done = False
            used += 1

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

            self._build_app_frames(frames, sent_records, stream_payload, budget, used)
            self._build_path_and_datagram_frames(frames, used, budget, now)

    def _max_app_payload(self) -> Int:
        """Largest plaintext a 1-RTT packet can carry in an empty datagram."""
        return MAX_DATAGRAM_SIZE - self._header_len(2) - AEAD_TAG_LEN

    def _emit_one_stream_frame(
        mut self,
        sid: Int,
        p: UnsafePointer[Stream, MutUntrackedOrigin],
        ss: SendState,
        limit: Int,
        mut sent_records: List[SentStreamFrame],
        mut stream_payload: List[UInt8],
        budget: Int,
        used: Int,
    ) raises -> Optional[Tuple[Int, UInt64]]:
        """Emit a single STREAM frame for one stream. Returns (new_used, conn_delta) or None."""
        var meta = p[].send_buf.value().prepare_frame(limit)
        if not meta:
            return None
        var frame_meta = meta.value()
        var frame_offset = frame_meta[0]
        var chunk_size = frame_meta[1]
        var frame_fin = frame_meta[2]
        var frame_len = UInt64(chunk_size)
        var data_view = p[].send_buf.value().data_span(frame_offset, chunk_size)
        var wl = write_stream_frame_direct(
            stream_payload, budget=budget - used,
            stream_id=p[].id, offset=frame_offset, data=data_view, fin=frame_fin,
        )
        debug_assert(wl > 0 and used + wl <= budget, "STREAM frame exceeds its charge")
        var new_used = used + wl
        var conn_delta = UInt64(0)
        var prev_end = frame_offset + frame_len
        if prev_end > p[].fc_send.value().received:
            conn_delta = prev_end - p[].fc_send.value().received
            p[].fc_send.value().add_received(conn_delta)
        if ss == SendState.READY:
            p[].send_state = Optional[SendState](SendState.SEND)
        if frame_fin and p[].send_buf.value().fin_offset:
            p[].send_state = Optional[SendState](SendState.DATA_SENT)
        var rec = SentStreamFrame()
        rec.kind = SSF_STREAM
        rec.stream_id = p[].id
        rec.offset = frame_offset
        rec.length = frame_len
        rec.fin = frame_fin
        sent_records.append(rec^)
        return Tuple[Int, UInt64](new_used, conn_delta)

    def _build_path_and_datagram_frames(
        mut self, mut frames: List[Frame], mut used: Int, budget: Int, now: UInt64,
    ) raises:
        """Append PATH_RESPONSE, PATH_CHALLENGE, and DATAGRAM frames."""
        var n_resp = len(self.path.pending_responses)
        if n_resp > 0 and used + 9 * n_resp <= budget:
            var path_responses = self.emit_path_response_frames()
            for i in range(len(path_responses)):
                ref pr = path_responses[i]
                frames.append(pr.copy())
            used += 9 * n_resp
        var n_chal = len(self.path.validator.pending)
        if n_chal > 0 and used + 9 * n_chal <= budget:
            var path_challenges = self.emit_path_challenge_frames(now)
            for i in range(len(path_challenges)):
                ref pc = path_challenges[i]
                frames.append(pc.copy())
            used += 9 * n_chal
        while self._outbound_dg_head < len(self.pending_outbound_datagrams):
            var dl = len(self.pending_outbound_datagrams[self._outbound_dg_head])
            var wl = 1 + varint_len(UInt64(dl)) + dl
            if used + wl > budget:
                if wl > self._max_app_payload():
                    raise "DATAGRAM frame of " + String(wl) + " bytes can never fit a packet"
                break
            var head = List[UInt8](copy=self.pending_outbound_datagrams[self._outbound_dg_head])
            self._outbound_dg_head += 1
            frames.append(Frame.datagram_with_len(head^))
            used += wl
        if self._outbound_dg_head >= len(self.pending_outbound_datagrams):
            self.pending_outbound_datagrams = List[List[UInt8]]()
            self._outbound_dg_head = 0

    def _build_app_frames(
        mut self,
        mut frames: List[Frame],
        mut sent_records: List[SentStreamFrame],
        mut stream_payload: List[UInt8],
        budget: Int,
        mut used: Int,
    ) raises:
        """Append Application-space stream / FC / CID frames within budget."""
        self._emit_cid_and_fc_frames(frames, sent_records, budget, used)
        self._drain_max_stream_data_frames(frames, sent_records, budget, used)
        self._drain_reset_stream_frames(frames, sent_records, budget, used)
        self._drain_stop_sending_frames(frames, sent_records, budget, used)
        self._emit_stream_frames(sent_records, stream_payload, budget, used)
        self._emit_blocked_frames(frames, budget, used)

    def _emit_cid_and_fc_frames(
        mut self,
        mut frames: List[Frame],
        mut sent_records: List[SentStreamFrame],
        budget: Int,
        mut used: Int,
    ) raises:
        """Emit NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, MAX_DATA, MAX_STREAMS."""
        var pending_new = self.cid_mgr.pending_new_cid_entries()
        for i in range(len(pending_new)):
            var entry = CidEntry(copy=pending_new[i])
            var ncid = NewConnectionIdFrame()
            ncid.sequence = entry.sequence
            ncid.retire_prior_to = self.cid_mgr.local_retire_prior_to
            ncid.cid = CidBuf.from_span(Span(entry.cid))
            ncid.stateless_reset_token = List[UInt8](copy=entry.reset_token)
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
        for i in range(len(pending_retire)):
            var seq = pending_retire[i]
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

    def _drain_max_stream_data_frames(
        mut self,
        mut frames: List[Frame],
        mut sent_records: List[SentStreamFrame],
        budget: Int,
        mut used: Int,
    ) raises:
        """Drain MAX_STREAM_DATA control list with write-cursor compaction."""
        var write = 0
        var full = False
        for i in range(len(self.stream_map.control_max_stream_data)):
            var sid = self.stream_map.control_max_stream_data[i]
            if full:
                if write != i:
                    self.stream_map.control_max_stream_data[write] = sid
                write += 1
                continue
            if not self.stream_map.has_stream(sid):
                continue
            var p = self.stream_map.stream_ptr(sid)
            if not p[].needs_max_stream_data or not p[].fc_recv:
                continue
            var next_limit = p[].fc_recv.value().next_limit()
            var wl = 1 + varint_len(p[].id) + varint_len(next_limit)
            if used + wl > budget:
                if write != i:
                    self.stream_map.control_max_stream_data[write] = sid
                write += 1
                full = True
                continue
            var new_limit = p[].fc_recv.value().update_limit()
            p[].needs_max_stream_data = False
            var f = Frame.max_stream_data(MaxStreamDataFrame(p[].id, new_limit))
            used += f.wire_len()
            frames.append(f^)
            var rec = SentStreamFrame()
            rec.kind = SSF_MAX_STREAM_DATA
            rec.stream_id = p[].id
            sent_records.append(rec^)
        while len(self.stream_map.control_max_stream_data) > write:
            _ = self.stream_map.control_max_stream_data.pop()

    def _drain_reset_stream_frames(
        mut self,
        mut frames: List[Frame],
        mut sent_records: List[SentStreamFrame],
        budget: Int,
        mut used: Int,
    ) raises:
        """Drain RESET_STREAM control list with write-cursor compaction."""
        var write = 0
        var full = False
        for i in range(len(self.stream_map.control_reset)):
            var sid = self.stream_map.control_reset[i]
            if full:
                if write != i:
                    self.stream_map.control_reset[write] = sid
                write += 1
                continue
            if not self.stream_map.has_stream(sid):
                continue
            var p = self.stream_map.stream_ptr(sid)
            if not p[].needs_reset_stream:
                continue
            var rs_f = ResetStreamFrame(
                p[].id,
                p[].reset_stream_error,
                p[].reset_stream_final_size,
            )
            var f = Frame.reset_stream(rs_f)
            var wl = f.wire_len()
            if used + wl > budget:
                if write != i:
                    self.stream_map.control_reset[write] = sid
                write += 1
                full = True
                continue
            frames.append(f^)
            used += wl
            p[].needs_reset_stream = False
            var rec = SentStreamFrame()
            rec.kind = SSF_RESET_STREAM
            rec.stream_id = p[].id
            sent_records.append(rec^)
        while len(self.stream_map.control_reset) > write:
            _ = self.stream_map.control_reset.pop()

    def _drain_stop_sending_frames(
        mut self,
        mut frames: List[Frame],
        mut sent_records: List[SentStreamFrame],
        budget: Int,
        mut used: Int,
    ) raises:
        """Drain STOP_SENDING control list with write-cursor compaction."""
        var write = 0
        var full = False
        for i in range(len(self.stream_map.control_stop_sending)):
            var sid = self.stream_map.control_stop_sending[i]
            if full:
                if write != i:
                    self.stream_map.control_stop_sending[write] = sid
                write += 1
                continue
            if not self.stream_map.has_stream(sid):
                continue
            var p = self.stream_map.stream_ptr(sid)
            if not p[].needs_stop_sending:
                continue
            var ss_f = StopSendingFrame(p[].id, p[].stop_sending_error)
            var f = Frame.stop_sending(ss_f)
            var wl = f.wire_len()
            if used + wl > budget:
                if write != i:
                    self.stream_map.control_stop_sending[write] = sid
                write += 1
                full = True
                continue
            frames.append(f^)
            used += wl
            p[].needs_stop_sending = False
            var rec = SentStreamFrame()
            rec.kind = SSF_STOP_SENDING
            rec.stream_id = p[].id
            sent_records.append(rec^)
        while len(self.stream_map.control_stop_sending) > write:
            _ = self.stream_map.control_stop_sending.pop()

    def _emit_stream_frames(
        mut self,
        mut sent_records: List[SentStreamFrame],
        mut stream_payload: List[UInt8],
        budget: Int,
        mut used: Int,
    ) raises:
        """Emit STREAM frames from the sendable queue with round-robin fairness."""
        var max_bytes_per_frame = MAX_DATAGRAM_SIZE
        var initial_len = len(self.stream_map.sendable_queue)
        var popped = 0
        while popped < initial_len:
            var sid = self.stream_map.sendable_queue.popleft()
            popped += 1
            if sid not in self.stream_map.sendable_set:
                continue
            if sid not in self.stream_map.streams:
                self.stream_map.remove_sendable(sid)
                continue
            var conn_avail = self.stream_map.conn_fc_send.available()
            if conn_avail == 0:
                self.stream_map.sendable_queue.appendleft(sid)
                break
            var p = self.stream_map.stream_ptr(sid)
            if not p[].send_state or not p[].send_buf or not p[].fc_send:
                self.stream_map.remove_sendable(sid)
                continue
            var ss = p[].send_state.value()
            if ss != SendState.READY and ss != SendState.SEND:
                self.stream_map.remove_sendable(sid)
                continue
            var stream_avail = p[].fc_send.value().available()
            var fin_pending = (
                p[].send_buf.value().fin and not p[].send_buf.value().fin_offset
            )
            if stream_avail == 0 and not fin_pending:
                self.stream_map.sendable_queue.append(sid)
                continue
            var hdr_charge = (
                1 + varint_len(p[].id)
                + varint_len(p[].send_buf.value().unsent_offset) + 2
            )
            var room = budget - used - hdr_charge
            if room < 0:
                self.stream_map.sendable_queue.appendleft(sid)
                break
            var limit = Int(conn_avail)
            if Int(stream_avail) < limit:
                limit = Int(stream_avail)
            if max_bytes_per_frame < limit:
                limit = max_bytes_per_frame
            if room < limit:
                limit = room
            var emitted = self._emit_one_stream_frame(
                sid, p, ss, limit, sent_records, stream_payload, budget, used,
            )
            if not emitted:
                self.stream_map.remove_sendable(sid)
                continue
            used = emitted.value()[0]
            var conn_delta = emitted.value()[1]
            if conn_delta > 0:
                self.stream_map.conn_fc_send.add_received(conn_delta)
            if not p[].send_buf.value().has_pending():
                self.stream_map.remove_sendable(sid)
            else:
                self.stream_map.sendable_queue.append(sid)

    def _emit_blocked_frames(
        mut self,
        mut frames: List[Frame],
        budget: Int,
        mut used: Int,
    ) raises:
        """Emit DATA_BLOCKED, STREAM_DATA_BLOCKED, and STREAMS_BLOCKED frames."""
        var conn_limit = self.stream_map.conn_fc_send.limit
        if (self.stream_map.conn_fc_send.received >= conn_limit
                and self.stream_map.conn_fc_send.blocked_at != conn_limit):
            var wl = 1 + varint_len(conn_limit)
            if used + wl <= budget:
                frames.append(Frame.data_blocked(conn_limit))
                used += wl
                self.stream_map.conn_fc_send.blocked_at = conn_limit
        var blocked_ids = List[Int]()
        for key in self.stream_map.sendable_set.keys():
            blocked_ids.append(key)
        for i in range(len(blocked_ids)):
            var sid = blocked_ids[i]
            if not self.stream_map.has_stream(sid):
                continue
            var p = self.stream_map.stream_ptr(sid)
            if not p[].fc_send:
                continue
            var stream_limit = p[].fc_send.value().limit
            if (p[].fc_send.value().available() == UInt64(0)
                    and p[].fc_send.value().blocked_at != stream_limit
                    and stream_limit > UInt64(0)):
                var wl = 1 + varint_len(p[].id) + varint_len(stream_limit)
                if used + wl > budget:
                    continue
                frames.append(Frame.stream_data_blocked(StreamDataBlockedFrame(p[].id, stream_limit)))
                used += wl
                p[].fc_send.value().blocked_at = stream_limit
        if self.stream_map.needs_streams_blocked_bidi:
            var bidi_limit = self.stream_map.peer_max_streams_bidi
            var wl = 1 + varint_len(bidi_limit)
            if self.stream_map.streams_blocked_at_bidi != bidi_limit and used + wl <= budget:
                frames.append(
                    Frame.streams_blocked(StreamsBlockedFrame(bidi_limit, True))
                )
                used += wl
                self.stream_map.streams_blocked_at_bidi = bidi_limit
        if self.stream_map.needs_streams_blocked_uni:
            var uni_limit = self.stream_map.peer_max_streams_uni
            var wl = 1 + varint_len(uni_limit)
            if self.stream_map.streams_blocked_at_uni != uni_limit and used + wl <= budget:
                frames.append(
                    Frame.streams_blocked(StreamsBlockedFrame(uni_limit, False))
                )
                used += wl
                self.stream_map.streams_blocked_at_uni = uni_limit

    # ── Packet building ──────────────────────────────────────────────

    def _build_packet(
        mut self,
        space_idx: Int,
        pn: UInt64,
        pn_len: Int,
        payload: List[UInt8],
        padding: Int = 0,
    ) raises:
        """Delegate to packet_builder.build_packet."""
        build_packet(
            self.pkt_buf, self.protect,
            self.peer_cid.as_span(), self.local_cid.as_span(),
            space_idx, pn, pn_len, payload,
            self._header_len(space_idx), padding,
        )

    # ── Application-space frame ACK/loss handling ─────────────

    def _on_app_pkt_acked(mut self, pn: Int) raises:
        """Apply ACK side-effects for stream-layer frames in the acked packet."""
        if pn not in self.app_frames_sent:
            return
        var records = self.app_frames_sent.pop(pn)
        for i in range(len(records)):
            ref rec = records[i]
            if rec.kind == SSF_STREAM:
                var key = Int(rec.stream_id)
                if key not in self.stream_map.streams:
                    continue
                var p = self.stream_map.stream_ptr(key)
                if p[].send_buf:
                    p[].send_buf.value().on_ack(rec.offset, rec.length)
                    var fully = p[].send_buf.value().is_fully_acked()
                    if fully and p[].send_state:
                        var ss = p[].send_state.value()
                        if ss == SendState.DATA_SENT:
                            p[].send_state = Optional[SendState](SendState.DATA_RECVD)
                    _ = self.stream_map.maybe_cleanup(key)
            elif rec.kind == SSF_RESET_STREAM:
                var key = Int(rec.stream_id)
                if key not in self.stream_map.streams:
                    continue
                var p = self.stream_map.stream_ptr(key)
                if p[].send_state:
                    var ss = p[].send_state.value()
                    if ss == SendState.RESET_SENT:
                        p[].send_state = Optional[SendState](SendState.RESET_RECVD)
                _ = self.stream_map.maybe_cleanup(key)

    def _on_app_pkt_lost(mut self, pn: Int) raises:
        """Re-queue stream-layer frames for retransmission on packet loss."""
        if pn not in self.app_frames_sent:
            return
        var records = self.app_frames_sent.pop(pn)
        for i in range(len(records)):
            ref rec = records[i]
            if rec.kind == SSF_STREAM:
                var key = Int(rec.stream_id)
                if key not in self.stream_map.streams:
                    continue
                var p = self.stream_map.stream_ptr(key)
                if p[].send_buf:
                    p[].send_buf.value().on_loss(rec.offset, rec.length)
                    var has_pending = p[].send_buf.value().has_pending()
                    if has_pending:
                        self.stream_map.add_sendable(key)
            elif rec.kind == SSF_RESET_STREAM:
                var key = Int(rec.stream_id)
                if key in self.stream_map.streams:
                    var p = self.stream_map.stream_ptr(key)
                    p[].needs_reset_stream = True
                    self.stream_map.mark_reset(key)
            elif rec.kind == SSF_STOP_SENDING:
                var key = Int(rec.stream_id)
                if key in self.stream_map.streams:
                    var p = self.stream_map.stream_ptr(key)
                    p[].needs_stop_sending = True
                    self.stream_map.mark_stop_sending(key)
            elif rec.kind == SSF_MAX_DATA:
                self.stream_map.needs_max_data = True
            elif rec.kind == SSF_MAX_STREAM_DATA:
                var key = Int(rec.stream_id)
                if key in self.stream_map.streams:
                    var p = self.stream_map.stream_ptr(key)
                    p[].needs_max_stream_data = True
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
                # Re-queue the retirement if possible (respects cap).
                self.cid_mgr.requeue_retire(rec.cid_seq)

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

        Sources: per-space PTO and ACK deadlines (omitted while
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
            if wait and (earliest is None or wait.value() < earliest.value()) and self._space_has_other_sendable(2):
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
                    for fi in range(len(entry.value.frames)):
                        if entry.value.frames[fi].is_crypto():
                            ref cf = entry.value.frames[fi].as_crypto()
                            self.crypto_streams[s].requeue(
                                cf.offset, Span(cf.data)
                            )
            self.spaces[s].probe_pending = True
        self.recovery.pto_count += 1

    # ── Public API ───────────────────────────────────────────────────

    def poll(mut self) -> Optional[QuicEvent]:
        """Next pending event in append order; O(1) via a head index, the
        list is reset (not rebuilt) once drained."""
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
        return ev^

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
        var reason_bytes = List[UInt8]()
        var reason_str_bytes = reason.as_bytes()
        var n = len(reason_str_bytes)
        if n > MAX_CLOSE_REASON_BYTES:
            n = MAX_CLOSE_REASON_BYTES
        for i in range(n):
            reason_bytes.append(reason_str_bytes[i])
        var cc = ConnectionCloseFrame()
        cc.is_transport = not is_app
        cc.error_code = error_code
        cc.frame_type = UInt64(0)
        cc.reason = reason_bytes^
        self.close.pending = cc^

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
        var initial_span = self.initial_dcid.as_span()
        if len(dcid) == len(initial_span):
            var match_initial = True
            for i in range(len(dcid)):
                if dcid[i] != initial_span[i]:
                    match_initial = False
                    break
            if match_initial:
                return True
        var local_span = self.local_cid.as_span()
        if len(dcid) == len(local_span):
            var match_local = True
            for i in range(len(dcid)):
                if dcid[i] != local_span[i]:
                    match_local = False
                    break
            if match_local:
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
        mut self, stream_id: UInt64, data: Span[UInt8, _], fin: Bool
    ) raises:
        """Queue data for sending on a stream (and optionally mark FIN)."""
        var key = Int(stream_id)
        if key not in self.stream_map.streams:
            raise "unknown stream"
        var p = self.stream_map.stream_ptr(key)
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
        app_payload: List[UInt8],
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
        var combined = List[UInt8](capacity=hdr_len + payload_len)
        # H3 DATA frame type = 0x00.
        combined.append(0x00)
        # Varint-encode the payload length directly into the buffer.
        varint_encode_raw(combined, UInt64(payload_len))
        # Bulk-copy the application payload.
        combined.extend(Span(app_payload))
        self.send_stream_data(stream_id, Span(combined), fin)

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
        var p = self.stream_map.stream_ptr(key)
        if not p[].recv_buf or not p[].fc_recv:
            raise "STREAM_STATE_ERROR: no recv side"
        var result = p[].recv_buf.value().read(p[].fin_offset)
        var data = List[UInt8]()
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
        if key not in self.stream_map.streams:
            raise "unknown stream"
        var p = self.stream_map.stream_ptr(key)
        if not p[].send_state:
            raise "STREAM_STATE_ERROR: no send side"
        var ss = p[].send_state.value()
        if (ss == SendState.DATA_RECVD or ss == SendState.RESET_SENT
                or ss == SendState.RESET_RECVD):
            return
        var final_size: UInt64 = 0
        if p[].send_buf:
            ref sb = p[].send_buf.value()
            if sb.fin_offset:
                final_size = sb.fin_offset.value()
            else:
                final_size = sb.unsent_offset
        p[].send_state = Optional[SendState](SendState.RESET_SENT)
        p[].needs_reset_stream = True
        p[].reset_stream_error = error_code
        p[].reset_stream_final_size = final_size
        self.stream_map.remove_sendable(key)
        self.stream_map.mark_reset(key)

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
        var p = self.stream_map.stream_ptr(key)
        if not p[].recv_state:
            raise "STREAM_STATE_ERROR: no recv side"
        var rs = p[].recv_state.value()
        if (rs == RecvState.DATA_READ or rs == RecvState.RESET_READ
                or rs == RecvState.RESET_RECVD):
            return
        p[].recv_state = Optional[RecvState](RecvState.STOP_SENDING_SENT)
        p[].needs_stop_sending = True
        p[].stop_sending_error = error_code
        self.stream_map.mark_stop_sending(key)

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


def _generate_random_cid() raises -> List[UInt8]:
    """Generate a random 8-byte connection ID via getrandom(2)."""
    var buf_owned = Owned[UInt8](8)
    var buf = buf_owned.ptr()
    var rc = external_call["getrandom", Int](buf, UInt64(8), UInt32(0))
    if rc != 8:
        raise "getrandom failed"
    var cid = List[UInt8](capacity=8)
    for i in range(8):
        cid.append(buf[unsafe_offset=i])
    # Keep buf_owned alive across the post-FFI `buf[i]` copy loop above.
    _ = buf_owned
    return cid^


def _has_ack_eliciting(ref frames: List[Frame]) -> Bool:
    """Check if any frame in the list is ack-eliciting."""
    for i in range(len(frames)):
        if frames[i].is_ack_eliciting():
            return True
    return False


def _min_deadline(mut earliest: Optional[UInt64], candidate: Optional[UInt64]):
    """Fold `candidate` into `earliest` (None never wins)."""
    if not candidate:
        return
    if not earliest or candidate.value() < earliest.value():
        earliest = Optional[UInt64](candidate.value())


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
