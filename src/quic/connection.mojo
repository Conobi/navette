# src/quic/connection.mojo
#
# QuicConnection — sans-I/O QUIC state machine.
#
# Orchestrates packet protection, packet number spaces, loss recovery,
# crypto streams, and the TLS handshake via FFI into librustls_mojo.
#
# Usage:
#   var conn = QuicConnection.client(lib_addr, cfg, "example.com", tp, now)
#   var datagrams = conn.send(now)       # Initial with ClientHello
#   conn.recv(response_bytes, now)       # Feed server reply
#   var ev = conn.poll()                 # HANDSHAKE_COMPLETE, etc.

from std.collections import Dict, Optional
from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc

from src.tls.lib import RustlsLibrary
from src.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode, varint_len
from src.quic.error import QuicTransportError, NO_ERROR, PROTOCOL_VIOLATION
from src.quic.profile import AcceptProfile, PROFILE_ACCEPT, monotonic_us
from src.quic.frame import (
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
from src.quic.stream_map import StreamMap
from src.quic.cid import CidManager, CidEntry, CID_ACTIVE, CID_PENDING_RETIRE, CID_RETIRED
from src.quic.stream import (
    Stream, SendBuf, RecvBuf,
    SEND_READY, SEND_SEND, SEND_DATA_SENT, SEND_DATA_RECVD, SEND_RESET_SENT, SEND_RESET_RECVD,
    RECV_RECV, RECV_SIZE_KNOWN, RECV_DATA_RECVD, RECV_DATA_READ, RECV_STOP_SENDING_SENT, RECV_RESET_RECVD, RECV_RESET_READ,
    send_state_is_terminal, recv_state_is_terminal,
    stream_is_bidi, stream_is_local, stream_is_client_initiated,
)
from src.quic.flow_control import FlowControl
from src.quic.packet import (
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
from src.quic.trans_param import (
    TransportParams,
    parse_transport_params,
    serialize_transport_params,
)
from src.quic.pn_space import (
    EncryptionLevel,
    packet_type_to_space,
    PacketNumberSpace,
    SentPacket,
)
from src.quic.recovery import Recovery, K_GRANULARITY
from src.quic.crypto_stream import CryptoStream
from src.quic.packet_protect import PacketProtect
from src.quic.cc.cc_trait import AckedPacket, LostPacket, PERSISTENT_CONG_THRESHOLD
from src.quic.ecn import (
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


# ── SentStreamFrame ──────────────────────────────────────────────────
#
# Per-packet record of stream/flow-control/CID frames sent in the Application
# space, used for ACK and loss processing (M3c).  STREAM/CRYPTO retransmission
# for Initial/Handshake is still handled via SentPacket.frames (M3b).

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

    var type_id: UInt8
    var error_code: UInt64
    var reason: String
    var transport_params: Optional[TransportParams]
    var stream_id: UInt64
    var final_size: UInt64

    def __init__(out self, type_id: UInt8):
        self.type_id = type_id
        self.error_code = UInt64(0)
        self.reason = String("")
        self.transport_params = None
        self.stream_id = UInt64(0)
        self.final_size = UInt64(0)

    def __init__(out self, *, other: Self):
        self.type_id = other.type_id
        self.error_code = other.error_code
        self.reason = other.reason
        self.transport_params = other.transport_params.copy()
        self.stream_id = other.stream_id
        self.final_size = other.final_size

    def __init__(out self, *, deinit take: Self):
        self.type_id = take.type_id
        self.error_code = take.error_code
        self.reason = take.reason^
        self.transport_params = take.transport_params^
        self.stream_id = take.stream_id
        self.final_size = take.final_size

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
    var lib_addr: UInt64
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
    # Maps Application-space packet number -> list of stream-layer frames
    # sent in that packet, for ACK/loss processing (M3c).
    var app_frames_sent: Dict[Int, List[SentStreamFrame]]
    # ECN path validation state (RFC 9000 §13.4.2, RFC 9002 §7.9).
    var ecn_state: UInt8           # ECN_STATE_PROBING / ECN_STATE_CAPABLE / ECN_STATE_DISABLED
    var ecn_probe_pkts_needed: Int # probe this many ECT(0) packets before validation check
    var ecn_probe_pkts_sent: Int   # ECT(0) packets sent during probing phase
    var ecn_probe_first_pn: UInt64 # PN of first ECT(0) probe packet

    # ── Plan B profile instrumentation (always present; off-build = dead) ──
    #
    # struct-layout drift accepted in spec §Constraints. The profile_ptr field
    # is null for non-bench callers (client tests, conformance suite). Server
    # constructors stamp profile_first_initial_us before any FFI call so
    # handshake-latency does not under-report by Initial-key-derivation cost.
    #
    # First-iteration bleed-in semantic: profile_first_iter_done starts False.
    # Iter 1 of recv_from_buffer does NOT reset profile_rustls_us_accum at
    # its top — it inherits the constructor's accumulator (zero for server,
    # Initial-key-derivation cost for client). Iter 2+ resets at top.
    var profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]
    var profile_first_initial_us: UInt64
    var profile_rustls_us_accum: UInt64
    var profile_first_iter_done: Bool

    # ── Move constructor ─────────────────────────────────────────────

    def __init__(out self, *, deinit take: Self):
        self.is_server = take.is_server
        self.state = take.state
        self.spaces = take.spaces^
        self.crypto_streams = take.crypto_streams^
        self.recovery = take.recovery^
        self.protect = take.protect^
        self.conn_handle = take.conn_handle
        self.lib_addr = take.lib_addr
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
        self.app_frames_sent = take.app_frames_sent^
        self.ecn_state = take.ecn_state
        self.ecn_probe_pkts_needed = take.ecn_probe_pkts_needed
        self.ecn_probe_pkts_sent = take.ecn_probe_pkts_sent
        self.ecn_probe_first_pn = take.ecn_probe_first_pn
        self.profile_ptr = take.profile_ptr
        self.profile_first_initial_us = take.profile_first_initial_us
        self.profile_rustls_us_accum = take.profile_rustls_us_accum
        self.profile_first_iter_done = take.profile_first_iter_done

    # ── Private constructor (used by factory methods) ────────────────

    def __init__(
        out self,
        is_server: Bool,
        lib_addr: UInt64,
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
        self.protect = PacketProtect(lib_addr)
        self.conn_handle = conn_handle
        self.lib_addr = lib_addr
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
        self.profile_ptr = UnsafePointer[AcceptProfile, MutAnyOrigin]()
        self.profile_first_initial_us = UInt64(0)
        self.profile_rustls_us_accum = UInt64(0)
        self.profile_first_iter_done = False
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
            lib_addr=self.lib_addr,
            initial_local_cid=List[UInt8](copy=local_cid),
            initial_remote_cid=List[UInt8](copy=peer_cid),
            local_active_limit=UInt64(2),
            peer_active_limit=UInt64(2),
        )
        self.app_frames_sent = Dict[Int, List[SentStreamFrame]]()

    # ── Destructor ───────────────────────────────────────────────────

    def __del__(deinit self):
        if self.conn_handle >= 0:
            _ = self._lib()[].quic_conn_free(self.conn_handle)
        # PacketProtect.__del__ handles key cleanup.

    # ── Static factory methods ───────────────────────────────────────

    @staticmethod
    def client(
        lib_addr: UInt64,
        config_handle: Int32,
        server_name: String,
        local_params: TransportParams,
        now: UInt64,
    ) raises -> QuicConnection:
        """Create a QUIC client connection.

        Derives initial keys, creates TLS connection, and drives the
        initial write_hs to generate ClientHello CRYPTO data.
        """
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
        var sni_buf = _heap_alloc[UInt8](sni_len).as_any_origin()
        for i in range(sni_len):
            sni_buf[i] = sni_bytes[i]

        var tp_len = len(tp_bytes)
        var tp_buf = _heap_alloc[UInt8](tp_len).as_any_origin()
        for i in range(tp_len):
            tp_buf[i] = tp_bytes[i]

        var out_handle = _heap_alloc[Int32](1).as_any_origin()
        out_handle[0] = Int32(-1)

        var lib = _get_lib(lib_addr)
        var rc = lib[].quic_client_conn_new(
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
            var err = lib[].last_error()
            out_handle.free()
            raise "quic_client_conn_new failed: " + err

        var conn_handle = out_handle[0]
        out_handle.free()

        if conn_handle < 0:
            raise "quic_client_conn_new returned invalid handle"

        # 4. Build connection object.
        var conn = QuicConnection(
            is_server=False,
            lib_addr=lib_addr,
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
        lib_addr: UInt64,
        config_handle: Int32,
        local_params: TransportParams,
        orig_dcid: Span[UInt8, _],
        client_dcid: Span[UInt8, _],
        now: UInt64,
        profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]
            = UnsafePointer[AcceptProfile, MutAnyOrigin](),
    ) raises -> QuicConnection:
        """Create a QUIC server connection.

        Derives initial keys from the client's DCID and waits for
        the client Initial to drive the handshake.
        """
        # Plan B: stamp arrival timestamp BEFORE any FFI call so that
        # handshake-latency does not under-report by Initial-key-derivation.
        # The stamp is unconditional (8 bytes) — see spec §Constraints.
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
        var tp_buf = _heap_alloc[UInt8](tp_len).as_any_origin()
        for i in range(tp_len):
            tp_buf[i] = tp_bytes[i]

        var out_handle = _heap_alloc[Int32](1).as_any_origin()
        out_handle[0] = Int32(-1)

        var lib = _get_lib(lib_addr)
        var rc = lib[].quic_server_conn_new(
            config_handle,
            Int32(1),  # QUIC version 1
            tp_buf,
            Int32(tp_len),
            out_handle,
        )

        tp_buf.free()

        if rc < 0:
            var err = lib[].last_error()
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
            lib_addr=lib_addr,
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

        @parameter
        if PROFILE_ACCEPT:
            if Int(profile_ptr) != 0:
                profile_ptr[].record_handshake_arrival()

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
        var buf = _heap_alloc[UInt8](n).as_any_origin()
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
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
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

            # 1. Copy remaining bytes for parse_packet_header (needs Span
            # from List — known remaining copy, to be removed later).
            var remaining_list = List[UInt8](capacity=remaining_len)
            for i in range(remaining_len):
                remaining_list.append(remaining_ptr[i])

            # 2. Parse packet header.
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    ph_header_parse_us = monotonic_us()
            var header_result = parse_packet_header(
                Span(remaining_list), len(self.local_cid)
            )
            var header = header_result[0].copy()
            var header_end = header_result[1]
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    ph_header_parse_us = monotonic_us() - ph_header_parse_us

            # 2b. Adopt peer's SCID as peer_cid (RFC 9000 §7.2).
            if header.is_long_header and len(header.scid) > 0:
                if header.packet_type == PacketType.initial():
                    self.peer_cid = List[UInt8](copy=header.scid)

            # 3. Map to PN space.
            var space_idx = packet_type_to_space(header.packet_type)
            if space_idx < 0:
                break  # VN, Retry — skip for M3b

            if not self.protect.has_keys(space_idx):
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
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        ph_hp_us = monotonic_us()
                var hp_result = self.protect.unprotect_header_ptr(
                    space_idx, pkt_ptr, pkt_len, header.pn_offset
                )
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        ph_hp_us = monotonic_us() - ph_hp_us
                var first_byte = hp_result[0]
                var pn_length = hp_result[1]

                # 7. Decode packet number.
                var truncated_pn = UInt64(0)
                for i in range(pn_length):
                    truncated_pn = (truncated_pn << 8) | UInt64(
                        pkt_ptr[header.pn_offset + i]
                    )
                var largest = UInt64(0)
                if self.spaces[space_idx].largest_recv_pn >= 0:
                    largest = UInt64(self.spaces[space_idx].largest_recv_pn)
                var full_pn = pn_decode(truncated_pn, pn_length, largest)

                # 8. Decrypt payload in-place (zero-copy).
                var header_len = header.pn_offset + pn_length
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        ph_aead_us = monotonic_us()
                var plaintext_len = self.protect.decrypt_payload_in_place(
                    space_idx, full_pn, header_len, pkt_ptr, pkt_len
                )
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        ph_aead_us = monotonic_us() - ph_aead_us

                # 9. Server validates address on first Handshake decrypt.
                if self.is_server and space_idx == 1 and (self.state & CONN_ADDR_VALIDATED) == 0:
                    self.state = self.state | CONN_ADDR_VALIDATED

                # 10. Parse and dispatch frames.
                # Copy plaintext into list for ByteReader (known remaining
                # copy — ByteReader needs Span from List).
                var pt_list = List[UInt8](capacity=plaintext_len)
                for i in range(plaintext_len):
                    pt_list.append(pkt_ptr[header_len + i])
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        ph_frame_parse_us = monotonic_us()
                var reader = ByteReader(Span(pt_list))
                var frames = parse_frames(reader)
                var ack_eliciting = False
                for i in range(len(frames)):
                    if frames[i].is_ack_eliciting():
                        ack_eliciting = True
                    self._dispatch_frame(frames[i], space_idx, now)
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        ph_frame_parse_us = monotonic_us() - ph_frame_parse_us

                # 11. Update PN space.
                self.spaces[space_idx].on_packet_received(full_pn, ack_eliciting)

                # ECN accounting: count marks seen on received packets.
                if self.ecn_state != ECN_STATE_DISABLED:
                    if ecn_mark == ECN_CE:
                        self.spaces[space_idx].recv_ecn.ce += UInt64(1)
                    elif ecn_mark == ECN_ECT0:
                        self.spaces[space_idx].recv_ecn.ect0 += UInt64(1)
                    elif ecn_mark == ECN_ECT1:
                        self.spaces[space_idx].recv_ecn.ect1 += UInt64(1)

                # Track lowest processed space for retransmission logic.
                if space_idx < lowest_recv_space:
                    lowest_recv_space = space_idx
            except e:
                # Decryption or frame processing failed for this packet.
                # Per RFC 9000 §12.2, stop processing remaining coalesced
                # packets (they may use keys we don't have yet).
                _ = e
                decrypt_ok = False

            # 12. Drive handshake OUTSIDE try/except so TLS errors
            # propagate to the caller (they are fatal, not recoverable).
            if decrypt_ok:
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        ph_sm_us = monotonic_us()
                self._drive_handshake(now)
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        ph_sm_us = monotonic_us() - ph_sm_us

            if not decrypt_ok:
                break  # Stop processing coalesced packets

            # Plan B: emit per-packet record at iteration end. Bleed-in:
            # iter 1 inherits constructor's profile_rustls_us_accum.
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    var t_iter_end = monotonic_us()
                    var total_us = t_iter_end - t_iter_start
                    self.profile_ptr[].record_pkt(
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
            for i in range(len(new_ids)):
                self.events.append(QuicEvent.stream_opened(new_ids[i]))

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
        if offset + data_len > fc_r.limit:
            raise "FLOW_CONTROL_ERROR: stream FC exceeded"

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

    # ── Frame dispatch ───────────────────────────────────────────────

    def _dispatch_frame(
        mut self, frame: Frame, space_idx: Int, now: UInt64
    ) raises:
        """Route a parsed frame to its handler."""
        var tid = frame.type_id

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
        if tid == FRAME_HANDSHAKE_DONE:
            if not self.is_server:
                self.handshake_confirmed = True
                self.state = self.state | CONN_ESTABLISHED
                self._discard_handshake_space()
                self.events.append(QuicEvent.handshake_complete())
            return

        # NEW_TOKEN: minimal handling (client-only; ignored for M3c).
        if tid == FRAME_NEW_TOKEN:
            return

        # NEW_CONNECTION_ID: hand off to CidManager.
        if tid == FRAME_NEW_CONNECTION_ID:
            if frame._new_cid:
                var nc = frame._new_cid.value().copy()
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
                if key in self.stream_map.streams:
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
                if ms.maximum > self.stream_map.peer_max_streams_bidi:
                    self.stream_map.peer_max_streams_bidi = ms.maximum
                    # Peer granted more streams; reset dedup so we re-notify if we hit the new limit.
                    self.stream_map.needs_streams_blocked_bidi = False
                    self.stream_map.streams_blocked_at_bidi = UInt64(0)
            return

        if tid == FRAME_MAX_STREAMS_UNI:
            if frame._max_streams:
                var ms = frame._max_streams.value().copy()
                if ms.maximum > self.stream_map.peer_max_streams_uni:
                    self.stream_map.peer_max_streams_uni = ms.maximum
                    self.stream_map.needs_streams_blocked_uni = False
                    self.stream_map.streams_blocked_at_uni = UInt64(0)
            return

        # *_BLOCKED frames: informational only for M3c.
        if (tid == FRAME_DATA_BLOCKED
                or tid == FRAME_STREAM_DATA_BLOCKED
                or tid == FRAME_STREAMS_BLOCKED_BIDI
                or tid == FRAME_STREAMS_BLOCKED_UNI):
            return

        # Unknown frame type: ignore.
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

        # Process stream-layer frames for acked Application-space packets (M3c).
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
        # persistent-congestion detection (spec §5.4).
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

                # Re-apply stream-layer loss handling for Application space (M3c).
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

        Filtering to ack-eliciting packets is inline (spec §5.3): the check
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

        var lib = self._lib()

        # 1. Drain contiguous CRYPTO bytes from each space's crypto_stream
        #    and feed them to the TLS engine.
        for level in range(3):
            if self.crypto_streams[level].has_pending():
                var crypto_data = self.crypto_streams[level].drain()
                if len(crypto_data) > 0:
                    var data_buf = _heap_alloc[UInt8](
                        len(crypto_data)
                    ).as_any_origin()
                    for i in range(len(crypto_data)):
                        data_buf[i] = crypto_data[i]

                    var t_start: UInt64 = 0
                    @parameter
                    if PROFILE_ACCEPT:
                        if Int(self.profile_ptr) != 0:
                            t_start = monotonic_us()
                            self.profile_rustls_us_accum -= t_start
                    var rc = lib[].quic_conn_read_hs(
                        self.conn_handle,
                        data_buf,
                        Int32(len(crypto_data)),
                    )
                    @parameter
                    if PROFILE_ACCEPT:
                        if Int(self.profile_ptr) != 0:
                            var t_end = monotonic_us()
                            self.profile_rustls_us_accum += t_end
                            self.profile_ptr[].record_ffi_read_hs(t_end - t_start)
                    data_buf.free()

                    if rc < 0:
                        raise (
                            "quic_conn_read_hs failed: " + lib[].last_error()
                        )

        # 2. Loop write_hs to drain TLS output.
        var out_buf = _heap_alloc[UInt8](_WRITE_HS_BUF_SIZE).as_any_origin()
        var out_written = _heap_alloc[Int32](1).as_any_origin()
        var out_kc = _heap_alloc[UInt8](1).as_any_origin()

        while True:
            out_written[0] = Int32(0)
            out_kc[0] = UInt8(0)

            var t_start: UInt64 = 0
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    t_start = monotonic_us()
                    self.profile_rustls_us_accum -= t_start
            var rc = lib[].quic_conn_write_hs(
                self.conn_handle,
                out_buf,
                Int32(_WRITE_HS_BUF_SIZE),
                out_written,
                out_kc,
            )
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    var t_end = monotonic_us()
                    self.profile_rustls_us_accum += t_end
                    self.profile_ptr[].record_ffi_write_hs(t_end - t_start)

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
                var keys_handle_buf = _heap_alloc[Int32](1).as_any_origin()
                keys_handle_buf[0] = Int32(-1)

                var t_start: UInt64 = 0
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        t_start = monotonic_us()
                        self.profile_rustls_us_accum -= t_start
                var take_rc = lib[].quic_conn_take_keys(
                    self.conn_handle, keys_handle_buf
                )
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        var t_end = monotonic_us()
                        self.profile_rustls_us_accum += t_end
                        self.profile_ptr[].record_ffi_take_keys(t_end - t_start)

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

    def _on_handshake_complete(mut self, now: UInt64) raises:
        """Called when TLS reports handshake is complete."""
        if (self.state & CONN_ESTABLISHED) != 0:
            return  # Already processed

        # Plan B: record handshake latency on the SERVER side. Clients
        # have profile_first_initial_us = 0 (default) and are skipped.
        @parameter
        if PROFILE_ACCEPT:
            if self.is_server and Int(self.profile_ptr) != 0:
                if self.profile_first_initial_us > UInt64(0):
                    var latency_us = now - self.profile_first_initial_us
                    self.profile_ptr[].record_handshake_complete(latency_us)

        # Increment full/resumed counter exactly once per server connection.
        # Runtime gate only (not @parameter if PROFILE_ACCEPT:) so the test
        # build (PROFILE_ACCEPT=False) can verify the increment by attaching a
        # profile_ptr directly — approach (c) per Plan 2026-05-03.
        # profile_ptr is null when PROFILE_ACCEPT=False (no bench attachment),
        # so the runtime branch is paid at most once per server handshake.
        if self.is_server and Int(self.profile_ptr) != 0:
            var hs_kind = self._lib()[].quic_conn_handshake_kind(self.conn_handle)
            if hs_kind == Int32(1) or hs_kind == Int32(3):
                self.profile_ptr[].record_handshake_full()
            elif hs_kind == Int32(2):
                self.profile_ptr[].record_handshake_resumed()
            elif hs_kind == Int32(0):
                raise (
                    "_on_handshake_complete: handshake_kind=0 with "
                    + "is_handshaking==false (rustls state-machine "
                    + "invariant broken)"
                )
            # hs_kind == -2 (client path) or -1 (invalid handle): no-op.
            # is_server gate above already excludes client; -1 means the conn
            # handle was freed mid-call (should never happen in practice).

        # Clear HANDSHAKING flag.
        self.state = self.state & ~CONN_HANDSHAKING

        # Read peer transport params.
        var tp_buf = _heap_alloc[UInt8](_TP_BUF_SIZE).as_any_origin()
        var tp_written = _heap_alloc[Int32](1).as_any_origin()
        tp_written[0] = Int32(0)

        var lib = self._lib()
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

            var peer_tp = parse_transport_params(Span(tp_bytes))
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
            self.send_handshake_done = True
            self.events.append(QuicEvent.handshake_complete())
        else:
            # Client: discard Initial. If handshake_confirmed (via 1-RTT ACK),
            # also set ESTABLISHED and discard Handshake.
            self._discard_initial_space()
            if self.handshake_confirmed:
                self.state = self.state | CONN_ESTABLISHED
                self._discard_handshake_space()
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

            if space_idx == 0:
                has_initial = True

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
            # so ACK / loss handlers can re-apply state (M3c).
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

        # Application-space stream-layer frames (M3c).
        if space_idx == 2:
            self._build_app_frames(frames, sent_records)

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
                # Token is empty for M3b (no retry support yet).
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
            for i in range(_AEAD_TAG_LEN):
                header_bytes.append(UInt8(0))

            # header_bytes is now: [header | PN | payload | tag_space]
            var total_len = len(header_bytes)
            var pkt_ptr = header_bytes.unsafe_ptr().unsafe_mut_cast[True]().as_any_origin()

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
            for i in range(_AEAD_TAG_LEN):
                header_bytes.append(UInt8(0))

            var total_len = len(header_bytes)
            var pkt_ptr = header_bytes.unsafe_ptr().unsafe_mut_cast[True]().as_any_origin()

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

    # ── Application-space frame ACK/loss handling (M3c) ─────────────

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

    def close(mut self, error_code: UInt64, reason: String, now: UInt64):
        """Initiate a graceful connection close."""
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
        cc.is_transport = True
        cc.error_code = error_code
        cc.frame_type = UInt64(0)
        cc.reason = reason_bytes^
        self.pending_close = cc^

    def is_established(self) -> Bool:
        """True if the handshake is complete and the connection is usable."""
        return (self.state & CONN_ESTABLISHED) != 0

    fn is_expected_dcid(self, dcid: Span[UInt8, _]) -> Bool:
        """True if `dcid` matches either initial_dcid or local_cid.

        - `initial_dcid` is the client's random Initial DCID, used for
          Initial-key derivation. Valid pre-handshake and during the brief
          post-handshake transition before the client switches over.
        - `local_cid` is the server's chosen SCID (or, on a client conn,
          the locally-chosen SCID). The peer uses it as DCID after the
          first server Initial.

        Connection migration is a project non-goal in v1 of M3 (project
        non-goal line 28 of docs/project-context.md). Once
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

    # ── Stream public API (M3c) ──────────────────────────────────────

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
        ngtcp2 / quiche pace every encryption level. See
        specs/2026-04-25-quic-pacer-bypass-handshake.md for the verdict.
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

    @always_inline
    def _lib(self) -> UnsafePointer[RustlsLibrary, MutAnyOrigin]:
        return UnsafePointer[RustlsLibrary, MutAnyOrigin](
            unsafe_from_address=Int(self.lib_addr)
        )


# ── Module-level helpers ─────────────────────────────────────────────


def _get_lib(
    lib_addr: UInt64,
) -> UnsafePointer[RustlsLibrary, MutAnyOrigin]:
    return UnsafePointer[RustlsLibrary, MutAnyOrigin](
        unsafe_from_address=Int(lib_addr)
    )


def _generate_random_cid() raises -> List[UInt8]:
    """Generate a random 8-byte connection ID via getrandom(2)."""
    var buf = _heap_alloc[UInt8](8).as_any_origin()
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
    """Set M3c flow-control / stream-limit defaults if not already set."""
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
