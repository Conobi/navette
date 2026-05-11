# bench/h3_server.mojo
#
# HTTP/3 QUIC benchmark server for HttpArena on port 8443 (UDP).
#
# Uses boucle BatchCompletionLoop with multishot recvmsg and provided
# buffer rings for high-performance UDP I/O.

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.collections import Dict, InlineArray

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection
from src.quic.trans_param import TransportParams, default_transport_params
from src.quic.packet import parse_packet_header
from src.h3.h3_handler_server import H3HandlerServer
from bench.handler import (
    BenchHandler,
    BenchState,
    StaticEntry,
    _load_static_files,
    _load_dataset,
)
from interop.file_io import read_file, getenv_opt, write_file, mkdir_p
from interop.udp import monotonic_us
from src.quic.profile import AcceptProfile, PROFILE_ACCEPT, DRAIN_TO_EAGAIN, EGRESS_POOL, EGRESS_POOL_SIZE, EGRESS_POOL_V2, monotonic_us as profile_monotonic_us

from boucle import BatchCompletionLoop, BatchCompletionHandler
from boucle.handle import RawHandle
from boucle._sys.linux.raw.ctypes import c_void
from boucle._sys.linux.raw.x86_64.io_uring import IORING_CQE_F_BUFFER, IORING_CQE_F_MORE, IORING_CQE_BUFFER_SHIFT


# ── constants ──────────────────────────────────────────────────────────

comptime OP_RECVMSG: UInt8 = 0
comptime OP_SENDMSG: UInt8 = 1
comptime OP_TIMEOUT: UInt8 = 2
comptime OP_PROVIDE_BUF: UInt8 = 3

comptime DATAGRAM_BUF_SIZE: Int = 1500
comptime ADDR_SIZE: Int = 28
comptime MSGHDR_SIZE: Int = 56
comptime IOVEC_SIZE: Int = 16
comptime TIMESPEC_SIZE: Int = 16

comptime SOL_SOCKET: Int32 = 1
comptime SO_REUSEADDR: Int32 = 2
comptime SO_REUSEPORT: Int32 = 15
comptime IPPROTO_IPV6: Int32 = 41
comptime IPV6_V6ONLY: Int32 = 26

comptime _SUBMIT_SENDMSG: UInt8 = 1
comptime _SUBMIT_TIMEOUT: UInt8 = 2

comptime PBUF_COUNT: Int = 1024
comptime PBUF_SIZE: Int = 1600
comptime PBUF_GROUP_ID: UInt16 = 0
comptime RECVMSG_OUT_HDR_SIZE: Int = 16

# Drain-extension scratch pool (Plan: 2026-05-05-quic-bench-drain-extension §3).
# `_drain_extension` issues recvfrom(MSG_DONTWAIT) in a loop on the shared UDP
# fd; each successful pull builds a PendingDatagram with sentinel buf_id=0xFFFF
# pointing into one of these scratch buffers. Pool capacity caps how many
# datagrams a single drain call can pull before signalling overflow.
comptime DRAIN_SCRATCH_BUFS: Int = 64
comptime MAX_DATAGRAM_SIZE: Int = 1500
comptime DRAIN_BUF_ID_SENTINEL: UInt16 = 0xFFFF
comptime DRAIN_ADDR_SCRATCH_SIZE: Int = 128  # sockaddr_storage upper bound
comptime MSG_DONTWAIT: Int32 = 0x40
comptime EAGAIN_ERRNO: Int32 = 11

# ── Plan B SIGINT plumbing ────────────────────────────────────────────
#
# Mojo 0.26.2 forbids module-level `var`, so we cannot declare a global
# `Atomic[Int32]` flag. `comptime _heap_alloc(...)` is also unusable
# because each function captures its own copy of the comptime value
# (verified empirically — the address differs across `main` and
# `_profile_signal_handler`).
#
# Workaround: mmap a one-page anonymous mapping at a fixed low address.
# Both `main` and the signal handler agree on the literal `Int` constant
# `PROFILE_FLAG_ADDR`, so they read/write the same word. This is the
# simplest async-signal-safe state-sharing scheme available in 0.26.2.
# The signal handler itself does no allocation, no Mojo runtime calls,
# and no I/O — it just stores `1` to that word.
#
# `signal(2)` FFI signature: signal(int signum, void (*handler)(int))
# returns void (*)(int). We cast our `thin` fn pointer through Int and
# pass it as an opaque pointer. Empirically validated against libc.
comptime PROFILE_FLAG_ADDR: Int = 0x60000000  # 1.5 GiB — well below any heap
comptime PROFILE_MAP_PRIVATE: Int32 = 2
comptime PROFILE_MAP_ANON: Int32 = 0x20
comptime PROFILE_MAP_FIXED: Int32 = 0x110  # MAP_FIXED | MAP_FIXED_NOREPLACE (Linux 4.17+) — fail with ENOMEM instead of clobbering an existing mapping
comptime PROFILE_PROT_RW: Int32 = 3
comptime PROFILE_SIGINT: Int32 = 2
comptime PROFILE_SIGTERM: Int32 = 15


fn _profile_signal_handler(signo: Int32):
    # Async-signal-safe: store `1` to the fixed-address flag word. No
    # allocation, no print, no Mojo runtime.
    var p = UnsafePointer[Int32, MutAnyOrigin](
        unsafe_from_address=PROFILE_FLAG_ADDR
    )
    p[0] = Int32(1)


def _profile_install_signal_handlers() raises:
    """Map the flag page and install SIGINT/SIGTERM handlers."""
    var hint = UnsafePointer[NoneType, MutAnyOrigin](
        unsafe_from_address=PROFILE_FLAG_ADDR
    )
    var mapped = external_call["mmap", UnsafePointer[NoneType, MutAnyOrigin]](
        hint,
        Int(4096),
        PROFILE_PROT_RW,
        PROFILE_MAP_PRIVATE | PROFILE_MAP_ANON | PROFILE_MAP_FIXED,
        Int32(-1),
        Int(0),
    )
    if Int(mapped) != PROFILE_FLAG_ADDR:
        # MAP_FIXED_NOREPLACE returns MAP_FAILED with errno=EEXIST when the
        # address is already mapped (instead of silently clobbering), or
        # ENOMEM under low memory. Either way, we cannot use the flag page.
        raise "_profile_install_signal_handlers: mmap failed (address already in use or out of memory)"
    var p = UnsafePointer[Int32, MutAnyOrigin](
        unsafe_from_address=PROFILE_FLAG_ADDR
    )
    p[0] = Int32(0)

    var fn_ptr: fn(Int32) -> None = _profile_signal_handler
    var fp_value = UnsafePointer(to=fn_ptr).bitcast[UInt64]()[0]
    var handler_ptr = UnsafePointer[NoneType, MutAnyOrigin](
        unsafe_from_address=Int(fp_value)
    )
    _ = external_call["signal", UnsafePointer[NoneType, MutAnyOrigin]](
        PROFILE_SIGINT, handler_ptr
    )
    _ = external_call["signal", UnsafePointer[NoneType, MutAnyOrigin]](
        PROFILE_SIGTERM, handler_ptr
    )


@always_inline
fn _profile_dump_pending() -> Bool:
    var p = UnsafePointer[Int32, MutAnyOrigin](
        unsafe_from_address=PROFILE_FLAG_ADDR
    )
    return p[0] != Int32(0)


def _encode_token(slot_idx: UInt64, op_kind: UInt8) -> UInt64:
    return (slot_idx << 8) | UInt64(op_kind)


@always_inline
def _read_u32_le(ptr: UnsafePointer[UInt8, MutAnyOrigin]) -> UInt32:
    return UInt32(ptr[0]) | (UInt32(ptr[1]) << 8) | (UInt32(ptr[2]) << 16) | (UInt32(ptr[3]) << 24)


fn _zpad2_int(n: Int) -> String:
    """Zero-pad an Int to 2 digits (used for UTC timestamp formatting)."""
    if n < 10:
        return String("0") + String(n)
    return String(n)


# ── helpers (kept from original) ───────────────────────────────────────


alias _HEX_DIGITS = "0123456789abcdef"


# unused at hot-path post-2026-04-28-quic-bench-dcid-u64-demux; retained
# for ad-hoc debug rendering and for `tests/test_quic_connection.mojo`'s
# `test_dcid_demux_disambiguates_two_conns`. Do not delete without
# re-grepping across the repo.
fn _bytes_to_hex(bytes: Span[UInt8, _]) -> String:
    """Hex-encode bytes for use as a Dict[String, Int] key.

    Mirrors `_addr_to_key`'s encoding to keep Dict-key shape consistent
    across the codebase. Pinned to 8-byte DCIDs (server SCID length is
    pinned at 8 bytes; client Initial DCIDs are RFC 9000 §7.2 minimum 8).
    Span parameter so call sites pass `Span(quic.initial_dcid)` or
    `Span(pd.dcid)` without consuming the source list.
    """
    var key = String()
    var hex_bytes = _HEX_DIGITS.as_bytes()
    for i in range(len(bytes)):
        var b = Int(bytes[i])
        key += chr(Int(hex_bytes[b >> 4]))
        key += chr(Int(hex_bytes[b & 0x0F]))
    return key^


fn _dcid_to_u64(bytes: Span[UInt8, _]) -> UInt64:
    """Pack 8 bytes (big-endian) into a UInt64 for use as a Dict[UInt64, Int]
    key. Replaces `_bytes_to_hex` on the bench's hot DCID-demux path.

    Precondition: `len(bytes) == 8` (locked by upstream
    `test_quic_connection_dcid_lengths_are_8_bytes` and by debug_assert at
    the conn-create site). When ASSERT mode is `none` (the bench's
    measurement-build configuration), the assert below is compiled out and
    the function is a pure 8-iter shift loop (~20 ns).
    """
    debug_assert(len(bytes) == 8, "DCID must be 8 bytes")
    var result: UInt64 = 0
    for i in range(8):
        result = (result << 8) | UInt64(bytes[i])
    return result


fn _is_long_header_initial(payload: Span[UInt8, _]) -> Bool:
    """True iff the QUIC packet's first byte indicates a long-header Initial.

    First byte (RFC 9000 v1):
      bit 7 (0x80): header form. 1 = long, 0 = short.
      bits 5-4 (0x30): packet type for long header.
        0b00 = 0x00 = Initial
        0b01 = 0x10 = 0-RTT
        0b10 = 0x20 = Handshake
        0b11 = 0x30 = Retry

    Empty `payload` returns False (defensive).
    QUIC v1 only (project non-goal: gQUIC, draft versions).
    """
    if len(payload) == 0:
        return False
    var first = payload[0]
    if (first & 0x80) == 0:
        return False  # short header
    return (first & 0x30) == 0x00


def _addr_to_key(addr: List[UInt8]) -> String:
    """Convert raw 16-byte sockaddr to a string key for connection demux."""
    var key = String()
    for i in range(len(addr)):
        var b = Int(addr[i])
        comptime HEX: String = "0123456789abcdef"
        var hex_bytes = HEX.as_bytes()
        key += chr(Int(hex_bytes[b >> 4]))
        key += chr(Int(hex_bytes[b & 0x0F]))
    return key^


def _extract_dcid(data: Span[UInt8, _]) raises -> List[UInt8]:
    """Extract the DCID from an incoming QUIC packet.

    For long-header packets (Initial):
      byte 0: header byte (high bit set)
      bytes 1-4: version
      byte 5: DCID length
      bytes 6..6+dcid_len: DCID

    For short-header packets, we use parse_packet_header with a
    default CID length of 8.
    """
    if len(data) < 6:
        raise "_extract_dcid: packet too short"

    var first = Int(data[0])
    if (first & 0x80) != 0:
        # Long header — extract DCID directly.
        var dcid_len = Int(data[5])
        if len(data) < 6 + dcid_len:
            raise "_extract_dcid: packet too short for DCID"
        var dcid = List[UInt8](capacity=dcid_len)
        for i in range(dcid_len):
            dcid.append(data[6 + i])
        return dcid^
    else:
        # Short header — use parser with assumed 8-byte CID.
        var result = parse_packet_header(data, 8)
        return List[UInt8](copy=result[0].dcid)


def _create_server_config(
    lib_ptr: UnsafePointer[RustlsLibrary, MutAnyOrigin],
    alpn: String,
    certs_dir: String,
) raises -> Int32:
    """Create a QUIC server TLS config from PEM files in certs_dir."""
    var cert_data = read_file(certs_dir + "/server.crt")
    var key_data = read_file(certs_dir + "/server.key")

    var cert_len = len(cert_data)
    var key_len = len(key_data)

    var cert_buf = _heap_alloc[UInt8](cert_len).as_any_origin()
    for i in range(cert_len):
        cert_buf[i] = cert_data[i]

    var key_buf = _heap_alloc[UInt8](key_len).as_any_origin()
    for i in range(key_len):
        key_buf[i] = key_data[i]

    # ALPN: raw protocol name bytes.
    var alpn_bytes = alpn.as_bytes()
    var alpn_wire_len = len(alpn_bytes)
    var alpn_buf = _heap_alloc[UInt8](alpn_wire_len).as_any_origin()
    for i in range(len(alpn_bytes)):
        alpn_buf[i] = alpn_bytes[i]

    var out_handle = _heap_alloc[Int32](1).as_any_origin()
    var rc = lib_ptr[].quic_server_config_new(
        cert_buf, Int32(cert_len),
        key_buf, Int32(key_len),
        alpn_buf, Int32(alpn_wire_len),
        Int32(0),  # max_early_data: 0-RTT disabled (P3 will flip)
        out_handle,
    )

    var config_handle = out_handle[0]
    cert_buf.free()
    key_buf.free()
    alpn_buf.free()
    out_handle.free()

    if rc != Int32(0):
        raise "quic_server_config_new failed: " + lib_ptr[].last_error()

    return config_handle


# ── PendingDatagram ──────────────────────────────────────────────────


struct PendingDatagram(Copyable, Movable):
    var buf_id: UInt16
    var buf_ptr: UnsafePointer[UInt8, MutAnyOrigin]
    var payload_ptr: UnsafePointer[UInt8, MutAnyOrigin]
    var payload_len: Int
    var addr_offset: Int
    var addr_len: Int
    var addr_key: String
    var dcid: List[UInt8]
    # Arrival-to-processing queueing-tail instrumentation.
    # Read only when PROFILE_ACCEPT is True; off-build the value is always 0
    # and any computed `now - arrival_us` delta is meaningless.
    var arrival_us: UInt64

    def __init__(out self, buf_id: UInt16, buf_ptr: UnsafePointer[UInt8, MutAnyOrigin],
                 payload_ptr: UnsafePointer[UInt8, MutAnyOrigin], payload_len: Int,
                 addr_offset: Int, addr_len: Int, var addr_key: String, var dcid: List[UInt8],
                 arrival_us: UInt64 = UInt64(0)):
        self.buf_id = buf_id
        self.buf_ptr = buf_ptr
        self.payload_ptr = payload_ptr
        self.payload_len = payload_len
        self.addr_offset = addr_offset
        self.addr_len = addr_len
        self.addr_key = addr_key^
        self.dcid = dcid^
        self.arrival_us = arrival_us

    def __init__(out self, *, other: Self):
        self.buf_id = other.buf_id
        self.buf_ptr = other.buf_ptr
        self.payload_ptr = other.payload_ptr
        self.payload_len = other.payload_len
        self.addr_offset = other.addr_offset
        self.addr_len = other.addr_len
        self.addr_key = String(other.addr_key)
        self.dcid = List[UInt8](copy=other.dcid)
        self.arrival_us = other.arrival_us

    def __init__(out self, *, deinit take: Self):
        self.buf_id = take.buf_id
        self.buf_ptr = take.buf_ptr
        self.payload_ptr = take.payload_ptr
        self.payload_len = take.payload_len
        self.addr_offset = take.addr_offset
        self.addr_len = take.addr_len
        self.addr_key = take.addr_key^
        self.dcid = take.dcid^
        self.arrival_us = take.arrival_us


# ── UdpTxSlot ─────────────────────────────────────────────────────────


struct UdpTxSlot(Movable):
    """Dynamically allocated send buffer set for a single sendmsg operation."""

    var msghdr_buf: UnsafePointer[UInt8, MutAnyOrigin]
    var iov_buf: UnsafePointer[UInt8, MutAnyOrigin]
    var addr_buf: UnsafePointer[UInt8, MutAnyOrigin]
    var data_buf: UnsafePointer[UInt8, MutAnyOrigin]

    def __init__(out self, var data: List[UInt8], addr: List[UInt8]):
        var data_len = len(data)

        self.msghdr_buf = _heap_alloc[UInt8](MSGHDR_SIZE).as_any_origin()
        self.iov_buf = _heap_alloc[UInt8](IOVEC_SIZE).as_any_origin()
        self.addr_buf = _heap_alloc[UInt8](ADDR_SIZE).as_any_origin()
        self.data_buf = _heap_alloc[UInt8](data_len).as_any_origin()

        # Copy data
        for i in range(data_len):
            self.data_buf[i] = data[i]

        # Copy addr (up to ADDR_SIZE bytes)
        var addr_len = len(addr)
        for i in range(ADDR_SIZE):
            if i < addr_len:
                self.addr_buf[i] = addr[i]
            else:
                self.addr_buf[i] = 0

        # Zero msghdr
        for i in range(MSGHDR_SIZE):
            self.msghdr_buf[i] = 0
        # Zero iov
        for i in range(IOVEC_SIZE):
            self.iov_buf[i] = 0

        var msghdr = self.msghdr_buf

        # offset 0: msg_name = addr_buf pointer
        var addr_ptr_val = UInt64(Int(self.addr_buf))
        var addr_ptr_bytes = UnsafePointer(to=addr_ptr_val).bitcast[UInt8]()
        for i in range(8):
            msghdr[i] = addr_ptr_bytes[i]

        # offset 8: msg_namelen = 28
        var namelen = UInt32(ADDR_SIZE)
        var namelen_bytes = UnsafePointer(to=namelen).bitcast[UInt8]()
        for i in range(4):
            msghdr[8 + i] = namelen_bytes[i]

        # offset 16: msg_iov = iov_buf pointer
        var iov_ptr_val = UInt64(Int(self.iov_buf))
        var iov_ptr_bytes = UnsafePointer(to=iov_ptr_val).bitcast[UInt8]()
        for i in range(8):
            msghdr[16 + i] = iov_ptr_bytes[i]

        # offset 24: msg_iovlen = 1
        var iovlen = UInt64(1)
        var iovlen_bytes = UnsafePointer(to=iovlen).bitcast[UInt8]()
        for i in range(8):
            msghdr[24 + i] = iovlen_bytes[i]

        # Wire iovec
        var iov = self.iov_buf
        var data_ptr_val = UInt64(Int(self.data_buf))
        var data_ptr_bytes = UnsafePointer(to=data_ptr_val).bitcast[UInt8]()
        for i in range(8):
            iov[i] = data_ptr_bytes[i]

        var iov_len = UInt64(data_len)
        var iov_len_bytes = UnsafePointer(to=iov_len).bitcast[UInt8]()
        for i in range(8):
            iov[8 + i] = iov_len_bytes[i]

    def __init__(out self, *, deinit take: Self):
        self.msghdr_buf = take.msghdr_buf
        self.iov_buf = take.iov_buf
        self.addr_buf = take.addr_buf
        self.data_buf = take.data_buf

    def free(mut self):
        """Free all 4 heap buffers."""
        self.msghdr_buf.free()
        self.iov_buf.free()
        self.addr_buf.free()
        self.data_buf.free()


# ── PendingSubmit ─────────────────────────────────────────────────────


struct PendingSubmit(Copyable, Movable):
    var kind: UInt8
    var slot_idx: UInt64

    def __init__(out self, kind: UInt8, slot_idx: UInt64):
        self.kind = kind
        self.slot_idx = slot_idx

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.slot_idx = other.slot_idx

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.slot_idx = take.slot_idx


# ── H3UdpHandler ─────────────────────────────────────────────────────


struct H3UdpHandler(BatchCompletionHandler):
    """BatchCompletionHandler for UDP-based H3 server using io_uring
    with multishot recvmsg and provided buffer rings."""

    var udp_fd: Int32
    var conn_dcid_map: Dict[UInt64, Int]
    var conn_h3s: List[UnsafePointer[H3HandlerServer[BenchHandler], MutAnyOrigin]]
    var conn_addrs: List[List[UInt8]]
    # Per-conn list of DCID-u64 keys we inserted into conn_dcid_map.
    # Used by _handle_timeout to remove ALL of a conn's entries on swap-and-pop
    # (B-permissive dual-DCID strategy: each conn has 2 entries — initial_dcid
    # AND local_cid).
    var conn_dcids: List[List[UInt64]]
    var pbuf_pool: UnsafePointer[UInt8, MutAnyOrigin]
    var pending_rx: List[PendingDatagram]
    var multishot_active: Bool
    var consumed_bufs: List[UInt16]
    var msghdr_template: UnsafePointer[UInt8, MutAnyOrigin]
    var tx_slots: List[UnsafePointer[UdpTxSlot, MutAnyOrigin]]
    var tx_slot_tokens: List[UInt64]
    var tx_slot_idx_by_token: Dict[UInt64, Int]
    # Q8 Phase 2 — egress pool V2: pre-allocated UdpTxSlot pointer freelist
    # (uninitialized memory at freelist-init; init_pointee_move happens at
    # _drain_and_send time). Parallel List `tx_slot_from_pool` tracks slot
    # source so _handle_sendmsg can return pool slots to freelist instead of
    # calling ptr.free(). Both fields gated on EGRESS_POOL_V2 — off-build
    # bit-identity preserved (freelist init is empty, append/pop sites are
    # under @parameter if EGRESS_POOL_V2:).
    var egress_pool_v2_freelist: List[UnsafePointer[UdpTxSlot, MutAnyOrigin]]
    var tx_slot_from_pool: List[Bool]
    var next_tx_id: UInt64
    var state_ptr: UnsafePointer[BenchState, MutAnyOrigin]
    var lib_addr: UInt64
    var server_config: Int32
    var timeout_ts: UnsafePointer[UInt8, MutAnyOrigin]
    var pending_submits: List[PendingSubmit]
    # Plan B profile (always present; dead in off-build).
    var profile: AcceptProfile
    var last_flush_end_us: UInt64
    # Plan C diagnostic — count kernel-level recvmsg drops + multishot terminations.
    var enobufs_count: UInt64
    var multishot_term_count: UInt64
    # Plan C diagnostic — count silent error swallows in _flush_impl.
    var quic_server_err_count: UInt64
    var h3_handler_err_count: UInt64
    var feed_datagram_err_count: UInt64
    var quic_server_err_first: Bool   # print first error message only
    # Drain-extension scratch pool (Plan: 2026-05-05-quic-bench-drain-extension).
    # Pre-allocated 64×1500 buffers + one sockaddr scratch reused across drain
    # iterations. Always present so the struct shape is stable regardless of
    # `DRAIN_TO_EAGAIN`. Off-build cost: ~96 KiB resident, never touched.
    var drain_scratch_pool: List[List[UInt8]]
    var drain_scratch_addr: List[UInt8]
    # Q-IO-1 (spec 2026-05-05-shortconn-io-path-investigation §4.1) — counts
    # `on_complete` invocations between two adjacent `loop.poll` returns.
    # Snapshot+reset by the event loop after each `loop.poll` cycle and fed
    # to `record_cqes_per_wake`. Field always present; only mutated under
    # PROFILE_ACCEPT (off-build path leaves it at zero).
    var cqes_this_wake_count: UInt64

    def __init__(
        out self,
        udp_fd: Int32,
        state_ptr: UnsafePointer[BenchState, MutAnyOrigin],
        lib_addr: UInt64,
        server_config: Int32,
    ):
        self.udp_fd = udp_fd
        self.conn_dcid_map = Dict[UInt64, Int]()
        self.conn_h3s = List[UnsafePointer[H3HandlerServer[BenchHandler], MutAnyOrigin]]()
        self.conn_addrs = List[List[UInt8]]()
        self.conn_dcids = List[List[UInt64]]()
        self.pbuf_pool = _heap_alloc[UInt8](PBUF_COUNT * PBUF_SIZE).as_any_origin()
        for i in range(PBUF_COUNT * PBUF_SIZE):
            self.pbuf_pool[i] = 0
        self.pending_rx = List[PendingDatagram]()
        self.multishot_active = False
        self.consumed_bufs = List[UInt16]()
        self.msghdr_template = _heap_alloc[UInt8](MSGHDR_SIZE).as_any_origin()
        for i in range(MSGHDR_SIZE):
            self.msghdr_template[i] = 0
        # msg_namelen at offset 8 = 28 (sockaddr_in6 size) — kernel
        # needs this to populate the peer address in provided buffers.
        self.msghdr_template[8] = 28
        # msg_iovlen stays 0: for multishot recvmsg with provided buffers
        # the kernel ignores msg_iov, but import_iovec still validates
        # the pointer if iovlen > 0 — setting iovlen=1 with iov=NULL
        # causes EFAULT.
        self.tx_slots = List[UnsafePointer[UdpTxSlot, MutAnyOrigin]]()
        self.tx_slot_tokens = List[UInt64]()
        self.tx_slot_idx_by_token = Dict[UInt64, Int]()
        # Q8 Phase 2 — pre-allocate EGRESS_POOL_SIZE slot pointers iff
        # EGRESS_POOL_V2 is enabled. Slots hold uninitialized memory; the
        # legacy `UdpTxSlot(data, addr)` ctor runs via init_pointee_move at
        # _drain_and_send time. Off-build path: empty List (zero alloc).
        @parameter
        if EGRESS_POOL_V2:
            self.egress_pool_v2_freelist = List[UnsafePointer[UdpTxSlot, MutAnyOrigin]](capacity=EGRESS_POOL_SIZE)
            for _ in range(EGRESS_POOL_SIZE):
                self.egress_pool_v2_freelist.append(_heap_alloc[UdpTxSlot](1).as_any_origin())
        else:
            self.egress_pool_v2_freelist = List[UnsafePointer[UdpTxSlot, MutAnyOrigin]]()
        self.tx_slot_from_pool = List[Bool]()
        self.next_tx_id = UInt64(0)
        self.state_ptr = state_ptr
        self.lib_addr = lib_addr
        self.server_config = server_config
        self.pending_submits = List[PendingSubmit]()

        # Allocate timeout timespec (16 bytes): 50ms = 50_000_000 ns LE.
        self.timeout_ts = _heap_alloc[UInt8](TIMESPEC_SIZE).as_any_origin()
        for i in range(TIMESPEC_SIZE):
            self.timeout_ts[i] = 0
        # tv_nsec at offset 8 = 50_000_000 = 0x02FAF080 LE
        self.timeout_ts[8] = 0x80
        self.timeout_ts[9] = 0xF0
        self.timeout_ts[10] = 0xFA
        self.timeout_ts[11] = 0x02

        self.profile = AcceptProfile()
        self.last_flush_end_us = UInt64(0)
        self.enobufs_count = UInt64(0)
        self.multishot_term_count = UInt64(0)
        self.quic_server_err_count = UInt64(0)
        self.h3_handler_err_count = UInt64(0)
        self.feed_datagram_err_count = UInt64(0)
        self.quic_server_err_first = False

        # Drain-extension scratch pool — 64 × 1500B datagram buffers + one
        # shared sockaddr scratch. Pre-fill each List[UInt8] with zero bytes
        # so unsafe_ptr() points to writable, owned storage; List capacity
        # alone does not produce indexable storage in Mojo 0.26.2.
        self.drain_scratch_pool = List[List[UInt8]](capacity=DRAIN_SCRATCH_BUFS)
        for _ in range(DRAIN_SCRATCH_BUFS):
            var buf = List[UInt8](capacity=MAX_DATAGRAM_SIZE)
            for _ in range(MAX_DATAGRAM_SIZE):
                buf.append(UInt8(0))
            self.drain_scratch_pool.append(buf^)
        self.drain_scratch_addr = List[UInt8](capacity=DRAIN_ADDR_SCRATCH_SIZE)
        for _ in range(DRAIN_ADDR_SCRATCH_SIZE):
            self.drain_scratch_addr.append(UInt8(0))
        # Q-IO-1 — per-wake CQE count (snapshot+reset by event loop).
        self.cqes_this_wake_count = UInt64(0)

    def __init__(out self, *, deinit take: Self):
        self.udp_fd = take.udp_fd
        self.conn_dcid_map = take.conn_dcid_map^
        self.conn_h3s = take.conn_h3s^
        self.conn_addrs = take.conn_addrs^
        self.conn_dcids = take.conn_dcids^
        self.pbuf_pool = take.pbuf_pool
        self.pending_rx = take.pending_rx^
        self.multishot_active = take.multishot_active
        self.consumed_bufs = take.consumed_bufs^
        self.msghdr_template = take.msghdr_template
        self.tx_slots = take.tx_slots^
        self.tx_slot_tokens = take.tx_slot_tokens^
        self.tx_slot_idx_by_token = take.tx_slot_idx_by_token^
        self.egress_pool_v2_freelist = take.egress_pool_v2_freelist^
        self.tx_slot_from_pool = take.tx_slot_from_pool^
        self.next_tx_id = take.next_tx_id
        self.state_ptr = take.state_ptr
        self.lib_addr = take.lib_addr
        self.server_config = take.server_config
        self.timeout_ts = take.timeout_ts
        self.pending_submits = take.pending_submits^
        self.profile = take.profile^
        self.last_flush_end_us = take.last_flush_end_us
        self.enobufs_count = take.enobufs_count
        self.multishot_term_count = take.multishot_term_count
        self.quic_server_err_count = take.quic_server_err_count
        self.h3_handler_err_count = take.h3_handler_err_count
        self.feed_datagram_err_count = take.feed_datagram_err_count
        self.quic_server_err_first = take.quic_server_err_first
        self.drain_scratch_pool = take.drain_scratch_pool^
        self.drain_scratch_addr = take.drain_scratch_addr^
        self.cqes_this_wake_count = take.cqes_this_wake_count

    # --- Conn lookup ---

    def _find_conn_by_dcid(self, dcid_u64: UInt64) -> Int:
        if dcid_u64 in self.conn_dcid_map:
            try:
                return self.conn_dcid_map[dcid_u64]
            except:
                return -1
        return -1

    # --- on_complete dispatch ---

    fn on_complete(mut self, token: UInt64, result: Int32, flags: UInt32):
        # Q-IO-1 (spec 2026-05-05-shortconn-io-path-investigation §4.1) —
        # count CQEs drained per `loop.poll` cycle. Snapshot+reset happens
        # in the event loop after `loop.poll` returns. Off-build path elides
        # this branch entirely.
        @parameter
        if PROFILE_ACCEPT:
            self.cqes_this_wake_count = self.cqes_this_wake_count + UInt64(1)
        try:
            self._dispatch(token, result, flags)
        except e:
            print("h3-bench: on_complete error:", e)

    # Q-IO-1 (spec 2026-05-05-shortconn-io-path-investigation §4.1) — read
    # `cqes_this_wake_count` and reset it to zero, returning the snapshot.
    # Method form (rather than direct field write through `loop._handler.<f>`)
    # works around a Mojo 0.26.2 mojox ICE on `loop._handler.cqes_this_wake_count = 0`
    # at the bench loop site (compiler crash via libstdc++ unwind, not a
    # source-level error). Functionally equivalent.
    fn snapshot_and_reset_cqes_per_wake(mut self) -> UInt64:
        var n = self.cqes_this_wake_count
        self.cqes_this_wake_count = UInt64(0)
        return n

    def _dispatch(mut self, token: UInt64, result: Int32, flags: UInt32) raises:
        var op_kind = UInt8(token & 0xFF)

        if op_kind == OP_RECVMSG:
            self._handle_recvmsg(result, flags)
        elif op_kind == OP_SENDMSG:
            var slot_idx = token >> 8
            self._handle_sendmsg(slot_idx, result)
        elif op_kind == OP_TIMEOUT:
            self._handle_timeout(result)
        elif op_kind == OP_PROVIDE_BUF:
            pass  # provide_buffers completion — nothing to do

    # --- multishot recvmsg path ---

    def _handle_recvmsg(mut self, result: Int32, flags: UInt32) raises:
        # Check if multishot is still active.
        if (flags & UInt32(IORING_CQE_F_MORE)) == 0:
            self.multishot_active = False
            self.multishot_term_count += UInt64(1)

        # Error or cancelled — nothing to process.
        if result <= 0:
            self.enobufs_count += UInt64(1)
            return

        # Must have a buffer attached.
        if (flags & UInt32(IORING_CQE_F_BUFFER)) == 0:
            return

        # Extract buffer ID from CQE flags.
        var buf_id = UInt16(flags >> UInt32(IORING_CQE_BUFFER_SHIFT))
        var buf_ptr = self.pbuf_pool + Int(buf_id) * PBUF_SIZE

        # Parse io_uring_recvmsg_out header (16 bytes):
        # [namelen: u32][controllen: u32][payloadlen: u32][flags: u32]
        if result < Int32(RECVMSG_OUT_HDR_SIZE):
            # Too short for header — return buffer.
            self.consumed_bufs.append(buf_id)
            return

        # Q4: count datagrams per recvmsg CQE. With io_uring multishot recvmsg,
        # each CQE carries exactly 1 datagram, so n=1 every call. The verdict
        # signal is whether this histogram shape differs from a hypothetical
        # `recvmmsg`-batched baseline. Plan: 2026-05-03-q4-fresh-conn-cpu-decomposition.
        # H3UdpHandler embeds AcceptProfile directly (line 511) — no pointer
        # indirection; call record_recv_batch on self.profile under the comptime gate.
        @parameter
        if PROFILE_ACCEPT:
            self.profile.record_recv_batch(1)
            # Q7 H_C: 8-bucket recvmsg batch histogram (raw shape, distinct
            # from Q4's per-flush total). With io_uring multishot recvmsg,
            # n=1 every CQE — bucket-0-dominant is itself H_C-positive evidence.
            # Plan: 2026-05-04-q7-cold-handshake-cpu-utilization-decomposition §3 T2.
            self.profile.record_recvmsg_batch_size(1)
        var namelen = Int(_read_u32_le(buf_ptr))
        var controllen = Int(_read_u32_le(buf_ptr + 4))
        var payloadlen = Int(_read_u32_le(buf_ptr + 8))
        var msg_flags = _read_u32_le(buf_ptr + 12)

        # Check MSG_TRUNC (0x20) — drop truncated datagrams.
        if (msg_flags & UInt32(0x20)) != 0:
            self.consumed_bufs.append(buf_id)
            return

        # Address starts after the 16-byte header.
        var addr_offset = RECVMSG_OUT_HDR_SIZE
        var addr_len = namelen

        # Payload starts after header + name + control.
        var payload_offset = RECVMSG_OUT_HDR_SIZE + namelen + controllen
        var payload_ptr = buf_ptr + payload_offset

        if payloadlen <= 0:
            self.consumed_bufs.append(buf_id)
            return

        # Extract DCID directly from the provided buffer — no copy.
        var dcid: List[UInt8]
        try:
            dcid = _extract_dcid(Span[UInt8, MutAnyOrigin](ptr=payload_ptr, length=payloadlen))
        except:
            # Bad packet — return buffer.
            self.consumed_bufs.append(buf_id)
            return

        # Build address key for connection demux. Stored as String — re-looked-up
        # in _flush_impl since timeout completions in the same poll batch may
        # swap-and-pop conn_h3s, invalidating any cached index.
        var addr_bytes = List[UInt8](capacity=addr_len)
        for i in range(addr_len):
            addr_bytes.append(buf_ptr[addr_offset + i])
        var key = _addr_to_key(addr_bytes)

        var stamp_us: UInt64 = UInt64(0)
        @parameter
        if PROFILE_ACCEPT:
            stamp_us = profile_monotonic_us()

        self.pending_rx.append(
            PendingDatagram(
                buf_id=buf_id,
                buf_ptr=buf_ptr,
                payload_ptr=payload_ptr,
                payload_len=payloadlen,
                addr_offset=addr_offset,
                addr_len=addr_len,
                addr_key=key^,
                dcid=dcid^,
                arrival_us=stamp_us,
            )
        )

    # --- drain-extension (userspace recvfrom-until-EAGAIN) ---

    def _drain_extension(mut self) raises -> Tuple[UInt64, Bool]:
        """Userspace recvfrom-until-EAGAIN drain on `self.udp_fd`.

        Diagnostic-pass implementation per
        `specs/2026-05-05-quic-bench-drain-extension.md` §3. Each successful
        recvfrom() appends a `PendingDatagram` to `self.pending_rx` with
        sentinel `buf_id == DRAIN_BUF_ID_SENTINEL` so the existing flush loop
        skips returning the buf to the kernel buf-ring (these bufs are owned
        by `drain_scratch_pool`, not the io_uring provided-buffer-ring).

        Returns `(datagrams_pulled, overflowed_pool)`. `overflowed_pool=True`
        means the scratch pool was exhausted before the kernel returned
        EAGAIN; remaining datagrams stay queued for the next poll cycle.

        Wiring into `_flush_impl` is T3's job; this method is dead code under
        `DRAIN_TO_EAGAIN=False`.
        """
        var pulled: UInt64 = 0
        var overflowed: Bool = False
        var pool_idx: Int = 0
        while pool_idx < len(self.drain_scratch_pool):
            var buf_ptr = self.drain_scratch_pool[pool_idx].unsafe_ptr()
            var addr_ptr = self.drain_scratch_addr.unsafe_ptr()
            var addrlen: Int32 = Int32(len(self.drain_scratch_addr))
            var n = external_call["recvfrom", Int64](
                self.udp_fd,
                buf_ptr,
                UInt64(MAX_DATAGRAM_SIZE),
                MSG_DONTWAIT,
                addr_ptr,
                UnsafePointer(to=addrlen),
            )
            if n < 0:
                # Expect EAGAIN(11) — socket drained, exit normally. Anything
                # else is a real error: log once and exit (no errno bookkeeping
                # field on AcceptProfile yet; T1 only added the success-path
                # counters).
                var errno = external_call[
                    "__errno_location", UnsafePointer[Int32, MutAnyOrigin]
                ]()[]
                if errno != EAGAIN_ERRNO:
                    print("h3-bench: drain-ext recvfrom errno=", errno)
                break
            if n == 0:
                # Zero-length datagram — drop and exit (next cycle re-tries).
                break
            # Extract DCID up front; malformed packets are skipped without
            # advancing pool_idx so the same buf is reused on the next iter.
            var dcid: List[UInt8]
            try:
                dcid = _extract_dcid(
                    Span[UInt8, MutAnyOrigin](ptr=buf_ptr, length=Int(n))
                )
            except:
                continue
            # Copy the addr scratch into a per-datagram List so subsequent
            # drain iterations (which reuse `drain_scratch_addr`) cannot
            # overwrite the bytes the demux path will key off.
            var addr_bytes = List[UInt8](capacity=Int(addrlen))
            for i in range(Int(addrlen)):
                addr_bytes.append(addr_ptr[i])
            var key = _addr_to_key(addr_bytes)
            var stamp_us: UInt64 = UInt64(0)
            @parameter
            if PROFILE_ACCEPT:
                stamp_us = profile_monotonic_us()
            self.pending_rx.append(
                PendingDatagram(
                    buf_id=DRAIN_BUF_ID_SENTINEL,
                    buf_ptr=buf_ptr,
                    payload_ptr=buf_ptr,
                    payload_len=Int(n),
                    addr_offset=0,
                    addr_len=Int(addrlen),
                    addr_key=key^,
                    dcid=dcid^,
                    arrival_us=stamp_us,
                )
            )
            pulled += UInt64(1)
            pool_idx += 1
        if pool_idx >= len(self.drain_scratch_pool):
            overflowed = True
        return Tuple(pulled, overflowed)

    # --- on_flush: batch process all pending datagrams ---

    fn on_flush(mut self):
        # Q-IO-1 (spec 2026-05-05-shortconn-io-path-investigation §4.1) —
        # bracket `_flush_impl` to histogram per-wake wall-clock duration.
        # Measures end-to-end `_flush_impl` time only (per-pkt loop + drain
        # hook). Excludes CQE processing in `on_complete` (already finished
        # before we arrive here) and SQE submissions in
        # `_drain_pending_submits` (run in the event loop after this
        # returns). Off-build path elides the brackets entirely.
        var t_flush_start: UInt64 = 0
        @parameter
        if PROFILE_ACCEPT:
            t_flush_start = profile_monotonic_us()
        try:
            self._flush_impl()
        except e:
            print("h3-bench: on_flush error:", e)
        @parameter
        if PROFILE_ACCEPT:
            self.profile.record_flush_impl_us(profile_monotonic_us() - t_flush_start)

    def _flush_impl(mut self) raises:
        # Drain-extension hook (specs/2026-05-05-quic-bench-drain-extension.md §3).
        # When `DRAIN_TO_EAGAIN=True`, pull additional datagrams off the UDP
        # socket via recvfrom(MSG_DONTWAIT) before processing pending_rx so a
        # single flush cycle can absorb burst arrivals the multishot recvmsg
        # ring would otherwise hand out one-per-poll. Off-build is a no-op:
        # the comptime gate elides the call entirely.
        @parameter
        if DRAIN_TO_EAGAIN:
            var drain_result = self._drain_extension()
            @parameter
            if PROFILE_ACCEPT:
                self.profile.record_drain_extension(drain_result[0], drain_result[1])

        var t_busy_start = UInt64(0)
        var n_pkts_at_start = 0
        @parameter
        if PROFILE_ACCEPT:
            t_busy_start = profile_monotonic_us()
            if self.last_flush_end_us > UInt64(0):
                self.profile.record_idle(t_busy_start - self.last_flush_end_us)
            n_pkts_at_start = len(self.pending_rx)

        var now = monotonic_us()

        for i in range(len(self.pending_rx)):
            var pd = self.pending_rx[i].copy()
            var t_pop_dispatch_start: UInt64 = 0
            @parameter
            if PROFILE_ACCEPT:
                t_pop_dispatch_start = profile_monotonic_us()
                self.profile.record_loop_iter()
            @parameter
            if PROFILE_ACCEPT:
                # Queueing wait: now (flush start) - arrival_us (recvmsg ingress).
                # delta is the wall-clock time the packet sat in pending_rx.
                if pd.arrival_us > UInt64(0) and now >= pd.arrival_us:
                    self.profile.record_arrival_lat(now - pd.arrival_us)
                else:
                    self.profile.record_arrival_lat(UInt64(0))
            @parameter
            if PROFILE_ACCEPT:
                self.profile.record_conn_pkt(pd.addr_key)
            # DCID-keyed lookup (migrated from addr_key). pd.dcid was extracted
            # at _handle_recvmsg (long+short header).
            var dcid_u64 = _dcid_to_u64(Span(pd.dcid))
            # Q7 H_B (Mojo-side): bracket demux Dict lookup. Single-boucle Mojo
            # Dict is uncontended; bucket-0-dominant histogram is itself the
            # falsification path for DEMUX-MAP-BOUND (sub-verdict of LOCK-BOUND).
            # Plan: 2026-05-04-q7-cold-handshake-cpu-utilization-decomposition §3 T2.
            var t_dlu_start: UInt64 = 0
            @parameter
            if PROFILE_ACCEPT:
                t_dlu_start = profile_monotonic_us()
            var conn_idx = self._find_conn_by_dcid(dcid_u64)
            @parameter
            if PROFILE_ACCEPT:
                self.profile.record_demux_map_lock_wait_us(profile_monotonic_us() - t_dlu_start)

            # Strict new-conn gate per RFC 9000 §12.4: only long-header Initial
            # packets create new conns. All other DCID-misses are dropped
            # silently (matches TQUIC, quiche, quic-go, aioquic).
            if conn_idx < 0:
                var first_byte_span = Span[UInt8, MutAnyOrigin](
                    ptr=pd.payload_ptr, length=pd.payload_len)
                if not _is_long_header_initial(first_byte_span):
                    # Drain-extension PendingDatagrams use sentinel buf_id; their
                    # bufs come from drain_scratch_pool, not the io_uring buf-ring,
                    # so they must not be reprovisioned to the kernel.
                    if pd.buf_id != DRAIN_BUF_ID_SENTINEL:
                        self.consumed_bufs.append(pd.buf_id)
                    @parameter
                    if PROFILE_ACCEPT:
                        self.profile.record_loop_pop_dispatch(profile_monotonic_us() - t_pop_dispatch_start)
                    continue
                # Fall through to QuicConnection.server(...) construction below.

            @parameter
            if PROFILE_ACCEPT:
                if conn_idx >= 0:
                    if not self.conn_h3s[conn_idx][]._h3._quic.is_expected_dcid(Span(pd.dcid)):
                        try:
                            self.profile.record_dcid_mismatch(pd.addr_key)
                        except:
                            pass

            if conn_idx < 0:
                # Create new QUIC connection. DCID was already extracted in
                # _handle_recvmsg and travels in PendingDatagram.
                var tp = default_transport_params()
                var dcid_copy = List[UInt8](copy=pd.dcid)
                var quic: QuicConnection
                # Q9 alloc_quic_state_us bracket — outer wall-clock of
                # QuicConnection.server (INCLUDES inner alloc_tls_handle_us
                # FFI bracket recorded inside connection.mojo:server).
                var t_qstate_start: UInt64 = 0
                @parameter
                if PROFILE_ACCEPT:
                    t_qstate_start = profile_monotonic_us()
                try:
                    @parameter
                    if PROFILE_ACCEPT:
                        quic = QuicConnection.server(
                            self.lib_addr,
                            self.server_config,
                            tp,
                            Span(pd.dcid),
                            Span(dcid_copy),
                            now,
                            UnsafePointer(to=self.profile),
                        )
                    else:
                        quic = QuicConnection.server(
                            self.lib_addr,
                            self.server_config,
                            tp,
                            Span(pd.dcid),
                            Span(dcid_copy),
                            now,
                        )
                except e:
                    self.quic_server_err_count += UInt64(1)
                    if not self.quic_server_err_first:
                        self.quic_server_err_first = True
                        print("h3-bench DIAG: first QuicConnection.server error:", e)
                    if pd.buf_id != DRAIN_BUF_ID_SENTINEL:
                        self.consumed_bufs.append(pd.buf_id)
                    @parameter
                    if PROFILE_ACCEPT:
                        self.profile.record_loop_pop_dispatch(profile_monotonic_us() - t_pop_dispatch_start)
                    continue
                @parameter
                if PROFILE_ACCEPT:
                    self.profile.record_alloc_quic_state_us(profile_monotonic_us() - t_qstate_start)

                # B-permissive dual-DCID extract (BEFORE quic^ is moved into
                # H3HandlerServer): both initial_dcid (client's random ICID)
                # and local_cid (server's chosen SCID) map to the same
                # conn_idx. Both stay until conn teardown.
                #
                # 8-byte invariant locked by tests/test_quic_connection.mojo
                # (test_quic_connection_dcid_lengths_are_8_bytes).
                debug_assert(len(quic.initial_dcid) == 8, "initial_dcid != 8 bytes")
                debug_assert(len(quic.local_cid) == 8, "local_cid != 8 bytes")

                var icid_u64 = _dcid_to_u64(Span(quic.initial_dcid))
                var lcid_u64 = _dcid_to_u64(Span(quic.local_cid))

                var handler = BenchHandler(self.state_ptr)
                var h3: H3HandlerServer[BenchHandler]
                # Q9 alloc_h3_state_us bracket — H3HandlerServer ctor wall-clock
                # (QPACK encoder/decoder init, stream maps, etc.).
                var t_h3state_start: UInt64 = 0
                @parameter
                if PROFILE_ACCEPT:
                    t_h3state_start = profile_monotonic_us()
                try:
                    @parameter
                    if PROFILE_ACCEPT:
                        h3 = H3HandlerServer[BenchHandler](
                            quic=quic^,
                            handler=handler^,
                            profile_ptr=UnsafePointer(to=self.profile),
                        )
                    else:
                        h3 = H3HandlerServer[BenchHandler](
                            quic=quic^,
                            handler=handler^,
                        )
                except e:
                    self.h3_handler_err_count += UInt64(1)
                    if self.h3_handler_err_count == UInt64(1):
                        print("h3-bench DIAG: first H3HandlerServer error:", e)
                    if pd.buf_id != DRAIN_BUF_ID_SENTINEL:
                        self.consumed_bufs.append(pd.buf_id)
                    @parameter
                    if PROFILE_ACCEPT:
                        self.profile.record_loop_pop_dispatch(profile_monotonic_us() - t_pop_dispatch_start)
                    continue
                @parameter
                if PROFILE_ACCEPT:
                    self.profile.record_alloc_h3_state_us(profile_monotonic_us() - t_h3state_start)

                var h3_ptr = _heap_alloc[H3HandlerServer[BenchHandler]](1).as_any_origin()
                h3_ptr.init_pointee_move(h3^)

                # Build address from buffer for the new connection.
                var addr = List[UInt8](capacity=pd.addr_len)
                for j in range(pd.addr_len):
                    addr.append(pd.buf_ptr[pd.addr_offset + j])

                # Q9 bench_dict_insert_us bracket — conn_dcid_map dual-DCID
                # insert + 3 parallel-list appends + dcids List build.
                var t_dict_start: UInt64 = 0
                @parameter
                if PROFILE_ACCEPT:
                    t_dict_start = profile_monotonic_us()
                conn_idx = len(self.conn_h3s)
                self.conn_dcid_map[icid_u64] = conn_idx
                self.conn_dcid_map[lcid_u64] = conn_idx
                self.conn_h3s.append(h3_ptr)
                self.conn_addrs.append(addr^)

                var dcids = List[UInt64]()
                dcids.append(icid_u64)
                dcids.append(lcid_u64)
                self.conn_dcids.append(dcids^)
                @parameter
                if PROFILE_ACCEPT:
                    self.profile.record_bench_dict_insert_us(profile_monotonic_us() - t_dict_start)

            @parameter
            if PROFILE_ACCEPT:
                self.profile.record_loop_pop_dispatch(profile_monotonic_us() - t_pop_dispatch_start)
            # Feed datagram to the connection.
            try:
                self.conn_h3s[conn_idx][].feed_datagram_from_buffer(pd.payload_ptr, pd.payload_len, now)
            except e:
                self.feed_datagram_err_count += UInt64(1)
                if self.feed_datagram_err_count == UInt64(1):
                    print("h3-bench DIAG: first feed_datagram_from_buffer error:", e)

            var t_post_pkt_start: UInt64 = 0
            @parameter
            if PROFILE_ACCEPT:
                t_post_pkt_start = profile_monotonic_us()
            @parameter
            if PROFILE_ACCEPT:
                # Poll handshake-complete state; idempotent record.
                # is_established() flips True only after CONN_ESTABLISHED bit is
                # set atomically with QuicEvent.handshake_complete() event
                # (verified at src/quic/connection.mojo:1779-1786).
                if self.conn_h3s[conn_idx][]._h3.is_established():
                    self.profile.record_conn_hs_complete(pd.addr_key)

            # Update peer address.
            var addr_update = List[UInt8](capacity=pd.addr_len)
            for j in range(pd.addr_len):
                addr_update.append(pd.buf_ptr[pd.addr_offset + j])
            self.conn_addrs[conn_idx] = addr_update^

            @parameter
            if PROFILE_ACCEPT:
                self.profile.record_loop_post_pkt(profile_monotonic_us() - t_post_pkt_start)
            # Drain and send outgoing datagrams.
            var t_drain_start = UInt64(0)
            @parameter
            if PROFILE_ACCEPT:
                t_drain_start = profile_monotonic_us()
            try:
                self._drain_and_send(conn_idx, now)
            except:
                pass
            @parameter
            if PROFILE_ACCEPT:
                var drain_us = profile_monotonic_us() - t_drain_start
                self.profile.record_drain(drain_us)

            # Save buf_id for reprovision in main loop. Skip sentinel: drain-
            # extension bufs are owned by drain_scratch_pool, not the buf-ring.
            if pd.buf_id != DRAIN_BUF_ID_SENTINEL:
                self.consumed_bufs.append(pd.buf_id)

        var t_teardown_start: UInt64 = 0
        @parameter
        if PROFILE_ACCEPT:
            t_teardown_start = profile_monotonic_us()
        self.pending_rx.clear()
        @parameter
        if PROFILE_ACCEPT:
            self.profile.record_loop_teardown(profile_monotonic_us() - t_teardown_start)

        @parameter
        if PROFILE_ACCEPT:
            var t_busy_end = profile_monotonic_us()
            self.profile.record_flush(n_pkts_at_start, t_busy_end - t_busy_start)
            self.last_flush_end_us = t_busy_end

        @parameter
        if PROFILE_ACCEPT:
            if _profile_dump_pending():
                # Timeout sweep: count surviving non-established conns
                # (B9 already counted evicted ones).
                for i in range(len(self.conn_h3s)):
                    if not self.conn_h3s[i][]._h3.is_established():
                        self.profile.record_handshake_timeout(UInt64(1))
                # Write text report to stderr-equivalent (stdout is fine
                # for the bench; B11 will add structured JSON sidecar).
                print(self.profile.report_text(), end="")
                # Plan C diagnostic: surface kernel-level recvmsg drops + multishot terminations + silent error swallows.
                print("=== Plan C diagnostic counters ===")
                print("  recvmsg drops (result<=0):       " + String(self.enobufs_count))
                print("  multishot terminations:          " + String(self.multishot_term_count))
                print("  QuicConnection.server errors:    " + String(self.quic_server_err_count))
                print("  H3HandlerServer ctor errors:     " + String(self.h3_handler_err_count))
                print("  feed_datagram_from_buffer errs:  " + String(self.feed_datagram_err_count))
                print("=== end ===")
                self._write_profile_json_sidecar()
                # Exit cleanly via libc exit().
                _ = external_call["exit", NoneType](Int32(0))

    def _drain_and_send(mut self, conn_idx: Int, now: UInt64) raises:
        """Drain outgoing datagrams from a connection and queue sendmsg."""
        var datagrams = self.conn_h3s[conn_idx][].drain_datagrams(now)
        for i in range(len(datagrams)):
            var pkt = List[UInt8](copy=datagrams[i])
            if len(pkt) == 0:
                continue

            var tx_id = self.next_tx_id
            self.next_tx_id += 1
            var token = _encode_token(tx_id, OP_SENDMSG)

            var addr_copy = List[UInt8](copy=self.conn_addrs[conn_idx])

            # Q8 Phase 2 — slot acquisition: pop pointer from freelist when
            # EGRESS_POOL_V2 is on; fall back to fresh alloc on miss. The
            # legacy `UdpTxSlot(data, addr)` ctor still runs via
            # init_pointee_move (allocates 4 inner heap buffers), so the
            # savings are limited to the slot-struct heap-alloc itself.
            var tx_ptr: UnsafePointer[UdpTxSlot, MutAnyOrigin]
            var from_pool: Bool = False
            @parameter
            if EGRESS_POOL_V2:
                if len(self.egress_pool_v2_freelist) > 0:
                    tx_ptr = self.egress_pool_v2_freelist.pop()
                    tx_ptr.init_pointee_move(UdpTxSlot(pkt^, addr_copy))
                    from_pool = True
                    @parameter
                    if PROFILE_ACCEPT:
                        self.profile.record_egress_pool_hit()
                else:
                    tx_ptr = _heap_alloc[UdpTxSlot](1).as_any_origin()
                    tx_ptr.init_pointee_move(UdpTxSlot(pkt^, addr_copy))
                    @parameter
                    if PROFILE_ACCEPT:
                        self.profile.record_egress_pool_miss()
            else:
                tx_ptr = _heap_alloc[UdpTxSlot](1).as_any_origin()
                tx_ptr.init_pointee_move(UdpTxSlot(pkt^, addr_copy))

            var slot_idx = len(self.tx_slots)
            self.tx_slots.append(tx_ptr)
            self.tx_slot_tokens.append(token)
            # Parallel-List source tracking — gated to preserve off-build
            # bit-identity (FR-4.6).
            @parameter
            if EGRESS_POOL_V2:
                self.tx_slot_from_pool.append(from_pool)
            self.tx_slot_idx_by_token[token] = slot_idx

            self.pending_submits.append(
                PendingSubmit(kind=_SUBMIT_SENDMSG, slot_idx=tx_id)
            )

    # --- sendmsg path ---

    def _handle_sendmsg(mut self, tx_id: UInt64, result: Int32) raises:
        # O(1) lookup via the token→idx map.
        var token = _encode_token(tx_id, OP_SENDMSG)
        if token not in self.tx_slot_idx_by_token:
            return
        var idx = self.tx_slot_idx_by_token[token]

        # Free the TX slot buffers; return pool-sourced slot pointers to the
        # freelist instead of calling ptr.free() — the slot-struct memory
        # stays alive for the next reuse cycle (Q8 Phase 2).
        var ptr = self.tx_slots[idx]
        @parameter
        if EGRESS_POOL_V2:
            var was_pooled = self.tx_slot_from_pool[idx]
            if was_pooled:
                ptr[].free()
                self.egress_pool_v2_freelist.append(ptr)
            else:
                ptr[].free()
                ptr.free()
        else:
            ptr[].free()
            ptr.free()

        # Swap-and-pop. Update the dict for the slot that moves into
        # position `idx`, and remove the entry for the freed token.
        var last = len(self.tx_slots) - 1
        if idx != last:
            var moved_token = self.tx_slot_tokens[last]
            self.tx_slots[idx] = self.tx_slots[last]
            self.tx_slot_tokens[idx] = moved_token
            @parameter
            if EGRESS_POOL_V2:
                self.tx_slot_from_pool[idx] = self.tx_slot_from_pool[last]
            self.tx_slot_idx_by_token[moved_token] = idx
        _ = self.tx_slots.pop()
        _ = self.tx_slot_tokens.pop()
        @parameter
        if EGRESS_POOL_V2:
            _ = self.tx_slot_from_pool.pop()
        _ = self.tx_slot_idx_by_token.pop(token)

        # Q7 H_C: 8-bucket sendmsg batch histogram. Mojo-net's sendmsg path is
        # per-packet (one CQE per datagram) — bucket-0-dominant histogram is
        # itself H_C-positive evidence vs a hypothetical sendmmsg-batched path.
        # Plan: 2026-05-04-q7-cold-handshake-cpu-utilization-decomposition §3 T2.
        @parameter
        if PROFILE_ACCEPT:
            self.profile.record_sendmsg_batch_size(1)

    # --- timeout path ---

    def _handle_timeout(mut self, result: Int32) raises:
        var now = monotonic_us()

        # Drain all connections — they may have pending retransmissions.
        var i = 0
        while i < len(self.conn_h3s):
            # Drain datagrams for this connection.
            try:
                self._drain_and_send(i, now)
            except:
                pass

            # Close dead connections (swap-and-pop).
            if self.conn_h3s[i][].should_close():
                @parameter
                if PROFILE_ACCEPT:
                    if not self.conn_h3s[i][]._h3.is_established():
                        self.profile.record_handshake_timeout(UInt64(1))
                var ptr = self.conn_h3s[i]
                ptr.destroy_pointee()
                ptr.free()

                # B-permissive teardown: pop ALL of dying conn's DCID entries
                # (typically 2: initial_dcid + local_cid). The pre-migration
                # single-DCID single-pop with first-match-break is incorrect
                # for the dual-key shape.
                for dcid_u64 in self.conn_dcids[i]:
                    _ = self.conn_dcid_map.pop(dcid_u64)

                var last = len(self.conn_h3s) - 1
                if i != last:
                    # Swap the last element into position i in all parallel
                    # lists (conn_h3s, conn_addrs, conn_dcids).
                    self.conn_h3s[i] = self.conn_h3s[last]
                    self.conn_addrs[i] = List[UInt8](copy=self.conn_addrs[last])
                    self.conn_dcids[i] = List[UInt64](copy=self.conn_dcids[last])

                    # Remap ALL of the swapped-in conn's DCID entries from
                    # `last` → `i`. CRITICAL: do NOT break after first match
                    # (the survivor has 2 entries; both must be remapped).
                    for dcid_u64 in self.conn_dcids[i]:
                        self.conn_dcid_map[dcid_u64] = i

                _ = self.conn_h3s.pop()
                _ = self.conn_addrs.pop()
                _ = self.conn_dcids.pop()
                # Don't increment i — the swapped-in element needs checking.
                continue
            i += 1

        # Re-arm the 50ms timeout.
        self.pending_submits.append(
            PendingSubmit(kind=_SUBMIT_TIMEOUT, slot_idx=UInt64(0))
        )

    def _write_profile_json_sidecar(self) raises:
        """Write profile JSON sidecar to bench/quic_perf/results/profile/.

        Spec §"Report write": dump-pending writes
        ``bench/quic_perf/results/profile/INSTRUMENTATION-<UTC ts>.json``
        containing ``self.profile.report_json()``. Creates the directory
        with mkdir -p semantics if absent.
        """
        # 1. Compute UTC timestamp via time(2) + gmtime_r(3).
        # struct tm layout (Linux glibc): tm_sec, tm_min, tm_hour,
        # tm_mday, tm_mon (0-11), tm_year (since 1900), tm_wday, tm_yday,
        # tm_isdst — 9 Int32 fields = 36 bytes. Allocate 56 bytes to
        # cover tm_gmtoff + tm_zone tail (Linux extension).
        var now_t = external_call["time", Int64](
            UnsafePointer[Int64, MutAnyOrigin]()
        )
        var t_buf = InlineArray[Int64, 1](fill=now_t)
        var tm_buf = InlineArray[UInt8, 56](fill=0)
        var tm_ptr = UnsafePointer(to=tm_buf).bitcast[UInt8]()
        var t_ptr = UnsafePointer(to=t_buf).bitcast[Int64]()
        _ = external_call[
            "gmtime_r", UnsafePointer[UInt8, MutAnyOrigin]
        ](t_ptr, tm_ptr)
        var tm_i32 = UnsafePointer(to=tm_buf).bitcast[Int32]()
        var sec = Int(tm_i32[0])
        var minu = Int(tm_i32[1])
        var hour = Int(tm_i32[2])
        var mday = Int(tm_i32[3])
        var mon = Int(tm_i32[4]) + 1
        var year = Int(tm_i32[5]) + 1900

        # 2. Format yyyymmdd-hhmmss with zero-padding.
        var ts = (
            String(year)
            + _zpad2_int(mon)
            + _zpad2_int(mday)
            + "-"
            + _zpad2_int(hour)
            + _zpad2_int(minu)
            + _zpad2_int(sec)
        )

        # 3. mkdir -p the sidecar directory (ignores EEXIST).
        var dir_path = String("bench/quic_perf/results/profile")
        try:
            mkdir_p(dir_path)
        except e:
            print("h3-bench: profile sidecar mkdir_p failed:", e)
            return

        # 4. Write JSON via interop.file_io.write_file (open/pwrite64/close).
        var path = dir_path + "/INSTRUMENTATION-" + ts + ".json"
        var json_text = self.profile.report_json()
        try:
            write_file(path, json_text.as_bytes())
        except e:
            print("h3-bench: profile sidecar write failed:", path, "err=", e)
            return
        print("h3-bench: profile sidecar written:", path)


# ── _drain_pending_submits ───────────────────────────────────────────


def _drain_pending_submits(mut loop: BatchCompletionLoop[H3UdpHandler]) raises:
    var submits = loop._handler.pending_submits^
    loop._handler.pending_submits = List[PendingSubmit]()

    for i in range(len(submits)):
        var s = submits[i].copy()

        if s.kind == _SUBMIT_SENDMSG:
            # O(1) lookup via the token→idx map.
            var tx_id = s.slot_idx
            var token = _encode_token(tx_id, OP_SENDMSG)
            if token not in loop._handler.tx_slot_idx_by_token:
                continue
            var tx_idx = loop._handler.tx_slot_idx_by_token[token]
            var msghdr_addr = Int(loop._handler.tx_slots[tx_idx][].msghdr_buf)
            var msghdr_ptr = UnsafePointer[c_void, StaticConstantOrigin](
                unsafe_from_address=msghdr_addr
            )
            try:
                loop.submit_sendmsg(loop._handler.udp_fd, msghdr_ptr, token)
            except:
                loop._handler.pending_submits.append(s.copy())

        elif s.kind == _SUBMIT_TIMEOUT:
            var ts_addr = Int(loop._handler.timeout_ts)
            var ts_ptr = UnsafePointer[c_void, StaticConstantOrigin](
                unsafe_from_address=ts_addr
            )
            var token = _encode_token(UInt64(0), OP_TIMEOUT)
            try:
                loop.submit_timeout(ts_ptr, token)
            except:
                loop._handler.pending_submits.append(s.copy())


# ── _setup_udp_socket ────────────────────────────────────────────────


comptime AF_INET6: Int32 = 10
comptime SOCK_DGRAM: Int32 = 2


def _setup_udp_socket(port: Int) raises -> Int32:
    """Create a dual-stack UDP socket bound to [::]:port via raw syscalls."""
    var fd = external_call["socket", Int32](AF_INET6, SOCK_DGRAM, Int32(0))
    if fd < 0:
        raise "_setup_udp_socket: socket() failed"

    var optval = _heap_alloc[UInt8](4).as_any_origin()

    # SO_REUSEADDR = 1
    optval[0] = 1
    optval[1] = 0
    optval[2] = 0
    optval[3] = 0
    var sso = external_call["setsockopt", Int32](
        fd, SOL_SOCKET, SO_REUSEADDR, optval, Int32(4)
    )
    if sso < 0:
        optval.free()
        raise "setsockopt(SO_REUSEADDR) failed"

    # SO_REUSEPORT for multi-worker support
    optval[0] = 1
    optval[1] = 0
    optval[2] = 0
    optval[3] = 0
    var rp = external_call["setsockopt", Int32](
        fd, SOL_SOCKET, SO_REUSEPORT, optval, Int32(4)
    )
    if rp < 0:
        optval.free()
        raise "setsockopt(SO_REUSEPORT) failed"

    # IPV6_V6ONLY = 0 (dual-stack)
    optval[0] = 0
    var v6o = external_call["setsockopt", Int32](
        fd, IPPROTO_IPV6, IPV6_V6ONLY, optval, Int32(4)
    )
    optval.free()
    if v6o < 0:
        raise "setsockopt(IPV6_V6ONLY) failed"

    # sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16) + scope_id(4) = 28
    var addr = _heap_alloc[UInt8](ADDR_SIZE).as_any_origin()
    for i in range(ADDR_SIZE):
        addr[i] = 0
    # sin6_family = AF_INET6 (10) — little-endian u16
    addr[0] = 10
    addr[1] = 0
    # sin6_port — big-endian u16
    var port_be = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    addr[2] = UInt8(port_be & 0xFF)
    addr[3] = UInt8((port_be >> 8) & 0xFF)

    var rc = external_call["bind", Int32](fd, addr, Int32(ADDR_SIZE))
    addr.free()
    if rc < 0:
        _ = external_call["close", Int32](fd)
        raise "_setup_udp_socket: bind() failed on port " + String(port)

    return fd


# ── main ─────────────────────────────────────────────────────────────


def main() raises:
    # Load static files from STATIC_DIR env var (default /data/static).
    var static_dir_opt = getenv_opt("STATIC_DIR")
    var static_dir: String
    if static_dir_opt.__bool__():
        static_dir = static_dir_opt.value()
    else:
        static_dir = String("/data/static")
    var cache = _load_static_files(static_dir)

    # Load dataset for the /json profile from DATA_DIR (default /data).
    var data_dir_opt = getenv_opt("DATA_DIR")
    var data_dir: String
    if data_dir_opt.__bool__():
        data_dir = data_dir_opt.value()
    else:
        data_dir = String("/data")
    var dataset = _load_dataset(data_dir + "/dataset.json")

    # Heap-allocate combined bench state.
    var bstate = BenchState(static_cache=cache^, dataset=dataset^)
    var state_ptr = _heap_alloc[BenchState](1).as_any_origin()
    state_ptr.init_pointee_move(bstate^)

    # Load TLS library and create server config.
    var certs_dir_opt = getenv_opt("CERTS_DIR")
    var certs_dir: String
    if certs_dir_opt.__bool__():
        certs_dir = certs_dir_opt.value()
    else:
        certs_dir = String("certs")

    var lib = RustlsLibrary()
    var lib_ptr = _heap_alloc[RustlsLibrary](1).as_any_origin()
    lib_ptr.init_pointee_move(lib^)
    var lib_addr = UInt64(Int(lib_ptr))

    var server_config = _create_server_config(lib_ptr, "h3", certs_dir)

    # Create UDP socket.
    var port = 8443
    var udp_fd = _setup_udp_socket(port)

    var worker_id_opt = getenv_opt("BENCH_WORKER_ID")
    var prefix: String
    if worker_id_opt.__bool__():
        prefix = "[h3-w" + worker_id_opt.value() + "] "
    else:
        prefix = ""
    print(prefix + "h3-bench: listening on https://[::]:" + String(port) + " (UDP/QUIC/H3)")

    # Q-IO-1 (spec 2026-05-05-shortconn-io-path-investigation §4.1, §5
    # Lever A): runtime-configurable `wait_nr` for the io_uring
    # `submit_and_wait` floor. Default 1 preserves existing behavior so
    # off-knob baselines are bit-identical to pre-spec runs. Range
    # [1, 256] — 1 matches the pre-T1 hardcoded site at line 1622; 256
    # is a safe upper clamp (the SQ ring is 4096; setting wait_nr above
    # the ring depth would deadlock the loop). T2 sweeps this knob to
    # decide the optimum; T1 (instrumentation only) lands the knob.
    var wait_nr_opt = getenv_opt("BENCH_WAIT_NR")
    var wait_nr_runtime: UInt32 = UInt32(1)
    if wait_nr_opt.__bool__():
        try:
            var parsed = Int(wait_nr_opt.value())
            if parsed < 1:
                parsed = 1
            elif parsed > 256:
                parsed = 256
            wait_nr_runtime = UInt32(parsed)
        except:
            print(prefix + "h3-bench: BENCH_WAIT_NR parse failed, using default 1")
            wait_nr_runtime = UInt32(1)
    print(prefix + "h3-bench: BENCH_WAIT_NR=" + String(wait_nr_runtime))

    # Plan B: install SIGINT/SIGTERM handler so that Ctrl-C / kill
    # triggers a profile dump + clean exit at the next flush boundary.
    # Off-build: zero overhead (no comptime branch elided at compile time).
    @parameter
    if PROFILE_ACCEPT:
        _profile_install_signal_handlers()

    # Build handler + loop.
    var handler = H3UdpHandler(
        udp_fd=udp_fd,
        state_ptr=state_ptr,
        lib_addr=lib_addr,
        server_config=server_config,
    )
    var loop = BatchCompletionLoop[H3UdpHandler](handler^, sq_entries=4096)

    # Register provided buffer pool with io_uring.
    var provide_token = _encode_token(UInt64(0), OP_PROVIDE_BUF)
    loop.provide_buffers(loop._handler.pbuf_pool, PBUF_SIZE, PBUF_COUNT, PBUF_GROUP_ID, UInt16(0), provide_token)

    # Submit one multishot recvmsg using the msghdr template.
    var msghdr_addr = Int(loop._handler.msghdr_template)
    var msghdr_ptr = UnsafePointer[c_void, StaticConstantOrigin](
        unsafe_from_address=msghdr_addr
    )
    var recvmsg_token = _encode_token(UInt64(0), OP_RECVMSG)
    loop.submit_recvmsg_multishot(udp_fd, msghdr_ptr, PBUF_GROUP_ID, recvmsg_token)
    loop._handler.multishot_active = True

    # Submit initial timeout.
    var ts_addr = Int(loop._handler.timeout_ts)
    var ts_ptr = UnsafePointer[c_void, StaticConstantOrigin](
        unsafe_from_address=ts_addr
    )
    loop.submit_timeout(ts_ptr, _encode_token(UInt64(0), OP_TIMEOUT))

    # Event loop.
    while True:
        # Q7 H_F: bracket the canonical io_uring park site (loop.poll calls
        # BatchCompletionLoop._ring.submit_and_wait internally). Q-IO-1
        # (spec 2026-05-05-shortconn-io-path-investigation §4.1) promoted
        # the bracket from total-only to total + 24-bucket pow2 histogram
        # (work happens inside `record_iouring_park_us`).
        # Plan: 2026-05-04-q7-cold-handshake-cpu-utilization-decomposition §3 T2.
        var t_park_start: UInt64 = 0
        @parameter
        if PROFILE_ACCEPT:
            t_park_start = profile_monotonic_us()
        # Q-IO-1: BENCH_WAIT_NR env-var runtime knob (parsed in main()).
        # Default 1 = pre-spec hardcoded value. Range [1, 256].
        loop.poll(wait_nr=wait_nr_runtime)
        @parameter
        if PROFILE_ACCEPT:
            loop._handler.profile.record_iouring_park_us(profile_monotonic_us() - t_park_start)
            # Q-IO-1: snapshot+reset via method (Mojo 0.26.2 mojox ICEs on the
            # equivalent direct field write `loop._handler.<field> = 0`).
            var cqes_this_wake = loop._handler.snapshot_and_reset_cqes_per_wake()
            loop._handler.profile.record_cqes_per_wake(cqes_this_wake)

        # Re-provide consumed buffers.
        var consumed = loop._handler.consumed_bufs^
        loop._handler.consumed_bufs = List[UInt16]()
        for i in range(len(consumed)):
            var bid = consumed[i]
            var buf_base = loop._handler.pbuf_pool + Int(bid) * PBUF_SIZE
            # Kernel overwrites the buffer on recvmsg — no need to zero.
            var rprov_token = _encode_token(UInt64(bid), OP_PROVIDE_BUF)
            loop.reprovide_buffer(buf_base, PBUF_SIZE, PBUF_GROUP_ID, bid, rprov_token)

        # Re-arm multishot recvmsg if it ended.
        if not loop._handler.multishot_active:
            var ms_addr = Int(loop._handler.msghdr_template)
            var ms_ptr = UnsafePointer[c_void, StaticConstantOrigin](
                unsafe_from_address=ms_addr
            )
            var ms_token = _encode_token(UInt64(0), OP_RECVMSG)
            loop.submit_recvmsg_multishot(udp_fd, ms_ptr, PBUF_GROUP_ID, ms_token)
            loop._handler.multishot_active = True

        # Drain pending sendmsg/timeout submits.
        # Q-IO-1 (spec 2026-05-05-shortconn-io-path-investigation §4.1) —
        # bracket _drain_pending_submits to close the AC3 wall-clock budget
        # (`park + flush_impl + drain_submits ≈ wall_clock`). Total-only;
        # bucket emit deferred to T2 if AC3 fails.
        var t_dsubmit_start: UInt64 = 0
        @parameter
        if PROFILE_ACCEPT:
            t_dsubmit_start = profile_monotonic_us()
        _drain_pending_submits(loop)
        @parameter
        if PROFILE_ACCEPT:
            loop._handler.profile.record_drain_submits_us(profile_monotonic_us() - t_dsubmit_start)

        # Q7 H_A: 100ms-cadence gauge sampling (active_drive_count, in-flight HS).
        # Plan: 2026-05-04-q7-cold-handshake-cpu-utilization-decomposition §3 T2.
        @parameter
        if PROFILE_ACCEPT:
            loop._handler.profile.tick_profile_gauges(profile_monotonic_us())
