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
from src.quic.profile import AcceptProfile, PROFILE_ACCEPT, monotonic_us as profile_monotonic_us

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

    def __init__(out self, buf_id: UInt16, buf_ptr: UnsafePointer[UInt8, MutAnyOrigin],
                 payload_ptr: UnsafePointer[UInt8, MutAnyOrigin], payload_len: Int,
                 addr_offset: Int, addr_len: Int, var addr_key: String, var dcid: List[UInt8]):
        self.buf_id = buf_id
        self.buf_ptr = buf_ptr
        self.payload_ptr = payload_ptr
        self.payload_len = payload_len
        self.addr_offset = addr_offset
        self.addr_len = addr_len
        self.addr_key = addr_key^
        self.dcid = dcid^

    def __init__(out self, *, other: Self):
        self.buf_id = other.buf_id
        self.buf_ptr = other.buf_ptr
        self.payload_ptr = other.payload_ptr
        self.payload_len = other.payload_len
        self.addr_offset = other.addr_offset
        self.addr_len = other.addr_len
        self.addr_key = String(other.addr_key)
        self.dcid = List[UInt8](copy=other.dcid)

    def __init__(out self, *, deinit take: Self):
        self.buf_id = take.buf_id
        self.buf_ptr = take.buf_ptr
        self.payload_ptr = take.payload_ptr
        self.payload_len = take.payload_len
        self.addr_offset = take.addr_offset
        self.addr_len = take.addr_len
        self.addr_key = take.addr_key^
        self.dcid = take.dcid^


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
    var conn_map: Dict[String, Int]
    var conn_h3s: List[UnsafePointer[H3HandlerServer[BenchHandler], MutAnyOrigin]]
    var conn_addrs: List[List[UInt8]]
    var pbuf_pool: UnsafePointer[UInt8, MutAnyOrigin]
    var pending_rx: List[PendingDatagram]
    var multishot_active: Bool
    var consumed_bufs: List[UInt16]
    var msghdr_template: UnsafePointer[UInt8, MutAnyOrigin]
    var tx_slots: List[UnsafePointer[UdpTxSlot, MutAnyOrigin]]
    var tx_slot_tokens: List[UInt64]
    var tx_slot_idx_by_token: Dict[UInt64, Int]
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

    def __init__(
        out self,
        udp_fd: Int32,
        state_ptr: UnsafePointer[BenchState, MutAnyOrigin],
        lib_addr: UInt64,
        server_config: Int32,
    ):
        self.udp_fd = udp_fd
        self.conn_map = Dict[String, Int]()
        self.conn_h3s = List[UnsafePointer[H3HandlerServer[BenchHandler], MutAnyOrigin]]()
        self.conn_addrs = List[List[UInt8]]()
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

    def __init__(out self, *, deinit take: Self):
        self.udp_fd = take.udp_fd
        self.conn_map = take.conn_map^
        self.conn_h3s = take.conn_h3s^
        self.conn_addrs = take.conn_addrs^
        self.pbuf_pool = take.pbuf_pool
        self.pending_rx = take.pending_rx^
        self.multishot_active = take.multishot_active
        self.consumed_bufs = take.consumed_bufs^
        self.msghdr_template = take.msghdr_template
        self.tx_slots = take.tx_slots^
        self.tx_slot_tokens = take.tx_slot_tokens^
        self.tx_slot_idx_by_token = take.tx_slot_idx_by_token^
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

    # --- Conn lookup ---

    def _find_conn(self, key: String) -> Int:
        if key in self.conn_map:
            try:
                return self.conn_map[key]
            except:
                return -1
        return -1

    # --- on_complete dispatch ---

    fn on_complete(mut self, token: UInt64, result: Int32, flags: UInt32):
        try:
            self._dispatch(token, result, flags)
        except e:
            print("h3-bench: on_complete error:", e)

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
            )
        )

    # --- on_flush: batch process all pending datagrams ---

    fn on_flush(mut self):
        try:
            self._flush_impl()
        except e:
            print("h3-bench: on_flush error:", e)

    def _flush_impl(mut self) raises:
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
            # Re-lookup conn_idx by addr_key — the index recorded at
            # _handle_recvmsg time may be stale if a timeout completion
            # in the same poll batch did swap-and-pop on conn_h3s.
            var conn_idx = self._find_conn(pd.addr_key)

            if conn_idx < 0:
                # Create new QUIC connection. DCID was already extracted in
                # _handle_recvmsg and travels in PendingDatagram.
                var tp = default_transport_params()
                var dcid_copy = List[UInt8](copy=pd.dcid)
                var quic: QuicConnection
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
                    self.consumed_bufs.append(pd.buf_id)
                    continue

                var handler = BenchHandler(self.state_ptr)
                var h3: H3HandlerServer[BenchHandler]
                try:
                    h3 = H3HandlerServer[BenchHandler](quic=quic^, handler=handler^)
                except e:
                    self.h3_handler_err_count += UInt64(1)
                    if self.h3_handler_err_count == UInt64(1):
                        print("h3-bench DIAG: first H3HandlerServer error:", e)
                    self.consumed_bufs.append(pd.buf_id)
                    continue

                var h3_ptr = _heap_alloc[H3HandlerServer[BenchHandler]](1).as_any_origin()
                h3_ptr.init_pointee_move(h3^)

                # Build address from buffer for the new connection.
                var addr = List[UInt8](capacity=pd.addr_len)
                for j in range(pd.addr_len):
                    addr.append(pd.buf_ptr[pd.addr_offset + j])

                conn_idx = len(self.conn_h3s)
                self.conn_map[pd.addr_key] = conn_idx
                self.conn_h3s.append(h3_ptr)
                self.conn_addrs.append(addr^)

            # Feed datagram to the connection.
            try:
                self.conn_h3s[conn_idx][].feed_datagram_from_buffer(pd.payload_ptr, pd.payload_len, now)
            except e:
                self.feed_datagram_err_count += UInt64(1)
                if self.feed_datagram_err_count == UInt64(1):
                    print("h3-bench DIAG: first feed_datagram_from_buffer error:", e)

            # Update peer address.
            var addr_update = List[UInt8](capacity=pd.addr_len)
            for j in range(pd.addr_len):
                addr_update.append(pd.buf_ptr[pd.addr_offset + j])
            self.conn_addrs[conn_idx] = addr_update^

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

            # Save buf_id for reprovision in main loop.
            self.consumed_bufs.append(pd.buf_id)

        self.pending_rx.clear()

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
            var tx_ptr = _heap_alloc[UdpTxSlot](1).as_any_origin()
            tx_ptr.init_pointee_move(UdpTxSlot(pkt^, addr_copy))
            var slot_idx = len(self.tx_slots)
            self.tx_slots.append(tx_ptr)
            self.tx_slot_tokens.append(token)
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

        # Free the TX slot buffers and pointer.
        var ptr = self.tx_slots[idx]
        ptr[].free()
        ptr.free()

        # Swap-and-pop. Update the dict for the slot that moves into
        # position `idx`, and remove the entry for the freed token.
        var last = len(self.tx_slots) - 1
        if idx != last:
            var moved_token = self.tx_slot_tokens[last]
            self.tx_slots[idx] = self.tx_slots[last]
            self.tx_slot_tokens[idx] = moved_token
            self.tx_slot_idx_by_token[moved_token] = idx
        _ = self.tx_slots.pop()
        _ = self.tx_slot_tokens.pop()
        _ = self.tx_slot_idx_by_token.pop(token)

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

                # Find the key that maps to index i and remove it.
                var dead_key = String()
                for entry in self.conn_map.items():
                    if entry.value == i:
                        dead_key = entry.key
                        break
                if dead_key:
                    _ = self.conn_map.pop(dead_key)

                var last = len(self.conn_h3s) - 1
                if i != last:
                    # Swap the last element into position i.
                    self.conn_h3s[i] = self.conn_h3s[last]
                    self.conn_addrs[i] = List[UInt8](copy=self.conn_addrs[last])
                    # Update the Dict entry for the swapped-in connection.
                    for entry in self.conn_map.items():
                        if entry.value == last:
                            self.conn_map[entry.key] = i
                            break
                _ = self.conn_h3s.pop()
                _ = self.conn_addrs.pop()
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
        loop.poll(wait_nr=1)

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
        _drain_pending_submits(loop)
