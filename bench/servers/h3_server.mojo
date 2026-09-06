# bench/servers/h3_server.mojo
#
# HTTP/3 QUIC benchmark server for HttpArena on port 8443 (UDP).
#
# Uses boucle's IoUringDriver with multishot recvmsg and classic
# IORING_OP_PROVIDE_BUFFERS provided buffers for high-performance UDP I/O.
#
# Every operation carries its own `Completion`, whose address the kernel
# returns as the CQE user_data. The singleton operations (multishot recvmsg,
# the 50ms timer, buffer re-provision) each own a Completion on the server;
# each in-flight sendmsg owns one on its heap-allocated `UdpTxSlot`, which is
# how the completion finds the buffers to release. Nothing is dispatched on a
# token any more.
#
# Submission is inline: SQEs land in the unsynced submission queue and are
# flushed by the next `tick()`, so io_uring_enter still runs once per loop
# iteration, exactly as the previous drain-after-poll structure did.

from std.ffi import external_call
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc
from std.collections import Dict, InlineArray

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.quic.packet import parse_packet_header, is_long_header_initial, extract_dcid
from navette.quic.cid import dcid_to_u64
from navette.runtime.socket_helpers import udp_listener
from navette.h3.h3_handler_server import H3HandlerServer
from bench.lib.handler import (
    BenchHandler,
    BenchState,
    StaticEntry,
    _load_static_files,
    _load_dataset,
)
from interop.file_io import read_file, getenv_opt, write_file, mkdir_p
from interop.udp import monotonic_us
from navette.quic.profile import AcceptProfile, PROFILE_ACCEPT, monotonic_us as profile_monotonic_us

from boucle.proactor.completion import Completion
from boucle.drivers.io_uring import IoUringDriver
from boucle.socle.linux.raw import (
    IORING_CQE_F_BUFFER,
    IORING_CQE_F_MORE,
    IORING_CQE_BUFFER_SHIFT,
    msghdr,
)
from navette.util.null_ptr import null_ptr


# ── constants ──────────────────────────────────────────────────────────

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

comptime _SQ_ENTRIES: Int = 4096
comptime PBUF_COUNT: Int = 1024
comptime PBUF_SIZE: Int = 1600
comptime PBUF_GROUP_ID: UInt16 = 0
comptime RECVMSG_OUT_HDR_SIZE: Int = 16

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


def _profile_signal_handler(signo: Int32):
    # Async-signal-safe: store `1` to the fixed-address flag word. No
    # allocation, no print, no Mojo runtime.
    var p = Pointer[Int32, MutUntrackedOrigin](
        unsafe_from_address=PROFILE_FLAG_ADDR
    )
    p[unsafe_offset=0] = Int32(1)


def _profile_install_signal_handlers() raises:
    """Map the flag page and install SIGINT/SIGTERM handlers."""
    var hint = Pointer[NoneType, MutUntrackedOrigin](
        unsafe_from_address=PROFILE_FLAG_ADDR
    )
    var mapped = external_call["mmap", Pointer[NoneType, MutUntrackedOrigin]](
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
    var p = Pointer[Int32, MutUntrackedOrigin](
        unsafe_from_address=PROFILE_FLAG_ADDR
    )
    p[unsafe_offset=0] = Int32(0)

    var fn_ptr: def(Int32) thin -> None = _profile_signal_handler
    var fp_value = Pointer(to=fn_ptr).unsafe_bitcast[UInt64]()[]
    var handler_ptr = Pointer[NoneType, MutUntrackedOrigin](
        unsafe_from_address=Int(fp_value)
    )
    _ = external_call["signal", Pointer[NoneType, MutUntrackedOrigin]](
        PROFILE_SIGINT, handler_ptr
    )
    _ = external_call["signal", Pointer[NoneType, MutUntrackedOrigin]](
        PROFILE_SIGTERM, handler_ptr
    )


@always_inline
def _profile_dump_pending() -> Bool:
    var p = Pointer[Int32, MutUntrackedOrigin](
        unsafe_from_address=PROFILE_FLAG_ADDR
    )
    return p[unsafe_offset=0] != Int32(0)


@always_inline
def _read_u32_le(ptr: Pointer[UInt8, MutUntrackedOrigin]) -> UInt32:
    return UInt32(ptr[unsafe_offset=0]) | (UInt32(ptr[unsafe_offset=1]) << 8) | (UInt32(ptr[unsafe_offset=2]) << 16) | (UInt32(ptr[unsafe_offset=3]) << 24)


def _zpad2_int(n: Int) -> String:
    """Zero-pad an Int to 2 digits (used for UTC timestamp formatting)."""
    if n < 10:
        return String("0") + String(n)
    return String(n)


# ── helpers (kept from original) ───────────────────────────────────────


comptime _HEX_DIGITS = "0123456789abcdef"


# unused at hot-path post-2026-04-28-quic-bench-dcid-u64-demux; retained
# for ad-hoc debug rendering and for `tests/test_quic_connection.mojo`'s
# `test_dcid_demux_disambiguates_two_conns`. Do not delete without
# re-grepping across the repo.
def _bytes_to_hex(bytes: Span[UInt8, _]) -> String:
    """Hex-encode bytes for use as a Dict[String, Int] key.

    Pinned to 8-byte DCIDs (server SCID length is pinned at 8 bytes;
    client Initial DCIDs are RFC 9000 §7.2 minimum 8). Span parameter
    so call sites pass `Span(quic.initial_dcid)` or `Span(pd.dcid)`
    without consuming the source list.
    """
    var key = String()
    var hex_bytes = _HEX_DIGITS.as_bytes()
    for i in range(len(bytes)):
        var b = Int(bytes[i])
        key += chr(Int(hex_bytes[b >> 4]))
        key += chr(Int(hex_bytes[b & 0x0F]))
    return key^


# ── PendingDatagram ──────────────────────────────────────────────────


struct PendingDatagram(Copyable, Movable):
    var buf_id: UInt16
    var buf_ptr: Pointer[UInt8, MutUntrackedOrigin]
    var payload_ptr: Pointer[UInt8, MutUntrackedOrigin]
    var payload_len: Int
    var addr_offset: Int
    var addr_len: Int
    var dcid: List[UInt8]
    # Arrival-to-processing queueing-tail instrumentation.
    # Read only when PROFILE_ACCEPT is True; off-build the value is always 0
    # and any computed `now - arrival_us` delta is meaningless.
    var arrival_us: UInt64

    def __init__(out self, buf_id: UInt16, buf_ptr: Pointer[UInt8, MutUntrackedOrigin],
                 payload_ptr: Pointer[UInt8, MutUntrackedOrigin], payload_len: Int,
                 addr_offset: Int, addr_len: Int, var dcid: List[UInt8],
                 arrival_us: UInt64 = UInt64(0)):
        self.buf_id = buf_id
        self.buf_ptr = buf_ptr
        self.payload_ptr = payload_ptr
        self.payload_len = payload_len
        self.addr_offset = addr_offset
        self.addr_len = addr_len
        self.dcid = dcid^
        self.arrival_us = arrival_us

    def __init__(out self, *, copy: Self):
        self.buf_id = copy.buf_id
        self.buf_ptr = copy.buf_ptr
        self.payload_ptr = copy.payload_ptr
        self.payload_len = copy.payload_len
        self.addr_offset = copy.addr_offset
        self.addr_len = copy.addr_len
        self.dcid = List[UInt8](copy=copy.dcid)
        self.arrival_us = copy.arrival_us

    def __init__(out self, *, deinit move: Self):
        self.buf_id = move.buf_id
        self.buf_ptr = move.buf_ptr
        self.payload_ptr = move.payload_ptr
        self.payload_len = move.payload_len
        self.addr_offset = move.addr_offset
        self.addr_len = move.addr_len
        self.dcid = move.dcid^
        self.arrival_us = move.arrival_us


# ── UdpTxSlot ─────────────────────────────────────────────────────────


struct UdpTxSlot(Movable):
    """Buffers for a single sendmsg, plus the Completion it is submitted under.

    The slot is heap-allocated, so `cmp`'s address is stable for as long as
    the kernel holds the operation. When the completion fires it hands this
    slot straight back, and `_owner` leads from there to the server that
    must release it -- no token, no side table.
    """

    var msghdr_buf: Pointer[UInt8, MutUntrackedOrigin]
    var iov_buf: Pointer[UInt8, MutUntrackedOrigin]
    var addr_buf: Pointer[UInt8, MutUntrackedOrigin]
    var data_buf: Pointer[UInt8, MutUntrackedOrigin]
    var cmp: Completion
    var _owner: Pointer[NoneType, MutUntrackedOrigin]

    def __init__(out self, var data: List[UInt8], addr: List[UInt8]):
        """Allocate and wire the msghdr/iovec/addr/data buffers.

        Args:
            data: Datagram payload, moved in and copied into `data_buf`.
            addr: Peer sockaddr bytes, copied into `addr_buf`.
        """
        self.cmp = Completion(
            invoke=_on_sendmsg, context=null_ptr[NoneType, MutUntrackedOrigin]()
        )
        self._owner = null_ptr[NoneType, MutUntrackedOrigin]()
        var data_len = len(data)

        self.msghdr_buf = _heap_alloc[UInt8](MSGHDR_SIZE)
        self.iov_buf = _heap_alloc[UInt8](IOVEC_SIZE)
        self.addr_buf = _heap_alloc[UInt8](ADDR_SIZE)
        self.data_buf = _heap_alloc[UInt8](data_len)

        # Copy data
        for i in range(data_len):
            self.data_buf[unsafe_offset=i] = data[i]

        # Copy addr (up to ADDR_SIZE bytes)
        var addr_len = len(addr)
        for i in range(ADDR_SIZE):
            if i < addr_len:
                self.addr_buf[unsafe_offset=i] = addr[i]
            else:
                self.addr_buf[unsafe_offset=i] = 0

        # Zero msghdr
        for i in range(MSGHDR_SIZE):
            self.msghdr_buf[unsafe_offset=i] = 0
        # Zero iov
        for i in range(IOVEC_SIZE):
            self.iov_buf[unsafe_offset=i] = 0

        var msghdr = self.msghdr_buf

        # offset 0: msg_name = addr_buf pointer
        var addr_ptr_val = UInt64(Int(self.addr_buf))
        var addr_ptr_bytes = Pointer(to=addr_ptr_val).unsafe_bitcast[UInt8]()
        for i in range(8):
            msghdr[unsafe_offset=i] = addr_ptr_bytes[unsafe_offset=i]

        # offset 8: msg_namelen = 28
        var namelen = UInt32(ADDR_SIZE)
        var namelen_bytes = Pointer(to=namelen).unsafe_bitcast[UInt8]()
        for i in range(4):
            msghdr[unsafe_offset=8 + i] = namelen_bytes[unsafe_offset=i]

        # offset 16: msg_iov = iov_buf pointer
        var iov_ptr_val = UInt64(Int(self.iov_buf))
        var iov_ptr_bytes = Pointer(to=iov_ptr_val).unsafe_bitcast[UInt8]()
        for i in range(8):
            msghdr[unsafe_offset=16 + i] = iov_ptr_bytes[unsafe_offset=i]

        # offset 24: msg_iovlen = 1
        var iovlen = UInt64(1)
        var iovlen_bytes = Pointer(to=iovlen).unsafe_bitcast[UInt8]()
        for i in range(8):
            msghdr[unsafe_offset=24 + i] = iovlen_bytes[unsafe_offset=i]

        # Wire iovec
        var iov = self.iov_buf
        var data_ptr_val = UInt64(Int(self.data_buf))
        var data_ptr_bytes = Pointer(to=data_ptr_val).unsafe_bitcast[UInt8]()
        for i in range(8):
            iov[unsafe_offset=i] = data_ptr_bytes[unsafe_offset=i]

        var iov_len = UInt64(data_len)
        var iov_len_bytes = Pointer(to=iov_len).unsafe_bitcast[UInt8]()
        for i in range(8):
            iov[unsafe_offset=8 + i] = iov_len_bytes[unsafe_offset=i]

    def __init__(out self, *, deinit move: Self):
        """Move constructor."""
        self.msghdr_buf = move.msghdr_buf
        self.iov_buf = move.iov_buf
        self.addr_buf = move.addr_buf
        self.data_buf = move.data_buf
        self.cmp = move.cmp^
        self._owner = move._owner

    def wire_context(mut self, owner: Pointer[NoneType, MutUntrackedOrigin]):
        """Point `cmp` at this slot's final heap address.

        Must run after the slot reaches its permanent address and before
        the sendmsg SQE is queued.

        Args:
            owner: Type-erased pointer to the owning H3UdpHandler.
        """
        self.cmp.context = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self))
        )
        self._owner = owner

    def free(mut self):
        """Free all 4 heap buffers."""
        self.msghdr_buf.unsafe_free()
        self.iov_buf.unsafe_free()
        self.addr_buf.unsafe_free()
        self.data_buf.unsafe_free()


# ── H3UdpHandler ─────────────────────────────────────────────────────


struct H3UdpHandler(Movable):
    """UDP-based H3 benchmark server driven by io_uring completions.

    Ingress is one multishot recvmsg over a classic provided-buffer group;
    egress is one sendmsg per datagram, each owning its own `UdpTxSlot`.
    The recvmsg, timer and buffer-re-provision operations each own a
    Completion here, so the kernel routes their CQEs back by pointer.

    Must be heap-allocated before use: those Completions and every
    `UdpTxSlot._owner` store this struct's address, so it may not move
    afterwards.
    """

    var udp_fd: Int32
    var conn_dcid_map: Dict[UInt64, Int]
    var conn_h3s: List[Pointer[H3HandlerServer[BenchHandler], MutUntrackedOrigin]]
    var conn_addrs: List[List[UInt8]]
    # Per-conn list of DCID-u64 keys we inserted into conn_dcid_map.
    # Used by _handle_timeout to remove ALL of a conn's entries on swap-and-pop
    # (B-permissive dual-DCID strategy: each conn has 2 entries — initial_dcid
    # AND local_cid).
    var conn_dcids: List[List[UInt64]]
    var pbuf_pool: Pointer[UInt8, MutUntrackedOrigin]
    var pending_rx: List[PendingDatagram]
    var multishot_active: Bool
    var consumed_bufs: List[UInt16]
    var msghdr_template: Pointer[UInt8, MutUntrackedOrigin]
    var state_ptr: Pointer[BenchState, MutUntrackedOrigin]
    var tls_lib: SharedLibrary
    var server_config: QuicServerConfig
    var timeout_ts: Pointer[UInt8, MutUntrackedOrigin]
    # Completions for the three singleton operations. The multishot recvmsg
    # fires `_recvmsg_cmp` once per datagram; `_provide_cmp` is shared by
    # every buffer re-provision because that completion carries no state
    # (its old token was decoded straight into a no-op branch).
    var _recvmsg_cmp: Completion
    var _timeout_cmp: Completion
    var _provide_cmp: Completion
    var _driver: Pointer[NoneType, MutUntrackedOrigin]
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
    # Q-IO-1 (spec 2026-05-05-shortconn-io-path-investigation §4.1) — counts
    # `on_complete` invocations between two adjacent `loop.poll` returns.
    # Snapshot+reset by the event loop after each `loop.poll` cycle and fed
    # to `record_cqes_per_wake`. Field always present; only mutated under
    # PROFILE_ACCEPT (off-build path leaves it at zero).
    var cqes_this_wake_count: UInt64

    def __init__(
        out self,
        udp_fd: Int32,
        state_ptr: Pointer[BenchState, MutUntrackedOrigin],
        var tls_lib: SharedLibrary,
        var server_config: QuicServerConfig,
    ):
        """Build the server with unwired Completions.

        Args:
            udp_fd: Bound dual-stack UDP socket.
            state_ptr: Shared benchmark state (static cache + dataset).
            tls_lib: The rustls shared library handle.
            server_config: QUIC server config (certs + transport params).
        """
        self.udp_fd = udp_fd
        self.conn_dcid_map = Dict[UInt64, Int]()
        self.conn_h3s = List[Pointer[H3HandlerServer[BenchHandler], MutUntrackedOrigin]]()
        self.conn_addrs = List[List[UInt8]]()
        self.conn_dcids = List[List[UInt64]]()
        self.pbuf_pool = _heap_alloc[UInt8](PBUF_COUNT * PBUF_SIZE)
        for i in range(PBUF_COUNT * PBUF_SIZE):
            self.pbuf_pool[unsafe_offset=i] = 0
        self.pending_rx = List[PendingDatagram]()
        self.multishot_active = False
        self.consumed_bufs = List[UInt16]()
        self.msghdr_template = _heap_alloc[UInt8](MSGHDR_SIZE)
        for i in range(MSGHDR_SIZE):
            self.msghdr_template[unsafe_offset=i] = 0
        # msg_namelen at offset 8 = 28 (sockaddr_in6 size) — kernel
        # needs this to populate the peer address in provided buffers.
        self.msghdr_template[unsafe_offset=8] = 28
        # msg_iovlen stays 0: for multishot recvmsg with provided buffers
        # the kernel ignores msg_iov, but import_iovec still validates
        # the pointer if iovlen > 0 — setting iovlen=1 with iov=NULL
        # causes EFAULT.
        self.state_ptr = state_ptr
        self.tls_lib = tls_lib^
        self.server_config = server_config^
        self._recvmsg_cmp = Completion(
            invoke=_on_recvmsg, context=null_ptr[NoneType, MutUntrackedOrigin]()
        )
        self._timeout_cmp = Completion(
            invoke=_on_timeout, context=null_ptr[NoneType, MutUntrackedOrigin]()
        )
        self._provide_cmp = Completion(
            invoke=_on_provide_buf,
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )
        self._driver = null_ptr[NoneType, MutUntrackedOrigin]()

        # Allocate timeout timespec (16 bytes): 50ms = 50_000_000 ns LE.
        self.timeout_ts = _heap_alloc[UInt8](TIMESPEC_SIZE)
        for i in range(TIMESPEC_SIZE):
            self.timeout_ts[unsafe_offset=i] = 0
        # tv_nsec at offset 8 = 50_000_000 = 0x02FAF080 LE
        self.timeout_ts[unsafe_offset=8] = 0x80
        self.timeout_ts[unsafe_offset=9] = 0xF0
        self.timeout_ts[unsafe_offset=10] = 0xFA
        self.timeout_ts[unsafe_offset=11] = 0x02

        self.profile = AcceptProfile()
        self.last_flush_end_us = UInt64(0)
        self.enobufs_count = UInt64(0)
        self.multishot_term_count = UInt64(0)
        self.quic_server_err_count = UInt64(0)
        self.h3_handler_err_count = UInt64(0)
        self.feed_datagram_err_count = UInt64(0)
        self.quic_server_err_first = False

        # Q-IO-1 — per-wake CQE count (snapshot+reset by event loop).
        self.cqes_this_wake_count = UInt64(0)

    def __init__(out self, *, deinit move: Self):
        """Move constructor."""
        self.udp_fd = move.udp_fd
        self.conn_dcid_map = move.conn_dcid_map^
        self.conn_h3s = move.conn_h3s^
        self.conn_addrs = move.conn_addrs^
        self.conn_dcids = move.conn_dcids^
        self.pbuf_pool = move.pbuf_pool
        self.pending_rx = move.pending_rx^
        self.multishot_active = move.multishot_active
        self.consumed_bufs = move.consumed_bufs^
        self.msghdr_template = move.msghdr_template
        self.state_ptr = move.state_ptr
        self.tls_lib = move.tls_lib^
        self.server_config = move.server_config^
        self.timeout_ts = move.timeout_ts
        self._recvmsg_cmp = move._recvmsg_cmp^
        self._timeout_cmp = move._timeout_cmp^
        self._provide_cmp = move._provide_cmp^
        self._driver = move._driver
        self.profile = move.profile^
        self.last_flush_end_us = move.last_flush_end_us
        self.enobufs_count = move.enobufs_count
        self.multishot_term_count = move.multishot_term_count
        self.quic_server_err_count = move.quic_server_err_count
        self.h3_handler_err_count = move.h3_handler_err_count
        self.feed_datagram_err_count = move.feed_datagram_err_count
        self.quic_server_err_first = move.quic_server_err_first
        self.cqes_this_wake_count = move.cqes_this_wake_count

    # --- Conn lookup ---

    def _find_conn_by_dcid(self, dcid_u64: UInt64) -> Int:
        """Map a DCID to a connection index.

        Args:
            dcid_u64: First 8 DCID bytes packed into a u64.

        Returns:
            The connection index, or -1 when the DCID is unknown.
        """
        if dcid_u64 in self.conn_dcid_map:
            try:
                return self.conn_dcid_map[dcid_u64]
            except:
                return -1
        return -1

    # --- Lifecycle + submission ---

    def wire_context(mut self):
        """Point the three singleton Completions at this server's address."""
        var self_ctx = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self))
        )
        self._recvmsg_cmp.context = self_ctx
        self._timeout_cmp.context = self_ctx
        self._provide_cmp.context = self_ctx

    def start(mut self, mut driver: IoUringDriver) raises:
        """Record the driver, provide the buffer pool, arm recvmsg + timer.

        Args:
            driver: The io_uring driver every operation is queued on.
        """
        self._driver = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=driver))
        )
        # Register the provided-buffer pool with io_uring.
        var provide_cmp = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self._provide_cmp))
        )
        driver.provide_buffers(
            self.pbuf_pool,
            PBUF_SIZE,
            PBUF_COUNT,
            PBUF_GROUP_ID,
            UInt16(0),
            provide_cmp,
        )
        self._arm_recvmsg()
        self._arm_timeout()

    def _driver_ptr(self) -> Pointer[IoUringDriver, MutUntrackedOrigin]:
        """Recover the typed driver pointer stored by `start()`."""
        return Pointer[IoUringDriver, MutUntrackedOrigin](
            unsafe_from_address=Int(self._driver)
        )

    def _arm_recvmsg(mut self) raises:
        """Arm the multishot recvmsg over the provided-buffer group."""
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self._recvmsg_cmp))
        )
        var msg_ptr = Pointer[msghdr, MutUntrackedOrigin](
            unsafe_from_address=Int(self.msghdr_template)
        )
        self._driver_ptr()[].multishot_recvmsg(
            self.udp_fd, msg_ptr, PBUF_GROUP_ID, cmp_ptr
        )
        self.multishot_active = True

    def _arm_timeout(mut self) raises:
        """Arm the 50ms periodic kernel timer."""
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self._timeout_cmp))
        )
        var ts_ptr = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(self.timeout_ts)
        )
        self._driver_ptr()[].timeout(ts_ptr, cmp_ptr)

    def reprovide_consumed(mut self) raises:
        """Hand every buffer drained this cycle back to the kernel.

        One IORING_OP_PROVIDE_BUFFERS SQE per buffer, as before -- all of
        them share `_provide_cmp` because the completion is a no-op.
        """
        var consumed = self.consumed_bufs^
        self.consumed_bufs = List[UInt16]()
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self._provide_cmp))
        )
        for i in range(len(consumed)):
            var bid = consumed[i]
            var buf_base = self.pbuf_pool.unsafe_offset(Int(bid) * PBUF_SIZE)
            # Kernel overwrites the buffer on recvmsg — no need to zero.
            self._driver_ptr()[].provide_buffers(
                buf_base, PBUF_SIZE, 1, PBUF_GROUP_ID, bid, cmp_ptr
            )

    def _profile_ptr(mut self) -> Pointer[AcceptProfile, MutUntrackedOrigin]:
        """Return an untracked pointer to the embedded AcceptProfile.

        `Pointer(to=self.profile)` carries a tracked origin, which the QUIC
        and H3 constructors will not accept; they take an untracked one.

        Returns:
            The profile's address with an untracked mutable origin.
        """
        return Pointer[AcceptProfile, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self.profile))
        )

    def count_cqe(mut self):
        """Count one dispatched completion for the per-wake histogram."""
        comptime if PROFILE_ACCEPT:
            self.cqes_this_wake_count = self.cqes_this_wake_count + UInt64(1)

    # Q-IO-1 (spec 2026-05-05-shortconn-io-path-investigation §4.1) — read
    # `cqes_this_wake_count` and reset it to zero, returning the snapshot.
    # Method form (rather than a direct field write from the run loop) works
    # around a Mojo mojox ICE on `<server>.cqes_this_wake_count = 0` at the
    # bench loop site (compiler crash via libstdc++ unwind, not a
    # source-level error). Functionally equivalent.
    def snapshot_and_reset_cqes_per_wake(mut self) -> UInt64:
        """Return the per-wake completion count and reset it to zero.

        Returns:
            Completions dispatched since the previous snapshot.
        """
        var n = self.cqes_this_wake_count
        self.cqes_this_wake_count = UInt64(0)
        return n

    # --- multishot recvmsg path ---

    def _handle_recvmsg(mut self, result: Int, flags: UInt32) raises:
        """Buffer one received datagram for the next flush.

        Args:
            result: Bytes written by the kernel, or a negative errno.
            flags: CQE flags carrying the buffer id and F_MORE.
        """
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
        var buf_ptr = self.pbuf_pool.unsafe_offset(Int(buf_id) * PBUF_SIZE)

        # Parse io_uring_recvmsg_out header (16 bytes):
        # [namelen: u32][controllen: u32][payloadlen: u32][flags: u32]
        if result < RECVMSG_OUT_HDR_SIZE:
            # Too short for header — return buffer.
            self.consumed_bufs.append(buf_id)
            return

        # Q4: count datagrams per recvmsg CQE. With io_uring multishot recvmsg,
        # each CQE carries exactly 1 datagram, so n=1 every call. The verdict
        # signal is whether this histogram shape differs from a hypothetical
        # `recvmmsg`-batched baseline. Plan: 2026-05-03-q4-fresh-conn-cpu-decomposition.
        # H3UdpHandler embeds AcceptProfile directly (line 511) — no pointer
        # indirection; call record_recv_batch on self.profile under the comptime gate.
        comptime if PROFILE_ACCEPT:
            self.profile.record_recv_batch(1)
            # Q7 H_C: 8-bucket recvmsg batch histogram (raw shape, distinct
            # from Q4's per-flush total). With io_uring multishot recvmsg,
            # n=1 every CQE — bucket-0-dominant is itself H_C-positive evidence.
            # Plan: 2026-05-04-q7-cold-handshake-cpu-utilization-decomposition §3 T2.
            self.profile.record_recvmsg_batch_size(1)
        var namelen = Int(_read_u32_le(buf_ptr))
        var controllen = Int(_read_u32_le(buf_ptr.unsafe_offset(4)))
        var payloadlen = Int(_read_u32_le(buf_ptr.unsafe_offset(8)))
        var msg_flags = _read_u32_le(buf_ptr.unsafe_offset(12))

        # Check MSG_TRUNC (0x20) — drop truncated datagrams.
        if (msg_flags & UInt32(0x20)) != 0:
            self.consumed_bufs.append(buf_id)
            return

        # Address starts after the 16-byte header.
        var addr_offset = RECVMSG_OUT_HDR_SIZE
        var addr_len = namelen

        # Payload starts after header + name + control.
        var payload_offset = RECVMSG_OUT_HDR_SIZE + namelen + controllen
        var payload_ptr = buf_ptr.unsafe_offset(payload_offset)

        if payloadlen <= 0:
            self.consumed_bufs.append(buf_id)
            return

        # Extract DCID directly from the provided buffer — no copy.
        var dcid: List[UInt8]
        try:
            dcid = extract_dcid(Span[UInt8](unsafe_ptr=payload_ptr, length=payloadlen))
        except:
            # Bad packet — return buffer.
            self.consumed_bufs.append(buf_id)
            return

        # Build address key for connection demux. Stored as String — re-looked-up
        # in _flush_impl since timeout completions in the same poll batch may
        # swap-and-pop conn_h3s, invalidating any cached index.
        var stamp_us: UInt64 = UInt64(0)
        comptime if PROFILE_ACCEPT:
            stamp_us = profile_monotonic_us()

        self.pending_rx.append(
            PendingDatagram(
                buf_id=buf_id,
                buf_ptr=buf_ptr,
                payload_ptr=payload_ptr,
                payload_len=payloadlen,
                addr_offset=addr_offset,
                addr_len=addr_len,
                dcid=dcid^,
                arrival_us=stamp_us,
            )
        )

    # --- flush: batch process all pending datagrams ---

    def flush(mut self):
        """Process every datagram buffered since the last tick.

        The run loop calls this once per tick, immediately after the driver
        finishes dispatching completions -- the same point at which the
        retired batch-completion loop invoked its flush hook.
        """
        # Q-IO-1 (spec 2026-05-05-shortconn-io-path-investigation §4.1) —
        # bracket `_flush_impl` to histogram per-wake wall-clock duration.
        # Measures end-to-end `_flush_impl` time only (per-pkt loop + drain
        # hook). Excludes completion dispatch, which has already finished by
        # the time we arrive here. Off-build path elides the brackets.
        var t_flush_start: UInt64 = 0
        comptime if PROFILE_ACCEPT:
            t_flush_start = profile_monotonic_us()
        try:
            self._flush_impl()
        except e:
            print("h3-bench: flush error:", e)
        comptime if PROFILE_ACCEPT:
            self.profile.record_flush_impl_us(profile_monotonic_us() - t_flush_start)

    def _flush_impl(mut self) raises:
        """Route every buffered datagram to its connection and drain egress."""
        var t_busy_start = UInt64(0)
        var n_pkts_at_start = 0
        comptime if PROFILE_ACCEPT:
            t_busy_start = profile_monotonic_us()
            if self.last_flush_end_us > UInt64(0):
                self.profile.record_idle(t_busy_start - self.last_flush_end_us)
            n_pkts_at_start = len(self.pending_rx)

        var now = monotonic_us()

        for i in range(len(self.pending_rx)):
            var pd = self.pending_rx[i].copy()
            var t_pop_dispatch_start: UInt64 = 0
            comptime if PROFILE_ACCEPT:
                t_pop_dispatch_start = profile_monotonic_us()
                self.profile.record_loop_iter()
            comptime if PROFILE_ACCEPT:
                # Queueing wait: now (flush start) - arrival_us (recvmsg ingress).
                # delta is the wall-clock time the packet sat in pending_rx.
                if pd.arrival_us > UInt64(0) and now >= pd.arrival_us:
                    self.profile.record_arrival_lat(now - pd.arrival_us)
                else:
                    self.profile.record_arrival_lat(UInt64(0))
            # DCID-keyed lookup. pd.dcid was extracted at _handle_recvmsg
            # (long+short header).
            var dcid_u64 = dcid_to_u64(Span(pd.dcid))
            var conn_idx = self._find_conn_by_dcid(dcid_u64)

            # Strict new-conn gate per RFC 9000 §12.4: only long-header Initial
            # packets create new conns. All other DCID-misses are dropped
            # silently (matches TQUIC, quiche, quic-go, aioquic).
            if conn_idx < 0:
                var first_byte_span = Span[UInt8](
                    unsafe_ptr=pd.payload_ptr, length=pd.payload_len)
                if not is_long_header_initial(first_byte_span):
                    self.consumed_bufs.append(pd.buf_id)
                    comptime if PROFILE_ACCEPT:
                        self.profile.record_loop_pop_dispatch(profile_monotonic_us() - t_pop_dispatch_start)
                    continue
                # Fall through to QuicConnection.server(...) construction below.

            comptime if PROFILE_ACCEPT:
                if conn_idx >= 0:
                    if not self.conn_h3s[conn_idx][]._h3._quic.is_expected_dcid(Span(pd.dcid)):
                        try:
                            self.profile.record_dcid_mismatch()
                        except:
                            pass

            if conn_idx < 0:
                # Create new QUIC connection. DCID was already extracted in
                # _handle_recvmsg and travels in PendingDatagram.
                var tp = default_transport_params()
                var dcid_copy = List[UInt8](copy=pd.dcid)
                var quic: QuicConnection
                try:
                    comptime if PROFILE_ACCEPT:
                        quic = QuicConnection.server(
                            SharedLibrary(copy=self.tls_lib),
                            self.server_config,
                            tp,
                            Span(pd.dcid),
                            Span(dcid_copy),
                            now,
                            self._profile_ptr(),
                        )
                    else:
                        quic = QuicConnection.server(
                            SharedLibrary(copy=self.tls_lib),
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
                    comptime if PROFILE_ACCEPT:
                        self.profile.record_loop_pop_dispatch(profile_monotonic_us() - t_pop_dispatch_start)
                    continue

                # B-permissive dual-DCID extract (BEFORE quic^ is moved into
                # H3HandlerServer): both initial_dcid (client's random ICID)
                # and local_cid (server's chosen SCID) map to the same
                # conn_idx. Both stay until conn teardown.
                #
                # 8-byte invariant locked by tests/test_quic_connection.mojo
                # (test_quic_connection_dcid_lengths_are_8_bytes).
                debug_assert(len(quic.initial_dcid) == 8, "initial_dcid != 8 bytes")
                debug_assert(len(quic.local_cid) == 8, "local_cid != 8 bytes")

                var icid_u64 = dcid_to_u64(Span(quic.initial_dcid))
                var lcid_u64 = dcid_to_u64(Span(quic.local_cid))

                var handler = BenchHandler(self.state_ptr)
                var h3: H3HandlerServer[BenchHandler]
                try:
                    comptime if PROFILE_ACCEPT:
                        h3 = H3HandlerServer[BenchHandler](
                            quic=quic^,
                            handler=handler^,
                            profile_ptr=self._profile_ptr(),
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
                    self.consumed_bufs.append(pd.buf_id)
                    comptime if PROFILE_ACCEPT:
                        self.profile.record_loop_pop_dispatch(profile_monotonic_us() - t_pop_dispatch_start)
                    continue

                var h3_ptr = _heap_alloc[H3HandlerServer[BenchHandler]](1)
                h3_ptr.unsafe_write(h3^)

                # Build address from buffer for the new connection.
                var addr = List[UInt8](capacity=pd.addr_len)
                for j in range(pd.addr_len):
                    addr.append(pd.buf_ptr[unsafe_offset=pd.addr_offset + j])

                conn_idx = len(self.conn_h3s)
                self.conn_dcid_map[icid_u64] = conn_idx
                self.conn_dcid_map[lcid_u64] = conn_idx
                self.conn_h3s.append(h3_ptr)
                self.conn_addrs.append(addr^)

                var dcids = List[UInt64]()
                dcids.append(icid_u64)
                dcids.append(lcid_u64)
                self.conn_dcids.append(dcids^)

            comptime if PROFILE_ACCEPT:
                self.profile.record_loop_pop_dispatch(profile_monotonic_us() - t_pop_dispatch_start)
            # Feed datagram to the connection.
            # Q10 §3.4 — flush_feed_datagram_us bracket. Fires AFTER
            # record_loop_pop_dispatch and BEFORE t_post_pkt_start.
            var t_feed_start: UInt64 = 0
            comptime if PROFILE_ACCEPT:
                t_feed_start = profile_monotonic_us()
            try:
                self.conn_h3s[conn_idx][].feed_datagram_from_buffer(pd.payload_ptr, pd.payload_len, now)
            except e:
                self.feed_datagram_err_count += UInt64(1)
                if self.feed_datagram_err_count == UInt64(1):
                    print("h3-bench DIAG: first feed_datagram_from_buffer error:", e)
            comptime if PROFILE_ACCEPT:
                self.profile.record_flush_feed_datagram_us(profile_monotonic_us() - t_feed_start)

            var t_post_pkt_start: UInt64 = 0
            comptime if PROFILE_ACCEPT:
                t_post_pkt_start = profile_monotonic_us()
            # Update peer address.
            var addr_update = List[UInt8](capacity=pd.addr_len)
            for j in range(pd.addr_len):
                addr_update.append(pd.buf_ptr[unsafe_offset=pd.addr_offset + j])
            self.conn_addrs[conn_idx] = addr_update^

            comptime if PROFILE_ACCEPT:
                self.profile.record_loop_post_pkt(profile_monotonic_us() - t_post_pkt_start)
            # Drain and send outgoing datagrams.
            var t_drain_start = UInt64(0)
            comptime if PROFILE_ACCEPT:
                t_drain_start = profile_monotonic_us()
            try:
                self._drain_and_send(conn_idx, now)
            except:
                pass
            comptime if PROFILE_ACCEPT:
                var drain_us = profile_monotonic_us() - t_drain_start
                self.profile.record_drain(drain_us)

            # Save buf_id for reprovision in main loop.
            self.consumed_bufs.append(pd.buf_id)

        var t_teardown_start: UInt64 = 0
        comptime if PROFILE_ACCEPT:
            t_teardown_start = profile_monotonic_us()
        self.pending_rx.clear()
        comptime if PROFILE_ACCEPT:
            self.profile.record_loop_teardown(profile_monotonic_us() - t_teardown_start)

        comptime if PROFILE_ACCEPT:
            var t_busy_end = profile_monotonic_us()
            self.profile.record_flush(n_pkts_at_start, t_busy_end - t_busy_start)
            self.last_flush_end_us = t_busy_end

        comptime if PROFILE_ACCEPT:
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
        """Drain outgoing datagrams from a connection and queue sendmsg.

        Q10 dual-caller note: invoked from `_flush_impl` per-iter AND from
        `_handle_timeout` (teardown sweep at line 1348). The Q10 §3.5a/b
        recorders accumulate from BOTH call sites; per-bench teardown
        contribution is once vs thousands per second from `_flush_impl`,
        so the inflation is negligible. Documented for future analysts.
        """
        var datagrams = self.conn_h3s[conn_idx][].drain_datagrams(now)
        for i in range(len(datagrams)):
            var pkt = List[UInt8](copy=datagrams[i])
            if len(pkt) == 0:
                continue

            var addr_copy = List[UInt8](copy=self.conn_addrs[conn_idx])

            var tx_ptr = _heap_alloc[UdpTxSlot](1)
            tx_ptr.unsafe_write(UdpTxSlot(pkt^, addr_copy))
            tx_ptr[].wire_context(
                Pointer[NoneType, MutUntrackedOrigin](
                    unsafe_from_address=Int(Pointer(to=self))
                )
            )

            var msg_ptr = Pointer[NoneType, MutUntrackedOrigin](
                unsafe_from_address=Int(tx_ptr[].msghdr_buf)
            )
            var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
                unsafe_from_address=Int(Pointer(to=tx_ptr[].cmp))
            )
            try:
                self._driver_ptr()[].sendmsg(self.udp_fd, msg_ptr, cmp_ptr)
            except:
                # Submission queue full even after the driver's own flush —
                # drop the datagram rather than leak the slot. QUIC
                # retransmits, which is what the old re-queue path relied on
                # once the pending list grew unbounded.
                tx_ptr[].free()
                tx_ptr.unsafe_free()

    # --- sendmsg path ---

    def _handle_sendmsg(
        mut self, slot: Pointer[UdpTxSlot, MutUntrackedOrigin], result: Int
    ):
        """Release the slot whose sendmsg just completed.

        The completion hands the slot back directly, so retiring it is one
        free -- no token decode and no side table to keep consistent.

        Args:
            slot: The UdpTxSlot the completed operation was submitted from.
            result: Bytes sent, or a negative errno. QUIC handles loss, so a
                    failed send needs nothing beyond releasing the slot.
        """
        slot[].free()
        slot.unsafe_free()

        # Q7 H_C: 8-bucket sendmsg batch histogram. Mojo-net's sendmsg path is
        # per-packet (one CQE per datagram) — bucket-0-dominant histogram is
        # itself H_C-positive evidence vs a hypothetical sendmmsg-batched path.
        # Plan: 2026-05-04-q7-cold-handshake-cpu-utilization-decomposition §3 T2.
        comptime if PROFILE_ACCEPT:
            self.profile.record_sendmsg_batch_size(1)

    # --- timeout path ---

    def _handle_timeout(mut self, result: Int) raises:
        """Sweep every connection for retransmits and expiry, then re-arm.

        Args:
            result: Timer completion result (ignored; -ETIME is normal).
        """
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
                comptime if PROFILE_ACCEPT:
                    if not self.conn_h3s[i][]._h3.is_established():
                        self.profile.record_handshake_timeout(UInt64(1))
                var ptr = self.conn_h3s[i]
                ptr.unsafe_deinit_pointee()
                ptr.unsafe_free()

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
        self._arm_timeout()

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
            Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=Int(0))
        )
        var t_buf = InlineArray[Int64, 1](fill=now_t)
        var tm_buf = InlineArray[UInt8, 56](fill=0)
        var tm_ptr = Pointer(to=tm_buf).unsafe_bitcast[UInt8]()
        var t_ptr = Pointer(to=t_buf).unsafe_bitcast[Int64]()
        _ = external_call[
            "gmtime_r", Pointer[UInt8, MutUntrackedOrigin]
        ](t_ptr, tm_ptr)
        var tm_i32 = Pointer(to=tm_buf).unsafe_bitcast[Int32]()
        var sec = Int(tm_i32[unsafe_offset=0])
        var minu = Int(tm_i32[unsafe_offset=1])
        var hour = Int(tm_i32[unsafe_offset=2])
        var mday = Int(tm_i32[unsafe_offset=3])
        var mon = Int(tm_i32[unsafe_offset=4]) + 1
        var year = Int(tm_i32[unsafe_offset=5]) + 1900

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


# ── Module-level completion callbacks ────────────────────────────────


def _on_recvmsg(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Multishot-recvmsg completion: context is the H3UdpHandler.

    Args:
        ctx: Type-erased pointer to the owning H3UdpHandler.
        result: Bytes written into the provided buffer, or a negative errno.
        flags: CQE flags carrying the buffer id and F_MORE.
    """
    var srv = Pointer[H3UdpHandler, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    srv[].count_cqe()
    try:
        srv[]._handle_recvmsg(result, flags)
    except e:
        print("h3-bench: recvmsg completion error:", e)


def _on_timeout(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Periodic-timer completion: context is the H3UdpHandler.

    Args:
        ctx: Type-erased pointer to the owning H3UdpHandler.
        result: Timer result (-ETIME on normal expiry).
        flags: CQE flags (unused for timeouts).
    """
    var srv = Pointer[H3UdpHandler, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    srv[].count_cqe()
    try:
        srv[]._handle_timeout(result)
    except e:
        print("h3-bench: timeout completion error:", e)


def _on_provide_buf(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Buffer-provision completion. Nothing to retire; only counted.

    Shared by the initial pool registration and every re-provision, since
    none of them carry per-operation state.

    Args:
        ctx: Type-erased pointer to the owning H3UdpHandler.
        result: Provision result (negative errno on failure).
        flags: CQE flags (unused).
    """
    var srv = Pointer[H3UdpHandler, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    srv[].count_cqe()


def _on_sendmsg(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Sendmsg completion: context is the UdpTxSlot the send came from.

    Args:
        ctx: Type-erased pointer to the owning UdpTxSlot.
        result: Bytes sent, or a negative errno.
        flags: CQE flags (unused for sendmsg).
    """
    var slot = Pointer[UdpTxSlot, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    var srv = Pointer[H3UdpHandler, MutUntrackedOrigin](
        unsafe_from_address=Int(slot[]._owner)
    )
    srv[].count_cqe()
    srv[]._handle_sendmsg(slot, result)


# UDP socket factory moved to src/io/udp_socket.mojo; bench uses it
# via the `udp_listener(port)` import at the top of this file.


# ── main ─────────────────────────────────────────────────────────────


def main() raises:
    """Run the HTTP/3-over-QUIC benchmark server until killed."""
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
    var state_ptr = _heap_alloc[BenchState](1)
    state_ptr.unsafe_write(bstate^)

    # Load TLS library and create server config.
    var certs_dir_opt = getenv_opt("CERTS_DIR")
    var certs_dir: String
    if certs_dir_opt.__bool__():
        certs_dir = certs_dir_opt.value()
    else:
        certs_dir = String("certs")

    var tls = TlsBackend()
    var cert = read_file(certs_dir + "/server.crt")
    var key = read_file(certs_dir + "/server.key")
    var server_config = QuicServerConfig(tls.shared(), Span(cert), Span(key))

    # Create UDP socket via the library factory.
    # `sock` owns the fd via OwnedHandle and MUST outlive the io_uring
    # loop's outstanding SQEs — stays on this stack frame for the
    # entire serve loop below.
    var port = 8443
    var sock = udp_listener(port)
    var udp_fd = sock.raw()

    var worker_id_opt = getenv_opt("BENCH_WORKER_ID")
    var prefix: String
    if worker_id_opt.__bool__():
        prefix = "[h3-w" + worker_id_opt.value() + "] "
    else:
        prefix = ""
    print(prefix + "h3-bench: listening on https://[::]:" + String(port) + " (UDP/QUIC/H3)")

    # BENCH_WAIT_NR used to set the io_uring `submit_and_wait` completion
    # floor. The driver only exposes wait/no-wait, which is a floor of 1 —
    # the historical default, so unset and BENCH_WAIT_NR=1 runs are
    # unchanged. Any other value is read and reported but cannot be
    # honoured; say so rather than silently ignoring the knob.
    var wait_nr_opt = getenv_opt("BENCH_WAIT_NR")
    if wait_nr_opt.__bool__():
        var requested: Int
        try:
            requested = Int(wait_nr_opt.value())
        except:
            print(prefix + "h3-bench: BENCH_WAIT_NR parse failed, using 1")
            requested = 1
        if requested != 1:
            print(
                prefix
                + "h3-bench: BENCH_WAIT_NR="
                + String(requested)
                + " unsupported (driver exposes wait/no-wait only); using 1"
            )
    print(prefix + "h3-bench: BENCH_WAIT_NR=1")

    # Plan B: install SIGINT/SIGTERM handler so that Ctrl-C / kill
    # triggers a profile dump + clean exit at the next flush boundary.
    # Off-build: zero overhead (no comptime branch elided at compile time).
    comptime if PROFILE_ACCEPT:
        _profile_install_signal_handlers()

    # Build the io_uring driver and the heap-stable server. `start()`
    # provides the buffer pool, arms the multishot recvmsg and arms the
    # 50ms timer, in that order.
    var driver = IoUringDriver(capacity=_SQ_ENTRIES)

    var handler = H3UdpHandler(
        udp_fd=udp_fd,
        state_ptr=state_ptr,
        tls_lib=tls.shared(),
        server_config=server_config^,
    )
    var srv_ptr = _heap_alloc[H3UdpHandler](1)
    srv_ptr.unsafe_write(handler^)
    srv_ptr[].wire_context()
    srv_ptr[].start(driver)

    # Event loop.
    while True:
        # Q7 H_F: bracket the canonical io_uring park site (tick calls
        # submit_and_wait internally). Q-IO-1
        # (spec 2026-05-05-shortconn-io-path-investigation §4.1) promoted
        # the bracket from total-only to total + 24-bucket pow2 histogram
        # (work happens inside `record_iouring_park_us`).
        # Plan: 2026-05-04-q7-cold-handshake-cpu-utilization-decomposition §3 T2.
        var t_park_start: UInt64 = 0
        comptime if PROFILE_ACCEPT:
            t_park_start = profile_monotonic_us()
        # `tick(wait=True)` is submit_and_wait(wait_nr=1) followed by
        # completion dispatch — the same single io_uring_enter per iteration
        # that the retired poll(wait_nr=1) performed.
        _ = driver.tick(wait=True)
        comptime if PROFILE_ACCEPT:
            srv_ptr[].profile.record_iouring_park_us(profile_monotonic_us() - t_park_start)
            var cqes_this_wake = srv_ptr[].snapshot_and_reset_cqes_per_wake()
            srv_ptr[].profile.record_cqes_per_wake(cqes_this_wake)

        # Process the datagrams this tick buffered. Runs exactly where the
        # retired batch loop's flush hook ran: after every completion for
        # this wake, before any new SQE for this iteration.
        srv_ptr[].flush()

        # Re-provide consumed buffers, then re-arm the multishot if it
        # ended. Both only queue SQEs; the next tick() submits them.
        # Q-IO-1 (spec 2026-05-05-shortconn-io-path-investigation §4.1) —
        # bracket the submission block to close the AC3 wall-clock budget
        # (`park + flush_impl + submits ≈ wall_clock`). Total-only.
        var t_dsubmit_start: UInt64 = 0
        comptime if PROFILE_ACCEPT:
            t_dsubmit_start = profile_monotonic_us()
        srv_ptr[].reprovide_consumed()
        if not srv_ptr[].multishot_active:
            srv_ptr[]._arm_recvmsg()
        comptime if PROFILE_ACCEPT:
            srv_ptr[].profile.record_drain_submits_us(profile_monotonic_us() - t_dsubmit_start)

        # Q7 H_A: 100ms-cadence gauge sampling (active_drive_count, in-flight HS).
        # Plan: 2026-05-04-q7-cold-handshake-cpu-utilization-decomposition §3 T2.
        comptime if PROFILE_ACCEPT:
            srv_ptr[].profile.tick_profile_gauges(profile_monotonic_us())
        _ = sock
