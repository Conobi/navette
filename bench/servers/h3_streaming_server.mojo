# bench/servers/h3_streaming_server.mojo
#
# HTTP/3 QUIC benchmark server for H3 *streaming* handlers on port 8444 (UDP).
#
# Simplified single-process variant of bench/servers/h3_server.mojo. That
# bench uses H3HandlerServer (sync trait-based dispatch) + multishot recvmsg
# + io_uring with profiling instrumentation. This streaming bench uses
# H3StreamingServer (stackful coroutines) with the same QUIC/UDP/io_uring
# plumbing but without multi-process or PROFILE_ACCEPT complexity.
#
# Every operation carries its own `Completion`, whose address the kernel
# returns as the CQE user_data: the multishot recvmsg, the 50ms timer and
# buffer re-provision each own one on the server, and each in-flight sendmsg
# owns one on its heap-allocated `UdpTxSlot`. Nothing dispatches on a token.
#
# The demo handler is llm_stream_h3_handler from bench/lib/streaming_handler.mojo,
# which emits 64 SSE tokens per request (no body needed from client).
#
# Run smoke test:
#   ./bench/h3_streaming_server &
#   curl --http3-only -sk https://127.0.0.1:8444/stream | head -c 200
#   kill %1
#
# Uses port 8444 (not 8443) to avoid collision with bench/servers/h3_server.mojo.

from std.ffi import external_call
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc
from std.collections import Dict, InlineArray

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.quic.packet import parse_packet_header
from navette.runtime.socket_helpers import udp_listener
from navette.h3.h3_streaming_server import H3StreamingServer

from bench.lib.streaming_handler import llm_stream_h3_handler

from interop.file_io import read_file, getenv_opt
from interop.udp import monotonic_us

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

# Default UDP port for the streaming bench (separate from the sync bench's 8443)
comptime DEFAULT_PORT: Int = 8444


@always_inline
def _read_u32_le(ptr: Pointer[UInt8, MutUntrackedOrigin]) -> UInt32:
    return UInt32(ptr[unsafe_offset=0]) | (UInt32(ptr[unsafe_offset=1]) << 8) | (UInt32(ptr[unsafe_offset=2]) << 16) | (UInt32(ptr[unsafe_offset=3]) << 24)


def _addr_to_key(addr: List[UInt8]) -> String:
    """Convert raw sockaddr bytes to a hex string key for connection demux."""
    var key = String()
    for i in range(len(addr)):
        var b = Int(addr[i])
        comptime HEX: String = "0123456789abcdef"
        var hex_bytes = HEX.as_bytes()
        key += chr(Int(hex_bytes[b >> 4]))
        key += chr(Int(hex_bytes[b & 0x0F]))
    return key^


def _extract_dcid(data: Span[UInt8, _]) raises -> List[UInt8]:
    """Extract DCID from a QUIC packet (long or short header)."""
    if len(data) < 6:
        raise "_extract_dcid: packet too short"
    var first = Int(data[0])
    if (first & 0x80) != 0:
        var dcid_len = Int(data[5])
        if len(data) < 6 + dcid_len:
            raise "_extract_dcid: packet too short for DCID"
        var dcid = List[UInt8](capacity=dcid_len)
        for i in range(dcid_len):
            dcid.append(data[6 + i])
        return dcid^
    else:
        var result = parse_packet_header(data, 8)
        return List[UInt8](copy=result[0].dcid)


# ── PendingDatagram ──────────────────────────────────────────────────


struct PendingDatagram(Copyable, Movable):
    var buf_id: UInt16
    var buf_ptr: Pointer[UInt8, MutUntrackedOrigin]
    var payload_ptr: Pointer[UInt8, MutUntrackedOrigin]
    var payload_len: Int
    var addr_offset: Int
    var addr_len: Int
    var addr_key: String
    var dcid: List[UInt8]

    def __init__(out self, buf_id: UInt16, buf_ptr: Pointer[UInt8, MutUntrackedOrigin],
                 payload_ptr: Pointer[UInt8, MutUntrackedOrigin], payload_len: Int,
                 addr_offset: Int, addr_len: Int, var addr_key: String, var dcid: List[UInt8]):
        self.buf_id = buf_id
        self.buf_ptr = buf_ptr
        self.payload_ptr = payload_ptr
        self.payload_len = payload_len
        self.addr_offset = addr_offset
        self.addr_len = addr_len
        self.addr_key = addr_key^
        self.dcid = dcid^

    def __init__(out self, *, copy: Self):
        self.buf_id = copy.buf_id
        self.buf_ptr = copy.buf_ptr
        self.payload_ptr = copy.payload_ptr
        self.payload_len = copy.payload_len
        self.addr_offset = copy.addr_offset
        self.addr_len = copy.addr_len
        self.addr_key = String(copy.addr_key)
        self.dcid = List[UInt8](copy=copy.dcid)

    def __init__(out self, *, deinit move: Self):
        self.buf_id = move.buf_id
        self.buf_ptr = move.buf_ptr
        self.payload_ptr = move.payload_ptr
        self.payload_len = move.payload_len
        self.addr_offset = move.addr_offset
        self.addr_len = move.addr_len
        self.addr_key = move.addr_key^
        self.dcid = move.dcid^


# ── UdpTxSlot ─────────────────────────────────────────────────────────


struct UdpTxSlot(Movable):
    """Buffers for a single sendmsg, plus the Completion it is submitted under.

    The slot is heap-allocated, so `cmp`'s address is stable while the kernel
    holds the operation. Its completion hands the slot straight back, and
    `_owner` leads from there to the server that must release it.
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
        for i in range(data_len):
            self.data_buf[unsafe_offset=i] = data[i]
        var addr_len = len(addr)
        for i in range(ADDR_SIZE):
            if i < addr_len:
                self.addr_buf[unsafe_offset=i] = addr[i]
            else:
                self.addr_buf[unsafe_offset=i] = 0
        for i in range(MSGHDR_SIZE):
            self.msghdr_buf[unsafe_offset=i] = 0
        for i in range(IOVEC_SIZE):
            self.iov_buf[unsafe_offset=i] = 0
        var msghdr = self.msghdr_buf
        var addr_ptr_val = UInt64(Int(self.addr_buf))
        var addr_ptr_bytes = Pointer(to=addr_ptr_val).unsafe_bitcast[UInt8]()
        for i in range(8):
            msghdr[unsafe_offset=i] = addr_ptr_bytes[unsafe_offset=i]
        var namelen = UInt32(ADDR_SIZE)
        var namelen_bytes = Pointer(to=namelen).unsafe_bitcast[UInt8]()
        for i in range(4):
            msghdr[unsafe_offset=8 + i] = namelen_bytes[unsafe_offset=i]
        var iov_ptr_val = UInt64(Int(self.iov_buf))
        var iov_ptr_bytes = Pointer(to=iov_ptr_val).unsafe_bitcast[UInt8]()
        for i in range(8):
            msghdr[unsafe_offset=16 + i] = iov_ptr_bytes[unsafe_offset=i]
        var iovlen = UInt64(1)
        var iovlen_bytes = Pointer(to=iovlen).unsafe_bitcast[UInt8]()
        for i in range(8):
            msghdr[unsafe_offset=24 + i] = iovlen_bytes[unsafe_offset=i]
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

        Args:
            owner: Type-erased pointer to the owning H3StreamingUdpHandler.
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


# ── H3StreamingUdpHandler ─────────────────────────────────────────────


struct H3StreamingUdpHandler(Movable):
    """UDP-based H3 streaming server driven by io_uring completions.

    Ingress is one multishot recvmsg over a classic provided-buffer group;
    egress is one sendmsg per datagram, each owning its own `UdpTxSlot`.
    Mirrors H3UdpHandler in bench/servers/h3_server.mojo but uses
    H3StreamingServer instead of H3HandlerServer, with no profile
    instrumentation — single-process simplicity.

    Must be heap-allocated before use: the recvmsg/timer/provide Completions
    and every `UdpTxSlot._owner` store this struct's address.
    """

    var udp_fd: Int32
    var conn_map: Dict[String, Int]
    var conn_h3s: List[Pointer[H3StreamingServer, MutUntrackedOrigin]]
    var conn_addrs: List[List[UInt8]]
    var pbuf_pool: Pointer[UInt8, MutUntrackedOrigin]
    var pending_rx: List[PendingDatagram]
    var multishot_active: Bool
    var consumed_bufs: List[UInt16]
    var msghdr_template: Pointer[UInt8, MutUntrackedOrigin]
    var tls_lib: SharedLibrary
    var server_config: QuicServerConfig
    var timeout_ts: Pointer[UInt8, MutUntrackedOrigin]
    # Completions for the three singleton operations. `_provide_cmp` is
    # shared by every buffer re-provision because that completion carries no
    # per-operation state.
    var _recvmsg_cmp: Completion
    var _timeout_cmp: Completion
    var _provide_cmp: Completion
    var _driver: Pointer[NoneType, MutUntrackedOrigin]

    def __init__(
        out self,
        udp_fd: Int32,
        var tls_lib: SharedLibrary,
        var server_config: QuicServerConfig,
    ):
        """Build the server with unwired Completions.

        Args:
            udp_fd: Bound dual-stack UDP socket.
            tls_lib: The rustls shared library handle.
            server_config: QUIC server config (certs + transport params).
        """
        self.udp_fd = udp_fd
        self.conn_map = Dict[String, Int]()
        self.conn_h3s = List[Pointer[H3StreamingServer, MutUntrackedOrigin]]()
        self.conn_addrs = List[List[UInt8]]()
        self.pbuf_pool = _heap_alloc[UInt8](PBUF_COUNT * PBUF_SIZE)
        for i in range(PBUF_COUNT * PBUF_SIZE):
            self.pbuf_pool[unsafe_offset=i] = 0
        self.pending_rx = List[PendingDatagram]()
        self.multishot_active = False
        self.consumed_bufs = List[UInt16]()
        self.msghdr_template = _heap_alloc[UInt8](MSGHDR_SIZE)
        for i in range(MSGHDR_SIZE):
            self.msghdr_template[unsafe_offset=i] = 0
        self.msghdr_template[unsafe_offset=8] = 28  # msg_namelen
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
        self.timeout_ts = _heap_alloc[UInt8](TIMESPEC_SIZE)
        for i in range(TIMESPEC_SIZE):
            self.timeout_ts[unsafe_offset=i] = 0
        # tv_nsec = 50ms = 50_000_000 ns LE
        self.timeout_ts[unsafe_offset=8] = 0x80
        self.timeout_ts[unsafe_offset=9] = 0xF0
        self.timeout_ts[unsafe_offset=10] = 0xFA
        self.timeout_ts[unsafe_offset=11] = 0x02

    def __init__(out self, *, deinit move: Self):
        """Move constructor."""
        self.udp_fd = move.udp_fd
        self.conn_map = move.conn_map^
        self.conn_h3s = move.conn_h3s^
        self.conn_addrs = move.conn_addrs^
        self.pbuf_pool = move.pbuf_pool
        self.pending_rx = move.pending_rx^
        self.multishot_active = move.multishot_active
        self.consumed_bufs = move.consumed_bufs^
        self.msghdr_template = move.msghdr_template
        self.tls_lib = move.tls_lib^
        self.server_config = move.server_config^
        self.timeout_ts = move.timeout_ts
        self._recvmsg_cmp = move._recvmsg_cmp^
        self._timeout_cmp = move._timeout_cmp^
        self._provide_cmp = move._provide_cmp^
        self._driver = move._driver

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
        """Hand every buffer drained this cycle back to the kernel."""
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

    def _find_conn(self, key: String) -> Int:
        """Map a peer-address key to a connection index.

        Args:
            key: Hex-encoded sockaddr bytes.

        Returns:
            The connection index, or -1 when the peer is unknown.
        """
        if key in self.conn_map:
            try:
                return self.conn_map[key]
            except:
                return -1
        return -1

    def _handle_recvmsg(mut self, result: Int, flags: UInt32) raises:
        """Buffer one received datagram for the next flush.

        Args:
            result: Bytes written by the kernel, or a negative errno.
            flags: CQE flags carrying the buffer id and F_MORE.
        """
        if (flags & UInt32(IORING_CQE_F_MORE)) == 0:
            self.multishot_active = False
        if result <= 0:
            return
        if (flags & UInt32(IORING_CQE_F_BUFFER)) == 0:
            return
        var buf_id = UInt16(flags >> UInt32(IORING_CQE_BUFFER_SHIFT))
        var buf_ptr = self.pbuf_pool.unsafe_offset(Int(buf_id) * PBUF_SIZE)
        if result < RECVMSG_OUT_HDR_SIZE:
            self.consumed_bufs.append(buf_id)
            return
        var namelen = Int(_read_u32_le(buf_ptr))
        var controllen = Int(_read_u32_le(buf_ptr.unsafe_offset(4)))
        var payloadlen = Int(_read_u32_le(buf_ptr.unsafe_offset(8)))
        var msg_flags = _read_u32_le(buf_ptr.unsafe_offset(12))
        if (msg_flags & UInt32(0x20)) != 0:
            self.consumed_bufs.append(buf_id)
            return
        var addr_offset = RECVMSG_OUT_HDR_SIZE
        var addr_len = namelen
        var payload_offset = RECVMSG_OUT_HDR_SIZE + namelen + controllen
        var payload_ptr = buf_ptr.unsafe_offset(payload_offset)
        if payloadlen <= 0:
            self.consumed_bufs.append(buf_id)
            return
        var dcid: List[UInt8]
        try:
            dcid = _extract_dcid(Span[UInt8](unsafe_ptr=payload_ptr, length=payloadlen))
        except:
            self.consumed_bufs.append(buf_id)
            return
        var addr_bytes = List[UInt8](capacity=addr_len)
        for i in range(addr_len):
            addr_bytes.append(buf_ptr[unsafe_offset=addr_offset + i])
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

    def flush(mut self):
        """Process every datagram buffered since the last tick.

        The run loop calls this once per tick, immediately after the driver
        finishes dispatching completions — the same point at which the
        retired batch-completion loop invoked its flush hook.
        """
        try:
            self._flush_impl()
        except e:
            print("h3-streaming-bench: flush error:", e)

    def _flush_impl(mut self) raises:
        """Route every buffered datagram to its connection and drain egress."""
        var now = monotonic_us()
        for i in range(len(self.pending_rx)):
            var pd = self.pending_rx[i].copy()
            var conn_idx = self._find_conn(pd.addr_key)
            if conn_idx < 0:
                var tp = default_transport_params()
                var dcid_copy = List[UInt8](copy=pd.dcid)
                var quic: QuicConnection
                try:
                    quic = QuicConnection.server(
                        SharedLibrary(copy=self.tls_lib),
                        self.server_config,
                        tp,
                        Span(pd.dcid),
                        Span(dcid_copy),
                        now,
                    )
                except e:
                    print("h3-streaming-bench: QuicConnection.server error:", e)
                    self.consumed_bufs.append(pd.buf_id)
                    continue
                var h3: H3StreamingServer
                try:
                    h3 = H3StreamingServer(quic=quic^, handler_fn=llm_stream_h3_handler)
                except e:
                    print("h3-streaming-bench: H3StreamingServer error:", e)
                    self.consumed_bufs.append(pd.buf_id)
                    continue
                var h3_ptr = _heap_alloc[H3StreamingServer](1)
                h3_ptr.unsafe_write(h3^)
                var addr = List[UInt8](capacity=pd.addr_len)
                for j in range(pd.addr_len):
                    addr.append(pd.buf_ptr[unsafe_offset=pd.addr_offset + j])
                conn_idx = len(self.conn_h3s)
                self.conn_map[pd.addr_key] = conn_idx
                self.conn_h3s.append(h3_ptr)
                self.conn_addrs.append(addr^)
            try:
                self.conn_h3s[conn_idx][].feed_datagram_from_buffer(pd.payload_ptr, pd.payload_len, now)
            except e:
                print("h3-streaming-bench: feed_datagram error:", e)
            var addr_update = List[UInt8](capacity=pd.addr_len)
            for j in range(pd.addr_len):
                addr_update.append(pd.buf_ptr[unsafe_offset=pd.addr_offset + j])
            self.conn_addrs[conn_idx] = addr_update^
            try:
                self._drain_and_send(conn_idx, now)
            except:
                pass
            self.consumed_bufs.append(pd.buf_id)
        self.pending_rx.clear()

    def _drain_and_send(mut self, conn_idx: Int, now: UInt64) raises:
        """Drain a connection's outbound datagrams and submit one sendmsg each.

        Args:
            conn_idx: Index of the connection to drain.
            now: Current monotonic microseconds.
        """
        var datagrams = self.conn_h3s[conn_idx][].drain()
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
                # drop the datagram rather than leak the slot; QUIC
                # retransmits.
                tx_ptr[].free()
                tx_ptr.unsafe_free()

    def _handle_sendmsg(
        mut self, slot: Pointer[UdpTxSlot, MutUntrackedOrigin], result: Int
    ):
        """Release the slot whose sendmsg just completed.

        Args:
            slot: The UdpTxSlot the completed operation was submitted from.
            result: Bytes sent, or a negative errno. QUIC handles loss, so a
                    failed send needs nothing beyond releasing the slot.
        """
        slot[].free()
        slot.unsafe_free()

    def _handle_timeout(mut self, result: Int) raises:
        """Sweep every connection for retransmits and expiry, then re-arm.

        Args:
            result: Timer completion result (ignored; -ETIME is normal).
        """
        var now = monotonic_us()
        var i = 0
        while i < len(self.conn_h3s):
            try:
                self._drain_and_send(i, now)
            except:
                pass
            if self.conn_h3s[i][].should_close():
                var ptr = self.conn_h3s[i]
                ptr.unsafe_deinit_pointee()
                ptr.unsafe_free()
                var dead_key = String()
                for entry in self.conn_map.items():
                    if entry.value == i:
                        dead_key = entry.key
                        break
                if dead_key:
                    _ = self.conn_map.pop(dead_key)
                var last = len(self.conn_h3s) - 1
                if i != last:
                    self.conn_h3s[i] = self.conn_h3s[last]
                    self.conn_addrs[i] = List[UInt8](copy=self.conn_addrs[last])
                    for entry in self.conn_map.items():
                        if entry.value == last:
                            self.conn_map[entry.key] = i
                            break
                _ = self.conn_h3s.pop()
                _ = self.conn_addrs.pop()
                continue
            i += 1
        self._arm_timeout()


# ── Module-level completion callbacks ────────────────────────────────


def _on_recvmsg(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Multishot-recvmsg completion: context is the H3StreamingUdpHandler.

    Args:
        ctx: Type-erased pointer to the owning H3StreamingUdpHandler.
        result: Bytes written into the provided buffer, or a negative errno.
        flags: CQE flags carrying the buffer id and F_MORE.
    """
    var srv = Pointer[H3StreamingUdpHandler, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    try:
        srv[]._handle_recvmsg(result, flags)
    except e:
        print("h3-streaming-bench: recvmsg completion error:", e)


def _on_timeout(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Periodic-timer completion: context is the H3StreamingUdpHandler.

    Args:
        ctx: Type-erased pointer to the owning H3StreamingUdpHandler.
        result: Timer result (-ETIME on normal expiry).
        flags: CQE flags (unused for timeouts).
    """
    var srv = Pointer[H3StreamingUdpHandler, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    try:
        srv[]._handle_timeout(result)
    except e:
        print("h3-streaming-bench: timeout completion error:", e)


def _on_provide_buf(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Buffer-provision completion. Nothing to retire.

    Shared by the initial pool registration and every re-provision, since
    none of them carry per-operation state.

    Args:
        ctx: Type-erased pointer to the owning H3StreamingUdpHandler.
        result: Provision result (negative errno on failure).
        flags: CQE flags (unused).
    """
    pass


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
    var srv = Pointer[H3StreamingUdpHandler, MutUntrackedOrigin](
        unsafe_from_address=Int(slot[]._owner)
    )
    srv[]._handle_sendmsg(slot, result)


# UDP socket factory moved to navette/runtime/socket_helpers.mojo; bench
# uses it via the `udp_listener(port)` import at the top of this file.


# ── main ─────────────────────────────────────────────────────────────


def main() raises:
    """Run the HTTP/3 streaming benchmark server until killed."""
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
    var port = DEFAULT_PORT
    var sock = udp_listener(port)
    var udp_fd = sock.raw()

    print("h3-streaming-bench: listening on https://[::]:" + String(port) + " (UDP/QUIC/H3 streaming)")
    print("h3-streaming-bench: handler=llm_stream_h3_handler tokens=" + String(64) + " SSE chunks per request")

    # Build the io_uring driver and the heap-stable server. `start()`
    # provides the buffer pool, arms the multishot recvmsg and arms the
    # 50ms timer, in that order.
    var driver = IoUringDriver(capacity=_SQ_ENTRIES)

    var handler = H3StreamingUdpHandler(
        udp_fd=udp_fd,
        tls_lib=tls.shared(),
        server_config=server_config^,
    )
    var srv_ptr = _heap_alloc[H3StreamingUdpHandler](1)
    srv_ptr.unsafe_write(handler^)
    srv_ptr[].wire_context()
    srv_ptr[].start(driver)

    # Event loop: `tick(wait=True)` is submit_and_wait(wait_nr=1) followed by
    # completion dispatch — the same single io_uring_enter per iteration the
    # retired poll(wait_nr=1) performed. flush() then runs where the batch
    # loop's flush hook ran, and the re-provision/re-arm SQEs it queues are
    # submitted by the next tick.
    while True:
        _ = driver.tick(wait=True)
        srv_ptr[].flush()
        srv_ptr[].reprovide_consumed()
        if not srv_ptr[].multishot_active:
            srv_ptr[]._arm_recvmsg()
        _ = sock
