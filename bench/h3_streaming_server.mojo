# bench/h3_streaming_server.mojo
#
# HTTP/3 QUIC benchmark server for H3 *streaming* handlers on port 8444 (UDP).
#
# Simplified single-process variant of bench/h3_server.mojo. The existing
# H3 bench uses H3HandlerServer (sync trait-based dispatch) + multishot
# recvmsg + io_uring with profiling instrumentation. This streaming bench
# uses H3StreamingServer (stackful coroutines) with the same QUIC/UDP/io_uring
# plumbing but without multi-process or PROFILE_ACCEPT complexity.
#
# The demo handler is llm_stream_h3_handler from bench/streaming_handler.mojo,
# which emits 64 SSE tokens per request (no body needed from client).
#
# Run smoke test:
#   ./bench/h3_streaming_server &
#   curl --http3-only -sk https://127.0.0.1:8444/stream | head -c 200
#   kill %1
#
# Uses port 8444 (not 8443) to avoid collision with bench/h3_server.mojo.

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.collections import Dict, InlineArray

from mojo_net.tls.lib import RustlsLibrary
from mojo_net.quic.connection import QuicConnection
from mojo_net.quic.trans_param import TransportParams, default_transport_params
from mojo_net.quic.packet import parse_packet_header
from mojo_net.h3.h3_streaming_server import H3StreamingServer

from bench.streaming_handler import llm_stream_h3_handler

from interop.file_io import read_file, getenv_opt
from interop.udp import monotonic_us

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

# Default UDP port for the streaming bench (separate from the sync bench's 8443)
comptime DEFAULT_PORT: Int = 8444


def _encode_token(slot_idx: UInt64, op_kind: UInt8) -> UInt64:
    return (slot_idx << 8) | UInt64(op_kind)


@always_inline
def _read_u32_le(ptr: UnsafePointer[UInt8, MutAnyOrigin]) -> UInt32:
    return UInt32(ptr[0]) | (UInt32(ptr[1]) << 8) | (UInt32(ptr[2]) << 16) | (UInt32(ptr[3]) << 24)


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
        for i in range(data_len):
            self.data_buf[i] = data[i]
        var addr_len = len(addr)
        for i in range(ADDR_SIZE):
            if i < addr_len:
                self.addr_buf[i] = addr[i]
            else:
                self.addr_buf[i] = 0
        for i in range(MSGHDR_SIZE):
            self.msghdr_buf[i] = 0
        for i in range(IOVEC_SIZE):
            self.iov_buf[i] = 0
        var msghdr = self.msghdr_buf
        var addr_ptr_val = UInt64(Int(self.addr_buf))
        var addr_ptr_bytes = UnsafePointer(to=addr_ptr_val).bitcast[UInt8]()
        for i in range(8):
            msghdr[i] = addr_ptr_bytes[i]
        var namelen = UInt32(ADDR_SIZE)
        var namelen_bytes = UnsafePointer(to=namelen).bitcast[UInt8]()
        for i in range(4):
            msghdr[8 + i] = namelen_bytes[i]
        var iov_ptr_val = UInt64(Int(self.iov_buf))
        var iov_ptr_bytes = UnsafePointer(to=iov_ptr_val).bitcast[UInt8]()
        for i in range(8):
            msghdr[16 + i] = iov_ptr_bytes[i]
        var iovlen = UInt64(1)
        var iovlen_bytes = UnsafePointer(to=iovlen).bitcast[UInt8]()
        for i in range(8):
            msghdr[24 + i] = iovlen_bytes[i]
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


# ── H3StreamingUdpHandler ─────────────────────────────────────────────


struct H3StreamingUdpHandler(BatchCompletionHandler):
    """BatchCompletionHandler for UDP-based H3 streaming server using io_uring
    with multishot recvmsg and provided buffer rings.

    Mirrors H3UdpHandler in bench/h3_server.mojo but uses H3StreamingServer
    instead of H3HandlerServer. No profile instrumentation — single-process
    simplicity."""

    var udp_fd: Int32
    var conn_map: Dict[String, Int]
    var conn_h3s: List[UnsafePointer[H3StreamingServer, MutAnyOrigin]]
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
    var lib_addr: UInt64
    var server_config: Int32
    var timeout_ts: UnsafePointer[UInt8, MutAnyOrigin]
    var pending_submits: List[PendingSubmit]

    def __init__(
        out self,
        udp_fd: Int32,
        lib_addr: UInt64,
        server_config: Int32,
    ):
        self.udp_fd = udp_fd
        self.conn_map = Dict[String, Int]()
        self.conn_h3s = List[UnsafePointer[H3StreamingServer, MutAnyOrigin]]()
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
        self.msghdr_template[8] = 28  # msg_namelen
        self.tx_slots = List[UnsafePointer[UdpTxSlot, MutAnyOrigin]]()
        self.tx_slot_tokens = List[UInt64]()
        self.tx_slot_idx_by_token = Dict[UInt64, Int]()
        self.next_tx_id = UInt64(0)
        self.lib_addr = lib_addr
        self.server_config = server_config
        self.pending_submits = List[PendingSubmit]()
        self.timeout_ts = _heap_alloc[UInt8](TIMESPEC_SIZE).as_any_origin()
        for i in range(TIMESPEC_SIZE):
            self.timeout_ts[i] = 0
        # tv_nsec = 50ms = 50_000_000 ns LE
        self.timeout_ts[8] = 0x80
        self.timeout_ts[9] = 0xF0
        self.timeout_ts[10] = 0xFA
        self.timeout_ts[11] = 0x02

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
        self.lib_addr = take.lib_addr
        self.server_config = take.server_config
        self.timeout_ts = take.timeout_ts
        self.pending_submits = take.pending_submits^

    def _find_conn(self, key: String) -> Int:
        if key in self.conn_map:
            try:
                return self.conn_map[key]
            except:
                return -1
        return -1

    fn on_complete(mut self, token: UInt64, result: Int32, flags: UInt32):
        try:
            self._dispatch(token, result, flags)
        except e:
            print("h3-streaming-bench: on_complete error:", e)

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
            pass

    def _handle_recvmsg(mut self, result: Int32, flags: UInt32) raises:
        if (flags & UInt32(IORING_CQE_F_MORE)) == 0:
            self.multishot_active = False
        if result <= 0:
            return
        if (flags & UInt32(IORING_CQE_F_BUFFER)) == 0:
            return
        var buf_id = UInt16(flags >> UInt32(IORING_CQE_BUFFER_SHIFT))
        var buf_ptr = self.pbuf_pool + Int(buf_id) * PBUF_SIZE
        if result < Int32(RECVMSG_OUT_HDR_SIZE):
            self.consumed_bufs.append(buf_id)
            return
        var namelen = Int(_read_u32_le(buf_ptr))
        var controllen = Int(_read_u32_le(buf_ptr + 4))
        var payloadlen = Int(_read_u32_le(buf_ptr + 8))
        var msg_flags = _read_u32_le(buf_ptr + 12)
        if (msg_flags & UInt32(0x20)) != 0:
            self.consumed_bufs.append(buf_id)
            return
        var addr_offset = RECVMSG_OUT_HDR_SIZE
        var addr_len = namelen
        var payload_offset = RECVMSG_OUT_HDR_SIZE + namelen + controllen
        var payload_ptr = buf_ptr + payload_offset
        if payloadlen <= 0:
            self.consumed_bufs.append(buf_id)
            return
        var dcid: List[UInt8]
        try:
            dcid = _extract_dcid(Span[UInt8, MutAnyOrigin](ptr=payload_ptr, length=payloadlen))
        except:
            self.consumed_bufs.append(buf_id)
            return
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

    fn on_flush(mut self):
        try:
            self._flush_impl()
        except e:
            print("h3-streaming-bench: on_flush error:", e)

    def _flush_impl(mut self) raises:
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
                        self.lib_addr,
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
                var h3_ptr = _heap_alloc[H3StreamingServer](1).as_any_origin()
                h3_ptr.init_pointee_move(h3^)
                var addr = List[UInt8](capacity=pd.addr_len)
                for j in range(pd.addr_len):
                    addr.append(pd.buf_ptr[pd.addr_offset + j])
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
                addr_update.append(pd.buf_ptr[pd.addr_offset + j])
            self.conn_addrs[conn_idx] = addr_update^
            try:
                self._drain_and_send(conn_idx, now)
            except:
                pass
            self.consumed_bufs.append(pd.buf_id)
        self.pending_rx.clear()

    def _drain_and_send(mut self, conn_idx: Int, now: UInt64) raises:
        var datagrams = self.conn_h3s[conn_idx][].drain()
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

    def _handle_sendmsg(mut self, tx_id: UInt64, result: Int32) raises:
        var token = _encode_token(tx_id, OP_SENDMSG)
        if token not in self.tx_slot_idx_by_token:
            return
        var idx = self.tx_slot_idx_by_token[token]
        var ptr = self.tx_slots[idx]
        ptr[].free()
        ptr.free()
        var last = len(self.tx_slots) - 1
        if idx != last:
            var moved_token = self.tx_slot_tokens[last]
            self.tx_slots[idx] = self.tx_slots[last]
            self.tx_slot_tokens[idx] = moved_token
            self.tx_slot_idx_by_token[moved_token] = idx
        _ = self.tx_slots.pop()
        _ = self.tx_slot_tokens.pop()
        _ = self.tx_slot_idx_by_token.pop(token)

    def _handle_timeout(mut self, result: Int32) raises:
        var now = monotonic_us()
        var i = 0
        while i < len(self.conn_h3s):
            try:
                self._drain_and_send(i, now)
            except:
                pass
            if self.conn_h3s[i][].should_close():
                var ptr = self.conn_h3s[i]
                ptr.destroy_pointee()
                ptr.free()
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
        self.pending_submits.append(
            PendingSubmit(kind=_SUBMIT_TIMEOUT, slot_idx=UInt64(0))
        )


# ── _drain_pending_submits ───────────────────────────────────────────


def _drain_pending_submits(mut loop: BatchCompletionLoop[H3StreamingUdpHandler]) raises:
    var submits = loop._handler.pending_submits^
    loop._handler.pending_submits = List[PendingSubmit]()
    for i in range(len(submits)):
        var s = submits[i].copy()
        if s.kind == _SUBMIT_SENDMSG:
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
    """Create a dual-stack UDP socket bound to [::]:port."""
    var fd = external_call["socket", Int32](AF_INET6, SOCK_DGRAM, Int32(0))
    if fd < 0:
        raise "_setup_udp_socket: socket() failed"
    var optval = _heap_alloc[UInt8](4).as_any_origin()
    optval[0] = 1; optval[1] = 0; optval[2] = 0; optval[3] = 0
    var sso = external_call["setsockopt", Int32](fd, SOL_SOCKET, SO_REUSEADDR, optval, Int32(4))
    if sso < 0:
        optval.free()
        raise "setsockopt(SO_REUSEADDR) failed"
    optval[0] = 1
    var rp = external_call["setsockopt", Int32](fd, SOL_SOCKET, SO_REUSEPORT, optval, Int32(4))
    if rp < 0:
        optval.free()
        raise "setsockopt(SO_REUSEPORT) failed"
    optval[0] = 0
    var v6o = external_call["setsockopt", Int32](fd, IPPROTO_IPV6, IPV6_V6ONLY, optval, Int32(4))
    optval.free()
    if v6o < 0:
        raise "setsockopt(IPV6_V6ONLY) failed"
    var addr = _heap_alloc[UInt8](ADDR_SIZE).as_any_origin()
    for i in range(ADDR_SIZE):
        addr[i] = 0
    addr[0] = 10  # sin6_family = AF_INET6 LE
    addr[1] = 0
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

    var port = DEFAULT_PORT
    var udp_fd = _setup_udp_socket(port)

    print("h3-streaming-bench: listening on https://[::]:" + String(port) + " (UDP/QUIC/H3 streaming)")
    print("h3-streaming-bench: handler=llm_stream_h3_handler tokens=" + String(64) + " SSE chunks per request")

    var handler = H3StreamingUdpHandler(
        udp_fd=udp_fd,
        lib_addr=lib_addr,
        server_config=server_config,
    )
    var loop = BatchCompletionLoop[H3StreamingUdpHandler](handler^, sq_entries=4096)

    var provide_token = _encode_token(UInt64(0), OP_PROVIDE_BUF)
    loop.provide_buffers(loop._handler.pbuf_pool, PBUF_SIZE, PBUF_COUNT, PBUF_GROUP_ID, UInt16(0), provide_token)

    var msghdr_addr = Int(loop._handler.msghdr_template)
    var msghdr_ptr = UnsafePointer[c_void, StaticConstantOrigin](
        unsafe_from_address=msghdr_addr
    )
    var recvmsg_token = _encode_token(UInt64(0), OP_RECVMSG)
    loop.submit_recvmsg_multishot(udp_fd, msghdr_ptr, PBUF_GROUP_ID, recvmsg_token)
    loop._handler.multishot_active = True

    var ts_addr = Int(loop._handler.timeout_ts)
    var ts_ptr = UnsafePointer[c_void, StaticConstantOrigin](
        unsafe_from_address=ts_addr
    )
    loop.submit_timeout(ts_ptr, _encode_token(UInt64(0), OP_TIMEOUT))

    while True:
        loop.poll(wait_nr=1)
        var consumed = loop._handler.consumed_bufs^
        loop._handler.consumed_bufs = List[UInt16]()
        for i in range(len(consumed)):
            var bid = consumed[i]
            var buf_base = loop._handler.pbuf_pool + Int(bid) * PBUF_SIZE
            var rprov_token = _encode_token(UInt64(bid), OP_PROVIDE_BUF)
            loop.reprovide_buffer(buf_base, PBUF_SIZE, PBUF_GROUP_ID, bid, rprov_token)
        if not loop._handler.multishot_active:
            var ms_addr = Int(loop._handler.msghdr_template)
            var ms_ptr = UnsafePointer[c_void, StaticConstantOrigin](
                unsafe_from_address=ms_addr
            )
            var ms_token = _encode_token(UInt64(0), OP_RECVMSG)
            loop.submit_recvmsg_multishot(udp_fd, ms_ptr, PBUF_GROUP_ID, ms_token)
            loop._handler.multishot_active = True
        _drain_pending_submits(loop)
