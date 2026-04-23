# bench/h3_server.mojo
#
# HTTP/3 QUIC benchmark server for HttpArena on port 8443 (UDP).
#
# Uses boucle CompletionLoop with io_uring (recvmsg/sendmsg/timeout)
# for high-performance UDP I/O. Pattern adapted from bench/h1_server.mojo.

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.collections import Dict

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection
from src.quic.trans_param import TransportParams, default_transport_params
from src.quic.packet import parse_packet_header
from src.h3.h3_handler_server import H3HandlerServer
from bench.handler import BenchHandler, StaticEntry, _load_static_files
from interop.file_io import read_file, getenv_opt
from interop.udp import monotonic_us

from boucle import CompletionLoop, CompletionHandler
from boucle.handle import RawHandle
from boucle._sys.linux.raw.ctypes import c_void


# ── constants ──────────────────────────────────────────────────────────

comptime OP_RECVMSG: UInt8 = 0
comptime OP_SENDMSG: UInt8 = 1
comptime OP_TIMEOUT: UInt8 = 2

comptime RX_POOL_SIZE: Int = 64
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

comptime _SUBMIT_RECVMSG: UInt8 = 0
comptime _SUBMIT_SENDMSG: UInt8 = 1
comptime _SUBMIT_TIMEOUT: UInt8 = 2


def _encode_token(slot_idx: UInt64, op_kind: UInt8) -> UInt64:
    return (slot_idx << 8) | UInt64(op_kind)


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


# ── UdpRxSlot ─────────────────────────────────────────────────────────


struct UdpRxSlot(Movable):
    """Pre-allocated receive buffer set for a single recvmsg operation.

    Layout: msghdr (56 bytes) -> iovec (16 bytes) -> data_buf (1500 bytes)
            msghdr.msg_name -> addr_buf (28 bytes, sockaddr_in6)
    """

    var msghdr_buf: UnsafePointer[UInt8, MutAnyOrigin]
    var iov_buf: UnsafePointer[UInt8, MutAnyOrigin]
    var addr_buf: UnsafePointer[UInt8, MutAnyOrigin]
    var data_buf: UnsafePointer[UInt8, MutAnyOrigin]
    var in_use: Bool

    def __init__(out self):
        self.msghdr_buf = _heap_alloc[UInt8](MSGHDR_SIZE).as_any_origin()
        self.iov_buf = _heap_alloc[UInt8](IOVEC_SIZE).as_any_origin()
        self.addr_buf = _heap_alloc[UInt8](ADDR_SIZE).as_any_origin()
        self.data_buf = _heap_alloc[UInt8](DATAGRAM_BUF_SIZE).as_any_origin()
        self.in_use = False
        self._wire()

    def __init__(out self, *, deinit take: Self):
        self.msghdr_buf = take.msghdr_buf
        self.iov_buf = take.iov_buf
        self.addr_buf = take.addr_buf
        self.data_buf = take.data_buf
        self.in_use = take.in_use

    def _wire(mut self):
        """Zero buffers and wire msghdr -> iov -> data_buf, msg_name -> addr_buf."""
        # Zero msghdr
        for i in range(MSGHDR_SIZE):
            self.msghdr_buf[i] = 0
        # Zero iov
        for i in range(IOVEC_SIZE):
            self.iov_buf[i] = 0
        # Zero addr
        for i in range(ADDR_SIZE):
            self.addr_buf[i] = 0

        var msghdr = self.msghdr_buf

        # offset 0: msg_name = addr_buf pointer (8 bytes)
        var addr_ptr_val = UInt64(Int(self.addr_buf))
        var addr_ptr_bytes = UnsafePointer(to=addr_ptr_val).bitcast[UInt8]()
        for i in range(8):
            msghdr[i] = addr_ptr_bytes[i]

        # offset 8: msg_namelen = 28 (UInt32)
        var namelen = UInt32(ADDR_SIZE)
        var namelen_bytes = UnsafePointer(to=namelen).bitcast[UInt8]()
        for i in range(4):
            msghdr[8 + i] = namelen_bytes[i]

        # offset 12: padding (4 bytes, already zero)

        # offset 16: msg_iov = iov_buf pointer (8 bytes)
        var iov_ptr_val = UInt64(Int(self.iov_buf))
        var iov_ptr_bytes = UnsafePointer(to=iov_ptr_val).bitcast[UInt8]()
        for i in range(8):
            msghdr[16 + i] = iov_ptr_bytes[i]

        # offset 24: msg_iovlen = 1 (UInt64)
        var iovlen = UInt64(1)
        var iovlen_bytes = UnsafePointer(to=iovlen).bitcast[UInt8]()
        for i in range(8):
            msghdr[24 + i] = iovlen_bytes[i]

        # offsets 32-55: msg_control, msg_controllen, msg_flags — all zero

        # Wire iovec: offset 0 = iov_base (data_buf ptr), offset 8 = iov_len
        var iov = self.iov_buf
        var data_ptr_val = UInt64(Int(self.data_buf))
        var data_ptr_bytes = UnsafePointer(to=data_ptr_val).bitcast[UInt8]()
        for i in range(8):
            iov[i] = data_ptr_bytes[i]

        var iov_len = UInt64(DATAGRAM_BUF_SIZE)
        var iov_len_bytes = UnsafePointer(to=iov_len).bitcast[UInt8]()
        for i in range(8):
            iov[8 + i] = iov_len_bytes[i]


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


struct H3UdpHandler(CompletionHandler):
    """CompletionHandler for UDP-based H3 server using io_uring."""

    var udp_fd: Int32
    var conn_map: Dict[String, Int]
    var conn_h3s: List[UnsafePointer[H3HandlerServer[BenchHandler], MutAnyOrigin]]
    var conn_addrs: List[List[UInt8]]
    var rx_slots: UnsafePointer[UdpRxSlot, MutAnyOrigin]
    var tx_slots: List[UnsafePointer[UdpTxSlot, MutAnyOrigin]]
    var tx_slot_tokens: List[UInt64]
    var next_tx_id: UInt64
    var cache_ptr: UnsafePointer[Dict[String, StaticEntry], MutAnyOrigin]
    var lib_addr: UInt64
    var server_config: Int32
    var timeout_ts: UnsafePointer[UInt8, MutAnyOrigin]
    var pending_submits: List[PendingSubmit]

    def __init__(
        out self,
        udp_fd: Int32,
        cache_ptr: UnsafePointer[Dict[String, StaticEntry], MutAnyOrigin],
        lib_addr: UInt64,
        server_config: Int32,
    ):
        self.udp_fd = udp_fd
        self.conn_map = Dict[String, Int]()
        self.conn_h3s = List[UnsafePointer[H3HandlerServer[BenchHandler], MutAnyOrigin]]()
        self.conn_addrs = List[List[UInt8]]()
        self.rx_slots = _heap_alloc[UdpRxSlot](RX_POOL_SIZE).as_any_origin()
        self.tx_slots = List[UnsafePointer[UdpTxSlot, MutAnyOrigin]]()
        self.tx_slot_tokens = List[UInt64]()
        self.next_tx_id = UInt64(0)
        self.cache_ptr = cache_ptr
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

        # Pre-allocate RX pool.
        for i in range(RX_POOL_SIZE):
            (self.rx_slots + i).init_pointee_move(UdpRxSlot())

    def __init__(out self, *, deinit take: Self):
        self.udp_fd = take.udp_fd
        self.conn_map = take.conn_map^
        self.conn_h3s = take.conn_h3s^
        self.conn_addrs = take.conn_addrs^
        self.rx_slots = take.rx_slots
        self.tx_slots = take.tx_slots^
        self.tx_slot_tokens = take.tx_slot_tokens^
        self.next_tx_id = take.next_tx_id
        self.cache_ptr = take.cache_ptr
        self.lib_addr = take.lib_addr
        self.server_config = take.server_config
        self.timeout_ts = take.timeout_ts
        self.pending_submits = take.pending_submits^

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
            self._dispatch(token, result)
        except e:
            print("h3-bench: on_complete error:", e)

    def _dispatch(mut self, token: UInt64, result: Int32) raises:
        var op_kind = UInt8(token & 0xFF)
        var slot_idx = token >> 8

        if op_kind == OP_RECVMSG:
            self._handle_recvmsg(Int(slot_idx), result)
        elif op_kind == OP_SENDMSG:
            self._handle_sendmsg(slot_idx, result)
        elif op_kind == OP_TIMEOUT:
            self._handle_timeout(result)

    # --- recvmsg path ---

    def _handle_recvmsg(mut self, slot_idx: Int, result: Int32) raises:
        if slot_idx < 0 or slot_idx >= RX_POOL_SIZE:
            return

        var slot = self.rx_slots + slot_idx
        slot[].in_use = False

        if result <= 0:
            # Re-arm the slot for more data.
            slot[]._wire()
            slot[].in_use = True
            self.pending_submits.append(
                PendingSubmit(kind=_SUBMIT_RECVMSG, slot_idx=UInt64(slot_idx))
            )
            return

        var n = Int(result)

        # Zero-copy: use buffer directly for feed_datagram.
        var data_ptr = slot[].data_buf

        # Read source addr from addr_buf.
        var addr = List[UInt8](capacity=ADDR_SIZE)
        for i in range(ADDR_SIZE):
            addr.append(slot[].addr_buf[i])

        var now = monotonic_us()

        # Small copy for DCID extraction (header only, not full datagram).
        var temp_data = List[UInt8](capacity=n)
        for i in range(n):
            temp_data.append(data_ptr[i])

        # Extract DCID to find or create connection.
        var dcid: List[UInt8]
        try:
            dcid = _extract_dcid(Span(temp_data))
        except:
            # Bad packet — re-arm and ignore.
            slot[]._wire()
            slot[].in_use = True
            self.pending_submits.append(
                PendingSubmit(kind=_SUBMIT_RECVMSG, slot_idx=UInt64(slot_idx))
            )
            return

        var key = _addr_to_key(addr)
        var conn_idx = self._find_conn(key)

        if conn_idx < 0:
            # Create new QUIC connection.
            var tp = default_transport_params()
            var dcid_copy = List[UInt8](copy=dcid)
            var quic: QuicConnection
            try:
                quic = QuicConnection.server(
                    self.lib_addr,
                    self.server_config,
                    tp,
                    Span(dcid),
                    Span(dcid_copy),
                    now,
                )
            except:
                # Failed to create connection — re-arm slot.
                slot[]._wire()
                slot[].in_use = True
                self.pending_submits.append(
                    PendingSubmit(kind=_SUBMIT_RECVMSG, slot_idx=UInt64(slot_idx))
                )
                return

            var handler = BenchHandler(self.cache_ptr)
            var h3: H3HandlerServer[BenchHandler]
            try:
                h3 = H3HandlerServer[BenchHandler](quic=quic^, handler=handler^)
            except:
                slot[]._wire()
                slot[].in_use = True
                self.pending_submits.append(
                    PendingSubmit(kind=_SUBMIT_RECVMSG, slot_idx=UInt64(slot_idx))
                )
                return

            var h3_ptr = _heap_alloc[H3HandlerServer[BenchHandler]](1).as_any_origin()
            h3_ptr.init_pointee_move(h3^)

            conn_idx = len(self.conn_h3s)
            self.conn_map[key] = conn_idx
            self.conn_h3s.append(h3_ptr)
            self.conn_addrs.append(List[UInt8](copy=addr))

        # Feed datagram to the connection (zero-copy from RX slot buffer).
        try:
            self.conn_h3s[conn_idx][].feed_datagram_from_buffer(data_ptr, n, now)
        except:
            pass

        # Update peer address.
        self.conn_addrs[conn_idx] = List[UInt8](copy=addr)

        # Drain and send outgoing datagrams.
        try:
            self._drain_and_send(conn_idx, now)
        except:
            pass

        # Re-arm the RX slot.
        slot[]._wire()
        slot[].in_use = True
        self.pending_submits.append(
            PendingSubmit(kind=_SUBMIT_RECVMSG, slot_idx=UInt64(slot_idx))
        )

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
            self.tx_slots.append(tx_ptr)
            self.tx_slot_tokens.append(token)

            self.pending_submits.append(
                PendingSubmit(kind=_SUBMIT_SENDMSG, slot_idx=tx_id)
            )

    # --- sendmsg path ---

    def _handle_sendmsg(mut self, tx_id: UInt64, result: Int32) raises:
        # Find the TX slot by its token.
        var token = _encode_token(tx_id, OP_SENDMSG)
        var idx = -1
        for i in range(len(self.tx_slot_tokens)):
            if self.tx_slot_tokens[i] == token:
                idx = i
                break

        if idx < 0:
            return

        # Free the TX slot buffers and pointer.
        var ptr = self.tx_slots[idx]
        ptr[].free()
        ptr.free()

        # Swap-and-pop to remove from lists.
        var last = len(self.tx_slots) - 1
        if idx != last:
            self.tx_slots[idx] = self.tx_slots[last]
            self.tx_slot_tokens[idx] = self.tx_slot_tokens[last]
        _ = self.tx_slots.pop()
        _ = self.tx_slot_tokens.pop()

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
                var ptr = self.conn_h3s[i]
                ptr.destroy_pointee()
                ptr.free()

                # Find the key that maps to index i and remove it.
                var dead_key = String()
                for entry in self.conn_map.items():
                    if entry[].value == i:
                        dead_key = entry[].key
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
                        if entry[].value == last:
                            self.conn_map[entry[].key] = i
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


# ── _drain_pending_submits ───────────────────────────────────────────


def _drain_pending_submits(mut loop: CompletionLoop[H3UdpHandler]) raises:
    var submits = loop._handler.pending_submits^
    loop._handler.pending_submits = List[PendingSubmit]()

    for i in range(len(submits)):
        var s = submits[i].copy()

        if s.kind == _SUBMIT_RECVMSG:
            var slot_idx = Int(s.slot_idx)
            if slot_idx < 0 or slot_idx >= RX_POOL_SIZE:
                continue
            var rx_slot = loop._handler.rx_slots + slot_idx
            var msghdr_addr = Int(rx_slot[].msghdr_buf)
            var msghdr_ptr = UnsafePointer[c_void, StaticConstantOrigin](
                unsafe_from_address=msghdr_addr
            )
            var token = _encode_token(s.slot_idx, OP_RECVMSG)
            try:
                loop.submit_recvmsg(loop._handler.udp_fd, msghdr_ptr, token)
            except:
                rx_slot[].in_use = False
                loop._handler.pending_submits.append(s.copy())

        elif s.kind == _SUBMIT_SENDMSG:
            # Find TX slot by tx_id (s.slot_idx).
            var tx_id = s.slot_idx
            var token = _encode_token(tx_id, OP_SENDMSG)
            var tx_idx = -1
            for j in range(len(loop._handler.tx_slot_tokens)):
                if loop._handler.tx_slot_tokens[j] == token:
                    tx_idx = j
                    break
            if tx_idx < 0:
                continue
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

    # Heap-allocate cache so pointer remains stable.
    var cache_ptr = _heap_alloc[Dict[String, StaticEntry]](1).as_any_origin()
    cache_ptr.init_pointee_move(cache^)

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

    # Build handler + loop.
    var handler = H3UdpHandler(
        udp_fd=udp_fd,
        cache_ptr=cache_ptr,
        lib_addr=lib_addr,
        server_config=server_config,
    )
    var loop = CompletionLoop[H3UdpHandler](handler^, sq_entries=4096)

    # Submit initial recvmsg operations for all RX slots.
    for i in range(RX_POOL_SIZE):
        var rx_slot = loop._handler.rx_slots + i
        rx_slot[].in_use = True
        var msghdr_addr = Int(rx_slot[].msghdr_buf)
        var msghdr_ptr = UnsafePointer[c_void, StaticConstantOrigin](
            unsafe_from_address=msghdr_addr
        )
        var token = _encode_token(UInt64(i), OP_RECVMSG)
        loop.submit_recvmsg(udp_fd, msghdr_ptr, token)

    # Submit initial timeout.
    var ts_addr = Int(loop._handler.timeout_ts)
    var ts_ptr = UnsafePointer[c_void, StaticConstantOrigin](
        unsafe_from_address=ts_addr
    )
    loop.submit_timeout(ts_ptr, _encode_token(UInt64(0), OP_TIMEOUT))

    # Event loop.
    while True:
        loop.poll(wait_nr=1)
        _drain_pending_submits(loop)
