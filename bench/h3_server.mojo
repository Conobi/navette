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
from boucle.net.socket import Socket
from boucle.net.addr import SocketAddrV6
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


# ── main (placeholder) ────────────────────────────────────────────────


def main() raises:
    print("bench-h3: placeholder (Tasks 2-5 pending)")
