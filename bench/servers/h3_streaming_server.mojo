# bench/servers/h3_streaming_server.mojo
#
# HTTP/3 QUIC benchmark server for H3 *streaming* handlers on port 8444 (UDP).
#
# Simplified single-process variant of bench/servers/h3_server.mojo. Uses
# H3StreamingServer (stackful coroutines) with WatchLoop for all I/O:
# DatagramStream for multishot recvmsg, fire-and-forget send_msg for egress,
# and a TimerFuture for the 50ms periodic sweep. No profiling instrumentation.
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

from std.collections import Optional, Span
from std.collections.dict import Dict
from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc

from boucle import (
    WatchLoop,
    TimerFuture,
    BufferPool,
    DatagramStream,
    Datagram,
    Message,
    Socket,
    SocketAddrV4,
    SocketAddrV6,
)
from boucle.handle import OwnedHandle

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.quic.packet import extract_dcid
from navette.quic.cid_buf import CidBuf
from navette.runtime.socket_helpers import udp_listener
from navette.h3.h3_streaming_server import H3StreamingServer

from bench.lib.streaming_handler import llm_stream_h3_handler

from interop.file_io import read_file, getenv_opt
from interop.udp import monotonic_us
from navette.util.null_ptr import null_ptr


# ── constants ──────────────────────────────────────────────────────────

comptime _SQ_ENTRIES: Int = 4096
comptime PBUF_COUNT: Int = 1024
comptime PBUF_SIZE: Int = 1600
comptime DEFAULT_PORT: Int = 8444


# ── helpers ────────────────────────────────────────────────────────────


comptime _HEX_DIGITS: String = "0123456789abcdef"


def _addr_to_key(addr: Span[Byte, _]) -> String:
    """Convert raw sockaddr bytes to a hex string key for connection demux."""
    var key = String()
    var hex_bytes = _HEX_DIGITS.as_bytes()
    for i in range(len(addr)):
        var b = Int(addr[i])
        key += chr(Int(hex_bytes[b >> 4]))
        key += chr(Int(hex_bytes[b & 0x0F]))
    return key^


def _set_msg_peer_raw(mut msg: Message, addr: List[Byte]):
    """Set a Message's peer from raw sockaddr bytes (Linux layout)."""
    if len(addr) < 4:
        return
    var family = Int(addr[0]) | (Int(addr[1]) << 8)
    var port = (UInt16(addr[2]) << 8) | UInt16(addr[3])
    if family == 2:  # AF_INET
        if len(addr) < 8:
            return
        msg.set_peer(SocketAddrV4(
            addr[4], addr[5], addr[6], addr[7], port=port,
        ))
    elif family == 10:  # AF_INET6
        if len(addr) < 24:
            return
        var s0 = (UInt16(addr[8]) << 8) | UInt16(addr[9])
        var s1 = (UInt16(addr[10]) << 8) | UInt16(addr[11])
        var s2 = (UInt16(addr[12]) << 8) | UInt16(addr[13])
        var s3 = (UInt16(addr[14]) << 8) | UInt16(addr[15])
        var s4 = (UInt16(addr[16]) << 8) | UInt16(addr[17])
        var s5 = (UInt16(addr[18]) << 8) | UInt16(addr[19])
        var s6 = (UInt16(addr[20]) << 8) | UInt16(addr[21])
        var s7 = (UInt16(addr[22]) << 8) | UInt16(addr[23])
        var scope_id = UInt32(0)
        if len(addr) >= 28:
            scope_id = (
                UInt32(addr[24])
                | (UInt32(addr[25]) << 8)
                | (UInt32(addr[26]) << 16)
                | (UInt32(addr[27]) << 24)
            )
        msg.set_peer(SocketAddrV6(
            s0, s1, s2, s3, s4, s5, s6, s7,
            port=port, scope_id=scope_id,
        ))


# ── H3StreamingUdpHandler ─────────────────────────────────────────────


struct H3StreamingUdpHandler(Movable):
    """UDP-based H3 streaming server driven by WatchLoop.

    Ingress is a DatagramStream (multishot recvmsg into a BufferPool);
    egress is fire-and-forget send_msg; periodic sweep is a TimerFuture.
    Mirrors the WatchLoop pattern of H3UdpServer in the library.

    Must be heap-allocated before use so the WatchLoop pointer stays
    valid.
    """

    var udp_socket: Socket
    var conn_map: Dict[String, Int]
    var conn_h3s: List[Pointer[H3StreamingServer, MutUntrackedOrigin]]
    var conn_addrs: List[List[Byte]]
    var tls_lib: SharedLibrary
    var server_config: QuicServerConfig
    var _recv_pool: Optional[BufferPool]
    var _recv_stream: Optional[DatagramStream]
    var _timer: Optional[TimerFuture]
    var _loop_ptr: Pointer[WatchLoop, MutUntrackedOrigin]

    def __init__(
        out self,
        var udp_handle: OwnedHandle,
        var tls_lib: SharedLibrary,
        var server_config: QuicServerConfig,
    ):
        """Build the server.

        Args:
            udp_handle: Bound dual-stack UDP socket, wrapped in Socket.
            tls_lib: The rustls shared library handle.
            server_config: QUIC server config (certs + transport params).
        """
        self.udp_socket = Socket(udp_handle^)
        self.conn_map = Dict[String, Int]()
        self.conn_h3s = List[Pointer[H3StreamingServer, MutUntrackedOrigin]]()
        self.conn_addrs = List[List[Byte]]()
        self.tls_lib = tls_lib^
        self.server_config = server_config^
        self._recv_pool = Optional[BufferPool](None)
        self._recv_stream = Optional[DatagramStream](None)
        self._timer = Optional[TimerFuture](None)
        self._loop_ptr = null_ptr[WatchLoop, MutUntrackedOrigin]()

    def __init__(out self, *, deinit move: Self):
        self.udp_socket = move.udp_socket^
        self.conn_map = move.conn_map^
        self.conn_h3s = move.conn_h3s^
        self.conn_addrs = move.conn_addrs^
        self.tls_lib = move.tls_lib^
        self.server_config = move.server_config^
        self._recv_pool = move._recv_pool^
        self._recv_stream = move._recv_stream^
        self._timer = move._timer^
        self._loop_ptr = move._loop_ptr

    # --- Lifecycle ---

    def start(mut self, mut loop: WatchLoop) raises:
        """Create the buffer pool, arm the recv stream and timer.

        Args:
            loop: The WatchLoop that owns recv, send, and timer.
        """
        self._loop_ptr = Pointer[WatchLoop, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=loop))
        )
        self._recv_pool = Optional(loop.buffer_pool(PBUF_COUNT, PBUF_SIZE))
        self._recv_stream = Optional(
            loop.recv_msg_multishot(self.udp_socket, self._recv_pool.value())
        )
        self._timer = Optional(loop.timeout(UInt64(50)))

    # --- Conn lookup ---

    def _find_conn(self, key: String) -> Int:
        """Map a peer-address key to a connection index."""
        if key in self.conn_map:
            try:
                return self.conn_map[key]
            except:
                return -1
        return -1

    # --- flush: drain stream, process, poll timer ---

    def flush(mut self):
        """Process datagrams from the recv stream and poll the timer."""
        try:
            self._flush_impl()
        except e:
            print("h3-streaming-bench: flush error:", e)

    def _flush_impl(mut self) raises:
        """Drain the DatagramStream, route to connections, submit egress."""
        var now = monotonic_us()

        # 1. Drain all available datagrams from the DatagramStream.
        if self._recv_stream is not None:
            while True:
                var dgram_opt = self._recv_stream.value().next()
                if dgram_opt is None:
                    break

                if dgram_opt.value().truncated():
                    continue

                var payload = dgram_opt.value().payload()
                if len(payload) == 0:
                    continue

                var dcid: CidBuf
                try:
                    dcid = extract_dcid(payload)
                except:
                    continue

                # Peer address for demux key and egress.
                var name = dgram_opt.value()._header().name()
                var addr_key = _addr_to_key(name)

                var addr_bytes = List[Byte](capacity=len(name))
                for j in range(len(name)):
                    addr_bytes.append(name[j])

                var conn_idx = self._find_conn(addr_key)
                if conn_idx < 0:
                    var tp = default_transport_params()
                    var dcid_copy = List[Byte](capacity=Int(dcid.len))
                    var _ds = dcid.as_span()
                    for _i in range(len(_ds)):
                        dcid_copy.append(_ds[_i])
                    var quic: QuicConnection
                    try:
                        quic = QuicConnection.server(
                            SharedLibrary(copy=self.tls_lib),
                            self.server_config,
                            tp,
                            dcid.as_span(),
                            Span(dcid_copy),
                            now,
                        )
                    except e:
                        print("h3-streaming-bench: QuicConnection.server error:", e)
                        continue
                    var h3: H3StreamingServer
                    try:
                        h3 = H3StreamingServer(quic=quic^, handler_fn=llm_stream_h3_handler)
                    except e:
                        print("h3-streaming-bench: H3StreamingServer error:", e)
                        continue
                    var h3_ptr = _heap_alloc[H3StreamingServer](1)
                    h3_ptr.unsafe_write(h3^)
                    conn_idx = len(self.conn_h3s)
                    self.conn_map[addr_key] = conn_idx
                    self.conn_h3s.append(h3_ptr)
                    self.conn_addrs.append(addr_bytes^)
                else:
                    # Existing connection — update peer address.
                    self.conn_addrs[conn_idx] = addr_bytes^

                # Feed datagram via Span (zero-copy while lease is alive).
                try:
                    self.conn_h3s[conn_idx][].feed_datagram(payload, now)
                except e:
                    print("h3-streaming-bench: feed_datagram error:", e)

                # Drain egress for this connection.
                try:
                    self._drain_and_send(conn_idx, now)
                except:
                    pass

        # 2. Rearm the stream if it ended (e.g. ENOBUFS).
        if self._recv_stream is not None:
            if not self._recv_stream.value().armed():
                try:
                    self._recv_stream.value().rearm()
                except:
                    pass

        # 3. Poll the timer — sweep connections for retransmits/expiry.
        if self._timer is not None and self._timer.value().done():
            try:
                self._handle_timeout(0)
            except:
                pass
            self._timer = Optional[TimerFuture](None)
            try:
                self._timer = Optional(self._loop_ptr[].timeout(UInt64(50)))
            except:
                pass

    def _drain_and_send(mut self, conn_idx: Int, now: UInt64) raises:
        """Drain a connection's outbound datagrams and send via WatchLoop."""
        var datagrams = self.conn_h3s[conn_idx][].drain()
        for i in range(len(datagrams)):
            var pkt = List[Byte](copy=datagrams[i])
            if len(pkt) == 0:
                continue
            var msg = Message(pkt^)
            _set_msg_peer_raw(msg, self.conn_addrs[conn_idx])
            try:
                _ = self._loop_ptr[].send_msg(self.udp_socket, msg^)
            except:
                pass

    def _handle_timeout(mut self, result: Int) raises:
        """Sweep connections for retransmits and expiry."""
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
                    self.conn_addrs[i] = List[Byte](copy=self.conn_addrs[last])
                    for entry in self.conn_map.items():
                        if entry.value == last:
                            self.conn_map[entry.key] = i
                            break
                _ = self.conn_h3s.pop()
                _ = self.conn_addrs.pop()
                continue
            i += 1


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

    var port = DEFAULT_PORT
    var sock = udp_listener(port)

    print("h3-streaming-bench: listening on https://[::]:" + String(port) + " (UDP/QUIC/H3 streaming)")
    print("h3-streaming-bench: handler=llm_stream_h3_handler tokens=" + String(64) + " SSE chunks per request")

    var handler = H3StreamingUdpHandler(
        udp_handle=sock^,
        tls_lib=tls.shared(),
        server_config=server_config^,
    )
    var srv_ptr = _heap_alloc[H3StreamingUdpHandler](1)
    srv_ptr.unsafe_write(handler^)

    var loop_ptr = _heap_alloc[WatchLoop](1)
    loop_ptr.unsafe_write(WatchLoop(capacity=_SQ_ENTRIES))
    srv_ptr[].start(loop_ptr[])

    while True:
        _ = loop_ptr[].step()
        srv_ptr[].flush()
