# bench/servers/h2_streaming_server.mojo
#
# HTTP/2 TLS benchmark server for H2 *streaming* handlers on port 8445 (TCP).
#
# Uses WatchLoop futures for accept, recv and send. Each connection stores
# Optional[RecvFuture] and Optional[SendFuture]; the main loop polls them
# after each WatchLoop.step().
#
# The demo handler is llm_stream_h2_handler from bench/lib/streaming_handler.mojo,
# which emits 64 SSE tokens per request (no body needed from client).
#
# Run smoke test:
#   ./bench/h2_streaming_server &
#   h2load -c 1 -m 1 -n 1 https://127.0.0.1:8445/stream 2>&1 | head -20
#   kill %1

from std.ffi import external_call
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc

from navette.tls import TlsServerConfig, TlsConnection
from navette.tls.lib import TlsBackend, SharedLibrary

from navette.h2.h2_streaming_server import H2StreamingServer

from bench.lib.streaming_handler import llm_stream_h2_handler

from bouclette import WatchLoop
from bouclette.watch import RecvFuture, SendFuture, AcceptFuture
from bouclette.handle import OwnedHandle
from bouclette.net.socket import Socket
from bouclette.net.addr import SocketAddrV4
from bouclette.net.options import Backlog

from navette.util.null_ptr import null_ptr

from interop.file_io import read_file, getenv_opt


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
comptime _RECV_BUF_SIZE: Int = 8192
comptime _SQ_ENTRIES: Int = 4096
comptime _LISTEN_PORT: UInt16 = 8445
comptime SO_REUSEPORT: Int32 = 15
comptime _TLS_RECORD_CHUNK: Int = 16384


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------
comptime _PHASE_TLS_HANDSHAKE: UInt8 = 0
comptime _PHASE_H2_READY: UInt8 = 1
comptime _PHASE_DONE: UInt8 = 2


# ---------------------------------------------------------------------------
# H2StreamingConn — per-connection state
# ---------------------------------------------------------------------------


struct H2StreamingConn(Movable):
    """One TLS+HTTP/2 streaming connection with WatchLoop recv/send futures.

    Manages async I/O via Optional[RecvFuture] and Optional[SendFuture].
    The _closing flag prevents further submissions; the connection is
    drained (safe to deallocate) when _closing is True and both futures
    are absent.
    """

    var socket: Socket
    var tls: TlsConnection
    var h2: H2StreamingServer
    var phase: UInt8
    var recv_buf: List[Byte]
    var send_buf: List[Byte]
    var send_pending: List[Byte]
    var _closing: Bool
    var _recv_future: Optional[RecvFuture]
    var _send_future: Optional[SendFuture]
    var _loop_ptr: Pointer[NoneType, MutUntrackedOrigin]

    def __init__(
        out self,
        var socket: Socket,
        var tls: TlsConnection,
        var h2: H2StreamingServer,
        loop_ptr: Pointer[NoneType, MutUntrackedOrigin],
    ):
        """Build a connection ready for I/O submission.

        Args:
            socket: Accepted TCP socket.
            tls: TLS server connection state machine.
            h2: HTTP/2 streaming codec bound to the demo handler.
            loop_ptr: Type-erased pointer to the owning WatchLoop.
        """
        self.socket = socket^
        self.tls = tls^
        self.h2 = h2^
        self.phase = _PHASE_TLS_HANDSHAKE
        self.recv_buf = List[Byte](length=_RECV_BUF_SIZE, fill=Byte(0))
        self.send_buf = List[Byte]()
        self.send_pending = List[Byte]()
        self._closing = False
        self._recv_future = Optional[RecvFuture]()
        self._send_future = Optional[SendFuture]()
        self._loop_ptr = loop_ptr

    def __init__(out self, *, deinit move: Self):
        self.socket = move.socket^
        self.tls = move.tls^
        self.h2 = move.h2^
        self.phase = move.phase
        self.recv_buf = move.recv_buf^
        self.send_buf = move.send_buf^
        self.send_pending = move.send_pending^
        self._closing = move._closing
        self._recv_future = move._recv_future^
        self._send_future = move._send_future^
        self._loop_ptr = move._loop_ptr

    def is_drained(self) -> Bool:
        """True when closed and no I/O is in flight — safe to deallocate."""
        return (
            self._closing
            and not Bool(self._recv_future)
            and not Bool(self._send_future)
        )

    # --- I/O submission ---

    def _submit_recv(mut self) raises:
        """Submit a recv via WatchLoop, storing the returned future.

        No-op when a recv is already in flight or the connection is closing.
        The buffer moves into the future and comes back on result.
        """
        if Bool(self._recv_future) or self._closing:
            return
        var loop = Pointer[WatchLoop, MutUntrackedOrigin](
            unsafe_from_address=Int(self._loop_ptr)
        )
        var buf = self.recv_buf^
        self.recv_buf = List[Byte]()
        try:
            self._recv_future = loop[].recv(self.socket, buf^)
        except e:
            var opt_buf = e^.take_buffer()
            if Bool(opt_buf):
                self.recv_buf = opt_buf.unsafe_take()
            else:
                self.recv_buf = List[Byte](length=_RECV_BUF_SIZE, fill=Byte(0))
            raise Error("recv submit failed")

    def _submit_send(mut self) raises:
        """Submit a send via WatchLoop, storing the returned future.

        No-op when a send is already in flight, the connection is
        closing, or there is nothing to send.
        """
        if Bool(self._send_future) or self._closing:
            return
        if len(self.send_buf) == 0:
            return
        var loop = Pointer[WatchLoop, MutUntrackedOrigin](
            unsafe_from_address=Int(self._loop_ptr)
        )
        var buf = self.send_buf^
        self.send_buf = List[Byte]()
        try:
            self._send_future = loop[].send(self.socket, buf^)
        except e:
            var opt_buf = e^.take_buffer()
            if Bool(opt_buf):
                self.send_buf = opt_buf.unsafe_take()
            else:
                self.send_buf = List[Byte]()
            raise Error("send submit failed")

    def _stage_send(mut self, var data: List[Byte]) raises:
        """Send data now, or queue it behind an in-flight send.

        Args:
            data: Outbound ciphertext bytes to send.
        """
        if len(data) == 0:
            return
        if Bool(self._send_future):
            self.send_pending.extend(data^)
            return
        self.send_buf = data^
        self._submit_send()

    def _begin_close(mut self):
        """Initiate connection shutdown via shutdown(SHUT_RDWR).

        Idempotent — no-op if already closing.
        """
        if self._closing:
            return
        _ = external_call["shutdown", Int32](
            self.socket._handle._raw, Int32(2)
        )
        self._closing = True

    # --- Recv processing (ciphertext → TLS → plaintext → H2) ---

    def _handle_recv_impl(mut self, result: Int) raises:
        """Process a completed recv through the TLS+H2 pipeline.

        Args:
            result: Byte count from the completed recv (>= 0).
        """
        if self._closing:
            return

        if result <= 0:
            self._begin_close()
            return

        var n = Int(result)
        var chunk = List[Byte](capacity=n)
        for i in range(n):
            chunk.append(self.recv_buf[i])

        self.tls.receive_data(Span(chunk))

        if self.tls.wants_write():
            var ct = self.tls.drain_ciphertext()
            self._stage_send(ct^)

        if self.tls.is_handshaking():
            if not Bool(self._send_future):
                self._submit_recv()
            return

        var plaintext = self.tls.drain_plaintext()

        if self.phase == _PHASE_TLS_HANDSHAKE:
            var preface_bytes = self.h2.drain()
            if len(preface_bytes) > 0:
                self.tls.send_data(Span(preface_bytes))
                var ct2 = self.tls.drain_ciphertext()
                self._stage_send(ct2^)
            self.phase = _PHASE_H2_READY

        if len(plaintext) > 0:
            self.h2.feed(Span(plaintext))
            var h2_out = self.h2.drain()
            var total = len(h2_out)
            var off = 0
            while off < total:
                var end = off + _TLS_RECORD_CHUNK
                if end > total:
                    end = total
                self.tls.send_data(Span(h2_out)[off:end])
                var ct = self.tls.drain_ciphertext()
                if len(ct) > 0:
                    self._stage_send(ct^)
                off = end

        if self.h2.should_close():
            self._begin_close()
        elif not Bool(self._send_future):
            self._submit_recv()

    # --- Send processing ---

    def _handle_send_impl(mut self, result: Int) raises:
        """Process a completed send — handle partial sends, promote pending.

        Args:
            result: Byte count from the completed send (>= 0).
        """
        if self._closing:
            return

        if result < 0:
            self._begin_close()
            return

        var sent = Int(result)
        var buf_len = len(self.send_buf)
        if sent < buf_len:
            var remaining = List[Byte](capacity=buf_len - sent)
            remaining.extend(Span(self.send_buf)[sent:buf_len])
            self.send_buf = remaining^
            self._submit_send()
            return

        self.send_buf = List[Byte]()

        if len(self.send_pending) > 0:
            var n = len(self.send_pending)
            var fresh = List[Byte](capacity=n)
            fresh.extend(Span(self.send_pending))
            self.send_pending = List[Byte]()
            self.send_buf = fresh^
            self._submit_send()
            return

        if self.phase == _PHASE_DONE:
            self._begin_close()
            return

        self._submit_recv()

    # --- Future polling ---

    def _poll_recv(mut self):
        """Check recv future, process completed result."""
        if not Bool(self._recv_future):
            return
        if not self._recv_future.value().done():
            return

        var opt = self._recv_future^
        self._recv_future = Optional[RecvFuture]()
        var future = opt.unsafe_take()

        var count = 0
        try:
            var result = future^.result()
            count = result.count
            self.recv_buf = result^.take_buffer()
        except e:
            self._begin_close()
            return

        try:
            self._handle_recv_impl(count)
        except e:
            print("h2-streaming-bench: recv processing error:", e)

    def _poll_send(mut self):
        """Check send future, process completed result."""
        if not Bool(self._send_future):
            return
        if not self._send_future.value().done():
            return

        var opt = self._send_future^
        self._send_future = Optional[SendFuture]()
        var future = opt.unsafe_take()

        var count = 0
        try:
            var result = future^.result()
            count = result.count
            self.send_buf = result^.take_buffer()
        except e:
            self._begin_close()
            return

        try:
            self._handle_send_impl(count)
        except e:
            print("h2-streaming-bench: send processing error:", e)

    def poll_io(mut self):
        """Poll both recv and send futures."""
        self._poll_recv()
        self._poll_send()


# ---------------------------------------------------------------------------
# H2StreamingBenchServer
# ---------------------------------------------------------------------------


struct H2StreamingBenchServer(Movable):
    """Owns the listener, the connection table and WatchLoop-based accept.

    Must be heap-allocated before use: the accept future references the
    listener socket, so the server may not move afterwards.
    """

    var listener: Socket
    var connections: List[Pointer[H2StreamingConn, MutUntrackedOrigin]]
    var tls_lib: SharedLibrary
    var server_tls_config: TlsServerConfig
    var _accept_future: Optional[AcceptFuture]
    var _loop_ptr: Pointer[NoneType, MutUntrackedOrigin]
    var _needs_accept_rearm: Bool

    def __init__(
        out self,
        var listener: Socket,
        var tls_lib: SharedLibrary,
        var server_tls_config: TlsServerConfig,
    ):
        """Build the server.

        Args:
            listener: Bound and listening TCP socket (moved in).
            tls_lib: The rustls shared library handle.
            server_tls_config: The rustls server config (certs + ALPN).
        """
        self.listener = listener^
        self.connections = List[Pointer[H2StreamingConn, MutUntrackedOrigin]]()
        self.tls_lib = tls_lib^
        self.server_tls_config = server_tls_config^
        self._accept_future = Optional[AcceptFuture]()
        self._loop_ptr = null_ptr[NoneType, MutUntrackedOrigin]()
        self._needs_accept_rearm = False

    def __init__(out self, *, deinit move: Self):
        self.listener = move.listener^
        self.connections = move.connections^
        self.tls_lib = move.tls_lib^
        self.server_tls_config = move.server_tls_config^
        self._accept_future = move._accept_future^
        self._loop_ptr = move._loop_ptr
        self._needs_accept_rearm = move._needs_accept_rearm

    def __deinit__(deinit self):
        """Release every connection still in the table."""
        for i in range(len(self.connections)):
            var ptr = self.connections[i]
            ptr.unsafe_deinit_pointee()
            ptr.unsafe_free()

    # --- Lifecycle ---

    def start(mut self, mut loop: WatchLoop) raises:
        """Store the loop pointer and submit the initial accept.

        Args:
            loop: The WatchLoop for all I/O operations.
        """
        self._loop_ptr = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=loop))
        )
        self._submit_accept()

    # --- Accept ---

    def _submit_accept(mut self) raises:
        """Submit an accept operation on the listening socket via WatchLoop."""
        var loop = Pointer[WatchLoop, MutUntrackedOrigin](
            unsafe_from_address=Int(self._loop_ptr)
        )
        self._accept_future = Optional(loop[].accept(self.listener))

    def poll_accept(mut self):
        """Poll the accept future and process any accepted connection.

        Called after loop.step(). If the accept future is done, extracts
        the accepted socket and delegates to _handle_accept_impl.
        """
        if not Bool(self._accept_future):
            return
        if not self._accept_future.value().done():
            return

        var opt = self._accept_future^
        self._accept_future = Optional[AcceptFuture]()
        var future = opt.unsafe_take()

        try:
            var socket = future.result()
            self._handle_accept_impl(socket^)
        except e:
            print("h2-streaming-bench: accept error:", e)
            self._needs_accept_rearm = True

    def _handle_accept_impl(mut self, var socket: Socket) raises:
        """Handle an accepted socket — create conn, submit initial recv.

        Args:
            socket: The accepted TCP socket (moved in).
        """
        var tls_conn = TlsConnection.new_server(
            SharedLibrary(copy=self.tls_lib), self.server_tls_config
        )

        var h2 = H2StreamingServer(handler_fn=llm_stream_h2_handler)

        var conn = H2StreamingConn(
            socket=socket^,
            tls=tls_conn^,
            h2=h2^,
            loop_ptr=self._loop_ptr,
        )

        var conn_ptr = _heap_alloc[H2StreamingConn](1)
        conn_ptr.unsafe_write(conn^)
        self.connections.append(conn_ptr)

        # Re-submit accept BEFORE initial recv.
        try:
            self._submit_accept()
        except:
            self._needs_accept_rearm = True

        try:
            conn_ptr[]._submit_recv()
        except:
            conn_ptr[]._begin_close()

    # --- Connection polling ---

    def poll_connections(mut self):
        """Poll all connections' recv/send futures."""
        for i in range(len(self.connections)):
            self.connections[i][].poll_io()

    def reap_closed(mut self):
        """Sweep the connection list and free any fully-drained connections.

        Uses swap-and-pop for O(1) removal. Also retries any deferred
        accept rearm.
        """
        var i = 0
        while i < len(self.connections):
            if self.connections[i][].is_drained():
                var ptr = self.connections[i]
                var last = len(self.connections) - 1
                if i != last:
                    self.connections[i] = self.connections[last]
                _ = self.connections.pop()
                ptr.unsafe_deinit_pointee()
                ptr.unsafe_free()
            else:
                i += 1

        if self._needs_accept_rearm:
            try:
                self._submit_accept()
                self._needs_accept_rearm = False
            except:
                pass


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
    """Run the HTTP/2 streaming benchmark server until killed."""
    var certs_dir_opt = getenv_opt("CERTS_DIR")
    var certs_dir: String
    if Bool(certs_dir_opt):
        certs_dir = certs_dir_opt.unsafe_take()
    else:
        certs_dir = String("certs")

    var cert_pem = read_file(certs_dir + "/server.crt")
    var key_pem = read_file(certs_dir + "/server.key")

    # TLS setup with ALPN "h2"
    var tls = TlsBackend()
    var shared = tls.shared()
    var server_config = TlsServerConfig(
        shared, Span(cert_pem), Span(key_pem)
    )
    var server_alpn = List[String]()
    server_alpn.append("h2")
    server_config.set_alpn_protocols(server_alpn)

    # Listening socket on port 8445
    var listener = Socket.tcp_v4()
    var reuseport_val = _heap_alloc[UInt8](4)
    reuseport_val[unsafe_offset=0] = 1
    reuseport_val[unsafe_offset=1] = 0
    reuseport_val[unsafe_offset=2] = 0
    reuseport_val[unsafe_offset=3] = 0
    var rp_rc = external_call["setsockopt", Int32](
        listener.raw(), Int32(1), SO_REUSEPORT, reuseport_val, Int32(4)
    )
    reuseport_val.unsafe_free()
    if rp_rc < 0:
        print("h2-streaming-bench: warning: setsockopt(SO_REUSEPORT) failed")
    var bind_addr = SocketAddrV4(0, 0, 0, 0, port=_LISTEN_PORT)
    listener.bind(bind_addr)
    listener.listen(Backlog.DEFAULT)

    print("h2-streaming-bench: listening on https://127.0.0.1:" + String(_LISTEN_PORT))
    print("h2-streaming-bench: handler=llm_stream_h2_handler tokens=64 SSE chunks per request")

    var server = H2StreamingBenchServer(
        listener=listener^,
        tls_lib=tls.shared(),
        server_tls_config=server_config^,
    )
    var server_ptr = _heap_alloc[H2StreamingBenchServer](1)
    server_ptr.unsafe_write(server^)

    var loop = WatchLoop(capacity=_SQ_ENTRIES)
    server_ptr[].start(loop)

    while True:
        _ = loop.step(timeout_ms=-1)
        server_ptr[].poll_accept()
        server_ptr[].poll_connections()
        server_ptr[].reap_closed()
