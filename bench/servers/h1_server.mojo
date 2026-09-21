# bench/servers/h1_server.mojo
#
# HTTP/1.1 benchmark server, plaintext or TLS-wrapped depending on env:
#
#   BENCH_H1_TLS=0|1   — enable TLS handshake + record layer (default 0)
#   BENCH_H1_PORT      — listen port (default 8080 plaintext, 8081 TLS)
#   BENCH_H1_ROLE      — log prefix tag (default "h1", set to "h1tls" by
#                        the launcher for the TLS sidecar worker)
#
# Uses bouclette's WatchLoop with per-connection RecvFuture/SendFuture handles
# plus H1HandlerServer[BenchHandler]. Each connection owns Optional recv and
# send futures; after each loop.step() the server polls every connection's
# futures for completed results.
#
# When TLS is enabled, lifts the rustls glue from the H2 path:
# TlsConnection wraps every accepted socket, ALPN advertises "http/1.1"
# only, and recv/send go through tls.receive_data / tls.drain_plaintext /
# tls.send_data / tls.drain_ciphertext.

from std.collections.optional import Optional
from std.ffi import external_call
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc
from navette.util.owned_alloc import Owned
from navette.util.null_ptr import null_ptr

from navette.h1.handler_server import H1HandlerServer
from navette.tls import TlsServerConfig, TlsConnection
from navette.tls.lib import TlsBackend, SharedLibrary
from bench.lib.handler import (
    BenchHandler,
    BenchState,
    _load_static_files,
    _load_dataset,
)
from interop.file_io import getenv_opt, read_file

from bouclette import WatchLoop, RecvFuture, SendFuture, AcceptFuture, Socket
from bouclette.net.addr import SocketAddrV4
from bouclette.net.options import Backlog

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

comptime _RECV_BUF_SIZE: Int = 8192
comptime _SQ_ENTRIES: Int = 4096
comptime _DEFAULT_PLAINTEXT_PORT: UInt16 = 8080
comptime _DEFAULT_TLS_PORT: UInt16 = 8081
comptime SO_REUSEPORT: Int32 = 15

comptime _PHASE_TLS_HANDSHAKE: UInt8 = 0
comptime _PHASE_READY: UInt8 = 1


# ---------------------------------------------------------------------------
# H1Conn — per-connection state
# ---------------------------------------------------------------------------


struct H1Conn(Movable):
    """One accepted TCP connection with WatchLoop recv/send futures.

    Manages recv and send via Optional futures stored on the connection.
    The close state machine uses _closing: once set, no further I/O
    submissions are made. The connection is drained (safe to free) when
    _closing is True and both futures are absent.
    """

    var socket: Socket
    var http: H1HandlerServer[BenchHandler]
    var tls: Optional[TlsConnection]
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
        var http: H1HandlerServer[BenchHandler],
        var tls: Optional[TlsConnection],
        loop_ptr: Pointer[NoneType, MutUntrackedOrigin],
    ):
        """Build a connection with WatchLoop futures.

        Args:
            socket: Owned accepted TCP socket.
            http: H1 codec plus benchmark handler for this connection.
            tls: A rustls connection when TLS is enabled, empty otherwise.
            loop_ptr: Type-erased pointer to the WatchLoop.
        """
        self.socket = socket^
        self.http = http^
        self.tls = tls^
        self.phase = _PHASE_TLS_HANDSHAKE if Bool(self.tls) else _PHASE_READY
        self.recv_buf = List[Byte](length=_RECV_BUF_SIZE, fill=Byte(0))
        self.send_buf = List[Byte]()
        self.send_pending = List[Byte]()
        self._closing = False
        self._recv_future = Optional[RecvFuture]()
        self._send_future = Optional[SendFuture]()
        self._loop_ptr = loop_ptr

    def __init__(out self, *, deinit move: Self):
        self.socket = move.socket^
        self.http = move.http^
        self.tls = move.tls^
        self.phase = move.phase
        self.recv_buf = move.recv_buf^
        self.send_buf = move.send_buf^
        self.send_pending = move.send_pending^
        self._closing = move._closing
        self._recv_future = move._recv_future^
        self._send_future = move._send_future^
        self._loop_ptr = move._loop_ptr

    def is_drained(self) -> Bool:
        """Check if the connection is closed and has no I/O in flight."""
        return (
            self._closing
            and not Bool(self._recv_future)
            and not Bool(self._send_future)
        )

    # --- I/O submission ---

    def _submit_recv(mut self) raises:
        """Submit a recv via WatchLoop, storing the returned future.

        Moves recv_buf into the future; reclaimed on result.
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
                self.recv_buf = List[Byte](length=_RECV_BUF_SIZE, fill=0)
            raise Error("recv submit failed")

    def _submit_send(mut self) raises:
        """Submit a send via WatchLoop, storing the returned future.

        Moves send_buf into the future; reclaimed on result.
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
        """Send `data` now, or append it to the pending tail if busy.

        Args:
            data: Outbound bytes, moved in.
        """
        if len(data) == 0:
            return
        if Bool(self._send_future):
            self.send_pending.extend(Span(data))
            return
        self.send_buf = data^
        self._submit_send()

    def _begin_close(mut self):
        """Mark the connection for shutdown and drop in-flight futures.

        Idempotent -- no-op if already closing.
        """
        if self._closing:
            return
        try:
            _ = external_call["shutdown", Int32](
                self.socket.raw(), Int32(2)
            )
        except:
            pass
        self._closing = True
        self._recv_future = Optional[RecvFuture]()
        self._send_future = Optional[SendFuture]()

    # --- Future polling ---

    def poll_io(mut self):
        """Poll recv and send futures, processing any completed results."""
        self._poll_recv()
        self._poll_send()

    def _poll_recv(mut self):
        """Check the recv future; if done, process the result."""
        if not Bool(self._recv_future):
            return
        if not self._recv_future.value().done():
            return

        var opt = self._recv_future^
        self._recv_future = Optional[RecvFuture]()
        var future = opt.unsafe_take()

        var count = 0
        var chunk = List[Byte]()
        try:
            var result = future^.result()
            count = result.count
            var span = result.transferred()
            chunk = List[Byte](capacity=count)
            for i in range(count):
                chunk.append(span[i])
        except:
            self._begin_close()
            return

        try:
            self._handle_recv_result(count, chunk)
        except:
            self._begin_close()

    def _poll_send(mut self):
        """Check the send future; if done, process the result."""
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
        except:
            self._begin_close()
            return

        try:
            self._handle_send_result(count)
        except:
            self._begin_close()

    # --- Recv handling ---

    def _handle_recv_result(mut self, count: Int, chunk: List[Byte]) raises:
        """Process received bytes through plaintext or TLS+H1 pipeline.

        Args:
            count: Bytes received.
            chunk: The received bytes (copied from the buffer).
        """
        if self._closing:
            return

        if count <= 0:
            self._begin_close()
            return

        if Bool(self.tls):
            self._handle_recv_tls(Span(chunk))
        else:
            self.http.feed(Span(chunk))
            var response_bytes = self.http.drain()
            if len(response_bytes) > 0:
                self._stage_send(response_bytes^)
            if not Bool(self._send_future):
                if not self.http.should_close():
                    self._submit_recv()

    def _handle_recv_tls(mut self, chunk: Span[Byte, _]) raises:
        """Drive the rustls handshake, then the H1 codec, over one chunk.

        Args:
            chunk: Ciphertext bytes just received from the socket.
        """
        self.tls.value().receive_data(chunk)

        if self.tls.value().wants_write():
            var ct = self.tls.value().drain_ciphertext()
            self._stage_send(ct^)

        if self.tls.value().is_handshaking():
            self._submit_recv()
            return

        if self.phase == _PHASE_TLS_HANDSHAKE:
            self.phase = _PHASE_READY

        var plaintext = self.tls.value().drain_plaintext()
        if len(plaintext) > 0:
            self.http.feed(Span(plaintext))
            var response_bytes = self.http.drain()
            if len(response_bytes) > 0:
                self.tls.value().send_data(Span(response_bytes))
                var ct2 = self.tls.value().drain_ciphertext()
                self._stage_send(ct2^)

        if not Bool(self._send_future):
            if not self.http.should_close():
                self._submit_recv()

    # --- Send handling ---

    def _handle_send_result(mut self, count: Int) raises:
        """Retire a send, re-queueing the tail or the pending buffer.

        Args:
            count: Bytes successfully sent.
        """
        if self._closing:
            return

        if count < 0:
            self._begin_close()
            return

        var buf_len = len(self.send_buf)
        if count < buf_len:
            var remaining = List[Byte](capacity=buf_len - count)
            remaining.extend(Span(self.send_buf)[count:buf_len])
            self.send_buf = remaining^
            self._submit_send()
            return

        self.send_buf = List[Byte]()

        if len(self.send_pending) > 0:
            var pending_view = Span(self.send_pending)
            var pending = List[Byte](capacity=len(pending_view))
            pending.extend(pending_view)
            self.send_pending = List[Byte]()
            self.send_buf = pending^
            self._submit_send()
            return

        if self.http.should_close():
            self._begin_close()
        else:
            self._submit_recv()


# ---------------------------------------------------------------------------
# H1BenchServer
# ---------------------------------------------------------------------------


struct H1BenchServer(Movable):
    """Owns the listener, the connection table and the accept future.

    Must be heap-allocated before use so that the loop pointer stays
    stable across the server's lifetime.
    """

    var listener: Socket
    var connections: List[Pointer[H1Conn, MutUntrackedOrigin]]
    var state_ptr: Pointer[BenchState, MutUntrackedOrigin]
    var tls_enabled: Bool
    var tls_lib: Optional[SharedLibrary]
    var server_tls_config: Optional[TlsServerConfig]
    var _accept_future: Optional[AcceptFuture]
    var _loop_ptr: Pointer[NoneType, MutUntrackedOrigin]
    var _needs_accept_rearm: Bool

    def __init__(
        out self,
        var listener: Socket,
        state_ptr: Pointer[BenchState, MutUntrackedOrigin],
        var tls_lib: Optional[SharedLibrary],
        var server_tls_config: Optional[TlsServerConfig],
    ):
        """Build the server.

        Args:
            listener: Bound and listening TCP socket (moved in).
            state_ptr: Shared benchmark state (static cache + dataset).
            tls_lib: The rustls shared library when TLS is enabled.
            server_tls_config: The rustls server config when TLS is enabled.
        """
        self.listener = listener^
        self.connections = List[Pointer[H1Conn, MutUntrackedOrigin]]()
        self.state_ptr = state_ptr
        self.tls_enabled = Bool(tls_lib) and Bool(server_tls_config)
        self.tls_lib = tls_lib^
        self.server_tls_config = server_tls_config^
        self._accept_future = Optional[AcceptFuture]()
        self._loop_ptr = null_ptr[NoneType, MutUntrackedOrigin]()
        self._needs_accept_rearm = False

    def __init__(out self, *, deinit move: Self):
        self.listener = move.listener^
        self.connections = move.connections^
        self.state_ptr = move.state_ptr
        self.tls_enabled = move.tls_enabled
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
        """Store the loop pointer and arm the initial accept.

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
        """Poll the accept future and process any accepted connection."""
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
            print("h1-bench: accept error:", e)
            self._needs_accept_rearm = True

    def _handle_accept_impl(mut self, var socket: Socket) raises:
        """Register an accepted socket and start reading from it.

        Args:
            socket: The accepted TCP socket (moved in).
        """
        var handler = BenchHandler(self.state_ptr)
        var http = H1HandlerServer[BenchHandler](handler=handler^)

        var tls_opt: Optional[TlsConnection]
        if self.tls_enabled:
            var tls_conn = TlsConnection.new_server(
                SharedLibrary(copy=self.tls_lib.value()),
                self.server_tls_config.value(),
            )
            tls_opt = Optional[TlsConnection](tls_conn^)
        else:
            tls_opt = Optional[TlsConnection]()

        var conn = H1Conn(
            socket=socket^,
            http=http^,
            tls=tls_opt^,
            loop_ptr=self._loop_ptr,
        )

        var conn_ptr = _heap_alloc[H1Conn](1)
        conn_ptr.unsafe_write(conn^)
        self.connections.append(conn_ptr)

        try:
            self._submit_accept()
        except:
            self._needs_accept_rearm = True

        try:
            conn_ptr[]._submit_recv()
        except:
            conn_ptr[]._begin_close()

    # --- Polling ---

    def poll_connections(mut self):
        """Poll all connections' recv/send futures for completed results."""
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
    """Run the HTTP/1.1 benchmark server until killed."""
    # Decide TLS mode + listen port from env.
    var tls_env = getenv_opt("BENCH_H1_TLS")
    var tls_enabled = tls_env.__bool__() and tls_env.value() == "1"

    var port: UInt16 = _DEFAULT_TLS_PORT if tls_enabled else _DEFAULT_PLAINTEXT_PORT
    var port_env = getenv_opt("BENCH_H1_PORT")
    if port_env.__bool__():
        try:
            port = UInt16(Int(port_env.value()))
        except:
            pass

    var role_env = getenv_opt("BENCH_H1_ROLE")
    var role: String = role_env.value() if role_env.__bool__() else (
        String("h1tls") if tls_enabled else String("h1")
    )

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

    # Heap-allocate combined bench state so the pointer stays stable.
    var state = BenchState(static_cache=cache^, dataset=dataset^)
    var state_ptr = _heap_alloc[BenchState](1)
    state_ptr.unsafe_write(state^)

    # Optionally build the TLS backend + server config (TLS mode).
    var tls_lib_opt: Optional[SharedLibrary]
    var server_tls_config_opt: Optional[TlsServerConfig]
    if tls_enabled:
        var certs_dir_opt = getenv_opt("CERTS_DIR")
        var certs_dir: String
        if certs_dir_opt.__bool__():
            certs_dir = certs_dir_opt.value()
        else:
            certs_dir = String("/certs")
        var cert_pem = read_file(certs_dir + "/server.crt")
        var key_pem = read_file(certs_dir + "/server.key")
        var tls = TlsBackend()
        var shared = tls.shared()
        var server_config = TlsServerConfig(
            shared, Span(cert_pem), Span(key_pem)
        )
        var alpn = List[String]()
        alpn.append("http/1.1")
        server_config.set_alpn_protocols(alpn)
        tls_lib_opt = Optional[SharedLibrary](tls.shared())
        server_tls_config_opt = Optional[TlsServerConfig](server_config^)
    else:
        tls_lib_opt = Optional[SharedLibrary]()
        server_tls_config_opt = Optional[TlsServerConfig]()

    # Listening socket (IPv4 TCP, non-blocking).
    var listener = Socket.tcp_v4()

    # Set SO_REUSEPORT for multi-worker support.
    var optval_buf = Owned[UInt8](4)
    var optval = optval_buf.ptr()
    optval[unsafe_offset=0] = 1
    optval[unsafe_offset=1] = 0
    optval[unsafe_offset=2] = 0
    optval[unsafe_offset=3] = 0
    var sso = external_call["setsockopt", Int32](
        listener.raw(), Int32(1), SO_REUSEPORT, optval, Int32(4)
    )
    # Keep optval alive across the setsockopt FFI call above.
    _ = optval_buf
    if sso < 0:
        print("h1-bench: warning: setsockopt(SO_REUSEPORT) failed")

    var bind_addr = SocketAddrV4(0, 0, 0, 0, port=port)
    listener.bind(bind_addr)
    listener.listen(Backlog.DEFAULT)

    var worker_id_opt = getenv_opt("BENCH_WORKER_ID")
    var prefix: String
    if worker_id_opt.__bool__():
        prefix = "[" + role + "-w" + worker_id_opt.value() + "] "
    else:
        prefix = ""
    var scheme: String = "https" if tls_enabled else "http"
    print(prefix + "h1-bench: listening on " + scheme + "://0.0.0.0:" + String(port)
          + (" (TLS, ALPN=http/1.1)" if tls_enabled else ""))

    # Build the WatchLoop and the heap-stable server.
    var server = H1BenchServer(
        listener=listener^,
        state_ptr=state_ptr,
        tls_lib=tls_lib_opt^,
        server_tls_config=server_tls_config_opt^,
    )
    var server_ptr = _heap_alloc[H1BenchServer](1)
    server_ptr.unsafe_write(server^)

    var loop = WatchLoop(capacity=_SQ_ENTRIES)
    server_ptr[].start(loop)

    # Event loop: step dispatches completions, then we poll futures.
    while True:
        _ = loop.step(timeout_ms=-1)
        server_ptr[].poll_accept()
        server_ptr[].poll_connections()
        server_ptr[].reap_closed()
