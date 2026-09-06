# bench/servers/h1_server.mojo
#
# HTTP/1.1 benchmark server, plaintext or TLS-wrapped depending on env:
#
#   BENCH_H1_TLS=0|1   — enable TLS handshake + record layer (default 0)
#   BENCH_H1_PORT      — listen port (default 8080 plaintext, 8081 TLS)
#   BENCH_H1_ROLE      — log prefix tag (default "h1", set to "h1tls" by
#                        the launcher for the TLS sidecar worker)
#
# Uses boucle's IoUringDriver with per-operation `Completion` callbacks plus
# H1HandlerServer[BenchHandler]. Each connection owns its recv and send
# Completions; the kernel hands the Completion pointer back as the CQE
# user_data, so the callback recovers the connection directly instead of
# decoding a token. Submission is inline from the callbacks — SQEs land in
# the unsynced submission queue and are flushed by the next `tick()`, so the
# io_uring_enter cadence is one per loop iteration, as before.
#
# When TLS is enabled, lifts the rustls glue from h2_server.mojo:
# TlsConnection wraps every accepted socket, ALPN advertises "http/1.1"
# only, and recv/send go through tls.receive_data / tls.drain_plaintext /
# tls.send_data / tls.drain_ciphertext just like the H2 path.

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

from boucle.proactor.completion import Completion
from boucle.drivers.io_uring import IoUringDriver
from boucle.socle.linux.raw import IORING_CQE_F_MORE
from boucle.handle import OwnedHandle
from boucle.net.socket import Socket
from boucle.net.addr import SocketAddrV4
from boucle.net.options import Backlog

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

comptime _RECV_BUF_SIZE: Int = 8192
comptime _SQ_ENTRIES: Int = 4096
comptime _DEFAULT_PLAINTEXT_PORT: UInt16 = 8080
comptime _DEFAULT_TLS_PORT: UInt16 = 8081
comptime SO_REUSEPORT: Int32 = 15

# TLS connection phases — only meaningful when tls_enabled.
comptime _PHASE_TLS_HANDSHAKE: UInt8 = 0
comptime _PHASE_READY: UInt8 = 1


# ---------------------------------------------------------------------------
# H1Conn — per-connection state
# ---------------------------------------------------------------------------


struct H1Conn(Movable):
    """One accepted TCP connection plus its two owned Completion tokens.

    `_recv_cmp` and `_send_cmp` are submitted as the io_uring user_data for
    this connection's recv and send operations, so a completion routes back
    here by pointer rather than by decoding a token. `_owner` points at the
    `H1BenchServer` that allocated this connection; the module-level
    callbacks follow it to reach the server-side handling code.

    Both Completion contexts and `_owner` are null until `wire_context()`
    runs, which must happen once the struct is at its final heap address.
    """

    var fd: OwnedHandle
    var http: H1HandlerServer[BenchHandler]
    var tls: Optional[TlsConnection]
    var phase: UInt8
    var recv_buf: List[UInt8]
    var send_buf: List[UInt8]
    var send_pending: List[UInt8]
    var send_in_flight: Bool
    var recv_in_flight: Bool
    var closed: Bool
    var _recv_cmp: Completion
    var _send_cmp: Completion
    var _owner: Pointer[NoneType, MutUntrackedOrigin]

    def __init__(
        out self,
        var fd: OwnedHandle,
        var http: H1HandlerServer[BenchHandler],
        var tls: Optional[TlsConnection],
    ):
        """Build a connection with unwired Completions.

        Args:
            fd: Owned accepted socket handle.
            http: H1 codec plus benchmark handler for this connection.
            tls: A rustls connection when TLS is enabled, empty otherwise.
        """
        self.fd = fd^
        self.http = http^
        self.tls = tls^
        self.phase = _PHASE_TLS_HANDSHAKE if Bool(self.tls) else _PHASE_READY
        self.recv_buf = List[UInt8](length=_RECV_BUF_SIZE, fill=UInt8(0))
        self.send_buf = List[UInt8]()
        self.send_pending = List[UInt8]()
        self.send_in_flight = False
        self.recv_in_flight = False
        self.closed = False
        self._recv_cmp = Completion(
            invoke=_on_recv, context=null_ptr[NoneType, MutUntrackedOrigin]()
        )
        self._send_cmp = Completion(
            invoke=_on_send, context=null_ptr[NoneType, MutUntrackedOrigin]()
        )
        self._owner = null_ptr[NoneType, MutUntrackedOrigin]()

    def __init__(out self, *, deinit move: Self):
        """Move constructor."""
        self.fd = move.fd^
        self.http = move.http^
        self.tls = move.tls^
        self.phase = move.phase
        self.recv_buf = move.recv_buf^
        self.send_buf = move.send_buf^
        self.send_pending = move.send_pending^
        self.send_in_flight = move.send_in_flight
        self.recv_in_flight = move.recv_in_flight
        self.closed = move.closed
        self._recv_cmp = move._recv_cmp^
        self._send_cmp = move._send_cmp^
        self._owner = move._owner

    def wire_context(mut self, owner: Pointer[NoneType, MutUntrackedOrigin]):
        """Point both Completions at this connection's final heap address.

        Must run after the connection reaches its permanent address and
        before any SQE referencing it is queued.

        Args:
            owner: Type-erased pointer to the owning H1BenchServer.
        """
        var self_ctx = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self))
        )
        self._recv_cmp.context = self_ctx
        self._send_cmp.context = self_ctx
        self._owner = owner


# ---------------------------------------------------------------------------
# Module-level completion callbacks
# ---------------------------------------------------------------------------


def _on_accept(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Multishot-accept completion: context is the H1BenchServer.

    Args:
        ctx: Type-erased pointer to the owning H1BenchServer.
        result: Accepted file descriptor, or a negative errno.
        flags: CQE flags; IORING_CQE_F_MORE means the multishot lives on.
    """
    var srv = Pointer[H1BenchServer, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    try:
        srv[]._handle_accept(result, flags)
    except e:
        print("h1-bench: accept completion error:", e)


def _on_recv(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Recv completion: context is the H1Conn that owns the operation.

    Args:
        ctx: Type-erased pointer to the owning H1Conn.
        result: Bytes received, or a negative errno.
        flags: CQE flags (unused for single-shot recv).
    """
    var conn = Pointer[H1Conn, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    var srv = Pointer[H1BenchServer, MutUntrackedOrigin](
        unsafe_from_address=Int(conn[]._owner)
    )
    try:
        srv[]._handle_recv(conn, result)
    except e:
        print("h1-bench: recv completion error:", e)


def _on_send(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Send completion: context is the H1Conn that owns the operation.

    Args:
        ctx: Type-erased pointer to the owning H1Conn.
        result: Bytes sent, or a negative errno.
        flags: CQE flags (unused for single-shot send).
    """
    var conn = Pointer[H1Conn, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    var srv = Pointer[H1BenchServer, MutUntrackedOrigin](
        unsafe_from_address=Int(conn[]._owner)
    )
    try:
        srv[]._handle_send(conn, result)
    except e:
        print("h1-bench: send completion error:", e)


# ---------------------------------------------------------------------------
# H1BenchServer
# ---------------------------------------------------------------------------


struct H1BenchServer(Movable):
    """Owns the listener, the connection table and the accept Completion.

    Must be heap-allocated before use: the accept Completion and every
    connection's `_owner` store its address, so it may not move afterwards.
    """

    var listener_fd: Int32
    var connections: List[Pointer[H1Conn, MutUntrackedOrigin]]
    var state_ptr: Pointer[BenchState, MutUntrackedOrigin]
    var tls_enabled: Bool
    var tls_lib: Optional[SharedLibrary]
    var server_tls_config: Optional[TlsServerConfig]
    var _accept_cmp: Completion
    var _driver: Pointer[NoneType, MutUntrackedOrigin]

    def __init__(
        out self,
        listener_fd: Int32,
        state_ptr: Pointer[BenchState, MutUntrackedOrigin],
        var tls_lib: Optional[SharedLibrary],
        var server_tls_config: Optional[TlsServerConfig],
    ):
        """Build the server with an unwired accept Completion.

        Args:
            listener_fd: Bound and listening TCP socket.
            state_ptr: Shared benchmark state (static cache + dataset).
            tls_lib: The rustls shared library when TLS is enabled.
            server_tls_config: The rustls server config when TLS is enabled.
        """
        self.listener_fd = listener_fd
        self.connections = List[Pointer[H1Conn, MutUntrackedOrigin]]()
        self.state_ptr = state_ptr
        self.tls_enabled = Bool(tls_lib) and Bool(server_tls_config)
        self.tls_lib = tls_lib^
        self.server_tls_config = server_tls_config^
        self._accept_cmp = Completion(
            invoke=_on_accept, context=null_ptr[NoneType, MutUntrackedOrigin]()
        )
        self._driver = null_ptr[NoneType, MutUntrackedOrigin]()

    def __init__(out self, *, deinit move: Self):
        """Move constructor."""
        self.listener_fd = move.listener_fd
        self.connections = move.connections^
        self.state_ptr = move.state_ptr
        self.tls_enabled = move.tls_enabled
        self.tls_lib = move.tls_lib^
        self.server_tls_config = move.server_tls_config^
        self._accept_cmp = move._accept_cmp^
        self._driver = move._driver

    def __deinit__(deinit self):
        """Release every connection still in the table."""
        for i in range(len(self.connections)):
            var ptr = self.connections[i]
            ptr.unsafe_deinit_pointee()
            ptr.unsafe_free()

    # --- Lifecycle ---

    def wire_context(mut self):
        """Point the accept Completion at this server's final heap address."""
        self._accept_cmp.context = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self))
        )

    def start(mut self, mut driver: IoUringDriver) raises:
        """Record the driver and arm the multishot accept.

        Args:
            driver: The io_uring driver every operation is queued on.
        """
        self._driver = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=driver))
        )
        self._arm_accept()

    def _driver_ptr(self) -> Pointer[IoUringDriver, MutUntrackedOrigin]:
        """Recover the typed driver pointer stored by `start()`."""
        return Pointer[IoUringDriver, MutUntrackedOrigin](
            unsafe_from_address=Int(self._driver)
        )

    # --- Conn lookup ---

    def _find_index(self, conn: Pointer[H1Conn, MutUntrackedOrigin]) -> Int:
        """Locate a connection in the table by address.

        Only used on the close path, so the linear scan stays off the
        per-request hot path.

        Args:
            conn: Address of the connection to find.

        Returns:
            Its index, or -1 when the connection is no longer registered.
        """
        for i in range(len(self.connections)):
            if Int(self.connections[i]) == Int(conn):
                return i
        return -1

    # --- Operation arming ---

    def _arm_accept(mut self) raises:
        """Queue the multishot accept on the listener."""
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self._accept_cmp))
        )
        self._driver_ptr()[].accept_multishot(self.listener_fd, cmp_ptr)

    def _arm_recv(mut self, conn: Pointer[H1Conn, MutUntrackedOrigin]) raises:
        """Queue a recv into this connection's receive buffer.

        No-op when a recv is already outstanding. The in-flight flag is
        only set once the SQE is queued, so a full submission queue leaves
        the connection re-armable rather than permanently stuck.

        Args:
            conn: The connection to receive on.
        """
        if conn[].recv_in_flight:
            return
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=conn[]._recv_cmp))
        )
        var buf_ptr = Pointer[UInt8, MutUntrackedOrigin](
            unsafe_from_address=Int(conn[].recv_buf.unsafe_ptr())
        )
        self._driver_ptr()[].recv(
            conn[].fd.raw(), buf_ptr, UInt32(_RECV_BUF_SIZE), cmp_ptr
        )
        conn[].recv_in_flight = True

    def _arm_send(mut self, conn: Pointer[H1Conn, MutUntrackedOrigin]) raises:
        """Queue a send of this connection's staged output buffer.

        No-op when a send is already outstanding or the buffer is empty.

        Args:
            conn: The connection to send on.
        """
        if conn[].send_in_flight:
            return
        var n = len(conn[].send_buf)
        if n == 0:
            return
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=conn[]._send_cmp))
        )
        var buf_ptr = Pointer[UInt8, MutUntrackedOrigin](
            unsafe_from_address=Int(conn[].send_buf.unsafe_ptr())
        )
        self._driver_ptr()[].send(conn[].fd.raw(), buf_ptr, UInt32(n), cmp_ptr)
        conn[].send_in_flight = True

    # --- Staging helper ---

    def _stage_send(
        mut self,
        conn: Pointer[H1Conn, MutUntrackedOrigin],
        var data: List[UInt8],
    ) raises:
        """Send `data` now, or append it to the pending tail if busy.

        Args:
            conn: The connection the bytes belong to.
            data: Outbound bytes, moved in.
        """
        if len(data) == 0:
            return
        if conn[].send_in_flight:
            conn[].send_pending.extend(Span(data))
            return
        conn[].send_buf = data^
        self._arm_send(conn)

    # --- Accept ---

    def _handle_accept(mut self, result: Int, flags: UInt32) raises:
        """Register an accepted socket and start reading from it.

        Args:
            result: Accepted file descriptor, or a negative errno.
            flags: CQE flags; without IORING_CQE_F_MORE the multishot has
                   ended and must be re-armed.
        """
        var more = (flags & UInt32(IORING_CQE_F_MORE)) != 0

        if result < 0:
            print("h1-bench: accept failed:", result)
            if not more:
                self._arm_accept()
            return

        var client_fd = Int32(result)
        var handle = OwnedHandle(raw=client_fd)
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

        var conn = H1Conn(fd=handle^, http=http^, tls=tls_opt^)

        var conn_ptr = _heap_alloc[H1Conn](1)
        conn_ptr.unsafe_write(conn^)
        conn_ptr[].wire_context(
            Pointer[NoneType, MutUntrackedOrigin](
                unsafe_from_address=Int(Pointer(to=self))
            )
        )
        self.connections.append(conn_ptr)

        # Re-arm accept before the initial recv: queueing used to be
        # infallible, so a full submission queue must not be able to take
        # the listener down with it. A connection that cannot be armed is
        # closed so it drains and is reaped.
        if not more:
            self._arm_accept()
        try:
            self._arm_recv(conn_ptr)
        except:
            self._close_connection(conn_ptr)

    # --- Recv ---

    def _handle_recv(
        mut self, conn: Pointer[H1Conn, MutUntrackedOrigin], result: Int
    ) raises:
        """Feed received bytes through the H1 codec and stage the reply.

        Args:
            conn: The connection the completion belongs to.
            result: Bytes received, or a negative errno.
        """
        conn[].recv_in_flight = False

        if conn[].closed:
            if not conn[].send_in_flight:
                self._free_connection(conn)
            return

        if result <= 0:
            self._close_connection(conn)
            return

        var n = Int(result)
        # Slice the recv buffer to just the bytes the kernel produced — no copy.
        var recv_span = Span(conn[].recv_buf)[0:n]

        if self.tls_enabled:
            self._handle_recv_tls(conn, recv_span)
        else:
            conn[].http.feed(recv_span)
            var response_bytes = conn[].http.drain()
            if len(response_bytes) > 0:
                self._stage_send(conn, response_bytes^)

            if not conn[].send_in_flight:
                if not conn[].http.should_close():
                    self._arm_recv(conn)

    def _handle_recv_tls(
        mut self,
        conn: Pointer[H1Conn, MutUntrackedOrigin],
        chunk: Span[UInt8, _],
    ) raises:
        """Drive the rustls handshake, then the H1 codec, over one chunk.

        Args:
            conn: The connection the ciphertext belongs to.
            chunk: Ciphertext bytes just received from the socket.
        """
        # Feed ciphertext into rustls.
        conn[].tls.value().receive_data(chunk)

        # Flush any handshake-reply ciphertext immediately.
        if conn[].tls.value().wants_write():
            var ct = conn[].tls.value().drain_ciphertext()
            self._stage_send(conn, ct^)

        # Still handshaking — keep reading more ciphertext.
        if conn[].tls.value().is_handshaking():
            self._arm_recv(conn)
            return

        # Handshake done — switch phase and drain plaintext into H1 codec.
        if conn[].phase == _PHASE_TLS_HANDSHAKE:
            conn[].phase = _PHASE_READY

        var plaintext = conn[].tls.value().drain_plaintext()
        if len(plaintext) > 0:
            conn[].http.feed(Span(plaintext))
            var response_bytes = conn[].http.drain()
            if len(response_bytes) > 0:
                conn[].tls.value().send_data(Span(response_bytes))
                var ct2 = conn[].tls.value().drain_ciphertext()
                self._stage_send(conn, ct2^)

        if not conn[].send_in_flight:
            if not conn[].http.should_close():
                self._arm_recv(conn)

    # --- Send ---

    def _handle_send(
        mut self, conn: Pointer[H1Conn, MutUntrackedOrigin], result: Int
    ) raises:
        """Retire a send, re-queueing the tail or the pending buffer.

        Args:
            conn: The connection the completion belongs to.
            result: Bytes sent, or a negative errno.
        """
        conn[].send_in_flight = False

        if conn[].closed:
            if not conn[].recv_in_flight:
                self._free_connection(conn)
            return

        if result < 0:
            self._close_connection(conn)
            return

        # Handle partial sends.
        var sent = Int(result)
        var buf_len = len(conn[].send_buf)
        if sent < buf_len:
            var remaining = List[UInt8](capacity=buf_len - sent)
            remaining.extend(Span(conn[].send_buf)[sent:buf_len])
            conn[].send_buf = remaining^
            self._arm_send(conn)
            return

        conn[].send_buf = List[UInt8]()

        # Promote any pending data — single memcpy via extend, not byte-by-byte.
        if len(conn[].send_pending) > 0:
            var pending_view = Span(conn[].send_pending)
            var pending = List[UInt8](capacity=len(pending_view))
            pending.extend(pending_view)
            conn[].send_pending = List[UInt8]()
            conn[].send_buf = pending^
            self._arm_send(conn)
            return

        if conn[].http.should_close():
            self._close_connection(conn)
        else:
            # Ready for next request.
            self._arm_recv(conn)

    # --- Close ---

    def _close_connection(mut self, conn: Pointer[H1Conn, MutUntrackedOrigin]):
        """Mark a connection dead, freeing it once the kernel is done with it.

        While an operation is still in flight the kernel may write to this
        connection's buffers, so the memory is only released when the last
        outstanding completion has been retired.

        Args:
            conn: The connection to close.
        """
        if conn[].closed:
            return
        conn[].closed = True
        if not conn[].recv_in_flight and not conn[].send_in_flight:
            self._free_connection(conn)

    def _free_connection(mut self, conn: Pointer[H1Conn, MutUntrackedOrigin]):
        """Unregister and deallocate a connection with no operations pending.

        Args:
            conn: The connection to free. Dangling on return.
        """
        var idx = self._find_index(conn)
        if idx < 0:
            return
        var last = len(self.connections) - 1
        if idx != last:
            self.connections[idx] = self.connections[last]
        _ = self.connections.pop()
        conn.unsafe_deinit_pointee()
        conn.unsafe_free()


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
    var listener_fd = listener.raw()

    var worker_id_opt = getenv_opt("BENCH_WORKER_ID")
    var prefix: String
    if worker_id_opt.__bool__():
        prefix = "[" + role + "-w" + worker_id_opt.value() + "] "
    else:
        prefix = ""
    var scheme: String = "https" if tls_enabled else "http"
    print(prefix + "h1-bench: listening on " + scheme + "://0.0.0.0:" + String(port)
          + (" (TLS, ALPN=http/1.1)" if tls_enabled else ""))

    # Build the io_uring driver and the heap-stable server.
    var driver = IoUringDriver(capacity=_SQ_ENTRIES)

    var server = H1BenchServer(
        listener_fd=listener_fd,
        state_ptr=state_ptr,
        tls_lib=tls_lib_opt^,
        server_tls_config=server_tls_config_opt^,
    )
    var server_ptr = _heap_alloc[H1BenchServer](1)
    server_ptr.unsafe_write(server^)
    server_ptr[].wire_context()
    server_ptr[].start(driver)

    # Event loop: one submit_and_wait per iteration, completions dispatched
    # inline by their Completion callbacks.
    while True:
        _ = driver.tick(wait=True)
        _ = listener
