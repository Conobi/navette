# bench/servers/h2_streaming_server.mojo
#
# HTTP/2 TLS benchmark server for H2 *streaming* handlers on port 8445 (TCP).
#
# Simplified single-process variant of bench/servers/h2_server.mojo. That
# bench uses H2CoroServer (sync coroutine dispatch) + multishot recv over a
# registered BufRing + multi-worker support. This streaming bench uses
# H2StreamingServer (stackful coroutines) with the same TCP/TLS/io_uring
# plumbing but plain single-shot recv into a per-connection buffer and no
# multi-process or BufRing complexity — simpler to reason about for the
# streaming demo.
#
# Each connection owns the Completions its recv and send are submitted
# under, so the kernel returns the connection by pointer (the Completion
# address is the CQE user_data) rather than by a decoded token. Submission
# is inline from the callbacks; the SQEs are flushed by the next `tick()`,
# so io_uring_enter still runs once per loop iteration.
#
# The demo handler is llm_stream_h2_handler from bench/lib/streaming_handler.mojo,
# which emits 64 SSE tokens per request (no body needed from client).
#
# Run smoke test:
#   ./bench/h2_streaming_server &
#   h2load -c 1 -m 1 -n 1 https://127.0.0.1:8445/stream 2>&1 | head -20
#   kill %1
#
# Uses port 8445 (not 8443) to avoid collision with bench/servers/h2_server.mojo.

from std.ffi import external_call
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc

from navette.tls import TlsServerConfig, TlsConnection
from navette.tls.lib import TlsBackend, SharedLibrary
from navette.h2.h2_streaming_server import H2StreamingServer
from navette.util.null_ptr import null_ptr

from bench.lib.streaming_handler import llm_stream_h2_handler

from boucle.proactor.completion import Completion
from boucle.drivers.io_uring import IoUringDriver
from boucle.socle.linux.raw import IORING_CQE_F_MORE
from boucle.handle import OwnedHandle
from boucle.net.socket import Socket
from boucle.net.addr import SocketAddrV4
from boucle.net.options import Backlog

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
    """One TLS+HTTP/2 streaming connection and its two owned Completions.

    `_recv_cmp` and `_send_cmp` are the io_uring user_data for this
    connection's recv and send, so a completion routes back here by pointer.
    `_owner` points at the `H2StreamingBenchServer`, which is how the
    module-level callbacks reach the server-side handling code.
    """

    var handle: OwnedHandle
    var tls: TlsConnection
    var h2: H2StreamingServer
    var phase: UInt8
    var send_buf: List[UInt8]
    var send_pending: List[UInt8]
    var send_in_flight: Bool
    var recv_in_flight: Bool
    var closed: Bool
    var recv_buf: Pointer[UInt8, MutUntrackedOrigin]
    var _recv_cmp: Completion
    var _send_cmp: Completion
    var _owner: Pointer[NoneType, MutUntrackedOrigin]

    def __init__(
        out self,
        var handle: OwnedHandle,
        var tls: TlsConnection,
        var h2: H2StreamingServer,
        recv_buf_size: Int,
    ):
        """Build a connection with unwired Completions.

        Args:
            handle: Owned accepted socket handle.
            tls: The rustls server connection wrapping this socket.
            h2: HTTP/2 streaming codec bound to the demo handler.
            recv_buf_size: Bytes to allocate for the receive buffer.
        """
        self.handle = handle^
        self.tls = tls^
        self.h2 = h2^
        self.phase = _PHASE_TLS_HANDSHAKE
        self.send_buf = List[UInt8]()
        self.send_pending = List[UInt8]()
        self.send_in_flight = False
        self.recv_in_flight = False
        self.closed = False
        self.recv_buf = _heap_alloc[UInt8](recv_buf_size)
        self._recv_cmp = Completion(
            invoke=_on_recv, context=null_ptr[NoneType, MutUntrackedOrigin]()
        )
        self._send_cmp = Completion(
            invoke=_on_send, context=null_ptr[NoneType, MutUntrackedOrigin]()
        )
        self._owner = null_ptr[NoneType, MutUntrackedOrigin]()

    def __init__(out self, *, deinit move: Self):
        """Move constructor."""
        self.handle = move.handle^
        self.tls = move.tls^
        self.h2 = move.h2^
        self.phase = move.phase
        self.send_buf = move.send_buf^
        self.send_pending = move.send_pending^
        self.send_in_flight = move.send_in_flight
        self.recv_in_flight = move.recv_in_flight
        self.closed = move.closed
        self.recv_buf = move.recv_buf
        self._recv_cmp = move._recv_cmp^
        self._send_cmp = move._send_cmp^
        self._owner = move._owner

    def wire_context(mut self, owner: Pointer[NoneType, MutUntrackedOrigin]):
        """Point both Completions at this connection's final heap address.

        Must run after the connection reaches its permanent address and
        before any SQE referencing it is queued.

        Args:
            owner: Type-erased pointer to the owning H2StreamingBenchServer.
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
    """Multishot-accept completion: context is the server.

    Args:
        ctx: Type-erased pointer to the owning H2StreamingBenchServer.
        result: Accepted file descriptor, or a negative errno.
        flags: CQE flags; IORING_CQE_F_MORE means the multishot lives on.
    """
    var srv = Pointer[H2StreamingBenchServer, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    try:
        srv[]._handle_accept(result, flags)
    except e:
        print("h2-streaming-bench: accept completion error:", e)


def _on_recv(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Recv completion: context is the H2StreamingConn that owns it.

    Args:
        ctx: Type-erased pointer to the owning H2StreamingConn.
        result: Bytes received, or a negative errno.
        flags: CQE flags.
    """
    var conn = Pointer[H2StreamingConn, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    var srv = Pointer[H2StreamingBenchServer, MutUntrackedOrigin](
        unsafe_from_address=Int(conn[]._owner)
    )
    try:
        srv[]._dispatch_recv(conn, result, flags)
    except e:
        print("h2-streaming-bench: recv completion error:", e)


def _on_send(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Send completion: context is the H2StreamingConn that owns it.

    Args:
        ctx: Type-erased pointer to the owning H2StreamingConn.
        result: Bytes sent, or a negative errno.
        flags: CQE flags (unused for single-shot send).
    """
    var conn = Pointer[H2StreamingConn, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    var srv = Pointer[H2StreamingBenchServer, MutUntrackedOrigin](
        unsafe_from_address=Int(conn[]._owner)
    )
    try:
        srv[]._dispatch_send(conn, result)
    except e:
        print("h2-streaming-bench: send completion error:", e)


# ---------------------------------------------------------------------------
# H2StreamingBenchServer
# ---------------------------------------------------------------------------


struct H2StreamingBenchServer(Movable):
    """Owns the listener, the connection table and the accept Completion.

    Must be heap-allocated before use: the accept Completion and every
    connection's `_owner` store its address, so it may not move afterwards.
    """

    var listener_fd: Int32
    var connections: List[Pointer[H2StreamingConn, MutUntrackedOrigin]]
    var tls_lib: SharedLibrary
    var server_tls_config: TlsServerConfig
    var _accept_cmp: Completion
    var _driver: Pointer[NoneType, MutUntrackedOrigin]

    def __init__(
        out self,
        listener_fd: Int32,
        var tls_lib: SharedLibrary,
        var server_tls_config: TlsServerConfig,
    ):
        """Build the server with an unwired accept Completion.

        Args:
            listener_fd: Bound and listening TCP socket.
            tls_lib: The rustls shared library handle.
            server_tls_config: The rustls server config (certs + ALPN).
        """
        self.listener_fd = listener_fd
        self.connections = List[Pointer[H2StreamingConn, MutUntrackedOrigin]]()
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
        self.tls_lib = move.tls_lib^
        self.server_tls_config = move.server_tls_config^
        self._accept_cmp = move._accept_cmp^
        self._driver = move._driver

    def __deinit__(deinit self):
        """Release every connection still in the table."""
        for i in range(len(self.connections)):
            var ptr = self.connections[i]
            ptr[].recv_buf.unsafe_free()
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

    def _find_index(
        self, conn: Pointer[H2StreamingConn, MutUntrackedOrigin]
    ) -> Int:
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

    def _arm_recv(
        mut self, conn: Pointer[H2StreamingConn, MutUntrackedOrigin]
    ) raises:
        """Queue a single-shot recv into this connection's receive buffer.

        No-op when a recv is already outstanding.

        Args:
            conn: The connection to receive on.
        """
        if conn[].recv_in_flight:
            return
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=conn[]._recv_cmp))
        )
        self._driver_ptr()[].recv(
            conn[].handle.raw(),
            conn[].recv_buf,
            UInt32(_RECV_BUF_SIZE),
            cmp_ptr,
        )
        conn[].recv_in_flight = True

    def _arm_send(
        mut self, conn: Pointer[H2StreamingConn, MutUntrackedOrigin]
    ) raises:
        """Queue a send of this connection's staged ciphertext buffer.

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
        self._driver_ptr()[].send(
            conn[].handle.raw(), buf_ptr, UInt32(n), cmp_ptr
        )
        conn[].send_in_flight = True

    # --- Outbound staging ---

    def _stage_send(
        mut self,
        conn: Pointer[H2StreamingConn, MutUntrackedOrigin],
        var ct: List[UInt8],
    ) raises:
        """Send `ct` now, or append it to the pending tail if busy.

        Args:
            conn: The connection the ciphertext belongs to.
            ct: Outbound ciphertext, moved in.
        """
        if len(ct) == 0:
            return
        if conn[].send_in_flight:
            conn[].send_pending.extend(ct^)
            return
        conn[].send_buf = ct^
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
            print("h2-streaming-bench: accept failed:", result)
            if not more:
                self._arm_accept()
            return

        var client_fd = Int32(result)

        var tls_conn = TlsConnection.new_server(
            SharedLibrary(copy=self.tls_lib), self.server_tls_config
        )

        var h2 = H2StreamingServer(handler_fn=llm_stream_h2_handler)

        var client_handle = OwnedHandle(raw=client_fd)
        var conn = H2StreamingConn(
            handle=client_handle^,
            tls=tls_conn^,
            h2=h2^,
            recv_buf_size=_RECV_BUF_SIZE,
        )

        var conn_ptr = _heap_alloc[H2StreamingConn](1)
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

    # --- RECV ---

    def _dispatch_recv(
        mut self,
        conn: Pointer[H2StreamingConn, MutUntrackedOrigin],
        result: Int,
        flags: UInt32,
    ) raises:
        """Route a recv completion, retiring a closed connection if drained.

        Args:
            conn: The connection the completion belongs to.
            result: Bytes received, or a negative errno.
            flags: CQE flags.
        """
        # recv here is single-shot, so IORING_CQE_F_MORE is never set and
        # every completion retires the operation. The check is kept so the
        # in-flight bookkeeping stays correct if the recv is ever promoted
        # to multishot.
        var multishot_ended = (flags & UInt32(IORING_CQE_F_MORE)) == 0

        if conn[].closed:
            if multishot_ended:
                conn[].recv_in_flight = False
            if not conn[].recv_in_flight and not conn[].send_in_flight:
                self._free_connection(conn)
            return

        self._handle_recv(conn, result, multishot_ended)

    def _handle_recv(
        mut self,
        conn: Pointer[H2StreamingConn, MutUntrackedOrigin],
        result: Int,
        multishot_ended: Bool,
    ) raises:
        """Decrypt the received bytes and drive the streaming HTTP/2 codec.

        Args:
            conn: The connection the completion belongs to.
            result: Bytes received, or a negative errno.
            multishot_ended: Whether this completion retired the operation.
        """
        if multishot_ended:
            conn[].recv_in_flight = False

        if result < 0:
            self._close_connection(conn)
            return

        if result == 0:
            self._close_connection(conn)
            return

        var n = Int(result)
        var buf_ptr = conn[].recv_buf

        conn[].tls.receive_data(Span[UInt8](unsafe_ptr=buf_ptr, length=n))

        if multishot_ended:
            self._arm_recv(conn)

        if conn[].tls.wants_write():
            var ct = conn[].tls.drain_ciphertext()
            self._stage_send(conn, ct^)

        if conn[].tls.is_handshaking():
            return

        var plaintext = conn[].tls.drain_plaintext()

        if conn[].phase == _PHASE_TLS_HANDSHAKE:
            var preface_bytes = conn[].h2.drain()
            if len(preface_bytes) > 0:
                conn[].tls.send_data(Span(preface_bytes))
                var ct2 = conn[].tls.drain_ciphertext()
                self._stage_send(conn, ct2^)
            conn[].phase = _PHASE_H2_READY

        if len(plaintext) > 0:
            conn[].h2.feed(Span(plaintext))
            var h2_out = conn[].h2.drain()
            var total = len(h2_out)
            var off = 0
            while off < total:
                var end = off + _TLS_RECORD_CHUNK
                if end > total:
                    end = total
                conn[].tls.send_data(Span(h2_out)[off:end])
                var ct = conn[].tls.drain_ciphertext()
                if len(ct) > 0:
                    self._stage_send(conn, ct^)
                off = end

        if conn[].h2.should_close():
            self._close_connection(conn)

    # --- SEND ---

    def _dispatch_send(
        mut self,
        conn: Pointer[H2StreamingConn, MutUntrackedOrigin],
        result: Int,
    ) raises:
        """Route a send completion, retiring a closed connection if drained.

        Args:
            conn: The connection the completion belongs to.
            result: Bytes sent, or a negative errno.
        """
        conn[].send_in_flight = False

        if conn[].closed:
            if not conn[].recv_in_flight:
                self._free_connection(conn)
            return

        self._handle_send(conn, result)

    def _handle_send(
        mut self,
        conn: Pointer[H2StreamingConn, MutUntrackedOrigin],
        result: Int,
    ) raises:
        """Retire a send, re-queueing the tail or the pending buffer.

        Args:
            conn: The connection the completion belongs to.
            result: Bytes sent, or a negative errno.
        """
        if result < 0:
            self._close_connection(conn)
            return

        var sent = Int(result)
        var buf_len = len(conn[].send_buf)
        if sent < buf_len:
            var remaining = List[UInt8](capacity=buf_len - sent)
            remaining.extend(Span(conn[].send_buf)[sent:buf_len])
            conn[].send_buf = remaining^
            self._arm_send(conn)
            return

        conn[].send_buf = List[UInt8]()

        if len(conn[].send_pending) > 0:
            var n = len(conn[].send_pending)
            var fresh = List[UInt8](capacity=n)
            fresh.extend(Span(conn[].send_pending))
            conn[].send_pending = List[UInt8]()
            conn[].send_buf = fresh^
            self._arm_send(conn)
            return

        if conn[].phase == _PHASE_DONE:
            self._close_connection(conn)
            return

    # --- Close ---

    def _close_connection(
        mut self, conn: Pointer[H2StreamingConn, MutUntrackedOrigin]
    ):
        """Mark a connection dead, freeing it once the kernel is done with it.

        While an operation is in flight the kernel may still write into this
        connection's receive buffer, so the memory is only released when the
        last outstanding completion has been retired.

        Args:
            conn: The connection to close.
        """
        if conn[].closed:
            return
        conn[].closed = True
        if not conn[].recv_in_flight and not conn[].send_in_flight:
            self._free_connection(conn)

    def _free_connection(
        mut self, conn: Pointer[H2StreamingConn, MutUntrackedOrigin]
    ):
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
        conn[].recv_buf.unsafe_free()
        conn.unsafe_deinit_pointee()
        conn.unsafe_free()


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
    var listener_fd = listener.raw()

    print("h2-streaming-bench: listening on https://127.0.0.1:" + String(_LISTEN_PORT))
    print("h2-streaming-bench: handler=llm_stream_h2_handler tokens=64 SSE chunks per request")

    var driver = IoUringDriver(capacity=_SQ_ENTRIES)

    var server = H2StreamingBenchServer(
        listener_fd=listener_fd,
        tls_lib=tls.shared(),
        server_tls_config=server_config^,
    )
    var server_ptr = _heap_alloc[H2StreamingBenchServer](1)
    server_ptr.unsafe_write(server^)
    server_ptr[].wire_context()
    server_ptr[].start(driver)

    # Event loop: one submit_and_wait per iteration, completions dispatched
    # inline by their Completion callbacks.
    while True:
        _ = driver.tick(wait=True)
        _ = listener
