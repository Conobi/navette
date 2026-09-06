# bench/servers/h2_server.mojo
#
# HTTP/2 TLS benchmark server on port 8443 (TCP).
#
# Uses boucle's IoUringDriver with per-operation `Completion` callbacks, TLS
# via librustls-mojo, and H2CoroServer with bench_h2_body_fn from handler.mojo.
#
# Each connection owns the two Completions its operations are submitted
# under, so the kernel hands the connection back by pointer (the Completion
# address is the CQE user_data) and no token has to be decoded. The recv
# Completion is armed once as a multishot and fires repeatedly until the
# kernel drops it. Submission happens inline from the callbacks; SQEs are
# only flushed by the next `tick()`, so io_uring_enter still runs once per
# loop iteration.
#
# Layout:
#   - H2Conn — per-connection state (TLS + H2CoroServer + Completions)
#   - Module-level completion callbacks
#   - H2BenchServer — listener, connection table, buffer ring
#   - main

from std.ffi import external_call
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc
from navette.util.owned_alloc import Owned
from navette.util.null_ptr import null_ptr

from navette.tls import TlsServerConfig, TlsConnection
from navette.tls.lib import TlsBackend, SharedLibrary
from navette.h2.h2_sync_server import H2CoroServer
from bench.lib.handler import (
    bench_h2_body_fn,
    BenchState,
    _load_static_files,
    _load_dataset,
)

from boucle.proactor.completion import Completion
from boucle.drivers.io_uring import IoUringDriver
from boucle.drivers.bufring import BufRing
from boucle.socle.linux.raw import (
    IORING_CQE_F_BUFFER,
    IORING_CQE_F_MORE,
    IORING_CQE_BUFFER_SHIFT,
)
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
comptime _LISTEN_PORT: UInt16 = 8443
comptime SO_REUSEPORT: Int32 = 15
# Slice H2 plaintext into ~one-TLS-record-sized chunks before encrypting so
# each batch of HTTP/2 frames lands in its own TLS record on the wire. This
# matches what real servers (nginx) emit and gives clients more cut points
# to interleave inbound WINDOW_UPDATEs and new HEADERS with our outbound
# response stream.
comptime _TLS_RECORD_CHUNK: Int = 16384
# Per-worker registered buffer ring (IORING_REGISTER_PBUF_RING). Returning
# a consumed buffer is a userspace store on `BufRing.add_buffer(buf_id)` —
# no SQE, no syscall, no kernel buffer-pool tree.
comptime _BUF_GROUP_ID: UInt16 = 1
comptime _BUF_RING_SIZE: Int = 1024  # 1024 × 8 KB = 8 MiB resident per worker
comptime _ENOBUFS: Int = -105


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------
comptime _PHASE_TLS_HANDSHAKE: UInt8 = 0
comptime _PHASE_H2_READY: UInt8 = 1
comptime _PHASE_DONE: UInt8 = 2


# ---------------------------------------------------------------------------
# H2Conn — per-connection state
# ---------------------------------------------------------------------------


struct H2Conn(Movable):
    """One TLS+HTTP/2 connection and the Completions it submits under.

    `_recv_cmp` backs a multishot recv, so it fires once per arrival until
    the kernel retires the operation; `_send_cmp` backs one send at a time.
    `_owner` points at the `H2BenchServer` so the module-level callbacks can
    reach the server-side handling code from the connection pointer alone.
    """

    var handle: OwnedHandle
    var tls: TlsConnection
    var h2: H2CoroServer
    var phase: UInt8
    var send_buf: List[UInt8]
    var send_pending: List[UInt8]
    var send_in_flight: Bool
    # `recv_in_flight` means "kernel multishot recv is registered" — set at
    # accept-time submit, cleared when a completion arrives without
    # IORING_CQE_F_MORE. (No per-conn recv_buf — buffers come from the
    # registered ring.)
    var recv_in_flight: Bool
    var closed: Bool
    var _recv_cmp: Completion
    var _send_cmp: Completion
    var _owner: Pointer[NoneType, MutUntrackedOrigin]

    def __init__(
        out self,
        var handle: OwnedHandle,
        var tls: TlsConnection,
        var h2: H2CoroServer,
    ):
        """Build a connection with unwired Completions.

        Args:
            handle: Owned accepted socket handle.
            tls: The rustls server connection wrapping this socket.
            h2: HTTP/2 codec bound to the benchmark body function.
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
        self._recv_cmp = move._recv_cmp^
        self._send_cmp = move._send_cmp^
        self._owner = move._owner

    def wire_context(mut self, owner: Pointer[NoneType, MutUntrackedOrigin]):
        """Point both Completions at this connection's final heap address.

        Must run after the connection reaches its permanent address and
        before any SQE referencing it is queued.

        Args:
            owner: Type-erased pointer to the owning H2BenchServer.
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
    """Multishot-accept completion: context is the H2BenchServer.

    Args:
        ctx: Type-erased pointer to the owning H2BenchServer.
        result: Accepted file descriptor, or a negative errno.
        flags: CQE flags; IORING_CQE_F_MORE means the multishot lives on.
    """
    var srv = Pointer[H2BenchServer, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    try:
        srv[]._handle_accept(result, flags)
    except e:
        print("h2-bench: accept completion error:", e)


def _on_recv(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Multishot-recv completion: context is the H2Conn that armed it.

    Args:
        ctx: Type-erased pointer to the owning H2Conn.
        result: Bytes received, or a negative errno.
        flags: CQE flags carrying the selected buffer id and F_MORE.
    """
    var conn = Pointer[H2Conn, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    var srv = Pointer[H2BenchServer, MutUntrackedOrigin](
        unsafe_from_address=Int(conn[]._owner)
    )
    try:
        srv[]._dispatch_recv(conn, result, flags)
    except e:
        print("h2-bench: recv completion error:", e)


def _on_send(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Send completion: context is the H2Conn that owns the operation.

    Args:
        ctx: Type-erased pointer to the owning H2Conn.
        result: Bytes sent, or a negative errno.
        flags: CQE flags (unused for single-shot send).
    """
    var conn = Pointer[H2Conn, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    var srv = Pointer[H2BenchServer, MutUntrackedOrigin](
        unsafe_from_address=Int(conn[]._owner)
    )
    try:
        srv[]._dispatch_send(conn, result)
    except e:
        print("h2-bench: send completion error:", e)


# ---------------------------------------------------------------------------
# H2BenchServer
# ---------------------------------------------------------------------------


struct H2BenchServer(Movable):
    """Owns the listener, the connection table and the provided-buffer ring.

    Must be heap-allocated before use: the accept Completion and every
    connection's `_owner` store its address, so it may not move afterwards.
    """

    var listener_fd: Int32
    var connections: List[Pointer[H2Conn, MutUntrackedOrigin]]
    var tls_lib: SharedLibrary
    var server_tls_config: TlsServerConfig
    var state_ptr: Pointer[BenchState, MutUntrackedOrigin]
    # Registered provided-buffer ring. CQE.flags >> IORING_CQE_BUFFER_SHIFT
    # gives buf_id; the buffer pointer is bring.buf_base + buf_id * buf_size.
    # Returning a buffer is bring.add_buffer(buf_id) — userspace store.
    var bring: BufRing
    var _accept_cmp: Completion
    var _driver: Pointer[NoneType, MutUntrackedOrigin]

    def __init__(
        out self,
        listener_fd: Int32,
        var tls_lib: SharedLibrary,
        var server_tls_config: TlsServerConfig,
        state_ptr: Pointer[BenchState, MutUntrackedOrigin],
        var bring: BufRing,
    ):
        """Build the server with an unwired accept Completion.

        Args:
            listener_fd: Bound and listening TCP socket.
            tls_lib: The rustls shared library handle.
            server_tls_config: The rustls server config (certs + ALPN).
            state_ptr: Shared benchmark state (static cache + dataset).
            bring: Registered provided-buffer ring, moved in.
        """
        self.listener_fd = listener_fd
        self.connections = List[Pointer[H2Conn, MutUntrackedOrigin]]()
        self.tls_lib = tls_lib^
        self.server_tls_config = server_tls_config^
        self.state_ptr = state_ptr
        self.bring = bring^
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
        self.state_ptr = move.state_ptr
        self.bring = move.bring^
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

    def _find_index(self, conn: Pointer[H2Conn, MutUntrackedOrigin]) -> Int:
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

    def _arm_recv_multishot(
        mut self, conn: Pointer[H2Conn, MutUntrackedOrigin]
    ) raises:
        """Arm a multishot recv drawing from the registered buffer ring.

        Produces one completion per arrival until the multishot ends (peer
        close, error, or ENOBUFS). Idempotent.

        Args:
            conn: The connection to receive on.
        """
        if conn[].recv_in_flight:
            return
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=conn[]._recv_cmp))
        )
        self._driver_ptr()[].recv_multishot(
            conn[].handle.raw(), _BUF_GROUP_ID, cmp_ptr
        )
        conn[].recv_in_flight = True

    def _arm_send(mut self, conn: Pointer[H2Conn, MutUntrackedOrigin]) raises:
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
        conn: Pointer[H2Conn, MutUntrackedOrigin],
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
            # Bulk move into pending (was per-byte append: ~16% self).
            conn[].send_pending.extend(ct^)
            return
        conn[].send_buf = ct^
        self._arm_send(conn)

    # --- Accept ---

    def _handle_accept(mut self, result: Int, flags: UInt32) raises:
        """Register an accepted socket and arm its multishot recv.

        Args:
            result: Accepted file descriptor, or a negative errno.
            flags: CQE flags; without IORING_CQE_F_MORE the multishot has
                   ended and must be re-armed.
        """
        var more = (flags & UInt32(IORING_CQE_F_MORE)) != 0

        if result < 0:
            print("h2-bench: accept failed:", result)
            if not more:
                self._arm_accept()
            return

        var client_fd = Int32(result)

        var tls_conn = TlsConnection.new_server(
            SharedLibrary(copy=self.tls_lib), self.server_tls_config
        )

        var noneptr = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(self.state_ptr)
        )
        var h2 = H2CoroServer(body_fn=bench_h2_body_fn, extra_data=noneptr)

        var client_handle = OwnedHandle(raw=client_fd)
        var conn = H2Conn(handle=client_handle^, tls=tls_conn^, h2=h2^)

        var conn_ptr = _heap_alloc[H2Conn](1)
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
            self._arm_recv_multishot(conn_ptr)
        except:
            self._close_connection(conn_ptr)

    # --- RECV ---

    def _dispatch_recv(
        mut self,
        conn: Pointer[H2Conn, MutUntrackedOrigin],
        result: Int,
        flags: UInt32,
    ) raises:
        """Route a recv completion, retiring a closed connection if drained.

        Multishot recv lifetime: `recv_in_flight` only clears when the
        multishot ends (no F_MORE). Until then the kernel keeps producing
        completions into ring buffers, so the connection must stay alive
        for buf_id-decoded reads to be valid.

        Args:
            conn: The connection the completion belongs to.
            result: Bytes received, or a negative errno.
            flags: CQE flags carrying the selected buffer id and F_MORE.
        """
        var multishot_ended = (flags & UInt32(IORING_CQE_F_MORE)) == 0

        if conn[].closed:
            if multishot_ended:
                conn[].recv_in_flight = False
            if not conn[].recv_in_flight and not conn[].send_in_flight:
                self._free_connection(conn)
            return

        self._handle_recv(conn, result, flags, multishot_ended)

    def _handle_recv(
        mut self,
        conn: Pointer[H2Conn, MutUntrackedOrigin],
        result: Int,
        flags: UInt32,
        multishot_ended: Bool,
    ) raises:
        """Decrypt one ring buffer and drive the HTTP/2 codec with it.

        Args:
            conn: The connection the completion belongs to.
            result: Bytes received, or a negative errno.
            flags: CQE flags carrying the selected buffer id.
            multishot_ended: Whether this completion retired the multishot.
        """
        if multishot_ended:
            conn[].recv_in_flight = False

        # -ENOBUFS: ring transiently empty when data arrived. Kernel ends
        # the multishot; re-arm it. (Should be rare with a 1024-buffer
        # ring; stays defensive in case of a burst.)
        if result == _ENOBUFS:
            if multishot_ended:
                self._arm_recv_multishot(conn)
            return

        if result < 0:
            self._close_connection(conn)
            return

        # result == 0: peer closed cleanly.
        if result == 0:
            self._close_connection(conn)
            return

        # Successful recv: kernel selected a buffer for us. Decode buf_id
        # from the upper 16 bits of `flags` and read directly from the
        # ring-mapped buffer.
        if (flags & UInt32(IORING_CQE_F_BUFFER)) == 0:
            if multishot_ended:
                self._close_connection(conn)
            return

        var buf_id_u32 = (flags >> UInt32(IORING_CQE_BUFFER_SHIFT)) & UInt32(0xFFFF)
        var buf_id = UInt16(buf_id_u32)
        var n = Int(result)
        var buf_ptr = self.bring.buf_base.unsafe_offset(
            Int(buf_id) * _RECV_BUF_SIZE
        )

        # TLS receive_data forwards to rustls' read_tls FFI synchronously
        # (the rustls C call deframes + copies into its internal state
        # before returning), so a Span over the ring slot is safe — the
        # kernel can only re-use this buf_id after add_buffer() runs,
        # which we sequence AFTER receive_data returns.
        conn[].tls.receive_data(Span[UInt8](unsafe_ptr=buf_ptr, length=n))

        # Userspace store — no SQE, no syscall.
        self.bring.add_buffer(buf_id)

        # If the multishot ended on this completion, re-arm it.
        if multishot_ended:
            self._arm_recv_multishot(conn)

        # If TLS has ciphertext to send (handshake reply), stage it.
        if conn[].tls.wants_write():
            var ct = conn[].tls.drain_ciphertext()
            self._stage_send(conn, ct^)

        # Still handshaking — multishot keeps draining.
        if conn[].tls.is_handshaking():
            return

        # TLS handshake done — drain plaintext.
        var plaintext = conn[].tls.drain_plaintext()

        # On first post-TLS recv, flush the H2 server preface.
        if conn[].phase == _PHASE_TLS_HANDSHAKE:
            var preface_bytes = conn[].h2.drain()
            if len(preface_bytes) > 0:
                conn[].tls.send_data(Span(preface_bytes))
                var ct2 = conn[].tls.drain_ciphertext()
                self._stage_send(conn, ct2^)
            conn[].phase = _PHASE_H2_READY

        # Feed plaintext into H2CoroServer.
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

    # --- SEND ---

    def _dispatch_send(
        mut self, conn: Pointer[H2Conn, MutUntrackedOrigin], result: Int
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
        mut self, conn: Pointer[H2Conn, MutUntrackedOrigin], result: Int
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
            # Partial send — keep unsent tail. Bulk-extend (was per-byte loop).
            var remaining = List[UInt8](capacity=buf_len - sent)
            remaining.extend(Span(conn[].send_buf)[sent:buf_len])
            conn[].send_buf = remaining^
            self._arm_send(conn)
            return

        conn[].send_buf = List[UInt8]()

        if len(conn[].send_pending) > 0:
            # Bulk-extend send_buf from a Span over pending; cheaper than
            # the prior per-byte append loop. (A direct field-move through
            # `conn[]` is rejected by Mojo's origin checker; this is a
            # single bulk memcpy instead.)
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

    def _close_connection(mut self, conn: Pointer[H2Conn, MutUntrackedOrigin]):
        """Mark a connection dead, freeing it once the kernel is done with it.

        While an operation is still in flight the kernel may write into a
        ring buffer tagged for this connection, so the memory is only
        released when the last outstanding completion has been retired.

        Args:
            conn: The connection to close.
        """
        if conn[].closed:
            return
        conn[].closed = True
        if not conn[].recv_in_flight and not conn[].send_in_flight:
            self._free_connection(conn)

    def _free_connection(mut self, conn: Pointer[H2Conn, MutUntrackedOrigin]):
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
    """Run the HTTP/2-over-TLS benchmark server until killed."""
    # Load certs
    var certs_dir_opt = getenv_opt("CERTS_DIR")
    var certs_dir: String
    if Bool(certs_dir_opt):
        certs_dir = certs_dir_opt.unsafe_take()
    else:
        certs_dir = String("/certs")

    var static_dir_opt = getenv_opt("STATIC_DIR")
    var static_dir: String
    if Bool(static_dir_opt):
        static_dir = static_dir_opt.unsafe_take()
    else:
        static_dir = String("/data/static")

    var cert_pem = read_file(certs_dir + "/server.crt")
    var key_pem = read_file(certs_dir + "/server.key")

    # TLS setup
    var tls = TlsBackend()
    var shared = tls.shared()
    var server_config = TlsServerConfig(
        shared, Span(cert_pem), Span(key_pem)
    )
    var server_alpn = List[String]()
    server_alpn.append("h2")
    server_config.set_alpn_protocols(server_alpn)

    # Load static files
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

    # Listening socket
    var listener = Socket.tcp_v4()
    # Set SO_REUSEPORT for multi-worker support.
    var reuseport_val_buf = Owned[UInt8](4)
    var reuseport_val = reuseport_val_buf.ptr()
    reuseport_val[unsafe_offset=0] = 1
    reuseport_val[unsafe_offset=1] = 0
    reuseport_val[unsafe_offset=2] = 0
    reuseport_val[unsafe_offset=3] = 0
    var rp_rc = external_call["setsockopt", Int32](
        listener.raw(), Int32(1), SO_REUSEPORT, reuseport_val, Int32(4)
    )
    # Keep reuseport_val alive across the setsockopt FFI call above.
    _ = reuseport_val_buf
    if rp_rc < 0:
        print("h2-bench: warning: setsockopt(SO_REUSEPORT) failed")
    var bind_addr = SocketAddrV4(0, 0, 0, 0, port=_LISTEN_PORT)
    listener.bind(bind_addr)
    listener.listen(Backlog.DEFAULT)
    var listener_fd = listener.raw()

    var worker_id_opt = getenv_opt("BENCH_WORKER_ID")
    var prefix: String
    if worker_id_opt.__bool__():
        prefix = "[h2-w" + worker_id_opt.value() + "] "
    else:
        prefix = ""
    print(prefix + "h2-bench: listening on https://127.0.0.1:" + String(_LISTEN_PORT))

    # Allocate the per-worker buffer pool (data buffers; the ring
    # metadata is allocated separately by register_buf_ring).
    var buf_base = _heap_alloc[UInt8](_BUF_RING_SIZE * _RECV_BUF_SIZE)

    var driver = IoUringDriver(capacity=_SQ_ENTRIES)

    # Register the buffer ring with the kernel before the first accept.
    # From here on, returning a buffer is a userspace store
    # (BufRing.add_buffer).
    var bring = driver.register_buf_ring(
        buf_base,
        buf_size=UInt32(_RECV_BUF_SIZE),
        count=_BUF_RING_SIZE,
        group_id=_BUF_GROUP_ID,
    )

    var server = H2BenchServer(
        listener_fd=listener_fd,
        tls_lib=tls.shared(),
        server_tls_config=server_config^,
        state_ptr=state_ptr,
        bring=bring^,
    )
    var server_ptr = _heap_alloc[H2BenchServer](1)
    server_ptr.unsafe_write(server^)
    server_ptr[].wire_context()
    server_ptr[].start(driver)

    # Event loop: one submit_and_wait per iteration, completions dispatched
    # inline by their Completion callbacks.
    while True:
        _ = driver.tick(wait=True)
        _ = listener
