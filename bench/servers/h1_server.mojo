# bench/h1_server.mojo
#
# HTTP/1.1 benchmark server, plaintext or TLS-wrapped depending on env:
#
#   BENCH_H1_TLS=0|1   — enable TLS handshake + record layer (default 0)
#   BENCH_H1_PORT      — listen port (default 8080 plaintext, 8081 TLS)
#   BENCH_H1_ROLE      — log prefix tag (default "h1", set to "h1tls" by
#                        the launcher for the TLS sidecar worker)
#
# Uses boucle CompletionLoop + H1HandlerServer[BenchHandler]. When TLS is
# enabled, lifts the rustls glue from h2_server.mojo: TlsConnection wraps
# every accepted socket, ALPN advertises "http/1.1" only, and recv/send
# go through tls.receive_data / tls.drain_plaintext / tls.send_data /
# tls.drain_ciphertext just like the H2 path.

from std.collections import Dict
from std.collections.optional import Optional
from std.ffi import external_call
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.h1.handler_server import H1HandlerServer
from navette.runtime.io_uring import IoUring
from navette.tls import RustlsLibrary, TlsServerConfig, TlsConnection
from bench.lib.handler import (
    BenchHandler,
    BenchState,
    StaticEntry,
    _load_static_files,
    _load_dataset,
)
from interop.file_io import getenv_opt, read_file

from boucle import CompletionLoop, CompletionHandler
from boucle.handle import RawHandle, OwnedHandle
from boucle.net.socket import Socket
from boucle.net.addr import SocketAddrV4
from boucle.net.options import Backlog

# ---------------------------------------------------------------------------
# Token encoding
# ---------------------------------------------------------------------------

comptime OP_ACCEPT: UInt8 = 0
comptime OP_RECV: UInt8 = 1
comptime OP_SEND: UInt8 = 2
comptime LISTENER_CONN_ID: UInt64 = 0


def encode_token(conn_id: UInt64, op_kind: UInt8) -> UInt64:
    return (conn_id << 8) | UInt64(op_kind)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

comptime _RECV_BUF_SIZE: Int = 8192
comptime _DEFAULT_PLAINTEXT_PORT: UInt16 = 8080
comptime _DEFAULT_TLS_PORT: UInt16 = 8081
comptime SO_REUSEPORT: Int32 = 15

# TLS connection phases — only meaningful when tls_enabled.
comptime _PHASE_TLS_HANDSHAKE: UInt8 = 0
comptime _PHASE_READY: UInt8 = 1

# ---------------------------------------------------------------------------
# PendingSubmit
# ---------------------------------------------------------------------------

comptime _SUBMIT_ACCEPT: UInt8 = 0
comptime _SUBMIT_RECV: UInt8 = 1
comptime _SUBMIT_SEND: UInt8 = 2


struct PendingSubmit(Copyable, Movable):
    var kind: UInt8
    var fd: Int32
    var conn_id: UInt64
    var op_kind: UInt8

    def __init__(out self, kind: UInt8, fd: Int32, conn_id: UInt64, op_kind: UInt8):
        self.kind = kind
        self.fd = fd
        self.conn_id = conn_id
        self.op_kind = op_kind

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.fd = other.fd
        self.conn_id = other.conn_id
        self.op_kind = other.op_kind

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.fd = take.fd
        self.conn_id = take.conn_id
        self.op_kind = take.op_kind


# ---------------------------------------------------------------------------
# H1Conn — per-connection state
# ---------------------------------------------------------------------------


struct H1Conn(Movable):
    var conn_id: UInt64
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

    def __init__(
        out self,
        conn_id: UInt64,
        var fd: OwnedHandle,
        var http: H1HandlerServer[BenchHandler],
        var tls: Optional[TlsConnection],
    ):
        self.conn_id = conn_id
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

    def __init__(out self, *, deinit take: Self):
        self.conn_id = take.conn_id
        self.fd = take.fd^
        self.http = take.http^
        self.tls = take.tls^
        self.phase = take.phase
        self.recv_buf = take.recv_buf^
        self.send_buf = take.send_buf^
        self.send_pending = take.send_pending^
        self.send_in_flight = take.send_in_flight
        self.recv_in_flight = take.recv_in_flight
        self.closed = take.closed


# ---------------------------------------------------------------------------
# H1ServerHandler — CompletionHandler
# ---------------------------------------------------------------------------


struct H1ServerHandler(CompletionHandler):
    var listener_fd: Int32
    var connections: List[UnsafePointer[H1Conn, MutAnyOrigin]]
    var next_conn_id: UInt64
    var state_ptr: UnsafePointer[BenchState, MutAnyOrigin]
    var pending_submits: List[PendingSubmit]
    var tls_enabled: Bool
    var tls_lib: Optional[RustlsLibrary]
    var server_tls_config: Optional[TlsServerConfig]

    def __init__(
        out self,
        listener_fd: Int32,
        state_ptr: UnsafePointer[BenchState, MutAnyOrigin],
        var tls_lib: Optional[RustlsLibrary],
        var server_tls_config: Optional[TlsServerConfig],
    ):
        self.listener_fd = listener_fd
        self.connections = List[UnsafePointer[H1Conn, MutAnyOrigin]]()
        self.next_conn_id = 1
        self.state_ptr = state_ptr
        self.pending_submits = List[PendingSubmit]()
        self.tls_enabled = Bool(tls_lib) and Bool(server_tls_config)
        self.tls_lib = tls_lib^
        self.server_tls_config = server_tls_config^

    def __init__(out self, *, deinit take: Self):
        self.listener_fd = take.listener_fd
        self.connections = take.connections^
        self.next_conn_id = take.next_conn_id
        self.state_ptr = take.state_ptr
        self.pending_submits = take.pending_submits^
        self.tls_enabled = take.tls_enabled
        self.tls_lib = take.tls_lib^
        self.server_tls_config = take.server_tls_config^

    # --- Conn lookup ---

    def _find_index(self, conn_id: UInt64) -> Int:
        for i in range(len(self.connections)):
            if self.connections[i][].conn_id == conn_id:
                return i
        return -1

    # --- on_complete dispatch ---

    def on_complete(mut self, token: UInt64, result: Int32, flags: UInt32):
        try:
            self._dispatch(token, result, flags)
        except e:
            print("h1-bench: on_complete error:", e)

    def _dispatch(mut self, token: UInt64, result: Int32, flags: UInt32) raises:
        var op_kind = UInt8(token & 0xFF)
        var conn_id = token >> 8

        if op_kind == OP_ACCEPT:
            self._handle_accept(result, flags)
            return

        var idx = self._find_index(conn_id)
        if idx < 0:
            return

        # If connection is marked closed (deferred), clear in-flight flag
        # and free if no more operations are outstanding.
        if self.connections[idx][].closed:
            if op_kind == OP_RECV:
                self.connections[idx][].recv_in_flight = False
            elif op_kind == OP_SEND:
                self.connections[idx][].send_in_flight = False
            if (
                not self.connections[idx][].recv_in_flight
                and not self.connections[idx][].send_in_flight
            ):
                self._free_connection(idx)
            return

        if op_kind == OP_RECV:
            self._handle_recv(idx, result)
        elif op_kind == OP_SEND:
            self._handle_send(idx, result)

    # --- Submit queue helpers ---

    def _queue_accept(mut self):
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_ACCEPT,
                fd=self.listener_fd,
                conn_id=LISTENER_CONN_ID,
                op_kind=OP_ACCEPT,
            )
        )

    def _queue_recv(mut self, idx: Int):
        if self.connections[idx][].recv_in_flight:
            return
        self.connections[idx][].recv_in_flight = True
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_RECV,
                fd=self.connections[idx][].fd.raw(),
                conn_id=self.connections[idx][].conn_id,
                op_kind=OP_RECV,
            )
        )

    def _queue_send(mut self, idx: Int):
        if self.connections[idx][].send_in_flight:
            return
        if len(self.connections[idx][].send_buf) == 0:
            return
        self.connections[idx][].send_in_flight = True
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_SEND,
                fd=self.connections[idx][].fd.raw(),
                conn_id=self.connections[idx][].conn_id,
                op_kind=OP_SEND,
            )
        )

    # --- Staging helper ---

    def _stage_send(mut self, idx: Int, var data: List[UInt8]):
        if len(data) == 0:
            return
        if self.connections[idx][].send_in_flight:
            self.connections[idx][].send_pending.extend(Span(data))
            return
        self.connections[idx][].send_buf = data^
        self._queue_send(idx)

    # --- Accept ---

    def _handle_accept(mut self, result: Int32, flags: UInt32) raises:
        var more = (flags & UInt32(2)) != 0

        if result < 0:
            print("h1-bench: accept failed:", result)
            if not more:
                self._queue_accept()
            return

        var client_fd = result
        var conn_id = self.next_conn_id
        self.next_conn_id += 1

        var handle = OwnedHandle(raw=client_fd)
        var handler = BenchHandler(self.state_ptr)
        var http = H1HandlerServer[BenchHandler](handler=handler^)

        var tls_opt: Optional[TlsConnection]
        if self.tls_enabled:
            var tls_conn = TlsConnection.new_server(
                self.tls_lib.value(), self.server_tls_config.value()
            )
            tls_opt = Optional[TlsConnection](tls_conn^)
        else:
            tls_opt = Optional[TlsConnection]()

        var conn = H1Conn(
            conn_id=conn_id,
            fd=handle^,
            http=http^,
            tls=tls_opt^,
        )

        var conn_ptr = _heap_alloc[H1Conn](1).as_any_origin()
        conn_ptr.init_pointee_move(conn^)
        self.connections.append(conn_ptr)
        var idx = len(self.connections) - 1

        self._queue_recv(idx)
        if not more:
            self._queue_accept()

    # --- Recv ---

    def _handle_recv(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].recv_in_flight = False

        if result <= 0:
            self._close_connection(idx)
            return

        var n = Int(result)
        # Slice the recv buffer to just the bytes the kernel produced — no copy.
        var recv_span = Span(self.connections[idx][].recv_buf)[0:n]

        if self.tls_enabled:
            self._handle_recv_tls(idx, recv_span)
        else:
            self.connections[idx][].http.feed(recv_span)
            var response_bytes = self.connections[idx][].http.drain()
            if len(response_bytes) > 0:
                self._stage_send(idx, response_bytes^)

            if not self.connections[idx][].send_in_flight:
                if not self.connections[idx][].http.should_close():
                    self._queue_recv(idx)

    def _handle_recv_tls(mut self, idx: Int, chunk: Span[UInt8, _]) raises:
        # Feed ciphertext into rustls.
        self.connections[idx][].tls.value().receive_data(chunk)

        # Flush any handshake-reply ciphertext immediately.
        if self.connections[idx][].tls.value().wants_write():
            var ct = self.connections[idx][].tls.value().drain_ciphertext()
            self._stage_send(idx, ct^)

        # Still handshaking — keep reading more ciphertext.
        if self.connections[idx][].tls.value().is_handshaking():
            self._queue_recv(idx)
            return

        # Handshake done — switch phase and drain plaintext into H1 codec.
        if self.connections[idx][].phase == _PHASE_TLS_HANDSHAKE:
            self.connections[idx][].phase = _PHASE_READY

        var plaintext = self.connections[idx][].tls.value().drain_plaintext()
        if len(plaintext) > 0:
            self.connections[idx][].http.feed(Span(plaintext))
            var response_bytes = self.connections[idx][].http.drain()
            if len(response_bytes) > 0:
                self.connections[idx][].tls.value().send_data(Span(response_bytes))
                var ct2 = self.connections[idx][].tls.value().drain_ciphertext()
                self._stage_send(idx, ct2^)

        if not self.connections[idx][].send_in_flight:
            if not self.connections[idx][].http.should_close():
                self._queue_recv(idx)

    # --- Send ---

    def _handle_send(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].send_in_flight = False

        if result < 0:
            self._close_connection(idx)
            return

        # Handle partial sends.
        var sent = Int(result)
        var buf_len = len(self.connections[idx][].send_buf)
        if sent < buf_len:
            var remaining = List[UInt8](capacity=buf_len - sent)
            remaining.extend(Span(self.connections[idx][].send_buf)[sent:buf_len])
            self.connections[idx][].send_buf = remaining^
            self._queue_send(idx)
            return

        self.connections[idx][].send_buf = List[UInt8]()

        # Promote any pending data — single memcpy via extend, not byte-by-byte.
        if len(self.connections[idx][].send_pending) > 0:
            var pending_view = Span(self.connections[idx][].send_pending)
            var pending = List[UInt8](capacity=len(pending_view))
            pending.extend(pending_view)
            self.connections[idx][].send_pending = List[UInt8]()
            self.connections[idx][].send_buf = pending^
            self._queue_send(idx)
            return

        if self.connections[idx][].http.should_close():
            self._close_connection(idx)
        else:
            # Ready for next request.
            self._queue_recv(idx)

    # --- Close ---

    def _close_connection(mut self, idx: Int):
        if self.connections[idx][].closed:
            return
        self.connections[idx][].closed = True
        # If no io_uring operations are in-flight, free immediately.
        # Otherwise, keep the connection alive so the kernel can still
        # access its buffers.  The deferred path in _dispatch will call
        # _free_connection once all outstanding CQEs have drained.
        if (
            not self.connections[idx][].recv_in_flight
            and not self.connections[idx][].send_in_flight
        ):
            self._free_connection(idx)

    def _free_connection(mut self, idx: Int):
        var ptr = self.connections[idx]
        var last = len(self.connections) - 1
        if idx != last:
            self.connections[idx] = self.connections[last]
        _ = self.connections.pop()
        ptr.destroy_pointee()
        ptr.free()


# ---------------------------------------------------------------------------
# _drain_pending_submits
# ---------------------------------------------------------------------------


def _drain_pending_submits(mut io: IoUring[H1ServerHandler]) raises:
    var submits = io.loop._handler.pending_submits^
    io.loop._handler.pending_submits = List[PendingSubmit]()

    for i in range(len(submits)):
        var s = submits[i].copy()
        var token = encode_token(s.conn_id, s.op_kind)

        if s.kind == _SUBMIT_ACCEPT:
            try:
                io.loop.submit_accept_multishot(s.fd, token)
            except:
                # SQ full — re-queue for next poll iteration.
                io.loop._handler.pending_submits.append(s.copy())
        elif s.kind == _SUBMIT_RECV:
            var idx = io.loop._handler._find_index(s.conn_id)
            if idx < 0:
                # Connection gone — clear the in-flight flag would be moot,
                # just skip.
                continue
            var raw_addr = Int(
                io.loop._handler.connections[idx][].recv_buf.unsafe_ptr()
            )
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            try:
                io.loop.submit_recv(s.fd, buf_ptr, UInt(_RECV_BUF_SIZE), token)
            except:
                # SQ full — mark not-in-flight so it can be re-queued.
                io.loop._handler.connections[idx][].recv_in_flight = False
                io.loop._handler.pending_submits.append(s.copy())
        elif s.kind == _SUBMIT_SEND:
            var idx = io.loop._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            var n = len(io.loop._handler.connections[idx][].send_buf)
            if n == 0:
                continue
            var raw_addr = Int(
                io.loop._handler.connections[idx][].send_buf.unsafe_ptr()
            )
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            try:
                io.loop.submit_send(s.fd, buf_ptr, UInt(n), token)
            except:
                # SQ full — mark not-in-flight so it can be re-queued.
                io.loop._handler.connections[idx][].send_in_flight = False
                io.loop._handler.pending_submits.append(s.copy())


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
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
    var state_ptr = _heap_alloc[BenchState](1).as_any_origin()
    state_ptr.init_pointee_move(state^)

    # Optionally build the rustls library + server config (TLS mode).
    var tls_lib_opt: Optional[RustlsLibrary]
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
        var tls_lib = RustlsLibrary()
        var server_config = TlsServerConfig(
            tls_lib, Span(cert_pem), Span(key_pem)
        )
        var alpn = List[String]()
        alpn.append("http/1.1")
        server_config.set_alpn_protocols(tls_lib, alpn)
        tls_lib_opt = Optional[RustlsLibrary](tls_lib^)
        server_tls_config_opt = Optional[TlsServerConfig](server_config^)
    else:
        tls_lib_opt = Optional[RustlsLibrary]()
        server_tls_config_opt = Optional[TlsServerConfig]()

    # Listening socket (IPv4 TCP, non-blocking).
    var listener = Socket.tcp_v4()

    # Set SO_REUSEPORT for multi-worker support.
    var optval = _heap_alloc[UInt8](4).as_any_origin()
    optval[0] = 1
    optval[1] = 0
    optval[2] = 0
    optval[3] = 0
    var sso = external_call["setsockopt", Int32](
        listener.raw(), Int32(1), SO_REUSEPORT, optval, Int32(4)
    )
    optval.free()
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

    # Build handler + loop.
    var handler = H1ServerHandler(
        listener_fd=listener_fd,
        state_ptr=state_ptr,
        tls_lib=tls_lib_opt^,
        server_tls_config=server_tls_config_opt^,
    )
    var io = IoUring[H1ServerHandler](handler^, sq_entries=4096)

    # Initial accept submission.
    io.loop.submit_accept_multishot(listener_fd, encode_token(LISTENER_CONN_ID, OP_ACCEPT))

    # Event loop.
    while True:
        io.loop.poll(wait_nr=1)
        _drain_pending_submits(io)
        _ = listener
