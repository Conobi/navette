# bench/h2_server.mojo
#
# HTTP/2 TLS benchmark server on port 8443 (TCP).
#
# Uses boucle CompletionLoop + CompletionHandler, TLS via librustls-mojo,
# and H2CoroServer with bench_h2_body_fn from handler.mojo.
#
# Layout:
#   - Token encoding helpers
#   - PendingSubmit
#   - H2Conn — per-connection state (TLS + H2CoroServer)
#   - H2ServerHandler — CompletionHandler implementation
#   - _drain_pending_submits
#   - main

from std.collections import Dict
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from src.tls import RustlsLibrary, TlsServerConfig, TlsConnection
from src.h2.h2_coro_server import H2CoroServer
from bench.handler import bench_h2_body_fn, StaticEntry, _load_static_files

from boucle import CompletionLoop, CompletionHandler
from boucle.handle import OwnedHandle
from boucle.net.socket import Socket
from boucle.net.addr import SocketAddrV4
from boucle.net.options import Backlog

from interop.file_io import read_file, getenv_opt


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
comptime _LISTEN_PORT: UInt16 = 8443


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------
comptime _PHASE_TLS_HANDSHAKE: UInt8 = 0
comptime _PHASE_H2_READY: UInt8 = 1
comptime _PHASE_DONE: UInt8 = 2


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
# H2Conn — per-connection state
# ---------------------------------------------------------------------------


struct H2Conn(Movable):
    var conn_id: UInt64
    var handle: OwnedHandle
    var tls: TlsConnection
    var h2: H2CoroServer
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
        var handle: OwnedHandle,
        var tls: TlsConnection,
        var h2: H2CoroServer,
    ):
        self.conn_id = conn_id
        self.handle = handle^
        self.tls = tls^
        self.h2 = h2^
        self.phase = _PHASE_TLS_HANDSHAKE
        self.recv_buf = List[UInt8](capacity=_RECV_BUF_SIZE)
        for _ in range(_RECV_BUF_SIZE):
            self.recv_buf.append(0)
        self.send_buf = List[UInt8]()
        self.send_pending = List[UInt8]()
        self.send_in_flight = False
        self.recv_in_flight = False
        self.closed = False

    def __init__(out self, *, deinit take: Self):
        self.conn_id = take.conn_id
        self.handle = take.handle^
        self.tls = take.tls^
        self.h2 = take.h2^
        self.phase = take.phase
        self.recv_buf = take.recv_buf^
        self.send_buf = take.send_buf^
        self.send_pending = take.send_pending^
        self.send_in_flight = take.send_in_flight
        self.recv_in_flight = take.recv_in_flight
        self.closed = take.closed


# ---------------------------------------------------------------------------
# H2ServerHandler — CompletionHandler
# ---------------------------------------------------------------------------


struct H2ServerHandler(CompletionHandler):
    var listener_fd: Int32
    var connections: List[UnsafePointer[H2Conn, MutAnyOrigin]]
    var next_conn_id: UInt64
    var tls_lib: RustlsLibrary
    var server_tls_config: TlsServerConfig
    var cache_ptr: UnsafePointer[Dict[String, StaticEntry], MutAnyOrigin]
    var pending_submits: List[PendingSubmit]

    def __init__(
        out self,
        listener_fd: Int32,
        var tls_lib: RustlsLibrary,
        var server_tls_config: TlsServerConfig,
        cache_ptr: UnsafePointer[Dict[String, StaticEntry], MutAnyOrigin],
    ):
        self.listener_fd = listener_fd
        self.connections = List[UnsafePointer[H2Conn, MutAnyOrigin]]()
        self.next_conn_id = 1
        self.tls_lib = tls_lib^
        self.server_tls_config = server_tls_config^
        self.cache_ptr = cache_ptr
        self.pending_submits = List[PendingSubmit]()

    fn __moveinit__(out self, deinit take: Self):
        self.listener_fd = take.listener_fd
        self.connections = take.connections^
        self.next_conn_id = take.next_conn_id
        self.tls_lib = take.tls_lib^
        self.server_tls_config = take.server_tls_config^
        self.cache_ptr = take.cache_ptr
        self.pending_submits = take.pending_submits^

    # --- Conn lookup ---

    def _find_index(self, conn_id: UInt64) -> Int:
        for i in range(len(self.connections)):
            if self.connections[i][].conn_id == conn_id:
                return i
        return -1

    # --- on_complete dispatch ---

    fn on_complete(mut self, token: UInt64, result: Int32, flags: UInt32):
        try:
            self._dispatch(token, result)
        except e:
            print("h2-bench: on_complete error:", e)

    def _dispatch(mut self, token: UInt64, result: Int32) raises:
        var op_kind = UInt8(token & 0xFF)
        var conn_id = token >> 8

        if op_kind == OP_ACCEPT:
            self._handle_accept(result)
            return

        var idx = self._find_index(conn_id)
        if idx < 0:
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
                fd=self.connections[idx][].handle.raw(),
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
                fd=self.connections[idx][].handle.raw(),
                conn_id=self.connections[idx][].conn_id,
                op_kind=OP_SEND,
            )
        )

    # --- Outbound staging ---

    def _stage_send(mut self, idx: Int, var ct: List[UInt8]):
        if len(ct) == 0:
            return
        if self.connections[idx][].send_in_flight:
            for i in range(len(ct)):
                self.connections[idx][].send_pending.append(ct[i])
            return
        self.connections[idx][].send_buf = ct^
        self._queue_send(idx)

    # --- Accept ---

    def _handle_accept(mut self, result: Int32) raises:
        if result < 0:
            print("h2-bench: accept failed:", result)
            self._queue_accept()
            return

        var client_fd = result
        var conn_id = self.next_conn_id
        self.next_conn_id += 1

        var tls_conn = TlsConnection.new_server(
            self.tls_lib, self.server_tls_config
        )

        var noneptr = UnsafePointer[NoneType, MutExternalOrigin](
            unsafe_from_address=Int(self.cache_ptr)
        )
        var h2 = H2CoroServer(
            body_fn=bench_h2_body_fn, extra_data=noneptr
        )

        var client_handle = OwnedHandle(raw=client_fd)
        var conn = H2Conn(
            conn_id=conn_id,
            handle=client_handle^,
            tls=tls_conn^,
            h2=h2^,
        )

        var conn_ptr = _heap_alloc[H2Conn](1).as_any_origin()
        conn_ptr.init_pointee_move(conn^)
        self.connections.append(conn_ptr)
        var idx = len(self.connections) - 1

        self._queue_recv(idx)
        self._queue_accept()

    # --- RECV ---

    def _handle_recv(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].recv_in_flight = False

        if result <= 0:
            self._close_connection(idx)
            return

        var n = Int(result)
        var chunk = List[UInt8](capacity=n)
        for i in range(n):
            chunk.append(self.connections[idx][].recv_buf[i])
        self.connections[idx][].tls.receive_data(Span(chunk))

        # If TLS has ciphertext to send (handshake reply), stage it
        if self.connections[idx][].tls.wants_write():
            var ct = self.connections[idx][].tls.drain_ciphertext()
            self._stage_send(idx, ct^)

        # Still handshaking — just keep reading
        if self.connections[idx][].tls.is_handshaking():
            self._queue_recv(idx)
            return

        # TLS handshake done — drain plaintext
        var plaintext = self.connections[idx][].tls.drain_plaintext()

        # On first post-TLS recv, flush the H2 server preface
        if self.connections[idx][].phase == _PHASE_TLS_HANDSHAKE:
            var preface_bytes = self.connections[idx][].h2.drain()
            if len(preface_bytes) > 0:
                self.connections[idx][].tls.send_data(Span(preface_bytes))
                var ct2 = self.connections[idx][].tls.drain_ciphertext()
                self._stage_send(idx, ct2^)
            self.connections[idx][].phase = _PHASE_H2_READY

        # Feed plaintext into H2CoroServer
        if len(plaintext) > 0:
            self.connections[idx][].h2.feed(Span(plaintext))
            var h2_out = self.connections[idx][].h2.drain()
            if len(h2_out) > 0:
                self.connections[idx][].tls.send_data(Span(h2_out))
                var ct3 = self.connections[idx][].tls.drain_ciphertext()
                self._stage_send(idx, ct3^)

        # Keep reading
        self._queue_recv(idx)

    # --- SEND ---

    def _handle_send(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].send_in_flight = False

        if result < 0:
            self._close_connection(idx)
            return

        var sent = Int(result)
        var buf_len = len(self.connections[idx][].send_buf)
        if sent < buf_len:
            # Partial send — keep unsent tail
            var remaining = List[UInt8](capacity=buf_len - sent)
            var i = sent
            while i < buf_len:
                remaining.append(self.connections[idx][].send_buf[i])
                i += 1
            self.connections[idx][].send_buf = remaining^
            self._queue_send(idx)
            return

        self.connections[idx][].send_buf = List[UInt8]()

        if len(self.connections[idx][].send_pending) > 0:
            var n_pending = len(self.connections[idx][].send_pending)
            var pending = List[UInt8](capacity=n_pending)
            for i in range(n_pending):
                pending.append(self.connections[idx][].send_pending[i])
            self.connections[idx][].send_pending = List[UInt8]()
            self.connections[idx][].send_buf = pending^
            self._queue_send(idx)
            return

        if self.connections[idx][].phase == _PHASE_DONE:
            self._close_connection(idx)
            return

    # --- Close ---

    def _close_connection(mut self, idx: Int):
        var ptr = self.connections[idx]
        ptr[].closed = True
        var last = len(self.connections) - 1
        if idx != last:
            self.connections[idx] = self.connections[last]
        _ = self.connections.pop()
        ptr.destroy_pointee()
        ptr.free()


# ---------------------------------------------------------------------------
# _drain_pending_submits
# ---------------------------------------------------------------------------


def _drain_pending_submits(mut loop: CompletionLoop[H2ServerHandler]) raises:
    var submits = loop._handler.pending_submits^
    loop._handler.pending_submits = List[PendingSubmit]()

    for i in range(len(submits)):
        var s = submits[i].copy()
        var token = encode_token(s.conn_id, s.op_kind)

        if s.kind == _SUBMIT_ACCEPT:
            loop.submit_accept(s.fd, token)
        elif s.kind == _SUBMIT_RECV:
            var idx = loop._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            var raw_addr = Int(
                loop._handler.connections[idx][].recv_buf.unsafe_ptr()
            )
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            loop.submit_recv(s.fd, buf_ptr, UInt(_RECV_BUF_SIZE), token)
        elif s.kind == _SUBMIT_SEND:
            var idx = loop._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            var n = len(loop._handler.connections[idx][].send_buf)
            if n == 0:
                continue
            var raw_addr = Int(
                loop._handler.connections[idx][].send_buf.unsafe_ptr()
            )
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            loop.submit_send(s.fd, buf_ptr, UInt(n), token)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
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
    var tls_lib = RustlsLibrary()
    var server_config = TlsServerConfig(
        tls_lib, Span(cert_pem), Span(key_pem)
    )
    var server_alpn = List[String]()
    server_alpn.append("h2")
    server_config.set_alpn_protocols(tls_lib, server_alpn)

    # Load static files
    var cache = _load_static_files(static_dir)
    var cache_ptr = _heap_alloc[Dict[String, StaticEntry]](1).as_any_origin()
    cache_ptr.init_pointee_move(cache^)

    # Listening socket
    var listener = Socket.tcp_v4()
    var bind_addr = SocketAddrV4(0, 0, 0, 0, port=_LISTEN_PORT)
    listener.bind(bind_addr)
    listener.listen(Backlog.DEFAULT)
    var listener_fd = listener.raw()

    print(
        "h2-bench: listening on https://127.0.0.1:" + String(_LISTEN_PORT)
    )

    # Build handler + loop
    var handler = H2ServerHandler(
        listener_fd=listener_fd,
        tls_lib=tls_lib^,
        server_tls_config=server_config^,
        cache_ptr=cache_ptr,
    )
    var loop = CompletionLoop[H2ServerHandler](handler^, sq_entries=256)

    loop.submit_accept(listener_fd, encode_token(LISTENER_CONN_ID, OP_ACCEPT))

    while True:
        loop.poll(wait_nr=1)
        _drain_pending_submits(loop)
        _ = listener
