# bench/h1_server.mojo
#
# HTTP/1.1 plaintext benchmark server on port 8080.
# Uses boucle CompletionLoop + H1HandlerServer[BenchHandler].
#
# Adapted from examples/reverse_proxy/main.mojo with all TLS and
# backend-proxy logic stripped out.

from std.collections import Dict
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from src.h1.handler_server import H1HandlerServer
from bench.handler import BenchHandler, StaticEntry, _load_static_files
from interop.file_io import getenv_opt

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
comptime _LISTEN_PORT: UInt16 = 8080

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
    ):
        self.conn_id = conn_id
        self.fd = fd^
        self.http = http^
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
        self.fd = take.fd^
        self.http = take.http^
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
    var cache_ptr: UnsafePointer[Dict[String, StaticEntry], MutAnyOrigin]
    var pending_submits: List[PendingSubmit]

    def __init__(
        out self,
        listener_fd: Int32,
        cache_ptr: UnsafePointer[Dict[String, StaticEntry], MutAnyOrigin],
    ):
        self.listener_fd = listener_fd
        self.connections = List[UnsafePointer[H1Conn, MutAnyOrigin]]()
        self.next_conn_id = 1
        self.cache_ptr = cache_ptr
        self.pending_submits = List[PendingSubmit]()

    fn __moveinit__(out self, deinit take: Self):
        self.listener_fd = take.listener_fd
        self.connections = take.connections^
        self.next_conn_id = take.next_conn_id
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
            print("h1-bench: on_complete error:", e)

    def _dispatch(mut self, token: UInt64, result: Int32) raises:
        var op_kind = UInt8(token & 0xFF)
        var conn_id = token >> 8

        if op_kind == OP_ACCEPT:
            self._handle_accept(result)
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
            for i in range(len(data)):
                self.connections[idx][].send_pending.append(data[i])
            return
        self.connections[idx][].send_buf = data^
        self._queue_send(idx)

    # --- Accept ---

    def _handle_accept(mut self, result: Int32) raises:
        if result < 0:
            print("h1-bench: accept failed:", result)
            self._queue_accept()
            return

        var client_fd = result
        var conn_id = self.next_conn_id
        self.next_conn_id += 1

        var handle = OwnedHandle(raw=client_fd)
        var handler = BenchHandler(self.cache_ptr)
        var http = H1HandlerServer[BenchHandler](handler=handler^)

        var conn = H1Conn(
            conn_id=conn_id,
            fd=handle^,
            http=http^,
        )

        var conn_ptr = _heap_alloc[H1Conn](1).as_any_origin()
        conn_ptr.init_pointee_move(conn^)
        self.connections.append(conn_ptr)
        var idx = len(self.connections) - 1

        self._queue_recv(idx)
        self._queue_accept()

    # --- Recv ---

    def _handle_recv(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].recv_in_flight = False

        if result <= 0:
            self._close_connection(idx)
            return

        var n = Int(result)
        var chunk = List[UInt8](capacity=n)
        for i in range(n):
            chunk.append(self.connections[idx][].recv_buf[i])

        self.connections[idx][].http.feed(Span(chunk))

        var response_bytes = self.connections[idx][].http.drain()
        if len(response_bytes) > 0:
            self._stage_send(idx, response_bytes^)

        # If no response produced yet and connection still open, read more.
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
            var i = sent
            while i < buf_len:
                remaining.append(self.connections[idx][].send_buf[i])
                i += 1
            self.connections[idx][].send_buf = remaining^
            self._queue_send(idx)
            return

        self.connections[idx][].send_buf = List[UInt8]()

        # Promote any pending data.
        if len(self.connections[idx][].send_pending) > 0:
            var n_pending = len(self.connections[idx][].send_pending)
            var pending = List[UInt8](capacity=n_pending)
            for i in range(n_pending):
                pending.append(self.connections[idx][].send_pending[i])
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


def _drain_pending_submits(mut loop: CompletionLoop[H1ServerHandler]) raises:
    var submits = loop._handler.pending_submits^
    loop._handler.pending_submits = List[PendingSubmit]()

    for i in range(len(submits)):
        var s = submits[i].copy()
        var token = encode_token(s.conn_id, s.op_kind)

        if s.kind == _SUBMIT_ACCEPT:
            try:
                loop.submit_accept(s.fd, token)
            except:
                # SQ full — re-queue for next poll iteration.
                loop._handler.pending_submits.append(s.copy())
        elif s.kind == _SUBMIT_RECV:
            var idx = loop._handler._find_index(s.conn_id)
            if idx < 0:
                # Connection gone — clear the in-flight flag would be moot,
                # just skip.
                continue
            var raw_addr = Int(
                loop._handler.connections[idx][].recv_buf.unsafe_ptr()
            )
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            try:
                loop.submit_recv(s.fd, buf_ptr, UInt(_RECV_BUF_SIZE), token)
            except:
                # SQ full — mark not-in-flight so it can be re-queued.
                loop._handler.connections[idx][].recv_in_flight = False
                loop._handler.pending_submits.append(s.copy())
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
            try:
                loop.submit_send(s.fd, buf_ptr, UInt(n), token)
            except:
                # SQ full — mark not-in-flight so it can be re-queued.
                loop._handler.connections[idx][].send_in_flight = False
                loop._handler.pending_submits.append(s.copy())


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


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

    # Listening socket (IPv4 TCP, non-blocking).
    var listener = Socket.tcp_v4()
    var bind_addr = SocketAddrV4(0, 0, 0, 0, port=_LISTEN_PORT)
    listener.bind(bind_addr)
    listener.listen(Backlog.DEFAULT)
    var listener_fd = listener.raw()

    print("h1-bench: listening on http://0.0.0.0:" + String(_LISTEN_PORT))

    # Build handler + loop.
    var handler = H1ServerHandler(
        listener_fd=listener_fd,
        cache_ptr=cache_ptr,
    )
    var loop = CompletionLoop[H1ServerHandler](handler^, sq_entries=4096)

    # Initial accept submission.
    loop.submit_accept(listener_fd, encode_token(LISTENER_CONN_ID, OP_ACCEPT))

    # Event loop.
    while True:
        loop.poll(wait_nr=1)
        _drain_pending_submits(loop)
        _ = listener
