# bench/h2_streaming_server.mojo
#
# HTTP/2 TLS benchmark server for H2 *streaming* handlers on port 8445 (TCP).
#
# Simplified single-process variant of bench/h2_server.mojo. The existing H2
# bench uses H2CoroServer (sync coroutine dispatch) + multishot recv + io_uring
# with BufRing and multi-worker support. This streaming bench uses
# H2StreamingServer (stackful coroutines via boucle.stackful) with the same
# TCP/TLS/io_uring CompletionLoop plumbing but without multi-process or
# BufRing complexity — simpler to reason about for the streaming demo.
#
# The demo handler is llm_stream_h2_handler from bench/streaming_handler.mojo,
# which emits 64 SSE tokens per request (no body needed from client).
#
# Run smoke test:
#   ./bench/h2_streaming_server &
#   h2load -c 1 -m 1 -n 1 https://127.0.0.1:8445/stream 2>&1 | head -20
#   kill %1
#
# Uses port 8445 (not 8443) to avoid collision with bench/h2_server.mojo.

from std.collections import Dict
from std.ffi import external_call
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.tls import RustlsLibrary, TlsServerConfig, TlsConnection
from navette.h2.h2_streaming_server import H2StreamingServer

from bench.lib.streaming_handler import llm_stream_h2_handler

from boucle import CompletionLoop, CompletionHandler
from boucle.handle import OwnedHandle
from boucle.net.socket import Socket
from boucle.net.addr import SocketAddrV4
from boucle.net.options import Backlog
from boucle._sys.linux.raw.x86_64.io_uring import (
    IORING_CQE_F_MORE,
)

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
# H2StreamingConn — per-connection state
# ---------------------------------------------------------------------------


struct H2StreamingConn(Movable):
    var conn_id: UInt64
    var handle: OwnedHandle
    var tls: TlsConnection
    var h2: H2StreamingServer
    var phase: UInt8
    var send_buf: List[UInt8]
    var send_pending: List[UInt8]
    var send_in_flight: Bool
    var recv_in_flight: Bool
    var closed: Bool
    var recv_buf: UnsafePointer[UInt8, MutAnyOrigin]

    def __init__(
        out self,
        conn_id: UInt64,
        var handle: OwnedHandle,
        var tls: TlsConnection,
        var h2: H2StreamingServer,
        recv_buf_size: Int,
    ):
        self.conn_id = conn_id
        self.handle = handle^
        self.tls = tls^
        self.h2 = h2^
        self.phase = _PHASE_TLS_HANDSHAKE
        self.send_buf = List[UInt8]()
        self.send_pending = List[UInt8]()
        self.send_in_flight = False
        self.recv_in_flight = False
        self.closed = False
        self.recv_buf = _heap_alloc[UInt8](recv_buf_size).as_any_origin()

    def __init__(out self, *, deinit take: Self):
        self.conn_id = take.conn_id
        self.handle = take.handle^
        self.tls = take.tls^
        self.h2 = take.h2^
        self.phase = take.phase
        self.send_buf = take.send_buf^
        self.send_pending = take.send_pending^
        self.send_in_flight = take.send_in_flight
        self.recv_in_flight = take.recv_in_flight
        self.closed = take.closed
        self.recv_buf = take.recv_buf


# ---------------------------------------------------------------------------
# H2StreamingServerHandler — CompletionHandler
# ---------------------------------------------------------------------------


struct H2StreamingServerHandler(CompletionHandler):
    var listener_fd: Int32
    var connections: List[UnsafePointer[H2StreamingConn, MutAnyOrigin]]
    var next_conn_id: UInt64
    var tls_lib: RustlsLibrary
    var server_tls_config: TlsServerConfig
    var pending_submits: List[PendingSubmit]

    def __init__(
        out self,
        listener_fd: Int32,
        var tls_lib: RustlsLibrary,
        var server_tls_config: TlsServerConfig,
    ):
        self.listener_fd = listener_fd
        self.connections = List[UnsafePointer[H2StreamingConn, MutAnyOrigin]]()
        self.next_conn_id = 1
        self.tls_lib = tls_lib^
        self.server_tls_config = server_tls_config^
        self.pending_submits = List[PendingSubmit]()

    def __init__(out self, *, deinit take: Self):
        self.listener_fd = take.listener_fd
        self.connections = take.connections^
        self.next_conn_id = take.next_conn_id
        self.tls_lib = take.tls_lib^
        self.server_tls_config = take.server_tls_config^
        self.pending_submits = take.pending_submits^

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
            print("h2-streaming-bench: on_complete error:", e)

    def _dispatch(mut self, token: UInt64, result: Int32, flags: UInt32) raises:
        var op_kind = UInt8(token & 0xFF)
        var conn_id = token >> 8

        if op_kind == OP_ACCEPT:
            self._handle_accept(result, flags)
            return

        var idx = self._find_index(conn_id)
        if idx < 0:
            return

        var multishot_ended = False
        if op_kind == OP_RECV:
            multishot_ended = (flags & UInt32(IORING_CQE_F_MORE)) == 0

        if self.connections[idx][].closed:
            if op_kind == OP_RECV and multishot_ended:
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
            self._handle_recv(idx, result, flags)
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
            self.connections[idx][].send_pending.extend(ct^)
            return
        self.connections[idx][].send_buf = ct^
        self._queue_send(idx)

    # --- Accept ---

    def _handle_accept(mut self, result: Int32, flags: UInt32) raises:
        var more = (flags & UInt32(2)) != 0

        if result < 0:
            print("h2-streaming-bench: accept failed:", result)
            if not more:
                self._queue_accept()
            return

        var client_fd = result
        var conn_id = self.next_conn_id
        self.next_conn_id += 1

        var tls_conn = TlsConnection.new_server(
            self.tls_lib, self.server_tls_config
        )

        var h2 = H2StreamingServer(handler_fn=llm_stream_h2_handler)

        var client_handle = OwnedHandle(raw=client_fd)
        var conn = H2StreamingConn(
            conn_id=conn_id,
            handle=client_handle^,
            tls=tls_conn^,
            h2=h2^,
            recv_buf_size=_RECV_BUF_SIZE,
        )

        var conn_ptr = _heap_alloc[H2StreamingConn](1).as_any_origin()
        conn_ptr.init_pointee_move(conn^)
        self.connections.append(conn_ptr)
        var idx = len(self.connections) - 1

        self._queue_recv(idx)
        if not more:
            self._queue_accept()

    # --- RECV ---

    def _handle_recv(mut self, idx: Int, result: Int32, flags: UInt32) raises:
        var multishot_ended = (flags & UInt32(IORING_CQE_F_MORE)) == 0
        if multishot_ended:
            self.connections[idx][].recv_in_flight = False

        if result < 0:
            self._close_connection(idx)
            return

        if result == 0:
            self._close_connection(idx)
            return

        var n = Int(result)
        var buf_ptr = self.connections[idx][].recv_buf

        self.connections[idx][].tls.receive_data(
            Span[UInt8](ptr=buf_ptr, length=n)
        )

        if multishot_ended and not self.connections[idx][].closed:
            self._queue_recv(idx)

        if self.connections[idx][].tls.wants_write():
            var ct = self.connections[idx][].tls.drain_ciphertext()
            self._stage_send(idx, ct^)

        if self.connections[idx][].tls.is_handshaking():
            return

        var plaintext = self.connections[idx][].tls.drain_plaintext()

        if self.connections[idx][].phase == _PHASE_TLS_HANDSHAKE:
            var preface_bytes = self.connections[idx][].h2.drain()
            if len(preface_bytes) > 0:
                self.connections[idx][].tls.send_data(Span(preface_bytes))
                var ct2 = self.connections[idx][].tls.drain_ciphertext()
                self._stage_send(idx, ct2^)
            self.connections[idx][].phase = _PHASE_H2_READY

        if len(plaintext) > 0:
            self.connections[idx][].h2.feed(Span(plaintext))
            var h2_out = self.connections[idx][].h2.drain()
            var total = len(h2_out)
            var off = 0
            while off < total:
                var end = off + _TLS_RECORD_CHUNK
                if end > total:
                    end = total
                self.connections[idx][].tls.send_data(Span(h2_out)[off:end])
                var ct = self.connections[idx][].tls.drain_ciphertext()
                if len(ct) > 0:
                    self._stage_send(idx, ct^)
                off = end

        if self.connections[idx][].h2.should_close():
            self._close_connection(idx)

    # --- SEND ---

    def _handle_send(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].send_in_flight = False

        if result < 0:
            self._close_connection(idx)
            return

        var sent = Int(result)
        var buf_len = len(self.connections[idx][].send_buf)
        if sent < buf_len:
            var remaining = List[UInt8](capacity=buf_len - sent)
            remaining.extend(Span(self.connections[idx][].send_buf)[sent:buf_len])
            self.connections[idx][].send_buf = remaining^
            self._queue_send(idx)
            return

        self.connections[idx][].send_buf = List[UInt8]()

        if len(self.connections[idx][].send_pending) > 0:
            var n = len(self.connections[idx][].send_pending)
            var fresh = List[UInt8](capacity=n)
            fresh.extend(Span(self.connections[idx][].send_pending))
            self.connections[idx][].send_pending = List[UInt8]()
            self.connections[idx][].send_buf = fresh^
            self._queue_send(idx)
            return

        if self.connections[idx][].phase == _PHASE_DONE:
            self._close_connection(idx)
            return

    # --- Close ---

    def _close_connection(mut self, idx: Int):
        if self.connections[idx][].closed:
            return
        self.connections[idx][].closed = True
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
        ptr[].recv_buf.free()
        ptr.destroy_pointee()
        ptr.free()


# ---------------------------------------------------------------------------
# _drain_pending_submits
# ---------------------------------------------------------------------------


def _drain_pending_submits(
    mut loop: CompletionLoop[H2StreamingServerHandler],
) raises:
    var submits = loop._handler.pending_submits^
    loop._handler.pending_submits = List[PendingSubmit]()

    for i in range(len(submits)):
        var s = submits[i].copy()
        var token = encode_token(s.conn_id, s.op_kind)

        if s.kind == _SUBMIT_ACCEPT:
            try:
                loop.submit_accept_multishot(s.fd, token)
            except:
                loop._handler.pending_submits.append(s.copy())
        elif s.kind == _SUBMIT_RECV:
            var idx = loop._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            # Use the per-connection recv_buf (allocated at accept time)
            var raw_addr = Int(loop._handler.connections[idx][].recv_buf)
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            try:
                loop.submit_recv(s.fd, buf_ptr, UInt(_RECV_BUF_SIZE), token)
            except:
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
                loop._handler.connections[idx][].send_in_flight = False
                loop._handler.pending_submits.append(s.copy())


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
    var certs_dir_opt = getenv_opt("CERTS_DIR")
    var certs_dir: String
    if Bool(certs_dir_opt):
        certs_dir = certs_dir_opt.unsafe_take()
    else:
        certs_dir = String("certs")

    var cert_pem = read_file(certs_dir + "/server.crt")
    var key_pem = read_file(certs_dir + "/server.key")

    # TLS setup with ALPN "h2"
    var tls_lib = RustlsLibrary()
    var server_config = TlsServerConfig(
        tls_lib, Span(cert_pem), Span(key_pem)
    )
    var server_alpn = List[String]()
    server_alpn.append("h2")
    server_config.set_alpn_protocols(tls_lib, server_alpn)

    # Listening socket on port 8445
    var listener = Socket.tcp_v4()
    var reuseport_val = _heap_alloc[UInt8](4).as_any_origin()
    reuseport_val[0] = 1
    reuseport_val[1] = 0
    reuseport_val[2] = 0
    reuseport_val[3] = 0
    var rp_rc = external_call["setsockopt", Int32](
        listener.raw(), Int32(1), SO_REUSEPORT, reuseport_val, Int32(4)
    )
    reuseport_val.free()
    if rp_rc < 0:
        print("h2-streaming-bench: warning: setsockopt(SO_REUSEPORT) failed")
    var bind_addr = SocketAddrV4(0, 0, 0, 0, port=_LISTEN_PORT)
    listener.bind(bind_addr)
    listener.listen(Backlog.DEFAULT)
    var listener_fd = listener.raw()

    print("h2-streaming-bench: listening on https://127.0.0.1:" + String(_LISTEN_PORT))
    print("h2-streaming-bench: handler=llm_stream_h2_handler tokens=64 SSE chunks per request")

    var handler = H2StreamingServerHandler(
        listener_fd=listener_fd,
        tls_lib=tls_lib^,
        server_tls_config=server_config^,
    )
    var loop = CompletionLoop[H2StreamingServerHandler](handler^, sq_entries=4096)

    loop.submit_accept_multishot(listener_fd, encode_token(LISTENER_CONN_ID, OP_ACCEPT))

    while True:
        loop.poll(wait_nr=1)
        _drain_pending_submits(loop)
        _ = listener
