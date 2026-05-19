"""H2TcpServer — generic HTTP/2 server over TLS-on-TCP + io_uring.

# Architecture

```text
  Mojo land                                Kernel
  ─────────                                ──────

  H2TcpServer[H: StreamHandler]            io_uring
    │
    │  on_complete(token, result, flags) ───  (CQE)
    │  ├─ accept CQE → alloc H2Conn[H], TlsConnection.new_server, queue recv
    │  ├─ recv CQE  → tls.receive_data → tls.drain_plaintext → h2.feed
    │  │              → h2.drain → tls.send_data → tls.drain_ciphertext
    │  │              → stage_send
    │  └─ send CQE  → handle partial, drain pending, re-queue recv
    │
    │  outer driver: tick() → drain_pending_submits() → SQE
    │
    └─ connections: List[UnsafePointer[H2Conn[H]]]
         └─ per conn: fd OwnedHandle, TlsConnection, H2HandlerServer[H],
                     phase, buffers, flags
```

# Why TLS-only

HTTP/2 over plaintext (h2c) is essentially never deployed —
real-world h2 always goes through TLS with ALPN=h2 negotiated.
This server requires PEM cert + key at construction and refuses
clients without an h2 ALPN preference (rustls handles the
negotiation).

# Per-conn handler factory

Same model as `H1TcpServer` and `H3UdpServer`: pass a
`make_handler: fn () raises -> H` to `__init__`. Server calls
the factory once per accepted TCP connection.
"""

from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.ffi import external_call

from boucle.handle import RawHandle, OwnedHandle
from boucle.completion import CompletionHandler, CompletionLoop
from boucle._sys.linux.raw.x86_64.io_uring import IORING_CQE_F_MORE

from navette.http.handler import StreamHandler
from navette.h2.h2_handler_server import H2HandlerServer
from navette.tls import RustlsLibrary, TlsServerConfig, TlsConnection


# ── Token encoding ──────────────────────────────────────────────────────────


comptime OP_ACCEPT: UInt8 = 0
comptime OP_RECV: UInt8 = 1
comptime OP_SEND: UInt8 = 2
comptime LISTENER_CONN_ID: UInt64 = 0

comptime _RECV_BUF_SIZE: Int = 8192

# TLS-record chunk size — slice H2 plaintext into one-record-sized pieces
# before encrypting so each batch of H2 frames lands in its own TLS record
# (gives the client more cut points to interleave inbound flow-control
# updates with our outbound response stream).
comptime _TLS_RECORD_CHUNK: Int = 16384

# Phases of a connection's lifecycle.
comptime _PHASE_TLS_HANDSHAKE: UInt8 = 0
comptime _PHASE_H2_READY: UInt8 = 1
comptime _PHASE_DONE: UInt8 = 2


def _encode_token(conn_id: UInt64, op_kind: UInt8) -> UInt64:
    return (conn_id << 8) | UInt64(op_kind)


# ── PendingSubmit ────────────────────────────────────────────────────────────


comptime _SUBMIT_ACCEPT: UInt8 = 0
comptime _SUBMIT_RECV: UInt8 = 1
comptime _SUBMIT_SEND: UInt8 = 2


struct PendingSubmit(Copyable, Movable):
    var kind: UInt8
    var fd: RawHandle
    var conn_id: UInt64
    var op_kind: UInt8

    def __init__(out self, kind: UInt8, fd: RawHandle, conn_id: UInt64, op_kind: UInt8):
        self.kind = kind
        self.fd = fd
        self.conn_id = conn_id
        self.op_kind = op_kind

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.fd = other.fd
        self.conn_id = other.conn_id
        self.op_kind = other.op_kind


# ── H2Conn — per-connection state ────────────────────────────────────────────


struct H2Conn[H: StreamHandler](Movable):
    """One TCP+TLS connection's worth of state."""
    var conn_id: UInt64
    var fd: OwnedHandle
    var tls: TlsConnection
    var http: H2HandlerServer[Self.H]
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
        var tls: TlsConnection,
        var http: H2HandlerServer[Self.H],
    ):
        self.conn_id = conn_id
        self.fd = fd^
        self.tls = tls^
        self.http = http^
        self.phase = _PHASE_TLS_HANDSHAKE
        self.recv_buf = List[UInt8](capacity=_RECV_BUF_SIZE)
        for _ in range(_RECV_BUF_SIZE):
            self.recv_buf.append(0)
        self.send_buf = List[UInt8]()
        self.send_pending = List[UInt8]()
        self.send_in_flight = False
        self.recv_in_flight = False
        self.closed = False


# ── H2TcpServer ──────────────────────────────────────────────────────────────


struct H2TcpServer[H: StreamHandler](CompletionHandler):
    """Generic HTTP/2 server over TLS+TCP+io_uring.

    Owns: the listening fd, the rustls library handle, the server-side
    TlsServerConfig (with ALPN=h2 set by the caller), the per-conn
    connection table, and the pending-submit queue.
    """

    var listen_handle: OwnedHandle
    var connections: List[UnsafePointer[H2Conn[Self.H], MutAnyOrigin]]
    var next_conn_id: UInt64
    var pending_submits: List[PendingSubmit]
    var make_handler: def () thin raises -> Self.H
    var tls_lib: RustlsLibrary
    var server_tls_config: TlsServerConfig

    def __init__(
        out self,
        var listen_handle: OwnedHandle,
        make_handler: def () thin raises -> Self.H,
        var tls_lib: RustlsLibrary,
        var server_tls_config: TlsServerConfig,
    ):
        self.listen_handle = listen_handle^
        self.connections = List[UnsafePointer[H2Conn[Self.H], MutAnyOrigin]]()
        self.next_conn_id = 1
        self.pending_submits = List[PendingSubmit]()
        self.make_handler = make_handler
        self.tls_lib = tls_lib^
        self.server_tls_config = server_tls_config^

    # ── Lookup ───────────────────────────────────────────────────

    def _find_index(self, conn_id: UInt64) -> Int:
        for i in range(len(self.connections)):
            if self.connections[i][].conn_id == conn_id:
                return i
        return -1

    # ── CompletionHandler ────────────────────────────────────────

    def on_complete(mut self, token: UInt64, result: Int32, flags: UInt32):
        try:
            self._dispatch(token, result, flags)
        except e:
            print("H2TcpServer: on_complete error:", e)

    def _dispatch(mut self, token: UInt64, result: Int32, flags: UInt32) raises:
        var op_kind = UInt8(token & 0xFF)
        var conn_id = token >> 8

        if op_kind == OP_ACCEPT:
            self._handle_accept(result, flags)
            return

        var idx = self._find_index(conn_id)
        if idx < 0:
            return

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

    # ── Submit-queue helpers ─────────────────────────────────────

    def _queue_accept(mut self):
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_ACCEPT,
                fd=self.listen_handle.raw(),
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

    def _stage_send(mut self, idx: Int, var data: List[UInt8]):
        if len(data) == 0:
            return
        if self.connections[idx][].send_in_flight:
            for i in range(len(data)):
                self.connections[idx][].send_pending.append(data[i])
            return
        self.connections[idx][].send_buf = data^
        self._queue_send(idx)

    # ── Accept ───────────────────────────────────────────────────

    def _handle_accept(mut self, result: Int32, flags: UInt32) raises:
        var more = (flags & UInt32(IORING_CQE_F_MORE)) != 0

        if result < 0:
            print("H2TcpServer: accept failed:", result)
            if not more:
                self._queue_accept()
            return

        var client_fd = result
        var conn_id = self.next_conn_id
        self.next_conn_id += 1

        var handle = OwnedHandle(raw=client_fd)
        var tls = TlsConnection.new_server(self.tls_lib, self.server_tls_config)

        var handler = self.make_handler()
        var http = H2HandlerServer[Self.H](handler=handler^)

        var conn = H2Conn[Self.H](
            conn_id=conn_id,
            fd=handle^,
            tls=tls^,
            http=http^,
        )

        var conn_ptr = _heap_alloc[H2Conn[Self.H]](1).as_any_origin()
        conn_ptr.init_pointee_move(conn^)
        self.connections.append(conn_ptr)
        var idx = len(self.connections) - 1

        self._queue_recv(idx)
        if not more:
            self._queue_accept()

    # ── Recv (ciphertext → TLS → plaintext → H2) ────────────────

    def _handle_recv(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].recv_in_flight = False

        if result <= 0:
            self._close_connection(idx)
            return

        var n = Int(result)
        var chunk = List[UInt8](capacity=n)
        for i in range(n):
            chunk.append(self.connections[idx][].recv_buf[i])

        # 1. Feed ciphertext into TLS state machine.
        self.connections[idx][].tls.receive_data(Span(chunk))

        # 2. Flush any handshake-reply ciphertext immediately.
        if self.connections[idx][].tls.wants_write():
            var ct = self.connections[idx][].tls.drain_ciphertext()
            self._stage_send(idx, ct^)

        # 3. Still handshaking — keep reading more ciphertext.
        if self.connections[idx][].tls.is_handshaking():
            if not self.connections[idx][].send_in_flight:
                self._queue_recv(idx)
            return

        # 4. Handshake done — drain plaintext into H2HandlerServer.
        var plaintext = self.connections[idx][].tls.drain_plaintext()

        # First post-handshake recv: emit the H2 server preface
        # (SETTINGS frame) ahead of any client data.
        if self.connections[idx][].phase == _PHASE_TLS_HANDSHAKE:
            var preface = self.connections[idx][].http.drain()
            if len(preface) > 0:
                self.connections[idx][].tls.send_data(Span(preface))
                var ct2 = self.connections[idx][].tls.drain_ciphertext()
                if len(ct2) > 0:
                    self._stage_send(idx, ct2^)
            self.connections[idx][].phase = _PHASE_H2_READY

        # 5. Feed plaintext into the H2 codec + dispatch any complete
        #    requests via StreamHandler.
        if len(plaintext) > 0:
            self.connections[idx][].http.feed(Span(plaintext))
            var h2_out = self.connections[idx][].http.drain()
            # Slice into TLS-record-sized chunks so the wire format is
            # nginx-like (multiple records → client can interleave
            # WINDOW_UPDATEs between chunks).
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

        # 6. Re-queue recv if conn is still alive.
        if not self.connections[idx][].send_in_flight:
            if not self.connections[idx][].http.should_close():
                self._queue_recv(idx)

    # ── Send ─────────────────────────────────────────────────────

    def _handle_send(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].send_in_flight = False

        if result < 0:
            self._close_connection(idx)
            return

        var sent = Int(result)
        var buf_len = len(self.connections[idx][].send_buf)

        # Partial send — keep the unsent tail and re-queue.
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
            self._queue_recv(idx)

    # ── Close ────────────────────────────────────────────────────

    def _close_connection(mut self, idx: Int):
        if self.connections[idx][].closed:
            return
        # shutdown(SHUT_RDWR) -> FIN; close() doesn't send FIN while io_uring holds fd refs.
        var fd = self.connections[idx][].fd.raw()
        _ = external_call["shutdown", Int32](fd, Int32(2))
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
        ptr.destroy_pointee()
        ptr.free()


# ── Outer driver helpers ─────────────────────────────────────────────────────


def drain_pending_submits[H: StreamHandler](
    mut io: CompletionLoop[H2TcpServer[H]]
) raises:
    """Consume the server's `pending_submits` queue and issue
    accept / recv / send io_uring submissions."""
    var submits = io._handler.pending_submits^
    io._handler.pending_submits = List[PendingSubmit]()

    for i in range(len(submits)):
        var s = submits[i].copy()
        var token = _encode_token(s.conn_id, s.op_kind)

        if s.kind == _SUBMIT_ACCEPT:
            try:
                io.submit_accept_multishot(s.fd, token)
            except:
                io._handler.pending_submits.append(s.copy())
        elif s.kind == _SUBMIT_RECV:
            var idx = io._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            var raw_addr = Int(
                io._handler.connections[idx][].recv_buf.unsafe_ptr()
            )
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            try:
                io.submit_recv(s.fd, buf_ptr, UInt(_RECV_BUF_SIZE), token)
            except:
                io._handler.connections[idx][].recv_in_flight = False
                io._handler.pending_submits.append(s.copy())
        elif s.kind == _SUBMIT_SEND:
            var idx = io._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            var n = len(io._handler.connections[idx][].send_buf)
            if n == 0:
                continue
            var raw_addr = Int(
                io._handler.connections[idx][].send_buf.unsafe_ptr()
            )
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            try:
                io.submit_send(s.fd, buf_ptr, UInt(n), token)
            except:
                io._handler.connections[idx][].send_in_flight = False
                io._handler.pending_submits.append(s.copy())


def serve_forever[H: StreamHandler](
    var server: H2TcpServer[H],
    sq_entries: UInt32 = 4096,
) raises:
    """Bootstrap the io_uring loop and run the H2 server until exit.

    Steps:
      1. Wrap `H2TcpServer[H]` in a `CompletionLoop`.
      2. Submit the initial multishot accept on the listener fd.
      3. Loop: poll → drain_pending_submits.
    """
    var io = CompletionLoop[H2TcpServer[H]](server^, sq_entries=sq_entries)

    var listen_fd = io._handler.listen_handle.raw()
    io.submit_accept_multishot(
        listen_fd, _encode_token(LISTENER_CONN_ID, OP_ACCEPT),
    )

    while True:
        io.poll(wait_nr=1)
        drain_pending_submits(io)
