"""H2TcpServer — generic HTTP/2 server over TLS-on-TCP + WatchLoop.

Drives multiple HTTP/2 connections off a single TCP listener using
WatchLoop futures for accept, recv, and send.

# Architecture

```text
  Mojo land                                Kernel
  ─────────                                ──────

  H2TcpServer[H: StreamHandler]            WatchLoop (io_uring internally)
    │                                        │
    │  AcceptFuture (polled in poll_accept) ─┘
    │  ├─ alloc H2TcpConn[H], TlsConnection.new_server, submit recv future
    │
    │  H2TcpConn[H]                       (per-connection)
    │  ├─ _poll_recv → future.done() → result() → TLS+H2 pipeline
    │  └─ _poll_send → future.done() → result() → partial/pending
    │
    │  All I/O (accept, recv, send) via WatchLoop futures
    │
    └─ connections: List[Pointer[H2TcpConn[H]]]
         └─ per conn: Socket, TlsConnection, H2HandlerServer[H],
                     phase, buffers, flags, Optional recv/send futures
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

# Integration

After construction, the caller must:
  1. Heap-allocate the server (pointer stability).
  2. Call `start(loop)` to submit the initial accept.
  3. In the run loop: `loop.step()`, then `server.poll_accept()`,
     `server.poll_connections()`, then `server.reap_closed()`.
"""

from std.collections import Span
from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc
from std.ffi import external_call

from bouclette.handle import OwnedHandle
from bouclette.net.socket import Socket
from bouclette.watch import WatchLoop, RecvFuture, SendFuture, AcceptFuture, TimerFuture

from navette.http.handler import StreamHandler
from navette.h2.h2_handler_server import H2HandlerServer
from navette.http.config import DEADLINE_SWEEP_MS, DEFAULT_KEEP_ALIVE_TIMEOUT_SECS, DEFAULT_REQUEST_TIMEOUT_SECS
from navette.net.peer_addr import peer_addr_from_fd
from navette.quic.profile import monotonic_us
from navette.tls import TlsBackend, TlsServerConfig, TlsConnection
from navette.util.null_ptr import null_ptr


# ── Constants ──────────────────────────────────────────────────────────────


comptime _RECV_BUF_SIZE: Int = 8192

# TLS-record chunk size — slice H2 plaintext into one-record-sized pieces
# before encrypting so each batch of H2 frames lands in its own TLS record
# (gives the client more cut points to interleave inbound flow-control
# updates with our outbound response stream).
comptime _TLS_RECORD_CHUNK: Int = 16384

# Phases of a connection's lifecycle.
comptime _PHASE_TLS_HANDSHAKE: UInt8 = 0
comptime _PHASE_H2_READY: UInt8 = 1


# ── H2TcpConn — per-TCP-connection state ──────────────────────────────────


struct H2TcpConn[H: StreamHandler](Movable):
    """One TCP+TLS connection with WatchLoop recv/send futures.

    Manages a single HTTP/2-over-TLS connection using WatchLoop futures
    for async I/O. The recv and send futures are stored as Optionals;
    a present future means an operation is in flight.

    The close state machine uses the _closing flag: once set, no
    further I/O submissions are made. The connection is considered
    drained (ready for deallocation) when _closing is True and both
    recv and send futures are absent (no I/O in flight).
    """

    var socket: Socket
    var tls: TlsConnection
    var http: H2HandlerServer[Self.H]
    var phase: UInt8
    var recv_buf: List[Byte]
    var send_buf: List[Byte]
    var send_pending: List[Byte]
    var _closing: Bool
    var _recv_future: Optional[RecvFuture]
    var _send_future: Optional[SendFuture]
    var _loop_ptr: Pointer[NoneType, MutUntrackedOrigin]
    # Accept or last completed stream; PINGs and trickled frames never move it.
    var _since_us: UInt64
    var _completed_seen: Int

    def __init__(
        out self,
        var socket: Socket,
        var tls: TlsConnection,
        var http: H2HandlerServer[Self.H],
        loop_ptr: Pointer[NoneType, MutUntrackedOrigin],
    ):
        """Construct a new H2TcpConn.

        Args:
            socket: Owned TCP socket.
            tls: TLS connection state machine.
            http: H2 handler server adapter.
            loop_ptr: Type-erased pointer to the WatchLoop.
        """
        self.socket = socket^
        self.tls = tls^
        self.http = http^
        self.phase = _PHASE_TLS_HANDSHAKE
        self.recv_buf = List[Byte](length=_RECV_BUF_SIZE, fill=0)
        self.send_buf = List[Byte]()
        self.send_pending = List[Byte]()
        self._closing = False
        self._recv_future = Optional[RecvFuture]()
        self._send_future = Optional[SendFuture]()
        self._loop_ptr = loop_ptr
        self._since_us = monotonic_us()
        self._completed_seen = 0

    def is_drained(self) -> Bool:
        """Check if the connection is closed and has no I/O in flight.

        A drained connection is safe to deallocate -- both the recv and
        send futures are absent and _closing has been set.
        """
        return (
            self._closing
            and not Bool(self._recv_future)
            and not Bool(self._send_future)
        )

    def _submit_recv(mut self) raises:
        """Submit a recv via WatchLoop, storing the returned future.

        Guards on existing recv future and _closing -- no-op if either
        is true. Moves recv_buf into the future; reclaimed on result.
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
            # Recover buffer from TransferFailed.
            var opt_buf = e^.take_buffer()
            if Bool(opt_buf):
                self.recv_buf = opt_buf.unsafe_take()
            else:
                self.recv_buf = List[Byte](length=_RECV_BUF_SIZE, fill=0)
            raise Error("recv submit failed")

    def _submit_send(mut self) raises:
        """Submit a send via WatchLoop, storing the returned future.

        Guards on existing send future, _closing, and empty send_buf --
        no-op if any guard triggers. Moves send_buf into the future;
        reclaimed on result.
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
        """Stage data for sending -- submit directly or queue as pending.

        If no send future is in flight, moves the data into send_buf
        and submits immediately. If a send is in flight, appends the
        data to send_pending for later promotion.

        Args:
            data: Outbound ciphertext bytes to send.
        """
        if len(data) == 0:
            return
        if Bool(self._send_future):
            for ref byte in data:
                self.send_pending.append(byte)
            return
        self.send_buf = data^
        self._submit_send()

    def _begin_close(mut self):
        """Initiate connection shutdown via shutdown(SHUT_RDWR).

        Calls shutdown(2) with SHUT_RDWR to send FIN, then sets
        _closing = True to prevent further I/O submissions.
        Idempotent -- no-op if already closing.
        """
        if self._closing:
            return
        _ = external_call["shutdown", Int32](
            self.socket._handle._raw, Int32(2)
        )
        self._closing = True

    # ── Recv (ciphertext → TLS → plaintext → H2) ────────────────

    def _handle_recv_impl(mut self, result: Int) raises:
        """Process a completed recv -- feed ciphertext through TLS+H2, emit responses.

        Called after the recv future completes and the buffer is back in
        recv_buf. The result is the byte count (always >= 0; negative
        results are handled by _poll_recv).

        Pipeline:
          1. Feed ciphertext into TLS state machine.
          2. Flush handshake-reply ciphertext immediately.
          3. If still handshaking, re-queue recv (unless send in flight).
          4. First post-handshake: emit H2 server preface (SETTINGS frame).
          5. Feed plaintext into H2 codec, chunk output into TLS records.
          6. Re-queue recv if connection still alive.

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
        chunk.extend(Span(self.recv_buf)[:n])

        # 1. Feed ciphertext into TLS state machine.
        self.tls.receive_data(Span(chunk))

        # 2. Flush any handshake-reply ciphertext immediately.
        if self.tls.wants_write():
            var ct = self.tls.drain_ciphertext()
            self._stage_send(ct^)

        # 3. Still handshaking — keep reading more ciphertext.
        if self.tls.is_handshaking():
            if not Bool(self._send_future):
                self._submit_recv()
            return

        # 4. Handshake done — drain plaintext into H2HandlerServer.
        var plaintext = self.tls.drain_plaintext()

        # First post-handshake recv: emit the H2 server preface
        # (SETTINGS frame) ahead of any client data.
        if self.phase == _PHASE_TLS_HANDSHAKE:
            var preface = self.http.drain()
            if len(preface) > 0:
                self.tls.send_data(Span(preface))
                var ct2 = self.tls.drain_ciphertext()
                if len(ct2) > 0:
                    self._stage_send(ct2^)
            self.phase = _PHASE_H2_READY

        # 5. Feed plaintext into the H2 codec + dispatch any complete
        #    requests via StreamHandler.
        if len(plaintext) > 0:
            self.http.feed(Span(plaintext))
            if self.http.completed_streams != self._completed_seen:
                self._completed_seen, self._since_us = self.http.completed_streams, monotonic_us()
            var h2_out = self.http.drain()
            # Slice into TLS-record-sized chunks so the wire format is
            # nginx-like (multiple records → client can interleave
            # WINDOW_UPDATEs between chunks).
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

        # 6. Re-queue recv if conn is still alive.
        if not Bool(self._send_future):
            if not self.http.should_close():
                self._submit_recv()

    # ── Send ─────────────────────────────────────────────────────

    def _handle_send_impl(mut self, result: Int) raises:
        """Process a completed send -- handle partial sends, promote pending data.

        Called after the send future completes and the buffer is back in
        send_buf. The result is the byte count (always >= 0; negative
        results are handled by _poll_send).

        On successful full send, promotes any pending data and re-submits.
        If should_close is true after all data is flushed, begins closing.
        Otherwise re-queues recv for the next request.

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

        # Partial send — keep the unsent tail and re-queue.
        if sent < buf_len:
            var remaining = List[Byte](capacity=buf_len - sent)
            var i = sent
            while i < buf_len:
                remaining.append(self.send_buf[i])
                i += 1
            self.send_buf = remaining^
            self._submit_send()
            return

        self.send_buf = List[Byte]()

        # Promote any pending data.
        if len(self.send_pending) > 0:
            var n_pending = len(self.send_pending)
            var pending = List[Byte](capacity=n_pending)
            for i in range(n_pending):
                pending.append(self.send_pending[i])
            self.send_pending = List[Byte]()
            self.send_buf = pending^
            self._submit_send()
            return

        if self.http.should_close():
            self._begin_close()
        else:
            self._submit_recv()

    # ── Future polling ──────────────────────────────────────────────

    def _poll_recv(mut self):
        """Check recv future, process completed result. No-op if not done.

        Takes the future out of the Optional, extracts the byte count and
        buffer, stores the buffer back in recv_buf, and delegates to
        _handle_recv_impl. On IO failure, closes the connection.
        """
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
            print("H2TcpServer: recv IO error:", e)
            self._begin_close()
            return

        try:
            self._handle_recv_impl(count)
        except e:
            print("H2TcpServer: recv processing error:", e)

    def _poll_send(mut self):
        """Check send future, process completed result. No-op if not done.

        Takes the future out of the Optional, extracts the byte count and
        buffer, stores the buffer back in send_buf, and delegates to
        _handle_send_impl. On IO failure, closes the connection.
        """
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
            print("H2TcpServer: send IO error:", e)
            self._begin_close()
            return

        try:
            self._handle_send_impl(count)
        except e:
            print("H2TcpServer: send processing error:", e)


# ── H2TcpServer ──────────────────────────────────────────────────────────────


struct H2TcpServer[H: StreamHandler](Movable):
    """Generic HTTP/2 server over TLS+TCP + WatchLoop.

    Uses WatchLoop futures for accept, recv, and send. Each accepted
    TCP connection allocates a heap-owned H2TcpConn[H] that owns
    RecvFuture/SendFuture handles.

    Owns: the listening socket, the rustls library handle, the
    server-side TlsServerConfig (with ALPN=h2 set by the caller),
    and the per-conn connection table.

    After construction, the caller must:
      1. Heap-allocate the server (pointer stability).
      2. Call `start(loop)` to submit the initial accept.
      3. In the run loop: `loop.step()`, then `server.poll_accept()`,
         `server.poll_connections()`, then `server.reap_closed()`.
    """

    var listen_socket: Socket
    var connections: List[Pointer[H2TcpConn[Self.H], MutUntrackedOrigin]]
    var make_handler: def () thin raises -> Self.H
    var _tls: TlsBackend
    var server_tls_config: TlsServerConfig
    var _accept_future: Optional[AcceptFuture]
    var _loop_ptr: Pointer[NoneType, MutUntrackedOrigin]
    var _needs_accept_rearm: Bool
    var request_timeout_us: UInt64
    var keep_alive_timeout_us: UInt64
    var _sweep_timer: Optional[TimerFuture]

    def __init__(
        out self,
        var listen_handle: OwnedHandle,
        make_handler: def () thin raises -> Self.H,
        var tls: TlsBackend,
        var server_tls_config: TlsServerConfig,
        request_timeout_secs: Int = DEFAULT_REQUEST_TIMEOUT_SECS,
        keep_alive_timeout_secs: Int = DEFAULT_KEEP_ALIVE_TIMEOUT_SECS,
    ):
        """Construct an H2TcpServer.

        After construction, heap-allocate the server for pointer
        stability, then call start(loop).

        Args:
            listen_handle: Owned listening TCP socket (moved in).
            make_handler: Factory producing one H per connection.
            tls: TLS backend instance (moved in).
            server_tls_config: Server TLS config with ALPN=h2 (moved in).
            request_timeout_secs: Budget while a stream is open or its data is flow-control blocked, counted from accept or the last completed stream.
            keep_alive_timeout_secs: The same budget otherwise (TLS handshake included).
        """
        self.listen_socket = Socket(listen_handle^)
        self.connections = List[Pointer[H2TcpConn[Self.H], MutUntrackedOrigin]]()
        self.make_handler = make_handler
        self._tls = tls^
        self.server_tls_config = server_tls_config^
        self._accept_future = Optional[AcceptFuture]()
        self._loop_ptr = null_ptr[NoneType, MutUntrackedOrigin]()
        self._needs_accept_rearm = False
        self.request_timeout_us = UInt64(request_timeout_secs) * 1_000_000
        self.keep_alive_timeout_us = UInt64(keep_alive_timeout_secs) * 1_000_000
        self._sweep_timer = Optional[TimerFuture]()

    def __deinit__(deinit self):
        """Free all heap-allocated connections on server teardown."""
        for ref conn_ptr in self.connections:
            var ptr = conn_ptr
            ptr.unsafe_deinit_pointee()
            ptr.unsafe_free()

    # ── Lifecycle — start ────────────────────────────────────────

    def start(mut self, mut loop: WatchLoop) raises:
        """Submit the initial accept and arm the deadline-sweep timer.

        Must be called after heap-allocation and before the first step.
        Stores the loop pointer for all I/O (accept, recv, send).

        Args:
            loop: The WatchLoop for all I/O operations.
        """
        self._loop_ptr = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=loop))
        )
        self._submit_accept()
        self._sweep_timer = Optional(loop.timeout(DEADLINE_SWEEP_MS))

    def poll_connections(mut self):
        """Poll all connection recv/send futures and process completed ones.

        Must be called after loop.step() (which dispatches CQEs and marks
        futures done) and before reap_closed() (which frees drained
        connections). Each connection's _poll_recv and _poll_send handle
        errors internally and set _closing on failure.
        """
        for ref conn_ptr in self.connections:
            conn_ptr[]._poll_recv()
            conn_ptr[]._poll_send()

    def reap_closed(mut self):
        """Sweep the connection list and free any fully-drained connections.

        A connection is drained when _closing is True and both recv and
        send futures are absent. Called after poll_connections().
        Uses swap-and-pop for O(1) removal.

        Also retries any deferred accept rearm (set by transient errors
        or SQ-full conditions in _handle_accept_impl).

        Each `DEADLINE_SWEEP_MS` tick first closes expired connections (it wakes `step(-1)`).
        """
        if self._sweep_timer and self._sweep_timer.value().done():
            var now = monotonic_us()
            for ref c in self.connections:
                var busy = len(c[].http._streams) > 0 or len(c[].http._conn._pending_data) > 0
                if now - c[]._since_us > (self.request_timeout_us if busy else self.keep_alive_timeout_us):
                    c[]._begin_close()
            try:
                var loop = Pointer[WatchLoop, MutUntrackedOrigin](unsafe_from_address=Int(self._loop_ptr))
                self._sweep_timer = Optional(loop[].timeout(DEADLINE_SWEEP_MS))
            except:
                pass  # The done timer stays: retried next tick.
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
                # Don't increment i — the swapped-in element needs checking.
            else:
                i += 1

        # Retry deferred accept rearm (transient error or SQ-full).
        if self._needs_accept_rearm:
            try:
                self._submit_accept()
                self._needs_accept_rearm = False
            except:
                pass  # SQ still full — retry on next tick.

    # ── Accept ───────────────────────────────────────────────────

    def _submit_accept(mut self) raises:
        """Submit an accept operation on the listening socket via WatchLoop.

        Stores the returned AcceptFuture. Called from start() for the
        initial accept and from _handle_accept_impl for re-arming.
        """
        var loop = Pointer[WatchLoop, MutUntrackedOrigin](
            unsafe_from_address=Int(self._loop_ptr)
        )
        self._accept_future = Optional(loop[].accept(self.listen_socket))

    def poll_accept(mut self):
        """Poll the accept future and process any accepted connection.

        Called after loop.step(). If the accept future is done, extracts
        the accepted socket and delegates to _handle_accept_impl. On
        accept failure, defers rearm to the next reap_closed() tick.
        """
        if not Bool(self._accept_future):
            return
        if not self._accept_future.value().done():
            return

        var opt = self._accept_future^
        self._accept_future = Optional[AcceptFuture]()
        var future = opt.unsafe_take()

        # Split: result() raises on accept syscall failure;
        # _handle_accept_impl raises on processing errors.
        # Both are caught here — accept errors defer rearm.
        try:
            var socket = future.result()
            self._handle_accept_impl(socket^)
        except e:
            print("H2TcpServer: accept error:", e)
            self._needs_accept_rearm = True

    def _handle_accept_impl(mut self, var socket: Socket) raises:
        """Handle an accepted TCP connection.

        Creates a new H2TcpConn, submits initial recv, and rearms
        accept for the next connection.

        Args:
            socket: The accepted TCP socket (moved in).
        """
        var peer_addr = peer_addr_from_fd(socket.raw())

        var tls = TlsConnection.new_server(self._tls.shared(), self.server_tls_config)

        var handler = self.make_handler()
        var http = H2HandlerServer[Self.H](handler=handler^, peer_addr=peer_addr^)

        var conn = H2TcpConn[Self.H](
            socket=socket^,
            tls=tls^,
            http=http^,
            loop_ptr=self._loop_ptr,
        )

        var conn_ptr = _heap_alloc[H2TcpConn[Self.H]](1)
        conn_ptr.unsafe_write(conn^)
        self.connections.append(conn_ptr)

        # Re-submit accept BEFORE initial recv — if _submit_recv raises
        # (SQ full), the accept rearm is already queued.
        try:
            self._submit_accept()
        except:
            self._needs_accept_rearm = True

        # Submit initial recv on the new connection.  On failure, close
        # the connection so it drains and gets reaped.
        try:
            conn_ptr[]._submit_recv()
        except:
            conn_ptr[]._begin_close()
