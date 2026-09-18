"""H1TcpServer — generic plaintext HTTP/1.1 server over TCP + WatchLoop.

Drives multiple HTTP/1.1 connections off a single TCP listener using
WatchLoop futures for accept, recv, and send.

# Architecture

```text
  Mojo land                                Kernel
  ─────────                                ──────

  H1TcpServer[H: StreamHandler]            WatchLoop (io_uring internally)
    │                                        │
    │  AcceptFuture (polled in poll_accept) ─┘
    │  ├─ alloc H1TcpConn[H], submit recv
    │
    │  H1TcpConn[H]                       (per-connection)
    │  ├─ poll_io: RecvFuture → http.feed → http.drain → _stage_send
    │  │           SendFuture → handle partial, drain pending, recv
    │
    │  All I/O (accept, recv, send) via WatchLoop futures
    │
    └─ connections: List[UnsafePointer[H1TcpConn[H]]]
         └─ per conn: Socket, H1HandlerServer[H],
                     buffers, flags, owned RecvFuture/SendFuture
```

# Plaintext only

This is the plaintext HTTP/1.1 server — no TLS layer. For HTTPS
use `H2TcpServer` which wraps TLS+H2 with the same proactor model.

# Per-conn handler factory

Same model as `H2TcpServer` and `H3UdpServer`: pass a
`make_handler: fn () raises -> H` to `__init__`. Server calls
the factory once per accepted TCP connection.

# Integration

After construction, the caller must:
  1. Heap-allocate the server (pointer stability).
  2. Call `start(loop)` to submit the initial accept.
  3. In the run loop: `loop.step()`, then `server.poll_accept()`,
     `server.poll_connections()`, and `server.reap_closed()`.
"""

from std.collections import Optional
from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc
from std.ffi import external_call

from boucle import (
    WatchLoop,
    RecvFuture,
    SendFuture,
    TransferFailed,
    Socket,
    AcceptFuture,
)
from boucle.handle import OwnedHandle
from boucle.net import Shutdown

from navette.http.handler import StreamHandler
from navette.h1.handler_server import H1HandlerServer
from navette.h1.config import ParseConfig
from navette.util.owned_alloc import Owned
from navette.util.null_ptr import null_ptr


# ── Peer address extraction ─────────────────────────────────────────────────


def _peer_addr_from_fd(fd: Int32) -> String:
    """Extract the peer IP address from a connected socket fd via getpeername(2).

    Handles IPv4, IPv6, and IPv4-mapped IPv6 (::ffff:a.b.c.d) addresses.
    Returns the IP as a string (e.g. "192.168.1.1" or "fe80:0:0:0:0:0:0:1").
    Returns "" on failure.
    """
    # sockaddr_storage is 128 bytes on Linux, enough for any address family.
    var addr_buf = Owned[UInt8](128)
    var addr = addr_buf.ptr()
    for i in range(128):
        addr[unsafe_offset=i] = UInt8(0)

    # addrlen is an in/out parameter for getpeername(2).
    var len_buf = Owned[Int32](1)
    var len_ptr = len_buf.ptr()
    len_ptr[unsafe_offset=0] = Int32(128)

    var rc = external_call["getpeername", Int32](fd, addr, len_ptr)
    if rc < 0:
        return String("")

    var family = Int(addr[unsafe_offset=0])  # sa_family low byte (LE u16)

    if family == 2:  # AF_INET
        # sockaddr_in layout: family(2) port(2 BE) addr(4) zero(8)
        return (
            String(Int(addr[unsafe_offset=4])) + "." + String(Int(addr[unsafe_offset=5])) + "."
            + String(Int(addr[unsafe_offset=6])) + "." + String(Int(addr[unsafe_offset=7]))
        )

    if family == 10:  # AF_INET6
        # sockaddr_in6 layout: family(2) port(2 BE) flowinfo(4) addr(16) scope_id(4)
        # Check for IPv4-mapped address (::ffff:a.b.c.d) — bytes 8..17 = 0,
        # bytes 18..19 = 0xFF, bytes 20..23 = IPv4 octets.
        var is_v4_mapped = True
        for i in range(10):
            if addr[unsafe_offset=8 + i] != UInt8(0):
                is_v4_mapped = False
                break
        if is_v4_mapped and addr[unsafe_offset=18] == UInt8(0xFF) and addr[unsafe_offset=19] == UInt8(0xFF):
            return (
                String(Int(addr[unsafe_offset=20])) + "." + String(Int(addr[unsafe_offset=21])) + "."
                + String(Int(addr[unsafe_offset=22])) + "." + String(Int(addr[unsafe_offset=23]))
            )

        # Full IPv6 — format as 8 colon-separated hex segments (no :: compression).
        var result = String("")
        for i in range(8):
            if i > 0:
                result += ":"
            var hi = Int(addr[unsafe_offset=8 + 2 * i])
            var lo = Int(addr[unsafe_offset=8 + 2 * i + 1])
            var seg = (hi << 8) | lo
            # Format segment as lowercase hex (1-4 digits, no leading zeros).
            if seg == 0:
                result += "0"
            else:
                var hex_buf = List[Byte]()
                var v = seg
                while v > 0:
                    var nyb = v & 0xF
                    if nyb < 10:
                        hex_buf.append(UInt8(nyb + 48))
                    else:
                        hex_buf.append(UInt8(nyb - 10 + 97))
                    v >>= 4
                # Reverse into result (hex_buf is LSB-first).
                var j = len(hex_buf) - 1
                while j >= 0:
                    result += chr(Int(hex_buf[j]))
                    j -= 1
        return result^

    return String("")


# ── Constants ──────────────────────────────────────────────────────────────


# Per-conn recv buffer size — single in-flight recv at a time.
comptime _RECV_BUF_SIZE: Int = 16384


# ── H1TcpConn — per-TCP-connection state ──────────────────────────────────


struct H1TcpConn[H: StreamHandler](Movable):
    """One plaintext TCP connection driven by WatchLoop futures.

    Manages a single HTTP/1.1 connection using WatchLoop recv/send
    futures via a stored WatchLoop pointer. The recv and send futures
    are Optional — present when I/O is in flight, None otherwise.

    The close state machine uses the _closing flag: once set, no
    further I/O submissions are made and any in-flight futures are
    dropped. The connection is considered drained (ready for
    deallocation) when _closing is True and both futures are None.
    """

    var socket: Socket
    var http: H1HandlerServer[Self.H]
    var send_buf: List[Byte]
    var send_pending: List[Byte]
    var _closing: Bool
    var _recv_future: Optional[RecvFuture]
    var _send_future: Optional[SendFuture]
    var _loop_ptr: Pointer[WatchLoop, MutUntrackedOrigin]

    def __init__(
        out self,
        var socket: Socket,
        var http: H1HandlerServer[Self.H],
        loop_ptr: Pointer[WatchLoop, MutUntrackedOrigin],
    ):
        """Construct a new H1TcpConn.

        Args:
            socket: Owned TCP socket (wrapped in a Socket).
            http: H1 handler server adapter.
            loop_ptr: Pointer to the WatchLoop for recv/send submission.
        """
        self.socket = socket^
        self.http = http^
        self.send_buf = List[Byte]()
        self.send_pending = List[Byte]()
        self._closing = False
        self._recv_future = Optional[RecvFuture](None)
        self._send_future = Optional[SendFuture](None)
        self._loop_ptr = loop_ptr

    def __init__(out self, *, deinit move: Self):
        self.socket = move.socket^
        self.http = move.http^
        self.send_buf = move.send_buf^
        self.send_pending = move.send_pending^
        self._closing = move._closing
        self._recv_future = move._recv_future^
        self._send_future = move._send_future^
        self._loop_ptr = move._loop_ptr

    def is_drained(self) -> Bool:
        """Check if the connection is closed and has no I/O in flight.

        A drained connection is safe to deallocate -- _closing is set
        and both recv and send futures have been consumed or dropped.
        """
        return self._closing and self._recv_future is None and self._send_future is None

    def _submit_recv(mut self) raises:
        """Submit a recv operation on this connection's socket via WatchLoop.

        Guards on recv already in flight and _closing -- no-op if either
        is true. Creates a fresh buffer and submits via the stored
        WatchLoop pointer; stores the returned RecvFuture.
        """
        if self._recv_future is not None or self._closing:
            return
        var loop = self._loop_ptr
        var buf = List[Byte](length=_RECV_BUF_SIZE, fill=0)
        self._recv_future = Optional(loop[].recv(self.socket, buf^))

    def _submit_send(mut self) raises:
        """Submit a send operation on this connection's socket via WatchLoop.

        Guards on send already in flight, _closing, and empty send_buf --
        no-op if any guard triggers. Moves send_buf into the WatchLoop
        and stores the returned SendFuture.
        """
        if self._send_future is not None or self._closing:
            return
        if len(self.send_buf) == 0:
            return
        var loop = self._loop_ptr
        var buf = self.send_buf^
        self.send_buf = List[Byte]()
        self._send_future = Optional(loop[].send(self.socket, buf^))

    def _stage_send(mut self, var data: List[Byte]) raises:
        """Stage data for sending -- submit directly or queue as pending.

        If no send is currently in flight, moves the data into send_buf
        and submits immediately. If a send is in flight, appends the
        data to send_pending for later promotion.

        Args:
            data: Outbound plaintext response bytes to send.
        """
        if len(data) == 0:
            return
        if self._send_future is not None:
            for ref byte in data:
                self.send_pending.append(byte)
            return
        self.send_buf = data^
        self._submit_send()

    def _begin_close(mut self) raises:
        """Initiate connection shutdown via shutdown(SHUT_RDWR).

        Calls shutdown(2) with SHUT_RDWR to send FIN, then sets
        _closing = True and drops any in-flight futures so the
        connection drains immediately. Idempotent -- no-op if already
        closing.
        """
        if self._closing:
            return
        try:
            self.socket.shutdown(Shutdown.RDWR)
        except:
            pass  # Socket may already be disconnected.
        self._closing = True
        # Drop any in-flight futures — the WatchLoop handles CQE
        # cleanup when the future owner drops.
        self._recv_future = Optional[RecvFuture](None)
        self._send_future = Optional[SendFuture](None)

    # ── Polling — check futures and process results ─────────

    def poll_io(mut self) raises:
        """Poll recv and send futures, processing any completed results.

        Called by the server after each loop.step(). Checks both futures
        and delegates to the appropriate handler when done.
        """
        self._poll_recv()
        self._poll_send()

    def _poll_recv(mut self) raises:
        """Check the recv future; if done, process the result.

        On success, feeds received bytes through the H1 parser, drains
        response bytes, stages for sending, and re-queues recv.
        On failure or EOF, begins connection close.
        """
        if self._recv_future is None:
            return
        if not self._recv_future.value().done():
            return

        # Move the future out of the Optional and consume it.
        var future = self._recv_future.unsafe_take()

        # Split try blocks: result() raises TransferFailed (typed),
        # while processing code raises generic Error. Mixing them in
        # one try block is a Mojo typed-raises error.
        var count = 0
        var chunk = List[Byte]()
        try:
            var result = future^.result()
            count = result.count
            # Copy received bytes; result (and its buffer) drops at
            # the end of this try block.
            var span = result.transferred()
            chunk = List[Byte](capacity=count)
            for i in range(count):
                chunk.append(span[i])
        except e:
            # TransferFailed — IO error or loop gone.
            self._begin_close()
            return

        try:
            if count <= 0:
                self._begin_close()
                return

            # Feed plaintext into H1 parser + dispatch any complete requests.
            self.http.feed(Span(chunk))
            var response_bytes = self.http.drain()
            if len(response_bytes) > 0:
                self._stage_send(response_bytes^)

            # Re-queue recv if conn is still alive.
            if self._send_future is None:
                if not self.http.should_close():
                    self._submit_recv()
        except e:
            self._begin_close()

    def _poll_send(mut self) raises:
        """Check the send future; if done, process the result.

        On successful full send, promotes any pending data and re-submits.
        If should_close is true after all data is flushed, begins closing.
        Otherwise re-queues recv for the next request.
        """
        if self._send_future is None:
            return
        if not self._send_future.value().done():
            return

        # Move the future out of the Optional and consume it.
        var future = self._send_future.unsafe_take()

        # Split try blocks: result() raises TransferFailed (typed),
        # while processing code raises generic Error.
        var count = 0
        try:
            var result = future^.result()
            count = result.count
            self.send_buf = result^.take_buffer()
        except e:
            # TransferFailed — IO error or loop gone.
            self._begin_close()
            return

        try:
            if count < 0:
                self._begin_close()
                return

            var buf_len = len(self.send_buf)

            # Partial send — keep the unsent tail and re-queue.
            if count < buf_len:
                var remaining = List[Byte](capacity=buf_len - count)
                var i = count
                while i < buf_len:
                    remaining.append(self.send_buf[i])
                    i += 1
                self.send_buf = remaining^
                self._submit_send()
                return

            # Full send completed.
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
        except e:
            self._begin_close()


# ── H1TcpServer ──────────────────────────────────────────────────────────────


struct H1TcpServer[H: StreamHandler](Movable):
    """Generic plaintext HTTP/1.1 server over TCP + WatchLoop.

    Uses WatchLoop futures for accept, recv, and send. Each accepted
    TCP connection allocates a heap-owned H1TcpConn[H] that owns
    RecvFuture/SendFuture handles and submits I/O via the stored
    WatchLoop pointer.

    Owns: the listening socket, the parse config, and the per-conn
    connection table.

    After construction, the caller must:
      1. Heap-allocate the server (pointer stability).
      2. Call `start(loop)` to submit the initial accept.
      3. In the run loop: `loop.step()`, then `server.poll_accept()`,
         `server.poll_connections()`, and `server.reap_closed()`.
    """

    var listen_socket: Socket
    var connections: List[Pointer[H1TcpConn[Self.H], MutUntrackedOrigin]]
    var make_handler: def () thin raises -> Self.H
    var parse_config: ParseConfig
    var _accept_future: Optional[AcceptFuture]
    var _loop_ptr: Pointer[WatchLoop, MutUntrackedOrigin]
    var _needs_accept_rearm: Bool

    def __init__(
        out self,
        var listen_handle: OwnedHandle,
        make_handler: def () thin raises -> Self.H,
        var parse_config: ParseConfig,
    ):
        """Construct an H1TcpServer.

        After construction, heap-allocate the server for pointer
        stability, then call start(loop).

        Args:
            listen_handle: Owned listening TCP socket (moved in).
            make_handler: Factory producing one H per connection.
            parse_config: HTTP/1.1 parse configuration (moved in).
        """
        self.listen_socket = Socket(listen_handle^)
        self.connections = List[Pointer[H1TcpConn[Self.H], MutUntrackedOrigin]]()
        self.make_handler = make_handler
        self.parse_config = parse_config^
        self._accept_future = Optional[AcceptFuture](None)
        self._loop_ptr = null_ptr[WatchLoop, MutUntrackedOrigin]()
        self._needs_accept_rearm = False

    def __init__(out self, *, deinit move: Self):
        self.listen_socket = move.listen_socket^
        self.connections = move.connections^
        self.make_handler = move.make_handler
        self.parse_config = move.parse_config^
        self._accept_future = move._accept_future^
        self._loop_ptr = move._loop_ptr
        self._needs_accept_rearm = move._needs_accept_rearm

    def __deinit__(deinit self):
        """Free all heap-allocated connections on server teardown."""
        for ref conn_ptr in self.connections:
            var ptr = conn_ptr
            ptr.unsafe_deinit_pointee()
            ptr.unsafe_free()

    # ── Lifecycle — start ────────────────────────────────────────

    def start(mut self, mut loop: WatchLoop) raises:
        """Submit the initial accept on the listener socket.

        Must be called after heap-allocation and before the first step.
        Stores the loop pointer for all I/O (accept, recv, send).

        Args:
            loop: The WatchLoop for all I/O operations.
        """
        self._loop_ptr = Pointer[WatchLoop, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=loop))
        )
        self._submit_accept()

    def poll_connections(mut self):
        """Poll all connections' recv/send futures for completed results.

        Called after each loop.step(). Iterates every live connection
        and delegates to H1TcpConn.poll_io() which checks both
        recv and send futures.
        """
        for ref conn_ptr in self.connections:
            try:
                conn_ptr[].poll_io()
            except e:
                print("H1TcpServer: poll_io error:", e)

    def reap_closed(mut self):
        """Sweep the connection list and free any fully-drained connections.

        A connection is drained when _closing is True and both recv and
        send futures are None. Called after each tick cycle.
        Uses swap-and-pop for O(1) removal.

        Also retries any deferred accept rearm (set by transient errors
        or SQ-full conditions in _handle_accept_impl).
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
        var loop = self._loop_ptr
        self._accept_future = Optional(loop[].accept(self.listen_socket))

    def poll_accept(mut self):
        """Poll the accept future and process any accepted connection.

        Called after loop.step(). If the accept future is done, extracts
        the accepted socket and delegates to _handle_accept_impl. On
        accept failure, defers rearm to the next reap_closed() tick.
        """
        if self._accept_future is None:
            return
        if not self._accept_future.value().done():
            return

        var future = self._accept_future.unsafe_take()

        # Split: result() raises on accept syscall failure;
        # _handle_accept_impl raises on processing errors.
        # Both are caught here — accept errors defer rearm.
        try:
            var socket = future.result()
            self._handle_accept_impl(socket^)
        except e:
            print("H1TcpServer: accept error:", e)
            self._needs_accept_rearm = True

    def _handle_accept_impl(mut self, var socket: Socket) raises:
        """Handle an accepted TCP connection.

        Creates a new H1TcpConn with WatchLoop futures, submits the
        initial recv, and re-arms accept for the next connection.

        Args:
            socket: The accepted TCP socket (moved in).
        """
        var peer_addr = _peer_addr_from_fd(socket.raw())

        var handler = self.make_handler()
        var http = H1HandlerServer[Self.H](
            handler=handler^, config=self.parse_config.copy(),
            peer_addr=peer_addr^,
        )

        var conn = H1TcpConn[Self.H](
            socket=socket^,
            http=http^,
            loop_ptr=self._loop_ptr,
        )

        var conn_ptr = _heap_alloc[H1TcpConn[Self.H]](1)
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
            try:
                conn_ptr[]._begin_close()
            except:
                pass
