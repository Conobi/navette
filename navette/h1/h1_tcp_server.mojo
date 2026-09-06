"""H1TcpServer — generic plaintext HTTP/1.1 server over TCP + io_uring (proactor model).

Drives multiple HTTP/1.1 connections off a single TCP listener using
per-connection Completions with inline submission.

# Architecture

```text
  Mojo land                                Kernel
  ─────────                                ──────

  H1TcpServer[H: StreamHandler]            io_uring + IoUringDriver
    │                                        │
    │  _on_accept (Completion callback) ───┘   (CQE)
    │  ├─ alloc H1TcpConn[H], submit recv
    │
    │  H1TcpConn[H]                       (per-connection)
    │  ├─ _on_recv  → http.feed → http.drain → _stage_send
    │  │              → inline recv
    │  └─ _on_send  → handle partial, drain pending, inline recv
    │
    │  All submissions inline via stored IoUringDriver pointer
    │
    └─ connections: List[UnsafePointer[H1TcpConn[H]]]
         └─ per conn: fd OwnedHandle, H1HandlerServer[H],
                     buffers, flags, owned recv/send Completions
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
  2. Call `wire_context()` to set the accept Completion context pointer.
  3. Call `start(driver)` to submit the initial accept.
  4. In the run loop: `driver.tick(wait=True)` then `server.reap_closed()`.
"""

from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc
from std.ffi import external_call

from boucle.handle import RawHandle, OwnedHandle
from boucle.proactor.completion import Completion
from boucle.drivers.io_uring import IoUringDriver

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
                var hex_buf = List[UInt8]()
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
    """One plaintext TCP connection with owned recv/send Completions.

    Manages a single HTTP/1.1 connection using inline I/O submission
    via a stored IoUringDriver pointer. The recv and send Completions
    are owned by this struct; their context pointers are set via
    wire_context() after heap allocation.

    The close state machine uses the _closing flag: once set, no
    further I/O submissions are made. The connection is considered
    drained (ready for deallocation) when _closing is True and both
    recv_in_flight and send_in_flight are False.
    """

    var fd: OwnedHandle
    var http: H1HandlerServer[Self.H]
    var recv_buf: List[UInt8]
    var send_buf: List[UInt8]
    var send_pending: List[UInt8]
    var send_in_flight: Bool
    var recv_in_flight: Bool
    var _closing: Bool
    var _recv_cmp: Completion
    var _send_cmp: Completion
    var _driver_ptr: Pointer[NoneType, MutUntrackedOrigin]

    def __init__(
        out self,
        var fd: OwnedHandle,
        var http: H1HandlerServer[Self.H],
        driver_ptr: Pointer[NoneType, MutUntrackedOrigin],
    ):
        """Construct a new H1TcpConn.

        The recv and send Completions are initialized with the callback
        functions but null context pointers -- call wire_context() after
        heap allocation to set them.

        Args:
            fd: Owned TCP socket handle.
            http: H1 handler server adapter.
            driver_ptr: Type-erased pointer to the IoUringDriver.
        """
        self.fd = fd^
        self.http = http^
        self.recv_buf = List[UInt8](capacity=_RECV_BUF_SIZE)
        for _ in range(_RECV_BUF_SIZE):
            self.recv_buf.append(0)
        self.send_buf = List[UInt8]()
        self.send_pending = List[UInt8]()
        self.send_in_flight = False
        self.recv_in_flight = False
        self._closing = False
        self._recv_cmp = Completion(
            invoke=_on_recv[Self.H],
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )
        self._send_cmp = Completion(
            invoke=_on_send[Self.H],
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )
        self._driver_ptr = driver_ptr

    def is_drained(self) -> Bool:
        """Check if the connection is closed and has no I/O in flight.

        A drained connection is safe to deallocate -- both the recv and
        send operations have completed and _closing has been set.

        Returns:
            True if _closing and both recv/send not in flight.
        """
        return self._closing and not self.recv_in_flight and not self.send_in_flight

    def wire_context(mut self):
        """Set Completion context pointers to this connection's heap address.

        Must be called after the H1TcpConn is at its final heap address
        (pointer stability guaranteed) and before any SQE submission.
        """
        var self_ctx = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self))
        )
        self._recv_cmp.context = self_ctx
        self._send_cmp.context = self_ctx

    def _submit_recv(mut self) raises:
        """Submit a recv operation on this connection's fd.

        Guards on _recv_in_flight and _closing -- no-op if either is true.
        Submits directly to the stored IoUringDriver via inline submission.
        """
        if self.recv_in_flight or self._closing:
            return
        var driver = Pointer[IoUringDriver, MutUntrackedOrigin](
            unsafe_from_address=Int(self._driver_ptr)
        )
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self._recv_cmp))
        )
        var buf_ptr = Pointer[UInt8, MutUntrackedOrigin](
            unsafe_from_address=Int(self.recv_buf.unsafe_ptr())
        )
        driver[].recv(
            self.fd.raw(), buf_ptr, UInt32(_RECV_BUF_SIZE), cmp_ptr
        )
        # Set after successful submit — if submit raises (SQ full), the
        # flag stays False so the connection isn't permanently stuck.
        self.recv_in_flight = True

    def _submit_send(mut self) raises:
        """Submit a send operation on this connection's fd.

        Guards on _send_in_flight, _closing, and empty send_buf --
        no-op if any guard triggers. Submits directly to the stored
        IoUringDriver via inline submission.
        """
        if self.send_in_flight or self._closing:
            return
        if len(self.send_buf) == 0:
            return
        var driver = Pointer[IoUringDriver, MutUntrackedOrigin](
            unsafe_from_address=Int(self._driver_ptr)
        )
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self._send_cmp))
        )
        var buf_ptr = Pointer[UInt8, MutUntrackedOrigin](
            unsafe_from_address=Int(self.send_buf.unsafe_ptr())
        )
        driver[].send(
            self.fd.raw(), buf_ptr, UInt32(len(self.send_buf)), cmp_ptr
        )
        # Set after successful submit — if submit raises (SQ full), the
        # flag stays False so the connection isn't permanently stuck.
        self.send_in_flight = True

    def _stage_send(mut self, var data: List[UInt8]) raises:
        """Stage data for sending -- submit directly or queue as pending.

        If no send is currently in flight, moves the data into send_buf
        and submits immediately. If a send is in flight, appends the
        data to send_pending for later promotion.

        Args:
            data: Outbound plaintext response bytes to send.
        """
        if len(data) == 0:
            return
        if self.send_in_flight:
            for i in range(len(data)):
                self.send_pending.append(data[i])
            return
        self.send_buf = data^
        self._submit_send()

    def _begin_close(mut self) raises:
        """Initiate connection shutdown via shutdown(SHUT_RDWR).

        Calls shutdown(2) with SHUT_RDWR to send FIN, then sets
        _closing = True to prevent further I/O submissions.
        Idempotent -- no-op if already closing.
        """
        if self._closing:
            return
        var fd = self.fd.raw()
        _ = external_call["shutdown", Int32](fd, Int32(2))
        self._closing = True

    # ── Recv (raw bytes → H1 parser) ────────────────────────────

    def _handle_recv_impl(mut self, result: Int) raises:
        """Process a recv CQE -- feed raw bytes through H1 parser, emit responses.

        Pipeline:
          1. Copy received bytes from recv buffer.
          2. Feed plaintext into H1HandlerServer (parse + dispatch).
          3. Drain response bytes and stage for sending.
          4. Re-queue recv if connection still alive.

        Args:
            result: CQE result -- bytes received (>0) or negative errno.
        """
        debug_assert(self.recv_in_flight, "recv CQE fired without in-flight recv")
        self.recv_in_flight = False

        if self._closing:
            return

        if result <= 0:
            self._begin_close()
            return

        var n = Int(result)
        var chunk = List[UInt8](capacity=n)
        for i in range(n):
            chunk.append(self.recv_buf[i])

        # Feed plaintext into H1 parser + dispatch any complete requests.
        self.http.feed(Span(chunk))
        var response_bytes = self.http.drain()
        if len(response_bytes) > 0:
            self._stage_send(response_bytes^)

        # Re-queue recv if conn is still alive.
        if not self.send_in_flight:
            if not self.http.should_close():
                self._submit_recv()

    # ── Send ─────────────────────────────────────────────────────

    def _handle_send_impl(mut self, result: Int) raises:
        """Process a send CQE -- handle partial sends, promote pending data.

        On successful full send, promotes any pending data and re-submits.
        If should_close is true after all data is flushed, begins closing.
        Otherwise re-queues recv for the next request.

        Args:
            result: CQE result -- bytes sent (>=0) or negative errno.
        """
        debug_assert(self.send_in_flight, "send CQE fired without in-flight send")
        self.send_in_flight = False

        if self._closing:
            return

        if result < 0:
            self._begin_close()
            return

        var sent = Int(result)
        var buf_len = len(self.send_buf)

        # Partial send — keep the unsent tail and re-queue.
        if sent < buf_len:
            var remaining = List[UInt8](capacity=buf_len - sent)
            var i = sent
            while i < buf_len:
                remaining.append(self.send_buf[i])
                i += 1
            self.send_buf = remaining^
            self._submit_send()
            return

        self.send_buf = List[UInt8]()

        # Promote any pending data.
        if len(self.send_pending) > 0:
            var n_pending = len(self.send_pending)
            var pending = List[UInt8](capacity=n_pending)
            for i in range(n_pending):
                pending.append(self.send_pending[i])
            self.send_pending = List[UInt8]()
            self.send_buf = pending^
            self._submit_send()
            return

        if self.http.should_close():
            self._begin_close()
        else:
            self._submit_recv()


# ── Module-level completion callbacks ──────────────────────────────────────


def _on_accept[H: StreamHandler](
    ctx: Pointer[NoneType, MutUntrackedOrigin],
    result: Int,
    flags: UInt32,
):
    """Accept CQE callback. Casts context to H1TcpServer and delegates
    to _handle_accept_impl.

    Defined at module level (rather than as a static method on the
    parameterised struct) to avoid Mojo limitations with static
    methods on generic structs.

    Args:
        ctx: Type-erased pointer to the owning H1TcpServer instance.
        result: io_uring CQE result (accepted fd or negative errno).
        flags: io_uring CQE flags (unused for single-shot accept).
    """
    var self_ptr = Pointer[H1TcpServer[H], MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    try:
        self_ptr[]._handle_accept_impl(result)
    except e:
        print("H1TcpServer: _on_accept error:", e)


def _on_recv[H: StreamHandler](
    ctx: Pointer[NoneType, MutUntrackedOrigin],
    result: Int,
    flags: UInt32,
):
    """Recv CQE callback. Casts context to H1TcpConn and delegates
    to _handle_recv_impl.

    Defined at module level for parameterised-struct compatibility.

    Args:
        ctx: Type-erased pointer to the owning H1TcpConn instance.
        result: io_uring CQE result (bytes received or negative errno).
        flags: io_uring CQE flags (unused for TCP recv).
    """
    var self_ptr = Pointer[H1TcpConn[H], MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    try:
        self_ptr[]._handle_recv_impl(result)
    except e:
        print("H1TcpServer: _on_recv error:", e)


def _on_send[H: StreamHandler](
    ctx: Pointer[NoneType, MutUntrackedOrigin],
    result: Int,
    flags: UInt32,
):
    """Send CQE callback. Casts context to H1TcpConn and delegates
    to _handle_send_impl.

    Defined at module level for parameterised-struct compatibility.

    Args:
        ctx: Type-erased pointer to the owning H1TcpConn instance.
        result: io_uring CQE result (bytes sent or negative errno).
        flags: io_uring CQE flags (unused for TCP send).
    """
    var self_ptr = Pointer[H1TcpConn[H], MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    try:
        self_ptr[]._handle_send_impl(result)
    except e:
        print("H1TcpServer: _on_send error:", e)


# ── H1TcpServer ──────────────────────────────────────────────────────────────


struct H1TcpServer[H: StreamHandler](Movable):
    """Generic plaintext HTTP/1.1 server over TCP+io_uring (proactor model).

    Uses per-connection Completions with inline submission. Each
    accepted TCP connection allocates a heap-owned H1TcpConn[H]
    that owns recv/send Completions and submits I/O inline via the
    stored driver pointer.

    Owns: the listening fd, the parse config, and the per-conn
    connection table.

    After construction, the caller must:
      1. Heap-allocate the server (pointer stability).
      2. Call `wire_context()` to set the accept Completion context pointer.
      3. Call `start(driver)` to submit the initial accept.
      4. In the run loop: `driver.tick(wait=True)` then `server.reap_closed()`.
    """

    var listen_handle: OwnedHandle
    var connections: List[Pointer[H1TcpConn[Self.H], MutUntrackedOrigin]]
    var make_handler: def () thin raises -> Self.H
    var parse_config: ParseConfig
    var _accept_cmp: Completion
    var _driver_ptr: Pointer[NoneType, MutUntrackedOrigin]
    var _needs_accept_rearm: Bool

    def __init__(
        out self,
        var listen_handle: OwnedHandle,
        make_handler: def () thin raises -> Self.H,
        var parse_config: ParseConfig,
    ):
        """Construct an H1TcpServer.

        After construction, heap-allocate the server for pointer
        stability, then call wire_context() and start(driver).

        Args:
            listen_handle: Owned listening TCP socket (moved in).
            make_handler: Factory producing one H per connection.
            parse_config: HTTP/1.1 parse configuration (moved in).
        """
        self.listen_handle = listen_handle^
        self.connections = List[Pointer[H1TcpConn[Self.H], MutUntrackedOrigin]]()
        self.make_handler = make_handler
        self.parse_config = parse_config^
        self._accept_cmp = Completion(
            invoke=_on_accept[Self.H],
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )
        self._driver_ptr = null_ptr[NoneType, MutUntrackedOrigin]()
        self._needs_accept_rearm = False

    def __init__(out self, *, deinit move: Self):
        """Move constructor."""
        self.listen_handle = move.listen_handle^
        self.connections = move.connections^
        self.make_handler = move.make_handler
        self.parse_config = move.parse_config^
        self._accept_cmp = move._accept_cmp^
        self._driver_ptr = move._driver_ptr
        self._needs_accept_rearm = move._needs_accept_rearm

    def __deinit__(deinit self):
        """Free all heap-allocated connections on server teardown."""
        for i in range(len(self.connections)):
            var ptr = self.connections[i]
            ptr.unsafe_deinit_pointee()
            ptr.unsafe_free()

    # ── Lifecycle — wire_context / start ────────────────────────

    def wire_context(mut self):
        """Set accept Completion context pointer to this server's heap address.

        Must be called after the H1TcpServer is at its final heap address
        (pointer stability guaranteed) and before any SQE submission.
        """
        var self_ctx = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self))
        )
        self._accept_cmp.context = self_ctx

    def start(mut self, mut driver: IoUringDriver) raises:
        """Submit the initial accept on the listener fd.

        Must be called after wire_context() and before the first tick.
        Stores the driver pointer for inline submission by connections.

        Args:
            driver: The IoUringDriver to submit operations on.
        """
        self._driver_ptr = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=driver))
        )
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self._accept_cmp))
        )
        driver.accept(self.listen_handle.raw(), cmp_ptr)

    def reap_closed(mut self):
        """Sweep the connection list and free any fully-drained connections.

        A connection is drained when _closing is True and both recv and
        send are no longer in flight. Called after each driver tick.
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
                self._resubmit_accept()
                self._needs_accept_rearm = False
            except:
                pass  # SQ still full — retry on next tick.

    def _resubmit_accept(mut self) raises:
        """Re-submit the accept operation on the listener fd.

        Called after each accept CQE (success or failure) to keep
        the server listening for new connections (single-shot model).
        """
        var driver = Pointer[IoUringDriver, MutUntrackedOrigin](
            unsafe_from_address=Int(self._driver_ptr)
        )
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self._accept_cmp))
        )
        driver[].accept(self.listen_handle.raw(), cmp_ptr)

    # ── Accept ───────────────────────────────────────────────────

    def _handle_accept_impl(mut self, result: Int) raises:
        """Handle an accepted TCP connection.

        Creates a new H1TcpConn with owned Completions, wires its
        context pointers, submits the initial recv, and re-submits
        accept for the next connection.

        Transient resource errors (EMFILE, ENFILE, ENOMEM) defer the
        accept rearm to the next reap_closed() tick to avoid a
        CPU-burning hot loop. If the final _resubmit_accept raises
        (SQ full), the rearm is likewise deferred.

        Args:
            result: CQE result -- accepted fd (>=0) or negative errno.
        """
        if result < 0:
            # Transient resource errors — defer rearm to next reap_closed()
            # tick to avoid a CPU-burning hot loop.
            if result == -24 or result == -23 or result == -12:  # EMFILE / ENFILE / ENOMEM
                print("H1TcpServer: accept backoff (errno", result, ")")
                self._needs_accept_rearm = True
                return
            print("H1TcpServer: accept failed:", result)
            try:
                self._resubmit_accept()
            except:
                self._needs_accept_rearm = True
            return

        var client_fd = Int32(result)
        var peer_addr = _peer_addr_from_fd(client_fd)

        var handle = OwnedHandle(raw=client_fd)
        var handler = self.make_handler()
        var http = H1HandlerServer[Self.H](
            handler=handler^, config=self.parse_config.copy(),
            peer_addr=peer_addr^,
        )

        var conn = H1TcpConn[Self.H](
            fd=handle^,
            http=http^,
            driver_ptr=self._driver_ptr,
        )

        var conn_ptr = _heap_alloc[H1TcpConn[Self.H]](1)
        conn_ptr.unsafe_write(conn^)
        conn_ptr[].wire_context()
        self.connections.append(conn_ptr)

        # Re-submit accept BEFORE initial recv — if _submit_recv raises
        # (SQ full), the accept rearm is already queued.
        try:
            self._resubmit_accept()
        except:
            self._needs_accept_rearm = True

        # Submit initial recv on the new connection.  On failure, close
        # the connection so it drains and gets reaped.
        try:
            conn_ptr[]._submit_recv()
        except:
            conn_ptr[]._begin_close()
