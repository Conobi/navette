# examples/reverse_proxy/main.mojo
#
# HTTPS reverse proxy example composing the mojo-net sans-I/O library
# (Phases A–C) with the boucle io_uring CompletionLoop.
#
# Single hardcoded backend, TLS on both sides, single-threaded.
#
# Layout of this file:
#   - Token encoding helpers (OP_* constants from examples/reverse_proxy/token.mojo)
#   - ProxyPhase                  : state machine enum
#   - PendingSubmit               : queued I/O op for post-poll drain
#   - ProxyConnection             : per-client state
#   - header rewriting helpers
#   - error-response helpers
#   - ProxyHandler                : CompletionHandler implementation
#   - _drain_pending_submits      : free function that re-issues ops to the loop
#   - main                        : bind listener, build handler, run loop
#
# NOTE: M2 scope is a single hardcoded backend. Connection pooling, routing,
# CONNECT method, WebSocket upgrades, and timeouts are explicitly OUT of scope.

from std.collections.optional import Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.io.file import FileHandle
from std.ffi import external_call

from src.http import (
    Method,
    StatusCode,
    Version,
    Headers,
    BodyFrame,
    Request,
    Response,
)
from src.h1 import ParseConfig, ServerConnection, ClientConnection
from src.tls import (
    RustlsLibrary,
    TlsClientConfig,
    TlsServerConfig,
    TlsConnection,
)

from boucle import CompletionLoop, CompletionHandler
from boucle.handle import RawHandle, OwnedHandle
from boucle.net.socket import Socket
from boucle.net.addr import SocketAddrV4, SocketAddrStorV4
from boucle.net.options import Backlog, AddrFamily, SocketType, SocketFlags, Protocol
from boucle._sys.linux.net.socket import socket as _sys_socket

# Token encoding — inlined from examples/reverse_proxy/token.mojo to avoid
# the `examples.*` package import (the file is compiled as a top-level
# Mojo script; a sibling module import is not available to `mojo build`).
comptime OP_ACCEPT: UInt8 = 0
comptime OP_CLIENT_RECV: UInt8 = 1
comptime OP_CLIENT_SEND: UInt8 = 2
comptime OP_BACKEND_CONNECT: UInt8 = 3
comptime OP_BACKEND_RECV: UInt8 = 4
comptime OP_BACKEND_SEND: UInt8 = 5
comptime LISTENER_CONN_ID: UInt64 = 0


def encode_token(conn_id: UInt64, op_kind: UInt8) -> UInt64:
    return (conn_id << 8) | UInt64(op_kind)


# ---------------------------------------------------------------------------
# Buffer sizes
# ---------------------------------------------------------------------------

comptime _RECV_BUF_SIZE: Int = 8192
comptime _CERT_DIR: String = "examples/reverse_proxy/certs"
comptime _LISTEN_PORT: UInt16 = 8443
comptime _BACKEND_PORT: UInt16 = 9443
comptime _BACKEND_HOST: String = "localhost"


# ---------------------------------------------------------------------------
# ProxyPhase — per-connection state machine
# ---------------------------------------------------------------------------


comptime _PHASE_CLIENT_TLS_HANDSHAKE: UInt8 = 0
comptime _PHASE_CLIENT_READING_REQUEST: UInt8 = 1
comptime _PHASE_BACKEND_CONNECTING: UInt8 = 2
comptime _PHASE_BACKEND_TLS_HANDSHAKE: UInt8 = 3
comptime _PHASE_BACKEND_SENDING_REQUEST: UInt8 = 4
comptime _PHASE_BACKEND_READING_RESPONSE: UInt8 = 5
comptime _PHASE_CLIENT_SENDING_RESPONSE: UInt8 = 6
comptime _PHASE_DONE: UInt8 = 7


# ---------------------------------------------------------------------------
# PendingSubmit — I/O ops queued from on_complete, drained by main loop
# ---------------------------------------------------------------------------


comptime _SUBMIT_ACCEPT: UInt8 = 0
comptime _SUBMIT_RECV: UInt8 = 1
comptime _SUBMIT_SEND: UInt8 = 2
comptime _SUBMIT_CONNECT: UInt8 = 3


struct PendingSubmit(Copyable, Movable):
    """A queued I/O submission to be executed after on_complete returns."""

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
# ProxyConnection — per-client proxied state
# ---------------------------------------------------------------------------


struct ProxyConnection(Movable):
    """Per-client proxy state. Owns both sides of the proxied connection.

    Invariants:
      * `client_handle` is non-null after construction; owns the client fd.
      * `backend_handle` owns the backend fd (created in advance, connected
        async via io_uring). Always non-null while the connection is alive.
      * `backend_addr_stor` is stored here so its address remains stable for
        the io_uring Connect op (kernel reads from it asynchronously).
      * `recv_buf` / `send_buf` addresses must stay stable across polls; the
        connection is stored inside a stable slot in the handler's connection
        list, and we only read/write their contents, never moving the list
        while ops are in flight.
    """

    var conn_id: UInt64
    var client_handle: OwnedHandle
    var backend_handle: OwnedHandle
    var backend_addr_stor: SocketAddrStorV4
    var client_tls: TlsConnection
    var client_http: ServerConnection
    var backend_tls: TlsConnection
    var backend_http: ClientConnection
    var phase: UInt8
    var headers_committed: Bool
    var pending_method: Method  # method of the in-flight request (for next_response)
    var client_recv_buf: List[UInt8]
    var backend_recv_buf: List[UInt8]
    # Per-direction send buffers. Each is the buffer currently "owned" by an
    # in-flight io_uring SEND operation; the kernel reads from its address
    # until the corresponding completion arrives, so we MUST NOT reassign or
    # free it before then.
    var client_send_buf: List[UInt8]
    var backend_send_buf: List[UInt8]
    # Ciphertext that wants to go out while a send is already in flight.
    # When the in-flight send completes we promote pending → send_buf and
    # queue another send.
    var client_send_pending: List[UInt8]
    var backend_send_pending: List[UInt8]
    # In-flight flags. While true, do NOT queue another op of the same kind
    # on the same fd, and do NOT reassign the corresponding buffer.
    var client_send_in_flight: Bool
    var backend_send_in_flight: Bool
    var client_recv_in_flight: Bool
    var backend_recv_in_flight: Bool
    var closed: Bool

    def __init__(
        out self,
        conn_id: UInt64,
        var client_handle: OwnedHandle,
        var backend_handle: OwnedHandle,
        backend_addr_stor: SocketAddrStorV4,
        var client_tls: TlsConnection,
        var client_http: ServerConnection,
        var backend_tls: TlsConnection,
        var backend_http: ClientConnection,
    ):
        self.conn_id = conn_id
        self.client_handle = client_handle^
        self.backend_handle = backend_handle^
        self.backend_addr_stor = backend_addr_stor
        self.client_tls = client_tls^
        self.client_http = client_http^
        self.backend_tls = backend_tls^
        self.backend_http = backend_http^
        self.phase = _PHASE_CLIENT_TLS_HANDSHAKE
        self.headers_committed = False
        self.pending_method = Method.get()
        self.client_recv_buf = List[UInt8](capacity=_RECV_BUF_SIZE)
        for _ in range(_RECV_BUF_SIZE):
            self.client_recv_buf.append(0)
        self.backend_recv_buf = List[UInt8](capacity=_RECV_BUF_SIZE)
        for _ in range(_RECV_BUF_SIZE):
            self.backend_recv_buf.append(0)
        self.client_send_buf = List[UInt8]()
        self.backend_send_buf = List[UInt8]()
        self.client_send_pending = List[UInt8]()
        self.backend_send_pending = List[UInt8]()
        self.client_send_in_flight = False
        self.backend_send_in_flight = False
        self.client_recv_in_flight = False
        self.backend_recv_in_flight = False
        self.closed = False

    def __init__(out self, *, deinit take: Self):
        self.conn_id = take.conn_id
        self.client_handle = take.client_handle^
        self.backend_handle = take.backend_handle^
        self.backend_addr_stor = take.backend_addr_stor
        self.client_tls = take.client_tls^
        self.client_http = take.client_http^
        self.backend_tls = take.backend_tls^
        self.backend_http = take.backend_http^
        self.phase = take.phase
        self.headers_committed = take.headers_committed
        self.pending_method = take.pending_method^
        self.client_recv_buf = take.client_recv_buf^
        self.backend_recv_buf = take.backend_recv_buf^
        self.client_send_buf = take.client_send_buf^
        self.backend_send_buf = take.backend_send_buf^
        self.client_send_pending = take.client_send_pending^
        self.backend_send_pending = take.backend_send_pending^
        self.client_send_in_flight = take.client_send_in_flight
        self.backend_send_in_flight = take.backend_send_in_flight
        self.client_recv_in_flight = take.client_recv_in_flight
        self.backend_recv_in_flight = take.backend_recv_in_flight
        self.closed = take.closed


# ---------------------------------------------------------------------------
# Header rewriting
# ---------------------------------------------------------------------------


def _is_hop_by_hop(name: String) -> Bool:
    """Return True if `name` is a hop-by-hop header (lowercase)."""
    return (
        name == "connection"
        or name == "transfer-encoding"
        or name == "te"
        or name == "keep-alive"
        or name == "proxy-authorization"
        or name == "proxy-authenticate"
        or name == "proxy-connection"
        or name == "trailer"
        or name == "upgrade"
        or name == "expect"
    )


def rewrite_request_headers(
    mut request: Request, client_ip: String, backend_host: String
):
    """Strip hop-by-hop from `request.headers` in place, replace `Host`
    with `backend_host`, then add `Via` and `X-Forwarded-For`. Mutates
    the request's headers only; method/target/version/body are left untouched.
    """
    var new_headers = Headers()
    for i in range(len(request.headers)):
        var name = request.headers.name_at(i)
        var value = request.headers.value_at(i)
        if _is_hop_by_hop(name):
            continue
        if name == "host":
            continue  # skip; we add the rewritten Host below
        new_headers.add(name, value)
    new_headers.add("host", backend_host)
    new_headers.add("via", "1.1 mojo-proxy")
    new_headers.add("x-forwarded-for", client_ip)
    request.headers = new_headers^


def rewrite_response_headers(mut response: Response):
    """Strip hop-by-hop from the response in place, then add `Via`."""
    var new_headers = Headers()
    for i in range(len(response.headers)):
        var name = response.headers.name_at(i)
        var value = response.headers.value_at(i)
        if not _is_hop_by_hop(name):
            new_headers.add(name, value)
    new_headers.add("via", "1.1 mojo-proxy")
    response.headers = new_headers^


# ---------------------------------------------------------------------------
# Error response helpers
# ---------------------------------------------------------------------------


def make_error_response(code: Int, reason: String, body_text: String) -> Response:
    """Build a simple text/plain error response."""
    var headers = Headers()
    var body_bytes = body_text.as_bytes()
    headers.add("content-type", "text/plain; charset=utf-8")
    headers.add("content-length", String(len(body_bytes)))
    headers.add("connection", "close")
    var body_bytes_list = List[UInt8]()
    for i in range(len(body_bytes)):
        body_bytes_list.append(body_bytes[i])
    var body = List[BodyFrame]()
    body.append(BodyFrame.data(body_bytes_list^))
    return Response(
        status=StatusCode(code),
        reason=reason,
        version=Version.http_1_1(),
        headers=headers^,
        body=body^,
    )


# ---------------------------------------------------------------------------
# File I/O helper (native, matches test_tls_connection.mojo)
# ---------------------------------------------------------------------------


def _read_file(path: String) raises -> List[UInt8]:
    var fh = FileHandle(path, "r")
    var bytes = fh.read_bytes()
    fh.close()
    return bytes^


# ---------------------------------------------------------------------------
# ProxyHandler — CompletionHandler implementation
# ---------------------------------------------------------------------------


struct ProxyHandler(CompletionHandler):
    """Single-threaded reverse-proxy handler.

    Owns the listener fd, rustls lib + configs, the list of in-flight
    connections, and a queue of I/O ops to submit after poll().
    """

    var listener_fd: Int32
    # Heap-allocated ProxyConnection pointers. We use a pointer indirection
    # because ProxyConnection is Movable-only (not Copyable) and `List[T]`
    # requires `T: Copyable`. The pointers are Copyable (trivially).
    var connections: List[UnsafePointer[ProxyConnection, MutAnyOrigin]]
    var next_conn_id: UInt64
    var tls_lib: RustlsLibrary
    var server_tls_config: TlsServerConfig
    var client_tls_config: TlsClientConfig
    var backend_addr: SocketAddrV4
    var pending_submits: List[PendingSubmit]

    def __init__(
        out self,
        listener_fd: Int32,
        var tls_lib: RustlsLibrary,
        var server_tls_config: TlsServerConfig,
        var client_tls_config: TlsClientConfig,
        backend_addr: SocketAddrV4,
    ):
        self.listener_fd = listener_fd
        self.connections = List[UnsafePointer[ProxyConnection, MutAnyOrigin]]()
        self.next_conn_id = 1
        self.tls_lib = tls_lib^
        self.server_tls_config = server_tls_config^
        self.client_tls_config = client_tls_config^
        self.backend_addr = backend_addr
        self.pending_submits = List[PendingSubmit]()

    fn __moveinit__(out self, deinit take: Self):
        self.listener_fd = take.listener_fd
        self.connections = take.connections^
        self.next_conn_id = take.next_conn_id
        self.tls_lib = take.tls_lib^
        self.server_tls_config = take.server_tls_config^
        self.client_tls_config = take.client_tls_config^
        self.backend_addr = take.backend_addr
        self.pending_submits = take.pending_submits^

    # --- Conn lookup (linear; M2 scope — low concurrency example) ----------

    def _find_index(self, conn_id: UInt64) -> Int:
        """Return the index of the connection with `conn_id`, or -1."""
        for i in range(len(self.connections)):
            if self.connections[i][].conn_id == conn_id:
                return i
        return -1

    # --- on_complete dispatch ----------------------------------------------

    fn on_complete(mut self, token: UInt64, result: Int32, flags: UInt32):
        try:
            self._dispatch(token, result)
        except e:
            print("proxy: on_complete error:", e)

    def _dispatch(mut self, token: UInt64, result: Int32) raises:
        var op_kind = UInt8(token & 0xFF)
        var conn_id = token >> 8

        if op_kind == OP_ACCEPT:
            self._handle_accept(result)
            return

        var idx = self._find_index(conn_id)
        if idx < 0:
            return  # stale completion for closed connection

        if op_kind == OP_CLIENT_RECV:
            self._handle_client_recv(idx, result)
        elif op_kind == OP_CLIENT_SEND:
            self._handle_client_send(idx, result)
        elif op_kind == OP_BACKEND_CONNECT:
            self._handle_backend_connect(idx, result)
        elif op_kind == OP_BACKEND_RECV:
            self._handle_backend_recv(idx, result)
        elif op_kind == OP_BACKEND_SEND:
            self._handle_backend_send(idx, result)

    # --- Submit queue helpers ----------------------------------------------

    def _queue_accept(mut self):
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_ACCEPT,
                fd=self.listener_fd,
                conn_id=LISTENER_CONN_ID,
                op_kind=OP_ACCEPT,
            )
        )

    def _queue_client_recv(mut self, idx: Int):
        if self.connections[idx][].client_recv_in_flight:
            return
        self.connections[idx][].client_recv_in_flight = True
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_RECV,
                fd=self.connections[idx][].client_handle.raw(),
                conn_id=self.connections[idx][].conn_id,
                op_kind=OP_CLIENT_RECV,
            )
        )

    def _queue_client_send(mut self, idx: Int):
        # Caller is responsible for promoting client_send_pending into
        # client_send_buf before calling this. We assert here that a send
        # is not already in flight.
        if self.connections[idx][].client_send_in_flight:
            return
        if len(self.connections[idx][].client_send_buf) == 0:
            return
        self.connections[idx][].client_send_in_flight = True
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_SEND,
                fd=self.connections[idx][].client_handle.raw(),
                conn_id=self.connections[idx][].conn_id,
                op_kind=OP_CLIENT_SEND,
            )
        )

    def _queue_backend_connect(mut self, idx: Int):
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_CONNECT,
                fd=self.connections[idx][].backend_handle.raw(),
                conn_id=self.connections[idx][].conn_id,
                op_kind=OP_BACKEND_CONNECT,
            )
        )

    def _queue_backend_recv(mut self, idx: Int):
        if self.connections[idx][].backend_recv_in_flight:
            return
        self.connections[idx][].backend_recv_in_flight = True
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_RECV,
                fd=self.connections[idx][].backend_handle.raw(),
                conn_id=self.connections[idx][].conn_id,
                op_kind=OP_BACKEND_RECV,
            )
        )

    def _queue_backend_send(mut self, idx: Int):
        if self.connections[idx][].backend_send_in_flight:
            return
        if len(self.connections[idx][].backend_send_buf) == 0:
            return
        self.connections[idx][].backend_send_in_flight = True
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_SEND,
                fd=self.connections[idx][].backend_handle.raw(),
                conn_id=self.connections[idx][].conn_id,
                op_kind=OP_BACKEND_SEND,
            )
        )

    # --- Outbound staging helpers ------------------------------------------

    def _stage_client_send(mut self, idx: Int, var ct: List[UInt8]):
        """Stage `ct` to be sent to the client.

        If no client send is currently in flight, swap it into
        `client_send_buf` and queue a CLIENT_SEND. Otherwise append to
        `client_send_pending`; the in-flight send's completion handler will
        promote it later.
        """
        if len(ct) == 0:
            return
        if self.connections[idx][].client_send_in_flight:
            for i in range(len(ct)):
                self.connections[idx][].client_send_pending.append(ct[i])
            return
        self.connections[idx][].client_send_buf = ct^
        self._queue_client_send(idx)

    def _stage_backend_send(mut self, idx: Int, var ct: List[UInt8]):
        """Stage `ct` to be sent to the backend (see _stage_client_send)."""
        if len(ct) == 0:
            return
        if self.connections[idx][].backend_send_in_flight:
            for i in range(len(ct)):
                self.connections[idx][].backend_send_pending.append(ct[i])
            return
        self.connections[idx][].backend_send_buf = ct^
        self._queue_backend_send(idx)

    # --- Accept handling ----------------------------------------------------

    def _handle_accept(mut self, result: Int32) raises:
        if result < 0:
            print("proxy: accept failed:", result)
            # Re-arm accept anyway so the listener keeps running.
            self._queue_accept()
            return

        var client_fd = result
        var conn_id = self.next_conn_id
        self.next_conn_id += 1

        # Build the two TLS halves.
        var client_tls = TlsConnection.new_server(
            self.tls_lib, self.server_tls_config
        )
        var backend_tls = TlsConnection.new_client(
            self.tls_lib, self.client_tls_config, _BACKEND_HOST
        )

        # Build both H1 state machines with default config.
        var client_http = ServerConnection(ParseConfig())
        var backend_http = ClientConnection(ParseConfig())

        # Create the backend TCP socket up front so we have an fd to connect().
        var backend_handle = _sys_socket(
            AddrFamily.INET,
            SocketType.STREAM,
            SocketFlags.NONBLOCK | SocketFlags.CLOEXEC,
            Protocol.TCP,
        )

        # Stable storage for the backend address: kernel reads from this
        # asynchronously while the io_uring Connect op is in flight.
        var backend_addr_stor = self.backend_addr.addr_stor()

        # Wrap the accepted client fd in an OwnedHandle (RAII close on drop).
        var client_handle = OwnedHandle(raw=client_fd)

        var conn = ProxyConnection(
            conn_id=conn_id,
            client_handle=client_handle^,
            backend_handle=backend_handle^,
            backend_addr_stor=backend_addr_stor,
            client_tls=client_tls^,
            client_http=client_http^,
            backend_tls=backend_tls^,
            backend_http=backend_http^,
        )

        # Heap-allocate so the address is stable across any `connections`
        # List reallocations. io_uring ops read/write into buffers held
        # inside the pointee, so the pointee must not move.
        var conn_ptr = _heap_alloc[ProxyConnection](1).as_any_origin()
        conn_ptr.init_pointee_move(conn^)
        self.connections.append(conn_ptr)
        var idx = len(self.connections) - 1

        # TLS server has nothing to send until it sees the ClientHello.
        # Submit a CLIENT_RECV to start the handshake.
        self._queue_client_recv(idx)

        # Re-arm the accept for the next client.
        self._queue_accept()

    # --- Client RECV/SEND handlers -----------------------------------------

    def _handle_client_recv(mut self, idx: Int, result: Int32) raises:
        # Mark the in-flight RECV as completed regardless of result; the
        # buffer is now ours again to refill.
        self.connections[idx][].client_recv_in_flight = False

        if result <= 0:
            # 0 = EOF; <0 = error. Close the connection.
            self._close_connection(idx)
            return

        # Feed received ciphertext into the TLS state machine.
        var n = Int(result)
        var chunk = List[UInt8](capacity=n)
        for i in range(n):
            chunk.append(self.connections[idx][].client_recv_buf[i])
        self.connections[idx][].client_tls.receive_data(Span(chunk))

        # If TLS has ciphertext to send (handshake reply / encrypted app data),
        # stage it for SEND.
        if self.connections[idx][].client_tls.wants_write():
            var ct = self.connections[idx][].client_tls.drain_ciphertext()
            self._stage_client_send(idx, ct^)

        if self.connections[idx][].client_tls.is_handshaking():
            # Need more handshake bytes from the client.
            self._queue_client_recv(idx)
            return

        # Handshake done — feed any plaintext we just decrypted into the
        # HTTP parser.
        var plaintext = self.connections[idx][].client_tls.drain_plaintext()
        if len(plaintext) > 0:
            self.connections[idx][].client_http.receive_data(Span(plaintext))

        var req_opt = self.connections[idx][].client_http.next_request()
        if not req_opt:
            # Need more bytes — go back to reading.
            self.connections[idx][].phase = _PHASE_CLIENT_READING_REQUEST
            self._queue_client_recv(idx)
            return

        # Got a full request — rewrite headers and stash the method (for
        # later response parsing) before forwarding to the backend.
        var request = req_opt.take()
        self.connections[idx][].pending_method = Method(other=request.method)
        rewrite_request_headers(request, "127.0.0.1", _BACKEND_HOST)
        self.connections[idx][].backend_http.send_request(request^)

        self.connections[idx][].phase = _PHASE_BACKEND_CONNECTING
        self._queue_backend_connect(idx)

    def _handle_client_send(mut self, idx: Int, result: Int32) raises:
        # Mark in-flight send as done. The kernel is finished reading from
        # client_send_buf so it is safe to drop or reassign now.
        self.connections[idx][].client_send_in_flight = False

        if result < 0:
            self._close_connection(idx)
            return
        # Short-write case is intentionally unhandled in M2 (the plan scope
        # is a minimum-viable proxy). The send_buf is discarded.
        self.connections[idx][].client_send_buf = List[UInt8]()

        # If more ciphertext was queued while we were in flight, promote it
        # and immediately re-queue another send. This guarantees we never
        # leave staged ciphertext stranded.
        if len(self.connections[idx][].client_send_pending) > 0:
            var n_pending = len(self.connections[idx][].client_send_pending)
            var pending = List[UInt8](capacity=n_pending)
            for i in range(n_pending):
                pending.append(self.connections[idx][].client_send_pending[i])
            self.connections[idx][].client_send_pending = List[UInt8]()
            self.connections[idx][].client_send_buf = pending^
            self._queue_client_send(idx)
            # Don't transition phase yet — wait for this chained send to
            # complete first.
            return

        if self.connections[idx][].phase == _PHASE_DONE:
            self._close_connection(idx)
            return

        if self.connections[idx][].phase == _PHASE_CLIENT_SENDING_RESPONSE:
            # Fully flushed the response. Either keep-alive and loop back
            # or close.
            if self.connections[idx][].client_http.is_keep_alive():
                self.connections[idx][].phase = _PHASE_CLIENT_READING_REQUEST
                self.connections[idx][].headers_committed = False
                self._queue_client_recv(idx)
            else:
                self._close_connection(idx)
            return

        # Otherwise we are still in a handshake phase and need more recvs.
        if self.connections[idx][].client_tls.is_handshaking():
            self._queue_client_recv(idx)

    # --- Backend CONNECT/RECV/SEND handlers ---------------------------------

    def _handle_backend_connect(mut self, idx: Int, result: Int32) raises:
        if result < 0:
            print("proxy: backend connect failed:", result)
            self._send_error_and_close(idx, 502, "Bad Gateway", "backend unreachable")
            return

        self.connections[idx][].phase = _PHASE_BACKEND_TLS_HANDSHAKE

        # The client TLS (toward backend) already staged a ClientHello at
        # construction time. Drain + send it.
        if self.connections[idx][].backend_tls.wants_write():
            var ct = self.connections[idx][].backend_tls.drain_ciphertext()
            self._stage_backend_send(idx, ct^)
        else:
            # Unexpected — start reading anyway.
            self._queue_backend_recv(idx)

    def _handle_backend_recv(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].backend_recv_in_flight = False

        if result <= 0:
            self._send_error_and_close(idx, 502, "Bad Gateway", "backend closed")
            return

        var n = Int(result)
        var chunk = List[UInt8](capacity=n)
        for i in range(n):
            chunk.append(self.connections[idx][].backend_recv_buf[i])
        self.connections[idx][].backend_tls.receive_data(Span(chunk))

        if self.connections[idx][].backend_tls.wants_write():
            var ct = self.connections[idx][].backend_tls.drain_ciphertext()
            self._stage_backend_send(idx, ct^)

        if self.connections[idx][].backend_tls.is_handshaking():
            self._queue_backend_recv(idx)
            return

        # Backend TLS handshake is done — drain decrypted data into the
        # client H1 state machine (for response parsing).
        var plaintext = self.connections[idx][].backend_tls.drain_plaintext()
        if len(plaintext) > 0:
            self.connections[idx][].backend_http.receive_data(Span(plaintext))

        # If we just finished the handshake and haven't flushed the request
        # yet, do it now.
        if self.connections[idx][].phase == _PHASE_BACKEND_TLS_HANDSHAKE:
            self.connections[idx][].phase = _PHASE_BACKEND_SENDING_REQUEST
            var req_bytes = self.connections[idx][].backend_http.drain()
            if len(req_bytes) > 0:
                self.connections[idx][].backend_tls.send_data(Span(req_bytes))
                var ct2 = self.connections[idx][].backend_tls.drain_ciphertext()
                self._stage_backend_send(idx, ct2^)
            else:
                self._queue_backend_recv(idx)
            return

        # Try to extract a complete response.
        var method_copy = Method(other=self.connections[idx][].pending_method)
        var resp_opt = self.connections[idx][].backend_http.next_response(method_copy^)
        if not resp_opt:
            self._queue_backend_recv(idx)
            return

        # Got a full response — rewrite and hand to client HTTP engine.
        var response = resp_opt.take()
        rewrite_response_headers(response)
        self.connections[idx][].client_http.send_response(response^)

        # Drain client-side H1 serialization, feed to TLS, queue SEND.
        var pt = self.connections[idx][].client_http.drain()
        if len(pt) > 0:
            self.connections[idx][].client_tls.send_data(Span(pt))
        var ct3 = self.connections[idx][].client_tls.drain_ciphertext()
        self.connections[idx][].phase = _PHASE_CLIENT_SENDING_RESPONSE
        self.connections[idx][].headers_committed = True
        self._stage_client_send(idx, ct3^)

    def _handle_backend_send(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].backend_send_in_flight = False

        if result < 0:
            self._send_error_and_close(idx, 502, "Bad Gateway", "backend send failed")
            return

        self.connections[idx][].backend_send_buf = List[UInt8]()

        if len(self.connections[idx][].backend_send_pending) > 0:
            var n_pending = len(self.connections[idx][].backend_send_pending)
            var pending = List[UInt8](capacity=n_pending)
            for i in range(n_pending):
                pending.append(self.connections[idx][].backend_send_pending[i])
            self.connections[idx][].backend_send_pending = List[UInt8]()
            self.connections[idx][].backend_send_buf = pending^
            self._queue_backend_send(idx)
            return

        if self.connections[idx][].phase == _PHASE_BACKEND_TLS_HANDSHAKE:
            self._queue_backend_recv(idx)
            return

        if self.connections[idx][].phase == _PHASE_BACKEND_SENDING_REQUEST:
            # Request flushed — now wait for the response.
            self.connections[idx][].phase = _PHASE_BACKEND_READING_RESPONSE
            self._queue_backend_recv(idx)

    # --- Error + close helpers ---------------------------------------------

    def _send_error_and_close(
        mut self,
        idx: Int,
        code: Int,
        reason: String,
        body_text: String,
    ) raises:
        if not self.connections[idx][].headers_committed:
            var resp = make_error_response(code, reason, body_text)
            self.connections[idx][].client_http.send_response(resp^)
            var pt = self.connections[idx][].client_http.drain()
            if len(pt) > 0:
                self.connections[idx][].client_tls.send_data(Span(pt))
            var ct = self.connections[idx][].client_tls.drain_ciphertext()
            self.connections[idx][].phase = _PHASE_DONE
            self.connections[idx][].headers_committed = True
            self._stage_client_send(idx, ct^)
        else:
            self._close_connection(idx)

    def _close_connection(mut self, idx: Int):
        """Drop the connection: run its destructor (closes fds via the
        OwnedHandle fields) and free the heap slot.
        """
        var ptr = self.connections[idx]
        ptr[].closed = True
        var last = len(self.connections) - 1
        if idx != last:
            # Swap-remove: move the last entry into this slot.
            self.connections[idx] = self.connections[last]
        _ = self.connections.pop()
        ptr.destroy_pointee()
        ptr.free()


# ---------------------------------------------------------------------------
# _drain_pending_submits — post-poll drain into the loop
# ---------------------------------------------------------------------------


def _drain_pending_submits(mut loop: CompletionLoop[ProxyHandler]) raises:
    """Submit all queued ops from the handler, then clear the queue."""
    # Snapshot and clear to avoid infinite loops if a submit failure causes
    # a re-queue during error handling (not currently the case, but defensive).
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
            var raw_addr: Int
            if s.op_kind == OP_CLIENT_RECV:
                raw_addr = Int(
                    loop._handler.connections[idx][].client_recv_buf.unsafe_ptr()
                )
            else:
                raw_addr = Int(
                    loop._handler.connections[idx][].backend_recv_buf.unsafe_ptr()
                )
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            loop.submit_recv(s.fd, buf_ptr, UInt(_RECV_BUF_SIZE), token)
        elif s.kind == _SUBMIT_SEND:
            var idx = loop._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            var n: Int
            var raw_addr: Int
            if s.op_kind == OP_CLIENT_SEND:
                n = len(loop._handler.connections[idx][].client_send_buf)
                if n == 0:
                    continue
                raw_addr = Int(
                    loop._handler.connections[idx][].client_send_buf.unsafe_ptr()
                )
            else:
                n = len(loop._handler.connections[idx][].backend_send_buf)
                if n == 0:
                    continue
                raw_addr = Int(
                    loop._handler.connections[idx][].backend_send_buf.unsafe_ptr()
                )
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            loop.submit_send(s.fd, buf_ptr, UInt(n), token)
        elif s.kind == _SUBMIT_CONNECT:
            var idx = loop._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            var addr_ptr = (
                loop._handler.connections[idx][].backend_addr_stor.addr_unsafe_ptr()
            )
            var addr_len = UInt64(SocketAddrStorV4.ADDR_LEN)
            loop.submit_connect(s.fd, addr_ptr, addr_len, token)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
    var backend_addr = SocketAddrV4(127, 0, 0, 1, port=_BACKEND_PORT)

    # Load TLS material.
    var proxy_cert = _read_file(_CERT_DIR + "/proxy_cert.pem")
    var proxy_key = _read_file(_CERT_DIR + "/proxy_key.pem")

    # Initialize TLS library + configs.
    var tls_lib = RustlsLibrary()
    var server_config = TlsServerConfig(
        tls_lib, Span(proxy_cert), Span(proxy_key)
    )
    # Self-signed backend cert — use insecure client config for the example.
    # NOTE: requires librustls_mojo.so built with --features insecure.
    var client_config = TlsClientConfig(tls_lib, insecure=True)

    # Listening socket (IPv4 TCP, non-blocking).
    var listener = Socket.tcp_v4()
    var bind_addr = SocketAddrV4(0, 0, 0, 0, port=_LISTEN_PORT)
    listener.bind(bind_addr)
    listener.listen(Backlog.DEFAULT)
    var listener_fd = listener.raw()

    print("mojo-proxy: listening on https://127.0.0.1:" + String(_LISTEN_PORT))
    print("mojo-proxy: backend at   https://" + _BACKEND_HOST + ":" + String(_BACKEND_PORT))

    # Build the handler + loop.
    var handler = ProxyHandler(
        listener_fd=listener_fd,
        tls_lib=tls_lib^,
        server_tls_config=server_config^,
        client_tls_config=client_config^,
        backend_addr=backend_addr,
    )
    var loop = CompletionLoop[ProxyHandler](handler^, sq_entries=256)

    # Submit the initial accept (token = OP_ACCEPT, conn_id = 0).
    loop.submit_accept(listener_fd, encode_token(LISTENER_CONN_ID, OP_ACCEPT))

    # Event loop. We drain queued submissions from the handler after every
    # poll() tick — handlers cannot submit from inside on_complete because
    # the trait signature does not give them a loop reference.
    # Keep the listener Socket alive for the entire event loop. The
    # listener's raw fd was passed to io_uring (via `loop.submit_accept`),
    # and Mojo's eager destruction would close the fd if we didn't hold
    # the Socket past its last explicit use.
    while True:
        loop.poll(wait_nr=1)
        _drain_pending_submits(loop)
        _ = listener  # anchor: reaffirm `listener` lifetime each tick
