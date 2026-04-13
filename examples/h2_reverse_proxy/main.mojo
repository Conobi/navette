# examples/h2_reverse_proxy/main.mojo
#
# HTTPS H2 reverse proxy example composing the mojo-net sans-I/O library
# (H2Connection + H2Session) with the boucle io_uring CompletionLoop.
#
# Single hardcoded backend, TLS on both sides, single-threaded.
# Frontend uses H2CoroServer with per-stream coroutines.
# Backend uses H2Session (client adapter) to exercise the Session trait.
#
# Layout of this file:
#   - Token encoding helpers
#   - Phase constants
#   - PendingSubmit               : queued I/O op for post-poll drain
#   - _BackendWork / ProxyShared  : shared state between coroutines & event loop
#   - proxy_stream_body           : per-stream coroutine body
#   - ProxyConnection             : per-client state (uses H2CoroServer)
#   - header rewriting helpers
#   - ProxyHandler                : CompletionHandler implementation
#   - _drain_pending_submits      : free function that re-issues ops to the loop
#   - main                        : bind listener, build handler, run loop

from std.collections import Dict
from std.collections.optional import Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.io.file import FileHandle

from src.http import (
    Method,
    StatusCode,
    Version,
    Headers,
    BodyFrame,
    Request,
    Response,
)
from src.http.request import RequestBody
from src.http.session import RequestHandle
from src.h2.h2_session import H2Session
from src.h2.h2_coro_server import H2CoroServer, CoroStreamCtx
from src.tls import (
    RustlsLibrary,
    TlsClientConfig,
    TlsServerConfig,
    TlsConnection,
)

from boucle import CompletionLoop, CompletionHandler
from boucle.stackful import CoroYielder
from boucle.handle import OwnedHandle
from boucle.net.socket import Socket
from boucle.net.addr import SocketAddrV4, SocketAddrStorV4
from boucle.net.options import Backlog, AddrFamily, SocketType, SocketFlags, Protocol
from boucle._sys.linux.net.socket import socket as _sys_socket

# ---------------------------------------------------------------------------
# Token encoding — same scheme as H1 proxy
# ---------------------------------------------------------------------------
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
# Buffer sizes and addresses
# ---------------------------------------------------------------------------
comptime _RECV_BUF_SIZE: Int = 8192
comptime _CERT_DIR: String = "examples/reverse_proxy/certs"
comptime _LISTEN_PORT: UInt16 = 8444
comptime _BACKEND_PORT: UInt16 = 9444
comptime _BACKEND_HOST: String = "localhost"


# ---------------------------------------------------------------------------
# ProxyPhase — per-connection state machine
# ---------------------------------------------------------------------------
comptime _PHASE_CLIENT_TLS_HANDSHAKE: UInt8 = 0
comptime _PHASE_CLIENT_H2_READY: UInt8 = 1
comptime _PHASE_BACKEND_CONNECTING: UInt8 = 2
comptime _PHASE_BACKEND_TLS_HANDSHAKE: UInt8 = 3
comptime _PHASE_BACKEND_H2_PREFACE: UInt8 = 4
comptime _PHASE_PROXYING: UInt8 = 5
comptime _PHASE_DONE: UInt8 = 6


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
    """Per-client proxy state for H2 reverse proxy.

    Frontend: H2CoroServer with per-stream coroutines.
    Backend:  H2Session (client adapter) for Session trait validation.
    """

    var conn_id: UInt64
    var client_handle: OwnedHandle
    var backend_handle: OwnedHandle
    var backend_addr_stor: SocketAddrStorV4
    var client_tls: TlsConnection
    var client_coro_server: H2CoroServer  # server-side H2 (coroutine)
    var backend_tls: TlsConnection
    var backend_session: H2Session    # client-side H2 (Session adapter)
    var backend_handles: Dict[Int, UInt64]  # handle_id → heap RequestHandle addr
    var proxy_shared_ptr: UnsafePointer[ProxyShared, MutAnyOrigin]
    var phase: UInt8
    var client_recv_buf: List[UInt8]
    var backend_recv_buf: List[UInt8]
    var client_send_buf: List[UInt8]
    var backend_send_buf: List[UInt8]
    var client_send_pending: List[UInt8]
    var backend_send_pending: List[UInt8]
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
        var client_coro_server: H2CoroServer,
        var backend_tls: TlsConnection,
        var backend_session: H2Session,
        proxy_shared_ptr: UnsafePointer[ProxyShared, MutAnyOrigin],
    ):
        self.conn_id = conn_id
        self.client_handle = client_handle^
        self.backend_handle = backend_handle^
        self.backend_addr_stor = backend_addr_stor
        self.client_tls = client_tls^
        self.client_coro_server = client_coro_server^
        self.backend_tls = backend_tls^
        self.backend_session = backend_session^
        self.backend_handles = Dict[Int, UInt64]()
        self.proxy_shared_ptr = proxy_shared_ptr
        self.phase = _PHASE_CLIENT_TLS_HANDSHAKE
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
        self.client_coro_server = take.client_coro_server^
        self.backend_tls = take.backend_tls^
        self.backend_session = take.backend_session^
        self.backend_handles = take.backend_handles^
        self.proxy_shared_ptr = take.proxy_shared_ptr
        self.phase = take.phase
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

    fn __del__(deinit self):
        """Free heap-allocated ProxyShared."""
        self.proxy_shared_ptr.destroy_pointee()
        self.proxy_shared_ptr.free()


# ---------------------------------------------------------------------------
# Header rewriting
# ---------------------------------------------------------------------------


def rewrite_request_headers(
    mut request: Request, client_ip: String, backend_host: String
):
    """Strip hop-by-hop from `request.headers` in place, replace `Host`
    with `backend_host`, then add `Via` and `X-Forwarded-For`."""
    var new_headers = Headers()
    for i in range(len(request.headers)):
        var name = request.headers.name_at(i)
        var value = request.headers.value_at(i)
        if _is_hop_by_hop(name):
            continue
        if name == "host":
            continue
        new_headers.add(name, value)
    new_headers.add("host", backend_host)
    new_headers.add("via", "2.0 mojo-proxy")
    new_headers.add("x-forwarded-for", client_ip)
    request.headers = new_headers^


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


# ---------------------------------------------------------------------------
# File I/O helper
# ---------------------------------------------------------------------------


def _read_file(path: String) raises -> List[UInt8]:
    var fh = FileHandle(path, "r")
    var bytes = fh.read_bytes()
    fh.close()
    return bytes^


# ---------------------------------------------------------------------------
# _BackendWork — queued backend request from a stream coroutine
# ---------------------------------------------------------------------------


struct _BackendWork(Copyable, Movable):
    """A backend request queued by a stream coroutine.  The coroutine
    heap-allocates the Request and stores its address here so the event
    loop can take_pointee + free after submitting to the backend session."""

    var client_stream_id: Int
    var request_addr: UInt64  # address of heap-allocated Request

    def __init__(out self, client_stream_id: Int, request_addr: UInt64):
        self.client_stream_id = client_stream_id
        self.request_addr = request_addr

    def __init__(out self, *, other: Self):
        self.client_stream_id = other.client_stream_id
        self.request_addr = other.request_addr

    def __init__(out self, *, deinit take: Self):
        self.client_stream_id = take.client_stream_id
        self.request_addr = take.request_addr

    def request_ptr(self) -> UnsafePointer[Request, MutAnyOrigin]:
        return UnsafePointer[Request, MutAnyOrigin](
            unsafe_from_address=Int(self.request_addr)
        )


# ---------------------------------------------------------------------------
# ProxyShared — shared state between stream coroutines and event loop
# ---------------------------------------------------------------------------


struct ProxyShared(Movable):
    """Shared state between per-stream coroutines and the event loop.

    - pending_backend: coroutines append _BackendWork here and yield.
    - completed_responses: event loop stores heap-allocated Response addresses
      here keyed by client stream_id.
    - handle_to_stream: maps backend RequestHandle.id() -> client stream_id.
    """

    var pending_backend: List[_BackendWork]
    var completed_responses: Dict[Int, UInt64]
    var handle_to_stream: Dict[Int, Int]

    def __init__(out self):
        self.pending_backend = List[_BackendWork]()
        self.completed_responses = Dict[Int, UInt64]()
        self.handle_to_stream = Dict[Int, Int]()

    def __init__(out self, *, deinit take: Self):
        self.pending_backend = take.pending_backend^
        self.completed_responses = take.completed_responses^
        self.handle_to_stream = take.handle_to_stream^

    fn __del__(deinit self):
        """Free any remaining heap-allocated Requests and Responses."""
        for i in range(len(self.pending_backend)):
            var p = self.pending_backend[i].request_ptr()
            p.destroy_pointee()
            p.free()
        var resp_keys = List[Int]()
        for key in self.completed_responses.keys():
            resp_keys.append(key)
        for i in range(len(resp_keys)):
            try:
                var addr = self.completed_responses[resp_keys[i]]
                var p = UnsafePointer[Response, MutAnyOrigin](
                    unsafe_from_address=Int(addr)
                )
                p.destroy_pointee()
                p.free()
            except:
                pass


# ---------------------------------------------------------------------------
# proxy_stream_body — per-stream coroutine body for the reverse proxy
# ---------------------------------------------------------------------------


fn proxy_stream_body(mut yielder: CoroYielder) raises:
    """Per-stream coroutine body for the H2 reverse proxy.

    1. Read the entire client request body (yield when no data available).
    2. Build a backend Request, heap-allocate it, queue in ProxyShared, yield.
    3. After resume — read the completed response and forward to the client.
    """
    # --- Recover pointers from yielder ---
    var ctx_ptr = UnsafePointer[CoroStreamCtx, MutAnyOrigin](
        unsafe_from_address=Int(yielder.user_data())
    )
    var proxy_ptr = UnsafePointer[ProxyShared, MutAnyOrigin](
        unsafe_from_address=Int(ctx_ptr[].extra_data)
    )
    var stream_id = Int(ctx_ptr[].stream_id)

    # ── Step 1: Read entire client request body ──
    var body_bytes = List[UInt8]()
    while True:
        var ctx = ctx_ptr.take_pointee()
        var frame_opt = ctx.recv_body.try_read()
        ctx_ptr.init_pointee_move(ctx^)
        if not Bool(frame_opt):
            # No data available yet — yield and wait for more
            yielder.yield_to_caller()
            continue
        var frame = frame_opt.unsafe_take()
        if frame.is_data():
            var data = frame.data().copy()
            for j in range(len(data)):
                body_bytes.append(data[j])
        elif frame.is_end():
            break
        elif frame.is_error():
            # Stream error — nothing to forward
            return

    # ── Step 2: Build backend Request, queue in ProxyShared ──
    var ctx2 = ctx_ptr.take_pointee()
    var req_body: RequestBody
    if len(body_bytes) > 0:
        req_body = RequestBody.buffered(body_bytes^)
    else:
        req_body = RequestBody.empty()

    var request = Request(
        method=Method.custom(String(ctx2.request.method)),
        target=ctx2.request.target,
        version=Version.http_2(),
        headers=Headers(other=ctx2.request.headers),
        body=req_body^,
    )
    ctx_ptr.init_pointee_move(ctx2^)

    rewrite_request_headers(request, "127.0.0.1", _BACKEND_HOST)

    # Heap-allocate the Request for the event loop to consume
    var req_heap = _heap_alloc[Request](1).as_any_origin()
    req_heap.init_pointee_move(request^)

    var work = _BackendWork(
        client_stream_id=stream_id,
        request_addr=UInt64(Int(req_heap)),
    )
    proxy_ptr[].pending_backend.append(work^)

    # Yield — the event loop will submit to backend and resume us
    yielder.yield_to_caller()

    # ── Step 3: Forward backend response to client ──
    # The event loop has placed the response in completed_responses
    if stream_id not in proxy_ptr[].completed_responses:
        # No response — should not happen, but guard
        return

    var resp_addr = proxy_ptr[].completed_responses[stream_id]
    _ = proxy_ptr[].completed_responses.pop(stream_id)
    var resp_ptr = UnsafePointer[Response, MutAnyOrigin](
        unsafe_from_address=Int(resp_addr)
    )
    var response = resp_ptr.take_pointee()
    resp_ptr.free()

    # Build response headers, stripping hop-by-hop and adding Via
    var resp_headers = Headers()
    for i in range(len(response.headers)):
        var name = response.headers.name_at(i)
        var value = response.headers.value_at(i)
        if not _is_hop_by_hop(name):
            resp_headers.add(name, value)
    resp_headers.add("via", "2.0 mojo-proxy")

    # Extract body data
    var resp_body = List[UInt8]()
    for i in range(len(response.body)):
        var frame = response.body[i].copy()
        if frame.is_data():
            var data = frame.data().copy()
            for j in range(len(data)):
                resp_body.append(data[j])

    # Send through ResponseWriter
    var ctx3 = ctx_ptr.take_pointee()
    ctx3.resp_writer.send_status(
        StatusCode(other=response.status), resp_headers^
    )
    if len(resp_body) > 0:
        _ = ctx3.resp_writer.try_send_body(BodyFrame.data(resp_body^))
    ctx3.resp_writer.end()
    ctx_ptr.init_pointee_move(ctx3^)


# ---------------------------------------------------------------------------
# ProxyHandler — CompletionHandler implementation
# ---------------------------------------------------------------------------


struct ProxyHandler(CompletionHandler):
    """Single-threaded H2 reverse-proxy handler."""

    var listener_fd: Int32
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

    # --- Conn lookup ----------------------------------------------------------

    def _find_index(self, conn_id: UInt64) -> Int:
        for i in range(len(self.connections)):
            if self.connections[i][].conn_id == conn_id:
                return i
        return -1

    # --- on_complete dispatch -------------------------------------------------

    fn on_complete(mut self, token: UInt64, result: Int32, flags: UInt32):
        try:
            self._dispatch(token, result)
        except e:
            print("h2-proxy: on_complete error:", e)

    def _dispatch(mut self, token: UInt64, result: Int32) raises:
        var op_kind = UInt8(token & 0xFF)
        var conn_id = token >> 8

        if op_kind == OP_ACCEPT:
            self._handle_accept(result)
            return

        var idx = self._find_index(conn_id)
        if idx < 0:
            return

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

    # --- Submit queue helpers -------------------------------------------------

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

    # --- Outbound staging helpers ---------------------------------------------

    def _stage_client_send(mut self, idx: Int, var ct: List[UInt8]):
        if len(ct) == 0:
            return
        if self.connections[idx][].client_send_in_flight:
            for i in range(len(ct)):
                self.connections[idx][].client_send_pending.append(ct[i])
            return
        self.connections[idx][].client_send_buf = ct^
        self._queue_client_send(idx)

    def _stage_backend_send(mut self, idx: Int, var ct: List[UInt8]):
        if len(ct) == 0:
            return
        if self.connections[idx][].backend_send_in_flight:
            for i in range(len(ct)):
                self.connections[idx][].backend_send_pending.append(ct[i])
            return
        self.connections[idx][].backend_send_buf = ct^
        self._queue_backend_send(idx)

    # --- Accept handling ------------------------------------------------------

    def _handle_accept(mut self, result: Int32) raises:
        if result < 0:
            print("h2-proxy: accept failed:", result)
            self._queue_accept()
            return

        var client_fd = result
        var conn_id = self.next_conn_id
        self.next_conn_id += 1

        var client_tls = TlsConnection.new_server(
            self.tls_lib, self.server_tls_config
        )
        var backend_tls = TlsConnection.new_client(
            self.tls_lib, self.client_tls_config, _BACKEND_HOST
        )

        # Heap-allocate ProxyShared for stable address across moves
        var proxy_shared_ptr = _heap_alloc[ProxyShared](1).as_any_origin()
        proxy_shared_ptr.init_pointee_move(ProxyShared())
        var noneptr = UnsafePointer[NoneType, MutExternalOrigin](
            unsafe_from_address=Int(proxy_shared_ptr)
        )

        # Server-side H2CoroServer for the frontend (coroutine-based)
        var client_coro_server = H2CoroServer(
            body_fn=proxy_stream_body, extra_data=noneptr
        )

        # Client-side H2Session for the backend.
        var backend_session = H2Session()

        var backend_handle = _sys_socket(
            AddrFamily.INET,
            SocketType.STREAM,
            SocketFlags.NONBLOCK | SocketFlags.CLOEXEC,
            Protocol.TCP,
        )

        var backend_addr_stor = self.backend_addr.addr_stor()
        var client_handle = OwnedHandle(raw=client_fd)

        var conn = ProxyConnection(
            conn_id=conn_id,
            client_handle=client_handle^,
            backend_handle=backend_handle^,
            backend_addr_stor=backend_addr_stor,
            client_tls=client_tls^,
            client_coro_server=client_coro_server^,
            backend_tls=backend_tls^,
            backend_session=backend_session^,
            proxy_shared_ptr=proxy_shared_ptr,
        )

        var conn_ptr = _heap_alloc[ProxyConnection](1).as_any_origin()
        conn_ptr.init_pointee_move(conn^)
        self.connections.append(conn_ptr)
        var idx = len(self.connections) - 1

        self._queue_client_recv(idx)
        self._queue_accept()

    # --- Client RECV/SEND handlers --------------------------------------------

    def _handle_client_recv(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].client_recv_in_flight = False

        if result <= 0:
            self._close_connection(idx)
            return

        var n = Int(result)
        var chunk = List[UInt8](capacity=n)
        for i in range(n):
            chunk.append(self.connections[idx][].client_recv_buf[i])
        self.connections[idx][].client_tls.receive_data(Span(chunk))

        if self.connections[idx][].client_tls.wants_write():
            var ct = self.connections[idx][].client_tls.drain_ciphertext()
            self._stage_client_send(idx, ct^)

        if self.connections[idx][].client_tls.is_handshaking():
            self._queue_client_recv(idx)
            return

        # TLS handshake done — drain plaintext
        var plaintext = self.connections[idx][].client_tls.drain_plaintext()

        # H2CoroServer already called initiate_connection() in its constructor.
        # On first post-TLS recv, flush the server preface to the client.
        if self.connections[idx][].phase == _PHASE_CLIENT_TLS_HANDSHAKE:
            var preface_bytes = self.connections[idx][].client_coro_server.drain()
            if len(preface_bytes) > 0:
                self.connections[idx][].client_tls.send_data(Span(preface_bytes))
                var ct2 = self.connections[idx][].client_tls.drain_ciphertext()
                self._stage_client_send(idx, ct2^)
            self.connections[idx][].phase = _PHASE_CLIENT_H2_READY

        # Feed plaintext into the H2CoroServer (dispatches to coroutines)
        if len(plaintext) > 0:
            self.connections[idx][].client_coro_server.feed(Span(plaintext))
            var h2_out = self.connections[idx][].client_coro_server.drain()
            if len(h2_out) > 0:
                self.connections[idx][].client_tls.send_data(Span(h2_out))
                var ct3 = self.connections[idx][].client_tls.drain_ciphertext()
                self._stage_client_send(idx, ct3^)

        # If coroutines queued backend work, either start the backend
        # connection or process pending work immediately if already connected.
        if len(self.connections[idx][].proxy_shared_ptr[].pending_backend) > 0:
            if self.connections[idx][].phase == _PHASE_CLIENT_H2_READY:
                self.connections[idx][].phase = _PHASE_BACKEND_CONNECTING
                self._queue_backend_connect(idx)
            elif self.connections[idx][].phase == _PHASE_PROXYING:
                self._process_pending_backend(idx)

        # Keep reading from the client
        self._queue_client_recv(idx)

    def _handle_client_send(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].client_send_in_flight = False

        if result < 0:
            self._close_connection(idx)
            return

        self.connections[idx][].client_send_buf = List[UInt8]()

        if len(self.connections[idx][].client_send_pending) > 0:
            var n_pending = len(self.connections[idx][].client_send_pending)
            var pending = List[UInt8](capacity=n_pending)
            for i in range(n_pending):
                pending.append(self.connections[idx][].client_send_pending[i])
            self.connections[idx][].client_send_pending = List[UInt8]()
            self.connections[idx][].client_send_buf = pending^
            self._queue_client_send(idx)
            return

        if self.connections[idx][].phase == _PHASE_DONE:
            self._close_connection(idx)
            return

    # --- Backend CONNECT/RECV/SEND handlers -----------------------------------

    def _handle_backend_connect(mut self, idx: Int, result: Int32) raises:
        if result < 0:
            print("h2-proxy: backend connect failed:", result)
            self._close_connection(idx)
            return

        self.connections[idx][].phase = _PHASE_BACKEND_TLS_HANDSHAKE

        if self.connections[idx][].backend_tls.wants_write():
            var ct = self.connections[idx][].backend_tls.drain_ciphertext()
            self._stage_backend_send(idx, ct^)
        else:
            self._queue_backend_recv(idx)

    def _handle_backend_recv(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].backend_recv_in_flight = False

        if result <= 0:
            self._close_connection(idx)
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

        # Backend TLS handshake done — drain plaintext
        var plaintext = self.connections[idx][].backend_tls.drain_plaintext()

        if self.connections[idx][].phase == _PHASE_BACKEND_TLS_HANDSHAKE:
            # TLS handshake just completed. The H2Session was already
            # initiated in its constructor (initiate_connection called).
            # Drain the H2 preface bytes from the session and send them.
            self.connections[idx][].phase = _PHASE_BACKEND_H2_PREFACE
            var preface_bytes = self.connections[idx][].backend_session.drain()
            if len(preface_bytes) > 0:
                self.connections[idx][].backend_tls.send_data(Span(preface_bytes))
                var ct2 = self.connections[idx][].backend_tls.drain_ciphertext()
                self._stage_backend_send(idx, ct2^)

            # Feed any plaintext we already got (server preface)
            if len(plaintext) > 0:
                self.connections[idx][].backend_session.feed(Span(plaintext))
                var resp_bytes = self.connections[idx][].backend_session.drain()
                if len(resp_bytes) > 0:
                    self.connections[idx][].backend_tls.send_data(Span(resp_bytes))
                    var ct3 = self.connections[idx][].backend_tls.drain_ciphertext()
                    self._stage_backend_send(idx, ct3^)
            self._queue_backend_recv(idx)
            return

        if self.connections[idx][].phase == _PHASE_BACKEND_H2_PREFACE:
            # Feed backend server preface response
            if len(plaintext) > 0:
                self.connections[idx][].backend_session.feed(Span(plaintext))
                var resp_bytes = self.connections[idx][].backend_session.drain()
                if len(resp_bytes) > 0:
                    self.connections[idx][].backend_tls.send_data(Span(resp_bytes))
                    var ct4 = self.connections[idx][].backend_tls.drain_ciphertext()
                    self._stage_backend_send(idx, ct4^)

            # Transition to PROXYING and process pending backend work
            self.connections[idx][].phase = _PHASE_PROXYING
            self._process_pending_backend(idx)
            self._queue_backend_recv(idx)
            return

        # PROXYING phase — feed response data into H2Session
        if len(plaintext) > 0:
            self.connections[idx][].backend_session.feed(Span(plaintext))
            # Drain any outbound frames generated by the session
            var out_bytes = self.connections[idx][].backend_session.drain()
            if len(out_bytes) > 0:
                self.connections[idx][].backend_tls.send_data(Span(out_bytes))
                var ct5 = self.connections[idx][].backend_tls.drain_ciphertext()
                self._stage_backend_send(idx, ct5^)

        # Deliver completed backend responses to stream coroutines
        self._deliver_backend_responses(idx)
        self._queue_backend_recv(idx)

    def _handle_backend_send(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].backend_send_in_flight = False

        if result < 0:
            self._close_connection(idx)
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

        if self.connections[idx][].phase == _PHASE_BACKEND_H2_PREFACE:
            self._queue_backend_recv(idx)
            return

    # --- Pending backend work (coroutine → event loop) -------------------------

    def _process_pending_backend(mut self, idx: Int) raises:
        """Drain pending backend work queued by stream coroutines, submit to
        the backend H2Session, and send outbound frames through TLS."""
        var proxy = self.connections[idx][].proxy_shared_ptr
        while len(proxy[].pending_backend) > 0:
            var work = proxy[].pending_backend.pop(0)
            # Take the heap-allocated Request
            var req_ptr = UnsafePointer[Request, MutAnyOrigin](
                unsafe_from_address=Int(work.request_addr)
            )
            var req = req_ptr.take_pointee()
            req_ptr.free()
            # Submit to backend
            var handle = self.connections[idx][].backend_session.submit(req^)
            var handle_id = Int(handle.id())
            proxy[].handle_to_stream[handle_id] = work.client_stream_id
            # Heap-allocate the handle (RequestHandle is Movable-only)
            var h_ptr = _heap_alloc[RequestHandle](1)
            h_ptr.init_pointee_move(handle^)
            self.connections[idx][].backend_handles[handle_id] = UInt64(Int(h_ptr))
        # Drain backend session through TLS
        var out_bytes = self.connections[idx][].backend_session.drain()
        if len(out_bytes) > 0:
            self.connections[idx][].backend_tls.send_data(Span(out_bytes))
            var ct = self.connections[idx][].backend_tls.drain_ciphertext()
            self._stage_backend_send(idx, ct^)

    # --- Backend response delivery (event loop → coroutine) -------------------

    def _deliver_backend_responses(mut self, idx: Int) raises:
        """Drive all pending backend RequestHandles via run_one.  When one
        completes, heap-allocate the Response, store in ProxyShared, and
        resume the stream coroutine so it can forward the response."""
        if len(self.connections[idx][].backend_handles) == 0:
            return

        # Snapshot handle IDs to avoid mutating dict while iterating
        var handle_ids = List[Int]()
        for key in self.connections[idx][].backend_handles.keys():
            handle_ids.append(key)

        for i in range(len(handle_ids)):
            var hid = handle_ids[i]
            if hid not in self.connections[idx][].backend_handles:
                continue
            # Take handle from heap
            var h_addr = self.connections[idx][].backend_handles[hid]
            var h_ptr = UnsafePointer[RequestHandle, MutAnyOrigin](
                unsafe_from_address=Int(h_addr)
            )
            self.connections[idx][].backend_session.run_one(h_ptr[])

            if not h_ptr[].is_complete():
                continue  # not ready yet, leave in dict

            # Complete — take it out
            var handle = h_ptr.take_pointee()
            h_ptr.free()
            _ = self.connections[idx][].backend_handles.pop(hid)

            var proxy = self.connections[idx][].proxy_shared_ptr
            if hid not in proxy[].handle_to_stream:
                continue
            var client_stream_id = proxy[].handle_to_stream[hid]
            _ = proxy[].handle_to_stream.pop(hid)

            # Heap-allocate Response for the coroutine
            var response = handle^.take_response()
            var resp_heap = _heap_alloc[Response](1).as_any_origin()
            resp_heap.init_pointee_move(response^)
            proxy[].completed_responses[client_stream_id] = UInt64(Int(resp_heap))

            # Resume the stream coroutine so it can read the response
            self.connections[idx][].client_coro_server.resume_stream(
                client_stream_id
            )
            var h2_out = self.connections[idx][].client_coro_server.drain()
            if len(h2_out) > 0:
                self.connections[idx][].client_tls.send_data(Span(h2_out))
                var ct = self.connections[idx][].client_tls.drain_ciphertext()
                self._stage_client_send(idx, ct^)

    # --- Close helper ---------------------------------------------------------

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
# _drain_pending_submits — post-poll drain into the loop
# ---------------------------------------------------------------------------


def _drain_pending_submits(mut loop: CompletionLoop[ProxyHandler]) raises:
    """Submit all queued ops from the handler, then clear the queue."""
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

    # Load TLS material (shared with H1 proxy).
    var proxy_cert = _read_file(_CERT_DIR + "/proxy_cert.pem")
    var proxy_key = _read_file(_CERT_DIR + "/proxy_key.pem")

    # Initialize TLS library + configs.
    var tls_lib = RustlsLibrary()
    var server_config = TlsServerConfig(
        tls_lib, Span(proxy_cert), Span(proxy_key)
    )
    # Set ALPN for frontend: prefer h2
    var server_alpn = List[String]()
    server_alpn.append("h2")
    server_alpn.append("http/1.1")
    server_config.set_alpn_protocols(tls_lib, server_alpn)

    # Self-signed backend cert — use insecure client config.
    var client_config = TlsClientConfig(tls_lib, insecure=True)
    # Set ALPN for backend: prefer h2
    var client_alpn = List[String]()
    client_alpn.append("h2")
    client_alpn.append("http/1.1")
    client_config.set_alpn_protocols(tls_lib, client_alpn)

    # Listening socket (IPv4 TCP, non-blocking).
    var listener = Socket.tcp_v4()
    var bind_addr = SocketAddrV4(0, 0, 0, 0, port=_LISTEN_PORT)
    listener.bind(bind_addr)
    listener.listen(Backlog.DEFAULT)
    var listener_fd = listener.raw()

    print("h2-proxy: listening on https://127.0.0.1:" + String(_LISTEN_PORT))
    print("h2-proxy: backend at   https://" + _BACKEND_HOST + ":" + String(_BACKEND_PORT))

    # Build the handler + loop.
    var handler = ProxyHandler(
        listener_fd=listener_fd,
        tls_lib=tls_lib^,
        server_tls_config=server_config^,
        client_tls_config=client_config^,
        backend_addr=backend_addr,
    )
    var loop = CompletionLoop[ProxyHandler](handler^, sq_entries=256)

    loop.submit_accept(listener_fd, encode_token(LISTENER_CONN_ID, OP_ACCEPT))

    while True:
        loop.poll(wait_nr=1)
        _drain_pending_submits(loop)
        _ = listener
