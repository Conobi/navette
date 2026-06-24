# examples/reverse_proxy/proxy_h3.mojo
#
# H3/QUIC frontend for the unified reverse proxy (Option B).
#
# Design philosophy (mirrors proxy_h2.mojo's reuse-first approach):
#   We do NOT reimplement QUIC / H3 / QPACK. We EMBED navette's
#   `H3UdpServer[ForwardingHandler]` inside the proxy and drive it from the
#   proxy's existing io_uring `CompletionLoop` — NOT via `serve_forever`
#   (which owns its own loop). The proxy's `ProxyHandler.on_complete`
#   dispatches by token: tagged H3 tokens go to the embedded server,
#   everything else stays on the existing TCP paths.
#
#   Each inbound H3 request is forwarded to the SAME TCP backend machinery
#   proxy_h1 uses — an `H1Session` per in-flight request over its own
#   backend TCP + TLS connection. When the backend response (or a 502 on
#   connect failure) is ready, the driver calls the additive navette hook
#   `H3UdpServer.inject_response(conn_id, sid, ...)`, which stages the
#   response into the open stream's `ResponseWriter`; the next `on_flush`
#   tick emits it over QPACK/H3.
#
# Why a deferred-response hook is required (the H2 parallel):
#   In the sync H3 model the `StreamHandler` is handed a borrowed
#   `ResponseWriter` per callback; the surviving per-stream writer lives
#   inside `H3HandlerServer`'s private stream context. A backend TCP
#   completion fires on a DIFFERENT token with NO `StreamHandler` callback
#   to write through. proxy_h2 solved the same wall with the additive
#   `H2StreamingServer.resume_stream`; H3 gets the additive sync analog
#   `H3UdpServer.inject_response` / `has_stream` plus the `caps.conn_id` /
#   `caps.stream_id` surfacing.
#
# No module-level globals (Mojo 1.0.0b1 forbids them):
#   The `H3UdpServer` factory (`def () thin raises -> H`) cannot capture
#   state, so a forwarding handler cannot be handed a shared pointer at
#   construction. Instead each `ForwardingHandler` ACCUMULATES captured
#   requests in its own `_pending` list; the driver drains them per tick by
#   walking the server's public `conn_slots[i].h3[].handler`. The backend
#   registry + backend-TLS config addresses live on `ProxyHandler`
#   (`H3BackendRegistry`), stable inside the loop — not in a global.
#
# MODULE BOUNDARY:
#   This file holds the loop-agnostic building blocks. The loop-typed glue
#   (bootstrap, per-tick drain, SQE submission) lives in main.mojo, where
#   `ProxyHandler` / `CompletionLoop[ProxyHandler]` are in scope — exactly
#   as `_drain_pending_submits` already does for the TCP paths. This keeps
#   proxy_h3 free of a circular import on main.mojo.
#
# Token namespace (collision-free; the dispatch lives in main._dispatch):
#   bit 63 (H3_TOKEN_TAG)         — H3 frontend: UDP recvmsg / sendmsg /
#                                   timeout / provide-buf. Stripped before
#                                   forwarding to `_h3.on_complete`.
#   bit 62 (H3_BACKEND_TOKEN_TAG) — H3 backend TCP: connect / recv / send,
#                                   carrying a synthetic backend conn id in
#                                   the high bits and an OP_BACKEND_* kind
#                                   in the low byte (proxy_common encoding).
#   The proxy's own TCP tokens carry neither tag and decode unchanged.

from std.collections import Dict
from std.collections.optional import Optional
from std.ffi import external_call
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.h1 import H1Session
from navette.http import (
    BodyFrame,
    Headers,
    Method,
    Request,
    Response,
    StatusCode,
    Version,
)
from navette.http.request import RequestBody
from navette.http.handler import (
    StreamHandler,
    Request as HandlerRequest,
    RecvBody,
    ResponseWriter,
    Capabilities,
    StreamError,
)
from navette.http.session import RequestHandle
from navette.tls import (
    TlsBackend,
    TlsClientConfig,
    TlsConnection,
)
from navette.h3.h3_udp_server import H3UdpServer
from navette.runtime.socket_helpers import tcp_v4_nonblocking

from boucle.handle import OwnedHandle
from boucle.net.addr import SocketAddrV4, SocketAddrStorV4

from proxy_common import (
    ConnSendState,
    OP_BACKEND_CONNECT,
    OP_BACKEND_RECV,
    OP_BACKEND_SEND,
    PendingSubmit,
    SUBMIT_CONNECT,
    SUBMIT_RECV,
    SUBMIT_SEND,
    queue_backend_recv,
    queue_backend_send,
    rewrite_request_headers,
    stage_backend_send,
)


# ---------------------------------------------------------------------------
# Token-namespace tags
# ---------------------------------------------------------------------------


comptime H3_TOKEN_TAG: UInt64 = UInt64(1) << 63
"""High-bit tag marking a token as belonging to the embedded H3 frontend
(UDP recvmsg / sendmsg / timeout / provide-buf). ORed in before submission;
stripped before forwarding to `H3UdpServer.on_complete`."""

comptime H3_BACKEND_TOKEN_TAG: UInt64 = UInt64(1) << 62
"""Tag marking a token as an H3-backend TCP op (connect / recv / send for
the per-request `H1Session` round-trip). Carries a synthetic backend conn
id in the high bits and an `OP_BACKEND_*` kind in the low byte."""


comptime _VIA_H3: String = "3 mojo-proxy"


def h3_encode_backend_token(backend_conn_id: UInt64, op_kind: UInt8) -> UInt64:
    """Encode an H3-backend TCP token: tag | (conn_id << 8) | op_kind."""
    return H3_BACKEND_TOKEN_TAG | (backend_conn_id << 8) | UInt64(op_kind)


# H3-backend sub-phases (within the backend round-trip).
comptime _H3B_CONNECTING: UInt8 = 0
comptime _H3B_TLS_HANDSHAKE: UInt8 = 1
comptime _H3B_SENDING_REQUEST: UInt8 = 2
comptime _H3B_READING_RESPONSE: UInt8 = 3
comptime _H3B_DONE: UInt8 = 4


# ---------------------------------------------------------------------------
# _PendingForward — a request the handler captured, awaiting a backend conn
# ---------------------------------------------------------------------------


struct _PendingForward(Copyable, Movable):
    """A forwarded H3 request snapshot, accumulated by `ForwardingHandler`
    for the event-loop driver to turn into an `H3BackendConn`.

    The handler runs inside the H3 server's flush pass and cannot submit
    io_uring ops directly (the proxy loop holds a borrow on itself), so it
    parks the snapshot on its own `_pending` list; the driver's per-tick
    `h3_collect_forwards` walks every connection's handler, drains them,
    opens a backend TCP conn, and queues the SUBMIT_CONNECT.

    The request is heap-allocated (so it survives the handler→driver hop)
    and addressed by `request_addr`. The struct stays `Copyable` because
    `List[T]` requires `T: Copyable` in this Mojo version; the copy is a
    shallow pointer copy (the heap `Request` has exactly one logical owner
    at a time — see `open_backend` / the handler drop path).
    """

    var quic_conn_id: UInt64
    var h3_sid: Int
    var request_addr: UInt64

    def __init__(out self, quic_conn_id: UInt64, h3_sid: Int, request_addr: UInt64):
        self.quic_conn_id = quic_conn_id
        self.h3_sid = h3_sid
        self.request_addr = request_addr

    def __init__(out self, *, other: Self):
        self.quic_conn_id = other.quic_conn_id
        self.h3_sid = other.h3_sid
        self.request_addr = other.request_addr

    def __init__(out self, *, deinit take: Self):
        self.quic_conn_id = take.quic_conn_id
        self.h3_sid = take.h3_sid
        self.request_addr = take.request_addr

    def request_ptr(self) -> UnsafePointer[Request, MutAnyOrigin]:
        return UnsafePointer[Request, MutAnyOrigin](
            unsafe_from_address=Int(self.request_addr)
        )


# ---------------------------------------------------------------------------
# ForwardingHandler — StreamHandler plugged into H3UdpServer
# ---------------------------------------------------------------------------


struct ForwardingHandler(StreamHandler):
    """Per-H3-stream handler that forwards each request to the TCP backend.

    Instead of producing a response inline, `on_request` snapshots the
    request + stream identity, and `on_request_end` parks a
    `_PendingForward` on this handler's own `_pending` list, leaving the H3
    stream OPEN (request_ended True, response_ended False). The event-loop
    driver later drains `_pending` (via `take_pending`), opens a backend
    conn, runs the `H1Session` round-trip, and calls
    `H3UdpServer.inject_response` to complete the stream.

    Body handling: the request body is accumulated across
    `on_body_available` and finalized at `on_request_end`. (GETs reach
    `on_request_end` with an empty body — the common reverse-proxy case.)

    One handler per QUIC connection (re-invoked per stream). `_pending` can
    therefore hold multiple captures between driver ticks if several streams
    on one connection complete in the same flush; the driver drains the
    whole list each tick.
    """

    var _quic_conn_id: UInt64
    var _h3_sid: Int
    var _method: String
    var _target: String
    var _headers: Headers
    var _body: List[UInt8]
    var _captured: Bool
    var _pending: List[_PendingForward]

    def __init__(out self):
        self._quic_conn_id = UInt64(0)
        self._h3_sid = 0
        self._method = String("GET")
        self._target = String("/")
        self._headers = Headers()
        self._body = List[UInt8]()
        self._captured = False
        self._pending = List[_PendingForward]()

    def __init__(out self, *, deinit take: Self):
        self._quic_conn_id = take._quic_conn_id
        self._h3_sid = take._h3_sid
        self._method = take._method^
        self._target = take._target^
        self._headers = take._headers^
        self._body = take._body^
        self._captured = take._captured
        self._pending = take._pending^

    def on_request(
        mut self,
        var req: HandlerRequest,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        """Snapshot the request + stream identity. No response is produced
        here — the stream stays open until the backend round-trip completes
        (or fails with a 502)."""
        self._quic_conn_id = caps.conn_id
        self._h3_sid = Int(caps.stream_id)
        self._method = String(req.method)
        self._target = req.target.copy()
        var hdrs = Headers()
        for i in range(len(req.headers)):
            hdrs.add(req.headers.name_at(i), req.headers.value_at(i))
        self._headers = hdrs^
        self._body = List[UInt8]()
        self._captured = True

    def on_body_available(
        mut self, mut body: RecvBody, mut resp: ResponseWriter
    ) raises:
        """Accumulate request body bytes as they arrive."""
        while True:
            var f_opt = body.try_read()
            if not Bool(f_opt):
                break
            var f = f_opt.unsafe_take()
            if f.is_data():
                var data = f.data().copy()
                for j in range(len(data)):
                    self._body.append(data[j])

    def on_request_end(
        mut self, mut body: RecvBody, mut resp: ResponseWriter
    ) raises:
        """Drain any remaining body, build the backend Request, and park a
        `_PendingForward`. Returns without writing a response — the stream is
        intentionally left open until the backend round-trip completes."""
        while True:
            var f_opt = body.try_read()
            if not Bool(f_opt):
                break
            var f = f_opt.unsafe_take()
            if f.is_data():
                var data = f.data().copy()
                for j in range(len(data)):
                    self._body.append(data[j])

        if not self._captured:
            return

        var req_body: RequestBody
        if len(self._body) > 0:
            var bbytes = self._body.copy()
            req_body = RequestBody.buffered(bbytes^)
        else:
            req_body = RequestBody.empty()

        var request = Request(
            method=Method.custom(self._method.copy()),
            target=self._target.copy(),
            version=Version.http_1_1(),
            headers=Headers(other=self._headers),
            body=req_body^,
        )

        var req_heap = _heap_alloc[Request](1).as_unsafe_any_origin()
        req_heap.init_pointee_move(request^)

        self._pending.append(
            _PendingForward(
                quic_conn_id=self._quic_conn_id,
                h3_sid=self._h3_sid,
                request_addr=UInt64(Int(req_heap)),
            )
        )
        self._captured = False

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass

    def take_pending(mut self) -> List[_PendingForward]:
        """Move out the accumulated captures, leaving the list empty. Called
        by the driver each tick."""
        var out = self._pending^
        self._pending = List[_PendingForward]()
        return out^

    def __del__(deinit self):
        """Free any captured-but-undrained Requests if the handler is dropped
        mid-flight (connection torn down between flush and drain)."""
        for i in range(len(self._pending)):
            var p = self._pending[i].request_ptr()
            p.destroy_pointee()
            p.free()


def make_forwarding_handler() raises -> ForwardingHandler:
    """Per-connection factory called by `H3UdpServer` for each new QUIC
    connection. Stateless — captured requests accumulate on the returned
    handler and are drained by the driver via `take_pending`."""
    return ForwardingHandler()


# ---------------------------------------------------------------------------
# H3BackendConn — per-in-flight-request backend state
# ---------------------------------------------------------------------------


struct H3BackendConn(Movable):
    """One backend TCP + TLS + `H1Session` round-trip for a single H3
    request stream.

    `H1Session` is one-in-flight-per-connection, and H3 streams are
    multiplexed, so each concurrent H3 request gets its own
    `H3BackendConn` (its own backend fd + TLS connection + session + send
    buffers), keyed by a synthetic `backend_conn_id`. The
    `(quic_conn_id, h3_sid)` pair records which open H3 stream the eventual
    response must be injected into — `quic_conn_id` is the stable server
    SCID (from `caps.conn_id`), resolved through the generation-guarded DCID
    demux on injection, so a torn-down connection can never receive a stray
    response.

    Heap-allocated and addressed via `UnsafePointer` so recv/send buffers
    inside `send_state` stay put while io_uring ops are in flight.
    """

    var backend_conn_id: UInt64
    var quic_conn_id: UInt64
    var h3_sid: Int
    var backend_handle: OwnedHandle
    var backend_addr_stor: SocketAddrStorV4
    var backend_tls: TlsConnection
    var session: H1Session
    var send_state: ConnSendState
    var handle: Optional[RequestHandle]
    var phase: UInt8
    var responded: Bool

    def __init__(
        out self,
        backend_conn_id: UInt64,
        quic_conn_id: UInt64,
        h3_sid: Int,
        var backend_handle: OwnedHandle,
        backend_addr_stor: SocketAddrStorV4,
        var backend_tls: TlsConnection,
        var session: H1Session,
    ):
        self.backend_conn_id = backend_conn_id
        self.quic_conn_id = quic_conn_id
        self.h3_sid = h3_sid
        self.backend_handle = backend_handle^
        self.backend_addr_stor = backend_addr_stor
        self.backend_tls = backend_tls^
        self.session = session^
        self.send_state = ConnSendState()
        self.handle = Optional[RequestHandle]()
        self.phase = _H3B_CONNECTING
        self.responded = False

    def __init__(out self, *, deinit take: Self):
        self.backend_conn_id = take.backend_conn_id
        self.quic_conn_id = take.quic_conn_id
        self.h3_sid = take.h3_sid
        self.backend_handle = take.backend_handle^
        self.backend_addr_stor = take.backend_addr_stor
        self.backend_tls = take.backend_tls^
        self.session = take.session^
        self.send_state = take.send_state^
        self.handle = take.handle^
        self.phase = take.phase
        self.responded = take.responded


# ---------------------------------------------------------------------------
# H3BackendRegistry — owned by ProxyHandler (stable in the loop, not global)
# ---------------------------------------------------------------------------


struct H3BackendRegistry(Movable):
    """Per-process H3-backend bookkeeping, owned by `ProxyHandler`.

    Holds the backend dial target + SNI, the ADDRESSES of the long-lived
    `TlsBackend` and the H1-ALPN `TlsClientConfig` (both stable inside the
    loop's `ProxyHandler`), and the live `H3BackendConn` registry keyed by
    synthetic conn id.

    Addresses (not references) are stored because the configs live in the
    SAME `ProxyHandler` and Mojo cannot express a self-referential borrow.
    They are published once, after the handler is moved into the loop.
    """

    var backend_addr: SocketAddrV4
    var backend_host: String
    var h1_client_config_addr: UInt64
    var tls_shared_addr: UInt64
    var backends: Dict[UInt64, UInt64]
    var next_backend_id: UInt64

    def __init__(
        out self, backend_addr: SocketAddrV4, var backend_host: String
    ):
        self.backend_addr = backend_addr
        self.backend_host = backend_host^
        self.h1_client_config_addr = UInt64(0)
        self.tls_shared_addr = UInt64(0)
        self.backends = Dict[UInt64, UInt64]()
        self.next_backend_id = UInt64(1)

    def __init__(out self, *, deinit take: Self):
        self.backend_addr = take.backend_addr
        self.backend_host = take.backend_host^
        self.h1_client_config_addr = take.h1_client_config_addr
        self.tls_shared_addr = take.tls_shared_addr
        self.backends = take.backends^
        self.next_backend_id = take.next_backend_id

    def __del__(deinit self):
        """Free any live backend conns if the proxy is torn down mid-flight."""
        var keys = List[UInt64]()
        for key in self.backends.keys():
            keys.append(key)
        for i in range(len(keys)):
            try:
                var addr = self.backends[keys[i]]
                var p = UnsafePointer[H3BackendConn, MutAnyOrigin](
                    unsafe_from_address=Int(addr)
                )
                p.destroy_pointee()
                p.free()
            except:
                pass

    # --- Registry lookups ---

    def backend_ptr(
        self, backend_conn_id: UInt64
    ) -> UnsafePointer[H3BackendConn, MutAnyOrigin]:
        """Resolve a synthetic backend_conn_id to its heap `H3BackendConn`
        pointer, or a null pointer if absent (stale completion)."""
        if backend_conn_id not in self.backends:
            return UnsafePointer[H3BackendConn, MutAnyOrigin](
                unsafe_from_address=0
            )
        try:
            var addr = self.backends[backend_conn_id]
            return UnsafePointer[H3BackendConn, MutAnyOrigin](
                unsafe_from_address=Int(addr)
            )
        except:
            return UnsafePointer[H3BackendConn, MutAnyOrigin](
                unsafe_from_address=0
            )

    def free_backend(mut self, backend_conn_id: UInt64) raises:
        """Shutdown + destroy + free an `H3BackendConn` and drop its registry
        entry. Mirrors `_close_connection`'s shutdown-before-close so the
        backend TCP conn does not linger in ESTABLISHED."""
        if backend_conn_id not in self.backends:
            return
        var ptr = self.backend_ptr(backend_conn_id)
        if Int(ptr) == 0:
            return
        var backend_fd = ptr[].backend_handle.raw()
        _ = external_call["shutdown", Int32](backend_fd, Int32(2))
        try:
            _ = self.backends.pop(backend_conn_id)
        except:
            pass
        ptr.destroy_pointee()
        ptr.free()

    def open_backend(mut self, var fwd: _PendingForward) raises -> UInt64:
        """Open a backend TCP + TLS + `H1Session` for one captured request,
        register the resulting `H3BackendConn`, and return its
        `backend_conn_id`. The caller submits the SUBMIT_CONNECT (it needs
        the loop). Reads the long-lived `TlsBackend` + `TlsClientConfig`
        (ALPN http/1.1, insecure) by address; both outlive every backend
        conn."""
        var req_ptr = fwd.request_ptr()
        var request = req_ptr.take_pointee()
        req_ptr.free()

        rewrite_request_headers(
            request, "127.0.0.1", self.backend_host.copy(), _VIA_H3
        )

        var backend_handle = tcp_v4_nonblocking()
        var tls_shared_ptr = UnsafePointer[TlsBackend, MutAnyOrigin](
            unsafe_from_address=Int(self.tls_shared_addr)
        )
        var h1_cfg_ptr = UnsafePointer[TlsClientConfig, MutAnyOrigin](
            unsafe_from_address=Int(self.h1_client_config_addr)
        )
        var backend_tls = TlsConnection.new_client(
            tls_shared_ptr[].shared(),
            h1_cfg_ptr[],
            self.backend_host.copy(),
        )

        var session = H1Session()
        var handle = session.submit(request^)

        var backend_conn_id = self.next_backend_id
        self.next_backend_id += UInt64(1)

        var bconn = H3BackendConn(
            backend_conn_id=backend_conn_id,
            quic_conn_id=fwd.quic_conn_id,
            h3_sid=fwd.h3_sid,
            backend_handle=backend_handle^,
            backend_addr_stor=self.backend_addr.addr_stor(),
            backend_tls=backend_tls^,
            session=session^,
        )
        bconn.handle = Optional[RequestHandle](handle^)

        var bptr = _heap_alloc[H3BackendConn](1).as_unsafe_any_origin()
        bptr.init_pointee_move(bconn^)
        self.backends[backend_conn_id] = UInt64(Int(bptr))
        return backend_conn_id

    def backend_fd(self, backend_conn_id: UInt64) raises -> Int32:
        """Backend TCP fd for a live `H3BackendConn`, or -1."""
        var ptr = self.backend_ptr(backend_conn_id)
        if Int(ptr) == 0:
            return Int32(-1)
        return ptr[].backend_handle.raw()

    def backend_addr_ptr(
        self, backend_conn_id: UInt64
    ) raises -> UnsafePointer[Int8, StaticConstantOrigin]:
        """Pointer to a backend conn's stable, heap-stored `backend_addr_stor`
        (the connect target; outlives the in-flight connect). Null if
        absent."""
        var ptr = self.backend_ptr(backend_conn_id)
        if Int(ptr) == 0:
            return UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=0
            )
        return ptr[].backend_addr_stor.addr_unsafe_ptr()

    def backend_recv_buf_addr(self, backend_conn_id: UInt64) raises -> Int:
        """Raw address of a backend conn's recv buffer, or 0."""
        var ptr = self.backend_ptr(backend_conn_id)
        if Int(ptr) == 0:
            return 0
        return Int(ptr[].send_state.backend_recv_buf.unsafe_ptr())

    def backend_send_buf_addr(self, backend_conn_id: UInt64) raises -> Int:
        """Raw address of a backend conn's send buffer, or 0."""
        var ptr = self.backend_ptr(backend_conn_id)
        if Int(ptr) == 0:
            return 0
        return Int(ptr[].send_state.backend_send_buf.unsafe_ptr())

    def backend_send_buf_len(self, backend_conn_id: UInt64) raises -> Int:
        """Length of a backend conn's staged send buffer, or 0."""
        var ptr = self.backend_ptr(backend_conn_id)
        if Int(ptr) == 0:
            return 0
        return len(ptr[].send_state.backend_send_buf)


# ---------------------------------------------------------------------------
# Response injection
# ---------------------------------------------------------------------------


def h3_inject_502(
    mut h3: H3UdpServer[ForwardingHandler], quic_conn_id: UInt64, h3_sid: Int
) raises:
    """Inject a 502 Bad Gateway into the open H3 stream (upstream connect /
    backend failure path; mirrors proxy_h1's `502 Bad Gateway`)."""
    var headers = Headers()
    var body_text = String("502 Bad Gateway: upstream connect failed\n")
    var body_bytes = body_text.as_bytes()
    var body = List[UInt8]()
    for i in range(len(body_bytes)):
        body.append(body_bytes[i])
    headers.add("content-type", "text/plain; charset=utf-8")
    headers.add("content-length", String(len(body)))
    headers.add("via", _VIA_H3)
    if h3.has_stream(quic_conn_id, h3_sid):
        h3.inject_response(
            quic_conn_id, h3_sid, StatusCode.bad_gateway(), headers^, body^, True
        )


# ---------------------------------------------------------------------------
# Backend completion handlers (connect / recv / send)
# ---------------------------------------------------------------------------
#
# Each handler takes `mut h3` (for response injection), `mut registry` (for
# the backend-conn lookup + teardown), and the synthetic `backend_conn_id`,
# and returns the list of `PendingSubmit`s the caller must issue (the caller
# resolves buffer pointers from the registry and tags tokens). Backend conns
# that complete or fail are freed here; the returned list is empty then.


def h3_handle_backend_connect(
    mut h3: H3UdpServer[ForwardingHandler],
    mut registry: H3BackendRegistry,
    backend_conn_id: UInt64,
    result: Int32,
) raises -> List[PendingSubmit]:
    """Backend TCP connect completed. On success drain the pre-staged
    ClientHello and stage it for SEND. On failure inject a 502 into the H3
    stream and tear the backend conn down."""
    var out = List[PendingSubmit]()
    var ptr = registry.backend_ptr(backend_conn_id)
    if Int(ptr) == 0:
        return out^

    if result < 0:
        print("h3-proxy: backend connect failed:", result)
        h3_inject_502(h3, ptr[].quic_conn_id, ptr[].h3_sid)
        registry.free_backend(backend_conn_id)
        return out^

    ptr[].phase = _H3B_TLS_HANDSHAKE
    var backend_fd = ptr[].backend_handle.raw()

    if ptr[].backend_tls.wants_write():
        var ct = ptr[].backend_tls.drain_ciphertext()
        stage_backend_send(
            ptr[].send_state, out, backend_fd, backend_conn_id, ct^
        )
    else:
        queue_backend_recv(ptr[].send_state, out, backend_fd, backend_conn_id)
    return out^


def h3_handle_backend_recv(
    mut h3: H3UdpServer[ForwardingHandler],
    mut registry: H3BackendRegistry,
    backend_conn_id: UInt64,
    result: Int32,
) raises -> List[PendingSubmit]:
    """Drive backend TLS recv + the `H1Session` response parse. On a
    complete response, inject it into the open H3 stream and tear the
    backend conn down. On EOF/error before a response, inject a 502."""
    var out = List[PendingSubmit]()
    var ptr = registry.backend_ptr(backend_conn_id)
    if Int(ptr) == 0:
        return out^
    ptr[].send_state.backend_recv_in_flight = False
    var backend_fd = ptr[].backend_handle.raw()

    if result <= 0:
        if not ptr[].responded:
            h3_inject_502(h3, ptr[].quic_conn_id, ptr[].h3_sid)
        registry.free_backend(backend_conn_id)
        return out^

    var n = Int(result)
    var chunk = List[UInt8](capacity=n)
    for i in range(n):
        chunk.append(ptr[].send_state.backend_recv_buf[i])
    ptr[].backend_tls.receive_data(Span(chunk))

    if ptr[].backend_tls.wants_write():
        var ct = ptr[].backend_tls.drain_ciphertext()
        stage_backend_send(
            ptr[].send_state, out, backend_fd, backend_conn_id, ct^
        )

    if ptr[].backend_tls.is_handshaking():
        queue_backend_recv(ptr[].send_state, out, backend_fd, backend_conn_id)
        return out^

    var plaintext = ptr[].backend_tls.drain_plaintext()
    if len(plaintext) > 0:
        ptr[].session.feed(Span(plaintext))

    # First post-handshake pass: flush the request bytes the session queued
    # at submit() time.
    if ptr[].phase == _H3B_TLS_HANDSHAKE:
        ptr[].phase = _H3B_SENDING_REQUEST
        var req_bytes = ptr[].session.drain()
        if len(req_bytes) > 0:
            ptr[].backend_tls.send_data(Span(req_bytes))
            var ct2 = ptr[].backend_tls.drain_ciphertext()
            stage_backend_send(
                ptr[].send_state, out, backend_fd, backend_conn_id, ct2^
            )
        else:
            queue_backend_recv(
                ptr[].send_state, out, backend_fd, backend_conn_id
            )
        return out^

    # Step the in-flight handle against the parsed bytes.
    if not ptr[].handle:
        queue_backend_recv(ptr[].send_state, out, backend_fd, backend_conn_id)
        return out^

    var handle_opt = Optional[RequestHandle]()
    swap(handle_opt, ptr[].handle)
    var handle = handle_opt.take()
    ptr[].session.run_one(handle)
    if not handle.is_complete():
        ptr[].handle = Optional[RequestHandle](handle^)
        queue_backend_recv(ptr[].send_state, out, backend_fd, backend_conn_id)
        return out^

    # Got a complete response — strip hop-by-hop, add Via, inject into H3.
    var response = handle^.take_response()
    var resp_headers = Headers()
    for i in range(len(response.headers)):
        var name = response.headers.name_at(i)
        var value = response.headers.value_at(i)
        if _h3_is_hop_by_hop(name):
            continue
        resp_headers.add(name, value)
    resp_headers.add("via", _VIA_H3)

    var resp_body = List[UInt8]()
    for i in range(len(response.body)):
        var frame = response.body[i].copy()
        if frame.is_data():
            var data = frame.data().copy()
            for j in range(len(data)):
                resp_body.append(data[j])

    var quic_conn_id = ptr[].quic_conn_id
    var h3_sid = ptr[].h3_sid
    var status = StatusCode(other=response.status)
    ptr[].responded = True

    if h3.has_stream(quic_conn_id, h3_sid):
        h3.inject_response(
            quic_conn_id, h3_sid, status^, resp_headers^, resp_body^, True
        )
    registry.free_backend(backend_conn_id)
    return out^


def h3_handle_backend_send(
    mut h3: H3UdpServer[ForwardingHandler],
    mut registry: H3BackendRegistry,
    backend_conn_id: UInt64,
    result: Int32,
) raises -> List[PendingSubmit]:
    """Backend ciphertext flushed. Chain pending bytes or transition to
    reading the backend response."""
    var out = List[PendingSubmit]()
    var ptr = registry.backend_ptr(backend_conn_id)
    if Int(ptr) == 0:
        return out^
    ptr[].send_state.backend_send_in_flight = False
    var backend_fd = ptr[].backend_handle.raw()

    if result < 0:
        if not ptr[].responded:
            h3_inject_502(h3, ptr[].quic_conn_id, ptr[].h3_sid)
        registry.free_backend(backend_conn_id)
        return out^

    ptr[].send_state.backend_send_buf = List[UInt8]()

    if len(ptr[].send_state.backend_send_pending) > 0:
        var n_pending = len(ptr[].send_state.backend_send_pending)
        var pending = List[UInt8](capacity=n_pending)
        for i in range(n_pending):
            pending.append(ptr[].send_state.backend_send_pending[i])
        ptr[].send_state.backend_send_pending = List[UInt8]()
        ptr[].send_state.backend_send_buf = pending^
        queue_backend_send(ptr[].send_state, out, backend_fd, backend_conn_id)
        return out^

    if ptr[].phase == _H3B_SENDING_REQUEST:
        ptr[].phase = _H3B_READING_RESPONSE
    queue_backend_recv(ptr[].send_state, out, backend_fd, backend_conn_id)
    return out^


# ---------------------------------------------------------------------------
# Hop-by-hop check (proxy_common._is_hop_by_hop is module-private; same list)
# ---------------------------------------------------------------------------


def _h3_is_hop_by_hop(name: String) -> Bool:
    """Return True if `name` is a hop-by-hop header (lowercase). Inlined
    because proxy_common._is_hop_by_hop is module-private."""
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
