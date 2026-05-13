# examples/reverse_proxy/proxy_h2.mojo
#
# H2-specific state and completion-handler free functions for the unified
# reverse proxy. Built against the post-Sprint-2 H2StreamingServer +
# H2Session APIs (the bit-rotted examples/h2_reverse_proxy/main.mojo
# targeted the removed H2CoroServer.resume_stream surface).
#
# DESIGN NOTE (mirrors proxy_h1.mojo's Task 2 deviation):
#   ProxyConnection / ProxyVariant are NOT defined here. They aggregate
#   both H1ProxyState (from proxy_h1.mojo) and H2ProxyState (this file)
#   and live in the consumer (main.mojo, Task 4). Putting them in
#   proxy_common would invert the dependency direction; putting them in
#   either of the per-version files would force a circular import.
#
# DESIGN NOTE (H2StreamingServer additive API):
#   This file relies on the public `resume_stream(sid)` / `has_stream(sid)`
#   helpers added to mojo_net.h2.h2_streaming_server. Without them the
#   streaming server has no way for the proxy driver to wake a per-stream
#   coro that's suspended waiting on a backend response arriving via a
#   different transport.

from std.collections import Dict
from std.collections.optional import Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from mojo_net.h2.h2_session import H2Session
from mojo_net.h2.h2_streaming_server import (
    H2StreamingServer,
    H2StreamingCtx,
    next_chunk,
)
from mojo_net.http import (
    BodyFrame,
    Headers,
    Method,
    Request,
    Response,
    StatusCode,
    Version,
)
from mojo_net.http.request import RequestBody
from mojo_net.http.session import RequestHandle
from mojo_net.tls import TlsConnection

from boucle.stackful import CoroYielder

from proxy_common import (
    ConnSendState,
    OP_BACKEND_CONNECT,
    OP_BACKEND_RECV,
    OP_BACKEND_SEND,
    OP_CLIENT_RECV,
    OP_CLIENT_SEND,
    PHASE_BACKEND_CONNECTING,
    PHASE_BACKEND_TLS_HANDSHAKE,
    PHASE_DONE,
    PHASE_PROXYING,
    PendingSubmit,
    SUBMIT_CONNECT,
    SUBMIT_RECV,
    SUBMIT_SEND,
    _RECV_BUF_SIZE,
    encode_token,
    queue_backend_connect,
    queue_backend_recv,
    queue_backend_send,
    queue_client_recv,
    queue_client_send,
    rewrite_request_headers,
    stage_backend_send,
    stage_client_send,
)


# ---------------------------------------------------------------------------
# H2 sub-phase (layered on top of common PHASE_PROXYING)
# ---------------------------------------------------------------------------
#
# Once PHASE_PROXYING is reached, we still need a few intermediate states for
# the backend H2 preface dance. PHASE_BACKEND_TLS_HANDSHAKE covers the TLS
# layer; once that's done we send the H2 client preface, then wait for the
# server preface from the backend, only then can we submit pending requests.


comptime H2_SUB_BACKEND_H2_PREFACE: UInt8 = 0
comptime H2_SUB_PROXYING: UInt8 = 1


comptime _VIA_H2: String = "2.0 mojo-proxy"


# ---------------------------------------------------------------------------
# _BackendWork — request queued by a stream coro for the event-loop driver
# ---------------------------------------------------------------------------


struct _BackendWork(Copyable, Movable):
    """A backend request queued by a stream coroutine.

    The coroutine heap-allocates the Request (so it survives the coro's
    yield boundary) and stores its address here; the driver takes the
    pointee + frees the slot after submitting to the backend H2Session.
    """

    var client_stream_id: Int
    var request_addr: UInt64

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
# ProxyShared — shared state between per-stream coros and the event-loop driver
# ---------------------------------------------------------------------------


struct ProxyShared(Movable):
    """Shared state between per-stream H2StreamingServer coros and the
    event-loop driver (the h2_handle_* free functions below).

    - pending_backend: coros append _BackendWork here and yield; the driver
      drains, submits to H2Session, and tracks the resulting RequestHandle.
    - completed_responses: driver heap-allocates a Response here keyed by
      the client stream_id, then resumes the coro so it can forward it.
    - handle_to_stream: maps backend RequestHandle.id() -> client stream_id
      so the driver can find which coro to wake when a response completes.

    Heap-allocated so the address is stable across moves of the surrounding
    H2ProxyState (the H2StreamingServer's `extra_data` is plumbed in at
    construction time and never updated).
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
        """Free any remaining heap-allocated Requests / Responses if the
        proxy is torn down mid-flight (e.g. client RST during a backend
        round-trip)."""
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
# proxy_h2_stream_body — per-stream coroutine body
# ---------------------------------------------------------------------------


fn proxy_h2_stream_body(mut yielder: CoroYielder) raises -> None:
    """Per-stream coroutine body for the H2 reverse proxy.

    Lifecycle:
      1. Read the entire client request body via next_chunk (suspends until
         each frame arrives).
      2. Build a backend Request, heap-allocate it, queue in ProxyShared,
         yield. The driver picks up the work next time it runs.
      3. After the driver resumes us (via H2StreamingServer.resume_stream),
         read the completed response from ProxyShared and forward it to
         the client through the streaming-ctx's resp_writer.
    """
    # Recover ctx + ProxyShared pointers from the coro's user_data.
    var ctx_ptr = yielder.user_data().bitcast[H2StreamingCtx]().as_any_origin()
    var proxy_ptr = UnsafePointer[ProxyShared, MutAnyOrigin](
        unsafe_from_address=Int(ctx_ptr[].extra_data)
    )
    var stream_id = Int(ctx_ptr[].stream_id)

    # --- Step 1: drain the client request body ---
    var body_bytes = List[UInt8]()
    while True:
        var frame_opt = next_chunk(ctx_ptr, yielder)
        if not Bool(frame_opt):
            # EOF — request body done.
            break
        var frame = frame_opt.unsafe_take()
        if frame.is_data():
            var data = frame.data().copy()
            for j in range(len(data)):
                body_bytes.append(data[j])
        elif frame.is_end():
            break
        elif frame.is_trailers():
            # Trailers are accepted but not forwarded in this MVP — the
            # bit-rotted reference didn't either.
            break

    # --- Step 2: build the backend Request and queue it ---
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

    rewrite_request_headers(request, "127.0.0.1", "localhost", _VIA_H2)

    var req_heap = _heap_alloc[Request](1).as_any_origin()
    req_heap.init_pointee_move(request^)

    var work = _BackendWork(
        client_stream_id=stream_id,
        request_addr=UInt64(Int(req_heap)),
    )
    proxy_ptr[].pending_backend.append(work^)

    # Yield — the driver will submit, await the response, and resume us.
    yielder.yield_to_caller()

    # --- Step 3: forward backend response ---
    if stream_id not in proxy_ptr[].completed_responses:
        # Driver woke us without a response — likely a backend error or
        # stream cleanup during teardown. Drop.
        return

    var resp_addr = proxy_ptr[].completed_responses[stream_id]
    _ = proxy_ptr[].completed_responses.pop(stream_id)
    var resp_ptr = UnsafePointer[Response, MutAnyOrigin](
        unsafe_from_address=Int(resp_addr)
    )
    var response = resp_ptr.take_pointee()
    resp_ptr.free()

    # Strip hop-by-hop, add Via.
    var resp_headers = Headers()
    for i in range(len(response.headers)):
        var name = response.headers.name_at(i)
        var value = response.headers.value_at(i)
        # Inline hop-by-hop check — proxy_common._is_hop_by_hop is module-
        # private. The list matches.
        if (
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
        ):
            continue
        resp_headers.add(name, value)
    resp_headers.add("via", _VIA_H2)

    var resp_body = List[UInt8]()
    for i in range(len(response.body)):
        var frame = response.body[i].copy()
        if frame.is_data():
            var data = frame.data().copy()
            for j in range(len(data)):
                resp_body.append(data[j])

    # Hand the response off to the streaming server's resp_writer; its
    # _drain_responses pass picks it up and emits HEADERS / DATA frames.
    var ctx3 = ctx_ptr.take_pointee()
    ctx3.resp_writer.send_status(
        StatusCode(other=response.status), resp_headers^
    )
    if len(resp_body) > 0:
        _ = ctx3.resp_writer.try_send_body(BodyFrame.data(resp_body^))
    ctx3.resp_writer.end()
    ctx_ptr.init_pointee_move(ctx3^)


# ---------------------------------------------------------------------------
# H2ProxyState — H2-specific per-conn state
# ---------------------------------------------------------------------------


struct H2ProxyState(Movable):
    """H2-specific per-conn state for the unified reverse proxy.

    Owns the H2StreamingServer (frontend, per-stream coros) and the
    H2Session (backend, sans-I/O client). `shared_ptr` is a heap pointer
    into the ProxyShared struct that the per-stream coros need to reach
    via their `extra_data`; its lifetime is tied to this struct's __del__.
    `sub_phase` tracks the H2-specific intra-PHASE_PROXYING states (server
    preface handshake → request forwarding).
    """

    var client_h2: H2StreamingServer
    var backend_session: H2Session
    var shared_ptr: UnsafePointer[ProxyShared, MutAnyOrigin]
    var backend_handles: Dict[Int, UInt64]
    var sub_phase: UInt8

    def __init__(
        out self,
        var client_h2: H2StreamingServer,
        var backend_session: H2Session,
        shared_ptr: UnsafePointer[ProxyShared, MutAnyOrigin],
    ):
        self.client_h2 = client_h2^
        self.backend_session = backend_session^
        self.shared_ptr = shared_ptr
        self.backend_handles = Dict[Int, UInt64]()
        self.sub_phase = H2_SUB_BACKEND_H2_PREFACE

    def __init__(out self, *, deinit take: Self):
        self.client_h2 = take.client_h2^
        self.backend_session = take.backend_session^
        self.shared_ptr = take.shared_ptr
        self.backend_handles = take.backend_handles^
        self.sub_phase = take.sub_phase

    fn __del__(deinit self):
        # Free the heap-allocated ProxyShared and any orphaned RequestHandles.
        var hkeys = List[Int]()
        for key in self.backend_handles.keys():
            hkeys.append(key)
        for i in range(len(hkeys)):
            try:
                var addr = self.backend_handles[hkeys[i]]
                var p = UnsafePointer[RequestHandle, MutAnyOrigin](
                    unsafe_from_address=Int(addr)
                )
                p.destroy_pointee()
                p.free()
            except:
                pass
        self.shared_ptr.destroy_pointee()
        self.shared_ptr.free()


def h2_proxy_state_new() raises -> H2ProxyState:
    """Per-conn constructor helper.

    Heap-allocates a ProxyShared (stable address for the streaming
    server's extra_data), builds an H2StreamingServer wired to
    proxy_h2_stream_body, and pairs it with a default H2Session.
    """
    var shared_ptr = _heap_alloc[ProxyShared](1).as_any_origin()
    shared_ptr.init_pointee_move(ProxyShared())
    var noneptr = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(shared_ptr)
    )
    var server = H2StreamingServer(
        handler_fn=proxy_h2_stream_body, extra_data=noneptr
    )
    var session = H2Session()
    return H2ProxyState(
        client_h2=server^,
        backend_session=session^,
        shared_ptr=shared_ptr,
    )


# ---------------------------------------------------------------------------
# _process_pending_backend / _deliver_backend_responses — internal drivers
# ---------------------------------------------------------------------------


def _process_pending_backend(
    mut state: H2ProxyState,
    mut send_state: ConnSendState,
    mut backend_tls: TlsConnection,
    mut out_submits: List[PendingSubmit],
    backend_fd: Int32,
    conn_id: UInt64,
) raises:
    """Drain pending backend work queued by stream coros, submit each
    Request to the backend H2Session, and stage the resulting outbound
    bytes through the backend TLS connection."""
    var shared = state.shared_ptr
    while len(shared[].pending_backend) > 0:
        var work = shared[].pending_backend.pop(0)
        var req_ptr = UnsafePointer[Request, MutAnyOrigin](
            unsafe_from_address=Int(work.request_addr)
        )
        var req = req_ptr.take_pointee()
        req_ptr.free()
        var handle = state.backend_session.submit(req^)
        var handle_id = Int(handle.id())
        shared[].handle_to_stream[handle_id] = work.client_stream_id
        var h_ptr = _heap_alloc[RequestHandle](1).as_any_origin()
        h_ptr.init_pointee_move(handle^)
        state.backend_handles[handle_id] = UInt64(Int(h_ptr))

    var out_bytes = state.backend_session.drain()
    if len(out_bytes) > 0:
        backend_tls.send_data(Span(out_bytes))
        var ct = backend_tls.drain_ciphertext()
        stage_backend_send(send_state, out_submits, backend_fd, conn_id, ct^)


def _deliver_backend_responses(
    mut state: H2ProxyState,
    mut send_state: ConnSendState,
    mut client_tls: TlsConnection,
    mut out_submits: List[PendingSubmit],
    client_fd: Int32,
    conn_id: UInt64,
) raises:
    """Drive every in-flight backend handle via run_one; for each one that
    completes, store the Response in ProxyShared.completed_responses and
    resume the matching frontend stream coro so it can forward."""
    if len(state.backend_handles) == 0:
        return

    var handle_ids = List[Int]()
    for key in state.backend_handles.keys():
        handle_ids.append(key)

    for i in range(len(handle_ids)):
        var hid = handle_ids[i]
        if hid not in state.backend_handles:
            continue
        var h_addr = state.backend_handles[hid]
        var h_ptr = UnsafePointer[RequestHandle, MutAnyOrigin](
            unsafe_from_address=Int(h_addr)
        )
        state.backend_session.run_one(h_ptr[])
        if not h_ptr[].is_complete():
            continue

        var handle = h_ptr.take_pointee()
        h_ptr.free()
        _ = state.backend_handles.pop(hid)

        var shared = state.shared_ptr
        if hid not in shared[].handle_to_stream:
            continue
        var client_stream_id = shared[].handle_to_stream[hid]
        _ = shared[].handle_to_stream.pop(hid)

        var response = handle^.take_response()
        var resp_heap = _heap_alloc[Response](1).as_any_origin()
        resp_heap.init_pointee_move(response^)
        shared[].completed_responses[client_stream_id] = UInt64(
            Int(resp_heap)
        )

        # Resume the coro; resume_stream also drains responses + flushes
        # the streaming server's outbuf for our next drain() call.
        if state.client_h2.has_stream(client_stream_id):
            state.client_h2.resume_stream(client_stream_id)

    var h2_out = state.client_h2.drain()
    if len(h2_out) > 0:
        client_tls.send_data(Span(h2_out))
        var ct = client_tls.drain_ciphertext()
        stage_client_send(send_state, out_submits, client_fd, conn_id, ct^)


# ---------------------------------------------------------------------------
# Client RECV handler
# ---------------------------------------------------------------------------


def h2_handle_client_recv(
    mut state: H2ProxyState,
    mut send_state: ConnSendState,
    mut client_tls: TlsConnection,
    mut backend_tls: TlsConnection,
    mut phase: UInt8,
    mut closed: Bool,
    client_fd: Int32,
    backend_fd: Int32,
    conn_id: UInt64,
    result: Int32,
) raises -> List[PendingSubmit]:
    """Feed inbound TLS bytes from the client. After TLS handshake,
    feed plaintext into the H2StreamingServer; per-stream coros run
    inside `feed()` and may enqueue _BackendWork. After processing, if
    any work was queued, kick off the backend connect (first time) or
    submit immediately if the backend session is already proxying."""
    var out = List[PendingSubmit]()

    send_state.client_recv_in_flight = False

    if result <= 0:
        closed = True
        return out^

    var n = Int(result)
    var chunk = List[UInt8](capacity=n)
    for i in range(n):
        chunk.append(send_state.client_recv_buf[i])
    client_tls.receive_data(Span(chunk))

    if client_tls.wants_write():
        var ct = client_tls.drain_ciphertext()
        stage_client_send(send_state, out, client_fd, conn_id, ct^)

    if client_tls.is_handshaking():
        queue_client_recv(send_state, out, client_fd, conn_id)
        return out^

    # TLS handshake done — drain plaintext.
    var plaintext = client_tls.drain_plaintext()

    # On first post-TLS recv, flush the H2 server preface to the client.
    # We detect "first time" via len(client_h2.drain()) > 0 here — the
    # streaming server's constructor already called initiate_connection().
    var preface_bytes = state.client_h2.drain()
    if len(preface_bytes) > 0:
        client_tls.send_data(Span(preface_bytes))
        var ct2 = client_tls.drain_ciphertext()
        stage_client_send(send_state, out, client_fd, conn_id, ct2^)

    if len(plaintext) > 0:
        state.client_h2.feed(Span(plaintext))
        var h2_out = state.client_h2.drain()
        if len(h2_out) > 0:
            client_tls.send_data(Span(h2_out))
            var ct3 = client_tls.drain_ciphertext()
            stage_client_send(send_state, out, client_fd, conn_id, ct3^)

    # If stream coros queued backend work, drive the backend. The backend
    # connect was already queued by main.mojo's _maybe_finalize_handshake;
    # only call _process_pending_backend once the backend channel is up.
    if len(state.shared_ptr[].pending_backend) > 0:
        if state.sub_phase == H2_SUB_PROXYING:
            _process_pending_backend(
                state, send_state, backend_tls, out, backend_fd, conn_id
            )

    queue_client_recv(send_state, out, client_fd, conn_id)
    return out^


# ---------------------------------------------------------------------------
# Backend CONNECT handler
# ---------------------------------------------------------------------------


def h2_handle_backend_connect(
    mut state: H2ProxyState,
    mut send_state: ConnSendState,
    mut client_tls: TlsConnection,
    mut backend_tls: TlsConnection,
    mut phase: UInt8,
    mut closed: Bool,
    client_fd: Int32,
    backend_fd: Int32,
    conn_id: UInt64,
    result: Int32,
) raises -> List[PendingSubmit]:
    """Backend TCP connect completed; drain pre-staged ClientHello and
    send it. Closes the connection on connect failure (the H2 streaming
    server cannot synthesize an HTTP error mid-handshake the way H1 can,
    so just drop)."""
    var out = List[PendingSubmit]()

    if result < 0:
        print("h2-proxy: backend connect failed:", result)
        closed = True
        return out^

    phase = PHASE_BACKEND_TLS_HANDSHAKE

    if backend_tls.wants_write():
        var ct = backend_tls.drain_ciphertext()
        stage_backend_send(send_state, out, backend_fd, conn_id, ct^)
    else:
        queue_backend_recv(send_state, out, backend_fd, conn_id)
    return out^


# ---------------------------------------------------------------------------
# Backend RECV handler
# ---------------------------------------------------------------------------


def h2_handle_backend_recv(
    mut state: H2ProxyState,
    mut send_state: ConnSendState,
    mut client_tls: TlsConnection,
    mut backend_tls: TlsConnection,
    mut phase: UInt8,
    mut closed: Bool,
    client_fd: Int32,
    backend_fd: Int32,
    conn_id: UInt64,
    result: Int32,
) raises -> List[PendingSubmit]:
    """Drive backend TLS + H2Session. On first plaintext after TLS, flush
    the H2 client preface; after the server preface comes back, transition
    to PROXYING + drain any pending backend work the coros have queued."""
    var out = List[PendingSubmit]()

    send_state.backend_recv_in_flight = False

    if result <= 0:
        closed = True
        return out^

    var n = Int(result)
    var chunk = List[UInt8](capacity=n)
    for i in range(n):
        chunk.append(send_state.backend_recv_buf[i])
    backend_tls.receive_data(Span(chunk))

    if backend_tls.wants_write():
        var ct = backend_tls.drain_ciphertext()
        stage_backend_send(send_state, out, backend_fd, conn_id, ct^)

    if backend_tls.is_handshaking():
        queue_backend_recv(send_state, out, backend_fd, conn_id)
        return out^

    var plaintext = backend_tls.drain_plaintext()

    if phase == PHASE_BACKEND_TLS_HANDSHAKE:
        # TLS just completed; flush the H2 client preface.
        phase = PHASE_PROXYING
        state.sub_phase = H2_SUB_BACKEND_H2_PREFACE
        var preface_bytes = state.backend_session.drain()
        if len(preface_bytes) > 0:
            backend_tls.send_data(Span(preface_bytes))
            var ct2 = backend_tls.drain_ciphertext()
            stage_backend_send(send_state, out, backend_fd, conn_id, ct2^)

        if len(plaintext) > 0:
            state.backend_session.feed(Span(plaintext))
            var resp_bytes = state.backend_session.drain()
            if len(resp_bytes) > 0:
                backend_tls.send_data(Span(resp_bytes))
                var ct3 = backend_tls.drain_ciphertext()
                stage_backend_send(
                    send_state, out, backend_fd, conn_id, ct3^
                )
        queue_backend_recv(send_state, out, backend_fd, conn_id)
        return out^

    if state.sub_phase == H2_SUB_BACKEND_H2_PREFACE:
        # Drain backend server preface response.
        if len(plaintext) > 0:
            state.backend_session.feed(Span(plaintext))
            var resp_bytes = state.backend_session.drain()
            if len(resp_bytes) > 0:
                backend_tls.send_data(Span(resp_bytes))
                var ct4 = backend_tls.drain_ciphertext()
                stage_backend_send(
                    send_state, out, backend_fd, conn_id, ct4^
                )

        state.sub_phase = H2_SUB_PROXYING
        _process_pending_backend(
            state, send_state, backend_tls, out, backend_fd, conn_id
        )
        queue_backend_recv(send_state, out, backend_fd, conn_id)
        return out^

    # PROXYING phase — feed response data into H2Session.
    if len(plaintext) > 0:
        state.backend_session.feed(Span(plaintext))
        var out_bytes = state.backend_session.drain()
        if len(out_bytes) > 0:
            backend_tls.send_data(Span(out_bytes))
            var ct5 = backend_tls.drain_ciphertext()
            stage_backend_send(send_state, out, backend_fd, conn_id, ct5^)

    # Deliver completed responses to the frontend coros (which then write
    # response frames into client_h2; we drain + ship below).
    _deliver_backend_responses(
        state, send_state, client_tls, out, client_fd, conn_id
    )
    queue_backend_recv(send_state, out, backend_fd, conn_id)
    return out^


# ---------------------------------------------------------------------------
# Backend SEND handler
# ---------------------------------------------------------------------------


def h2_handle_backend_send(
    mut state: H2ProxyState,
    mut send_state: ConnSendState,
    mut client_tls: TlsConnection,
    mut phase: UInt8,
    mut closed: Bool,
    client_fd: Int32,
    backend_fd: Int32,
    conn_id: UInt64,
    result: Int32,
) raises -> List[PendingSubmit]:
    """Flush backend-side ciphertext. On completion, chain pending bytes
    or start reading."""
    var out = List[PendingSubmit]()

    send_state.backend_send_in_flight = False

    if result < 0:
        closed = True
        return out^

    send_state.backend_send_buf = List[UInt8]()

    if len(send_state.backend_send_pending) > 0:
        var n_pending = len(send_state.backend_send_pending)
        var pending = List[UInt8](capacity=n_pending)
        for i in range(n_pending):
            pending.append(send_state.backend_send_pending[i])
        send_state.backend_send_pending = List[UInt8]()
        send_state.backend_send_buf = pending^
        queue_backend_send(send_state, out, backend_fd, conn_id)
        return out^

    if phase == PHASE_BACKEND_TLS_HANDSHAKE:
        queue_backend_recv(send_state, out, backend_fd, conn_id)
        return out^

    if (
        phase == PHASE_PROXYING
        and state.sub_phase == H2_SUB_BACKEND_H2_PREFACE
    ):
        queue_backend_recv(send_state, out, backend_fd, conn_id)
        return out^

    # PROXYING + H2_SUB_PROXYING: keep listening for more backend frames.
    queue_backend_recv(send_state, out, backend_fd, conn_id)
    return out^


# ---------------------------------------------------------------------------
# Client SEND handler
# ---------------------------------------------------------------------------


def h2_handle_client_send(
    mut state: H2ProxyState,
    mut send_state: ConnSendState,
    mut client_tls: TlsConnection,
    mut phase: UInt8,
    mut closed: Bool,
    client_fd: Int32,
    conn_id: UInt64,
    result: Int32,
) raises -> List[PendingSubmit]:
    """Flush client-side ciphertext. On completion, either chain pending
    bytes or transition to read (H2 is multiplexed, so we always loop
    back to reading rather than synchronously closing like H1)."""
    var out = List[PendingSubmit]()

    send_state.client_send_in_flight = False

    if result < 0:
        closed = True
        return out^

    send_state.client_send_buf = List[UInt8]()

    if len(send_state.client_send_pending) > 0:
        var n_pending = len(send_state.client_send_pending)
        var pending = List[UInt8](capacity=n_pending)
        for i in range(n_pending):
            pending.append(send_state.client_send_pending[i])
        send_state.client_send_pending = List[UInt8]()
        send_state.client_send_buf = pending^
        queue_client_send(send_state, out, client_fd, conn_id)
        return out^

    if phase == PHASE_DONE:
        closed = True
        return out^

    # H2 stays open and multiplexed; the client_recv loop will pick up
    # the next request frame whenever the client sends one.
    return out^
