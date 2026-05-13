# examples/reverse_proxy/proxy_h1.mojo
#
# H1-specific state and completion-handler free functions for the unified
# reverse proxy. Extracted from the original `main.mojo` ProxyHandler in
# Task 2 of Plan 3 (Unified ALPN-Dispatched Reverse Proxy).
#
# DESIGN NOTE (Task 2 deviation from plan):
#   The plan caveat suggests moving `ProxyConnection` and `ProxyVariant`
#   into `proxy_common.mojo`. We cannot do that yet: `ProxyVariant` needs
#   `H2ProxyState`, which is introduced in Task 3, and `ProxyConnection`
#   aggregates both H1 and H2 state — a circular dependency.
#
#   Instead, this file uses the plan's option (b): the H1 free functions
#   take H1-relevant fields directly (`mut state: H1ProxyState`,
#   `mut send_state: ConnSendState`, individual TLS connections, etc.).
#   `ProxyConnection` will be introduced in Task 3/4 once `H2ProxyState`
#   exists, and the parameter lists tightened then.

from std.collections.optional import Optional
from std.memory import Span

from mojo_net.h1 import ParseConfig, ServerConnection, H1Session
from mojo_net.http import (
    BodyFrame,
    Headers,
    Method,
    Request,
    Response,
    StatusCode,
    Version,
)
from mojo_net.http.session import RequestHandle
from mojo_net.tls import TlsConnection

from boucle.handle import OwnedHandle

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
    make_error_response,
    queue_backend_connect,
    queue_backend_recv,
    queue_backend_send,
    queue_client_recv,
    queue_client_send,
    rewrite_request_headers,
    rewrite_response_headers,
    stage_backend_send,
    stage_client_send,
)


# ---------------------------------------------------------------------------
# Sub-phase enum (H1-specific, layered on top of common PHASE_PROXYING)
# ---------------------------------------------------------------------------
#
# The common PHASE_* enum covers the connection-lifecycle phases (TLS
# handshakes, backend connect, done). Once we reach PHASE_PROXYING the
# H1-specific sub-phase below tracks where we are in the request/response
# cycle. We encode it in a separate field on H1ProxyState so the H2 path
# can ignore it.


comptime H1_SUB_READING_REQUEST: UInt8 = 0
comptime H1_SUB_SENDING_REQUEST: UInt8 = 1
comptime H1_SUB_READING_RESPONSE: UInt8 = 2
comptime H1_SUB_SENDING_RESPONSE: UInt8 = 3


comptime _VIA_H1: String = "1.1 mojo-proxy"


# ---------------------------------------------------------------------------
# H1ProxyState — H1-specific per-conn state
# ---------------------------------------------------------------------------


struct H1ProxyState(Movable):
    """H1-specific per-conn state for the unified reverse proxy.

    Contains the H1 sans-I/O state machines for both sides of the proxy:
    `client_http` parses incoming requests from the client; `backend_session`
    sends requests to and parses responses from the H1 backend.
    `headers_committed` tracks whether the client-side response has begun
    streaming back (after which we can no longer send a synthesized error
    response).
    """

    var client_http: ServerConnection
    var backend_session: H1Session
    var backend_request_handle: Optional[RequestHandle]
    var headers_committed: Bool
    var sub_phase: UInt8

    def __init__(
        out self,
        var client_http: ServerConnection,
        var backend_session: H1Session,
    ):
        self.client_http = client_http^
        self.backend_session = backend_session^
        self.backend_request_handle = Optional[RequestHandle]()
        self.headers_committed = False
        self.sub_phase = H1_SUB_READING_REQUEST

    def __init__(out self, *, deinit take: Self):
        self.client_http = take.client_http^
        self.backend_session = take.backend_session^
        self.backend_request_handle = take.backend_request_handle^
        self.headers_committed = take.headers_committed
        self.sub_phase = take.sub_phase


def h1_proxy_state_new() raises -> H1ProxyState:
    """Per-conn constructor helper.

    Builds a default `ServerConnection(ParseConfig())` and a default
    `H1Session()`, then wraps them in an `H1ProxyState`.
    """
    var http = ServerConnection(ParseConfig())
    var session = H1Session()
    return H1ProxyState(client_http=http^, backend_session=session^)


# ---------------------------------------------------------------------------
# Error helper (free function)
# ---------------------------------------------------------------------------


def h1_send_error_and_close(
    mut state: H1ProxyState,
    mut send_state: ConnSendState,
    mut client_tls: TlsConnection,
    mut phase: UInt8,
    mut closed: Bool,
    mut out_submits: List[PendingSubmit],
    client_fd: Int32,
    conn_id: UInt64,
    code: Int,
    reason: String,
    body_text: String,
) raises:
    """Synthesize an error response (if headers haven't been committed yet)
    and stage it for client-side SEND. If headers were already committed,
    just mark the connection closed.
    """
    if not state.headers_committed:
        var resp = make_error_response(code, reason, body_text)
        state.client_http.send_response(resp^)
        var pt = state.client_http.drain()
        if len(pt) > 0:
            client_tls.send_data(Span(pt))
        var ct = client_tls.drain_ciphertext()
        phase = PHASE_DONE
        state.headers_committed = True
        stage_client_send(send_state, out_submits, client_fd, conn_id, ct^)
    else:
        closed = True


# ---------------------------------------------------------------------------
# Client RECV handler
# ---------------------------------------------------------------------------


def h1_handle_client_recv(
    mut state: H1ProxyState,
    mut send_state: ConnSendState,
    mut client_tls: TlsConnection,
    mut phase: UInt8,
    mut closed: Bool,
    backend_host: String,
    client_fd: Int32,
    backend_fd: Int32,
    conn_id: UInt64,
    result: Int32,
) raises -> List[PendingSubmit]:
    """Drive client-side TLS recv, feed plaintext into the H1 server parser,
    and submit the parsed request to the backend H1 session if a full
    request is available.

    Returns the list of `PendingSubmit` ops the outer loop should drain.
    """
    var out = List[PendingSubmit]()

    # Mark the in-flight RECV as completed regardless of result; the buffer
    # is now ours again to refill.
    send_state.client_recv_in_flight = False

    if result <= 0:
        # 0 = EOF; <0 = error. Caller closes the connection.
        closed = True
        return out^

    # Feed received ciphertext into the TLS state machine.
    var n = Int(result)
    var chunk = List[UInt8](capacity=n)
    for i in range(n):
        chunk.append(send_state.client_recv_buf[i])
    client_tls.receive_data(Span(chunk))

    # If TLS has ciphertext to send (handshake reply / encrypted app data),
    # stage it for SEND.
    if client_tls.wants_write():
        var ct = client_tls.drain_ciphertext()
        stage_client_send(send_state, out, client_fd, conn_id, ct^)

    if client_tls.is_handshaking():
        # Need more handshake bytes from the client.
        queue_client_recv(send_state, out, client_fd, conn_id)
        return out^

    # Handshake done — feed any plaintext we just decrypted into the HTTP
    # parser.
    var plaintext = client_tls.drain_plaintext()
    if len(plaintext) > 0:
        state.client_http.receive_data(Span(plaintext))

    var req_opt = state.client_http.next_request()
    if not req_opt:
        # Need more bytes — go back to reading.
        state.sub_phase = H1_SUB_READING_REQUEST
        queue_client_recv(send_state, out, client_fd, conn_id)
        return out^

    # Got a full request — rewrite headers and submit to the backend
    # session. H1Session.submit encodes the request, queues bytes in its
    # outbuf, and returns a RequestHandle that we drive via run_one once
    # the backend response arrives.
    var request = req_opt.take()
    rewrite_request_headers(request, "127.0.0.1", backend_host, _VIA_H1)
    var handle = state.backend_session.submit(request^)
    state.backend_request_handle = Optional[RequestHandle](handle^)

    phase = PHASE_BACKEND_CONNECTING
    queue_backend_connect(out, backend_fd, conn_id)
    return out^


# ---------------------------------------------------------------------------
# Backend CONNECT handler
# ---------------------------------------------------------------------------


def h1_handle_backend_connect(
    mut state: H1ProxyState,
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
    """Handle completion of the BACKEND_CONNECT op. On success, drains the
    pre-staged ClientHello from `backend_tls` and stages it for SEND."""
    var out = List[PendingSubmit]()

    if result < 0:
        print("proxy: backend connect failed:", result)
        h1_send_error_and_close(
            state,
            send_state,
            client_tls,
            phase,
            closed,
            out,
            client_fd,
            conn_id,
            502,
            "Bad Gateway",
            "backend unreachable",
        )
        return out^

    phase = PHASE_BACKEND_TLS_HANDSHAKE

    # The client TLS (toward backend) already staged a ClientHello at
    # construction time. Drain + send it.
    if backend_tls.wants_write():
        var ct = backend_tls.drain_ciphertext()
        stage_backend_send(send_state, out, backend_fd, conn_id, ct^)
    else:
        # Unexpected — start reading anyway.
        queue_backend_recv(send_state, out, backend_fd, conn_id)
    return out^


# ---------------------------------------------------------------------------
# Backend RECV handler
# ---------------------------------------------------------------------------


def h1_handle_backend_recv(
    mut state: H1ProxyState,
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
    """Drive backend-side TLS recv, feed plaintext into the backend
    H1Session, and once a complete response is extracted, rewrite it and
    hand it to the client-side encoder.
    """
    var out = List[PendingSubmit]()

    send_state.backend_recv_in_flight = False

    if result <= 0:
        h1_send_error_and_close(
            state,
            send_state,
            client_tls,
            phase,
            closed,
            out,
            client_fd,
            conn_id,
            502,
            "Bad Gateway",
            "backend closed",
        )
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

    # Backend TLS handshake is done — drain decrypted data into the
    # backend H1 session (for response parsing).
    var plaintext = backend_tls.drain_plaintext()
    if len(plaintext) > 0:
        state.backend_session.feed(Span(plaintext))

    # If we just finished the handshake and haven't flushed the request
    # yet, do it now. The bytes were already queued in H1Session._outbuf
    # by submit() — we just need to drain them through TLS.
    if phase == PHASE_BACKEND_TLS_HANDSHAKE:
        phase = PHASE_PROXYING
        state.sub_phase = H1_SUB_SENDING_REQUEST
        var req_bytes = state.backend_session.drain()
        if len(req_bytes) > 0:
            backend_tls.send_data(Span(req_bytes))
            var ct2 = backend_tls.drain_ciphertext()
            stage_backend_send(send_state, out, backend_fd, conn_id, ct2^)
        else:
            queue_backend_recv(send_state, out, backend_fd, conn_id)
        return out^

    # Try to extract a complete response by stepping the session against
    # the in-flight handle. H1Session tracks the request method internally.
    if not state.backend_request_handle:
        queue_backend_recv(send_state, out, backend_fd, conn_id)
        return out^

    # Move the handle out of the field so we can drive run_one against it.
    # The Optional[RequestHandle] field is replaced with an empty one for
    # the duration of the call; we put it back if the response isn't ready.
    var handle_opt = Optional[RequestHandle]()
    swap(handle_opt, state.backend_request_handle)
    var handle = handle_opt.take()
    state.backend_session.run_one(handle)
    if not handle.is_complete():
        # Response not ready yet; restore the handle and ask for more bytes.
        state.backend_request_handle = Optional[RequestHandle](handle^)
        queue_backend_recv(send_state, out, backend_fd, conn_id)
        return out^

    # Got a full response — extract it from the handle, rewrite, hand to
    # the client-side H1 engine.
    var response = handle^.take_response()
    rewrite_response_headers(response, _VIA_H1)
    state.client_http.send_response(response^)

    # Drain client-side H1 serialization, feed to TLS, queue SEND.
    var pt = state.client_http.drain()
    if len(pt) > 0:
        client_tls.send_data(Span(pt))
    var ct3 = client_tls.drain_ciphertext()
    state.sub_phase = H1_SUB_SENDING_RESPONSE
    state.headers_committed = True
    stage_client_send(send_state, out, client_fd, conn_id, ct3^)
    return out^


# ---------------------------------------------------------------------------
# Backend SEND handler
# ---------------------------------------------------------------------------


def h1_handle_backend_send(
    mut state: H1ProxyState,
    mut send_state: ConnSendState,
    mut client_tls: TlsConnection,
    mut phase: UInt8,
    mut closed: Bool,
    client_fd: Int32,
    backend_fd: Int32,
    conn_id: UInt64,
    result: Int32,
) raises -> List[PendingSubmit]:
    """Flush backend-side ciphertext. On completion, either chain pending
    bytes or transition into the appropriate read phase.
    """
    var out = List[PendingSubmit]()

    send_state.backend_send_in_flight = False

    if result < 0:
        h1_send_error_and_close(
            state,
            send_state,
            client_tls,
            phase,
            closed,
            out,
            client_fd,
            conn_id,
            502,
            "Bad Gateway",
            "backend send failed",
        )
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

    if phase == PHASE_PROXYING and state.sub_phase == H1_SUB_SENDING_REQUEST:
        # Request flushed — now wait for the response.
        state.sub_phase = H1_SUB_READING_RESPONSE
        queue_backend_recv(send_state, out, backend_fd, conn_id)

    return out^


# ---------------------------------------------------------------------------
# Client SEND handler
# ---------------------------------------------------------------------------


def h1_handle_client_send(
    mut state: H1ProxyState,
    mut send_state: ConnSendState,
    mut client_tls: TlsConnection,
    mut phase: UInt8,
    mut closed: Bool,
    client_fd: Int32,
    conn_id: UInt64,
    result: Int32,
) raises -> List[PendingSubmit]:
    """Flush client-side ciphertext. On completion, either chain pending
    bytes, transition to the keep-alive loop, or close the connection.
    """
    var out = List[PendingSubmit]()

    send_state.client_send_in_flight = False

    if result < 0:
        closed = True
        return out^

    # Short-write case is intentionally unhandled in M2 (the plan scope is
    # a minimum-viable proxy). The send_buf is discarded.
    send_state.client_send_buf = List[UInt8]()

    # If more ciphertext was queued while we were in flight, promote it
    # and immediately re-queue another send.
    if len(send_state.client_send_pending) > 0:
        var n_pending = len(send_state.client_send_pending)
        var pending = List[UInt8](capacity=n_pending)
        for i in range(n_pending):
            pending.append(send_state.client_send_pending[i])
        send_state.client_send_pending = List[UInt8]()
        send_state.client_send_buf = pending^
        queue_client_send(send_state, out, client_fd, conn_id)
        # Don't transition phase yet — wait for this chained send to
        # complete first.
        return out^

    if phase == PHASE_DONE:
        closed = True
        return out^

    if phase == PHASE_PROXYING and state.sub_phase == H1_SUB_SENDING_RESPONSE:
        # Fully flushed the response. Either keep-alive and loop back or
        # close.
        if state.client_http.is_keep_alive():
            state.sub_phase = H1_SUB_READING_REQUEST
            state.headers_committed = False
            queue_client_recv(send_state, out, client_fd, conn_id)
        else:
            closed = True
        return out^

    # Otherwise we are still in a handshake phase and need more recvs.
    if client_tls.is_handshaking():
        queue_client_recv(send_state, out, client_fd, conn_id)

    return out^
