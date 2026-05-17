# examples/reverse_proxy/proxy_common.mojo
#
# Shared scaffolding for the unified ALPN-dispatched reverse proxy.
# Imported by both proxy_h1.mojo and proxy_h2.mojo.
#
# Contents:
#   - Token encoding + OP_* / LISTENER_CONN_ID constants
#   - Unified PHASE_* enum (H1 + H2)
#   - Pending-submit kind constants
#   - PendingSubmit struct
#   - _read_file helper
#   - Hop-by-hop helpers (parameterized on via_token)
#   - make_error_response helper
#
# NOTE: _drain_pending_submits and ProxyConnection / ProxyVariant are
# intentionally not included here — they depend on the ProxyHandler /
# H1ProxyState types that are introduced in later tasks of Plan 3.

from std.io.file import FileHandle

from navette.http import (
    BodyFrame,
    Headers,
    Request,
    Response,
    StatusCode,
    Version,
)


# ---------------------------------------------------------------------------
# Token encoding helpers + op-kind constants
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
# Buffer sizing + cert directory
# ---------------------------------------------------------------------------


comptime _RECV_BUF_SIZE: Int = 8192
comptime _CERT_DIR: String = "examples/reverse_proxy/certs"


# ---------------------------------------------------------------------------
# Unified phase enum — shared across H1 and H2 proxy variants
# ---------------------------------------------------------------------------


comptime PHASE_CLIENT_TLS_HANDSHAKE: UInt8 = 0
comptime PHASE_BACKEND_CONNECTING: UInt8 = 1
comptime PHASE_BACKEND_TLS_HANDSHAKE: UInt8 = 2
comptime PHASE_PROXYING: UInt8 = 3
comptime PHASE_DONE: UInt8 = 4


# ---------------------------------------------------------------------------
# Pending-submit kind constants (queued from on_complete, drained after poll)
# ---------------------------------------------------------------------------


comptime SUBMIT_ACCEPT: UInt8 = 0
comptime SUBMIT_RECV: UInt8 = 1
comptime SUBMIT_SEND: UInt8 = 2
comptime SUBMIT_CONNECT: UInt8 = 3


# ---------------------------------------------------------------------------
# PendingSubmit — I/O ops queued from on_complete, drained by main loop
# ---------------------------------------------------------------------------


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
# ConnSendState — per-connection send/recv buffer bundle
# ---------------------------------------------------------------------------
#
# Bundles the per-direction send buffers, "pending" overflow queues, and
# in-flight flags that the H1 (and later H2) free-function handlers need
# to mutate. Without this bundle, each handler would take ~10 individual
# `mut` parameters for these fields; aggregating them keeps signatures
# tractable until Task 3 introduces `ProxyConnection` to subsume the
# whole connection record.


struct ConnSendState(Movable):
    """Per-direction send/recv buffers, overflow queues, in-flight flags.

    Both H1 and H2 free-function handlers take `mut send_state: ConnSendState`
    instead of ~10 individual `mut` parameters for the same fields.
    """

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

    def __init__(out self):
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

    def __init__(out self, *, deinit take: Self):
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


# ---------------------------------------------------------------------------
# Send-side queueing helpers (free functions over ConnSendState)
# ---------------------------------------------------------------------------


def queue_client_recv(
    mut send_state: ConnSendState,
    mut out_submits: List[PendingSubmit],
    client_fd: Int32,
    conn_id: UInt64,
):
    """Queue a CLIENT_RECV op if no client recv is currently in flight."""
    if send_state.client_recv_in_flight:
        return
    send_state.client_recv_in_flight = True
    out_submits.append(
        PendingSubmit(
            kind=SUBMIT_RECV, fd=client_fd, conn_id=conn_id, op_kind=OP_CLIENT_RECV,
        )
    )


def queue_client_send(
    mut send_state: ConnSendState,
    mut out_submits: List[PendingSubmit],
    client_fd: Int32,
    conn_id: UInt64,
):
    """Queue a CLIENT_SEND op (caller must have already populated
    `client_send_buf`)."""
    if send_state.client_send_in_flight:
        return
    if len(send_state.client_send_buf) == 0:
        return
    send_state.client_send_in_flight = True
    out_submits.append(
        PendingSubmit(
            kind=SUBMIT_SEND, fd=client_fd, conn_id=conn_id, op_kind=OP_CLIENT_SEND,
        )
    )


def queue_backend_connect(
    mut out_submits: List[PendingSubmit],
    backend_fd: Int32,
    conn_id: UInt64,
):
    """Queue a BACKEND_CONNECT op."""
    out_submits.append(
        PendingSubmit(
            kind=SUBMIT_CONNECT,
            fd=backend_fd,
            conn_id=conn_id,
            op_kind=OP_BACKEND_CONNECT,
        )
    )


def queue_backend_recv(
    mut send_state: ConnSendState,
    mut out_submits: List[PendingSubmit],
    backend_fd: Int32,
    conn_id: UInt64,
):
    """Queue a BACKEND_RECV op if no backend recv is in flight."""
    if send_state.backend_recv_in_flight:
        return
    send_state.backend_recv_in_flight = True
    out_submits.append(
        PendingSubmit(
            kind=SUBMIT_RECV, fd=backend_fd, conn_id=conn_id, op_kind=OP_BACKEND_RECV,
        )
    )


def queue_backend_send(
    mut send_state: ConnSendState,
    mut out_submits: List[PendingSubmit],
    backend_fd: Int32,
    conn_id: UInt64,
):
    """Queue a BACKEND_SEND op (caller must have already populated
    `backend_send_buf`)."""
    if send_state.backend_send_in_flight:
        return
    if len(send_state.backend_send_buf) == 0:
        return
    send_state.backend_send_in_flight = True
    out_submits.append(
        PendingSubmit(
            kind=SUBMIT_SEND, fd=backend_fd, conn_id=conn_id, op_kind=OP_BACKEND_SEND,
        )
    )


def stage_client_send(
    mut send_state: ConnSendState,
    mut out_submits: List[PendingSubmit],
    client_fd: Int32,
    conn_id: UInt64,
    var ct: List[UInt8],
):
    """Stage `ct` to be sent to the client.

    If no client send is currently in flight, swap it into
    `client_send_buf` and queue a CLIENT_SEND. Otherwise append to
    `client_send_pending`; the in-flight send's completion handler will
    promote it later.
    """
    if len(ct) == 0:
        return
    if send_state.client_send_in_flight:
        for i in range(len(ct)):
            send_state.client_send_pending.append(ct[i])
        return
    send_state.client_send_buf = ct^
    queue_client_send(send_state, out_submits, client_fd, conn_id)


def stage_backend_send(
    mut send_state: ConnSendState,
    mut out_submits: List[PendingSubmit],
    backend_fd: Int32,
    conn_id: UInt64,
    var ct: List[UInt8],
):
    """Stage `ct` to be sent to the backend (see `stage_client_send`)."""
    if len(ct) == 0:
        return
    if send_state.backend_send_in_flight:
        for i in range(len(ct)):
            send_state.backend_send_pending.append(ct[i])
        return
    send_state.backend_send_buf = ct^
    queue_backend_send(send_state, out_submits, backend_fd, conn_id)


# ---------------------------------------------------------------------------
# File I/O helper (native, matches test_tls_connection.mojo)
# ---------------------------------------------------------------------------


def _read_file(path: String) raises -> List[UInt8]:
    var fh = FileHandle(path, "r")
    var bytes = fh.read_bytes()
    fh.close()
    return bytes^


# ---------------------------------------------------------------------------
# Hop-by-hop header helpers
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
    mut request: Request,
    client_ip: String,
    backend_host: String,
    via_token: String,
):
    """Strip hop-by-hop from `request.headers` in place, replace `Host`
    with `backend_host`, then add `Via` and `X-Forwarded-For`. Mutates
    the request's headers only; method/target/version/body are left untouched.

    `via_token` is the value of the Via header (e.g. ``"1.1 mojo-proxy"`` for
    H1, ``"2.0 mojo-proxy"`` for H2).
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
    new_headers.add("via", via_token)
    new_headers.add("x-forwarded-for", client_ip)
    request.headers = new_headers^


def rewrite_response_headers(mut response: Response, via_token: String):
    """Strip hop-by-hop from the response in place, then add `Via`."""
    var new_headers = Headers()
    for i in range(len(response.headers)):
        var name = response.headers.name_at(i)
        var value = response.headers.value_at(i)
        if not _is_hop_by_hop(name):
            new_headers.add(name, value)
    new_headers.add("via", via_token)
    response.headers = new_headers^


# ---------------------------------------------------------------------------
# Error response helper
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
