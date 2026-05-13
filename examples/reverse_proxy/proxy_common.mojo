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

from mojo_net.http import (
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
