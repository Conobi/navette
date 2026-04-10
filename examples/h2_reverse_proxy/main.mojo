# examples/h2_reverse_proxy/main.mojo
#
# HTTPS H2 reverse proxy example composing the mojo-net sans-I/O library
# (H2Connection + H2Session) with the boucle io_uring CompletionLoop.
#
# Single hardcoded backend, TLS on both sides, single-threaded.
# Frontend uses raw H2Connection (server-side) for direct response timing.
# Backend uses H2Session (client adapter) to exercise the Session trait.
#
# Layout of this file:
#   - Token encoding helpers
#   - Phase constants
#   - PendingSubmit               : queued I/O op for post-poll drain
#   - ProxyConnection             : per-client state
#   - header rewriting helpers
#   - ProxyHandler                : CompletionHandler implementation
#   - _drain_pending_submits      : free function that re-issues ops to the loop
#   - main                        : bind listener, build handler, run loop

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
from src.h2.pseudo_headers import request_from_h2_headers
from src.h2.config import h2_production_config
from lib.http2.connection import (
    H2Connection,
    H2Event,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_GOAWAY_RECEIVED,
    H2_EVT_CONNECTION_TERMINATED,
)
from lib.http1.types import Header
from src.tls import (
    RustlsLibrary,
    TlsClientConfig,
    TlsServerConfig,
    TlsConnection,
)

from boucle import CompletionLoop, CompletionHandler
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
# _PendingRequest — captured client H2 request waiting for backend response
# ---------------------------------------------------------------------------


struct _PendingRequest(Movable):
    """A client request that has been captured from H2 events, waiting to
    be forwarded to the backend."""

    var client_stream_id: UInt32
    var method: String
    var target: String
    var headers: Headers
    var body: List[UInt8]
    var stream_ended: Bool

    def __init__(
        out self,
        client_stream_id: UInt32,
        method: String,
        target: String,
        var headers: Headers,
    ):
        self.client_stream_id = client_stream_id
        self.method = method
        self.target = target
        self.headers = headers^
        self.body = List[UInt8]()
        self.stream_ended = False

    def __init__(out self, *, deinit take: Self):
        self.client_stream_id = take.client_stream_id
        self.method = take.method^
        self.target = take.target^
        self.headers = take.headers^
        self.body = take.body^
        self.stream_ended = take.stream_ended


# Wrapper to store _PendingRequest pointers in a List (needs Copyable).
struct _PendingReqPtr(Copyable, Movable):
    var addr: UInt64

    def __init__(out self, addr: UInt64):
        self.addr = addr

    def __init__(out self, *, other: Self):
        self.addr = other.addr

    def __init__(out self, *, deinit take: Self):
        self.addr = take.addr

    def ptr(self) -> UnsafePointer[_PendingRequest, MutAnyOrigin]:
        return UnsafePointer[_PendingRequest, MutAnyOrigin](
            unsafe_from_address=Int(self.addr)
        )


# ---------------------------------------------------------------------------
# ProxyConnection — per-client proxied state
# ---------------------------------------------------------------------------


struct ProxyConnection(Movable):
    """Per-client proxy state for H2 reverse proxy.

    Frontend: raw H2Connection (server-side) for direct event control.
    Backend:  H2Session (client adapter) for Session trait validation.
    """

    var conn_id: UInt64
    var client_handle: OwnedHandle
    var backend_handle: OwnedHandle
    var backend_addr_stor: SocketAddrStorV4
    var client_tls: TlsConnection
    var client_h2: H2Connection       # server-side H2 (raw)
    var client_h2_initiated: Bool     # True after initiate_connection()
    var backend_tls: TlsConnection
    var backend_session: H2Session    # client-side H2 (Session adapter)
    var backend_request_handle: Optional[RequestHandle]
    # Map: backend_handle_id -> client_stream_id
    var handle_to_client_stream: List[UInt64]  # parallel arrays
    var handle_client_streams: List[UInt32]
    # Pending requests from client H2 events
    var pending_requests: List[_PendingReqPtr]
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
        var client_h2: H2Connection,
        var backend_tls: TlsConnection,
        var backend_session: H2Session,
    ):
        self.conn_id = conn_id
        self.client_handle = client_handle^
        self.backend_handle = backend_handle^
        self.backend_addr_stor = backend_addr_stor
        self.client_tls = client_tls^
        self.client_h2 = client_h2^
        self.client_h2_initiated = False
        self.backend_tls = backend_tls^
        self.backend_session = backend_session^
        self.backend_request_handle = Optional[RequestHandle]()
        self.handle_to_client_stream = List[UInt64]()
        self.handle_client_streams = List[UInt32]()
        self.pending_requests = List[_PendingReqPtr]()
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
        self.client_h2 = take.client_h2^
        self.client_h2_initiated = take.client_h2_initiated
        self.backend_tls = take.backend_tls^
        self.backend_session = take.backend_session^
        self.backend_request_handle = take.backend_request_handle^
        self.handle_to_client_stream = take.handle_to_client_stream^
        self.handle_client_streams = take.handle_client_streams^
        self.pending_requests = take.pending_requests^
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
        """Free heap-allocated pending requests."""
        for i in range(len(self.pending_requests)):
            var p = self.pending_requests[i].ptr()
            p.destroy_pointee()
            p.free()


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

        # Server-side H2Connection for the frontend (not initiated yet;
        # we wait until after TLS handshake completes).
        var client_h2 = H2Connection(
            client_side=False,
            config=h2_production_config(client_side=False),
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
            client_h2=client_h2^,
            backend_tls=backend_tls^,
            backend_session=backend_session^,
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

        # If we haven't initiated the server-side H2 connection yet, do so now.
        if not self.connections[idx][].client_h2_initiated:
            self.connections[idx][].client_h2.initiate_connection()
            self.connections[idx][].client_h2_initiated = True
            # Flush the server preface (SETTINGS frame) to the client
            var preface_bytes = self.connections[idx][].client_h2.data_to_send()
            if len(preface_bytes) > 0:
                self.connections[idx][].client_tls.send_data(Span(preface_bytes))
                var ct2 = self.connections[idx][].client_tls.drain_ciphertext()
                self._stage_client_send(idx, ct2^)
            self.connections[idx][].phase = _PHASE_CLIENT_H2_READY

        # Feed plaintext into the server-side H2 connection
        if len(plaintext) > 0:
            var pt_list = List[UInt8]()
            for i in range(len(plaintext)):
                pt_list.append(plaintext[i])
            var events = self.connections[idx][].client_h2.receive_data(pt_list)
            self._process_client_h2_events(idx, events)

            # Flush any H2 frames generated (e.g. SETTINGS ACK, WINDOW_UPDATE)
            var h2_out = self.connections[idx][].client_h2.data_to_send()
            if len(h2_out) > 0:
                self.connections[idx][].client_tls.send_data(Span(h2_out))
                var ct3 = self.connections[idx][].client_tls.drain_ciphertext()
                self._stage_client_send(idx, ct3^)

        # If we have pending requests ready to forward, either start the
        # backend connection or submit them immediately if already connected.
        if self._has_ready_requests(idx):
            if self.connections[idx][].phase == _PHASE_CLIENT_H2_READY:
                self.connections[idx][].phase = _PHASE_BACKEND_CONNECTING
                self._queue_backend_connect(idx)
            elif self.connections[idx][].phase == _PHASE_PROXYING:
                self._submit_pending_requests(idx)
                self._check_backend_responses(idx)

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

            # Transition to PROXYING and submit pending requests
            self.connections[idx][].phase = _PHASE_PROXYING
            self._submit_pending_requests(idx)
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

        # Check for completed backend responses
        self._check_backend_responses(idx)
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

    # --- H2 event processing (client side) ------------------------------------

    def _process_client_h2_events(
        mut self, idx: Int, mut events: List[H2Event]
    ) raises:
        """Process H2 events from the client connection and capture requests."""
        for i in range(len(events)):
            var evt = H2Event(other=events[i])
            if evt.kind == H2_EVT_REQUEST_RECEIVED:
                self._on_client_request(idx, evt)
            elif evt.kind == H2_EVT_DATA_RECEIVED:
                self._on_client_data(idx, evt)
            elif evt.kind == H2_EVT_STREAM_ENDED:
                self._on_client_stream_ended(idx, evt)
            elif evt.kind == H2_EVT_GOAWAY_RECEIVED:
                pass  # Client is shutting down
            elif evt.kind == H2_EVT_CONNECTION_TERMINATED:
                self._close_connection(idx)
                return

    def _on_client_request(
        mut self, idx: Int, evt: H2Event
    ) raises:
        """Capture an incoming H2 request from the client."""
        var req = request_from_h2_headers(evt.stream_id, evt.headers)
        var pending = _PendingRequest(
            client_stream_id=evt.stream_id,
            method=String(req.method),
            target=req.target,
            headers=Headers(other=req.headers),
        )
        if evt.stream_ended:
            pending.stream_ended = True
        var ptr = _heap_alloc[_PendingRequest](1).as_any_origin()
        ptr.init_pointee_move(pending^)
        self.connections[idx][].pending_requests.append(
            _PendingReqPtr(UInt64(Int(ptr)))
        )

    def _on_client_data(
        mut self, idx: Int, evt: H2Event
    ) raises:
        """Append body data to the pending request for this stream."""
        var sid = evt.stream_id
        for i in range(len(self.connections[idx][].pending_requests)):
            var pr = self.connections[idx][].pending_requests[i].ptr()
            if pr[].client_stream_id == sid:
                for j in range(len(evt.data)):
                    pr[].body.append(evt.data[j])
                if evt.stream_ended:
                    pr[].stream_ended = True
                break
        # Acknowledge received data for flow control
        if evt.flow_controlled_length > 0:
            self.connections[idx][].client_h2.acknowledge_received_data(
                evt.flow_controlled_length, evt.stream_id
            )

    def _on_client_stream_ended(
        mut self, idx: Int, evt: H2Event
    ) raises:
        """Mark the pending request for this stream as ready."""
        var sid = evt.stream_id
        for i in range(len(self.connections[idx][].pending_requests)):
            var pr = self.connections[idx][].pending_requests[i].ptr()
            if pr[].client_stream_id == sid:
                pr[].stream_ended = True
                break

    # --- Request forwarding ---------------------------------------------------

    def _has_ready_requests(self, idx: Int) -> Bool:
        """Check if there are requests ready to forward."""
        for i in range(len(self.connections[idx][].pending_requests)):
            var pr = self.connections[idx][].pending_requests[i].ptr()
            if pr[].stream_ended:
                return True
        return False

    def _submit_pending_requests(mut self, idx: Int) raises:
        """Submit all ready pending requests to the backend H2Session."""
        var remaining = List[_PendingReqPtr]()
        var n = len(self.connections[idx][].pending_requests)
        for i in range(n):
            var wrap = _PendingReqPtr(
                other=self.connections[idx][].pending_requests[i]
            )
            var pr = wrap.ptr()
            if not pr[].stream_ended:
                remaining.append(wrap.copy())
                continue

            # Build a Request and submit to the backend session
            var client_stream_id = pr[].client_stream_id
            var body_data = List[UInt8]()
            for j in range(len(pr[].body)):
                body_data.append(pr[].body[j])
            var req_body: RequestBody
            if len(body_data) > 0:
                req_body = RequestBody.buffered(body_data^)
            else:
                req_body = RequestBody.empty()

            var request = Request(
                method=Method.custom(pr[].method),
                target=pr[].target,
                version=Version.http_2(),
                headers=Headers(other=pr[].headers),
                body=req_body^,
            )
            rewrite_request_headers(request, "127.0.0.1", _BACKEND_HOST)
            var handle = self.connections[idx][].backend_session.submit(request^)
            var handle_id = handle.id()

            # Track the mapping from backend handle to client stream
            self.connections[idx][].handle_to_client_stream.append(handle_id)
            self.connections[idx][].handle_client_streams.append(client_stream_id)
            self.connections[idx][].backend_request_handle = Optional[RequestHandle](handle^)

            # Free the pending request
            pr.destroy_pointee()
            pr.free()

        self.connections[idx][].pending_requests = remaining^

        # Drain outbound H2 frames from the session and send via TLS
        var out_bytes = self.connections[idx][].backend_session.drain()
        if len(out_bytes) > 0:
            self.connections[idx][].backend_tls.send_data(Span(out_bytes))
            var ct = self.connections[idx][].backend_tls.drain_ciphertext()
            self._stage_backend_send(idx, ct^)

    # --- Backend response handling --------------------------------------------

    def _check_backend_responses(mut self, idx: Int) raises:
        """Check if backend responses are ready and forward to client."""
        if not self.connections[idx][].backend_request_handle:
            return

        # Move the handle out so we can drive run_one
        var handle_opt = Optional[RequestHandle]()
        swap(handle_opt, self.connections[idx][].backend_request_handle)
        var handle = handle_opt.take()
        self.connections[idx][].backend_session.run_one(handle)

        if not handle.is_complete():
            # Not ready yet, put the handle back
            self.connections[idx][].backend_request_handle = Optional[RequestHandle](handle^)
            return

        # Response is ready — find the client stream ID
        var handle_id = handle.id()
        var client_stream_id = UInt32(0)
        var found = False
        for i in range(len(self.connections[idx][].handle_to_client_stream)):
            if self.connections[idx][].handle_to_client_stream[i] == handle_id:
                client_stream_id = self.connections[idx][].handle_client_streams[i]
                found = True
                # Remove from tracking (swap-remove)
                var last = len(self.connections[idx][].handle_to_client_stream) - 1
                if i != last:
                    self.connections[idx][].handle_to_client_stream[i] = self.connections[idx][].handle_to_client_stream[last]
                    self.connections[idx][].handle_client_streams[i] = self.connections[idx][].handle_client_streams[last]
                _ = self.connections[idx][].handle_to_client_stream.pop()
                _ = self.connections[idx][].handle_client_streams.pop()
                break

        if not found:
            return

        # Extract response from the handle
        var response = handle^.take_response()

        # Build H2 response headers for client
        var resp_headers = List[Header]()
        resp_headers.append(Header(":status", String(response.status)))

        # Add response headers, stripping hop-by-hop and adding Via
        for i in range(len(response.headers)):
            var name = response.headers.name_at(i)
            var value = response.headers.value_at(i)
            if not _is_hop_by_hop(name):
                resp_headers.append(Header(name, value))
        resp_headers.append(Header("via", "2.0 mojo-proxy"))

        # Extract body data
        var body_data = List[UInt8]()
        for i in range(len(response.body)):
            var frame = response.body[i].copy()
            if frame.is_data():
                var data = frame.data().copy()
                for j in range(len(data)):
                    body_data.append(data[j])

        var has_body = len(body_data) > 0
        var end_stream = not has_body

        # Send response headers to client via H2
        self.connections[idx][].client_h2.send_headers(
            client_stream_id, resp_headers^, end_stream=end_stream
        )

        # Send body data if present
        if has_body:
            self.connections[idx][].client_h2.send_data(
                client_stream_id, body_data^, end_stream=True
            )

        # Flush H2 frames through TLS to the client
        var h2_out = self.connections[idx][].client_h2.data_to_send()
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
