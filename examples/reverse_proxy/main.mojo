# examples/reverse_proxy/main.mojo
#
# Unified ALPN-dispatched HTTPS reverse proxy. The frontend TLS listener
# advertises both `h2` and `http/1.1`; once the client TLS handshake
# completes, the negotiated ALPN selects which proxy variant
# (`proxy_h1` or `proxy_h2`) drives the rest of the connection. Both
# variants share the same accept / TLS / send-state plumbing. An H3/QUIC
# frontend (`proxy_h3`) rides the same ring and forwards each request to the
# H1 backend over its own TCP round-trip.
#
# Event model
#
#   One `IoUringDriver` drives everything. Every operation carries its own
#   `Completion`, whose pointer the kernel hands back as the SQE user_data,
#   so the driver routes each CQE directly to the code that submitted it —
#   there is no token, no central dispatch switch, and no retry queue for
#   operations the submission queue could not take (the driver flushes and
#   retries, raising only if the queue is still full).
#
#   A completion callback still cannot submit: it has no driver reference.
#   It queues a `PendingSubmit` and `_run_tick` issues the SQEs after the
#   tick, which is also what keeps the per-tick ordering stable.
#
#   Because a `Completion` pointer lives in the ring until its CQE arrives,
#   nothing that owns one is freed the moment it is closed. Connections and
#   H3-backend op blocks are marked, then reaped by `ProxyHandler.reap()` on
#   the first tick where they have no operation in flight.
#
# Build + run
#
#   $ ./scripts/gen_test_certs.sh        # one-time
#   $ cd examples/reverse_proxy
#   $ uv sync
#   $ LD_LIBRARY_PATH=../../lib uv run mojox build main.mojo -o mojo_reverse_proxy
#   $ python3 ../../scripts/test_backend.py &              # a backend MUST run
#   $ LD_LIBRARY_PATH=../../lib ./mojo_reverse_proxy --upstream 127.0.0.1:9443
#
# Config. CLI flags (override the env vars below):
#   --listen PORT          client-facing TLS port      (default 8443)
#   --upstream HOST:PORT    backend to proxy to         (default localhost:9443)
#                          accepts an optional scheme, e.g.
#                          --upstream https://127.0.0.1:9443
#   -h, --help             show usage and exit
#
# Env-var knobs (the smoke harness drives via these):
#   LISTEN_PORT          (default 8443)
#   H1_BACKEND_PORT      (default 9443)
#   H2_BACKEND_PORT      (default H1_BACKEND_PORT)
#   BACKEND_HOST         (default "localhost")
#
# If the upstream connect is refused, the proxy now returns 502 Bad Gateway
# (H1 and H2) instead of dropping the connection.

from std.collections.optional import Optional
from std.ffi import external_call
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc

from navette.http.session import RequestHandle
from navette.tls import (
    TlsBackend,
    TlsClientConfig,
    TlsServerConfig,
    TlsConnection,
    EarlyDataPolicy,
)
from navette.tls.config import QuicServerConfig

from boucle import WatchLoop
from boucle.drivers.io_uring import IoUringDriver
from boucle.proactor.completion import Completion
from boucle.handle import OwnedHandle
from boucle.net.socket import Socket
from boucle.net.addr import SocketAddrV4, SocketAddrStorV4
from boucle.net.options import Backlog

from navette.runtime.socket_helpers import tcp_v4_nonblocking, udp_listener
from navette.quic.trans_param import default_transport_params
from navette.util.null_ptr import null_ptr
from navette.h3.h3_udp_server import H3UdpServer

from proxy_common import (
    ConnSendState,
    LISTENER_CONN_ID,
    OP_ACCEPT,
    OP_BACKEND_CONNECT,
    OP_BACKEND_RECV,
    OP_BACKEND_SEND,
    OP_CLIENT_RECV,
    OP_CLIENT_SEND,
    PHASE_BACKEND_CONNECTING,
    PHASE_BACKEND_TLS_HANDSHAKE,
    PHASE_CLIENT_TLS_HANDSHAKE,
    PHASE_DONE,
    PHASE_PROXYING,
    PendingSubmit,
    SUBMIT_ACCEPT,
    SUBMIT_CONNECT,
    SUBMIT_RECV,
    SUBMIT_SEND,
    _CERT_DIR,
    _RECV_BUF_SIZE,
    _read_file,
    queue_client_recv,
    rewrite_request_headers,
    stage_backend_send,
    stage_client_send,
)
from proxy_h1 import (
    H1ProxyState,
    H1_SUB_READING_REQUEST,
    H1_SUB_SENDING_REQUEST,
    h1_handle_backend_connect,
    h1_handle_backend_recv,
    h1_handle_backend_send,
    h1_handle_client_recv,
    h1_handle_client_send,
    h1_proxy_state_new,
)
from proxy_h2 import (
    H2ProxyState,
    h2_handle_backend_connect,
    h2_handle_backend_recv,
    h2_handle_backend_send,
    h2_handle_client_recv,
    h2_handle_client_send,
    h2_proxy_state_new,
)
from proxy_h3 import (
    ForwardingHandler,
    H3BackendRegistry,
    h3_handle_backend_connect,
    h3_handle_backend_recv,
    h3_handle_backend_send,
    make_forwarding_handler,
)


# ---------------------------------------------------------------------------
# Env-var helpers (matches examples/hello_h1_server pattern)
# ---------------------------------------------------------------------------


def _getenv_str(name: String, default: String) -> String:
    """Read a string environment variable; fall back to default if unset."""
    var nbuf = _heap_alloc[UInt8](name.byte_length() + 1)
    var name_bytes = name.as_bytes()
    for i in range(len(name_bytes)):
        nbuf[unsafe_offset=i] = name_bytes[i]
    nbuf[unsafe_offset= len(name_bytes)] = 0
    var ptr_int = external_call["getenv", Int](nbuf)
    nbuf.unsafe_free()
    if ptr_int == 0:
        return default
    var ptr = Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=ptr_int)
    var s = String()
    var i = 0
    while ptr[unsafe_offset=i] != 0:
        s += chr(Int(ptr[unsafe_offset=i]))
        i += 1
    return s^


def _getenv_int(name: String, default: Int) -> Int:
    """Read an integer environment variable; fall back to default if
    unset / invalid."""
    var s = _getenv_str(name, String(""))
    if not s:
        return default
    try:
        return atol(s)
    except:
        return default


# ---------------------------------------------------------------------------
# ProxyVariant — tagged union over per-version state
# ---------------------------------------------------------------------------
#
# Mojo 0.26 has no native enum-with-payload, so we use the project's
# hand-rolled `Int tag + Optional[T] per variant` pattern (see
# `SessionSlot`, `RequestBody`, `H2Event` in navette for precedents).


comptime _VARIANT_HANDSHAKING: UInt8 = 0
comptime _VARIANT_H1: UInt8 = 1
comptime _VARIANT_H2: UInt8 = 2


struct ProxyVariant(Movable):
    """Tagged union of {handshaking, H1, H2} per-connection state.

    Before the client TLS handshake completes we don't know which variant
    a connection will adopt — only after we read the negotiated ALPN do
    we materialize either an `H1ProxyState` or an `H2ProxyState`. Until
    then the variant sits in the `_VARIANT_HANDSHAKING` slot with both
    inner Optionals empty.
    """

    var tag: UInt8
    var h1_state: Optional[H1ProxyState]
    var h2_state: Optional[H2ProxyState]

    def __init__(
        out self,
        tag: UInt8,
        var h1_state: Optional[H1ProxyState],
        var h2_state: Optional[H2ProxyState],
    ):
        self.tag = tag
        self.h1_state = h1_state^
        self.h2_state = h2_state^

    def __init__(out self, *, deinit move: Self):
        self.tag = move.tag
        self.h1_state = move.h1_state^
        self.h2_state = move.h2_state^

    @staticmethod
    def handshaking() -> Self:
        return Self(
            tag=_VARIANT_HANDSHAKING,
            h1_state=Optional[H1ProxyState](),
            h2_state=Optional[H2ProxyState](),
        )

    @staticmethod
    def h1(var s: H1ProxyState) -> Self:
        return Self(
            tag=_VARIANT_H1,
            h1_state=Optional[H1ProxyState](s^),
            h2_state=Optional[H2ProxyState](),
        )

    @staticmethod
    def h2(var s: H2ProxyState) -> Self:
        return Self(
            tag=_VARIANT_H2,
            h1_state=Optional[H1ProxyState](),
            h2_state=Optional[H2ProxyState](s^),
        )

    @always_inline
    def is_handshaking(self) -> Bool:
        return self.tag == _VARIANT_HANDSHAKING

    @always_inline
    def is_h1(self) -> Bool:
        return self.tag == _VARIANT_H1

    @always_inline
    def is_h2(self) -> Bool:
        return self.tag == _VARIANT_H2


# ---------------------------------------------------------------------------
# ProxyConnection — per-client proxied state
# ---------------------------------------------------------------------------


struct ProxyConnection(Movable):
    """Per-client proxy state.

    Owns both halves of the proxied connection: the client-side TLS
    connection + (post-ALPN) variant state, and the backend-side TCP
    handle + TLS connection. Stored heap-allocated and accessed via
    `Pointer` so that addresses inside (recv/send buffers, the backend
    addr storage, and the five owned `Completion`s) remain stable while
    io_uring ops are in flight.

    `variant` starts as `ProxyVariant.handshaking()`; the client TLS
    handshake completion handler reads the negotiated ALPN and replaces
    it with either an H1 or H2 state in-place.

    Each of the five operation kinds this connection can have in the ring
    (client recv/send, backend connect/recv/send) owns one `Completion`;
    the driver routes a CQE straight back here through the SQE user_data,
    so there is no token to decode and no central switch. `owner` points
    at the `ProxyHandler` that owns this connection, which is how a
    callback reaches the shared TLS configs and the submit queue.

    Teardown is two-phase, exactly as in `navette/h1/h1_tcp_server.mojo`:
    `closed` marks the connection for teardown and `ProxyHandler.reap()`
    frees the heap slot only once every in-flight operation has reported
    back. Freeing eagerly would hand a still-queued SQE a dangling
    `Completion` pointer.
    """

    var conn_id: UInt64
    var client_handle: OwnedHandle
    var backend_handle: OwnedHandle
    var backend_addr_stor: SocketAddrStorV4
    var client_tls: TlsConnection
    var backend_tls: TlsConnection
    var phase: UInt8
    var send_state: ConnSendState
    var variant: ProxyVariant
    var closed: Bool
    # True between the connect SQE and its CQE. The other four op kinds
    # already have their in-flight flags inside `send_state`.
    var connect_in_flight: Bool
    # True once both sockets have been shut down; keeps `_close_connection`
    # idempotent when several handlers ask to close the same connection.
    var shutdown_done: Bool
    # Type-erased pointer to the owning `ProxyHandler`.
    var owner: Pointer[NoneType, MutUntrackedOrigin]
    var client_recv_cmp: Completion
    var client_send_cmp: Completion
    var backend_connect_cmp: Completion
    var backend_recv_cmp: Completion
    var backend_send_cmp: Completion

    def __init__(
        out self,
        conn_id: UInt64,
        var client_handle: OwnedHandle,
        var backend_handle: OwnedHandle,
        backend_addr_stor: SocketAddrStorV4,
        var client_tls: TlsConnection,
        var backend_tls: TlsConnection,
    ):
        """Build a connection whose Completions carry their callbacks but
        no context yet — call `wire_context` once the record sits at its
        final heap address."""
        self.conn_id = conn_id
        self.client_handle = client_handle^
        self.backend_handle = backend_handle^
        self.backend_addr_stor = backend_addr_stor
        self.client_tls = client_tls^
        self.backend_tls = backend_tls^
        self.phase = PHASE_CLIENT_TLS_HANDSHAKE
        self.send_state = ConnSendState()
        self.variant = ProxyVariant.handshaking()
        self.closed = False
        self.connect_in_flight = False
        self.shutdown_done = False
        self.owner = null_ptr[NoneType, MutUntrackedOrigin]()
        self.client_recv_cmp = Completion(
            invoke=_on_client_recv,
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )
        self.client_send_cmp = Completion(
            invoke=_on_client_send,
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )
        self.backend_connect_cmp = Completion(
            invoke=_on_backend_connect,
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )
        self.backend_recv_cmp = Completion(
            invoke=_on_backend_recv,
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )
        self.backend_send_cmp = Completion(
            invoke=_on_backend_send,
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )

    def __init__(out self, *, deinit move: Self):
        """Move constructor."""
        self.conn_id = move.conn_id
        self.client_handle = move.client_handle^
        self.backend_handle = move.backend_handle^
        self.backend_addr_stor = move.backend_addr_stor
        self.client_tls = move.client_tls^
        self.backend_tls = move.backend_tls^
        self.phase = move.phase
        self.send_state = move.send_state^
        self.variant = move.variant^
        self.closed = move.closed
        self.connect_in_flight = move.connect_in_flight
        self.shutdown_done = move.shutdown_done
        self.owner = move.owner
        self.client_recv_cmp = move.client_recv_cmp^
        self.client_send_cmp = move.client_send_cmp^
        self.backend_connect_cmp = move.backend_connect_cmp^
        self.backend_recv_cmp = move.backend_recv_cmp^
        self.backend_send_cmp = move.backend_send_cmp^

    def wire_context(mut self, owner: Pointer[NoneType, MutUntrackedOrigin]):
        """Point every Completion at this record's final heap address and
        record the owning handler.

        Must run after the `ProxyConnection` has been written to its heap
        slot (pointer stability) and before any SQE referencing it.

        Args:
            owner: Type-erased pointer to the owning `ProxyHandler`.
        """
        var self_ctx = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self))
        )
        self.owner = owner
        self.client_recv_cmp.context = self_ctx
        self.client_send_cmp.context = self_ctx
        self.backend_connect_cmp.context = self_ctx
        self.backend_recv_cmp.context = self_ctx
        self.backend_send_cmp.context = self_ctx

    def cmp_ptr(mut self, op_kind: UInt8) -> Pointer[
        Completion, MutUntrackedOrigin
    ]:
        """Return the Completion this connection uses for `op_kind`.

        Taking the address inside the owning struct is the codegen-safe
        form; reaching a field through a chain of getters mis-lowers in
        Mojo 1.0.0b1.

        Args:
            op_kind: One of the `OP_*` constants from `proxy_common`.

        Returns:
            Pointer to the matching owned Completion. `OP_CLIENT_RECV` is
            the fallback for an unknown kind, which cannot occur — every
            call site passes an op kind this connection submits.
        """
        if op_kind == OP_CLIENT_SEND:
            return Pointer[Completion, MutUntrackedOrigin](
                unsafe_from_address=Int(Pointer(to=self.client_send_cmp))
            )
        if op_kind == OP_BACKEND_CONNECT:
            return Pointer[Completion, MutUntrackedOrigin](
                unsafe_from_address=Int(Pointer(to=self.backend_connect_cmp))
            )
        if op_kind == OP_BACKEND_RECV:
            return Pointer[Completion, MutUntrackedOrigin](
                unsafe_from_address=Int(Pointer(to=self.backend_recv_cmp))
            )
        if op_kind == OP_BACKEND_SEND:
            return Pointer[Completion, MutUntrackedOrigin](
                unsafe_from_address=Int(Pointer(to=self.backend_send_cmp))
            )
        return Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self.client_recv_cmp))
        )

    def clear_in_flight(mut self, op_kind: UInt8):
        """Mark the operation of kind `op_kind` as no longer in the ring.

        Called from the completion callback before any handler runs, so a
        connection that is already closed (and therefore skips its handler)
        still drains and becomes reapable.

        Args:
            op_kind: One of the `OP_*` constants from `proxy_common`.
        """
        if op_kind == OP_CLIENT_RECV:
            self.send_state.client_recv_in_flight = False
        elif op_kind == OP_CLIENT_SEND:
            self.send_state.client_send_in_flight = False
        elif op_kind == OP_BACKEND_CONNECT:
            self.connect_in_flight = False
        elif op_kind == OP_BACKEND_RECV:
            self.send_state.backend_recv_in_flight = False
        elif op_kind == OP_BACKEND_SEND:
            self.send_state.backend_send_in_flight = False

    def is_drained(self) -> Bool:
        """Return True once the connection is closed and the ring holds no
        further reference to it, i.e. the heap slot is safe to free."""
        return (
            self.closed
            and not self.connect_in_flight
            and not self.send_state.client_recv_in_flight
            and not self.send_state.client_send_in_flight
            and not self.send_state.backend_recv_in_flight
            and not self.send_state.backend_send_in_flight
        )


# ---------------------------------------------------------------------------
# Per-connection completion callbacks
# ---------------------------------------------------------------------------
#
# One free function per operation kind, because a `CompletionFn` takes only
# the context pointer: the op kind has to be baked into the callback rather
# than decoded from a token. Each recovers the `ProxyConnection` from the
# context, then the owning `ProxyHandler` from `conn.owner`, and hands both
# to the single dispatcher.


def _run_conn_completion(
    ctx: Pointer[NoneType, MutUntrackedOrigin],
    result: Int,
    op_kind: UInt8,
    label: String,
):
    """Shared body of the five per-connection completion callbacks.

    Args:
        ctx: Type-erased pointer to the owning `ProxyConnection`.
        result: Kernel result for the completed operation.
        op_kind: Which `OP_*` operation this completion belongs to.
        label: Op name used when reporting a handler error.
    """
    var conn = Pointer[ProxyConnection, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    conn[].clear_in_flight(op_kind)
    var handler = Pointer[ProxyHandler, MutUntrackedOrigin](
        unsafe_from_address=Int(conn[].owner)
    )
    try:
        handler[]._dispatch_conn(conn, op_kind, result)
    except e:
        print("proxy: " + label + " completion error:", e)


def _on_client_recv(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Client-side recv CQE: bytes read from the client socket."""
    _run_conn_completion(ctx, result, OP_CLIENT_RECV, String("client-recv"))


def _on_client_send(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Client-side send CQE: ciphertext flushed to the client socket."""
    _run_conn_completion(ctx, result, OP_CLIENT_SEND, String("client-send"))


def _on_backend_connect(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Backend connect CQE: upstream TCP connect settled (or was refused)."""
    _run_conn_completion(
        ctx, result, OP_BACKEND_CONNECT, String("backend-connect")
    )


def _on_backend_recv(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Backend recv CQE: bytes read from the upstream socket."""
    _run_conn_completion(ctx, result, OP_BACKEND_RECV, String("backend-recv"))


def _on_backend_send(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Backend send CQE: ciphertext flushed to the upstream socket."""
    _run_conn_completion(ctx, result, OP_BACKEND_SEND, String("backend-send"))


def _on_accept(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """Listener accept CQE: `result` is the new client fd, or a negative
    errno. The listener owns a single Completion because exactly one accept
    is ever in flight — each CQE re-arms the next one.

    Args:
        ctx: Type-erased pointer to the owning `ProxyHandler`.
        result: New client fd, or negative errno.
        flags: io_uring CQE flags (unused for accept).
    """
    var handler = Pointer[ProxyHandler, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    try:
        handler[]._handle_accept(result)
    except e:
        print("proxy: accept completion error:", e)


# ---------------------------------------------------------------------------
# H3BackendOps — Completions for one H3-backend TCP round-trip
# ---------------------------------------------------------------------------


struct H3BackendOps(Movable):
    """The three Completions driving one H3-request-to-H1-backend trip.

    Deliberately NOT stored inside `proxy_h3`'s `H3BackendConn`: the
    registry frees a backend conn the moment its response (or its 502) has
    been injected into the H3 stream, which can happen while another
    operation on that same conn is still queued in the ring. Under the old
    token model a late CQE for a freed conn was harmlessly ignored; a
    `Completion` embedded in the freed block would instead be dereferenced.
    Keeping the Completions on their own heap block preserves exactly the
    old tolerance — `ProxyHandler.reap()` frees the block once the registry
    entry is gone AND no operation is still in flight.
    """

    var owner: Pointer[NoneType, MutUntrackedOrigin]
    var backend_conn_id: UInt64
    var connect_in_flight: Bool
    var recv_in_flight: Bool
    var send_in_flight: Bool
    var connect_cmp: Completion
    var recv_cmp: Completion
    var send_cmp: Completion

    def __init__(out self, backend_conn_id: UInt64):
        """Build the op block for `backend_conn_id` with unwired contexts.

        Args:
            backend_conn_id: Synthetic id of the backend conn in the
                `H3BackendRegistry`.
        """
        self.owner = null_ptr[NoneType, MutUntrackedOrigin]()
        self.backend_conn_id = backend_conn_id
        self.connect_in_flight = False
        self.recv_in_flight = False
        self.send_in_flight = False
        self.connect_cmp = Completion(
            invoke=_on_h3_backend_connect,
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )
        self.recv_cmp = Completion(
            invoke=_on_h3_backend_recv,
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )
        self.send_cmp = Completion(
            invoke=_on_h3_backend_send,
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )

    def __init__(out self, *, deinit move: Self):
        """Move constructor."""
        self.owner = move.owner
        self.backend_conn_id = move.backend_conn_id
        self.connect_in_flight = move.connect_in_flight
        self.recv_in_flight = move.recv_in_flight
        self.send_in_flight = move.send_in_flight
        self.connect_cmp = move.connect_cmp^
        self.recv_cmp = move.recv_cmp^
        self.send_cmp = move.send_cmp^

    def wire_context(mut self, owner: Pointer[NoneType, MutUntrackedOrigin]):
        """Point the three Completions at this block's heap address.

        Args:
            owner: Type-erased pointer to the owning `ProxyHandler`.
        """
        var self_ctx = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self))
        )
        self.owner = owner
        self.connect_cmp.context = self_ctx
        self.recv_cmp.context = self_ctx
        self.send_cmp.context = self_ctx

    def cmp_ptr(mut self, op_kind: UInt8) -> Pointer[
        Completion, MutUntrackedOrigin
    ]:
        """Return the Completion used for `op_kind` on this backend trip.

        Args:
            op_kind: `OP_BACKEND_CONNECT`, `OP_BACKEND_RECV`, or
                `OP_BACKEND_SEND`.

        Returns:
            Pointer to the matching owned Completion; the connect
            Completion is the fallback for an unknown kind.
        """
        if op_kind == OP_BACKEND_RECV:
            return Pointer[Completion, MutUntrackedOrigin](
                unsafe_from_address=Int(Pointer(to=self.recv_cmp))
            )
        if op_kind == OP_BACKEND_SEND:
            return Pointer[Completion, MutUntrackedOrigin](
                unsafe_from_address=Int(Pointer(to=self.send_cmp))
            )
        return Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self.connect_cmp))
        )

    def set_in_flight(mut self, op_kind: UInt8, value: Bool):
        """Record whether the `op_kind` operation is currently in the ring.

        Args:
            op_kind: One of the three backend `OP_*` constants.
            value: True on submit, False when its CQE arrives.
        """
        if op_kind == OP_BACKEND_CONNECT:
            self.connect_in_flight = value
        elif op_kind == OP_BACKEND_RECV:
            self.recv_in_flight = value
        elif op_kind == OP_BACKEND_SEND:
            self.send_in_flight = value

    def is_idle(self) -> Bool:
        """Return True when none of the three operations is in the ring."""
        return (
            not self.connect_in_flight
            and not self.recv_in_flight
            and not self.send_in_flight
        )


def _run_h3_backend_completion(
    ctx: Pointer[NoneType, MutUntrackedOrigin],
    result: Int,
    op_kind: UInt8,
    label: String,
):
    """Shared body of the three H3-backend completion callbacks.

    Args:
        ctx: Type-erased pointer to the owning `H3BackendOps` block.
        result: Kernel result for the completed operation.
        op_kind: Which backend `OP_*` operation completed.
        label: Op name used when reporting a handler error.
    """
    var ops = Pointer[H3BackendOps, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx)
    )
    ops[].set_in_flight(op_kind, False)
    var handler = Pointer[ProxyHandler, MutUntrackedOrigin](
        unsafe_from_address=Int(ops[].owner)
    )
    try:
        handler[]._dispatch_h3_backend(
            ops[].backend_conn_id, op_kind, result
        )
    except e:
        print("proxy: h3 " + label + " completion error:", e)


def _on_h3_backend_connect(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """H3-backend connect CQE for one forwarded H3 request."""
    _run_h3_backend_completion(
        ctx, result, OP_BACKEND_CONNECT, String("backend-connect")
    )


def _on_h3_backend_recv(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """H3-backend recv CQE for one forwarded H3 request."""
    _run_h3_backend_completion(
        ctx, result, OP_BACKEND_RECV, String("backend-recv")
    )


def _on_h3_backend_send(
    ctx: Pointer[NoneType, MutUntrackedOrigin], result: Int, flags: UInt32
):
    """H3-backend send CQE for one forwarded H3 request."""
    _run_h3_backend_completion(
        ctx, result, OP_BACKEND_SEND, String("backend-send")
    )


# ---------------------------------------------------------------------------
# ProxyHandler — unified completion-handler dispatcher
# ---------------------------------------------------------------------------


struct ProxyHandler(Movable):
    """Single-threaded unified reverse-proxy state.

    Owns the listener fd, rustls lib + three configs (one server with
    dual-ALPN, two clients each pinned to one ALPN), the list of in-flight
    connections, and the queue of I/O ops to submit after each driver tick.

    The actual per-variant work lives in `proxy_h1` / `proxy_h2`
    free functions; this struct is just the dispatch + TLS-handshake
    completion driver.

    It is no longer a `CompletionHandler`: boucle routes each CQE straight
    to the `Completion` its SQE carried, so there is no single entry point
    receiving every completion and no token to decode. What is left of the
    old central switch is `_dispatch_conn`, which the five per-connection
    callbacks funnel into once they have recovered their connection.

    The handler must live at a stable heap address for the whole run — the
    Completions on every connection and on the embedded H3 server point
    back at it.
    """

    var listener_fd: Int32
    # Heap-allocated ProxyConnection pointers (see proxy_h1's notes on
    # stable addresses across `List` reallocations).
    var connections: List[Pointer[ProxyConnection, MutUntrackedOrigin]]
    var next_conn_id: UInt64
    var tls: TlsBackend
    var server_tls_config: TlsServerConfig
    var h1_client_tls_config: TlsClientConfig
    var h2_client_tls_config: TlsClientConfig
    var h1_backend_addr: SocketAddrV4
    var h2_backend_addr: SocketAddrV4
    var backend_host: String
    var pending_submits: List[PendingSubmit]
    # H3-backend TCP follow-up ops queued from a completion callback;
    # drained after the tick by `drain_h3_backend_submits` against the H3
    # backend-conn registry (these conn_ids are synthetic and do NOT live
    # in `self.connections`).
    var h3_backend_submits: List[PendingSubmit]
    # One heap-allocated Completion block per live H3-backend round-trip.
    # Kept out of `H3BackendRegistry` so it can outlive the backend conn —
    # see `H3BackendOps`.
    var h3_backend_ops: List[Pointer[H3BackendOps, MutUntrackedOrigin]]
    # H3-backend registry: per-request backend conns + the backend dial
    # target + the (addresses of the) long-lived TLS configs. Owned here so
    # there is no module-level global (Mojo 1.0.0b1 forbids those).
    var h3_backends: H3BackendRegistry
    # The listener's own Completion. Exactly one accept is in flight at a
    # time (each accept CQE re-arms the next), so one Completion suffices.
    var _accept_cmp: Completion
    # Embedded H3/QUIC frontend, driven off the same IoUringDriver through
    # its own Completions. Declared LAST and heap-allocated together with
    # this struct before any QUIC connection exists, so the pointer the H3
    # server's per-conn handlers take to `self.profile` stays stable.
    var _h3: H3UdpServer[ForwardingHandler]

    def __init__(
        out self,
        listener_fd: Int32,
        var tls: TlsBackend,
        var server_tls_config: TlsServerConfig,
        var h1_client_tls_config: TlsClientConfig,
        var h2_client_tls_config: TlsClientConfig,
        h1_backend_addr: SocketAddrV4,
        h2_backend_addr: SocketAddrV4,
        backend_host: String,
        var h3_backends: H3BackendRegistry,
        var h3: H3UdpServer[ForwardingHandler],
    ):
        """Assemble the proxy state. The accept Completion carries its
        callback but no context — call `wire_context` once this struct is
        at its final heap address."""
        self.listener_fd = listener_fd
        self.connections = List[
            Pointer[ProxyConnection, MutUntrackedOrigin]
        ]()
        self.next_conn_id = 1
        self.tls = tls^
        self.server_tls_config = server_tls_config^
        self.h1_client_tls_config = h1_client_tls_config^
        self.h2_client_tls_config = h2_client_tls_config^
        self.h1_backend_addr = h1_backend_addr
        self.h2_backend_addr = h2_backend_addr
        self.backend_host = backend_host
        self.pending_submits = List[PendingSubmit]()
        self.h3_backend_submits = List[PendingSubmit]()
        self.h3_backend_ops = List[
            Pointer[H3BackendOps, MutUntrackedOrigin]
        ]()
        self.h3_backends = h3_backends^
        self._accept_cmp = Completion(
            invoke=_on_accept,
            context=null_ptr[NoneType, MutUntrackedOrigin](),
        )
        self._h3 = h3^

    def __init__(out self, *, deinit move: Self):
        """Move constructor."""
        self.listener_fd = move.listener_fd
        self.connections = move.connections^
        self.next_conn_id = move.next_conn_id
        self.tls = move.tls^
        self.server_tls_config = move.server_tls_config^
        self.h1_client_tls_config = move.h1_client_tls_config^
        self.h2_client_tls_config = move.h2_client_tls_config^
        self.h1_backend_addr = move.h1_backend_addr
        self.h2_backend_addr = move.h2_backend_addr
        self.backend_host = move.backend_host^
        self.pending_submits = move.pending_submits^
        self.h3_backend_submits = move.h3_backend_submits^
        self.h3_backend_ops = move.h3_backend_ops^
        self.h3_backends = move.h3_backends^
        self._accept_cmp = move._accept_cmp^
        self._h3 = move._h3^

    # --- Lifecycle ------------------------------------------------------

    def wire_context(mut self):
        """Point the accept Completion (and the embedded H3 server's own
        Completions) at their final heap addresses.

        Must run after this struct has been written to its heap slot and
        before `start`, which is the first thing to submit an SQE.
        """
        self._accept_cmp.context = Pointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self))
        )
        self._h3.wire_context()

    def start(
        mut self, mut driver: IoUringDriver, mut loop: WatchLoop
    ) raises:
        """Submit the proxy's initial operations: the first TCP accept and
        the embedded H3 server's bootstrap (buf-ring registration, multishot
        recvmsg, periodic timeout).

        Args:
            driver: The io_uring driver every operation is submitted on.
            loop: The WatchLoop for recv/send/timer operations.
        """
        var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=self._accept_cmp))
        )
        driver.accept(self.listener_fd, cmp_ptr)
        self._h3.start(loop)

    def flush_h3(mut self, mut driver: IoUringDriver) raises:
        """Run the embedded H3 server's per-tick batch flush.

        `H3UdpServer.flush` demuxes the datagrams buffered by the
        recvmsg callback, runs the `ForwardingHandler` callbacks,
        submits egress via WatchLoop.send_msg, recycles buf-ring
        buffers, and re-arms both the multishot recvmsg and the
        periodic timeout.

        Args:
            driver: The io_uring driver (kept for lifecycle compat).
        """
        self._h3.flush()

    # --- H3 backend config publication ----------------------------------

    def publish_h3_backend_config_addrs(mut self):
        """Publish the stable addresses of `tls` + `h1_client_tls_config` to
        the H3 backend registry so `open_backend` can build backend TLS
        connections. Taken from `self` (a clean field lvalue) rather than
        through a chain of getters — the address-of of a field reached across
        an accessor mis-lowers in Mojo 1.0.0b1; taking it from inside the
        owning struct is the codegen-safe form. Call once, after the handler
        has been written to its heap slot (so the addresses point at the
        final, stable copies)."""
        self.h3_backends.tls_shared_addr = UInt64(
            Int(Pointer(to=self.tls))
        )
        self.h3_backends.h1_client_config_addr = UInt64(
            Int(Pointer(to=self.h1_client_tls_config))
        )

    # --- Connection lookup ----------------------------------------------

    def _find_index(self, conn_id: UInt64) -> Int:
        """Return the index of the connection with `conn_id`, or -1."""
        for i in range(len(self.connections)):
            if self.connections[i][].conn_id == conn_id:
                return i
        return -1

    # --- Completion dispatch --------------------------------------------

    def _dispatch_conn(
        mut self,
        ptr: Pointer[ProxyConnection, MutUntrackedOrigin],
        op_kind: UInt8,
        result: Int,
    ) raises:
        """Run one TCP-proxy completion against its connection.

        Reached from the five per-connection callbacks, which have already
        recovered the connection from the Completion context and cleared the
        matching in-flight flag. That replaces the token-era `_find_index`
        lookup: the driver hands the connection back directly.

        A completion for a connection already marked closed is a no-op — it
        is the late CQE of an operation that was still queued when the
        connection was torn down. The connection is left in `connections`
        for `reap()` to free once every such CQE has landed.

        Args:
            ptr: The connection this completion belongs to.
            op_kind: Which `OP_*` operation completed.
            result: Kernel result for the operation.
        """
        if ptr[].closed:
            return

        # While the variant is still "handshaking" we're driving the
        # client-side TLS handshake; once the handshake settles we
        # construct the matching variant and from then on everything
        # routes through the proxy_h1 / proxy_h2 free functions.
        if ptr[].variant.is_handshaking():
            self._drive_client_tls_handshake(ptr, op_kind, result)
            if not ptr[].closed:
                self._maybe_finalize_handshake(ptr)
            if ptr[].closed:
                self._close_connection(ptr)
            return

        if ptr[].variant.is_h1():
            self._dispatch_h1(ptr, op_kind, result)
        elif ptr[].variant.is_h2():
            self._dispatch_h2(ptr, op_kind, result)

        if ptr[].closed:
            self._close_connection(ptr)

    # --- H3 backend dispatch --------------------------------------------

    def _dispatch_h3_backend(
        mut self, backend_conn_id: UInt64, op_kind: UInt8, result: Int
    ) raises:
        """Route an H3-backend TCP completion to its handler and queue the
        follow-up ops into `h3_backend_submits`.

        The handlers take a `mut self._h3` (so a complete response or a 502
        injects straight into the owning H3 stream) and the synthetic
        backend conn id; they return the recv/send ops to issue next. Buffer
        pointers are resolved after the tick in `drain_h3_backend_submits`
        from the backend-conn registry, which returns a null pointer for a
        conn that has already been freed — the handlers are therefore safe
        to call for a late completion.

        Args:
            backend_conn_id: Synthetic id of the backend conn, read off the
                `H3BackendOps` block the completion belonged to.
            op_kind: Which backend `OP_*` operation completed.
            result: Kernel result for the operation.
        """
        if op_kind == OP_BACKEND_CONNECT:
            var subs = h3_handle_backend_connect(
                self._h3, self.h3_backends, backend_conn_id, result
            )
            self.h3_backend_submits.extend(subs^)
        elif op_kind == OP_BACKEND_RECV:
            var subs = h3_handle_backend_recv(
                self._h3, self.h3_backends, backend_conn_id, result
            )
            self.h3_backend_submits.extend(subs^)
        elif op_kind == OP_BACKEND_SEND:
            var subs = h3_handle_backend_send(
                self._h3, self.h3_backends, backend_conn_id, result
            )
            self.h3_backend_submits.extend(subs^)

    # --- Accept handling ------------------------------------------------

    def _handle_accept(mut self, result: Int) raises:
        """Admit one accepted client: build its TLS halves, heap-allocate the
        `ProxyConnection`, wire its Completions, queue the first client recv,
        and re-arm the listener.

        Args:
            result: The accept CQE result — the new client fd, or a negative
                errno (in which case only the re-arm happens).
        """
        if result < 0:
            print("proxy: accept failed:", result)
            self._queue_accept()
            return

        var client_fd = Int32(result)
        var conn_id = self.next_conn_id
        self.next_conn_id += 1

        # Build the client-side TLS connection from the dual-ALPN
        # server config; the backend TLS half is deferred until the
        # ALPN is known.
        var client_tls = TlsConnection.new_server(
            self.tls.shared(), self.server_tls_config
        )

        # Create the backend TCP socket up front so we have an fd to
        # connect once we know which backend to dial.
        var backend_handle = tcp_v4_nonblocking()

        # The actual backend addr is decided post-ALPN; seed with H1.
        var backend_addr_stor = self.h1_backend_addr.addr_stor()

        # A placeholder backend TLS connection. Replaced post-ALPN.
        var backend_tls = TlsConnection.new_client(
            self.tls.shared(), self.h1_client_tls_config, self.backend_host
        )

        var client_handle = OwnedHandle(raw=client_fd)

        var conn = ProxyConnection(
            conn_id=conn_id,
            client_handle=client_handle^,
            backend_handle=backend_handle^,
            backend_addr_stor=backend_addr_stor,
            client_tls=client_tls^,
            backend_tls=backend_tls^,
        )

        # Heap-allocate so the address is stable across any `connections`
        # List reallocations (io_uring ops read/write into buffers held
        # inside the pointee AND the pointee owns the five Completions the
        # ring dereferences, so it must not move).
        var conn_ptr = _heap_alloc[ProxyConnection](1)
        conn_ptr.unsafe_write(conn^)
        conn_ptr[].wire_context(
            Pointer[NoneType, MutUntrackedOrigin](
                unsafe_from_address=Int(Pointer(to=self))
            )
        )
        self.connections.append(conn_ptr)

        # Kick off the TLS handshake by reading the first client bytes.
        queue_client_recv(
            conn_ptr[].send_state,
            self.pending_submits,
            conn_ptr[].client_handle.raw(),
            conn_ptr[].conn_id,
        )

        # Re-arm accept for the next client.
        self._queue_accept()

    def _queue_accept(mut self):
        """Queue the listener re-arm. Like every other submission it goes
        through `pending_submits` and is issued after the tick, never from
        inside a completion callback."""
        self.pending_submits.append(
            PendingSubmit(
                kind=SUBMIT_ACCEPT,
                fd=self.listener_fd,
                conn_id=LISTENER_CONN_ID,
                op_kind=OP_ACCEPT,
            )
        )

    # --- Pre-ALPN TLS-handshake driver ----------------------------------

    def _drive_client_tls_handshake(
        mut self,
        ptr: Pointer[ProxyConnection, MutUntrackedOrigin],
        op_kind: UInt8,
        result: Int,
    ) raises:
        """Drive the client-side TLS handshake to completion.

        During the handshake phase, only CLIENT_RECV and CLIENT_SEND
        ops are valid. Each RECV feeds bytes into rustls; each SEND
        confirms a ciphertext flush so we can chain pending bytes.

        Args:
            ptr: The connection whose handshake is being driven.
            op_kind: Which `OP_*` operation completed.
            result: Kernel result for the operation.
        """
        if op_kind == OP_CLIENT_RECV:
            if result <= 0:
                ptr[].closed = True
                return
            var n = Int(result)
            var chunk = List[UInt8](capacity=n)
            for i in range(n):
                chunk.append(ptr[].send_state.client_recv_buf[i])
            ptr[].client_tls.receive_data(Span(chunk))

            if ptr[].client_tls.wants_write():
                var ct = ptr[].client_tls.drain_ciphertext()
                stage_client_send(
                    ptr[].send_state,
                    self.pending_submits,
                    ptr[].client_handle.raw(),
                    ptr[].conn_id,
                    ct^,
                )

            if ptr[].client_tls.is_handshaking():
                # Need more handshake bytes.
                queue_client_recv(
                    ptr[].send_state,
                    self.pending_submits,
                    ptr[].client_handle.raw(),
                    ptr[].conn_id,
                )
        elif op_kind == OP_CLIENT_SEND:
            if result < 0:
                ptr[].closed = True
                return
            ptr[].send_state.client_send_buf = List[UInt8]()
            if len(ptr[].send_state.client_send_pending) > 0:
                var n_pending = len(ptr[].send_state.client_send_pending)
                var pending = List[UInt8](capacity=n_pending)
                for i in range(n_pending):
                    pending.append(ptr[].send_state.client_send_pending[i])
                ptr[].send_state.client_send_pending = List[UInt8]()
                ptr[].send_state.client_send_buf = pending^
                # Re-queue another client send.
                if not ptr[].send_state.client_send_in_flight:
                    ptr[].send_state.client_send_in_flight = True
                    self.pending_submits.append(
                        PendingSubmit(
                            kind=SUBMIT_SEND,
                            fd=ptr[].client_handle.raw(),
                            conn_id=ptr[].conn_id,
                            op_kind=OP_CLIENT_SEND,
                        )
                    )
                return
            # If still handshaking, keep reading.
            if ptr[].client_tls.is_handshaking():
                queue_client_recv(
                    ptr[].send_state,
                    self.pending_submits,
                    ptr[].client_handle.raw(),
                    ptr[].conn_id,
                )

    def _maybe_finalize_handshake(
        mut self, ptr: Pointer[ProxyConnection, MutUntrackedOrigin]
    ) raises:
        """If the client TLS handshake has completed, read the negotiated
        ALPN, materialize the matching variant, rebuild the backend TLS
        connection against the ALPN-pinned client config, and kick off
        the backend connect.

        Args:
            ptr: The connection whose handshake may have settled.
        """
        if ptr[].client_tls.is_handshaking():
            return

        # Handshake done — pick a variant.
        var alpn_opt = ptr[].client_tls.alpn()
        var is_h2 = False
        if alpn_opt:
            if alpn_opt.value() == String("h2"):
                is_h2 = True

        if is_h2:
            var h2 = h2_proxy_state_new()
            ptr[].variant = ProxyVariant.h2(h2^)
            ptr[].backend_addr_stor = self.h2_backend_addr.addr_stor()
            var backend_tls = TlsConnection.new_client(
                self.tls.shared(),
                self.h2_client_tls_config,
                self.backend_host,
            )
            ptr[].backend_tls = backend_tls^
        else:
            var h1 = h1_proxy_state_new()
            ptr[].variant = ProxyVariant.h1(h1^)
            ptr[].backend_addr_stor = self.h1_backend_addr.addr_stor()
            var backend_tls = TlsConnection.new_client(
                self.tls.shared(),
                self.h1_client_tls_config,
                self.backend_host,
            )
            ptr[].backend_tls = backend_tls^

        # Drain any plaintext that arrived in the handshake-final TLS
        # record; curl typically piggybacks the application request here.
        var plaintext = ptr[].client_tls.drain_plaintext()

        if ptr[].variant.is_h2():
            # H2: feed any piggybacked client preface, then drain the
            # server preface. Connect to the backend eagerly — the H2
            # path multiplexes streams over the same connection and the
            # backend should be ready as soon as the first HEADERS frame
            # is forwarded.
            if len(plaintext) > 0:
                ptr[].variant.h2_state.value().client_h2.feed(
                    Span(plaintext)
                )
            var h2_out = ptr[].variant.h2_state.value().client_h2.drain()
            if len(h2_out) > 0:
                ptr[].client_tls.send_data(Span(h2_out))
                var ct = ptr[].client_tls.drain_ciphertext()
                stage_client_send(
                    ptr[].send_state,
                    self.pending_submits,
                    ptr[].client_handle.raw(),
                    ptr[].conn_id,
                    ct^,
                )
            ptr[].phase = PHASE_BACKEND_CONNECTING
            self.pending_submits.append(
                PendingSubmit(
                    kind=SUBMIT_CONNECT,
                    fd=ptr[].backend_handle.raw(),
                    conn_id=ptr[].conn_id,
                    op_kind=OP_BACKEND_CONNECT,
                )
            )
            queue_client_recv(
                ptr[].send_state,
                self.pending_submits,
                ptr[].client_handle.raw(),
                ptr[].conn_id,
            )
        elif ptr[].variant.is_h1():
            # H1: feed plaintext into client_http and try to extract a
            # full request. Only queue the backend connect once we have
            # something to forward (matches the original H1 proxy's
            # request-then-connect flow).
            if len(plaintext) > 0:
                ptr[].variant.h1_state.value().client_http.receive_data(
                    Span(plaintext)
                )
            var req_opt = (
                ptr[].variant.h1_state.value().client_http.next_request()
            )
            if req_opt:
                var request = req_opt.take()
                rewrite_request_headers(
                    request,
                    String("127.0.0.1"),
                    self.backend_host,
                    String("1.1 mojo-proxy"),
                )
                var handle = ptr[].variant.h1_state.value().backend_session.submit(
                    request^
                )
                ptr[].variant.h1_state.value().backend_request_handle = (
                    Optional[RequestHandle](handle^)
                )
                ptr[].phase = PHASE_BACKEND_CONNECTING
                self.pending_submits.append(
                    PendingSubmit(
                        kind=SUBMIT_CONNECT,
                        fd=ptr[].backend_handle.raw(),
                        conn_id=ptr[].conn_id,
                        op_kind=OP_BACKEND_CONNECT,
                    )
                )
            else:
                # Request not complete in the handshake-final record;
                # wait for more bytes from the client.
                ptr[].phase = PHASE_PROXYING
                ptr[].variant.h1_state.value().sub_phase = (
                    H1_SUB_READING_REQUEST
                )
                queue_client_recv(
                    ptr[].send_state,
                    self.pending_submits,
                    ptr[].client_handle.raw(),
                    ptr[].conn_id,
                )

    # --- Variant dispatch ----------------------------------------------

    def _dispatch_h1(
        mut self,
        ptr: Pointer[ProxyConnection, MutUntrackedOrigin],
        op_kind: UInt8,
        result: Int,
    ) raises:
        """Run one completion through the `proxy_h1` handlers and queue the
        follow-up ops they return.

        Args:
            ptr: The H1 connection this completion belongs to.
            op_kind: Which `OP_*` operation completed.
            result: Kernel result for the operation.
        """
        var client_fd = ptr[].client_handle.raw()
        var backend_fd = ptr[].backend_handle.raw()
        var conn_id = ptr[].conn_id

        if op_kind == OP_CLIENT_RECV:
            var subs = h1_handle_client_recv(
                ptr[].variant.h1_state.value(),
                ptr[].send_state,
                ptr[].client_tls,
                ptr[].phase,
                ptr[].closed,
                self.backend_host,
                client_fd,
                backend_fd,
                conn_id,
                result,
            )
            self.pending_submits.extend(subs^)
        elif op_kind == OP_CLIENT_SEND:
            var subs = h1_handle_client_send(
                ptr[].variant.h1_state.value(),
                ptr[].send_state,
                ptr[].client_tls,
                ptr[].phase,
                ptr[].closed,
                client_fd,
                conn_id,
                result,
            )
            self.pending_submits.extend(subs^)
        elif op_kind == OP_BACKEND_CONNECT:
            var subs = h1_handle_backend_connect(
                ptr[].variant.h1_state.value(),
                ptr[].send_state,
                ptr[].client_tls,
                ptr[].backend_tls,
                ptr[].phase,
                ptr[].closed,
                client_fd,
                backend_fd,
                conn_id,
                result,
            )
            self.pending_submits.extend(subs^)
        elif op_kind == OP_BACKEND_RECV:
            var subs = h1_handle_backend_recv(
                ptr[].variant.h1_state.value(),
                ptr[].send_state,
                ptr[].client_tls,
                ptr[].backend_tls,
                ptr[].phase,
                ptr[].closed,
                client_fd,
                backend_fd,
                conn_id,
                result,
            )
            self.pending_submits.extend(subs^)
        elif op_kind == OP_BACKEND_SEND:
            var subs = h1_handle_backend_send(
                ptr[].variant.h1_state.value(),
                ptr[].send_state,
                ptr[].client_tls,
                ptr[].phase,
                ptr[].closed,
                client_fd,
                backend_fd,
                conn_id,
                result,
            )
            self.pending_submits.extend(subs^)

    def _dispatch_h2(
        mut self,
        ptr: Pointer[ProxyConnection, MutUntrackedOrigin],
        op_kind: UInt8,
        result: Int,
    ) raises:
        """Run one completion through the `proxy_h2` handlers and queue the
        follow-up ops they return.

        `proxy_h2`'s handlers still take the kernel result as `Int32` (the
        `proxy_h1` / `proxy_h3` sides have already moved to `Int`); the
        narrowing is exact — the value originates from io_uring's `cqe.res`,
        which is a 32-bit signed field.

        Args:
            ptr: The H2 connection this completion belongs to.
            op_kind: Which `OP_*` operation completed.
            result: Kernel result for the operation.
        """
        var client_fd = ptr[].client_handle.raw()
        var backend_fd = ptr[].backend_handle.raw()
        var conn_id = ptr[].conn_id
        var result32 = Int32(result)

        if op_kind == OP_CLIENT_RECV:
            var subs = h2_handle_client_recv(
                ptr[].variant.h2_state.value(),
                ptr[].send_state,
                ptr[].client_tls,
                ptr[].backend_tls,
                ptr[].phase,
                ptr[].closed,
                client_fd,
                backend_fd,
                conn_id,
                result32,
            )
            self.pending_submits.extend(subs^)
        elif op_kind == OP_CLIENT_SEND:
            var subs = h2_handle_client_send(
                ptr[].variant.h2_state.value(),
                ptr[].send_state,
                ptr[].client_tls,
                ptr[].phase,
                ptr[].closed,
                client_fd,
                conn_id,
                result32,
            )
            self.pending_submits.extend(subs^)
        elif op_kind == OP_BACKEND_CONNECT:
            var subs = h2_handle_backend_connect(
                ptr[].variant.h2_state.value(),
                ptr[].send_state,
                ptr[].client_tls,
                ptr[].backend_tls,
                ptr[].phase,
                ptr[].closed,
                client_fd,
                backend_fd,
                conn_id,
                result32,
            )
            self.pending_submits.extend(subs^)
        elif op_kind == OP_BACKEND_RECV:
            var subs = h2_handle_backend_recv(
                ptr[].variant.h2_state.value(),
                ptr[].send_state,
                ptr[].client_tls,
                ptr[].backend_tls,
                ptr[].phase,
                ptr[].closed,
                client_fd,
                backend_fd,
                conn_id,
                result32,
            )
            self.pending_submits.extend(subs^)
        elif op_kind == OP_BACKEND_SEND:
            var subs = h2_handle_backend_send(
                ptr[].variant.h2_state.value(),
                ptr[].send_state,
                ptr[].client_tls,
                ptr[].phase,
                ptr[].closed,
                client_fd,
                backend_fd,
                conn_id,
                result32,
            )
            self.pending_submits.extend(subs^)

    # --- Close helper ---------------------------------------------------

    def _close_connection(
        mut self, ptr: Pointer[ProxyConnection, MutUntrackedOrigin]
    ) raises:
        """Begin teardown of a connection: mark it closed and shut down both
        sockets. The heap slot itself is freed by `reap()`.

        We shutdown(SHUT_RDWR) both fds immediately because close() alone is
        not enough to trigger TCP teardown when io_uring still holds
        references to the fd (in-flight or recently-completed submissions).
        Empirically, without the explicit shutdown the backend TCP
        connection stays in ESTABLISHED state after the proxy finishes a
        request, blocking the backend's accept loop in its previous
        handle_connection's recv() call and starving every subsequent
        connection. The shutdown(SHUT_RDWR) sends FIN synchronously.

        Under the token model the record was destroyed here and a later CQE
        for it was ignored because the token no longer resolved. A
        `Completion` is the SQE's user_data, so destroying the record here
        would leave the ring pointing at freed memory. Instead the record
        stays alive, refuses further work (`closed`), and `reap()` frees it
        on the first tick where nothing is in flight — the same two-phase
        close `navette/h1/h1_tcp_server.mojo` uses. `OwnedHandle.__del__`
        still reclaims both fds, one tick later.

        Args:
            ptr: The connection to tear down. Idempotent.
        """
        ptr[].closed = True
        if ptr[].shutdown_done:
            return
        ptr[].shutdown_done = True
        var client_fd = ptr[].client_handle.raw()
        var backend_fd = ptr[].backend_handle.raw()
        _ = external_call["shutdown", Int32](client_fd, Int32(2))
        _ = external_call["shutdown", Int32](backend_fd, Int32(2))

    # --- Post-tick submission drains ------------------------------------

    def drain_submits(mut self, mut driver: IoUringDriver) raises:
        """Submit every op queued by this tick's completions, then clear the
        queue.

        Each op is submitted with the Completion its connection owns for
        that op kind, so the driver can route the CQE straight back without
        a token. Ops for a connection that closed earlier in the same tick
        are dropped — the old code got that for free because closing removed
        the connection from `connections` immediately.

        Args:
            driver: The io_uring driver every operation is submitted on.
        """
        var submits = self.pending_submits^
        self.pending_submits = List[PendingSubmit]()

        for i in range(len(submits)):
            var s = submits[i].copy()

            if s.kind == SUBMIT_ACCEPT:
                var cmp_ptr = Pointer[Completion, MutUntrackedOrigin](
                    unsafe_from_address=Int(Pointer(to=self._accept_cmp))
                )
                driver.accept(s.fd, cmp_ptr)
                continue

            var idx = self._find_index(s.conn_id)
            if idx < 0:
                continue
            var conn = self.connections[idx]
            if conn[].closed:
                continue
            var cmp_ptr = conn[].cmp_ptr(s.op_kind)

            if s.kind == SUBMIT_RECV:
                var raw_addr: Int
                if s.op_kind == OP_CLIENT_RECV:
                    raw_addr = Int(
                        conn[].send_state.client_recv_buf.unsafe_ptr()
                    )
                else:
                    raw_addr = Int(
                        conn[].send_state.backend_recv_buf.unsafe_ptr()
                    )
                var buf_ptr = Pointer[UInt8, MutUntrackedOrigin](
                    unsafe_from_address=raw_addr
                )
                driver.recv(
                    s.fd, buf_ptr, UInt32(_RECV_BUF_SIZE), cmp_ptr
                )
            elif s.kind == SUBMIT_SEND:
                var n: Int
                var raw_addr: Int
                if s.op_kind == OP_CLIENT_SEND:
                    n = len(conn[].send_state.client_send_buf)
                    if n == 0:
                        continue
                    raw_addr = Int(
                        conn[].send_state.client_send_buf.unsafe_ptr()
                    )
                else:
                    n = len(conn[].send_state.backend_send_buf)
                    if n == 0:
                        continue
                    raw_addr = Int(
                        conn[].send_state.backend_send_buf.unsafe_ptr()
                    )
                var buf_ptr = Pointer[UInt8, MutUntrackedOrigin](
                    unsafe_from_address=raw_addr
                )
                driver.send(s.fd, buf_ptr, UInt32(n), cmp_ptr)
            elif s.kind == SUBMIT_CONNECT:
                var addr_ptr = conn[].backend_addr_stor.addr_unsafe_ptr()
                var addr_len = UInt64(SocketAddrStorV4.ADDR_LEN)
                driver.connect(s.fd, addr_ptr, addr_len, cmp_ptr)
                conn[].connect_in_flight = True

    def _find_h3_ops(self, backend_conn_id: UInt64) -> Int:
        """Return the index of the `H3BackendOps` block for
        `backend_conn_id`, or -1."""
        for i in range(len(self.h3_backend_ops)):
            if self.h3_backend_ops[i][].backend_conn_id == backend_conn_id:
                return i
        return -1

    def collect_h3_forwards(mut self, mut driver: IoUringDriver) raises:
        """Walk every live H3 connection's `ForwardingHandler`, drain its
        captured requests, open a backend TCP+TLS+`H1Session` for each, and
        submit the backend connect.

        Called each tick after `flush_h3`, which is what runs the handler
        callbacks that populate `_pending`. The per-conn handler is reached
        via the H3 server's public `conn_slots[i].h3[].handler` — there is no
        module-level global to bridge the factory to the driver (Mojo 1.0.0b1
        forbids globals).

        Args:
            driver: The io_uring driver every operation is submitted on.
        """
        var n_conns = len(self._h3.conn_slots)
        for ci in range(n_conns):
            if ci >= len(self._h3.conn_slots):
                break
            # conn_slots[ci].h3 is a Pointer[H3HandlerServer]; bind it to a
            # local pointer first (avoid a deep chained mutable place-expr)
            # and deref to reach the per-conn handler.
            var h3_ptr = self._h3.conn_slots[ci].h3
            var forwards = h3_ptr[].handler.take_pending()
            for fi in range(len(forwards)):
                var fwd = forwards[fi].copy()
                var backend_conn_id = self.h3_backends.open_backend(fwd^)
                var fd = self.h3_backends.backend_fd(backend_conn_id)
                if fd < 0:
                    continue
                # Use the conn's stable, heap-stored addr (outlives the
                # in-flight connect), not a stack temporary.
                var addr_ptr = self.h3_backends.backend_addr_ptr(
                    backend_conn_id
                )
                if Int(addr_ptr) == 0:
                    continue
                var ops_ptr = _heap_alloc[H3BackendOps](1)
                ops_ptr.unsafe_write(H3BackendOps(backend_conn_id))
                ops_ptr[].wire_context(
                    Pointer[NoneType, MutUntrackedOrigin](
                        unsafe_from_address=Int(Pointer(to=self))
                    )
                )
                self.h3_backend_ops.append(ops_ptr)
                var addr_len = UInt64(SocketAddrStorV4.ADDR_LEN)
                driver.connect(
                    fd,
                    addr_ptr,
                    addr_len,
                    ops_ptr[].cmp_ptr(OP_BACKEND_CONNECT),
                )
                ops_ptr[].set_in_flight(OP_BACKEND_CONNECT, True)

    def drain_h3_backend_submits(
        mut self, mut driver: IoUringDriver
    ) raises:
        """Issue the H3-backend recv/send SQEs queued by the backend
        handlers. Buffer pointers come from the backend-conn registry (these
        conn_ids are synthetic and absent from `self.connections`) and the
        Completions from the matching `H3BackendOps` block.

        Args:
            driver: The io_uring driver every operation is submitted on.
        """
        var submits = self.h3_backend_submits^
        self.h3_backend_submits = List[PendingSubmit]()

        for i in range(len(submits)):
            var s = submits[i].copy()
            var backend_conn_id = s.conn_id
            var ops_idx = self._find_h3_ops(backend_conn_id)
            if ops_idx < 0:
                continue
            var ops = self.h3_backend_ops[ops_idx]
            var cmp_ptr = ops[].cmp_ptr(s.op_kind)
            if s.kind == SUBMIT_RECV:
                var raw_addr = self.h3_backends.backend_recv_buf_addr(
                    backend_conn_id
                )
                if raw_addr == 0:
                    continue
                var buf_ptr = Pointer[UInt8, MutUntrackedOrigin](
                    unsafe_from_address=raw_addr
                )
                driver.recv(
                    s.fd, buf_ptr, UInt32(_RECV_BUF_SIZE), cmp_ptr
                )
                ops[].set_in_flight(s.op_kind, True)
            elif s.kind == SUBMIT_SEND:
                var n = self.h3_backends.backend_send_buf_len(
                    backend_conn_id
                )
                if n == 0:
                    continue
                var raw_addr = self.h3_backends.backend_send_buf_addr(
                    backend_conn_id
                )
                if raw_addr == 0:
                    continue
                var buf_ptr = Pointer[UInt8, MutUntrackedOrigin](
                    unsafe_from_address=raw_addr
                )
                driver.send(s.fd, buf_ptr, UInt32(n), cmp_ptr)
                ops[].set_in_flight(s.op_kind, True)

    # --- Reaping --------------------------------------------------------

    def reap(mut self) raises:
        """Free every heap block the ring no longer points at.

        Two sweeps, both swap-and-pop:

        1. `ProxyConnection`s that are closed and have no operation left in
           flight. Their destructor closes both fds.
        2. `H3BackendOps` blocks whose backend conn has already been freed
           by `proxy_h3` and which have no operation left in flight.

        Called once per tick, after the submission drains, so a block whose
        last op was submitted this tick is not reaped underneath the ring.
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
                # Don't advance — the swapped-in element needs checking.
            else:
                i += 1

        var j = 0
        while j < len(self.h3_backend_ops):
            var ops = self.h3_backend_ops[j]
            var conn_ptr = self.h3_backends.backend_ptr(
                ops[].backend_conn_id
            )
            if Int(conn_ptr) == 0 and ops[].is_idle():
                var last = len(self.h3_backend_ops) - 1
                if j != last:
                    self.h3_backend_ops[j] = self.h3_backend_ops[last]
                _ = self.h3_backend_ops.pop()
                ops.unsafe_deinit_pointee()
                ops.unsafe_free()
            else:
                j += 1


# ---------------------------------------------------------------------------
# _run_tick — one event-loop iteration
# ---------------------------------------------------------------------------


def _run_tick(
    handler: Pointer[ProxyHandler, MutUntrackedOrigin],
    mut driver: IoUringDriver,
    loop: Pointer[WatchLoop, MutUntrackedOrigin],
) raises:
    """One event-loop iteration: tick the ring, step the WatchLoop, then
    run the embedded H3 server's batch flush, then drain both the TCP
    proxy paths and the H3 backend follow-ups, then reap whatever the
    ring has finished with.

    `tick(wait=True)` submits everything queued and blocks for at least
    one completion, then fires each CQE's Completion. `loop.step()`
    drains WatchLoop completions (recv/send/timer). Handlers still
    cannot submit from inside a callback — they queue into
    `pending_submits` and the drains below issue the SQEs — so
    `reap()` is safe here: every submission for this tick has already
    happened.

    Extracted from `main`'s `while True` so the loop body lowers as its own
    small codegen unit rather than inflating `main`.

    Args:
        handler: The heap-stable proxy state.
        driver: The io_uring driver every operation is submitted on.
        loop: The WatchLoop for recv/send/timer completions.
    """
    _ = driver.tick(wait=True)
    _ = loop[].step()
    handler[].flush_h3(driver)
    handler[].collect_h3_forwards(driver)
    handler[].drain_submits(driver)
    handler[].drain_h3_backend_submits(driver)
    handler[].reap()


# ---------------------------------------------------------------------------
# Upstream / CLI parsing
# ---------------------------------------------------------------------------


def _ipv4_octets(host: String) raises -> List[Int]:
    """Parse a dotted-quad IPv4 literal into its four octets.

    `localhost` maps to 127.0.0.1. Raises on anything that is not an IPv4
    literal — hostname/DNS resolution is out of scope for this loopback
    demo, so pass an IP address (e.g. 127.0.0.1).
    """
    var octets = List[Int]()
    if host == "localhost":
        octets.append(127)
        octets.append(0)
        octets.append(0)
        octets.append(1)
        return octets^

    var hb = host.as_bytes()
    var cur = String()
    for i in range(len(hb)):
        if hb[i] == UInt8(46):  # '.'
            octets.append(atol(cur))
            cur = String()
        else:
            cur += chr(Int(hb[i]))
    octets.append(atol(cur))

    if len(octets) != 4:
        raise String(
            "upstream host must be an IPv4 address or 'localhost', got: "
        ) + host
    for i in range(len(octets)):
        if octets[i] < 0 or octets[i] > 255:
            raise String("invalid IPv4 octet in upstream host: ") + host
    return octets^


struct _Upstream(Movable):
    """A parsed `--upstream` target: IPv4 connect octets + SNI host + port."""

    var octets: List[Int]
    var host: String
    var port: UInt16

    def __init__(
        out self, var octets: List[Int], var host: String, port: UInt16
    ):
        self.octets = octets^
        self.host = host^
        self.port = port

    def __init__(out self, *, deinit move: Self):
        self.octets = move.octets^
        self.host = move.host^
        self.port = move.port


def _parse_upstream(spec: String) raises -> _Upstream:
    """Parse a `[scheme://]host:port` upstream spec.

    The scheme (if any) and any trailing path are ignored; the host is kept
    verbatim as the TLS SNI name and also resolved to IPv4 connect octets.
    """
    var b = spec.as_bytes()
    var n = len(b)
    var i = 0

    # Skip an optional `scheme://` prefix.
    var scheme_end = -1
    for j in range(n):
        if (
            j + 2 < n
            and b[j] == UInt8(58)  # ':'
            and b[j + 1] == UInt8(47)  # '/'
            and b[j + 2] == UInt8(47)  # '/'
        ):
            scheme_end = j
            break
    if scheme_end >= 0:
        i = scheme_end + 3

    # Host runs up to ':' (port) or '/' (path).
    var host = String()
    while i < n and b[i] != UInt8(58) and b[i] != UInt8(47):
        host += chr(Int(b[i]))
        i += 1

    if i >= n or b[i] != UInt8(58):
        raise String(
            "upstream must be host:port (e.g. 127.0.0.1:9443), got: "
        ) + spec
    i += 1  # skip ':'

    var port_str = String()
    while i < n and b[i] != UInt8(47):  # stop at '/'
        port_str += chr(Int(b[i]))
        i += 1

    if not host or port_str.byte_length() == 0:
        raise String(
            "upstream must be host:port (e.g. 127.0.0.1:9443), got: "
        ) + spec

    var octets = _ipv4_octets(host)
    return _Upstream(octets=octets^, host=host^, port=UInt16(atol(port_str)))


def _print_usage():
    """Print CLI usage for the reverse proxy."""
    print("Usage: reverse_proxy [OPTIONS]")
    print("")
    print("  --listen PORT          Port to accept client TLS on (default 8443)")
    print(
        "  --upstream HOST:PORT   Backend to proxy to (default localhost:9443)."
    )
    print("                         Accepts an optional scheme, e.g.")
    print("                         --upstream https://127.0.0.1:9443")
    print("  -h, --help             Show this help and exit")
    print("")
    print("Env vars (overridden by the flags above): LISTEN_PORT,")
    print("H1_BACKEND_PORT, H2_BACKEND_PORT, BACKEND_HOST.")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
    # Defaults come from env vars; the CLI flags below override them.
    var listen_port = UInt16(_getenv_int(String("LISTEN_PORT"), 8443))
    var h1_backend_port = UInt16(
        _getenv_int(String("H1_BACKEND_PORT"), 9443)
    )
    var h2_backend_port = UInt16(
        _getenv_int(String("H2_BACKEND_PORT"), Int(h1_backend_port))
    )
    var backend_host = _getenv_str(
        String("BACKEND_HOST"), String("localhost")
    )
    var connect_octets = _ipv4_octets(backend_host)

    # CLI flags override env. --upstream sets host + both backend ports;
    # --listen sets the client-facing port.
    from std.sys import argv

    var args = argv()
    var ai = 1
    while ai < len(args):
        var arg = args[ai]
        if arg == "--listen" and ai + 1 < len(args):
            ai += 1
            listen_port = UInt16(atol(args[ai]))
        elif arg == "--upstream" and ai + 1 < len(args):
            ai += 1
            var up = _parse_upstream(args[ai])
            backend_host = up.host.copy()
            h1_backend_port = up.port
            h2_backend_port = up.port
            connect_octets = up.octets.copy()
        elif arg == "-h" or arg == "--help":
            _print_usage()
            return
        else:
            _print_usage()
            raise String("unknown argument: ") + arg
        ai += 1

    var h1_backend_addr = SocketAddrV4(
        UInt8(connect_octets[0]),
        UInt8(connect_octets[1]),
        UInt8(connect_octets[2]),
        UInt8(connect_octets[3]),
        port=h1_backend_port,
    )
    var h2_backend_addr = SocketAddrV4(
        UInt8(connect_octets[0]),
        UInt8(connect_octets[1]),
        UInt8(connect_octets[2]),
        UInt8(connect_octets[3]),
        port=h2_backend_port,
    )

    # Load TLS material.
    var proxy_cert = _read_file(_CERT_DIR + "/proxy_cert.pem")
    var proxy_key = _read_file(_CERT_DIR + "/proxy_key.pem")

    # Initialize TLS backend + dual-ALPN server config.
    var tls = TlsBackend()
    var server_config = TlsServerConfig(
        tls.shared(), Span(proxy_cert), Span(proxy_key)
    )
    var server_alpn = List[String]()
    server_alpn.append(String("h2"))
    server_alpn.append(String("http/1.1"))
    server_config.set_alpn_protocols(server_alpn)

    # Two client configs, each pinned to one ALPN. Self-signed backend
    # cert — use insecure client config (requires librustls_mojo.so
    # built with --features insecure).
    var h1_client_config = TlsClientConfig(tls.shared(), insecure=True)
    var h1_alpn = List[String]()
    h1_alpn.append(String("http/1.1"))
    h1_client_config.set_alpn_protocols(h1_alpn)

    var h2_client_config = TlsClientConfig(tls.shared(), insecure=True)
    var h2_alpn = List[String]()
    h2_alpn.append(String("h2"))
    h2_client_config.set_alpn_protocols(h2_alpn)

    # ── H3/QUIC frontend ─────────────────────────────────────────────────
    #
    # The embedded H3 server reuses the proxy's TLS material (same cert/key)
    # and its own UDP listener. Each inbound H3 request is forwarded to the
    # H1 backend over a fresh TCP+TLS+H1Session round-trip; the backend TLS
    # client config is the SAME `h1_client_config` the H1 path uses, reached
    # by address from `ProxyShared` after the handler is moved into the loop.
    var h3_port = _getenv_int(String("H3_PORT"), 8444)
    var h3_quic_config = QuicServerConfig(
        tls.shared(), Span(proxy_cert), Span(proxy_key),
        policy=EarlyDataPolicy.off(),
    )
    var h3_sock = udp_listener(h3_port)
    var h3_tp = default_transport_params()

    # H3-backend registry: dial target + SNI. The long-lived TLS config
    # ADDRESSES are published below, after the handler is moved into the
    # loop (so they point at the stable, in-loop copies). No global needed.
    var h3_registry = H3BackendRegistry(
        backend_addr=h1_backend_addr, backend_host=backend_host.copy()
    )

    var h3_server = H3UdpServer[ForwardingHandler](
        h3_sock^,
        TlsBackend(copy=tls),
        h3_quic_config^,
        h3_tp^,
        make_forwarding_handler,
    )

    # Listening socket (IPv4 TCP, non-blocking).
    var listener = Socket.tcp_v4()
    var bind_addr = SocketAddrV4(
        UInt8(0), UInt8(0), UInt8(0), UInt8(0), port=listen_port
    )
    listener.bind(bind_addr)
    listener.listen(Backlog.DEFAULT)
    var listener_fd = listener.raw()

    print(
        "mojo-proxy: listening on https://127.0.0.1:" + String(listen_port)
    )
    print(
        "mojo-proxy: H3 (QUIC) listening on udp/" + String(h3_port)
    )
    print(
        "mojo-proxy: H1 backend at https://"
        + backend_host
        + ":"
        + String(h1_backend_port)
    )
    print(
        "mojo-proxy: H2 backend at https://"
        + backend_host
        + ":"
        + String(h2_backend_port)
    )

    var handler = ProxyHandler(
        listener_fd=listener_fd,
        tls=tls^,
        server_tls_config=server_config^,
        h1_client_tls_config=h1_client_config^,
        h2_client_tls_config=h2_client_config^,
        h1_backend_addr=h1_backend_addr,
        h2_backend_addr=h2_backend_addr,
        backend_host=backend_host,
        h3_backends=h3_registry^,
        h3=h3_server^,
    )
    # Capacity bumped from 256 to 4096: the H3 path adds a 1024-entry
    # provided-buffer ring + multishot recvmsg + timeout + per-stream sendmsg
    # on top of the TCP accept/recv/send/connect ops; 256 would overflow
    # under load.
    var driver = IoUringDriver(capacity=4096)
    var loop_ptr = _heap_alloc[WatchLoop](1)
    loop_ptr.unsafe_write(WatchLoop(capacity=4096))

    # The handler must not move again: every Completion the ring holds
    # points either at it or at a record that stores its address. Heap it,
    # then wire the contexts.
    var handler_ptr = _heap_alloc[ProxyHandler](1)
    handler_ptr.unsafe_write(handler^)
    handler_ptr[].wire_context()

    # Now that the handler (and its `tls` + `h1_client_tls_config`) lives at
    # a stable address, publish those addresses to the H3 backend registry so
    # `open_backend` can build backend TLS connections.
    handler_ptr[].publish_h3_backend_config_addrs()

    # Submit the initial accept plus the embedded H3 server's bootstrap
    # (buf-ring registration + multishot recvmsg + periodic timeout).
    handler_ptr[].start(driver, loop_ptr[])

    # Event loop. Drain queued submissions from the handler after every
    # tick — handlers still cannot submit from inside a completion callback,
    # because a callback has no driver reference. The per-tick body is
    # extracted into `_run_tick` to keep `main`'s codegen unit small (large
    # monolithic `main` bodies that mix the driver with many free-function
    # calls stress the lowering pass).
    while True:
        _run_tick(handler_ptr, driver, loop_ptr)
        _ = listener  # anchor: keep listener fd alive for io_uring
