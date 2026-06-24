# examples/reverse_proxy/main.mojo
#
# Unified ALPN-dispatched HTTPS reverse proxy. The frontend TLS listener
# advertises both `h2` and `http/1.1`; once the client TLS handshake
# completes, the negotiated ALPN selects which proxy variant
# (`proxy_h1` or `proxy_h2`) drives the rest of the connection. Both
# variants share the same accept / TLS / send-state plumbing.
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
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.http.session import RequestHandle
from navette.tls import (
    TlsBackend,
    TlsClientConfig,
    TlsServerConfig,
    TlsConnection,
    EarlyDataPolicy,
)
from navette.tls.config import QuicServerConfig

from boucle import CompletionLoop, CompletionHandler
from boucle.ctypes import c_void
from boucle.handle import OwnedHandle
from boucle.net.socket import Socket
from boucle.net.addr import SocketAddrV4, SocketAddrStorV4
from boucle.net.options import Backlog

from navette.runtime.socket_helpers import tcp_v4_nonblocking, udp_listener
from navette.quic.trans_param import default_transport_params
from navette.h3.h3_udp_server import (
    H3UdpServer,
    PBUF_SIZE,
    PBUF_COUNT,
    PBUF_GROUP_ID,
    OP_PROVIDE_BUF,
    OP_RECVMSG,
    OP_SENDMSG,
    OP_TIMEOUT,
    PendingSubmit as H3PendingSubmit,
    _encode_token as h3_encode_token,
)

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
    encode_token,
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
    H3_TOKEN_TAG,
    H3_BACKEND_TOKEN_TAG,
    h3_encode_backend_token,
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
    var nbuf = _heap_alloc[UInt8](len(name) + 1)
    var name_bytes = name.as_bytes()
    for i in range(len(name_bytes)):
        nbuf[i] = name_bytes[i]
    nbuf[len(name_bytes)] = 0
    var ptr_int = external_call["getenv", Int](nbuf)
    nbuf.free()
    if ptr_int == 0:
        return default
    var ptr = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=ptr_int)
    var s = String()
    var i = 0
    while ptr[i] != 0:
        s += chr(Int(ptr[i]))
        i += 1
    return s^


def _getenv_int(name: String, default: Int) -> Int:
    """Read an integer environment variable; fall back to default if
    unset / invalid."""
    var s = _getenv_str(name, String(""))
    if len(s) == 0:
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

    def __init__(out self, *, deinit take: Self):
        self.tag = take.tag
        self.h1_state = take.h1_state^
        self.h2_state = take.h2_state^

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
    `UnsafePointer` so that addresses inside (recv/send buffers, the
    backend addr storage) remain stable while io_uring ops are in flight.

    `variant` starts as `ProxyVariant.handshaking()`; the client TLS
    handshake completion handler reads the negotiated ALPN and replaces
    it with either an H1 or H2 state in-place.
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

    def __init__(
        out self,
        conn_id: UInt64,
        var client_handle: OwnedHandle,
        var backend_handle: OwnedHandle,
        backend_addr_stor: SocketAddrStorV4,
        var client_tls: TlsConnection,
        var backend_tls: TlsConnection,
    ):
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

    def __init__(out self, *, deinit take: Self):
        self.conn_id = take.conn_id
        self.client_handle = take.client_handle^
        self.backend_handle = take.backend_handle^
        self.backend_addr_stor = take.backend_addr_stor
        self.client_tls = take.client_tls^
        self.backend_tls = take.backend_tls^
        self.phase = take.phase
        self.send_state = take.send_state^
        self.variant = take.variant^
        self.closed = take.closed


# ---------------------------------------------------------------------------
# ProxyHandler — unified completion-handler dispatcher
# ---------------------------------------------------------------------------


struct ProxyHandler(CompletionHandler):
    """Single-threaded unified reverse-proxy handler.

    Owns the listener fd, rustls lib + three configs (one server with
    dual-ALPN, two clients each pinned to one ALPN), the list of in-flight
    connections, and the queue of I/O ops to submit after `poll()`.

    The actual per-variant work lives in `proxy_h1` / `proxy_h2`
    free functions; this handler is just the dispatch + TLS-handshake
    completion driver.
    """

    var listener_fd: Int32
    # Heap-allocated ProxyConnection pointers (see proxy_h1's notes on
    # stable addresses across `List` reallocations).
    var connections: List[UnsafePointer[ProxyConnection, MutAnyOrigin]]
    var next_conn_id: UInt64
    var tls: TlsBackend
    var server_tls_config: TlsServerConfig
    var h1_client_tls_config: TlsClientConfig
    var h2_client_tls_config: TlsClientConfig
    var h1_backend_addr: SocketAddrV4
    var h2_backend_addr: SocketAddrV4
    var backend_host: String
    var pending_submits: List[PendingSubmit]
    # H3-backend TCP follow-up ops queued from on_complete; drained post-poll
    # by `_drain_h3_backend_submits` against the H3 backend-conn registry
    # (these conn_ids are synthetic and do NOT live in `self.connections`).
    var h3_backend_submits: List[PendingSubmit]
    # H3-backend registry: per-request backend conns + the backend dial
    # target + the (addresses of the) long-lived TLS configs. Owned here so
    # there is no module-level global (Mojo 1.0.0b1 forbids those).
    var h3_backends: H3BackendRegistry
    # Embedded H3/QUIC frontend, driven from this same CompletionLoop via
    # the H3-tagged tokens (see _dispatch). Declared LAST and moved into the
    # loop before any QUIC connection exists, so the pointer the H3 server's
    # per-conn handlers take to `self.profile` stays stable (the struct does
    # not move again after the handler^ move into CompletionLoop).
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
        self.listener_fd = listener_fd
        self.connections = List[
            UnsafePointer[ProxyConnection, MutAnyOrigin]
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
        self.h3_backends = h3_backends^
        self._h3 = h3^

    def __init__(out self, *, deinit take: Self):
        self.listener_fd = take.listener_fd
        self.connections = take.connections^
        self.next_conn_id = take.next_conn_id
        self.tls = take.tls^
        self.server_tls_config = take.server_tls_config^
        self.h1_client_tls_config = take.h1_client_tls_config^
        self.h2_client_tls_config = take.h2_client_tls_config^
        self.h1_backend_addr = take.h1_backend_addr
        self.h2_backend_addr = take.h2_backend_addr
        self.backend_host = take.backend_host^
        self.pending_submits = take.pending_submits^
        self.h3_backend_submits = take.h3_backend_submits^
        self.h3_backends = take.h3_backends^
        self._h3 = take._h3^

    # --- H3 backend config publication ----------------------------------

    def publish_h3_backend_config_addrs(mut self):
        """Publish the stable in-loop addresses of `tls` + `h1_client_tls_config`
        to the H3 backend registry so `open_backend` can build backend TLS
        connections. Taken from `self` (a clean field lvalue) rather than
        through `loop._handler.<field>` — the address-of of a field reached
        across the loop's handler getter mis-lowers in Mojo 1.0.0b1; taking it
        from inside the owning struct is the codegen-safe form. Call once,
        after the handler has been moved into the loop (so the addresses point
        at the final, stable copies)."""
        self.h3_backends.tls_shared_addr = UInt64(
            Int(UnsafePointer(to=self.tls))
        )
        self.h3_backends.h1_client_config_addr = UInt64(
            Int(UnsafePointer(to=self.h1_client_tls_config))
        )

    # --- Connection lookup ----------------------------------------------

    def _find_index(self, conn_id: UInt64) -> Int:
        """Return the index of the connection with `conn_id`, or -1."""
        for i in range(len(self.connections)):
            if self.connections[i][].conn_id == conn_id:
                return i
        return -1

    # --- on_complete dispatch -------------------------------------------

    def on_complete(mut self, token: UInt64, result: Int32, flags: UInt32):
        try:
            self._dispatch(token, result, flags)
        except e:
            print("proxy: on_complete error:", e)

    def _dispatch(mut self, token: UInt64, result: Int32, flags: UInt32) raises:
        # H3 frontend tokens (UDP recvmsg / sendmsg / timeout / provide-buf):
        # strip the tag and hand straight to the embedded H3 server. The CQE
        # `flags` MUST be forwarded verbatim: the multishot recvmsg path reads
        # the provided-buffer id (flags >> IORING_CQE_BUFFER_SHIFT) and the
        # IORING_CQE_F_MORE / F_BUFFER bits out of it. Dropping flags (passing
        # 0) silently discards every inbound datagram → QUIC handshake stalls.
        if (token & H3_TOKEN_TAG) != 0:
            self._h3.on_complete(token & ~H3_TOKEN_TAG, result, flags)
            return

        # H3 backend TCP tokens (per-request H1Session round-trip): decode the
        # synthetic backend conn id + op kind and run the H3 backend handler,
        # then issue any follow-up SQEs it queued.
        if (token & H3_BACKEND_TOKEN_TAG) != 0:
            self._dispatch_h3_backend(token, result)
            return

        var op_kind = UInt8(token & 0xFF)
        var conn_id = token >> 8

        if op_kind == OP_ACCEPT:
            self._handle_accept(result)
            return

        var idx = self._find_index(conn_id)
        if idx < 0:
            return  # stale completion for closed connection

        # While the variant is still "handshaking" we're driving the
        # client-side TLS handshake; once the handshake settles we
        # construct the matching variant and from then on everything
        # routes through the proxy_h1 / proxy_h2 free functions.
        if self.connections[idx][].variant.is_handshaking():
            self._drive_client_tls_handshake(idx, op_kind, result)
            if not self.connections[idx][].closed:
                self._maybe_finalize_handshake(idx)
            if self.connections[idx][].closed:
                self._close_connection(idx)
            return

        if self.connections[idx][].variant.is_h1():
            self._dispatch_h1(idx, op_kind, result)
        elif self.connections[idx][].variant.is_h2():
            self._dispatch_h2(idx, op_kind, result)

        if self.connections[idx][].closed:
            self._close_connection(idx)

    # --- H3 backend dispatch --------------------------------------------

    def _dispatch_h3_backend(mut self, token: UInt64, result: Int32) raises:
        """Route an H3-backend TCP completion to its handler and queue the
        follow-up ops into `h3_backend_submits`.

        The handlers take a `mut self._h3` (so a complete response or a 502
        injects straight into the owning H3 stream) and the synthetic
        backend conn id; they return the recv/send ops to issue next. Buffer
        pointers are resolved post-poll in `_drain_h3_backend_submits` from
        the backend-conn registry.
        """
        var untagged = token & ~H3_BACKEND_TOKEN_TAG
        var op_kind = UInt8(untagged & 0xFF)
        var backend_conn_id = untagged >> 8

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

    def _handle_accept(mut self, result: Int32) raises:
        if result < 0:
            print("proxy: accept failed:", result)
            self._queue_accept()
            return

        var client_fd = result
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
        # inside the pointee, so the pointee must not move).
        var conn_ptr = _heap_alloc[ProxyConnection](1).as_unsafe_any_origin()
        conn_ptr.init_pointee_move(conn^)
        self.connections.append(conn_ptr)
        var idx = len(self.connections) - 1

        # Kick off the TLS handshake by reading the first client bytes.
        queue_client_recv(
            self.connections[idx][].send_state,
            self.pending_submits,
            self.connections[idx][].client_handle.raw(),
            self.connections[idx][].conn_id,
        )

        # Re-arm accept for the next client.
        self._queue_accept()

    def _queue_accept(mut self):
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
        mut self, idx: Int, op_kind: UInt8, result: Int32,
    ) raises:
        """Drive the client-side TLS handshake to completion.

        During the handshake phase, only CLIENT_RECV and CLIENT_SEND
        ops are valid. Each RECV feeds bytes into rustls; each SEND
        confirms a ciphertext flush so we can chain pending bytes.
        """
        var ptr = self.connections[idx]

        if op_kind == OP_CLIENT_RECV:
            ptr[].send_state.client_recv_in_flight = False
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
            ptr[].send_state.client_send_in_flight = False
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

    def _maybe_finalize_handshake(mut self, idx: Int) raises:
        """If the client TLS handshake has completed, read the negotiated
        ALPN, materialize the matching variant, rebuild the backend TLS
        connection against the ALPN-pinned client config, and kick off
        the backend connect.
        """
        var ptr = self.connections[idx]
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
        mut self, idx: Int, op_kind: UInt8, result: Int32
    ) raises:
        var ptr = self.connections[idx]
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
        mut self, idx: Int, op_kind: UInt8, result: Int32
    ) raises:
        var ptr = self.connections[idx]
        var client_fd = ptr[].client_handle.raw()
        var backend_fd = ptr[].backend_handle.raw()
        var conn_id = ptr[].conn_id

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
                result,
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
                result,
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
                result,
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
                result,
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
                result,
            )
            self.pending_submits.extend(subs^)

    # --- Close helper ---------------------------------------------------

    def _close_connection(mut self, idx: Int) raises:
        """Drop the connection: shutdown + close both sockets, run the
        ProxyConnection destructor, and free the heap slot.

        We shutdown(SHUT_RDWR) + close BEFORE destroy_pointee because
        close() alone is not enough to trigger TCP teardown when io_uring
        still holds references to the fd (in-flight or recently-completed
        submissions). Empirically, without the explicit shutdown the
        backend TCP connection stays in ESTABLISHED state after the proxy
        finishes a request, blocking the backend's accept loop in its
        previous handle_connection's recv() call and starving every
        subsequent connection. The shutdown(SHUT_RDWR) sends FIN
        synchronously; close() reclaims the fd.
        """
        var ptr = self.connections[idx]
        ptr[].closed = True
        var client_fd = ptr[].client_handle.raw()
        var backend_fd = ptr[].backend_handle.raw()
        # Explicit shutdown(SHUT_RDWR) before letting RAII close the fds:
        # close() alone can leave the peer in ESTABLISHED if io_uring still
        # holds references; FIN must be sent synchronously to unblock the
        # backend's accept loop. OwnedHandle.__del__ (via destroy_pointee
        # below) reclaims each fd.
        _ = external_call["shutdown", Int32](client_fd, Int32(2))
        _ = external_call["shutdown", Int32](backend_fd, Int32(2))
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

        if s.kind == SUBMIT_ACCEPT:
            loop.submit_accept(s.fd, token)
        elif s.kind == SUBMIT_RECV:
            var idx = loop._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            var raw_addr: Int
            if s.op_kind == OP_CLIENT_RECV:
                raw_addr = Int(
                    loop._handler.connections[idx][].send_state.client_recv_buf.unsafe_ptr()
                )
            else:
                raw_addr = Int(
                    loop._handler.connections[idx][].send_state.backend_recv_buf.unsafe_ptr()
                )
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            loop.submit_recv(s.fd, buf_ptr, UInt(_RECV_BUF_SIZE), token)
        elif s.kind == SUBMIT_SEND:
            var idx = loop._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            var n: Int
            var raw_addr: Int
            if s.op_kind == OP_CLIENT_SEND:
                n = len(
                    loop._handler.connections[idx][].send_state.client_send_buf
                )
                if n == 0:
                    continue
                raw_addr = Int(
                    loop._handler.connections[idx][].send_state.client_send_buf.unsafe_ptr()
                )
            else:
                n = len(
                    loop._handler.connections[idx][].send_state.backend_send_buf
                )
                if n == 0:
                    continue
                raw_addr = Int(
                    loop._handler.connections[idx][].send_state.backend_send_buf.unsafe_ptr()
                )
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            loop.submit_send(s.fd, buf_ptr, UInt(n), token)
        elif s.kind == SUBMIT_CONNECT:
            var idx = loop._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            var addr_ptr = (
                loop._handler.connections[idx][].backend_addr_stor.addr_unsafe_ptr()
            )
            var addr_len = UInt64(SocketAddrStorV4.ADDR_LEN)
            loop.submit_connect(s.fd, addr_ptr, addr_len, token)


# ---------------------------------------------------------------------------
# H3 frontend + backend glue (loop-typed; lives here so proxy_h3 stays free
# of a circular import on ProxyHandler / CompletionLoop[ProxyHandler]).
# ---------------------------------------------------------------------------


def h3_collect_forwards(mut loop: CompletionLoop[ProxyHandler]) raises:
    """Walk every live H3 connection's `ForwardingHandler`, drain its
    captured requests, open a backend TCP+TLS+`H1Session` for each, and
    submit the SUBMIT_CONNECT. Called each tick after `_h3.on_flush()` (the
    flush is what runs the handler callbacks that populate `_pending`).

    The handler is reached via the H3 server's public
    `conn_slots[i].h3[].handler` — there is no module-level global to bridge
    the factory to the driver (Mojo 1.0.0b1 forbids globals).
    """
    var n_conns = len(loop._handler._h3.conn_slots)
    for ci in range(n_conns):
        if ci >= len(loop._handler._h3.conn_slots):
            break
        # conn_slots[ci].h3 is an UnsafePointer[H3HandlerServer]; bind it to
        # a local pointer first (avoid a deep chained mutable place-expr) and
        # deref to reach the per-conn handler and drain its captured requests.
        var h3_ptr = loop._handler._h3.conn_slots[ci].h3
        var forwards = h3_ptr[].handler.take_pending()
        for fi in range(len(forwards)):
            var fwd = forwards[fi].copy()
            var backend_conn_id = loop._handler.h3_backends.open_backend(fwd^)
            var fd = loop._handler.h3_backends.backend_fd(backend_conn_id)
            if fd < 0:
                continue
            var token = h3_encode_backend_token(
                backend_conn_id, OP_BACKEND_CONNECT
            )
            # Use the conn's stable, heap-stored addr (outlives the in-flight
            # connect), not a stack temporary.
            var addr_ptr = loop._handler.h3_backends.backend_addr_ptr(
                backend_conn_id
            )
            if Int(addr_ptr) == 0:
                continue
            var addr_len = UInt64(SocketAddrStorV4.ADDR_LEN)
            loop.submit_connect(fd, addr_ptr, addr_len, token)


def _drain_h3_backend_submits(mut loop: CompletionLoop[ProxyHandler]) raises:
    """Issue the H3-backend recv/send SQEs queued by the backend handlers.
    Buffer pointers come from the backend-conn registry (these conn_ids are
    synthetic and absent from `self.connections`)."""
    var submits = loop._handler.h3_backend_submits^
    loop._handler.h3_backend_submits = List[PendingSubmit]()

    for i in range(len(submits)):
        var s = submits[i].copy()
        var backend_conn_id = s.conn_id
        var token = h3_encode_backend_token(backend_conn_id, s.op_kind)
        if s.kind == SUBMIT_RECV:
            var raw_addr = loop._handler.h3_backends.backend_recv_buf_addr(
                backend_conn_id
            )
            if raw_addr == 0:
                continue
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            loop.submit_recv(s.fd, buf_ptr, UInt(_RECV_BUF_SIZE), token)
        elif s.kind == SUBMIT_SEND:
            var n = loop._handler.h3_backends.backend_send_buf_len(
                backend_conn_id
            )
            if n == 0:
                continue
            var raw_addr = loop._handler.h3_backends.backend_send_buf_addr(
                backend_conn_id
            )
            if raw_addr == 0:
                continue
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            loop.submit_send(s.fd, buf_ptr, UInt(n), token)


def h3_bootstrap(mut loop: CompletionLoop[ProxyHandler]) raises:
    """Bootstrap the embedded H3 server against the proxy's CompletionLoop:
    register the provided-buffer pool, submit the initial multishot recvmsg,
    and submit the initial periodic timeout. Direct port of `serve_forever`'s
    bootstrap, with every token ORed with `H3_TOKEN_TAG`.
    """
    var provide_token = H3_TOKEN_TAG | h3_encode_token(
        UInt64(0), OP_PROVIDE_BUF
    )
    loop.provide_buffers(
        loop._handler._h3.pbuf_pool, PBUF_SIZE, PBUF_COUNT, PBUF_GROUP_ID,
        UInt16(0), provide_token,
    )

    var msghdr_addr = Int(loop._handler._h3.msghdr_template)
    var msghdr_ptr = UnsafePointer[c_void, StaticConstantOrigin](
        unsafe_from_address=msghdr_addr
    )
    var recvmsg_token = H3_TOKEN_TAG | h3_encode_token(UInt64(0), OP_RECVMSG)
    loop.submit_recvmsg_multishot(
        loop._handler._h3.udp_handle.raw(), msghdr_ptr, PBUF_GROUP_ID,
        recvmsg_token,
    )
    loop._handler._h3.multishot_active = True

    var ts_addr = Int(loop._handler._h3.timeout_ts)
    var ts_ptr = UnsafePointer[c_void, StaticConstantOrigin](
        unsafe_from_address=ts_addr
    )
    loop.submit_timeout(
        ts_ptr, H3_TOKEN_TAG | h3_encode_token(UInt64(0), OP_TIMEOUT)
    )


def h3_post_poll(mut loop: CompletionLoop[ProxyHandler]) raises:
    """Per-tick H3 housekeeping: re-provide buffers consumed during this
    batch and re-arm the multishot recvmsg if it ended. Call AFTER
    `_h3.on_flush()`.
    """
    var consumed = loop._handler._h3.consumed_bufs^
    loop._handler._h3.consumed_bufs = List[UInt16]()
    for i in range(len(consumed)):
        var bid = consumed[i]
        var buf_base = loop._handler._h3.pbuf_pool + Int(bid) * PBUF_SIZE
        loop.reprovide_buffer(
            buf_base, PBUF_SIZE, PBUF_GROUP_ID, bid,
            H3_TOKEN_TAG | h3_encode_token(UInt64(bid), OP_PROVIDE_BUF),
        )

    if not loop._handler._h3.multishot_active:
        var ms_addr = Int(loop._handler._h3.msghdr_template)
        var ms_ptr = UnsafePointer[c_void, StaticConstantOrigin](
            unsafe_from_address=ms_addr
        )
        loop.submit_recvmsg_multishot(
            loop._handler._h3.udp_handle.raw(), ms_ptr, PBUF_GROUP_ID,
            H3_TOKEN_TAG | h3_encode_token(UInt64(0), OP_RECVMSG),
        )
        loop._handler._h3.multishot_active = True


def h3_drain_pending_submits(mut loop: CompletionLoop[ProxyHandler]) raises:
    """Drain the embedded H3 server's `pending_submits` (sendmsg / timeout)
    into the proxy loop. Port of navette's `drain_pending_submits`, tagging
    every token with `H3_TOKEN_TAG`. Call each tick after `h3_post_poll`.
    """
    var submits = loop._handler._h3.pending_submits^
    loop._handler._h3.pending_submits = List[H3PendingSubmit]()

    for i in range(len(submits)):
        var s = submits[i].copy()
        if s.kind == OP_SENDMSG:
            var tx_id = s.slot_idx
            var inner = h3_encode_token(tx_id, OP_SENDMSG)
            if inner not in loop._handler._h3.tx_slot_idx_by_token:
                continue
            var tx_idx = loop._handler._h3.tx_slot_idx_by_token[inner]
            var msghdr_addr = Int(
                loop._handler._h3.tx_slots[tx_idx][].msghdr_buf
            )
            var msghdr_ptr = UnsafePointer[c_void, StaticConstantOrigin](
                unsafe_from_address=msghdr_addr
            )
            try:
                loop.submit_sendmsg(
                    loop._handler._h3.udp_handle.raw(),
                    msghdr_ptr,
                    H3_TOKEN_TAG | inner,
                )
            except:
                loop._handler._h3.pending_submits.append(s.copy())
        elif s.kind == OP_TIMEOUT:
            var ts_addr = Int(loop._handler._h3.timeout_ts)
            var ts_ptr = UnsafePointer[c_void, StaticConstantOrigin](
                unsafe_from_address=ts_addr
            )
            var inner = h3_encode_token(s.slot_idx, OP_TIMEOUT)
            try:
                loop.submit_timeout(ts_ptr, H3_TOKEN_TAG | inner)
            except:
                loop._handler._h3.pending_submits.append(s.copy())


def _run_tick(mut loop: CompletionLoop[ProxyHandler]) raises:
    """One event-loop iteration: poll the ring, then run the embedded H3
    server's batch flush + per-tick housekeeping, then drain both the TCP
    proxy paths and the H3 backend follow-ups.

    Extracted from `main`'s `while True` so the loop body lowers as its own
    small codegen unit rather than inflating `main`. `on_flush` also runs
    the `ForwardingHandler` callbacks, which park forwarded requests for
    `h3_collect_forwards` to turn into backend connects.
    """
    loop.poll(wait_nr=1)
    loop._handler._h3.on_flush()
    h3_collect_forwards(loop)
    h3_post_poll(loop)
    h3_drain_pending_submits(loop)
    _drain_pending_submits(loop)
    _drain_h3_backend_submits(loop)


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

    def __init__(out self, *, deinit take: Self):
        self.octets = take.octets^
        self.host = take.host^
        self.port = take.port


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

    if len(host) == 0 or len(port_str) == 0:
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
        connect_octets[0],
        connect_octets[1],
        connect_octets[2],
        connect_octets[3],
        port=h1_backend_port,
    )
    var h2_backend_addr = SocketAddrV4(
        connect_octets[0],
        connect_octets[1],
        connect_octets[2],
        connect_octets[3],
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
        TlsBackend(other=tls),
        h3_quic_config^,
        h3_tp^,
        make_forwarding_handler,
    )

    # Listening socket (IPv4 TCP, non-blocking).
    var listener = Socket.tcp_v4()
    var bind_addr = SocketAddrV4(0, 0, 0, 0, port=listen_port)
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
    # sq_entries bumped from 256 to 4096: the H3 path adds provide_buffers
    # (1024) + multishot recvmsg + timeout + per-stream sendmsg on top of the
    # TCP accept/recv/send/connect ops; 256 would overflow under load.
    var loop = CompletionLoop[ProxyHandler](handler^, sq_entries=4096)

    # Now that the handler (and its `tls` + `h1_client_tls_config`) lives at
    # a stable address inside the loop, publish those addresses to the H3
    # backend registry so `open_backend` can build backend TLS connections.
    loop._handler.publish_h3_backend_config_addrs()

    # Submit the initial accept.
    loop.submit_accept(listener_fd, encode_token(LISTENER_CONN_ID, OP_ACCEPT))

    # Bootstrap the embedded H3 server (provide-buffers + multishot recvmsg +
    # periodic timeout), all on H3-tagged tokens.
    h3_bootstrap(loop)

    # Event loop. Drain queued submissions from the handler after every
    # poll() tick — handlers cannot submit from inside on_complete
    # because the trait signature does not give them a loop reference.
    # The per-tick body is extracted into `_run_tick` to keep `main`'s
    # codegen unit small (large monolithic `main` bodies that mix the
    # generic loop with many free-function calls stress the lowering pass).
    while True:
        _run_tick(loop)
        _ = listener  # anchor: keep listener fd alive for io_uring
