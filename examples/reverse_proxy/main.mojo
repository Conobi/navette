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
#   $ python3 ../../scripts/test_backend.py &
#   $ LD_LIBRARY_PATH=../../lib ./mojo_reverse_proxy
#
# Env-var knobs (no CLI flags; the smoke harness drives via env):
#   LISTEN_PORT          (default 8443)
#   H1_BACKEND_PORT      (default 9443)
#   H2_BACKEND_PORT      (default H1_BACKEND_PORT)
#   BACKEND_HOST         (default "localhost")

from std.collections.optional import Optional
from std.ffi import external_call
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from mojo_net.tls import (
    RustlsLibrary,
    TlsClientConfig,
    TlsServerConfig,
    TlsConnection,
)

from boucle import CompletionLoop, CompletionHandler
from boucle.handle import OwnedHandle
from boucle.net.socket import Socket
from boucle.net.addr import SocketAddrV4, SocketAddrStorV4
from boucle.net.options import (
    Backlog,
    AddrFamily,
    SocketType,
    SocketFlags,
    Protocol,
)
from boucle._sys.linux.net.socket import socket as _sys_socket

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
    stage_backend_send,
    stage_client_send,
)
from proxy_h1 import (
    H1ProxyState,
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


# ---------------------------------------------------------------------------
# Env-var helpers (matches examples/hello_h1_server pattern)
# ---------------------------------------------------------------------------


fn _getenv_str(name: String, default: String) -> String:
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


fn _getenv_int(name: String, default: Int) -> Int:
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
# `SessionSlot`, `RequestBody`, `H2Event` in mojo_net for precedents).


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

    fn __init__(out self, *, deinit take: Self):
        self.tag = take.tag
        self.h1_state = take.h1_state^
        self.h2_state = take.h2_state^

    @staticmethod
    fn handshaking() -> Self:
        return Self(
            tag=_VARIANT_HANDSHAKING,
            h1_state=Optional[H1ProxyState](),
            h2_state=Optional[H2ProxyState](),
        )

    @staticmethod
    fn h1(var s: H1ProxyState) -> Self:
        return Self(
            tag=_VARIANT_H1,
            h1_state=Optional[H1ProxyState](s^),
            h2_state=Optional[H2ProxyState](),
        )

    @staticmethod
    fn h2(var s: H2ProxyState) -> Self:
        return Self(
            tag=_VARIANT_H2,
            h1_state=Optional[H1ProxyState](),
            h2_state=Optional[H2ProxyState](s^),
        )

    @always_inline
    fn is_handshaking(self) -> Bool:
        return self.tag == _VARIANT_HANDSHAKING

    @always_inline
    fn is_h1(self) -> Bool:
        return self.tag == _VARIANT_H1

    @always_inline
    fn is_h2(self) -> Bool:
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
    var tls_lib: RustlsLibrary
    var server_tls_config: TlsServerConfig
    var h1_client_tls_config: TlsClientConfig
    var h2_client_tls_config: TlsClientConfig
    var h1_backend_addr: SocketAddrV4
    var h2_backend_addr: SocketAddrV4
    var backend_host: String
    var pending_submits: List[PendingSubmit]

    def __init__(
        out self,
        listener_fd: Int32,
        var tls_lib: RustlsLibrary,
        var server_tls_config: TlsServerConfig,
        var h1_client_tls_config: TlsClientConfig,
        var h2_client_tls_config: TlsClientConfig,
        h1_backend_addr: SocketAddrV4,
        h2_backend_addr: SocketAddrV4,
        backend_host: String,
    ):
        self.listener_fd = listener_fd
        self.connections = List[
            UnsafePointer[ProxyConnection, MutAnyOrigin]
        ]()
        self.next_conn_id = 1
        self.tls_lib = tls_lib^
        self.server_tls_config = server_tls_config^
        self.h1_client_tls_config = h1_client_tls_config^
        self.h2_client_tls_config = h2_client_tls_config^
        self.h1_backend_addr = h1_backend_addr
        self.h2_backend_addr = h2_backend_addr
        self.backend_host = backend_host
        self.pending_submits = List[PendingSubmit]()

    fn __moveinit__(out self, deinit take: Self):
        self.listener_fd = take.listener_fd
        self.connections = take.connections^
        self.next_conn_id = take.next_conn_id
        self.tls_lib = take.tls_lib^
        self.server_tls_config = take.server_tls_config^
        self.h1_client_tls_config = take.h1_client_tls_config^
        self.h2_client_tls_config = take.h2_client_tls_config^
        self.h1_backend_addr = take.h1_backend_addr
        self.h2_backend_addr = take.h2_backend_addr
        self.backend_host = take.backend_host^
        self.pending_submits = take.pending_submits^

    # --- Connection lookup ----------------------------------------------

    def _find_index(self, conn_id: UInt64) -> Int:
        """Return the index of the connection with `conn_id`, or -1."""
        for i in range(len(self.connections)):
            if self.connections[i][].conn_id == conn_id:
                return i
        return -1

    # --- on_complete dispatch -------------------------------------------

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
            self.tls_lib, self.server_tls_config
        )

        # Create the backend TCP socket up front so we have an fd to
        # connect once we know which backend to dial.
        var backend_handle = _sys_socket(
            AddrFamily.INET,
            SocketType.STREAM,
            SocketFlags.NONBLOCK | SocketFlags.CLOEXEC,
            Protocol.TCP,
        )

        # The actual backend addr is decided post-ALPN; seed with H1.
        var backend_addr_stor = self.h1_backend_addr.addr_stor()

        # A placeholder backend TLS connection. Replaced post-ALPN.
        var backend_tls = TlsConnection.new_client(
            self.tls_lib, self.h1_client_tls_config, self.backend_host
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
        var conn_ptr = _heap_alloc[ProxyConnection](1).as_any_origin()
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
                self.tls_lib,
                self.h2_client_tls_config,
                self.backend_host,
            )
            ptr[].backend_tls = backend_tls^
        else:
            var h1 = h1_proxy_state_new()
            ptr[].variant = ProxyVariant.h1(h1^)
            ptr[].backend_addr_stor = self.h1_backend_addr.addr_stor()
            var backend_tls = TlsConnection.new_client(
                self.tls_lib,
                self.h1_client_tls_config,
                self.backend_host,
            )
            ptr[].backend_tls = backend_tls^

        # For the H2 path, surface any decrypted plaintext that arrived
        # along with the handshake-final TLS record into the streaming
        # server so it can emit settings ACKs.
        # We also need the variant handlers to take it from here, so we
        # simply re-arm a client_recv: the next batch of inbound bytes
        # will route through the variant handler, which is the natural
        # place to drain remaining handshake-trailing plaintext.
        # Drain any plaintext now so the variant handler doesn't miss
        # the bytes that arrived in the handshake-final record.
        var plaintext = ptr[].client_tls.drain_plaintext()
        if len(plaintext) > 0:
            if ptr[].variant.is_h2():
                # Feed into the H2 streaming server; its drain() will
                # surface the server-preface frames + any frames it
                # parsed from the first inbound record.
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
            elif ptr[].variant.is_h1():
                ptr[].variant.h1_state.value().client_http.receive_data(
                    Span(plaintext)
                )

        # H2 still needs to flush its server preface even without
        # client-side plaintext arriving with the handshake.
        if ptr[].variant.is_h2():
            var preface = ptr[].variant.h2_state.value().client_h2.drain()
            if len(preface) > 0:
                ptr[].client_tls.send_data(Span(preface))
                var ct2 = ptr[].client_tls.drain_ciphertext()
                stage_client_send(
                    ptr[].send_state,
                    self.pending_submits,
                    ptr[].client_handle.raw(),
                    ptr[].conn_id,
                    ct2^,
                )

        # Transition to BACKEND_CONNECTING and queue the connect.
        ptr[].phase = PHASE_BACKEND_CONNECTING
        self.pending_submits.append(
            PendingSubmit(
                kind=SUBMIT_CONNECT,
                fd=ptr[].backend_handle.raw(),
                conn_id=ptr[].conn_id,
                op_kind=OP_BACKEND_CONNECT,
            )
        )
        # Also continue reading from the client so we don't miss any
        # follow-up frames (especially relevant for H2 multiplexing).
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

    def _close_connection(mut self, idx: Int):
        """Drop the connection: run its destructor (closes fds via the
        OwnedHandle fields) and free the heap slot."""
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
# main
# ---------------------------------------------------------------------------


def main() raises:
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

    var h1_backend_addr = SocketAddrV4(127, 0, 0, 1, port=h1_backend_port)
    var h2_backend_addr = SocketAddrV4(127, 0, 0, 1, port=h2_backend_port)

    # Load TLS material.
    var proxy_cert = _read_file(_CERT_DIR + "/proxy_cert.pem")
    var proxy_key = _read_file(_CERT_DIR + "/proxy_key.pem")

    # Initialize TLS library + dual-ALPN server config.
    var tls_lib = RustlsLibrary()
    var server_config = TlsServerConfig(
        tls_lib, Span(proxy_cert), Span(proxy_key)
    )
    var server_alpn = List[String]()
    server_alpn.append(String("h2"))
    server_alpn.append(String("http/1.1"))
    server_config.set_alpn_protocols(tls_lib, server_alpn)

    # Two client configs, each pinned to one ALPN. Self-signed backend
    # cert — use insecure client config (requires librustls_mojo.so
    # built with --features insecure).
    var h1_client_config = TlsClientConfig(tls_lib, insecure=True)
    var h1_alpn = List[String]()
    h1_alpn.append(String("http/1.1"))
    h1_client_config.set_alpn_protocols(tls_lib, h1_alpn)

    var h2_client_config = TlsClientConfig(tls_lib, insecure=True)
    var h2_alpn = List[String]()
    h2_alpn.append(String("h2"))
    h2_client_config.set_alpn_protocols(tls_lib, h2_alpn)

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
        tls_lib=tls_lib^,
        server_tls_config=server_config^,
        h1_client_tls_config=h1_client_config^,
        h2_client_tls_config=h2_client_config^,
        h1_backend_addr=h1_backend_addr,
        h2_backend_addr=h2_backend_addr,
        backend_host=backend_host,
    )
    var loop = CompletionLoop[ProxyHandler](handler^, sq_entries=256)

    # Submit the initial accept.
    loop.submit_accept(listener_fd, encode_token(LISTENER_CONN_ID, OP_ACCEPT))

    # Event loop. Drain queued submissions from the handler after every
    # poll() tick — handlers cannot submit from inside on_complete
    # because the trait signature does not give them a loop reference.
    while True:
        loop.poll(wait_nr=1)
        _drain_pending_submits(loop)
        _ = listener  # anchor: keep listener fd alive for io_uring
