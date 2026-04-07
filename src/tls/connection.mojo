# src/tls/connection.mojo
#
# Sans-I/O TLS connection wrapper.
#
# A TlsConnection wraps a rustls connection handle and exposes a feed/drain
# API. Callers shovel ciphertext in (`receive_data`) and pull plaintext out
# (`drain_plaintext`); they push plaintext in (`send_data`) and pull
# ciphertext out (`drain_ciphertext`). No sockets, no I/O.
#
# After construction (especially for clients) and after every `receive_data`
# / `send_data` call, any pending outbound ciphertext is automatically
# drained from rustls into the internal `_ciphertext_out` buffer so the
# handshake loop stays trivial:
#
#     while tls.is_handshaking():
#         tls.receive_data(network_in)
#         if tls.wants_write():
#             network_out = tls.drain_ciphertext()
#             ... send to peer ...
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.collections.optional import Optional
from std.memory import Span

from .lib import RustlsLibrary
from .config import TlsClientConfig, TlsServerConfig


comptime _IO_BUF_SIZE = 16384
comptime _ALPN_BUF_SIZE = 64


def _drain_write_tls(
    ref lib: RustlsLibrary,
    handle: Int32,
    mut out: List[UInt8],
) raises:
    """Drain all pending ciphertext from a connection into `out`.

    Loops `rlsm_tls_conn_write_tls` until the rustls write buffer reports
    nothing more to send. Raises if the underlying FFI returns a negative
    value so TLS alerts and fatal handshake errors propagate up.
    """
    var buf = _heap_alloc[UInt8](_IO_BUF_SIZE).as_any_origin()
    while True:
        var n = lib.tls_conn_write_tls(handle, buf, Int32(_IO_BUF_SIZE))
        if n < 0:
            var err = lib.last_error()
            buf.free()
            raise "rlsm_tls_conn_write_tls failed: " + err
        if n == 0:
            break
        for i in range(Int(n)):
            out.append(buf[i])
    buf.free()


struct TlsConnection(Movable):
    """Sans-I/O TLS connection wrapping a rustls connection handle.

    Inbound flow:  receive_data(ciphertext) -> drain_plaintext() -> bytes
    Outbound flow: send_data(plaintext)     -> drain_ciphertext() -> bytes
    """

    var _lib_addr: UInt64
    var _handle: Int32
    var _ciphertext_out: List[UInt8]

    # -- Private constructor (used by factory methods) ------------------------

    def __init__(
        out self,
        *,
        _lib_addr: UInt64,
        _handle: Int32,
        var _ciphertext_out: List[UInt8],
    ):
        self._lib_addr = _lib_addr
        self._handle = _handle
        self._ciphertext_out = _ciphertext_out^

    # -- Move / Destroy --------------------------------------------------------

    def __init__(out self, *, deinit take: Self):
        self._lib_addr = take._lib_addr
        self._handle = take._handle
        self._ciphertext_out = take._ciphertext_out^

    def __del__(deinit self):
        if self._handle > 0:
            _ = self._lib()[].tls_conn_free(self._handle)

    # -- Construction ----------------------------------------------------------

    @staticmethod
    def new_client(
        ref lib: RustlsLibrary,
        ref config: TlsClientConfig,
        server_name: String,
    ) raises -> Self:
        """Create a TLS client connection.

        Immediately drains the initial ClientHello into the internal
        ciphertext-out buffer so the caller can grab it via
        `drain_ciphertext()` right after construction.

        Args:
            lib: The loaded RustlsLibrary (must outlive the connection).
            config: Client config (must outlive the connection).
            server_name: SNI hostname (e.g. "localhost").
        """
        var name_bytes = server_name.as_bytes()
        var name_len = len(name_bytes)
        var name_buf = _heap_alloc[UInt8](name_len).as_any_origin()
        for i in range(name_len):
            name_buf[i] = name_bytes[i]

        var handle = lib.tls_client_new(
            config.handle(),
            name_buf,
            Int32(name_len),
        )
        name_buf.free()

        if handle < 0:
            raise "rlsm_tls_client_new failed: " + lib.last_error()

        # Drain the ClientHello immediately so the caller can send it.
        # If draining fails, free the rustls handle before propagating to
        # avoid leaking it (no destructor runs since construction failed).
        var ct_out = List[UInt8]()
        try:
            _drain_write_tls(lib, handle, ct_out)
        except e:
            _ = lib.tls_conn_free(handle)
            raise e.copy()

        return Self(
            _lib_addr=UInt64(Int(UnsafePointer(to=lib))),
            _handle=handle,
            _ciphertext_out=ct_out^,
        )

    @staticmethod
    def new_server(
        ref lib: RustlsLibrary,
        ref config: TlsServerConfig,
    ) raises -> Self:
        """Create a TLS server connection.

        The server has nothing to send until it has received a ClientHello,
        so the internal ciphertext-out buffer starts empty.
        """
        var handle = lib.tls_server_new(config.handle())
        if handle < 0:
            raise "rlsm_tls_server_new failed: " + lib.last_error()

        return Self(
            _lib_addr=UInt64(Int(UnsafePointer(to=lib))),
            _handle=handle,
            _ciphertext_out=List[UInt8](),
        )

    # -- Inbound: ciphertext -> plaintext --------------------------------------

    def receive_data(mut self, ciphertext: Span[UInt8, _]) raises:
        """Feed received ciphertext into the TLS state machine.

        Any handshake replies / encrypted alerts that rustls produces in
        response are automatically drained into the internal
        ciphertext-out buffer so the caller can pick them up with
        `drain_ciphertext()`.

        The Rust FFI loops `read_tls` + `process_new_packets` internally
        until either the input is fully consumed or rustls' deframer cannot
        make progress, so a single FFI call is sufficient here.
        """
        var n = len(ciphertext)
        if n == 0:
            return

        var buf = _heap_alloc[UInt8](n).as_any_origin()
        for i in range(n):
            buf[i] = ciphertext[i]

        var rc = self._lib()[].tls_conn_read_tls(
            self._handle, buf, Int32(n)
        )
        buf.free()

        if rc < 0:
            raise (
                "rlsm_tls_conn_read_tls failed: "
                + self._lib()[].last_error()
            )

        _drain_write_tls(
            self._lib()[], self._handle, self._ciphertext_out
        )

    def drain_plaintext(mut self) raises -> List[UInt8]:
        """Return any decrypted plaintext available after `receive_data`.

        Loops `rlsm_tls_conn_read_plaintext` until it returns 0 (no more
        decrypted data right now). Returns an empty list during the
        handshake or whenever the peer has not yet sent any application
        data. Raises on FFI errors so close_notify / fatal alerts surface
        rather than being indistinguishable from "no data yet".
        """
        var buf = _heap_alloc[UInt8](_IO_BUF_SIZE).as_any_origin()
        var result = List[UInt8]()

        while True:
            var n = self._lib()[].tls_conn_read_plaintext(
                self._handle, buf, Int32(_IO_BUF_SIZE)
            )
            if n < 0:
                var err = self._lib()[].last_error()
                buf.free()
                raise "rlsm_tls_conn_read_plaintext failed: " + err
            if n == 0:
                break
            for i in range(Int(n)):
                result.append(buf[i])

        buf.free()
        return result^

    # -- Outbound: plaintext -> ciphertext -------------------------------------

    def send_data(mut self, plaintext: Span[UInt8, _]) raises:
        """Encrypt plaintext. The resulting ciphertext is buffered
        internally; retrieve it with `drain_ciphertext`.
        """
        var n = len(plaintext)
        if n == 0:
            return

        var buf = _heap_alloc[UInt8](n).as_any_origin()
        for i in range(n):
            buf[i] = plaintext[i]

        var rc = self._lib()[].tls_conn_write_plaintext(
            self._handle, buf, Int32(n)
        )
        buf.free()
        if rc < 0:
            raise (
                "rlsm_tls_conn_write_plaintext failed: "
                + self._lib()[].last_error()
            )

        _drain_write_tls(
            self._lib()[], self._handle, self._ciphertext_out
        )

    def drain_ciphertext(mut self) -> List[UInt8]:
        """Return all buffered ciphertext, clearing the internal buffer.

        This is the data that must be sent to the peer over the network.
        """
        var out = self._ciphertext_out^
        self._ciphertext_out = List[UInt8]()
        return out^

    # -- State -----------------------------------------------------------------

    def is_handshaking(self) -> Bool:
        """True if the TLS handshake is still in progress."""
        var rc = self._lib()[].tls_conn_is_handshaking(self._handle)
        return rc == Int32(1)

    def wants_write(self) -> Bool:
        """True if there is buffered ciphertext waiting to be sent."""
        return len(self._ciphertext_out) > 0

    def alpn(self) -> Optional[String]:
        """Return the negotiated ALPN protocol identifier, or None."""
        var buf = _heap_alloc[UInt8](_ALPN_BUF_SIZE).as_any_origin()
        var n = self._lib()[].tls_conn_alpn(
            self._handle, buf, Int32(_ALPN_BUF_SIZE)
        )
        if n <= 0:
            buf.free()
            return Optional[String](None)
        var s = String()
        for i in range(Int(n)):
            s += chr(Int(buf[i]))
        buf.free()
        return Optional[String](s^)

    # -- Internal --------------------------------------------------------------

    @always_inline
    def _lib(self) -> UnsafePointer[RustlsLibrary, MutAnyOrigin]:
        return UnsafePointer[RustlsLibrary, MutAnyOrigin](
            unsafe_from_address=Int(self._lib_addr)
        )
