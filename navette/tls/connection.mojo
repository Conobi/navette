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

from .lib import SharedLibrary
from .config import TlsClientConfig, TlsServerConfig


comptime _IO_BUF_SIZE = 16384
# Ciphertext drain buffer must hold a full TLS record: up to 16384 bytes of
# plaintext payload plus record header (5 B), AEAD tag (16 B), content type
# (1 B), and a margin for any record-layer padding rustls may emit. We use
# 18432 (16 KiB + 2 KiB headroom) so a single `write_tls` call can always
# extract a full record without short-writing into the SliceWriter (which
# would surface as a rustls WriteZero error).
comptime _CIPHERTEXT_DRAIN_BUF_SIZE = 18432
comptime _ALPN_BUF_SIZE = 256


struct TlsConnection(Movable):
    """Sans-I/O TLS connection wrapping a rustls connection handle.

    Inbound flow:  receive_data(ciphertext) -> drain_plaintext() -> bytes
    Outbound flow: send_data(plaintext)     -> drain_ciphertext() -> bytes
    """

    var _lib: SharedLibrary
    var _handle: Int32
    var _ciphertext_out: List[UInt8]
    var _ct_drain_buf: UnsafePointer[UInt8, MutAnyOrigin]
    var _pt_drain_buf: UnsafePointer[UInt8, MutAnyOrigin]
    var _handshake_complete: Bool

    # -- Private constructor (used by factory methods) ------------------------

    def __init__(
        out self,
        *,
        _lib: SharedLibrary,
        _handle: Int32,
        var _ciphertext_out: List[UInt8],
        _ct_drain_buf: UnsafePointer[UInt8, MutAnyOrigin],
        _pt_drain_buf: UnsafePointer[UInt8, MutAnyOrigin],
        _handshake_complete: Bool,
    ):
        self._lib = SharedLibrary(other=_lib)
        self._handle = _handle
        self._ciphertext_out = _ciphertext_out^
        self._ct_drain_buf = _ct_drain_buf
        self._pt_drain_buf = _pt_drain_buf
        self._handshake_complete = _handshake_complete

    # -- Move / Destroy --------------------------------------------------------

    def __init__(out self, *, deinit take: Self):
        self._lib = take._lib^
        self._handle = take._handle
        self._ciphertext_out = take._ciphertext_out^
        self._ct_drain_buf = take._ct_drain_buf
        self._pt_drain_buf = take._pt_drain_buf
        self._handshake_complete = take._handshake_complete

    def __del__(deinit self):
        if self._handle >= 0:
            _ = self._lib.inner_ptr()[].tls_conn_free(self._handle)
        self._ct_drain_buf.free()
        self._pt_drain_buf.free()

    # -- Construction ----------------------------------------------------------

    @staticmethod
    def new_client(
        lib: SharedLibrary,
        ref config: TlsClientConfig,
        server_name: String,
    ) raises -> Self:
        """Create a TLS client connection.

        Immediately drains the initial ClientHello into the internal
        ciphertext-out buffer so the caller can grab it via
        `drain_ciphertext()` right after construction.

        Args:
            lib: SharedLibrary handle (refcount is incremented).
            config: Client config (must outlive the connection).
            server_name: SNI hostname (e.g. "localhost").
        """
        var rlib = lib.inner_ptr()
        var name_bytes = server_name.as_bytes()
        var name_len = len(name_bytes)
        var name_buf = _heap_alloc[UInt8](name_len).as_any_origin()
        for i in range(name_len):
            name_buf[i] = name_bytes[i]

        var handle = rlib[].tls_client_new(
            config.handle(),
            name_buf,
            Int32(name_len),
        )
        name_buf.free()

        if handle < 0:
            raise "rlsm_tls_client_new failed: " + rlib[].last_error()

        # Drain the ClientHello immediately so the caller can send it.
        # We allocate the ciphertext drain buffer here and reuse it as the
        # struct's pre-allocated buffer (no double allocation).
        var ct_out = List[UInt8]()
        var init_ct_buf = _heap_alloc[UInt8](_CIPHERTEXT_DRAIN_BUF_SIZE).as_any_origin()
        try:
            while True:
                var dn = rlib[].tls_conn_write_tls(
                    handle, init_ct_buf, Int32(_CIPHERTEXT_DRAIN_BUF_SIZE)
                )
                if dn < 0:
                    init_ct_buf.free()
                    raise "rlsm_tls_conn_write_tls failed: " + rlib[].last_error()
                if dn == 0:
                    break
                for di in range(Int(dn)):
                    ct_out.append(init_ct_buf[di])
        except e:
            init_ct_buf.free()
            _ = rlib[].tls_conn_free(handle)
            raise e.copy()

        return Self(
            _lib=lib,
            _handle=handle,
            _ciphertext_out=ct_out^,
            _ct_drain_buf=init_ct_buf,
            _pt_drain_buf=_heap_alloc[UInt8](_IO_BUF_SIZE).as_any_origin(),
            _handshake_complete=False,
        )

    @staticmethod
    def new_server(
        lib: SharedLibrary,
        ref config: TlsServerConfig,
    ) raises -> Self:
        """Create a TLS server connection.

        The server has nothing to send until it has received a ClientHello,
        so the internal ciphertext-out buffer starts empty.
        """
        var rlib = lib.inner_ptr()
        var handle = rlib[].tls_server_new(config.handle())
        if handle < 0:
            raise "rlsm_tls_server_new failed: " + rlib[].last_error()

        return Self(
            _lib=lib,
            _handle=handle,
            _ciphertext_out=List[UInt8](),
            _ct_drain_buf=_heap_alloc[UInt8](_CIPHERTEXT_DRAIN_BUF_SIZE).as_any_origin(),
            _pt_drain_buf=_heap_alloc[UInt8](_IO_BUF_SIZE).as_any_origin(),
            _handshake_complete=False,
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

        var rc = self._lib.inner_ptr()[].tls_conn_read_tls(
            self._handle,
            ciphertext.unsafe_ptr().unsafe_mut_cast[True]().as_any_origin(),
            Int32(n),
        )

        if rc < 0:
            raise (
                "rlsm_tls_conn_read_tls failed: "
                + self._lib.inner_ptr()[].last_error()
            )

        self._drain_write_tls()

        if not self._handshake_complete:
            var hs = self._lib.inner_ptr()[].tls_conn_is_handshaking(self._handle)
            if hs == Int32(0):
                self._handshake_complete = True

    def drain_plaintext(mut self) raises -> List[UInt8]:
        """Return any decrypted plaintext available after `receive_data`.

        Loops `rlsm_tls_conn_read_plaintext` until it returns 0 (no more
        decrypted data right now). Returns an empty list during the
        handshake or whenever the peer has not yet sent any application
        data. Raises on FFI errors so close_notify / fatal alerts surface
        rather than being indistinguishable from "no data yet".
        """
        var result = List[UInt8]()
        while True:
            var n = self._lib.inner_ptr()[].tls_conn_read_plaintext(
                self._handle, self._pt_drain_buf, Int32(_IO_BUF_SIZE)
            )
            if n < 0:
                raise (
                    "rlsm_tls_conn_read_plaintext failed: "
                    + self._lib.inner_ptr()[].last_error()
                )
            if n == 0:
                break
            for i in range(Int(n)):
                result.append(self._pt_drain_buf[i])
        return result^

    # -- Outbound: plaintext -> ciphertext -------------------------------------

    def send_data(mut self, plaintext: Span[UInt8, _]) raises:
        """Encrypt plaintext. The resulting ciphertext is buffered
        internally; retrieve it with `drain_ciphertext`.
        """
        var n = len(plaintext)
        if n == 0:
            return

        var rc = self._lib.inner_ptr()[].tls_conn_write_plaintext(
            self._handle,
            plaintext.unsafe_ptr().unsafe_mut_cast[True]().as_any_origin(),
            Int32(n),
        )
        if rc < 0:
            raise (
                "rlsm_tls_conn_write_plaintext failed: "
                + self._lib.inner_ptr()[].last_error()
            )

        self._drain_write_tls()

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
        return not self._handshake_complete

    def wants_write(self) -> Bool:
        """True if there is buffered ciphertext waiting to be sent."""
        return len(self._ciphertext_out) > 0

    def alpn(self) raises -> Optional[String]:
        """Return the negotiated ALPN protocol identifier, or None.

        The buffer is sized to fit any realistic ALPN identifier (256 B —
        ALPN strings in practice are short tokens like "h2", "http/1.1",
        "h3"). The Rust FFI returns -1 if it would have to truncate, so
        any -1 here is a real error rather than silent data loss.
        """
        var buf = _heap_alloc[UInt8](_ALPN_BUF_SIZE).as_any_origin()
        var n = self._lib.inner_ptr()[].tls_conn_alpn(
            self._handle, buf, Int32(_ALPN_BUF_SIZE)
        )
        if n < 0:
            var err = self._lib.inner_ptr()[].last_error()
            buf.free()
            raise "rlsm_tls_conn_alpn failed: " + err
        if n == 0:
            buf.free()
            return Optional[String](None)
        var s = String()
        for i in range(Int(n)):
            s += chr(Int(buf[i]))
        buf.free()
        return Optional[String](s^)

    # -- Internal --------------------------------------------------------------

    def _drain_write_tls(mut self) raises:
        """Drain all pending ciphertext from rustls into `_ciphertext_out`."""
        while True:
            var n = self._lib.inner_ptr()[].tls_conn_write_tls(
                self._handle,
                self._ct_drain_buf,
                Int32(_CIPHERTEXT_DRAIN_BUF_SIZE),
            )
            if n < 0:
                raise (
                    "rlsm_tls_conn_write_tls failed: "
                    + self._lib.inner_ptr()[].last_error()
                )
            if n == 0:
                break
            for i in range(Int(n)):
                self._ciphertext_out.append(self._ct_drain_buf[i])

