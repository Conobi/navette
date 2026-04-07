# src/tls/lib.mojo
#
# RustlsLibrary — dynamically loaded librustls_mojo.so with TCP-TLS FFI.
#
# Follows the same OwnedDLHandle pattern as conformance/lib/rustls.mojo, but
# wraps the 13 TCP-TLS FFI symbols (4 config + 9 connection) plus the shared
# rlsm_last_error helper. The QUIC FFI symbols stay in conformance/lib/rustls
# for now and will be consolidated when QUIC lands at M3+.
from std.ffi import OwnedDLHandle
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc


struct RustlsLibrary(Movable):
    """Dynamically loaded librustls_mojo.so (TCP-TLS symbols)."""

    var _handle: OwnedDLHandle

    def __init__(out self, path: String = "lib/librustls_mojo.so") raises:
        self._handle = OwnedDLHandle(path)

    def __init__(out self, *, deinit take: Self):
        self._handle = take._handle^

    # -- Error retrieval -------------------------------------------------------

    def last_error(self) -> String:
        """Retrieve the last error message from the library.

        Returns an empty string if no error is set.
        """
        var buf = _heap_alloc[UInt8](512).as_any_origin()
        var n = self._handle.call["rlsm_last_error", Int32](buf, Int32(512))
        if n <= 0:
            buf.free()
            return String("")
        # n includes the NUL terminator; the message is n-1 bytes.
        var msg = String()
        for i in range(Int(n - 1)):
            msg += chr(Int(buf[i]))
        buf.free()
        return msg^

    # -- Config: client --------------------------------------------------------

    @always_inline
    def client_config_new(self) -> Int32:
        """Create a TLS client config with Mozilla WebPKI roots.

        Returns a positive handle on success, or -1 on error.
        """
        return self._handle.call["rlsm_client_config_new", Int32]()

    @always_inline
    def client_config_new_insecure(self) -> Int32:
        """Create an insecure TLS client config that accepts any cert.

        Requires librustls_mojo.so built with --features insecure.
        Returns a positive handle on success, or -1 on error.
        """
        return self._handle.call["rlsm_client_config_new_insecure", Int32]()

    # -- Config: server --------------------------------------------------------

    @always_inline
    def server_config_new(
        self,
        cert_pem: UnsafePointer[UInt8, MutAnyOrigin],
        cert_len: Int32,
        key_pem: UnsafePointer[UInt8, MutAnyOrigin],
        key_len: Int32,
    ) -> Int32:
        """Create a TLS server config from a PEM cert chain and PEM private key.

        Returns a positive handle on success, or -1 on error.
        """
        return self._handle.call["rlsm_server_config_new", Int32](
            cert_pem, cert_len, key_pem, key_len,
        )

    # -- Config: free ----------------------------------------------------------

    @always_inline
    def config_free(self, handle: Int32) -> Int32:
        """Free a config handle. Returns 0 on success, or -1 if not found."""
        return self._handle.call["rlsm_config_free", Int32](handle)

    # -- Connection: create ----------------------------------------------------

    @always_inline
    def tls_client_new(
        self,
        config_handle: Int32,
        server_name: UnsafePointer[UInt8, MutAnyOrigin],
        name_len: Int32,
    ) -> Int32:
        """Create a TLS client connection bound to `config_handle`.

        `server_name` is the SNI hostname (UTF-8, not NUL-terminated).
        Returns a positive connection handle on success, or -1 on error.
        """
        return self._handle.call["rlsm_tls_client_new", Int32](
            config_handle, server_name, name_len,
        )

    @always_inline
    def tls_server_new(self, config_handle: Int32) -> Int32:
        """Create a TLS server connection bound to `config_handle`.

        Returns a positive connection handle on success, or -1 on error.
        """
        return self._handle.call["rlsm_tls_server_new", Int32](config_handle)

    # -- Connection: free ------------------------------------------------------

    @always_inline
    def tls_conn_free(self, handle: Int32) -> Int32:
        """Free a connection handle. Returns 0 on success, or -1 if not found."""
        return self._handle.call["rlsm_tls_conn_free", Int32](handle)

    # -- Connection: ciphertext I/O -------------------------------------------

    @always_inline
    def tls_conn_read_tls(
        self,
        handle: Int32,
        ciphertext: UnsafePointer[UInt8, MutAnyOrigin],
        ct_len: Int32,
    ) -> Int32:
        """Feed received ciphertext into the rustls state machine.

        Advances the state machine via process_new_packets() on the Rust side.
        Returns the number of bytes consumed, or -1 on error.
        """
        return self._handle.call["rlsm_tls_conn_read_tls", Int32](
            handle, ciphertext, ct_len,
        )

    @always_inline
    def tls_conn_write_tls(
        self,
        handle: Int32,
        out_buf: UnsafePointer[UInt8, MutAnyOrigin],
        buf_len: Int32,
    ) -> Int32:
        """Drain pending ciphertext from rustls into `out_buf`.

        Returns the number of bytes written, 0 if nothing pending, or -1 on
        error.
        """
        return self._handle.call["rlsm_tls_conn_write_tls", Int32](
            handle, out_buf, buf_len,
        )

    # -- Connection: plaintext I/O --------------------------------------------

    @always_inline
    def tls_conn_read_plaintext(
        self,
        handle: Int32,
        out_buf: UnsafePointer[UInt8, MutAnyOrigin],
        buf_len: Int32,
    ) -> Int32:
        """Read decrypted application data.

        Returns the number of bytes written, 0 if no data is currently
        available, or -1 on error.
        """
        return self._handle.call["rlsm_tls_conn_read_plaintext", Int32](
            handle, out_buf, buf_len,
        )

    @always_inline
    def tls_conn_write_plaintext(
        self,
        handle: Int32,
        data: UnsafePointer[UInt8, MutAnyOrigin],
        data_len: Int32,
    ) -> Int32:
        """Write plaintext application data to be encrypted.

        Returns the number of bytes consumed, or -1 on error.
        """
        return self._handle.call["rlsm_tls_conn_write_plaintext", Int32](
            handle, data, data_len,
        )

    # -- Connection: state -----------------------------------------------------

    @always_inline
    def tls_conn_is_handshaking(self, handle: Int32) -> Int32:
        """1 if the TLS handshake is in progress, 0 if complete, -1 on error."""
        return self._handle.call["rlsm_tls_conn_is_handshaking", Int32](handle)

    @always_inline
    def tls_conn_alpn(
        self,
        handle: Int32,
        out_buf: UnsafePointer[UInt8, MutAnyOrigin],
        buf_len: Int32,
    ) -> Int32:
        """Get the negotiated ALPN protocol identifier.

        Returns the number of bytes written, 0 if no ALPN was negotiated, or
        -1 on error.
        """
        return self._handle.call["rlsm_tls_conn_alpn", Int32](
            handle, out_buf, buf_len,
        )
