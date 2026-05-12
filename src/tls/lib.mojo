# src/tls/lib.mojo
#
# RustlsLibrary — dynamically loaded librustls_mojo.so with TCP-TLS FFI.
#
# Follows the same OwnedDLHandle pattern as conformance/lib/rustls.mojo, but
# wraps the 13 TCP-TLS FFI symbols (4 config + 9 connection) plus the shared
# rlsm_last_error helper. QUIC FFI symbols consolidated from
# conformance/lib/rustls.mojo as of M3b.
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

    # -- Config: ALPN ----------------------------------------------------------

    @always_inline
    def config_set_alpn_protocols(
        self,
        config_handle: Int32,
        protocols: UnsafePointer[UInt8, MutAnyOrigin],
        protocols_len: Int32,
    ) -> Int32:
        """Set ALPN protocol preferences on a config handle.

        protocols is a length-prefixed wire format buffer.
        Returns 0 on success, -1 on error.
        """
        return self._handle.call["rlsm_config_set_alpn_protocols", Int32](
            config_handle, protocols, protocols_len,
        )

    # -- QUIC Wave 1: keys + AEAD + HP ----------------------------------------

    @always_inline
    def initial_keys(
        self,
        version: Int32,
        dcid: UnsafePointer[UInt8, MutAnyOrigin],
        dcid_len: Int32,
        is_client: Int32,
    ) -> Int32:
        """Derive QUIC Initial keys, returning a handle.

        Returns a positive handle on success, -1 on error.
        """
        return self._handle.call["rlsm_initial_keys", Int32](
            version, dcid, dcid_len, is_client,
        )

    @always_inline
    def keys_tag_len(self, keys_handle: Int32) -> Int32:
        """Return AEAD tag length (16 for AES-128-GCM). -1 on error."""
        return self._handle.call["rlsm_keys_tag_len", Int32](keys_handle)

    @always_inline
    def keys_local_encrypt(
        self,
        keys_handle: Int32,
        packet_number: UInt64,
        header: UnsafePointer[UInt8, MutAnyOrigin],
        header_len: Int32,
        payload: UnsafePointer[UInt8, MutAnyOrigin],
        payload_len: Int32,
        buf_capacity: Int32,
    ) -> Int32:
        """Encrypt payload in-place. Returns ciphertext length or -1."""
        return self._handle.call["rlsm_keys_local_encrypt", Int32](
            keys_handle, packet_number,
            header, header_len,
            payload, payload_len, buf_capacity,
        )

    @always_inline
    def keys_remote_decrypt(
        self,
        keys_handle: Int32,
        packet_number: UInt64,
        header: UnsafePointer[UInt8, MutAnyOrigin],
        header_len: Int32,
        payload: UnsafePointer[UInt8, MutAnyOrigin],
        payload_len: Int32,
    ) -> Int32:
        """Decrypt payload in-place. Returns plaintext length or -1."""
        return self._handle.call["rlsm_keys_remote_decrypt", Int32](
            keys_handle, packet_number,
            header, header_len,
            payload, payload_len,
        )

    @always_inline
    def keys_local_header_protect(
        self,
        keys_handle: Int32,
        sample: UnsafePointer[UInt8, MutAnyOrigin],
        sample_len: Int32,
        first_byte: UnsafePointer[UInt8, MutAnyOrigin],
        pn_bytes: UnsafePointer[UInt8, MutAnyOrigin],
        pn_len: Int32,
    ) -> Int32:
        """Apply header protection (local/encrypt direction). Returns 0 or -1."""
        return self._handle.call["rlsm_keys_local_header_protect", Int32](
            keys_handle, sample, sample_len,
            first_byte, pn_bytes, pn_len,
        )

    @always_inline
    def keys_remote_header_unprotect(
        self,
        keys_handle: Int32,
        sample: UnsafePointer[UInt8, MutAnyOrigin],
        sample_len: Int32,
        first_byte: UnsafePointer[UInt8, MutAnyOrigin],
        pn_bytes: UnsafePointer[UInt8, MutAnyOrigin],
        pn_len: Int32,
    ) -> Int32:
        """Remove header protection (remote/decrypt direction). Returns 0 or -1."""
        return self._handle.call["rlsm_keys_remote_header_unprotect", Int32](
            keys_handle, sample, sample_len,
            first_byte, pn_bytes, pn_len,
        )

    @always_inline
    def keys_batch_header_unprotect(
        self,
        keys_handle: Int32,
        count: Int32,
        packet_ptrs: UnsafePointer[UnsafePointer[UInt8, MutAnyOrigin], MutAnyOrigin],
        packet_lens: UnsafePointer[Int32, MutAnyOrigin],
        pn_offsets: UnsafePointer[Int32, MutAnyOrigin],
        out_first_bytes: UnsafePointer[UInt8, MutAnyOrigin],
        out_pn_lengths: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Batch header unprotection. Returns success count or -1."""
        return self._handle.call[
            "rlsm_keys_batch_header_unprotect", Int32
        ](
            keys_handle, count,
            packet_ptrs, packet_lens, pn_offsets,
            out_first_bytes, out_pn_lengths,
        )

    @always_inline
    def keys_batch_decrypt(
        self,
        keys_handle: Int32,
        count: Int32,
        packet_numbers: UnsafePointer[UInt64, MutAnyOrigin],
        packet_ptrs: UnsafePointer[UnsafePointer[UInt8, MutAnyOrigin], MutAnyOrigin],
        packet_lens: UnsafePointer[Int32, MutAnyOrigin],
        header_lens: UnsafePointer[Int32, MutAnyOrigin],
        out_plaintext_lens: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Batch AEAD decryption. Returns success count or -1."""
        return self._handle.call[
            "rlsm_keys_batch_decrypt", Int32
        ](
            keys_handle, count,
            packet_numbers, packet_ptrs, packet_lens, header_lens,
            out_plaintext_lens,
        )

    @always_inline
    def keys_batch_header_protect(
        self,
        keys_handle: Int32,
        count: Int32,
        packet_ptrs: UnsafePointer[UnsafePointer[UInt8, MutAnyOrigin], MutAnyOrigin],
        packet_lens: UnsafePointer[Int32, MutAnyOrigin],
        pn_offsets: UnsafePointer[Int32, MutAnyOrigin],
        pn_lengths: UnsafePointer[Int32, MutAnyOrigin],
        out_results: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Batch header protection. Returns success count or -1."""
        return self._handle.call[
            "rlsm_keys_batch_header_protect", Int32
        ](
            keys_handle, count,
            packet_ptrs, packet_lens, pn_offsets, pn_lengths,
            out_results,
        )

    @always_inline
    def keys_batch_encrypt(
        self,
        keys_handle: Int32,
        count: Int32,
        packet_numbers: UnsafePointer[UInt64, MutAnyOrigin],
        packet_ptrs: UnsafePointer[UnsafePointer[UInt8, MutAnyOrigin], MutAnyOrigin],
        header_lens: UnsafePointer[Int32, MutAnyOrigin],
        payload_lens: UnsafePointer[Int32, MutAnyOrigin],
        buf_capacities: UnsafePointer[Int32, MutAnyOrigin],
        out_ciphertext_lens: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Batch AEAD encryption. Returns success count or -1."""
        return self._handle.call[
            "rlsm_keys_batch_encrypt", Int32
        ](
            keys_handle, count,
            packet_numbers, packet_ptrs,
            header_lens, payload_lens, buf_capacities,
            out_ciphertext_lens,
        )

    @always_inline
    def keys_free(self, keys_handle: Int32) -> Int32:
        """Free keys. Returns 0 on success, -1 if handle not found."""
        return self._handle.call["rlsm_keys_free", Int32](keys_handle)

    # -- QUIC Wave 2: handshake ------------------------------------------------

    @always_inline
    def quic_client_config_new(
        self,
        alpn_ptr: UnsafePointer[UInt8, MutAnyOrigin], alpn_len: Int32,
        out_handle: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Create a QUIC client TLS config with Mozilla WebPKI roots.

        Returns 0 on success, -1 on error. Handle written to out_handle.
        """
        return self._handle.call["rlsm_quic_client_config_new", Int32](
            alpn_ptr, alpn_len, out_handle,
        )

    @always_inline
    def quic_client_config_new_insecure(
        self,
        alpn_ptr: UnsafePointer[UInt8, MutAnyOrigin], alpn_len: Int32,
        out_handle: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Create a QUIC client TLS config that accepts ANY server cert.

        **Insecure** — feature-gated (`insecure` Cargo feature). Use only
        for local dev / CLI tools against self-signed certs.
        Returns 0 on success, -1 on error. Handle written to out_handle.
        """
        return self._handle.call["rlsm_quic_client_config_new_insecure", Int32](
            alpn_ptr, alpn_len, out_handle,
        )

    @always_inline
    def quic_server_config_new(
        self,
        cert_pem: UnsafePointer[UInt8, MutAnyOrigin], cert_len: Int32,
        key_pem:  UnsafePointer[UInt8, MutAnyOrigin], key_len:  Int32,
        alpn_ptr: UnsafePointer[UInt8, MutAnyOrigin], alpn_len: Int32,
        max_early_data: Int32,
        out_handle: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Create QUIC server TLS config. Always-on TLS 1.3 session resumption
        (rustls aws_lc_rs Ticketer). max_early_data: 0 disables 0-RTT (default);
        non-zero plumbs to ServerConfig::max_early_data_size for P3.
        Returns 0 on success, -1 on error."""
        return self._handle.call["rlsm_quic_server_config_new", Int32](
            cert_pem, cert_len, key_pem, key_len, alpn_ptr, alpn_len,
            max_early_data, out_handle,
        )

    @always_inline
    def quic_client_config_with_ca(
        self,
        ca_pem:   UnsafePointer[UInt8, MutAnyOrigin], ca_len:   Int32,
        alpn_ptr: UnsafePointer[UInt8, MutAnyOrigin], alpn_len: Int32,
        out_handle: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Create QUIC client TLS config trusting ca_pem (for testing). Returns 0."""
        return self._handle.call["rlsm_quic_client_config_with_ca", Int32](
            ca_pem, ca_len, alpn_ptr, alpn_len, out_handle,
        )

    @always_inline
    def quic_client_conn_new(
        self,
        config_handle: Int32,
        version: Int32,
        server_name: UnsafePointer[UInt8, MutAnyOrigin], name_len: Int32,
        tp: UnsafePointer[UInt8, MutAnyOrigin], tp_len: Int32,
        out_handle: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Create QUIC client connection. Returns 0 on success."""
        return self._handle.call["rlsm_quic_client_conn_new", Int32](
            config_handle, version, server_name, name_len, tp, tp_len, out_handle,
        )

    @always_inline
    def quic_server_conn_new(
        self,
        config_handle: Int32,
        version: Int32,
        tp: UnsafePointer[UInt8, MutAnyOrigin], tp_len: Int32,
        out_handle: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Create QUIC server connection. Returns 0 on success."""
        return self._handle.call["rlsm_quic_server_conn_new", Int32](
            config_handle, version, tp, tp_len, out_handle,
        )

    @always_inline
    def quic_conn_free(self, conn_handle: Int32) -> Int32:
        """Free QUIC connection handle. Returns 0 on success."""
        return self._handle.call["rlsm_quic_conn_free", Int32](conn_handle)

    @always_inline
    def quic_conn_write_hs(
        self,
        conn_handle: Int32,
        out_buf: UnsafePointer[UInt8, MutAnyOrigin],
        out_capacity: Int32,
        out_written: UnsafePointer[Int32, MutAnyOrigin],
        out_kc: UnsafePointer[UInt8, MutAnyOrigin],
    ) -> Int32:
        """Drain outgoing TLS bytes. out_kc: 0=none, 1=Handshake, 2=OneRtt. Returns 0."""
        return self._handle.call["rlsm_quic_conn_write_hs", Int32](
            conn_handle, out_buf, out_capacity, out_written, out_kc,
        )

    @always_inline
    def quic_conn_read_hs(
        self,
        conn_handle: Int32,
        data: UnsafePointer[UInt8, MutAnyOrigin],
        data_len: Int32,
        out_state_machine_us: UnsafePointer[UInt64, MutAnyOrigin] = UnsafePointer[UInt64, MutAnyOrigin](),
        out_handle_lookup_us: UnsafePointer[UInt64, MutAnyOrigin] = UnsafePointer[UInt64, MutAnyOrigin](),
    ) -> Int32:
        """Feed CRYPTO frame payload to TLS state machine. Returns 0 on success.

        Q6 instrumentation out-params (both default-NULL, NULL-safe in Rust):
          out_state_machine_us: rustls read_hs body µs (Q6 slot 1).
          out_handle_lookup_us: with_mut handle-table lookup µs (Q6 slot 2).
        """
        return self._handle.call["rlsm_quic_conn_read_hs", Int32](
            conn_handle, data, data_len,
            out_state_machine_us, out_handle_lookup_us,
        )

    @always_inline
    def quic_conn_take_keys(
        self,
        conn_handle: Int32,
        out_keys_handle: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Move pending Keys into Wave 1 KEYS_TABLE. Returns 0 on success."""
        return self._handle.call["rlsm_quic_conn_take_keys", Int32](
            conn_handle, out_keys_handle,
        )

    @always_inline
    def quic_conn_is_handshaking(self, conn_handle: Int32) -> Int32:
        """Returns 1 if handshaking, 0 if complete, -1 on invalid handle."""
        return self._handle.call["rlsm_quic_conn_is_handshaking", Int32](conn_handle)

    @always_inline
    def quic_conn_handshake_kind(self, conn_handle: Int32) -> Int32:
        """Returns -2 client, -1 invalid, 0 unknown, 1 Full, 2 Resumed, 3 FullWithHRR."""
        return self._handle.call["rlsm_quic_conn_handshake_kind", Int32](conn_handle)

    @always_inline
    def quic_conn_transport_params(
        self,
        conn_handle: Int32,
        out_buf: UnsafePointer[UInt8, MutAnyOrigin],
        out_capacity: Int32,
        out_written: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Read peer transport params. Returns 0 (available), 1 (not yet), -1 (error)."""
        return self._handle.call["rlsm_quic_conn_transport_params", Int32](
            conn_handle, out_buf, out_capacity, out_written,
        )

    @always_inline
    def quic_conn_alert(self, conn_handle: Int32) -> Int32:
        """Read cached TLS alert code. Returns alert number, or -1 if no alert."""
        return self._handle.call["rlsm_quic_conn_alert", Int32](conn_handle)

    # -- Raw AES-GCM-128 -------------------------------------------------------

    @always_inline
    def aes_gcm_128_seal(
        self,
        key: UnsafePointer[UInt8, MutAnyOrigin], key_len: Int32,
        nonce: UnsafePointer[UInt8, MutAnyOrigin], nonce_len: Int32,
        aad: UnsafePointer[UInt8, MutAnyOrigin], aad_len: Int32,
        plaintext: UnsafePointer[UInt8, MutAnyOrigin], pt_len: Int32,
        out_buf: UnsafePointer[UInt8, MutAnyOrigin],
        out_len: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """AES-GCM-128 encrypt. out_buf must hold pt_len + 16 bytes. Returns 0 or -1."""
        return self._handle.call["rlsm_aes_gcm_128_seal", Int32](
            key, key_len, nonce, nonce_len, aad, aad_len,
            plaintext, pt_len, out_buf, out_len,
        )

    @always_inline
    def aes_gcm_128_open(
        self,
        key: UnsafePointer[UInt8, MutAnyOrigin], key_len: Int32,
        nonce: UnsafePointer[UInt8, MutAnyOrigin], nonce_len: Int32,
        aad: UnsafePointer[UInt8, MutAnyOrigin], aad_len: Int32,
        ciphertext: UnsafePointer[UInt8, MutAnyOrigin], ct_len: Int32,
        out_buf: UnsafePointer[UInt8, MutAnyOrigin],
        out_len: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """AES-GCM-128 decrypt. ct_len includes 16-byte tag. Returns 0 or -1."""
        return self._handle.call["rlsm_aes_gcm_128_open", Int32](
            key, key_len, nonce, nonce_len, aad, aad_len,
            ciphertext, ct_len, out_buf, out_len,
        )

    # -- Microbench: thunk overhead --------------------------------------------

    @always_inline
    def noop(self) -> Int32:
        """No-op FFI call — for thunk-overhead microbench (Q5 follow-up).
        Returns 0. Body in Rust is `pub extern \"C\" fn rlsm_noop() -> i32 { 0 }`."""
        return self._handle.call["rlsm_noop", Int32]()

    # -- Raw HMAC-SHA256 -------------------------------------------------------

    @always_inline
    def hmac_sha256(
        self,
        key: UnsafePointer[UInt8, MutAnyOrigin], key_len: Int32,
        msg: UnsafePointer[UInt8, MutAnyOrigin], msg_len: Int32,
        out_buf: UnsafePointer[UInt8, MutAnyOrigin],
    ) -> Int32:
        """HMAC-SHA256. out_buf must hold 32 bytes. Returns 0 or -1."""
        return self._handle.call["rlsm_hmac_sha256", Int32](
            key, key_len, msg, msg_len, out_buf,
        )
