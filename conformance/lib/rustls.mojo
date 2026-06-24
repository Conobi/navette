# conformance/lib/rustls.mojo
#
# RAII wrapper around librustls_mojo.so for use in conformance tests.
# Loads the shared library via OwnedDLHandle and exposes typed Mojo
# functions for the rlsm_* C FFI symbols.
from std.ffi import OwnedDLHandle
from std.memory import UnsafePointer
from navette.util.owned_alloc import Owned


struct RustlsLibrary(Movable):
    """Dynamically loaded librustls_mojo.so."""

    var _handle: OwnedDLHandle

    def __init__(out self, path: String = "../lib/librustls_mojo.so") raises:
        self._handle = OwnedDLHandle(path)

    def __init__(out self, *, deinit take: Self):
        self._handle = take._handle^

    # -- Error retrieval -------------------------------------------------------

    def last_error(self) -> String:
        """Retrieve the last error message from the library.

        Returns an empty string if no error is set.
        """
        var buf_owned = Owned[UInt8](512)
        var buf = buf_owned.ptr()
        var n = self._handle.call["rlsm_last_error", Int32](buf, Int32(512))
        if n <= 0:
            return String("")
        # n includes the NUL terminator; the message is n-1 bytes.
        # Build the String byte-by-byte (safe for Mojo 0.26.2).
        var msg = String()
        for i in range(Int(n - 1)):
            msg += chr(Int(buf[i]))
        # Keep buf alive across the FFI call + the post-FFI byte reads above.
        _ = buf_owned
        return msg^

    # -- QUIC Initial keys (raw) -----------------------------------------------

    @always_inline
    def initial_keys_raw(
        self,
        version: Int32,
        dcid: UnsafePointer[UInt8, MutAnyOrigin],
        dcid_len: Int32,
        is_client: Int32,
        out_key: UnsafePointer[UInt8, MutAnyOrigin],
        out_key_len: UnsafePointer[Int32, MutAnyOrigin],
        out_iv: UnsafePointer[UInt8, MutAnyOrigin],
        out_iv_len: UnsafePointer[Int32, MutAnyOrigin],
        out_hp: UnsafePointer[UInt8, MutAnyOrigin],
        out_hp_len: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Derive raw QUIC Initial key material (key, IV, HP key).

        Returns 0 on success, -1 on error.
        """
        return self._handle.call["rlsm_initial_keys_raw", Int32](
            version,
            dcid,
            dcid_len,
            is_client,
            out_key,
            out_key_len,
            out_iv,
            out_iv_len,
            out_hp,
            out_hp_len,
        )

    # -- QUIC Initial keys (handle-based) --------------------------------------

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
    def keys_free(self, keys_handle: Int32) -> Int32:
        """Free keys. Returns 0 on success, -1 if handle not found."""
        return self._handle.call["rlsm_keys_free", Int32](keys_handle)

    # -- QUIC Wave 2 config lifecycle -----------------------------------------

    @always_inline
    def quic_server_config_new(
        self,
        cert_pem: UnsafePointer[UInt8, MutAnyOrigin], cert_len: Int32,
        key_pem:  UnsafePointer[UInt8, MutAnyOrigin], key_len:  Int32,
        alpn_ptr: UnsafePointer[UInt8, MutAnyOrigin], alpn_len: Int32,
        out_handle: UnsafePointer[Int32, MutAnyOrigin],
        max_early_data: UInt32 = UInt32(0),
    ) -> Int32:
        """Create QUIC server TLS config. Returns 0 on success.

        max_early_data: 0 disables 0-RTT (default); UInt32(0xFFFFFFFF) enables
        0-RTT (rustls QUIC accepts only those two values per RFC 9001 §4.6.1).
        Any other value is rejected at the FFI boundary with rc=-1.
        """
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
        """Create QUIC client TLS config trusting ca_pem (test helper). Returns 0."""
        return self._handle.call["rlsm_quic_client_config_with_ca", Int32](
            ca_pem, ca_len, alpn_ptr, alpn_len, out_handle,
        )

    # -- QUIC Wave 2 connection lifecycle -------------------------------------

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

    # -- QUIC Wave 2 handshake exchange ---------------------------------------

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
        out_state_machine_us: UnsafePointer[UInt64, MutAnyOrigin] = UnsafePointer[UInt64, MutAnyOrigin](unsafe_from_address=Int(0)),
        out_handle_lookup_us: UnsafePointer[UInt64, MutAnyOrigin] = UnsafePointer[UInt64, MutAnyOrigin](unsafe_from_address=Int(0)),
    ) -> Int32:
        """Feed CRYPTO frame payload to TLS state machine. Returns 0 on success.

        Q6 instrumentation out-params (both default-NULL, NULL-safe in Rust):
          out_state_machine_us: rustls read_hs body µs.
          out_handle_lookup_us: with_mut handle-table lookup µs.
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
