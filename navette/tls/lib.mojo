# src/tls/lib.mojo
#
# RustlsLibrary — dynamically loaded librustls_mojo.so with TCP-TLS FFI.
#
# SharedLibrary — ref-counted wrapper keeping RustlsLibrary alive while
# any QUIC/TLS object holds a copy. Internal type.
#
# TlsBackend — public facade owning a SharedLibrary. Consumers never see
# RustlsLibrary directly.
#
# Follows the same OwnedDLHandle pattern as conformance/lib/rustls.mojo, but
# wraps the 13 TCP-TLS FFI symbols (4 config + 9 connection) plus the shared
# rlsm_last_error helper. QUIC FFI symbols consolidated from
# conformance/lib/rustls.mojo.
from std.ffi import OwnedDLHandle
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

# Typed FFI loaders auto-generated from crates/librustls-mojo/symbols.toml.
# §2.3 deps-enhancement: all rlsm_* call sites resolve symbols through the
# generated module so signature drift between Rust and Mojo produces a
# compile error, not a runtime dlsym failure.
from navette.tls._rlsm_bindings import (
    load_rlsm_aes_gcm_128_open,
    load_rlsm_aes_gcm_128_seal,
    load_rlsm_client_config_new,
    load_rlsm_client_config_new_insecure,
    load_rlsm_config_free,
    load_rlsm_config_set_alpn_protocols,
    load_rlsm_hmac_sha256,
    load_rlsm_initial_keys,
    load_rlsm_keys_batch_decrypt,
    load_rlsm_keys_batch_encrypt,
    load_rlsm_keys_batch_header_protect,
    load_rlsm_keys_batch_header_unprotect,
    load_rlsm_keys_free,
    load_rlsm_test_keys_free_count,
    load_rlsm_test_keys_free_reset,
    load_rlsm_keys_local_encrypt,
    load_rlsm_keys_local_header_protect,
    load_rlsm_keys_remote_decrypt,
    load_rlsm_keys_remote_header_unprotect,
    load_rlsm_keys_tag_len,
    load_rlsm_last_error,
    load_rlsm_noop,
    load_rlsm_quic_client_config_new,
    load_rlsm_quic_client_config_new_insecure,
    load_rlsm_quic_client_config_with_ca,
    load_rlsm_quic_client_conn_new,
    load_rlsm_quic_conn_alert,
    load_rlsm_quic_conn_free,
    load_rlsm_quic_conn_handshake_kind,
    load_rlsm_quic_conn_is_handshaking,
    load_rlsm_quic_conn_read_hs,
    load_rlsm_quic_conn_take_keys,
    load_rlsm_quic_conn_transport_params,
    load_rlsm_quic_conn_write_hs,
    load_rlsm_quic_server_config_new,
    load_rlsm_quic_server_conn_new,
    load_rlsm_quic_server_conn_zero_rtt_keys,
    load_rlsm_quic_server_conn_replay_authenticator,
    load_rlsm_server_config_new,
    load_rlsm_tls_client_new,
    load_rlsm_tls_conn_alpn,
    load_rlsm_tls_conn_free,
    load_rlsm_tls_conn_is_handshaking,
    load_rlsm_tls_conn_read_plaintext,
    load_rlsm_tls_conn_read_tls,
    load_rlsm_tls_conn_write_plaintext,
    load_rlsm_tls_conn_write_tls,
    load_rlsm_tls_server_new,
    # Function-pointer type aliases for the per-packet hot path — cached
    # once in `_HotFns` (below) to avoid a `dlsym` on every FFI crossing.
    rlsm_keys_remote_header_unprotect_fn,
    rlsm_keys_remote_decrypt_fn,
    rlsm_keys_local_encrypt_fn,
    rlsm_keys_local_header_protect_fn,
)
from navette.util.null_ptr import null_ptr


def librustls_supports_insecure() raises -> Bool:
    """Probe whether the loaded librustls_mojo.so exports the `*_new_insecure`
    family, without aborting if the symbol is absent.

    release/dev-profile builds export them (CLI tools' `--insecure` flag
    works). hardened/bench-profile builds strip them. CLI tools that
    gate self-signed-cert UX should call this before invoking the
    insecure wrappers — `OwnedDLHandle.get_function` aborts the process
    on a missing symbol, which is poor UX for "you passed -k against a
    hardened-profile install."

    Uses `OwnedDLHandle.check_symbol` (stdlib non-aborting symbol probe)
    against a temporary handle. libc dlopen is refcounted, so opening
    an already-loaded soname is a no-op — the probe doesn't disturb any
    long-lived RustlsLibrary that's already holding the same .so.
    """
    var probe = _open_librustls()
    return probe.check_symbol("rlsm_quic_client_config_new_insecure")


def _open_librustls() raises -> OwnedDLHandle:
    """Locate and dlopen librustls_mojo.so across deployment modes.

    Search order:
      1. Bare soname `librustls_mojo.so` — resolves via the running
         binary's RUNPATH (mojox-build injects an `$ORIGIN`-relative
         path to the venv's mojo_packages/lib for installed scripts)
         or `LD_LIBRARY_PATH` / `ld.so.cache`.
      2. CWD-relative `lib/librustls_mojo.so` — for `mojo run` from
         example directories that carry a committed `lib/` symlink
         (the running process is the Mojo driver, which has no RPATH
         configured for us).
    """
    try:
        return OwnedDLHandle("librustls_mojo.so")
    except:
        return OwnedDLHandle("lib/librustls_mojo.so")


struct _HotFns(Movable):
    """Per-packet FFI function pointers, resolved once at library load.

    The QUIC data path crosses into librustls_mojo four times per packet —
    header-unprotect + AEAD-decrypt on ingress, AEAD-encrypt + header-protect
    on egress. The generated loaders run a `dlsym` on every call; resolving
    these four symbols once here and caching the `thin abi("C")` pointers
    turns each crossing into a direct indirect call, with no per-packet
    dynamic-loader lookup.

    Lifetime: a cached pointer is valid only while the owning
    `RustlsLibrary._handle` keeps the .so loaded. Both live in the same
    struct and are destroyed together, so a cached pointer is never called
    after the handle closes. Only the four per-packet symbols are cached;
    every other (per-connection / setup) symbol keeps the resolve-on-call
    path, which is not hot.
    """

    var keys_remote_header_unprotect: rlsm_keys_remote_header_unprotect_fn
    var keys_remote_decrypt: rlsm_keys_remote_decrypt_fn
    var keys_local_encrypt: rlsm_keys_local_encrypt_fn
    var keys_local_header_protect: rlsm_keys_local_header_protect_fn

    def __init__(out self, ref handle: OwnedDLHandle):
        self.keys_remote_header_unprotect = load_rlsm_keys_remote_header_unprotect(handle)
        self.keys_remote_decrypt = load_rlsm_keys_remote_decrypt(handle)
        self.keys_local_encrypt = load_rlsm_keys_local_encrypt(handle)
        self.keys_local_header_protect = load_rlsm_keys_local_header_protect(handle)

    def __init__(out self, *, deinit take: Self):
        self.keys_remote_header_unprotect = take.keys_remote_header_unprotect
        self.keys_remote_decrypt = take.keys_remote_decrypt
        self.keys_local_encrypt = take.keys_local_encrypt
        self.keys_local_header_protect = take.keys_local_header_protect


struct RustlsLibrary(Movable):
    """Dynamically loaded librustls_mojo.so (TCP-TLS symbols)."""

    var _handle: OwnedDLHandle
    var _hot: _HotFns

    def __init__(out self) raises:
        self._handle = _open_librustls()
        self._hot = _HotFns(self._handle)

    def __init__(out self, path: String) raises:
        self._handle = OwnedDLHandle(path)
        self._hot = _HotFns(self._handle)

    def __init__(out self, *, deinit take: Self):
        self._handle = take._handle^
        self._hot = take._hot^

    # -- Error retrieval -------------------------------------------------------

    def last_error(self) -> String:
        """Retrieve the last error message from the library.

        Returns an empty string if no error is set.
        """
        var buf = _heap_alloc[UInt8](512).as_any_origin()
        var n = load_rlsm_last_error(self._handle)(buf, Int32(512))
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
        return load_rlsm_client_config_new(self._handle)()

    @always_inline
    def client_config_new_insecure(self) -> Int32:
        """Create an insecure TLS client config that accepts any cert.

        Requires librustls_mojo.so built with --features insecure.
        Returns a positive handle on success, or -1 on error.
        """
        return load_rlsm_client_config_new_insecure(self._handle)()

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
        return load_rlsm_server_config_new(self._handle)(
            cert_pem, cert_len, key_pem, key_len,
        )

    # -- Config: free ----------------------------------------------------------

    @always_inline
    def config_free(self, handle: Int32) -> Int32:
        """Free a config handle. Returns 0 on success, or -1 if not found."""
        return load_rlsm_config_free(self._handle)(handle)

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
        return load_rlsm_tls_client_new(self._handle)(
            config_handle, server_name, name_len,
        )

    @always_inline
    def tls_server_new(self, config_handle: Int32) -> Int32:
        """Create a TLS server connection bound to `config_handle`.

        Returns a positive connection handle on success, or -1 on error.
        """
        return load_rlsm_tls_server_new(self._handle)(config_handle)

    # -- Connection: free ------------------------------------------------------

    @always_inline
    def tls_conn_free(self, handle: Int32) -> Int32:
        """Free a connection handle. Returns 0 on success, or -1 if not found."""
        return load_rlsm_tls_conn_free(self._handle)(handle)

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
        return load_rlsm_tls_conn_read_tls(self._handle)(
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
        return load_rlsm_tls_conn_write_tls(self._handle)(
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
        return load_rlsm_tls_conn_read_plaintext(self._handle)(
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
        return load_rlsm_tls_conn_write_plaintext(self._handle)(
            handle, data, data_len,
        )

    # -- Connection: state -----------------------------------------------------

    @always_inline
    def tls_conn_is_handshaking(self, handle: Int32) -> Int32:
        """1 if the TLS handshake is in progress, 0 if complete, -1 on error."""
        return load_rlsm_tls_conn_is_handshaking(self._handle)(handle)

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
        return load_rlsm_tls_conn_alpn(self._handle)(
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
        return load_rlsm_config_set_alpn_protocols(self._handle)(
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
        return load_rlsm_initial_keys(self._handle)(
            version, dcid, dcid_len, is_client,
        )

    @always_inline
    def keys_tag_len(self, keys_handle: Int32) -> Int32:
        """Return AEAD tag length (16 for AES-128-GCM). -1 on error."""
        return load_rlsm_keys_tag_len(self._handle)(keys_handle)

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
        return self._hot.keys_local_encrypt(
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
        return self._hot.keys_remote_decrypt(
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
        return self._hot.keys_local_header_protect(
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
        return self._hot.keys_remote_header_unprotect(
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
        return load_rlsm_keys_batch_header_unprotect(self._handle)(
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
        return load_rlsm_keys_batch_decrypt(self._handle)(
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
        return load_rlsm_keys_batch_header_protect(self._handle)(
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
        return load_rlsm_keys_batch_encrypt(self._handle)(
            keys_handle, count,
            packet_numbers, packet_ptrs,
            header_lens, payload_lens, buf_capacities,
            out_ciphertext_lens,
        )

    @always_inline
    def keys_free(self, keys_handle: Int32) -> Int32:
        """Free keys. Returns 0 on success, -1 if handle not found."""
        return load_rlsm_keys_free(self._handle)(keys_handle)

    @always_inline
    def test_keys_free_count(self) -> UInt64:
        """[test-only] Read the number of successful keys_free calls.

        Only meaningful when librustls_mojo.so was built with
        --features test-instrumentation. Calling against a default build
        will fail at dlsym time (the symbol is gated on that feature).
        """
        return load_rlsm_test_keys_free_count(self._handle)()

    @always_inline
    def test_keys_free_reset(self) -> Int32:
        """[test-only] Reset the keys-free counter to zero. Returns 0.

        Only meaningful when librustls_mojo.so was built with
        --features test-instrumentation.
        """
        return load_rlsm_test_keys_free_reset(self._handle)()

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
        return load_rlsm_quic_client_config_new(self._handle)(
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
        return load_rlsm_quic_client_config_new_insecure(self._handle)(
            alpn_ptr, alpn_len, out_handle,
        )

    @always_inline
    def quic_server_config_new(
        self,
        cert_pem: UnsafePointer[UInt8, MutAnyOrigin], cert_len: Int32,
        key_pem:  UnsafePointer[UInt8, MutAnyOrigin], key_len:  Int32,
        alpn_ptr: UnsafePointer[UInt8, MutAnyOrigin], alpn_len: Int32,
        max_early_data: UInt32,
        out_handle: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Create QUIC server TLS config. Always-on TLS 1.3 session resumption
        (rustls aws_lc_rs Ticketer). max_early_data: 0 disables 0-RTT (default);
        UInt32(0xFFFFFFFF) enables 0-RTT (rustls QUIC accepts only those two
        values per RFC 9001 §4.6.1). Returns 0 on success, -1 on error
        (including any other max_early_data value)."""
        return load_rlsm_quic_server_config_new(self._handle)(
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
        return load_rlsm_quic_client_config_with_ca(self._handle)(
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
        return load_rlsm_quic_client_conn_new(self._handle)(
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
        return load_rlsm_quic_server_conn_new(self._handle)(
            config_handle, version, tp, tp_len, out_handle,
        )

    @always_inline
    def quic_conn_free(self, conn_handle: Int32) -> Int32:
        """Free QUIC connection handle. Returns 0 on success."""
        return load_rlsm_quic_conn_free(self._handle)(conn_handle)

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
        return load_rlsm_quic_conn_write_hs(self._handle)(
            conn_handle, out_buf, out_capacity, out_written, out_kc,
        )

    @always_inline
    def quic_conn_read_hs(
        self,
        conn_handle: Int32,
        data: UnsafePointer[UInt8, MutAnyOrigin],
        data_len: Int32,
        out_state_machine_us: UnsafePointer[UInt64, MutAnyOrigin] = null_ptr[UInt64, MutAnyOrigin](),
        out_handle_lookup_us: UnsafePointer[UInt64, MutAnyOrigin] = null_ptr[UInt64, MutAnyOrigin](),
    ) -> Int32:
        """Feed CRYPTO frame payload to TLS state machine. Returns 0 on success.

        Instrumentation out-params (both default-NULL, NULL-safe in Rust):
          out_state_machine_us: rustls read_hs body µs (slot 1).
          out_handle_lookup_us: with_mut handle-table lookup µs (slot 2).
        """
        return load_rlsm_quic_conn_read_hs(self._handle)(
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
        return load_rlsm_quic_conn_take_keys(self._handle)(
            conn_handle, out_keys_handle,
        )

    @always_inline
    def quic_conn_is_handshaking(self, conn_handle: Int32) -> Int32:
        """Returns 1 if handshaking, 0 if complete, -1 on invalid handle."""
        return load_rlsm_quic_conn_is_handshaking(self._handle)(conn_handle)

    @always_inline
    def quic_conn_handshake_kind(self, conn_handle: Int32) -> Int32:
        """Returns -2 client, -1 invalid, 0 unknown, 1 Full, 2 Resumed, 3 FullWithHRR."""
        return load_rlsm_quic_conn_handshake_kind(self._handle)(conn_handle)

    @always_inline
    def quic_conn_transport_params(
        self,
        conn_handle: Int32,
        out_buf: UnsafePointer[UInt8, MutAnyOrigin],
        out_capacity: Int32,
        out_written: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Read peer transport params. Returns 0 (available), 1 (not yet), -1 (error)."""
        return load_rlsm_quic_conn_transport_params(self._handle)(
            conn_handle, out_buf, out_capacity, out_written,
        )

    @always_inline
    def quic_conn_alert(self, conn_handle: Int32) -> Int32:
        """Read cached TLS alert code. Returns alert number, or -1 if no alert."""
        return load_rlsm_quic_conn_alert(self._handle)(conn_handle)

    @always_inline
    def quic_server_conn_zero_rtt_keys(
        self,
        conn_handle: Int32,
        out_keys_handle: UnsafePointer[Int32, MutAnyOrigin],
    ) -> Int32:
        """Fetch server-side 0-RTT decrypt keys into KEYS_TABLE.

        Returns 0 on success (`*out_keys_handle` is a valid keys index),
        1 if unavailable (no resumption / ticket rejected / max_early_data=0;
        `*out_keys_handle` is -1, NOT an error), or -1 on error (null out
        param, invalid handle, client variant, table exhausted; `last_error`
        populated). Direction-stateless and idempotent; RFC 9001 §4.1.3
        compliance (discard 0-RTT keys at handshake-complete) is enforced
        Mojo-side via PacketProtect. A successful return does NOT mean the
        eventual 0-RTT data is replay-safe.
        """
        return load_rlsm_quic_server_conn_zero_rtt_keys(self._handle)(
            conn_handle, out_keys_handle,
        )

    @always_inline
    def quic_server_conn_replay_authenticator(
        self,
        conn_handle: Int32,
        out_buf: UnsafePointer[UInt8, MutAnyOrigin],
        out_len: UnsafePointer[UInt, MutAnyOrigin],
    ) -> Int32:
        """Fetch the 32-byte 0-RTT replay authenticator (ClientHello.random)
        captured by the shim on the first server-side `read_hs` call.

        Returns 0 on success (`*out_len = 32`, `out_buf` holds 32 bytes),
        1 when the random has not yet been captured (no ClientHello seen,
        or fewer than 38 bytes accumulated; `*out_len = 0`), or -1 on
        anomaly (invalid handle or client variant). RFC 8446 §8 anchors
        the authenticator-as-replay-key invariant; the captured 32 bytes
        are opaque to Mojo — bytewise equality is the dedup contract.
        """
        return load_rlsm_quic_server_conn_replay_authenticator(self._handle)(
            conn_handle, out_buf, out_len,
        )

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
        return load_rlsm_aes_gcm_128_seal(self._handle)(
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
        return load_rlsm_aes_gcm_128_open(self._handle)(
            key, key_len, nonce, nonce_len, aad, aad_len,
            ciphertext, ct_len, out_buf, out_len,
        )

    # -- Microbench: thunk overhead --------------------------------------------

    @always_inline
    def noop(self) -> Int32:
        """No-op FFI call — for thunk-overhead microbench.
        Returns 0. Body in Rust is `pub extern \"C\" fn rlsm_noop() -> i32 { 0 }`."""
        return load_rlsm_noop(self._handle)()

    # -- Raw HMAC-SHA256 -------------------------------------------------------

    @always_inline
    def hmac_sha256(
        self,
        key: UnsafePointer[UInt8, MutAnyOrigin], key_len: Int32,
        msg: UnsafePointer[UInt8, MutAnyOrigin], msg_len: Int32,
        out_buf: UnsafePointer[UInt8, MutAnyOrigin],
    ) -> Int32:
        """HMAC-SHA256. out_buf must hold 32 bytes. Returns 0 or -1."""
        return load_rlsm_hmac_sha256(self._handle)(
            key, key_len, msg, msg_len, out_buf,
        )


# ── SharedLibrary (internal ref-counted wrapper) ─────────────────────────────


struct _SharedLibraryInner(Movable):
    """Heap-allocated interior: the library handle + a reference count."""

    var lib: RustlsLibrary
    var refcount: Int

    def __init__(out self, var lib: RustlsLibrary):
        self.lib = lib^
        self.refcount = 1

    def __init__(out self, *, deinit take: Self):
        self.lib = take.lib^
        self.refcount = take.refcount


struct SharedLibrary(Copyable, Movable):
    """Ref-counted handle to a RustlsLibrary.

    Internal type — consumers use `TlsBackend`. Every copy increments
    the refcount; destruction decrements it. When the count reaches zero
    the inner `RustlsLibrary` (and its `OwnedDLHandle`) is destroyed.
    """

    var _ptr: UnsafePointer[_SharedLibraryInner, MutAnyOrigin]

    def __init__(out self, var lib: RustlsLibrary):
        var p = _heap_alloc[_SharedLibraryInner](1).as_any_origin()
        p.init_pointee_move(_SharedLibraryInner(lib^))
        self._ptr = p

    def __init__(out self, *, other: Self):
        other._ptr[].refcount += 1
        self._ptr = other._ptr

    def __init__(out self, *, deinit take: Self):
        self._ptr = take._ptr

    def __del__(deinit self):
        self._ptr[].refcount -= 1
        if self._ptr[].refcount == 0:
            self._ptr.destroy_pointee()
            self._ptr.free()

    @always_inline
    def inner_ptr(self) -> UnsafePointer[RustlsLibrary, MutAnyOrigin]:
        return UnsafePointer(to=self._ptr[].lib).as_any_origin()


# ── TlsBackend (public facade) ──────────────────────────────────────────────


struct TlsBackend(Copyable, Movable):
    """Public entry point for navette's TLS/QUIC cryptography.

    Wraps a `SharedLibrary` so that every config and connection object
    can hold a refcounted copy, keeping the underlying `RustlsLibrary`
    alive for the entire lifetime of the connection graph.  Consumers
    never see `RustlsLibrary` directly.
    """

    var _lib: SharedLibrary

    def __init__(out self) raises:
        self._lib = SharedLibrary(RustlsLibrary())

    def __init__(out self, path: String) raises:
        self._lib = SharedLibrary(RustlsLibrary(path))

    def __init__(out self, *, other: Self):
        self._lib = SharedLibrary(other=other._lib)

    def __init__(out self, *, deinit take: Self):
        self._lib = take._lib^

    def shared(self) -> SharedLibrary:
        return SharedLibrary(other=self._lib)
