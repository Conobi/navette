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
# Follows the same OwnedDLHandle pattern as conformance/oracle/rustls.mojo, but
# wraps the 13 TCP-TLS FFI symbols (4 config + 9 connection) plus the shared
# rlsm_last_error helper. QUIC FFI symbols consolidated from
# conformance/oracle/rustls.mojo.
from std.ffi import OwnedDLHandle
from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc
from navette.util.owned_alloc import Owned

# Typed FFI wrappers auto-generated from crates/librustls-mojo/symbols.toml.
# All rlsm_* call sites resolve symbols through the generated module so
# signature drift between Rust and Mojo produces a compile error, not a
# runtime dlsym failure. Mojo 1.0.0's `get_function` takes only the return
# type, so the argument types now live in each `call_rlsm_*` wrapper's own
# signature rather than in the type handed to `get_function`.
from navette.tls._rlsm_bindings import (
    call_rlsm_aes_gcm_128_open,
    call_rlsm_aes_gcm_128_seal,
    call_rlsm_client_config_new,
    call_rlsm_client_config_new_insecure,
    call_rlsm_config_free,
    call_rlsm_config_set_alpn_protocols,
    call_rlsm_hmac_sha256,
    call_rlsm_initial_keys,
    call_rlsm_test_keys_free_count,
    call_rlsm_test_keys_free_reset,
    call_rlsm_last_error,
    call_rlsm_noop,
    call_rlsm_quic_client_config_new,
    call_rlsm_quic_client_config_new_insecure,
    call_rlsm_quic_client_config_with_ca,
    call_rlsm_quic_client_conn_new,
    call_rlsm_quic_conn_free,
    call_rlsm_quic_conn_take_keys,
    call_rlsm_quic_server_config_new,
    call_rlsm_quic_server_conn_new,
    call_rlsm_quic_server_conn_zero_rtt_keys,
    call_rlsm_quic_server_conn_replay_authenticator,
    call_rlsm_quic_server_conn_reject_early_data,
    call_rlsm_server_config_new,
    call_rlsm_tls_client_new,
    call_rlsm_tls_conn_alpn,
    call_rlsm_tls_conn_free,
    call_rlsm_tls_server_new,
    # Loaders + C ABI types for cached hot-path function pointers.
    # Resolved once into `_HotFns` at library load to avoid a `dlsym`
    # on every FFI crossing.
    load_rlsm_keys_local_encrypt,
    load_rlsm_keys_local_header_protect,
    load_rlsm_keys_remote_decrypt,
    load_rlsm_keys_remote_header_unprotect,
    rlsm_keys_remote_header_unprotect_fn,
    rlsm_keys_remote_decrypt_fn,
    rlsm_keys_local_encrypt_fn,
    rlsm_keys_local_header_protect_fn,
    # Batch crypto + keys lifecycle
    load_rlsm_keys_batch_header_unprotect,
    load_rlsm_keys_batch_decrypt,
    load_rlsm_keys_batch_header_protect,
    load_rlsm_keys_batch_encrypt,
    load_rlsm_keys_tag_len,
    load_rlsm_keys_free,
    rlsm_keys_batch_header_unprotect_fn,
    rlsm_keys_batch_decrypt_fn,
    rlsm_keys_batch_header_protect_fn,
    rlsm_keys_batch_encrypt_fn,
    rlsm_keys_tag_len_fn,
    rlsm_keys_free_fn,
    # QUIC per-connection-per-tick
    load_rlsm_quic_conn_write_hs,
    load_rlsm_quic_conn_read_hs,
    load_rlsm_quic_conn_is_handshaking,
    load_rlsm_quic_conn_handshake_kind,
    load_rlsm_quic_conn_alert,
    load_rlsm_quic_conn_transport_params,
    rlsm_quic_conn_write_hs_fn,
    rlsm_quic_conn_read_hs_fn,
    rlsm_quic_conn_is_handshaking_fn,
    rlsm_quic_conn_handshake_kind_fn,
    rlsm_quic_conn_alert_fn,
    rlsm_quic_conn_transport_params_fn,
    # TLS per-connection-per-read/write cycle (H2 path)
    load_rlsm_tls_conn_read_tls,
    load_rlsm_tls_conn_write_tls,
    load_rlsm_tls_conn_read_plaintext,
    load_rlsm_tls_conn_write_plaintext,
    load_rlsm_tls_conn_is_handshaking,
    rlsm_tls_conn_read_tls_fn,
    rlsm_tls_conn_write_tls_fn,
    rlsm_tls_conn_read_plaintext_fn,
    rlsm_tls_conn_write_plaintext_fn,
    rlsm_tls_conn_is_handshaking_fn,
)
from navette.util.null_ptr import null_ptr


def librustls_supports_insecure() raises -> Bool:
    """Probe whether the loaded librustls_mojo.so exports the `*_new_insecure`
    family, without aborting if the symbol is absent.

    release/dev-profile builds export them (CLI tools' `--insecure` flag
    works). hardened/bench-profile builds strip them. CLI tools that
    gate self-signed-cert UX should call this before invoking the
    insecure wrappers. Mojo 1.0.0's `get_function` raises rather than
    aborting on a missing symbol, so an unguarded call is now a catchable
    error rather than process death — but "symbol not found:
    rlsm_quic_client_config_new_insecure" is still poor UX for "you passed
    -k against a hardened-profile install."

    Uses `OwnedDLHandle.check_symbol` (stdlib non-raising symbol probe)
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
    """Hot-path FFI function pointers, resolved once at library load.

    The generated `call_rlsm_*` wrappers resolve via `dlsym` on every call.
    For per-packet and per-connection-per-tick symbols this is measurable
    overhead (~3.9 µs/req across 764 dlsym calls). Resolving them once
    here and caching the `thin abi("C")` pointers turns each crossing
    into a direct indirect call with no dynamic-loader lookup.

    Covers three tiers:
    - Per-packet (4): single-packet encrypt/decrypt + header protect.
    - Batch crypto (6): batch encrypt/decrypt + header protect + tag_len + free.
    - Per-connection-per-tick (11): QUIC handshake + TLS I/O.

    Lifetime: a cached pointer is valid only while the owning
    `RustlsLibrary._handle` keeps the .so loaded. Both live in the same
    struct and are destroyed together, so a cached pointer is never called
    after the handle closes.
    """

    # Per-packet single encrypt/decrypt
    var keys_remote_header_unprotect: rlsm_keys_remote_header_unprotect_fn
    var keys_remote_decrypt: rlsm_keys_remote_decrypt_fn
    var keys_local_encrypt: rlsm_keys_local_encrypt_fn
    var keys_local_header_protect: rlsm_keys_local_header_protect_fn
    # Batch crypto
    var keys_batch_header_unprotect: rlsm_keys_batch_header_unprotect_fn
    var keys_batch_decrypt: rlsm_keys_batch_decrypt_fn
    var keys_batch_header_protect: rlsm_keys_batch_header_protect_fn
    var keys_batch_encrypt: rlsm_keys_batch_encrypt_fn
    var keys_tag_len: rlsm_keys_tag_len_fn
    var keys_free: rlsm_keys_free_fn
    # QUIC per-connection-per-tick
    var quic_conn_write_hs: rlsm_quic_conn_write_hs_fn
    var quic_conn_read_hs: rlsm_quic_conn_read_hs_fn
    var quic_conn_is_handshaking: rlsm_quic_conn_is_handshaking_fn
    var quic_conn_handshake_kind: rlsm_quic_conn_handshake_kind_fn
    var quic_conn_alert: rlsm_quic_conn_alert_fn
    var quic_conn_transport_params: rlsm_quic_conn_transport_params_fn
    # TLS per-connection-per-read/write (H2 path)
    var tls_conn_read_tls: rlsm_tls_conn_read_tls_fn
    var tls_conn_write_tls: rlsm_tls_conn_write_tls_fn
    var tls_conn_read_plaintext: rlsm_tls_conn_read_plaintext_fn
    var tls_conn_write_plaintext: rlsm_tls_conn_write_plaintext_fn
    var tls_conn_is_handshaking: rlsm_tls_conn_is_handshaking_fn

    def __init__(out self, ref handle: OwnedDLHandle) raises:
        """Resolve all hot-path symbols from an open library handle.

        Args:
            handle: The `OwnedDLHandle` that must outlive this `_HotFns`.

        Raises:
            If any symbol is missing from the loaded library.
        """
        self.keys_remote_header_unprotect = load_rlsm_keys_remote_header_unprotect(handle)
        self.keys_remote_decrypt = load_rlsm_keys_remote_decrypt(handle)
        self.keys_local_encrypt = load_rlsm_keys_local_encrypt(handle)
        self.keys_local_header_protect = load_rlsm_keys_local_header_protect(handle)
        self.keys_batch_header_unprotect = load_rlsm_keys_batch_header_unprotect(handle)
        self.keys_batch_decrypt = load_rlsm_keys_batch_decrypt(handle)
        self.keys_batch_header_protect = load_rlsm_keys_batch_header_protect(handle)
        self.keys_batch_encrypt = load_rlsm_keys_batch_encrypt(handle)
        self.keys_tag_len = load_rlsm_keys_tag_len(handle)
        self.keys_free = load_rlsm_keys_free(handle)
        self.quic_conn_write_hs = load_rlsm_quic_conn_write_hs(handle)
        self.quic_conn_read_hs = load_rlsm_quic_conn_read_hs(handle)
        self.quic_conn_is_handshaking = load_rlsm_quic_conn_is_handshaking(handle)
        self.quic_conn_handshake_kind = load_rlsm_quic_conn_handshake_kind(handle)
        self.quic_conn_alert = load_rlsm_quic_conn_alert(handle)
        self.quic_conn_transport_params = load_rlsm_quic_conn_transport_params(handle)
        self.tls_conn_read_tls = load_rlsm_tls_conn_read_tls(handle)
        self.tls_conn_write_tls = load_rlsm_tls_conn_write_tls(handle)
        self.tls_conn_read_plaintext = load_rlsm_tls_conn_read_plaintext(handle)
        self.tls_conn_write_plaintext = load_rlsm_tls_conn_write_plaintext(handle)
        self.tls_conn_is_handshaking = load_rlsm_tls_conn_is_handshaking(handle)


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

    # -- Error retrieval -------------------------------------------------------

    def last_error(self) raises -> String:
        """Retrieve the last error message from the library.

        Returns an empty string if no error is set.
        """
        var buf_owner = Owned[UInt8](512)
        var buf = buf_owner.ptr()
        var n = call_rlsm_last_error(self._handle, buf, Int32(512))
        if n <= 0:
            return String("")
        # n includes the NUL terminator; the message is n-1 bytes.
        var msg = String()
        for i in range(Int(n - 1)):
            msg += chr(Int(buf[unsafe_offset=i]))
        return msg^

    # -- Config: client --------------------------------------------------------

    @always_inline
    def client_config_new(self) raises -> Int32:
        """Create a TLS client config with Mozilla WebPKI roots.

        Returns a positive handle on success, or -1 on error.
        """
        return call_rlsm_client_config_new(self._handle)

    @always_inline
    def client_config_new_insecure(self) raises -> Int32:
        """Create an insecure TLS client config that accepts any cert.

        Requires librustls_mojo.so built with --features insecure.
        Returns a positive handle on success, or -1 on error.
        """
        return call_rlsm_client_config_new_insecure(self._handle)

    # -- Config: server --------------------------------------------------------

    @always_inline
    def server_config_new(
        self,
        cert_pem: Pointer[mut=True, T=UInt8, origin=_],
        cert_len: Int32,
        key_pem: Pointer[mut=True, T=UInt8, origin=_],
        key_len: Int32,
    ) raises -> Int32:
        """Create a TLS server config from a PEM cert chain and PEM private key.

        Returns a positive handle on success, or -1 on error.
        """
        return call_rlsm_server_config_new(
            self._handle,
            cert_pem, cert_len, key_pem, key_len,
        )

    # -- Config: free ----------------------------------------------------------

    @always_inline
    def config_free(self, handle: Int32) raises -> Int32:
        """Free a config handle. Returns 0 on success, or -1 if not found."""
        return call_rlsm_config_free(self._handle, handle)

    # -- Connection: create ----------------------------------------------------

    @always_inline
    def tls_client_new(
        self,
        config_handle: Int32,
        server_name: Pointer[mut=True, T=UInt8, origin=_],
        name_len: Int32,
    ) raises -> Int32:
        """Create a TLS client connection bound to `config_handle`.

        `server_name` is the SNI hostname (UTF-8, not NUL-terminated).
        Returns a positive connection handle on success, or -1 on error.
        """
        return call_rlsm_tls_client_new(
            self._handle,
            config_handle, server_name, name_len,
        )

    @always_inline
    def tls_server_new(self, config_handle: Int32) raises -> Int32:
        """Create a TLS server connection bound to `config_handle`.

        Returns a positive connection handle on success, or -1 on error.
        """
        return call_rlsm_tls_server_new(self._handle, config_handle)

    # -- Connection: free ------------------------------------------------------

    @always_inline
    def tls_conn_free(self, handle: Int32) raises -> Int32:
        """Free a connection handle. Returns 0 on success, or -1 if not found."""
        return call_rlsm_tls_conn_free(self._handle, handle)

    # -- Connection: ciphertext I/O -------------------------------------------

    @always_inline
    def tls_conn_read_tls(
        self,
        handle: Int32,
        ciphertext: Pointer[mut=True, T=UInt8, origin=_],
        ct_len: Int32,
    ) raises -> Int32:
        """Feed received ciphertext into the rustls state machine.

        Advances the state machine via process_new_packets() on the Rust side.
        Returns the number of bytes consumed, or -1 on error.
        """
        return self._hot.tls_conn_read_tls(
            handle,
            ciphertext.unsafe_origin_cast[MutUntrackedOrigin](), ct_len,
        )

    @always_inline
    def tls_conn_write_tls(
        self,
        handle: Int32,
        out_buf: Pointer[mut=True, T=UInt8, origin=_],
        buf_len: Int32,
    ) raises -> Int32:
        """Drain pending ciphertext from rustls into `out_buf`.

        Returns the number of bytes written, 0 if nothing pending, or -1 on
        error.
        """
        return self._hot.tls_conn_write_tls(
            handle,
            out_buf.unsafe_origin_cast[MutUntrackedOrigin](), buf_len,
        )

    # -- Connection: plaintext I/O --------------------------------------------

    @always_inline
    def tls_conn_read_plaintext(
        self,
        handle: Int32,
        out_buf: Pointer[mut=True, T=UInt8, origin=_],
        buf_len: Int32,
    ) raises -> Int32:
        """Read decrypted application data.

        Returns the number of bytes written, 0 if no data is currently
        available, or -1 on error.
        """
        return self._hot.tls_conn_read_plaintext(
            handle,
            out_buf.unsafe_origin_cast[MutUntrackedOrigin](), buf_len,
        )

    @always_inline
    def tls_conn_write_plaintext(
        self,
        handle: Int32,
        data: Pointer[mut=True, T=UInt8, origin=_],
        data_len: Int32,
    ) raises -> Int32:
        """Write plaintext application data to be encrypted.

        Returns the number of bytes consumed, or -1 on error.
        """
        return self._hot.tls_conn_write_plaintext(
            handle,
            data.unsafe_origin_cast[MutUntrackedOrigin](), data_len,
        )

    # -- Connection: state -----------------------------------------------------

    @always_inline
    def tls_conn_is_handshaking(self, handle: Int32) raises -> Int32:
        """1 if the TLS handshake is in progress, 0 if complete, -1 on error."""
        return self._hot.tls_conn_is_handshaking(handle)

    @always_inline
    def tls_conn_alpn(
        self,
        handle: Int32,
        out_buf: Pointer[mut=True, T=UInt8, origin=_],
        buf_len: Int32,
    ) raises -> Int32:
        """Get the negotiated ALPN protocol identifier.

        Returns the number of bytes written, 0 if no ALPN was negotiated, or
        -1 on error.
        """
        return call_rlsm_tls_conn_alpn(
            self._handle,
            handle, out_buf, buf_len,
        )

    # -- Config: ALPN ----------------------------------------------------------

    @always_inline
    def config_set_alpn_protocols(
        self,
        config_handle: Int32,
        protocols: Pointer[mut=True, T=UInt8, origin=_],
        protocols_len: Int32,
    ) raises -> Int32:
        """Set ALPN protocol preferences on a config handle.

        protocols is a length-prefixed wire format buffer.
        Returns 0 on success, -1 on error.
        """
        return call_rlsm_config_set_alpn_protocols(
            self._handle,
            config_handle, protocols, protocols_len,
        )

    # -- QUIC Wave 1: keys + AEAD + HP ----------------------------------------

    @always_inline
    def initial_keys(
        self,
        version: Int32,
        dcid: Pointer[mut=True, T=UInt8, origin=_],
        dcid_len: Int32,
        is_client: Int32,
    ) raises -> Int32:
        """Derive QUIC Initial keys, returning a handle.

        Returns a positive handle on success, -1 on error.
        """
        return call_rlsm_initial_keys(
            self._handle,
            version, dcid, dcid_len, is_client,
        )

    @always_inline
    def keys_tag_len(self, keys_handle: Int32) raises -> Int32:
        """Return AEAD tag length (16 for AES-128-GCM). -1 on error."""
        return self._hot.keys_tag_len(keys_handle)

    @always_inline
    def keys_local_encrypt(
        self,
        keys_handle: Int32,
        packet_number: UInt64,
        header: Pointer[mut=True, T=UInt8, origin=_],
        header_len: Int32,
        payload: Pointer[mut=True, T=UInt8, origin=_],
        payload_len: Int32,
        buf_capacity: Int32,
    ) -> Int32:
        """Encrypt payload in-place. Returns ciphertext length or -1."""
        # The cached pointer's C ABI type fixes its pointer arguments to
        # `MutUntrackedOrigin`, so each buffer is handed over untracked --
        # correct, because the callee is C. The parameters above keep the
        # caller's real origins borrowed for the whole body, which spans
        # this synchronous call, so nothing can free a buffer under it.
        return self._hot.keys_local_encrypt(
            keys_handle, packet_number,
            header.unsafe_origin_cast[MutUntrackedOrigin](), header_len,
            payload.unsafe_origin_cast[MutUntrackedOrigin](), payload_len,
            buf_capacity,
        )

    @always_inline
    def keys_remote_decrypt(
        self,
        keys_handle: Int32,
        packet_number: UInt64,
        header: Pointer[mut=True, T=UInt8, origin=_],
        header_len: Int32,
        payload: Pointer[mut=True, T=UInt8, origin=_],
        payload_len: Int32,
    ) -> Int32:
        """Decrypt payload in-place. Returns plaintext length or -1."""
        # The cached pointer's C ABI type fixes its pointer arguments to
        # `MutUntrackedOrigin`, so each buffer is handed over untracked --
        # correct, because the callee is C. The parameters above keep the
        # caller's real origins borrowed for the whole body, which spans
        # this synchronous call, so nothing can free a buffer under it.
        return self._hot.keys_remote_decrypt(
            keys_handle, packet_number,
            header.unsafe_origin_cast[MutUntrackedOrigin](), header_len,
            payload.unsafe_origin_cast[MutUntrackedOrigin](), payload_len,
        )

    @always_inline
    def keys_local_header_protect(
        self,
        keys_handle: Int32,
        sample: Pointer[mut=True, T=UInt8, origin=_],
        sample_len: Int32,
        first_byte: Pointer[mut=True, T=UInt8, origin=_],
        pn_bytes: Pointer[mut=True, T=UInt8, origin=_],
        pn_len: Int32,
    ) -> Int32:
        """Apply header protection (local/encrypt direction). Returns 0 or -1."""
        # The cached pointer's C ABI type fixes its pointer arguments to
        # `MutUntrackedOrigin`, so each buffer is handed over untracked --
        # correct, because the callee is C. The parameters above keep the
        # caller's real origins borrowed for the whole body, which spans
        # this synchronous call, so nothing can free a buffer under it.
        return self._hot.keys_local_header_protect(
            keys_handle,
            sample.unsafe_origin_cast[MutUntrackedOrigin](), sample_len,
            first_byte.unsafe_origin_cast[MutUntrackedOrigin](),
            pn_bytes.unsafe_origin_cast[MutUntrackedOrigin](), pn_len,
        )

    @always_inline
    def keys_remote_header_unprotect(
        self,
        keys_handle: Int32,
        sample: Pointer[mut=True, T=UInt8, origin=_],
        sample_len: Int32,
        first_byte: Pointer[mut=True, T=UInt8, origin=_],
        pn_bytes: Pointer[mut=True, T=UInt8, origin=_],
        pn_len: Int32,
    ) -> Int32:
        """Remove header protection (remote/decrypt direction). Returns 0 or -1."""
        # The cached pointer's C ABI type fixes its pointer arguments to
        # `MutUntrackedOrigin`, so each buffer is handed over untracked --
        # correct, because the callee is C. The parameters above keep the
        # caller's real origins borrowed for the whole body, which spans
        # this synchronous call, so nothing can free a buffer under it.
        return self._hot.keys_remote_header_unprotect(
            keys_handle,
            sample.unsafe_origin_cast[MutUntrackedOrigin](), sample_len,
            first_byte.unsafe_origin_cast[MutUntrackedOrigin](),
            pn_bytes.unsafe_origin_cast[MutUntrackedOrigin](), pn_len,
        )

    @always_inline
    def keys_batch_header_unprotect(
        self,
        keys_handle: Int32,
        count: Int32,
        packet_ptrs: Pointer[mut=True, T=Pointer[UInt8, MutUntrackedOrigin], origin=_],
        packet_lens: Pointer[mut=True, T=Int32, origin=_],
        pn_offsets: Pointer[mut=True, T=Int32, origin=_],
        out_first_bytes: Pointer[mut=True, T=UInt8, origin=_],
        out_pn_lengths: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """Batch header unprotection. Returns success count or -1."""
        return self._hot.keys_batch_header_unprotect(
            keys_handle, count,
            packet_ptrs.unsafe_origin_cast[MutUntrackedOrigin](),
            packet_lens.unsafe_origin_cast[MutUntrackedOrigin](),
            pn_offsets.unsafe_origin_cast[MutUntrackedOrigin](),
            out_first_bytes.unsafe_origin_cast[MutUntrackedOrigin](),
            out_pn_lengths.unsafe_origin_cast[MutUntrackedOrigin](),
        )

    @always_inline
    def keys_batch_decrypt(
        self,
        keys_handle: Int32,
        count: Int32,
        packet_numbers: Pointer[mut=True, T=UInt64, origin=_],
        packet_ptrs: Pointer[mut=True, T=Pointer[UInt8, MutUntrackedOrigin], origin=_],
        packet_lens: Pointer[mut=True, T=Int32, origin=_],
        header_lens: Pointer[mut=True, T=Int32, origin=_],
        out_plaintext_lens: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """Batch AEAD decryption. Returns success count or -1."""
        return self._hot.keys_batch_decrypt(
            keys_handle, count,
            packet_numbers.unsafe_origin_cast[MutUntrackedOrigin](),
            packet_ptrs.unsafe_origin_cast[MutUntrackedOrigin](),
            packet_lens.unsafe_origin_cast[MutUntrackedOrigin](),
            header_lens.unsafe_origin_cast[MutUntrackedOrigin](),
            out_plaintext_lens.unsafe_origin_cast[MutUntrackedOrigin](),
        )

    @always_inline
    def keys_batch_header_protect(
        self,
        keys_handle: Int32,
        count: Int32,
        packet_ptrs: Pointer[mut=True, T=Pointer[UInt8, MutUntrackedOrigin], origin=_],
        packet_lens: Pointer[mut=True, T=Int32, origin=_],
        pn_offsets: Pointer[mut=True, T=Int32, origin=_],
        pn_lengths: Pointer[mut=True, T=Int32, origin=_],
        out_results: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """Batch header protection. Returns success count or -1."""
        return self._hot.keys_batch_header_protect(
            keys_handle, count,
            packet_ptrs.unsafe_origin_cast[MutUntrackedOrigin](),
            packet_lens.unsafe_origin_cast[MutUntrackedOrigin](),
            pn_offsets.unsafe_origin_cast[MutUntrackedOrigin](),
            pn_lengths.unsafe_origin_cast[MutUntrackedOrigin](),
            out_results.unsafe_origin_cast[MutUntrackedOrigin](),
        )

    @always_inline
    def keys_batch_encrypt(
        self,
        keys_handle: Int32,
        count: Int32,
        packet_numbers: Pointer[mut=True, T=UInt64, origin=_],
        packet_ptrs: Pointer[mut=True, T=Pointer[UInt8, MutUntrackedOrigin], origin=_],
        header_lens: Pointer[mut=True, T=Int32, origin=_],
        payload_lens: Pointer[mut=True, T=Int32, origin=_],
        buf_capacities: Pointer[mut=True, T=Int32, origin=_],
        out_ciphertext_lens: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """Batch AEAD encryption. Returns success count or -1."""
        return self._hot.keys_batch_encrypt(
            keys_handle, count,
            packet_numbers.unsafe_origin_cast[MutUntrackedOrigin](),
            packet_ptrs.unsafe_origin_cast[MutUntrackedOrigin](),
            header_lens.unsafe_origin_cast[MutUntrackedOrigin](),
            payload_lens.unsafe_origin_cast[MutUntrackedOrigin](),
            buf_capacities.unsafe_origin_cast[MutUntrackedOrigin](),
            out_ciphertext_lens.unsafe_origin_cast[MutUntrackedOrigin](),
        )

    @always_inline
    def keys_free(self, keys_handle: Int32) raises -> Int32:
        """Free keys. Returns 0 on success, -1 if handle not found."""
        return self._hot.keys_free(keys_handle)

    @always_inline
    def test_keys_free_count(self) raises -> UInt64:
        """[test-only] Read the number of successful keys_free calls.

        Only meaningful when librustls_mojo.so was built with
        --features test-instrumentation. Calling against a default build
        will fail at dlsym time (the symbol is gated on that feature).
        """
        return call_rlsm_test_keys_free_count(self._handle)

    @always_inline
    def test_keys_free_reset(self) raises -> Int32:
        """[test-only] Reset the keys-free counter to zero. Returns 0.

        Only meaningful when librustls_mojo.so was built with
        --features test-instrumentation.
        """
        return call_rlsm_test_keys_free_reset(self._handle)

    # -- QUIC Wave 2: handshake ------------------------------------------------

    @always_inline
    def quic_client_config_new(
        self,
        alpn_ptr: Pointer[mut=True, T=UInt8, origin=_], alpn_len: Int32,
        out_handle: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """Create a QUIC client TLS config with Mozilla WebPKI roots.

        Returns 0 on success, -1 on error. Handle written to out_handle.
        """
        return call_rlsm_quic_client_config_new(
            self._handle,
            alpn_ptr, alpn_len, out_handle,
        )

    @always_inline
    def quic_client_config_new_insecure(
        self,
        alpn_ptr: Pointer[mut=True, T=UInt8, origin=_], alpn_len: Int32,
        out_handle: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """Create a QUIC client TLS config that accepts ANY server cert.

        **Insecure** — feature-gated (`insecure` Cargo feature). Use only
        for local dev / CLI tools against self-signed certs.
        Returns 0 on success, -1 on error. Handle written to out_handle.
        """
        return call_rlsm_quic_client_config_new_insecure(
            self._handle,
            alpn_ptr, alpn_len, out_handle,
        )

    @always_inline
    def quic_server_config_new(
        self,
        cert_pem: Pointer[mut=True, T=UInt8, origin=_], cert_len: Int32,
        key_pem:  Pointer[mut=True, T=UInt8, origin=_], key_len:  Int32,
        alpn_ptr: Pointer[mut=True, T=UInt8, origin=_], alpn_len: Int32,
        max_early_data: UInt32,
        out_handle: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """Create QUIC server TLS config. Always-on TLS 1.3 session resumption
        (rustls aws_lc_rs Ticketer). max_early_data: 0 disables 0-RTT (default);
        UInt32(0xFFFFFFFF) enables 0-RTT (rustls QUIC accepts only those two
        values per RFC 9001 §4.6.1). Returns 0 on success, -1 on error
        (including any other max_early_data value)."""
        return call_rlsm_quic_server_config_new(
            self._handle,
            cert_pem, cert_len, key_pem, key_len, alpn_ptr, alpn_len,
            max_early_data, out_handle,
        )

    @always_inline
    def quic_client_config_with_ca(
        self,
        ca_pem:   Pointer[mut=True, T=UInt8, origin=_], ca_len:   Int32,
        alpn_ptr: Pointer[mut=True, T=UInt8, origin=_], alpn_len: Int32,
        out_handle: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """Create QUIC client TLS config trusting ca_pem (for testing). Returns 0."""
        return call_rlsm_quic_client_config_with_ca(
            self._handle,
            ca_pem, ca_len, alpn_ptr, alpn_len, out_handle,
        )

    @always_inline
    def quic_client_conn_new(
        self,
        config_handle: Int32,
        version: Int32,
        server_name: Pointer[mut=True, T=UInt8, origin=_], name_len: Int32,
        tp: Pointer[mut=True, T=UInt8, origin=_], tp_len: Int32,
        out_handle: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """Create QUIC client connection. Returns 0 on success."""
        return call_rlsm_quic_client_conn_new(
            self._handle,
            config_handle, version, server_name, name_len, tp, tp_len, out_handle,
        )

    @always_inline
    def quic_server_conn_new(
        self,
        config_handle: Int32,
        version: Int32,
        tp: Pointer[mut=True, T=UInt8, origin=_], tp_len: Int32,
        out_handle: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """Create QUIC server connection. Returns 0 on success."""
        return call_rlsm_quic_server_conn_new(
            self._handle,
            config_handle, version, tp, tp_len, out_handle,
        )

    def quic_server_conn_reject_early_data(self, conn_handle: Int32) raises -> Int32:
        """Decline 0-RTT; call before the connection is fed any CRYPTO data (rustls decides at the ClientHello).

        Returns 0, or -1 (bad handle, client, handshake done)."""
        return call_rlsm_quic_server_conn_reject_early_data(self._handle, conn_handle)

    @always_inline
    def quic_conn_free(self, conn_handle: Int32) raises -> Int32:
        """Free QUIC connection handle. Returns 0 on success."""
        return call_rlsm_quic_conn_free(self._handle, conn_handle)

    @always_inline
    def quic_conn_write_hs(
        self,
        conn_handle: Int32,
        out_buf: Pointer[mut=True, T=UInt8, origin=_],
        out_capacity: Int32,
        out_written: Pointer[mut=True, T=Int32, origin=_],
        out_kc: Pointer[mut=True, T=UInt8, origin=_],
    ) raises -> Int32:
        """Drain outgoing TLS bytes. out_kc: 0=none, 1=Handshake, 2=OneRtt. Returns 0."""
        return self._hot.quic_conn_write_hs(
            conn_handle,
            out_buf.unsafe_origin_cast[MutUntrackedOrigin](), out_capacity,
            out_written.unsafe_origin_cast[MutUntrackedOrigin](),
            out_kc.unsafe_origin_cast[MutUntrackedOrigin](),
        )

    @always_inline
    def quic_conn_read_hs(
        self,
        conn_handle: Int32,
        data: Pointer[mut=True, T=UInt8, origin=_],
        data_len: Int32,
        out_state_machine_us: Pointer[mut=True, T=UInt64, origin=_] = null_ptr[UInt64, MutUntrackedOrigin](),
        out_handle_lookup_us: Pointer[mut=True, T=UInt64, origin=_] = null_ptr[UInt64, MutUntrackedOrigin](),
    ) raises -> Int32:
        """Feed CRYPTO frame payload to TLS state machine. Returns 0 on success.

        Instrumentation out-params (both default-NULL, NULL-safe in Rust):
          out_state_machine_us: rustls read_hs body µs (slot 1).
          out_handle_lookup_us: with_mut handle-table lookup µs (slot 2).
        """
        return self._hot.quic_conn_read_hs(
            conn_handle,
            data.unsafe_origin_cast[MutUntrackedOrigin](), data_len,
            out_state_machine_us.unsafe_origin_cast[MutUntrackedOrigin](),
            out_handle_lookup_us.unsafe_origin_cast[MutUntrackedOrigin](),
        )

    @always_inline
    def quic_conn_take_keys(
        self,
        conn_handle: Int32,
        out_keys_handle: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """Move pending Keys into Wave 1 KEYS_TABLE. Returns 0 on success."""
        return call_rlsm_quic_conn_take_keys(
            self._handle,
            conn_handle, out_keys_handle,
        )

    @always_inline
    def quic_conn_is_handshaking(self, conn_handle: Int32) raises -> Int32:
        """Returns 1 if handshaking, 0 if complete, -1 on invalid handle."""
        return self._hot.quic_conn_is_handshaking(conn_handle)

    @always_inline
    def quic_conn_handshake_kind(self, conn_handle: Int32) raises -> Int32:
        """Returns -2 client, -1 invalid, 0 unknown, 1 Full, 2 Resumed, 3 FullWithHRR."""
        return self._hot.quic_conn_handshake_kind(conn_handle)

    @always_inline
    def quic_conn_transport_params(
        self,
        conn_handle: Int32,
        out_buf: Pointer[mut=True, T=UInt8, origin=_],
        out_capacity: Int32,
        out_written: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """Read peer transport params. Returns 0 (available), 1 (not yet), -1 (error)."""
        return self._hot.quic_conn_transport_params(
            conn_handle,
            out_buf.unsafe_origin_cast[MutUntrackedOrigin](), out_capacity,
            out_written.unsafe_origin_cast[MutUntrackedOrigin](),
        )

    @always_inline
    def quic_conn_alert(self, conn_handle: Int32) raises -> Int32:
        """Read cached TLS alert code. Returns alert number, or -1 if no alert."""
        return self._hot.quic_conn_alert(conn_handle)

    @always_inline
    def quic_server_conn_zero_rtt_keys(
        self,
        conn_handle: Int32,
        out_keys_handle: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
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
        return call_rlsm_quic_server_conn_zero_rtt_keys(
            self._handle,
            conn_handle, out_keys_handle,
        )

    @always_inline
    def quic_server_conn_replay_authenticator(
        self,
        conn_handle: Int32,
        out_buf: Pointer[mut=True, T=UInt8, origin=_],
        out_len: Pointer[mut=True, T=UInt, origin=_],
    ) raises -> Int32:
        """Fetch the 32-byte 0-RTT replay authenticator (ClientHello.random)
        captured by the shim on the first server-side `read_hs` call.

        Returns 0 on success (`*out_len = 32`, `out_buf` holds 32 bytes),
        1 when the random has not yet been captured (no ClientHello seen,
        or fewer than 38 bytes accumulated; `*out_len = 0`), or -1 on
        anomaly (invalid handle or client variant). RFC 8446 §8 anchors
        the authenticator-as-replay-key invariant; the captured 32 bytes
        are opaque to Mojo — bytewise equality is the dedup contract.
        """
        return call_rlsm_quic_server_conn_replay_authenticator(
            self._handle,
            conn_handle, out_buf, out_len,
        )

    # -- Raw AES-GCM-128 -------------------------------------------------------

    @always_inline
    def aes_gcm_128_seal(
        self,
        key: Pointer[mut=True, T=UInt8, origin=_], key_len: Int32,
        nonce: Pointer[mut=True, T=UInt8, origin=_], nonce_len: Int32,
        aad: Pointer[mut=True, T=UInt8, origin=_], aad_len: Int32,
        plaintext: Pointer[mut=True, T=UInt8, origin=_], pt_len: Int32,
        out_buf: Pointer[mut=True, T=UInt8, origin=_],
        out_len: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """AES-GCM-128 encrypt. out_buf must hold pt_len + 16 bytes. Returns 0 or -1."""
        return call_rlsm_aes_gcm_128_seal(
            self._handle,
            key, key_len, nonce, nonce_len, aad, aad_len,
            plaintext, pt_len, out_buf, out_len,
        )

    @always_inline
    def aes_gcm_128_open(
        self,
        key: Pointer[mut=True, T=UInt8, origin=_], key_len: Int32,
        nonce: Pointer[mut=True, T=UInt8, origin=_], nonce_len: Int32,
        aad: Pointer[mut=True, T=UInt8, origin=_], aad_len: Int32,
        ciphertext: Pointer[mut=True, T=UInt8, origin=_], ct_len: Int32,
        out_buf: Pointer[mut=True, T=UInt8, origin=_],
        out_len: Pointer[mut=True, T=Int32, origin=_],
    ) raises -> Int32:
        """AES-GCM-128 decrypt. ct_len includes 16-byte tag. Returns 0 or -1."""
        return call_rlsm_aes_gcm_128_open(
            self._handle,
            key, key_len, nonce, nonce_len, aad, aad_len,
            ciphertext, ct_len, out_buf, out_len,
        )

    # -- Microbench: thunk overhead --------------------------------------------

    @always_inline
    def noop(self) raises -> Int32:
        """No-op FFI call — for thunk-overhead microbench.
        Returns 0. Body in Rust is `pub extern \"C\" fn rlsm_noop() -> i32 { 0 }`."""
        return call_rlsm_noop(self._handle)

    # -- Raw HMAC-SHA256 -------------------------------------------------------

    @always_inline
    def hmac_sha256(
        self,
        key: Pointer[mut=True, T=UInt8, origin=_], key_len: Int32,
        msg: Pointer[mut=True, T=UInt8, origin=_], msg_len: Int32,
        out_buf: Pointer[mut=True, T=UInt8, origin=_],
    ) raises -> Int32:
        """HMAC-SHA256. out_buf must hold 32 bytes. Returns 0 or -1."""
        return call_rlsm_hmac_sha256(
            self._handle,
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


struct SharedLibrary(Copyable, Movable):
    """Ref-counted handle to a RustlsLibrary.

    Internal type — consumers use `TlsBackend`. Every copy increments
    the refcount; destruction decrements it. When the count reaches zero
    the inner `RustlsLibrary` (and its `OwnedDLHandle`) is destroyed.
    """

    var _ptr: Pointer[_SharedLibraryInner, MutUntrackedOrigin]

    def __init__(out self, var lib: RustlsLibrary):
        var p = _heap_alloc[_SharedLibraryInner](1).unsafe_origin_cast[
            MutUntrackedOrigin
        ]()
        p.unsafe_write(_SharedLibraryInner(lib^))
        self._ptr = p

    def __init__(out self, *, copy: Self):
        copy._ptr[].refcount += 1
        self._ptr = copy._ptr

    def __deinit__(deinit self):
        self._ptr[].refcount -= 1
        if self._ptr[].refcount == 0:
            self._ptr.unsafe_deinit_pointee()
            self._ptr.unsafe_free()

    @always_inline
    def inner_ptr(self) -> Pointer[RustlsLibrary, MutUntrackedOrigin]:
        return Pointer(to=self._ptr[].lib).unsafe_origin_cast[
            MutUntrackedOrigin
        ]()


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

    def __init__(out self, *, copy: Self):
        self._lib = SharedLibrary(copy=copy._lib)

    def shared(self) -> SharedLibrary:
        return SharedLibrary(copy=self._lib)
