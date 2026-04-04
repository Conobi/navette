# conformance/lib/rustls.mojo
#
# RAII wrapper around librustls_mojo.so for use in conformance tests.
# Loads the shared library via OwnedDLHandle and exposes typed Mojo
# functions for the rlsm_* C FFI symbols.
from std.ffi import OwnedDLHandle
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc


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
        var buf = _heap_alloc[UInt8](512).as_any_origin()
        var n = self._handle.call["rlsm_last_error", Int32](buf, Int32(512))
        if n <= 0:
            buf.free()
            return String("")
        # n includes the NUL terminator; the message is n-1 bytes.
        # Build the String byte-by-byte (safe for Mojo 0.26.2).
        var msg = String()
        for i in range(Int(n - 1)):
            msg += chr(Int(buf[i]))
        buf.free()
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
