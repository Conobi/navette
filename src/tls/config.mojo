# src/tls/config.mojo
#
# RAII wrappers for rustls config handles.
#
# TlsClientConfig wraps a `rlsm_client_config_new[_insecure]` handle.
# TlsServerConfig wraps a `rlsm_server_config_new` handle (PEM cert + key).
#
# Both store a non-owning UInt64 address of the RustlsLibrary that created
# them — the caller MUST ensure the library outlives any config it produced.
# Destructors call `rlsm_config_free`.
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.memory import Span

from .lib import RustlsLibrary


struct TlsClientConfig(Movable):
    """RAII wrapper for a rustls client config handle."""

    var _lib_addr: UInt64
    var _handle: Int32

    def __init__(
        out self, ref lib: RustlsLibrary, *, insecure: Bool = False
    ) raises:
        """Create a client config.

        Args:
            lib: The loaded RustlsLibrary (must outlive the config).
            insecure: If True, use a config that accepts any certificate.
                      Requires librustls_mojo.so built with --features insecure.
        """
        self._lib_addr = UInt64(Int(UnsafePointer(to=lib)))
        if insecure:
            self._handle = lib.client_config_new_insecure()
        else:
            self._handle = lib.client_config_new()
        if self._handle < 0:
            raise "rlsm_client_config_new failed: " + lib.last_error()

    def __init__(out self, *, deinit take: Self):
        self._lib_addr = take._lib_addr
        self._handle = take._handle

    def __del__(deinit self):
        if self._handle > 0:
            _ = self._lib()[].config_free(self._handle)

    @always_inline
    def _lib(self) -> UnsafePointer[RustlsLibrary, MutAnyOrigin]:
        return UnsafePointer[RustlsLibrary, MutAnyOrigin](
            unsafe_from_address=Int(self._lib_addr)
        )

    @always_inline
    def handle(self) -> Int32:
        """Return the raw config handle (borrowed; do not free)."""
        return self._handle


struct TlsServerConfig(Movable):
    """RAII wrapper for a rustls server config handle."""

    var _lib_addr: UInt64
    var _handle: Int32

    def __init__(
        out self,
        ref lib: RustlsLibrary,
        cert_pem: Span[UInt8, _],
        key_pem: Span[UInt8, _],
    ) raises:
        """Create a server config from PEM certificate chain + private key.

        The cert/key bytes are copied into temporary heap buffers for the
        FFI call and freed before returning, so the caller's spans only
        need to be valid for the duration of `__init__`.
        """
        self._lib_addr = UInt64(Int(UnsafePointer(to=lib)))

        var cert_len = len(cert_pem)
        var key_len = len(key_pem)

        var cert_buf = _heap_alloc[UInt8](cert_len).as_any_origin()
        for i in range(cert_len):
            cert_buf[i] = cert_pem[i]

        var key_buf = _heap_alloc[UInt8](key_len).as_any_origin()
        for i in range(key_len):
            key_buf[i] = key_pem[i]

        var handle = lib.server_config_new(
            cert_buf,
            Int32(cert_len),
            key_buf,
            Int32(key_len),
        )

        cert_buf.free()
        key_buf.free()

        if handle < 0:
            self._handle = handle
            raise "rlsm_server_config_new failed: " + lib.last_error()
        self._handle = handle

    def __init__(out self, *, deinit take: Self):
        self._lib_addr = take._lib_addr
        self._handle = take._handle

    def __del__(deinit self):
        if self._handle > 0:
            _ = self._lib()[].config_free(self._handle)

    @always_inline
    def _lib(self) -> UnsafePointer[RustlsLibrary, MutAnyOrigin]:
        return UnsafePointer[RustlsLibrary, MutAnyOrigin](
            unsafe_from_address=Int(self._lib_addr)
        )

    @always_inline
    def handle(self) -> Int32:
        """Return the raw config handle (borrowed; do not free)."""
        return self._handle
