# src/tls/config.mojo
#
# RAII wrappers for rustls config handles.
#
# TlsClientConfig wraps a `rlsm_client_config_new[_insecure]` handle.
# TlsServerConfig wraps a `rlsm_server_config_new` handle (PEM cert + key).
#
# Each config holds a SharedLibrary (ref-counted) so the underlying
# RustlsLibrary stays alive as long as any config or connection exists.
# Destructors call `rlsm_config_free`.
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.memory import Span

from .lib import SharedLibrary


struct TlsClientConfig(Movable):
    """RAII wrapper for a rustls client config handle."""

    var _lib: SharedLibrary
    var _handle: Int32

    def __init__(
        out self, lib: SharedLibrary, *, insecure: Bool = False
    ) raises:
        """Create a client config.

        Args:
            lib: SharedLibrary handle (refcount is incremented).
            insecure: If True, use a config that accepts any certificate.
                      Requires librustls_mojo.so built with --features insecure.
        """
        self._lib = SharedLibrary(other=lib)
        var rlib = self._lib.inner_ptr()
        if insecure:
            self._handle = rlib[].client_config_new_insecure()
        else:
            self._handle = rlib[].client_config_new()
        if self._handle < 0:
            raise "rlsm_client_config_new failed: " + rlib[].last_error()

    def __init__(out self, *, deinit take: Self):
        self._lib = take._lib^
        self._handle = take._handle

    def __del__(deinit self):
        if self._handle > 0:
            _ = self._lib.inner_ptr()[].config_free(self._handle)

    @always_inline
    def handle(self) -> Int32:
        """Return the raw config handle (borrowed; do not free)."""
        return self._handle

    def set_alpn_protocols(mut self, protocols: List[String]) raises:
        """Set ALPN protocol preferences. Call before creating connections.

        Protocols are ordered by preference (e.g., ["h2", "http/1.1"]).
        Encoded to length-prefixed wire format for the Rust FFI.
        """
        # Encode to length-prefixed wire format
        var buf = List[UInt8]()
        for i in range(len(protocols)):
            var proto = protocols[i]
            var proto_bytes = proto.as_bytes()
            var proto_len = len(proto_bytes)
            buf.append(UInt8(proto_len))
            for j in range(proto_len):
                buf.append(proto_bytes[j])
        var buf_ptr = _heap_alloc[UInt8](len(buf)).as_any_origin()
        for i in range(len(buf)):
            buf_ptr[i] = buf[i]
        var rc = self._lib.inner_ptr()[].config_set_alpn_protocols(
            self._handle, buf_ptr, Int32(len(buf))
        )
        buf_ptr.free()
        if rc < 0:
            raise "set_alpn_protocols failed: " + self._lib.inner_ptr()[].last_error()


struct TlsServerConfig(Movable):
    """RAII wrapper for a rustls server config handle."""

    var _lib: SharedLibrary
    var _handle: Int32

    def __init__(
        out self,
        lib: SharedLibrary,
        cert_pem: Span[UInt8, _],
        key_pem: Span[UInt8, _],
    ) raises:
        """Create a server config from PEM certificate chain + private key.

        The cert/key bytes are copied into temporary heap buffers for the
        FFI call and freed before returning, so the caller's spans only
        need to be valid for the duration of `__init__`.
        """
        self._lib = SharedLibrary(other=lib)

        var cert_len = len(cert_pem)
        var key_len = len(key_pem)

        var cert_buf = _heap_alloc[UInt8](cert_len).as_any_origin()
        for i in range(cert_len):
            cert_buf[i] = cert_pem[i]

        var key_buf = _heap_alloc[UInt8](key_len).as_any_origin()
        for i in range(key_len):
            key_buf[i] = key_pem[i]

        var rlib = self._lib.inner_ptr()
        var handle = rlib[].server_config_new(
            cert_buf,
            Int32(cert_len),
            key_buf,
            Int32(key_len),
        )

        cert_buf.free()
        key_buf.free()

        if handle < 0:
            self._handle = handle
            raise "rlsm_server_config_new failed: " + rlib[].last_error()
        self._handle = handle

    def __init__(out self, *, deinit take: Self):
        self._lib = take._lib^
        self._handle = take._handle

    def __del__(deinit self):
        if self._handle > 0:
            _ = self._lib.inner_ptr()[].config_free(self._handle)

    @always_inline
    def handle(self) -> Int32:
        """Return the raw config handle (borrowed; do not free)."""
        return self._handle

    def set_alpn_protocols(mut self, protocols: List[String]) raises:
        """Set ALPN protocol preferences. Call before creating connections.

        Protocols are ordered by preference (e.g., ["h2", "http/1.1"]).
        Encoded to length-prefixed wire format for the Rust FFI.
        """
        # Encode to length-prefixed wire format
        var buf = List[UInt8]()
        for i in range(len(protocols)):
            var proto = protocols[i]
            var proto_bytes = proto.as_bytes()
            var proto_len = len(proto_bytes)
            buf.append(UInt8(proto_len))
            for j in range(proto_len):
                buf.append(proto_bytes[j])
        var buf_ptr = _heap_alloc[UInt8](len(buf)).as_any_origin()
        for i in range(len(buf)):
            buf_ptr[i] = buf[i]
        var rc = self._lib.inner_ptr()[].config_set_alpn_protocols(
            self._handle, buf_ptr, Int32(len(buf))
        )
        buf_ptr.free()
        if rc < 0:
            raise "set_alpn_protocols failed: " + self._lib.inner_ptr()[].last_error()


struct QuicServerConfig(Movable):
    """RAII wrapper for a rustls QUIC server config handle."""

    var _lib: SharedLibrary
    var _handle: Int32
    var _max_early_data: UInt32

    def __init__(
        out self,
        lib: SharedLibrary,
        cert_pem: Span[UInt8, _],
        key_pem: Span[UInt8, _],
        alpn: String = "h3",
        max_early_data: UInt32 = UInt32(0),
    ) raises:
        self._lib = SharedLibrary(other=lib)

        var cert_len = len(cert_pem)
        var key_len = len(key_pem)

        var cert_buf = _heap_alloc[UInt8](cert_len).as_any_origin()
        for i in range(cert_len):
            cert_buf[i] = cert_pem[i]

        var key_buf = _heap_alloc[UInt8](key_len).as_any_origin()
        for i in range(key_len):
            key_buf[i] = key_pem[i]

        var alpn_bytes = alpn.as_bytes()
        var alpn_len = len(alpn_bytes)
        var alpn_buf = _heap_alloc[UInt8](alpn_len).as_any_origin()
        for i in range(alpn_len):
            alpn_buf[i] = alpn_bytes[i]

        var out_handle = _heap_alloc[Int32](1).as_any_origin()
        out_handle[0] = Int32(-1)
        var rlib = self._lib.inner_ptr()
        var rc = rlib[].quic_server_config_new(
            cert_buf, Int32(cert_len),
            key_buf, Int32(key_len),
            alpn_buf, Int32(alpn_len),
            max_early_data,
            out_handle,
        )

        cert_buf.free()
        key_buf.free()
        alpn_buf.free()

        if rc != 0:
            var err = rlib[].last_error()
            out_handle.free()
            self._handle = Int32(-1)
            self._max_early_data = UInt32(0)
            raise "quic_server_config_new failed: " + err
        self._handle = out_handle[0]
        out_handle.free()
        self._max_early_data = max_early_data

    def __init__(out self, *, deinit take: Self):
        self._lib = take._lib^
        self._handle = take._handle
        self._max_early_data = take._max_early_data

    def __del__(deinit self):
        if self._handle > 0:
            _ = self._lib.inner_ptr()[].config_free(self._handle)

    @always_inline
    def handle(self) -> Int32:
        return self._handle

    @always_inline
    def max_early_data(self) -> UInt32:
        """Return the max_early_data value set at construction. UInt32(0)
        means 0-RTT is disabled (rejection mode); UInt32::MAX means
        0-RTT decrypt is enabled (rustls QUIC constraint, RFC 9001 §4.6.1)."""
        return self._max_early_data


struct QuicClientConfig(Movable):
    """RAII wrapper for a rustls QUIC client config handle."""

    var _lib: SharedLibrary
    var _handle: Int32

    def __init__(
        out self,
        lib: SharedLibrary,
        *,
        alpn: String = "h3",
        insecure: Bool = False,
    ) raises:
        """Create a QUIC client config.

        Args:
            lib: SharedLibrary handle (refcount is incremented).
            alpn: ALPN protocol identifier (default "h3").
            insecure: If True, accept any server certificate.
                      Requires librustls_mojo.so built with --features insecure.
        """
        self._lib = SharedLibrary(other=lib)

        var alpn_bytes = alpn.as_bytes()
        var alpn_len = len(alpn_bytes)
        var alpn_buf = _heap_alloc[UInt8](alpn_len).as_any_origin()
        for i in range(alpn_len):
            alpn_buf[i] = alpn_bytes[i]

        var out_handle = _heap_alloc[Int32](1).as_any_origin()
        out_handle[0] = Int32(-1)

        var rlib = self._lib.inner_ptr()
        var rc: Int32
        if insecure:
            rc = rlib[].quic_client_config_new_insecure(
                alpn_buf, Int32(alpn_len), out_handle,
            )
        else:
            rc = rlib[].quic_client_config_new(
                alpn_buf, Int32(alpn_len), out_handle,
            )

        alpn_buf.free()

        if rc != 0:
            var err = rlib[].last_error()
            out_handle.free()
            self._handle = Int32(-1)
            raise "quic_client_config_new failed: " + err
        self._handle = out_handle[0]
        out_handle.free()

    def __init__(out self, *, _lib: SharedLibrary, _handle: Int32):
        """Private constructor for static factory methods."""
        self._lib = SharedLibrary(other=_lib)
        self._handle = _handle

    @staticmethod
    def with_ca(
        lib: SharedLibrary,
        ca_pem: Span[UInt8, _],
        alpn: String = "h3",
    ) raises -> QuicClientConfig:
        """Create a QUIC client config trusting a specific CA certificate.

        Args:
            lib: SharedLibrary handle (refcount is incremented).
            ca_pem: PEM-encoded CA certificate bytes.
            alpn: ALPN protocol identifier (default "h3").
        """
        var ca_len = len(ca_pem)
        var ca_buf = _heap_alloc[UInt8](ca_len).as_any_origin()
        for i in range(ca_len):
            ca_buf[i] = ca_pem[i]

        var alpn_bytes = alpn.as_bytes()
        var alpn_len = len(alpn_bytes)
        var alpn_buf = _heap_alloc[UInt8](alpn_len).as_any_origin()
        for i in range(alpn_len):
            alpn_buf[i] = alpn_bytes[i]

        var out_handle = _heap_alloc[Int32](1).as_any_origin()
        out_handle[0] = Int32(-1)
        var rlib = lib.inner_ptr()
        var rc = rlib[].quic_client_config_with_ca(
            ca_buf, Int32(ca_len),
            alpn_buf, Int32(alpn_len),
            out_handle,
        )

        ca_buf.free()
        alpn_buf.free()

        if rc != 0:
            var err = rlib[].last_error()
            var handle = out_handle[0]
            out_handle.free()
            raise "quic_client_config_with_ca failed: " + err
        var handle = out_handle[0]
        out_handle.free()
        return QuicClientConfig(_lib=lib, _handle=handle)

    def __init__(out self, *, deinit take: Self):
        self._lib = take._lib^
        self._handle = take._handle

    def __del__(deinit self):
        if self._handle > 0:
            _ = self._lib.inner_ptr()[].config_free(self._handle)

    @always_inline
    def handle(self) -> Int32:
        """Return the raw config handle (borrowed; do not free)."""
        return self._handle
