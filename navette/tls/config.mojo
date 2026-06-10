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
from navette.tls.early_data_filter import (
    EarlyDataPredicateFn,
    IdempotentOnlyFilter,
)
from navette.tls.early_data_policy import EarlyDataPolicy
from navette.tls.early_data_store import InMemoryEarlyDataStore


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
    var _early_data_store: Optional[InMemoryEarlyDataStore]
    var _early_data_filter: Optional[IdempotentOnlyFilter]
    """RFC 8470 HTTP early-data filter. Population is per policy
    variant: Off (or legacy `max_early_data == 0`) populates neither
    this field nor `_early_data_predicate_fn`; IdempotentOnly / Tuned
    (or legacy `max_early_data > 0` with `policy` omitted) populate
    this struct filter, paired with `_early_data_store`; Predicate
    enables 0-RTT (`max_early_data = u32::MAX`) but leaves this field
    `None` and populates `_early_data_predicate_fn` instead. The
    H3-layer dispatch helper reads this field to decide whether to
    admit or reject (425) a 0-RTT-tagged request."""
    var _early_data_predicate_fn: Optional[EarlyDataPredicateFn]
    """User-supplied 0-RTT predicate function from
    `EarlyDataPolicy.predicate(...)`. Populated only when the policy
    is the Predicate variant; mutually exclusive with
    `_early_data_filter` (the synchronised-population invariant)."""

    def __init__(
        out self,
        lib: SharedLibrary,
        cert_pem: Span[UInt8, _],
        key_pem: Span[UInt8, _],
        alpn: String = "h3",
        max_early_data: UInt32 = UInt32(0),
        policy: Optional[EarlyDataPolicy] = None,
    ) raises:
        """Build a rustls QUIC server config from PEM cert + key.

        Args:
            lib: SharedLibrary handle (refcount is incremented).
            cert_pem: PEM-encoded certificate chain bytes.
            key_pem: PEM-encoded private-key bytes.
            alpn: ALPN protocol id (default "h3").
            max_early_data: legacy 0-RTT enable knob, kept for
                backward compatibility with existing callers.
                `UInt32(0)` disables 0-RTT (rejection mode);
                `UInt32::MAX` enables acceptance (rustls QUIC, RFC
                9001 §4.6.1). Prefer the `policy=` kwarg for new code.
            policy: public `EarlyDataPolicy` ctor kwarg (default
                `None`, meaning "kwarg omitted; honor the legacy
                `max_early_data` reading unchanged"). When the caller
                supplies a non-None policy, it overrides the legacy
                semantics: `EarlyDataPolicy.off()` disables 0-RTT and
                conflicts with `max_early_data > 0`;
                `EarlyDataPolicy.idempotent_only()` or
                `EarlyDataPolicy.tuned(...)` enables 0-RTT (sets
                `_max_early_data` to `u32::MAX`) and populates both
                `_early_data_store` + `_early_data_filter`.
                `tuned(...)` threads the user-supplied
                `EarlyDataStoreConfig` into the store.

        Raises:
            Error: when the rustls FFI ctor reports failure, OR when
                the caller passes BOTH `max_early_data > 0` AND
                `policy=EarlyDataPolicy.off()` — the contradictory
                operator-intent case (only triggers when `policy` is
                explicitly supplied; the default `None` does not
                conflict with the legacy enable kwarg). The
                contradictory-kwarg error message contains the stable
                substring `"contradictory early-data kwargs"` (API
                contract; operator-facing diagnostic).
        """
        # Reject contradictory kwarg combinations early, before the
        # rustls FFI call. Fail-fast keeps the FFI resource graph
        # uninstantiated under operator confusion and surfaces the
        # mistake at the call site rather than at first handshake.
        #
        # The check fires only when the caller PASSED `policy`
        # explicitly (Some(...)). Omitting the kwarg leaves the
        # legacy `max_early_data` reading untouched — preserving the
        # observable behaviour for callers that have not migrated.
        if (
            max_early_data != UInt32(0)
            and policy is not None
            and policy.value().is_off()
        ):
            raise Error(
                "QuicServerConfig: contradictory early-data kwargs: "
                "max_early_data > 0 with policy=EarlyDataPolicy.off(). "
                "Pass either (a) policy=EarlyDataPolicy.idempotent_only() "
                "or .tuned(...) to enable 0-RTT, OR (b) max_early_data=0 "
                "(or omit it) to disable. Do not pass both."
            )

        # Resolve the effective max_early_data:
        #   - explicit, enabled policy → u32::MAX (policy wins).
        #   - explicit, Off policy     → legacy max_early_data
        #                                  (already guaranteed 0 by
        #                                  the contradictory-kwargs
        #                                  check above).
        #   - omitted policy           → legacy max_early_data
        #                                  (untouched backward-compat
        #                                  path).
        var effective_max_early_data: UInt32
        if policy is not None and policy.value().is_enabled():
            effective_max_early_data = UInt32(0xFFFFFFFF)
        else:
            effective_max_early_data = max_early_data

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
            effective_max_early_data,
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
            self._early_data_store = None
            self._early_data_filter = None
            self._early_data_predicate_fn = None
            raise "quic_server_config_new failed: " + err
        self._handle = out_handle[0]
        out_handle.free()
        self._max_early_data = effective_max_early_data
        # Synchronised-population invariant: when 0-RTT is enabled,
        # exactly one of `_early_data_filter` / `_early_data_predicate_fn`
        # is Some; the store is Some in both cases. When 0-RTT is
        # disabled, all three are None.
        if effective_max_early_data == UInt32(0):
            self._early_data_store = None
            self._early_data_filter = None
            self._early_data_predicate_fn = None
        elif policy is not None and policy.value().is_predicate():
            # Predicate variant: default store, no struct filter,
            # carry the fn-pointer.
            self._early_data_store = Optional[InMemoryEarlyDataStore](
                InMemoryEarlyDataStore()
            )
            self._early_data_filter = None
            self._early_data_predicate_fn = policy.value().predicate_fn()
        elif policy is not None and policy.value().is_tuned():
            # Tuned: thread the caller's store config through to
            # the in-memory store. `store_config()` returns Some
            # by construction whenever `is_tuned()` is true, so
            # the inner `.value()` is safe here.
            self._early_data_store = Optional[InMemoryEarlyDataStore](
                InMemoryEarlyDataStore(
                    config=policy.value().store_config().value().copy()
                )
            )
            self._early_data_filter = Optional[IdempotentOnlyFilter](
                IdempotentOnlyFilter()
            )
            self._early_data_predicate_fn = None
        else:
            # IdempotentOnly, or the omitted-policy legacy path
            # (`max_early_data > 0` without `policy=`): install
            # the default store config so the synchronised-
            # population invariant holds for both enable
            # surfaces.
            self._early_data_store = Optional[InMemoryEarlyDataStore](
                InMemoryEarlyDataStore()
            )
            self._early_data_filter = Optional[IdempotentOnlyFilter](
                IdempotentOnlyFilter()
            )
            self._early_data_predicate_fn = None

    def __init__(out self, *, deinit take: Self):
        self._lib = take._lib^
        self._handle = take._handle
        self._max_early_data = take._max_early_data
        self._early_data_store = take._early_data_store^
        self._early_data_filter = take._early_data_filter^
        self._early_data_predicate_fn = take._early_data_predicate_fn

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
