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
from navette.util.owned_alloc import Owned
from std.collections import Span
from std.utils import Variant

from .lib import SharedLibrary
from navette.tls.early_data_filter import (
    EarlyDataPredicateFn,
    IdempotentOnlyFilter,
)
from navette.tls.early_data_policy import EarlyDataPolicy
from navette.tls.early_data_store import InMemoryEarlyDataStore


struct FilterStrategy(Movable):
    """IdempotentOnly / Tuned: store + HTTP-method filter."""
    var store: InMemoryEarlyDataStore
    var filter: IdempotentOnlyFilter

    def __init__(out self, var store: InMemoryEarlyDataStore, var filter: IdempotentOnlyFilter):
        self.store = store^
        self.filter = filter^

    def __init__(out self, *, deinit move: Self):
        self.store = move.store^
        self.filter = move.filter^


struct PredicateStrategy(Movable):
    """Predicate: store + user-supplied predicate function."""
    var store: InMemoryEarlyDataStore
    var predicate_fn: EarlyDataPredicateFn

    def __init__(out self, var store: InMemoryEarlyDataStore, predicate_fn: EarlyDataPredicateFn):
        self.store = store^
        self.predicate_fn = predicate_fn

    def __init__(out self, *, deinit move: Self):
        self.store = move.store^
        self.predicate_fn = move.predicate_fn


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
        self._lib = SharedLibrary(copy=lib)
        var rlib = self._lib.inner_ptr()
        if insecure:
            self._handle = rlib[].client_config_new_insecure()
        else:
            self._handle = rlib[].client_config_new()
        if self._handle < 0:
            raise "rlsm_client_config_new failed: " + rlib[].last_error()

    def __init__(out self, *, deinit move: Self):
        self._lib = move._lib^
        self._handle = move._handle

    def __deinit__(deinit self):
        """Release the Rust-side config handle.

        A destructor may not raise. `config_free` can, but only from the
        symbol lookup: the Rust side returns -1 for an unknown handle
        rather than raising, and that status is already discarded here
        because a config that is not in the table needs no freeing.

        A lookup failure means the loaded librustls_mojo.so does not
        export `rlsm_config_free`, i.e. it is not the library the handle
        was created by. Swallowing it leaks one entry in the Rust
        CONFIG_TABLE; the alternative in a destructor is aborting the
        process while tearing a connection down, which is worse. Double
        free is impossible: `deinit self` consumes the config, so this
        runs exactly once per handle.
        """
        if self._handle > 0:
            try:
                _ = self._lib.inner_ptr()[].config_free(self._handle)
            except:
                pass
        # Anchor: `inner_ptr()` returns an untracked pointer, so the checker
        # cannot see that the call above depends on `_lib`. Without a later
        # reference, ASAP destruction frees `_lib` at that line -- closing the
        # dylib -- and the FFI call runs through a null handle.
        _ = self._lib.inner_ptr()

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
        var buf_ptr_buf = Owned[UInt8](len(buf))
        var buf_ptr = buf_ptr_buf.ptr()
        for i in range(len(buf)):
            buf_ptr[unsafe_offset=i] = buf[i]
        var rc = self._lib.inner_ptr()[].config_set_alpn_protocols(
            self._handle, buf_ptr, Int32(len(buf))
        )
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
        self._lib = SharedLibrary(copy=lib)

        var cert_len = len(cert_pem)
        var key_len = len(key_pem)

        var cert_buf_buf = Owned[UInt8](cert_len)
        var cert_buf = cert_buf_buf.ptr()
        for i in range(cert_len):
            cert_buf[unsafe_offset=i] = cert_pem[i]

        var key_buf_buf = Owned[UInt8](key_len)
        var key_buf = key_buf_buf.ptr()
        for i in range(key_len):
            key_buf[unsafe_offset=i] = key_pem[i]

        var rlib = self._lib.inner_ptr()
        var handle = rlib[].server_config_new(
            cert_buf,
            Int32(cert_len),
            key_buf,
            Int32(key_len),
        )

        if handle < 0:
            self._handle = handle
            raise "rlsm_server_config_new failed: " + rlib[].last_error()
        self._handle = handle

    def __init__(out self, *, deinit move: Self):
        self._lib = move._lib^
        self._handle = move._handle

    def __deinit__(deinit self):
        """Release the Rust-side config handle.

        A destructor may not raise. `config_free` can, but only from the
        symbol lookup: the Rust side returns -1 for an unknown handle
        rather than raising, and that status is already discarded here
        because a config that is not in the table needs no freeing.

        A lookup failure means the loaded librustls_mojo.so does not
        export `rlsm_config_free`, i.e. it is not the library the handle
        was created by. Swallowing it leaks one entry in the Rust
        CONFIG_TABLE; the alternative in a destructor is aborting the
        process while tearing a connection down, which is worse. Double
        free is impossible: `deinit self` consumes the config, so this
        runs exactly once per handle.
        """
        if self._handle > 0:
            try:
                _ = self._lib.inner_ptr()[].config_free(self._handle)
            except:
                pass
        # Anchor: `inner_ptr()` returns an untracked pointer, so the checker
        # cannot see that the call above depends on `_lib`. Without a later
        # reference, ASAP destruction frees `_lib` at that line -- closing the
        # dylib -- and the FFI call runs through a null handle.
        _ = self._lib.inner_ptr()

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
        var buf_ptr_buf = Owned[UInt8](len(buf))
        var buf_ptr = buf_ptr_buf.ptr()
        for i in range(len(buf)):
            buf_ptr[unsafe_offset=i] = buf[i]
        var rc = self._lib.inner_ptr()[].config_set_alpn_protocols(
            self._handle, buf_ptr, Int32(len(buf))
        )
        if rc < 0:
            raise "set_alpn_protocols failed: " + self._lib.inner_ptr()[].last_error()


struct QuicServerConfig(Movable):
    """RAII wrapper for a rustls QUIC server config handle."""

    var _lib: SharedLibrary
    var _handle: Int32
    var _max_early_data: UInt32
    var _early_data: Variant[NoneType, FilterStrategy, PredicateStrategy]
    """Early-data strategy Variant: NoneType (Off), FilterStrategy
    (IdempotentOnly/Tuned: store + filter), PredicateStrategy
    (Predicate: store + user-supplied fn)."""

    def __init__(
        out self,
        lib: SharedLibrary,
        cert_pem: Span[UInt8, _],
        key_pem: Span[UInt8, _],
        alpn: String = "h3",
        max_early_data: Optional[UInt32] = None,
        policy: Optional[EarlyDataPolicy] = None,
    ) raises:
        """Build a rustls QUIC server config from PEM cert + key.

        Early-data kwarg resolution (total — every cell):

        | `max_early_data` | `policy`  | result                          |
        |------------------|-----------|---------------------------------|
        | omitted          | omitted   | 0-RTT off (default)             |
        | Some(v), any v   | omitted   | legacy semantics, effective = v |
        | omitted          | off()     | 0-RTT off (kwargs agree)        |
        | omitted          | enabling  | policy decides: u32::MAX        |
        | Some(0)          | off()     | 0-RTT off (kwargs agree)        |
        | Some(v>0)        | off()     | raise (contradictory)           |
        | Some(0)          | enabling  | raise (contradictory)           |
        | Some(v>0)        | enabling  | policy wins: u32::MAX           |

        "enabling" means `policy.value().is_enabled()` — true for the
        IdempotentOnly, Tuned, and Predicate variants; false for Off.

        Args:
            lib: SharedLibrary handle (refcount is incremented).
            cert_pem: PEM-encoded certificate chain bytes.
            key_pem: PEM-encoded private-key bytes.
            alpn: ALPN protocol id (default "h3").
            max_early_data: Legacy 0-RTT enable knob, kept for
                backward compatibility with existing callers. `None`
                (omitted) defers entirely to `policy`. `UInt32(0)`
                explicitly disables 0-RTT (rejection mode);
                `UInt32::MAX` enables acceptance (rustls QUIC, RFC
                9001 §4.6.1). A `UInt32` value converts implicitly
                into the Optional; bare integer literals do not —
                pass `UInt32(...)`. Prefer the `policy=` kwarg for
                new code.
            policy: Public `EarlyDataPolicy` ctor kwarg (default
                `None`, meaning "kwarg omitted; honor the legacy
                `max_early_data` reading unchanged"). When the caller
                supplies a non-None policy, it overrides the legacy
                semantics per the table above:
                `EarlyDataPolicy.off()` disables 0-RTT and conflicts
                with `max_early_data > 0`;
                `EarlyDataPolicy.idempotent_only()`, `.tuned(...)`,
                and `.predicate(...)` enable 0-RTT (set
                `_max_early_data` to `u32::MAX`, also when the caller
                passes a redundant `max_early_data > 0`) and conflict
                with an explicit `max_early_data=UInt32(0)`.
                `tuned(...)` threads the user-supplied
                `EarlyDataStoreConfig` into the store.

        Raises:
            Error: when the rustls FFI ctor reports failure, OR on
                either contradictory kwarg combination: explicit
                `max_early_data > 0` with `policy=EarlyDataPolicy.off()`,
                or explicit `max_early_data=UInt32(0)` with an
                enabling policy. Both messages contain the stable
                substring `"contradictory early-data kwargs"` (API
                contract; operator-facing diagnostic). Both checks
                fire only when BOTH kwargs are explicitly supplied;
                omitting either kwarg never raises.
        """
        # Reject contradictory kwarg combinations early, before the
        # rustls FFI call. Fail-fast keeps the FFI resource graph
        # uninstantiated under operator confusion and surfaces the
        # mistake at the call site rather than at first handshake.
        #
        # Both checks fire only when the caller PASSED both kwargs
        # explicitly (Some(...)). Omitting `max_early_data` defers to
        # the policy; omitting `policy` preserves the legacy
        # `max_early_data` reading untouched.
        if (
            max_early_data is not None
            and max_early_data.value() != UInt32(0)
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
        if (
            max_early_data is not None
            and max_early_data.value() == UInt32(0)
            and policy is not None
            and policy.value().is_enabled()
        ):
            raise Error(
                "QuicServerConfig: contradictory early-data kwargs: "
                "explicit max_early_data=0 with an enabling policy "
                "(idempotent_only / tuned / predicate). Pass either "
                "(a) the enabling policy alone (omit max_early_data) to "
                "enable 0-RTT, OR (b) policy=EarlyDataPolicy.off() (or "
                "omit policy) to disable. Do not pass both."
            )

        # Resolve the effective max_early_data:
        #   - enabling policy          → u32::MAX (policy wins; an
        #                                  explicit max_early_data=0
        #                                  was already rejected by the
        #                                  contradictory-kwargs check
        #                                  above).
        #   - explicit max_early_data  → legacy reading, effective = v
        #                                  (an Off policy alongside
        #                                  v > 0 was already rejected
        #                                  above; Some(0) + off agree).
        #   - both omitted (and the
        #     omitted + off cell)      → 0 (0-RTT off, the safe
        #                                  default).
        var effective_max_early_data: UInt32
        if policy is not None and policy.value().is_enabled():
            effective_max_early_data = UInt32(0xFFFFFFFF)
        elif max_early_data is not None:
            effective_max_early_data = max_early_data.value()
        else:
            effective_max_early_data = UInt32(0)

        self._lib = SharedLibrary(copy=lib)

        var cert_len = len(cert_pem)
        var key_len = len(key_pem)

        var cert_buf_buf = Owned[UInt8](cert_len)
        var cert_buf = cert_buf_buf.ptr()
        for i in range(cert_len):
            cert_buf[unsafe_offset=i] = cert_pem[i]

        var key_buf_buf = Owned[UInt8](key_len)
        var key_buf = key_buf_buf.ptr()
        for i in range(key_len):
            key_buf[unsafe_offset=i] = key_pem[i]

        var alpn_bytes = alpn.as_bytes()
        var alpn_len = len(alpn_bytes)
        var alpn_buf_buf = Owned[UInt8](alpn_len)
        var alpn_buf = alpn_buf_buf.ptr()
        for i in range(alpn_len):
            alpn_buf[unsafe_offset=i] = alpn_bytes[i]

        var out_handle_buf = Owned[Int32](1)
        var out_handle = out_handle_buf.ptr()
        out_handle[unsafe_offset=0] = Int32(-1)
        var rlib = self._lib.inner_ptr()
        var rc = rlib[].quic_server_config_new(
            cert_buf, Int32(cert_len),
            key_buf, Int32(key_len),
            alpn_buf, Int32(alpn_len),
            effective_max_early_data,
            out_handle,
        )

        if rc != 0:
            var err = rlib[].last_error()
            self._handle = Int32(-1)
            self._max_early_data = UInt32(0)
            self._early_data = Variant[NoneType, FilterStrategy, PredicateStrategy](NoneType())
            raise "quic_server_config_new failed: " + err
        self._handle = out_handle[unsafe_offset=0]
        # Keep out_handle_buf alive across the post-FFI `[0]` read above
        # (origin-tie should suffice; defensive against ASAP free).
        _ = out_handle_buf
        self._max_early_data = effective_max_early_data
        # Synchronised-population invariant: when 0-RTT is enabled,
        # exactly one of `_early_data_filter` / `_early_data_predicate_fn`
        # is Some; the store is Some in both cases. When 0-RTT is
        # disabled, all three are None.
        if effective_max_early_data == UInt32(0):
            self._early_data = Variant[NoneType, FilterStrategy, PredicateStrategy](NoneType())
        elif policy is not None and policy.value().is_predicate():
            self._early_data = Variant[NoneType, FilterStrategy, PredicateStrategy](
                PredicateStrategy(
                    InMemoryEarlyDataStore(),
                    policy.value().predicate_fn().value(),
                )
            )
        elif policy is not None and policy.value().is_tuned():
            self._early_data = Variant[NoneType, FilterStrategy, PredicateStrategy](
                FilterStrategy(
                    InMemoryEarlyDataStore(
                        config=policy.value().store_config().value().copy()
                    ),
                    IdempotentOnlyFilter(),
                )
            )
        else:
            self._early_data = Variant[NoneType, FilterStrategy, PredicateStrategy](
                FilterStrategy(
                    InMemoryEarlyDataStore(),
                    IdempotentOnlyFilter(),
                )
            )

    def __init__(out self, *, deinit move: Self):
        self._lib = move._lib^
        self._handle = move._handle
        self._max_early_data = move._max_early_data
        self._early_data = move._early_data^

    def __deinit__(deinit self):
        """Release the Rust-side config handle."""
        if self._handle > 0:
            try:
                _ = self._lib.inner_ptr()[].config_free(self._handle)
            except:
                pass
        # Anchor: `inner_ptr()` returns an untracked pointer, so the checker
        # cannot see that the call above depends on `_lib`. Without a later
        # reference, ASAP destruction frees `_lib` at that line -- closing the
        # dylib -- and the FFI call runs through a null handle.
        _ = self._lib.inner_ptr()

    @always_inline
    def handle(self) -> Int32:
        return self._handle

    @always_inline
    def max_early_data(self) -> UInt32:
        """Return the max_early_data value set at construction."""
        return self._max_early_data

    def early_data_store(self) -> Optional[UnsafePointer[InMemoryEarlyDataStore, MutAnyOrigin]]:
        """Return a pointer to the early-data store, if any.

        Covers both FilterStrategy and PredicateStrategy branches,
        preventing callers from forgetting one.
        """
        if self._early_data.isa[FilterStrategy]():
            return Optional[UnsafePointer[InMemoryEarlyDataStore, MutAnyOrigin]](
                rebind[UnsafePointer[InMemoryEarlyDataStore, MutAnyOrigin]](
                    UnsafePointer(to=self._early_data.unsafe_get[FilterStrategy]().store)
                )
            )
        if self._early_data.isa[PredicateStrategy]():
            return Optional[UnsafePointer[InMemoryEarlyDataStore, MutAnyOrigin]](
                rebind[UnsafePointer[InMemoryEarlyDataStore, MutAnyOrigin]](
                    UnsafePointer(to=self._early_data.unsafe_get[PredicateStrategy]().store)
                )
            )
        return Optional[UnsafePointer[InMemoryEarlyDataStore, MutAnyOrigin]](None)


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
        self._lib = SharedLibrary(copy=lib)

        var alpn_bytes = alpn.as_bytes()
        var alpn_len = len(alpn_bytes)
        var alpn_buf_buf = Owned[UInt8](alpn_len)
        var alpn_buf = alpn_buf_buf.ptr()
        for i in range(alpn_len):
            alpn_buf[unsafe_offset=i] = alpn_bytes[i]

        var out_handle_buf = Owned[Int32](1)
        var out_handle = out_handle_buf.ptr()
        out_handle[unsafe_offset=0] = Int32(-1)

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

        if rc != 0:
            var err = rlib[].last_error()
            self._handle = Int32(-1)
            raise "quic_client_config_new failed: " + err
        self._handle = out_handle[unsafe_offset=0]
        # Keep out_handle_buf alive across the post-FFI `[0]` read above.
        _ = out_handle_buf

    def __init__(out self, *, _lib: SharedLibrary, _handle: Int32):
        """Private constructor for static factory methods."""
        self._lib = SharedLibrary(copy=_lib)
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
        var ca_buf_buf = Owned[UInt8](ca_len)
        var ca_buf = ca_buf_buf.ptr()
        for i in range(ca_len):
            ca_buf[unsafe_offset=i] = ca_pem[i]

        var alpn_bytes = alpn.as_bytes()
        var alpn_len = len(alpn_bytes)
        var alpn_buf_buf = Owned[UInt8](alpn_len)
        var alpn_buf = alpn_buf_buf.ptr()
        for i in range(alpn_len):
            alpn_buf[unsafe_offset=i] = alpn_bytes[i]

        var out_handle_buf = Owned[Int32](1)
        var out_handle = out_handle_buf.ptr()
        out_handle[unsafe_offset=0] = Int32(-1)
        var rlib = lib.inner_ptr()
        var rc = rlib[].quic_client_config_with_ca(
            ca_buf, Int32(ca_len),
            alpn_buf, Int32(alpn_len),
            out_handle,
        )

        if rc != 0:
            var err = rlib[].last_error()
            raise "quic_client_config_with_ca failed: " + err
        var handle = out_handle[unsafe_offset=0]
        # Keep out_handle_buf alive across the post-FFI `[0]` read above.
        _ = out_handle_buf
        return QuicClientConfig(_lib=lib, _handle=handle)

    def __init__(out self, *, deinit move: Self):
        self._lib = move._lib^
        self._handle = move._handle

    def __deinit__(deinit self):
        """Release the Rust-side config handle.

        A destructor may not raise. `config_free` can, but only from the
        symbol lookup: the Rust side returns -1 for an unknown handle
        rather than raising, and that status is already discarded here
        because a config that is not in the table needs no freeing.

        A lookup failure means the loaded librustls_mojo.so does not
        export `rlsm_config_free`, i.e. it is not the library the handle
        was created by. Swallowing it leaks one entry in the Rust
        CONFIG_TABLE; the alternative in a destructor is aborting the
        process while tearing a connection down, which is worse. Double
        free is impossible: `deinit self` consumes the config, so this
        runs exactly once per handle.
        """
        if self._handle > 0:
            try:
                _ = self._lib.inner_ptr()[].config_free(self._handle)
            except:
                pass
        # Anchor: `inner_ptr()` returns an untracked pointer, so the checker
        # cannot see that the call above depends on `_lib`. Without a later
        # reference, ASAP destruction frees `_lib` at that line -- closing the
        # dylib -- and the FFI call runs through a null handle.
        _ = self._lib.inner_ptr()

    @always_inline
    def handle(self) -> Int32:
        """Return the raw config handle (borrowed; do not free)."""
        return self._handle
