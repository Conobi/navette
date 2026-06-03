"""Public-API `EarlyDataPolicy` tagged-variant struct for 0-RTT acceptance.

Four variants:
  Off:            0-RTT rejected. Default — opt-in is a deliberate
                  config choice (security mandate).
  IdempotentOnly: 0-RTT accepted; GET/HEAD/OPTIONS dispatch;
                  everything else gets 425 Too Early (RFC 8470 §5.2).
                  The "safe-by-default-when-on" posture.
  Tuned:          0-RTT accepted with the IdempotentOnly filter and a
                  user-supplied `EarlyDataStoreConfig` (LRU capacity,
                  TTL, per-key quota, sliding window denominator +
                  numerator).
  Predicate:      0-RTT accepted; dispatch consults a user-supplied
                  free-function predicate (Option E). Uses the
                  default `InMemoryEarlyDataStore`; combining Tuned-
                  store tuning with a custom Predicate is deferred to
                  a follow-up change.

User-defined filter TYPES (via a `Custom(custom_filter)` variant) are
deferred to a follow-up change that introduces trait-object plumbing
across the QuicServerConfig + QuicConnection + H3 adapter surface.
`Tuned` is the v1 stand-in for that future variant.

All factories that consult `EarlyDataStoreConfig` raise via
`EarlyDataStoreConfig.validate()`. Bare `Error("contradictory ...")`
is reserved for the `QuicServerConfig` ctor — see the docstring there.
"""

from navette.tls.early_data_filter import EarlyDataPredicateFn
from navette.tls.early_data_store import (
    EarlyDataStoreConfig,
    default_early_data_store_config,
)


struct EarlyDataPolicy(Copyable, Movable):
    """Four-variant public-API enum controlling 0-RTT acceptance.

    Pure value type. Discriminant + EarlyDataStoreConfig payload +
    Optional predicate-fn slot. Construction + variant queries are
    sub-100 ns; the `tuned()` factory runs the same 5-knob
    `validate()` check that `InMemoryEarlyDataStore.__init__` runs.

    Pointer-lifetime invariant: the policy is consumed by
    `QuicServerConfig.__init__` (a ctor kwarg). There is no post-
    construction mutator on `QuicServerConfig` that re-derives the
    `_early_data_store` / `_early_data_filter` / `_early_data_predicate_fn`
    fields from a new policy, so the rustls FFI config's
    `max_early_data_size` and the Mojo-side mirror cannot drift.
    """

    var _kind: UInt8
    var _store_config: EarlyDataStoreConfig
    var _predicate_fn: Optional[EarlyDataPredicateFn]

    comptime KIND_OFF              = UInt8(0)
    comptime KIND_IDEMPOTENT_ONLY  = UInt8(1)
    comptime KIND_TUNED            = UInt8(2)
    comptime KIND_PREDICATE        = UInt8(3)

    def __init__(out self):
        """Default-construct an Off policy (the safe-by-default posture)."""
        self._kind = Self.KIND_OFF
        self._store_config = default_early_data_store_config()
        self._predicate_fn = Optional[EarlyDataPredicateFn](None)

    def __init__(out self, *, other: Self):
        """Copy-construct from another policy; preserves variant + config + predicate-fn."""
        self._kind = other._kind
        self._store_config = other._store_config.copy()
        self._predicate_fn = other._predicate_fn

    def __init__(out self, *, deinit take: Self):
        """Move-construct; preserves variant + config + predicate-fn."""
        self._kind = take._kind
        self._store_config = take._store_config.copy()
        self._predicate_fn = take._predicate_fn

    @staticmethod
    def off() -> Self:
        """Build the Off variant. Non-raising; the default store config
        it carries is never installed because `is_off() == True`."""
        var p = Self()
        p._kind = Self.KIND_OFF
        return p^

    @staticmethod
    def idempotent_only() -> Self:
        """Build the IdempotentOnly variant. Non-raising; uses the
        default store config (validated at module load by
        `default_early_data_store_config`)."""
        var p = Self()
        p._kind = Self.KIND_IDEMPOTENT_ONLY
        p._store_config = default_early_data_store_config()
        return p^

    @staticmethod
    def tuned(store_config: EarlyDataStoreConfig) raises -> Self:
        """Build the Tuned variant with a user-supplied store config.

        Eager validation runs at policy-build time. Raises if any of
        the five tuning knobs in `store_config` is zero.
        """
        store_config.validate()
        var p = Self()
        p._kind = Self.KIND_TUNED
        p._store_config = store_config.copy()
        return p^

    @staticmethod
    def predicate(predicate_fn: EarlyDataPredicateFn) -> Self:
        """Build the Predicate variant carrying the user-supplied fn.

        The parameter is named `predicate_fn` (not `fn`) because `fn`
        is a reserved keyword in Mojo 1.0.0b1.

        `EarlyDataPredicateFn` values are trivially copyable in Mojo
        1.0.0b1 (function pointers are POD-like). Pass-by-value to
        this factory yields a fn-pointer COPY; the caller's reference
        remains usable after the call.

        Args:
            predicate_fn: A free function with signature
                `(method: String, path: String, headers: Headers)
                 raises -> FilterDecision`. Module-scope; capturing
                closures are NOT supported by Mojo 1.0.0b1.

        Returns:
            An `EarlyDataPolicy` in the Predicate variant carrying
            `predicate_fn` in `_predicate_fn`.
        """
        var p = Self()
        p._kind = Self.KIND_PREDICATE
        p._predicate_fn = Optional[EarlyDataPredicateFn](predicate_fn)
        return p^

    def is_off(self) -> Bool:
        """True iff this policy is the Off variant."""
        return self._kind == Self.KIND_OFF

    def is_idempotent_only(self) -> Bool:
        """True iff this policy is the IdempotentOnly variant."""
        return self._kind == Self.KIND_IDEMPOTENT_ONLY

    def is_tuned(self) -> Bool:
        """True iff this policy is the Tuned variant."""
        return self._kind == Self.KIND_TUNED

    def is_predicate(self) -> Bool:
        """True iff this policy is the Predicate variant."""
        return self._kind == Self.KIND_PREDICATE

    def is_enabled(self) -> Bool:
        """True iff this policy enables 0-RTT acceptance (variant is
        IdempotentOnly, Tuned, or Predicate). Equivalent to
        `_kind != KIND_OFF`."""
        return self._kind != Self.KIND_OFF

    def store_config(self) -> Optional[EarlyDataStoreConfig]:
        """Return the store config this policy installs, or None on
        Off / Predicate.

        The Predicate variant uses the default store; operators
        consulting `store_config()` to decide whether to surface
        operator-supplied tuning MUST treat None as "default store"
        for both Off and Predicate. Callers that consult `store_config()`
        against Off / IdempotentOnly / Tuned only see no behavioural
        change.
        """
        if self._kind == Self.KIND_OFF or self._kind == Self.KIND_PREDICATE:
            return Optional[EarlyDataStoreConfig](None)
        return Optional[EarlyDataStoreConfig](self._store_config.copy())

    def predicate_fn(self) -> Optional[EarlyDataPredicateFn]:
        """Return Some(fn) iff is_predicate(); None otherwise."""
        return self._predicate_fn
