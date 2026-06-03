"""Public-API `EarlyDataPolicy` tagged-variant struct for 0-RTT acceptance.

Three variants:
  Off:            0-RTT rejected. Default — opt-in is a deliberate
                  config choice (security mandate).
  IdempotentOnly: 0-RTT accepted; GET/HEAD/OPTIONS dispatch;
                  everything else gets 425 Too Early (RFC 8470 §5.2).
                  The "safe-by-default-when-on" posture.
  Tuned:          0-RTT accepted with the IdempotentOnly filter and a
                  user-supplied `EarlyDataStoreConfig` (LRU capacity,
                  TTL, per-key quota, sliding window denominator +
                  numerator).

User-defined filter TYPES (via a `Custom(custom_filter)` variant) are
deferred to a follow-up change that introduces trait-object plumbing
across the QuicServerConfig + QuicConnection + H3 adapter surface.
`Tuned` is the v1 stand-in for that future variant.

All factories that consult `EarlyDataStoreConfig` raise via
`EarlyDataStoreConfig.validate()`. Bare `Error("contradictory ...")`
is reserved for the `QuicServerConfig` ctor — see the docstring there.
"""

from navette.tls.early_data_store import (
    EarlyDataStoreConfig,
    default_early_data_store_config,
)


struct EarlyDataPolicy(Copyable, Movable):
    """Three-variant public-API enum controlling 0-RTT acceptance.

    Pure value type. ~40 bytes (UInt8 discriminant + EarlyDataStoreConfig
    payload). Construction + variant queries are sub-100 ns; the
    `tuned()` factory runs the same 5-knob `validate()` check that
    `InMemoryEarlyDataStore.__init__` runs.

    Pointer-lifetime invariant: the policy is consumed by
    `QuicServerConfig.__init__` (a ctor kwarg). There is no
    post-construction mutator on `QuicServerConfig` that re-derives the
    `_early_data_store` Optional from a new policy, so the
    rustls FFI config's `max_early_data_size` and the Mojo-side
    `_max_early_data` mirror cannot drift.
    """

    var _kind: UInt8
    var _store_config: EarlyDataStoreConfig

    comptime KIND_OFF              = UInt8(0)
    comptime KIND_IDEMPOTENT_ONLY  = UInt8(1)
    comptime KIND_TUNED            = UInt8(2)

    def __init__(out self):
        """Default-construct an Off policy (the safe-by-default posture)."""
        self._kind = Self.KIND_OFF
        self._store_config = default_early_data_store_config()

    def __init__(out self, *, other: Self):
        """Copy-construct from another policy; preserves variant + config."""
        self._kind = other._kind
        self._store_config = other._store_config.copy()

    def __init__(out self, *, deinit take: Self):
        """Move-construct; preserves variant + config."""
        self._kind = take._kind
        self._store_config = take._store_config.copy()

    @staticmethod
    def off() -> Self:
        """Build the Off variant. Non-raising; the default store config
        it carries is never installed because `is_off() == True`.

        Returns:
            An `EarlyDataPolicy` in the Off variant.
        """
        var p = Self()
        p._kind = Self.KIND_OFF
        return p^

    @staticmethod
    def idempotent_only() -> Self:
        """Build the IdempotentOnly variant. Non-raising; uses the
        default store config (validated at module load by
        `default_early_data_store_config`).

        Returns:
            An `EarlyDataPolicy` in the IdempotentOnly variant.
        """
        var p = Self()
        p._kind = Self.KIND_IDEMPOTENT_ONLY
        p._store_config = default_early_data_store_config()
        return p^

    @staticmethod
    def tuned(store_config: EarlyDataStoreConfig) raises -> Self:
        """Build the Tuned variant with a user-supplied store config.
        Raises if any of the five tuning knobs in `store_config` is zero.

        Eager validation runs at policy-build time (close to the
        EarlyDataStoreConfig construction site), not deferred to
        `QuicServerConfig.__init__`.

        Args:
            store_config: The tuning knobs the resulting
                `InMemoryEarlyDataStore` will be constructed with when
                `QuicServerConfig.__init__` consumes this policy.

        Returns:
            An `EarlyDataPolicy` in the Tuned variant carrying
            `store_config`.

        Raises:
            Error: when any tuning knob is zero. The error message is
                produced by `EarlyDataStoreConfig.validate()`.
        """
        store_config.validate()
        var p = Self()
        p._kind = Self.KIND_TUNED
        p._store_config = store_config.copy()
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

    def is_enabled(self) -> Bool:
        """True iff this policy enables 0-RTT acceptance (i.e., the
        variant is IdempotentOnly or Tuned). Equivalent to
        `is_idempotent_only() or is_tuned()`."""
        return self._kind != Self.KIND_OFF

    def store_config(self) -> Optional[EarlyDataStoreConfig]:
        """Return the store config this policy installs, or None on Off.

        Returns:
            `Optional[EarlyDataStoreConfig]` — None when `is_off()`;
            `Some(config)` when `is_idempotent_only()` or `is_tuned()`.
            The Optional wrapper prevents callers from accidentally
            reading the placeholder-default value held by the Off
            variant.
        """
        if self._kind == Self.KIND_OFF:
            return Optional[EarlyDataStoreConfig](None)
        return Optional[EarlyDataStoreConfig](self._store_config.copy())
