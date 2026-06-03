# Pure-core anti-replay store for 0-RTT acceptance.
#
# Trait + default in-memory LRU implementation. No FFI, no rustls, no
# connection-state imports. Replay-defense contract is documented per
# RFC 8446 §8: given the same `authenticator` bytestring twice within
# `entry_ttl_ms`, `check_and_record` MUST return a non-accept decision
# on the second call. A first call with a fresh authenticator, all
# quotas unsaturated, MUST return ReplayDecision.accept().
#
# Authenticator opacity: the trait treats `authenticator: Span[UInt8]`
# as 32 opaque bytes. The capture from the encrypted CRYPTO bytes
# happens upstream, in the FFI shim. This module's only job is the
# dedup + rate-limit machinery.

from std.collections.dict import Dict, KeyElement
from std.collections.deque import Deque
from std.memory import Span


# ─────────────────────────────────────────────────────────────────────
# ReplayDecision — 4 variants with explicit discriminant constants.
# ─────────────────────────────────────────────────────────────────────

@fieldwise_init
struct ReplayDecision(Copyable, Movable, Equatable):
    """Outcome of EarlyDataStore.check_and_record.

    Four variants discriminated by kind. Anomaly paths (FFI rc != 0,
    store raise) do NOT produce a ReplayDecision; they short-circuit
    to the no_authenticator counter directly in the decrypt
    integration. Predicates (`is_accept`, `is_duplicate`,
    `is_per_key_quota`, `is_global_ceiling`) are how the integration
    code reads decisions — never bare `decision.kind == N`.
    """
    var kind: UInt8

    comptime KIND_ACCEPT                   = UInt8(0)
    comptime KIND_DUPLICATE                = UInt8(1)
    comptime KIND_PER_KEY_QUOTA_EXHAUSTED  = UInt8(2)
    comptime KIND_GLOBAL_CEILING_EXHAUSTED = UInt8(3)

    @staticmethod
    def accept() -> Self:
        return Self(kind=Self.KIND_ACCEPT)

    @staticmethod
    def duplicate() -> Self:
        return Self(kind=Self.KIND_DUPLICATE)

    @staticmethod
    def per_key_quota_exhausted() -> Self:
        return Self(kind=Self.KIND_PER_KEY_QUOTA_EXHAUSTED)

    @staticmethod
    def global_ceiling_exhausted() -> Self:
        return Self(kind=Self.KIND_GLOBAL_CEILING_EXHAUSTED)

    def is_accept(self) -> Bool:        return self.kind == Self.KIND_ACCEPT
    def is_reject(self) -> Bool:        return self.kind != Self.KIND_ACCEPT
    def is_duplicate(self) -> Bool:     return self.kind == Self.KIND_DUPLICATE
    def is_per_key_quota(self) -> Bool: return self.kind == Self.KIND_PER_KEY_QUOTA_EXHAUSTED
    def is_global_ceiling(self) -> Bool: return self.kind == Self.KIND_GLOBAL_CEILING_EXHAUSTED

    def __eq__(self, other: Self) -> Bool: return self.kind == other.kind
    def __ne__(self, other: Self) -> Bool: return self.kind != other.kind


# ─────────────────────────────────────────────────────────────────────
# KeyTag — 32-byte authenticator-as-dict-key.
# ─────────────────────────────────────────────────────────────────────

struct KeyTag(KeyElement):
    """32-byte authenticator-as-dict-key.

    Bytewise equality; FNV-1a 64-bit hash for dict bucket distribution.
    The hash is NOT cryptographic. Collision resistance is upstream —
    the FFI captures a 32-byte authenticator from the encrypted CRYPTO
    bytes (RFC 8446 §4.1.2 wire layout), CSPRNG-sourced. This struct's
    only job is to satisfy Mojo Dict's KeyElement traits without
    pulling in a crypto dependency.
    """
    var bytes: InlineArray[UInt8, 32]

    def __init__(out self):
        self.bytes = InlineArray[UInt8, 32](fill=UInt8(0))

    def __init__(out self, *, other: Self):
        self.bytes = InlineArray[UInt8, 32](fill=UInt8(0))
        for i in range(32):
            self.bytes[i] = other.bytes[i]

    def __init__(out self, *, deinit take: Self):
        self.bytes = InlineArray[UInt8, 32](fill=UInt8(0))
        for i in range(32):
            self.bytes[i] = take.bytes[i]

    @staticmethod
    def from_span(src: Span[UInt8, _]) raises -> Self:
        if len(src) != 32:
            raise Error(
                "KeyTag.from_span: expected exactly 32 bytes, got "
                + String(len(src))
            )
        var out = Self()
        for i in range(32):
            out.bytes[i] = src[i]
        return out^

    def __eq__(self, other: Self) -> Bool:
        for i in range(32):
            if self.bytes[i] != other.bytes[i]:
                return False
        return True

    def __ne__(self, other: Self) -> Bool:
        return not self.__eq__(other)

    def __hash__(self) -> UInt64:
        # FNV-1a 64-bit. Non-cryptographic; bucket distribution only.
        var h: UInt64 = 14695981039346656037
        for i in range(32):
            h ^= UInt64(self.bytes[i])
            h *= 1099511628211
        return h


# ─────────────────────────────────────────────────────────────────────
# EarlyDataStoreConfig — five numeric knobs with documented defaults.
# ─────────────────────────────────────────────────────────────────────

@fieldwise_init
struct EarlyDataStoreConfig(Copyable, Movable):
    """Tuning knobs for InMemoryEarlyDataStore. All five MUST be >= 1;
    construction raises on any violation.

    max_entries: capacity ceiling. LRU eviction bounds memory under
        attack. Default 16384 → ~1 MiB at ~64 B/entry.
    entry_ttl_ms: per-entry freshness window. Default 30 minutes;
        comfortably above the wire-level scenario budget. LRU eviction
        dominates at any production scale.
    per_key_max_attempts: maximum accept-or-duplicate count per
        authenticator before further attempts return
        per_key_quota_exhausted. Default 3.
    global_window_ms: sliding-window denominator for global-accept
        rate limit. Default 1000.
    global_window_max_accepts: numerator. Default 1000 accepts/second.
    """
    var max_entries: UInt32
    var entry_ttl_ms: UInt64
    var per_key_max_attempts: UInt32
    var global_window_ms: UInt64
    var global_window_max_accepts: UInt32


def default_early_data_store_config() -> EarlyDataStoreConfig:
    return EarlyDataStoreConfig(
        max_entries=UInt32(16384),
        entry_ttl_ms=UInt64(1_800_000),       # 30 minutes
        per_key_max_attempts=UInt32(3),
        global_window_ms=UInt64(1_000),
        global_window_max_accepts=UInt32(1_000),
    )


# ─────────────────────────────────────────────────────────────────────
# EarlyDataEntry — internal per-authenticator record.
# ─────────────────────────────────────────────────────────────────────

@fieldwise_init
struct EarlyDataEntry(Copyable, Movable):
    """Per-authenticator record stored inside InMemoryEarlyDataStore.

    first_seen_ms: monotonic millisecond timestamp at first registration
        of this authenticator (or its post-TTL reset).
    attempt_count: number of accept-or-duplicate observations seen
        within the current entry_ttl_ms window. Saturates at UInt32.MAX.
    """
    var first_seen_ms: UInt64
    var attempt_count: UInt32


# ─────────────────────────────────────────────────────────────────────
# EarlyDataStore — the trait. Single method, raises.
# ─────────────────────────────────────────────────────────────────────

trait EarlyDataStore(Movable):
    """Anti-replay store for 0-RTT acceptance.

    Implementations MUST be safe for single-thread cooperative-yield
    access (boucle.stackful). They MUST NOT block, MUST NOT perform
    I/O on the hot path, and MUST be amortised O(1) in per-call
    wall-clock cost under steady-state arrival.

    Replay-defense contract: given the same `authenticator` bytestring
    twice within `entry_ttl_ms`, check_and_record MUST return a
    non-accept ReplayDecision on the second call. A first call with a
    fresh authenticator, all quotas unsaturated, MUST return
    ReplayDecision.accept().

    `now_unix_ms` is advisory: implementations MUST treat it as a
    monotonic counter. Wall-clock accuracy is not required.
    """
    def check_and_record(
        mut self,
        authenticator: Span[UInt8, _],
        now_unix_ms: UInt64,
    ) raises -> ReplayDecision: ...


# ─────────────────────────────────────────────────────────────────────
# InMemoryEarlyDataStore — default LRU implementation.
# ─────────────────────────────────────────────────────────────────────

struct InMemoryEarlyDataStore(EarlyDataStore):
    """LRU-bounded in-memory store with per-key quotas + global ceiling.

    Storage: a Dict[KeyTag, EarlyDataEntry] holds live records; eviction
    order is tracked via a Deque[KeyTag] (front = least recent). On hit,
    the touched key is moved to the back; on insert past `max_entries`,
    the front is evicted.

    The global-accept window is a Deque[UInt64] of accept timestamps;
    each `check_and_record` slides off expired timestamps before
    consulting the ceiling, then push_back on accept.
    """
    var _entries: Dict[KeyTag, EarlyDataEntry]
    var _lru: Deque[KeyTag]
    var _global_window: Deque[UInt64]
    var _config: EarlyDataStoreConfig

    def __init__(out self) raises:
        # Inline the config-arg body — Mojo 1.0.0b1 does not support
        # `self.__init__(config=...)` delegation between ctors.
        var config = default_early_data_store_config()
        self._entries = Dict[KeyTag, EarlyDataEntry]()
        self._lru = Deque[KeyTag]()
        self._global_window = Deque[UInt64]()
        self._config = config^

    def __init__(out self, *, config: EarlyDataStoreConfig) raises:
        if config.max_entries == UInt32(0):
            raise Error("EarlyDataStoreConfig.max_entries must be >= 1")
        if config.entry_ttl_ms == UInt64(0):
            raise Error("EarlyDataStoreConfig.entry_ttl_ms must be >= 1")
        if config.per_key_max_attempts == UInt32(0):
            raise Error(
                "EarlyDataStoreConfig.per_key_max_attempts must be >= 1"
            )
        if config.global_window_ms == UInt64(0):
            raise Error("EarlyDataStoreConfig.global_window_ms must be >= 1")
        if config.global_window_max_accepts == UInt32(0):
            raise Error(
                "EarlyDataStoreConfig.global_window_max_accepts must be >= 1"
            )
        self._entries = Dict[KeyTag, EarlyDataEntry]()
        self._lru = Deque[KeyTag]()
        self._global_window = Deque[UInt64]()
        self._config = config.copy()

    def __init__(out self, *, deinit take: Self):
        self._entries = take._entries^
        self._lru = take._lru^
        self._global_window = take._global_window^
        self._config = take._config.copy()

    def check_and_record(
        mut self,
        authenticator: Span[UInt8, _],
        now_unix_ms: UInt64,
    ) raises -> ReplayDecision:
        # 1. Slide the global window. Anything older than now - window_ms
        #    is dropped from the deque front. Worst case O(window_max) on
        #    the post-idle wakeup; O(1) amortised under steady-state.
        var window_ms = self._config.global_window_ms
        while len(self._global_window) > 0:
            var front = self._global_window[0]
            if front + window_ms <= now_unix_ms:
                _ = self._global_window.popleft()
            else:
                break

        # 2. Global ceiling check BEFORE per-key bookkeeping. A saturated
        #    global window does NOT register the entry — the third
        #    authenticator in `global-ceiling-exhausts` is NOT inserted.
        var global_max = self._config.global_window_max_accepts
        if UInt32(len(self._global_window)) >= global_max:
            return ReplayDecision.global_ceiling_exhausted()

        # 3. Build the key tag.
        var key = KeyTag.from_span(authenticator)

        # 4. Lookup. Mojo Dict has no `get(key, default)`; use `key in dict`.
        if key in self._entries:
            # 5. Existing entry — saturating subtract guards clock regression.
            var entry = self._entries[key].copy()
            var elapsed: UInt64
            if now_unix_ms >= entry.first_seen_ms:
                elapsed = now_unix_ms - entry.first_seen_ms
            else:
                elapsed = UInt64(0)

            if elapsed >= self._config.entry_ttl_ms:
                # TTL expired — treat as fresh authenticator.
                entry.first_seen_ms = now_unix_ms
                entry.attempt_count = UInt32(1)
                self._entries[KeyTag(other=key)] = entry^
                self._touch_lru(key)
                self._global_window.append(now_unix_ms)
                return ReplayDecision.accept()

            # 6. Live entry — bump count (saturating).
            if entry.attempt_count < UInt32(0xFFFFFFFF):
                entry.attempt_count = entry.attempt_count + UInt32(1)
            var saved_count = entry.attempt_count
            self._entries[KeyTag(other=key)] = entry^
            self._touch_lru(key)
            if saved_count > self._config.per_key_max_attempts:
                return ReplayDecision.per_key_quota_exhausted()
            return ReplayDecision.duplicate()

        # 7. Fresh authenticator. Evict LRU if at capacity.
        if UInt32(len(self._entries)) >= self._config.max_entries:
            self._evict_lru()
        var fresh = EarlyDataEntry(
            first_seen_ms=now_unix_ms,
            attempt_count=UInt32(1),
        )
        self._entries[KeyTag(other=key)] = fresh^
        self._lru.append(key^)
        self._global_window.append(now_unix_ms)
        return ReplayDecision.accept()

    def _touch_lru(mut self, key: KeyTag):
        """Move `key` to the back of the LRU deque. Linear scan is
        acceptable for the default capacity (16384); production-grade
        deployments can swap in a custom store with a doubly-linked
        list via the EarlyDataStore trait seam."""
        var idx = -1
        for i in range(len(self._lru)):
            if self._lru[i] == key:
                idx = i
                break
        if idx < 0:
            self._lru.append(KeyTag(other=key))
            return
        # Remove at idx via swap-and-pop-with-rebuild: Deque doesn't
        # expose remove(idx). Rebuild excluding idx.
        var rebuilt = Deque[KeyTag]()
        for i in range(len(self._lru)):
            if i != idx:
                rebuilt.append(KeyTag(other=self._lru[i]))
        rebuilt.append(KeyTag(other=key))
        self._lru = rebuilt^

    def _evict_lru(mut self) raises:
        """Pop the LRU front and remove the matching dict entry."""
        if len(self._lru) == 0:
            return
        var victim = self._lru.popleft()
        if victim in self._entries:
            _ = self._entries.pop(victim)
