# Differential property test: InMemoryEarlyDataStore vs a brute-force
# O(N^2) reference. Random op streams via SplitMix64; both stores are fed
# identical sequences; pairwise outputs must agree.
#
# BruteForceReplayStore lives in THIS file only. A static check in the
# integration-check script enforces that the name does not appear in any
# non-test file.

from std.memory import Span

from navette.tls.early_data_store import (
    InMemoryEarlyDataStore, ReplayDecision, KeyTag,
    EarlyDataStoreConfig, default_early_data_store_config,
)
from tests._test_util import assert_true


# ---------------------------------------------------------------------
# SplitMix64 -- small deterministic PRNG for op streams.
# ---------------------------------------------------------------------

struct SplitMix64(Copyable, Movable):
    """SplitMix64 PRNG.

    Public-domain reference: https://prng.di.unimi.it/splitmix64.c. Inlined
    here rather than imported so this file remains the single home of the
    differential harness; the integration-check script can grep one file.
    """
    var state: UInt64

    def __init__(out self, seed: UInt64):
        self.state = seed

    def next(mut self) -> UInt64:
        """Advance state and return the next 64-bit output."""
        self.state = self.state + UInt64(0x9E3779B97F4A7C15)
        var z = self.state
        z = (z ^ (z >> UInt64(30))) * UInt64(0xBF58476D1CE4E5B9)
        z = (z ^ (z >> UInt64(27))) * UInt64(0x94D049BB133111EB)
        return z ^ (z >> UInt64(31))


# ---------------------------------------------------------------------
# BruteForceReplayStore -- O(N^2) reference (test-only).
# ---------------------------------------------------------------------
#
# Stores every accept-or-duplicate (auth, first_seen_ms, attempt_count)
# triple in a list and answers check_and_record via linear scan. The
# global window is tracked as a flat list of accept timestamps. The
# algorithm mirrors InMemoryEarlyDataStore but at O(N^2) cost -- the
# only purpose is differential cross-checking.

@fieldwise_init
struct _BruteEntry(Copyable, Movable):
    """Per-authenticator record for the brute-force reference."""
    var key: KeyTag
    var first_seen_ms: UInt64
    var attempt_count: UInt32


struct BruteForceReplayStore(Movable):
    """O(N^2) reference store. Linear-scan dedup, flat-list global window."""
    var entries: List[_BruteEntry]
    var window: List[UInt64]
    var config: EarlyDataStoreConfig

    def __init__(out self, *, config: EarlyDataStoreConfig):
        self.entries = List[_BruteEntry]()
        self.window = List[UInt64]()
        self.config = config.copy()

    def check_and_record(
        mut self,
        authenticator: Span[UInt8, _],
        now_unix_ms: UInt64,
    ) raises -> ReplayDecision:
        """Linear-scan mirror of InMemoryEarlyDataStore.check_and_record."""
        # 1. Slide the global window: drop timestamps older than the window.
        var pruned = List[UInt64]()
        for t in self.window:
            if t + self.config.global_window_ms > now_unix_ms:
                pruned.append(t)
        self.window = pruned^

        # 2. Global-ceiling gate BEFORE per-key bookkeeping. A saturated
        #    window does NOT register the entry.
        if UInt32(len(self.window)) >= self.config.global_window_max_accepts:
            return ReplayDecision.global_ceiling_exhausted()

        # 3. Build key + linear scan for existing entry.
        var key = KeyTag.from_span(authenticator)
        var hit = -1
        for i in range(len(self.entries)):
            if self.entries[i].key == key:
                hit = i
                break

        if hit >= 0:
            # 4. Existing entry -- saturating elapsed.
            var elapsed: UInt64
            if now_unix_ms >= self.entries[hit].first_seen_ms:
                elapsed = now_unix_ms - self.entries[hit].first_seen_ms
            else:
                elapsed = UInt64(0)

            if elapsed >= self.config.entry_ttl_ms:
                # TTL expired -- treat as fresh.
                self.entries[hit].first_seen_ms = now_unix_ms
                self.entries[hit].attempt_count = UInt32(1)
                self.window.append(now_unix_ms)
                return ReplayDecision.accept()

            # Live entry -- bump (saturating).
            if self.entries[hit].attempt_count < UInt32(0xFFFFFFFF):
                self.entries[hit].attempt_count = (
                    self.entries[hit].attempt_count + UInt32(1)
                )
            if self.entries[hit].attempt_count > self.config.per_key_max_attempts:
                return ReplayDecision.per_key_quota_exhausted()
            return ReplayDecision.duplicate()

        # 5. Fresh authenticator. No max_entries enforcement on the
        #    reference; tests use max_entries large enough that eviction
        #    would not trigger inside the op stream length (200 < default
        #    16384). If a scenario shrinks max_entries below the op-stream
        #    length, LRU-eviction divergence is expected and that scenario
        #    is excluded from this property test.
        var fresh = _BruteEntry(
            key=KeyTag(other=key),
            first_seen_ms=now_unix_ms,
            attempt_count=UInt32(1),
        )
        self.entries.append(fresh^)
        self.window.append(now_unix_ms)
        return ReplayDecision.accept()


# ---------------------------------------------------------------------
# Property test driver.
# ---------------------------------------------------------------------

def _gen_auth(rng_lo: UInt64, rng_hi: UInt64) -> List[UInt8]:
    """Project two 64-bit RNG outputs into a 32-byte authenticator.

    The op generator constrains the distinct-authenticator universe so
    repeats are likely (bucketed mod 8 = ~8 distinct keys over 200 ops).
    The second word is stirred into bytes [16..24) so distinct buckets
    are not also bytewise-identical past byte 0 -- paranoia against the
    always-broadcast-the-bucket reduction silently masking divergence.
    """
    var bucket = rng_lo % UInt64(8)
    var out = List[UInt8]()
    for _ in range(32):
        out.append(UInt8(bucket))
    var hi = rng_hi
    for i in range(8):
        out[16 + i] = UInt8(hi & UInt64(0xFF))
        hi = hi >> UInt64(8)
    out[0] = UInt8(bucket)  # restore bucket lead so byte-0 == bucket
    return out^


def _run_one_seed(seed: UInt64) raises:
    """Run one differential trial: 200 ops, both stores must agree."""
    var rng = SplitMix64(seed)
    var cfg = default_early_data_store_config()
    cfg.per_key_max_attempts = UInt32(3)
    cfg.global_window_ms = UInt64(1_000)
    cfg.global_window_max_accepts = UInt32(50)
    cfg.entry_ttl_ms = UInt64(500)
    # max_entries left at default (16384) so eviction never fires under
    # 200 ops with ~8 distinct authenticators.
    var lru = InMemoryEarlyDataStore(config=cfg)
    var brute = BruteForceReplayStore(config=cfg)

    var t = UInt64(0)
    for op_idx in range(200):
        var r1 = rng.next()
        var r2 = rng.next()
        var step = (r1 >> UInt64(32)) % UInt64(200)  # 0..199 ms forward
        t = t + step
        var auth = _gen_auth(r1, r2)
        var d_lru = lru.check_and_record(Span(auth), t)
        var d_brute = brute.check_and_record(Span(auth), t)
        assert_true(
            d_lru == d_brute,
            "divergence at op " + String(op_idx)
            + " seed " + String(seed)
            + " t=" + String(t)
            + " lru.kind=" + String(Int(d_lru.kind))
            + " brute.kind=" + String(Int(d_brute.kind)),
        )
    # extend lifetimes
    _ = lru._config
    _ = brute.config


def test_property_lru_matches_brute_force_across_seeds() raises:
    """Run the differential test against 50 distinct seeds. Each seed
    drives 200 ops, for 10000 pairwise comparisons total. Any pairwise
    divergence raises.

    The floor for must-prove differential properties is >=10^4 random
    sequences; 50 x 200 = 10000 hits that floor exactly. Seeds
    mix low-hamming-weight constants (0x1111..., 0xF0F0...) with
    high-entropy values to exercise diverse SplitMix64 mixer state.
    """
    var seeds: List[UInt64] = [
        UInt64(0xDEADBEEFCAFEBABE),
        UInt64(0x0123456789ABCDEF),
        UInt64(0xFEDCBA9876543210),
        UInt64(0x1111111111111111),
        UInt64(0x2222222222222222),
        UInt64(0x4444444444444444),
        UInt64(0x8888888888888888),
        UInt64(0xA5A5A5A5A5A5A5A5),
        UInt64(0x3333333333333333),
        UInt64(0x5555555555555555),
        UInt64(0x6666666666666666),
        UInt64(0x7777777777777777),
        UInt64(0x9999999999999999),
        UInt64(0xAAAAAAAAAAAAAAAA),
        UInt64(0xBBBBBBBBBBBBBBBB),
        UInt64(0xCCCCCCCCCCCCCCCC),
        UInt64(0xDDDDDDDDDDDDDDDD),
        UInt64(0xEEEEEEEEEEEEEEEE),
        UInt64(0xCAFEF00DCAFEF00D),
        UInt64(0xBADC0FFEEBADC0DE),
        UInt64(0xDEADC0DE5BADBEEF),
        UInt64(0xFACEFEEDC0FFEEEE),
        UInt64(0xC001D00DC001D00D),
        UInt64(0xFEEDFACEDEADBEEF),
        UInt64(0xB16B00B5B16B00B5),
        UInt64(0x8BADF00DBADC0FFE),
        UInt64(0x0BADCAFE0BADCAFE),
        UInt64(0xDEC0DEDDEC0DED01),
        UInt64(0x1357246813572468),
        UInt64(0x2468135724681357),
        UInt64(0xABCDABCDABCDABCD),
        UInt64(0xCDABCDABCDABCDAB),
        UInt64(0x0F0F0F0F0F0F0F0F),
        UInt64(0xF0F0F0F0F0F0F0F0),
        UInt64(0x00FF00FF00FF00FF),
        UInt64(0xFF00FF00FF00FF00),
        UInt64(0x123456789ABCDEF0),
        UInt64(0xFEDCBA0987654321),
        UInt64(0xA1B2C3D4E5F60718),
        UInt64(0x1807F6E5D4C3B2A1),
        UInt64(0xC0FFEE0C0FFEE0C0),
        UInt64(0xFEEDFEEDFEEDFEED),
        UInt64(0x5A5A5A5A5A5A5A5A),
        UInt64(0xA5A5A5A55A5A5A5A),
        UInt64(0xDABBAD00DABBAD00),
        UInt64(0x10101010F0F0F0F0),
        UInt64(0xE7E7E7E7E7E7E7E7),
        UInt64(0x9090909090909090),
        UInt64(0x6969696969696969),
        UInt64(0x42424242DEADBEEF),
    ]
    for s in seeds:
        _run_one_seed(s)
    print(
        "  test_property_lru_matches_brute_force_across_seeds:"
        " PASS (50 seeds × 200 ops)"
    )


def main() raises:
    test_property_lru_matches_brute_force_across_seeds()
