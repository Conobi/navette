# Pure-core tests for navette.tls.early_data_store.
#
# Covers the 14 ACs that do not need FFI or connection state.

from std.memory import Span
from std.collections.dict import Dict

from navette.tls.early_data_store import (
    InMemoryEarlyDataStore, ReplayDecision, KeyTag,
    EarlyDataStoreConfig, default_early_data_store_config,
)
from tests._test_util import assert_true, assert_false, assert_equal_int


def _fill_auth(byte: UInt8) -> List[UInt8]:
    var out = List[UInt8]()
    for _ in range(32):
        out.append(byte)
    return out^


def test_in_memory_lru_default_constructs() raises:
    """AC in-memory-lru-default-constructs-with-defaults: zero-arg ctor
    succeeds and stamps documented defaults."""
    var store = InMemoryEarlyDataStore()
    assert_equal_int(Int(store._config.max_entries), 16384, "max_entries")
    assert_equal_int(
        Int(store._config.entry_ttl_ms), 1_800_000, "entry_ttl_ms"
    )
    assert_equal_int(
        Int(store._config.per_key_max_attempts), 3, "per_key_max_attempts"
    )
    assert_equal_int(
        Int(store._config.global_window_ms), 1_000, "global_window_ms"
    )
    assert_equal_int(
        Int(store._config.global_window_max_accepts), 1_000,
        "global_window_max_accepts"
    )
    _ = store._entries  # extend lifetime
    print("  test_in_memory_lru_default_constructs: PASS")


def test_in_memory_lru_refuses_degenerate_config() raises:
    """AC in-memory-lru-refuses-degenerate-config: each numeric == 0
    individually raises on construction."""
    var cfg_max_entries = EarlyDataStoreConfig(
        max_entries=UInt32(0), entry_ttl_ms=UInt64(1),
        per_key_max_attempts=UInt32(1), global_window_ms=UInt64(1),
        global_window_max_accepts=UInt32(1),
    )
    var raised = False
    try:
        var _s = InMemoryEarlyDataStore(config=cfg_max_entries)
        _ = _s._config
    except:
        raised = True
    assert_true(raised, "max_entries=0 must raise")

    var cfg_ttl = EarlyDataStoreConfig(
        max_entries=UInt32(1), entry_ttl_ms=UInt64(0),
        per_key_max_attempts=UInt32(1), global_window_ms=UInt64(1),
        global_window_max_accepts=UInt32(1),
    )
    raised = False
    try:
        var _s = InMemoryEarlyDataStore(config=cfg_ttl)
        _ = _s._config
    except:
        raised = True
    assert_true(raised, "entry_ttl_ms=0 must raise")

    var cfg_per_key = EarlyDataStoreConfig(
        max_entries=UInt32(1), entry_ttl_ms=UInt64(1),
        per_key_max_attempts=UInt32(0), global_window_ms=UInt64(1),
        global_window_max_accepts=UInt32(1),
    )
    raised = False
    try:
        var _s = InMemoryEarlyDataStore(config=cfg_per_key)
        _ = _s._config
    except:
        raised = True
    assert_true(raised, "per_key_max_attempts=0 must raise")

    var cfg_window = EarlyDataStoreConfig(
        max_entries=UInt32(1), entry_ttl_ms=UInt64(1),
        per_key_max_attempts=UInt32(1), global_window_ms=UInt64(0),
        global_window_max_accepts=UInt32(1),
    )
    raised = False
    try:
        var _s = InMemoryEarlyDataStore(config=cfg_window)
        _ = _s._config
    except:
        raised = True
    assert_true(raised, "global_window_ms=0 must raise")

    var cfg_ceiling = EarlyDataStoreConfig(
        max_entries=UInt32(1), entry_ttl_ms=UInt64(1),
        per_key_max_attempts=UInt32(1), global_window_ms=UInt64(1),
        global_window_max_accepts=UInt32(0),
    )
    raised = False
    try:
        var _s = InMemoryEarlyDataStore(config=cfg_ceiling)
        _ = _s._config
    except:
        raised = True
    assert_true(raised, "global_window_max_accepts=0 must raise")
    print("  test_in_memory_lru_refuses_degenerate_config: PASS")


def test_key_tag_roundtrip() raises:
    """AC key-tag-roundtrip + key-tag-rejects-wrong-length."""
    var a = _fill_auth(UInt8(0x42))
    var ka = KeyTag.from_span(Span(a))
    var kb = KeyTag.from_span(Span(a))
    assert_true(ka == kb, "identical bytes must compare equal")

    var b = _fill_auth(UInt8(0x42))
    b[0] = UInt8(0x43)
    var kb2 = KeyTag.from_span(Span(b))
    assert_false(ka == kb2, "single-byte diff must compare not-equal")

    # wrong length
    var z0 = List[UInt8]()
    var raised = False
    try:
        var _k = KeyTag.from_span(Span(z0))
        _ = _k.bytes
    except:
        raised = True
    assert_true(raised, "len 0 must raise")

    var z31 = List[UInt8]()
    for _ in range(31):
        z31.append(UInt8(0))
    raised = False
    try:
        var _k = KeyTag.from_span(Span(z31))
        _ = _k.bytes
    except:
        raised = True
    assert_true(raised, "len 31 must raise")

    var z33 = List[UInt8]()
    for _ in range(33):
        z33.append(UInt8(0))
    raised = False
    try:
        var _k = KeyTag.from_span(Span(z33))
        _ = _k.bytes
    except:
        raised = True
    assert_true(raised, "len 33 must raise")
    print("  test_key_tag_roundtrip: PASS")


def test_first_authenticator_accepts() raises:
    """AC first-authenticator-accepts."""
    var store = InMemoryEarlyDataStore()
    var a = _fill_auth(UInt8(0xAA))
    var d = store.check_and_record(Span(a), UInt64(1000))
    assert_true(d.is_accept(), "fresh authenticator must accept")
    _ = store._config  # extend lifetime
    print("  test_first_authenticator_accepts: PASS")


def test_second_authenticator_rejects_duplicate() raises:
    """AC second-authenticator-rejects-duplicate."""
    var store = InMemoryEarlyDataStore()
    var a = _fill_auth(UInt8(0xAA))
    var d1 = store.check_and_record(Span(a), UInt64(1000))
    assert_true(d1.is_accept(), "first call must accept")
    var d2 = store.check_and_record(Span(a), UInt64(1000))
    assert_true(d2.is_duplicate(), "second identical call must report duplicate")
    _ = store._config
    print("  test_second_authenticator_rejects_duplicate: PASS")


def test_per_key_quota_exhausts() raises:
    """AC per-key-quota-exhausts: with per_key_max_attempts=3, four calls
    yield accept/duplicate/duplicate/per_key_quota_exhausted."""
    var cfg = default_early_data_store_config()
    cfg.per_key_max_attempts = UInt32(3)
    var store = InMemoryEarlyDataStore(config=cfg)
    var a = _fill_auth(UInt8(0xAA))
    var d1 = store.check_and_record(Span(a), UInt64(1000))
    var d2 = store.check_and_record(Span(a), UInt64(1000))
    var d3 = store.check_and_record(Span(a), UInt64(1000))
    var d4 = store.check_and_record(Span(a), UInt64(1000))
    assert_true(d1.is_accept(), "1st must accept")
    assert_true(d2.is_duplicate(), "2nd must duplicate")
    assert_true(d3.is_duplicate(), "3rd must duplicate")
    assert_true(d4.is_per_key_quota(), "4th must per_key_quota_exhausted")
    _ = store._config
    print("  test_per_key_quota_exhausts: PASS")


def test_global_ceiling_exhausts() raises:
    """AC global-ceiling-exhausts: ceiling=2 with three distinct
    authenticators at the same timestamp: accept, accept,
    global_ceiling_exhausted. Third key is NOT registered."""
    var cfg = default_early_data_store_config()
    cfg.global_window_max_accepts = UInt32(2)
    cfg.global_window_ms = UInt64(1000)
    var store = InMemoryEarlyDataStore(config=cfg)
    var a = _fill_auth(UInt8(0x01))
    var b = _fill_auth(UInt8(0x02))
    var c = _fill_auth(UInt8(0x03))
    var d1 = store.check_and_record(Span(a), UInt64(1000))
    var d2 = store.check_and_record(Span(b), UInt64(1000))
    var d3 = store.check_and_record(Span(c), UInt64(1000))
    assert_true(d1.is_accept(), "1st must accept")
    assert_true(d2.is_accept(), "2nd must accept")
    assert_true(d3.is_global_ceiling(), "3rd must global_ceiling")
    var key_c = KeyTag.from_span(Span(c))
    assert_false(
        key_c in store._entries,
        "third authenticator must NOT register after ceiling reject"
    )
    _ = store._config
    print("  test_global_ceiling_exhausts: PASS")


def test_global_ceiling_window_slides() raises:
    """AC global-ceiling-window-slides."""
    var cfg = default_early_data_store_config()
    cfg.global_window_max_accepts = UInt32(2)
    cfg.global_window_ms = UInt64(1000)
    var store = InMemoryEarlyDataStore(config=cfg)
    var a = _fill_auth(UInt8(0x01))
    var b = _fill_auth(UInt8(0x02))
    var c = _fill_auth(UInt8(0x03))
    var d = _fill_auth(UInt8(0x04))
    var d1 = store.check_and_record(Span(a), UInt64(0))
    var d2 = store.check_and_record(Span(b), UInt64(500))
    var d3 = store.check_and_record(Span(c), UInt64(1500))
    var d4 = store.check_and_record(Span(d), UInt64(1600))
    assert_true(d1.is_accept(), "t=0 must accept")
    assert_true(d2.is_accept(), "t=500 must accept")
    assert_true(
        d3.is_accept(),
        "t=1500 (after t=0 slides off at t=1000+window) must accept"
    )
    assert_true(d4.is_accept(), "t=1600 must accept")
    _ = store._config
    print("  test_global_ceiling_window_slides: PASS")


def test_global_window_boundary_half_open() raises:
    """AC window-boundary-convention-pinned: the global accept window is
    half-open (now − window_ms, now] — an accept recorded at t still
    counts at t + window_ms − 1 and is expired at exactly t + window_ms
    (`front + window_ms <= now` in the drain loop)."""
    var cfg = default_early_data_store_config()
    cfg.global_window_max_accepts = UInt32(2)
    cfg.global_window_ms = UInt64(1000)
    var store = InMemoryEarlyDataStore(config=cfg)
    var a = _fill_auth(UInt8(0x01))
    var b = _fill_auth(UInt8(0x02))
    var c = _fill_auth(UInt8(0x03))
    var d = _fill_auth(UInt8(0x04))
    # Fill the window (ceiling = 2) at t = 1000.
    var d1 = store.check_and_record(Span(a), UInt64(1000))
    var d2 = store.check_and_record(Span(b), UInt64(1000))
    assert_true(d1.is_accept(), "t=1000 first accept")
    assert_true(d2.is_accept(), "t=1000 second accept")
    # t + window_ms − 1 = 1999: both accepts still count — the global
    # ceiling rejects a third, distinct authenticator.
    var d3 = store.check_and_record(Span(c), UInt64(1999))
    assert_true(
        d3.is_global_ceiling(),
        "t+window_ms-1 must still count the window entries (ceiling fires)",
    )
    # t + window_ms = 2000: both accepts expire (front + window_ms <= now)
    # — a fresh authenticator is accepted.
    var d4 = store.check_and_record(Span(d), UInt64(2000))
    assert_true(
        d4.is_accept(),
        "at exactly t+window_ms the entries are expired (half-open window)",
    )
    _ = store._config
    print("  test_global_window_boundary_half_open: PASS")


def test_ttl_expiry_resets_authenticator() raises:
    """AC ttl-expiry-resets-authenticator."""
    var cfg = default_early_data_store_config()
    cfg.entry_ttl_ms = UInt64(1000)
    var store = InMemoryEarlyDataStore(config=cfg)
    var a = _fill_auth(UInt8(0xAA))
    var d1 = store.check_and_record(Span(a), UInt64(0))
    var d2 = store.check_and_record(Span(a), UInt64(1001))
    assert_true(d1.is_accept(), "first must accept")
    assert_true(d2.is_accept(), "post-TTL must accept (entry refreshed)")
    _ = store._config
    print("  test_ttl_expiry_resets_authenticator: PASS")


def test_clock_regression_treats_old_entry_as_live() raises:
    """AC clock-regression-treats-old-entry-as-live."""
    var store = InMemoryEarlyDataStore()
    var a = _fill_auth(UInt8(0xAA))
    var d1 = store.check_and_record(Span(a), UInt64(1000))
    var d2 = store.check_and_record(Span(a), UInt64(500))
    assert_true(d1.is_accept(), "first must accept")
    assert_true(
        d2.is_duplicate(),
        "second at earlier timestamp must report duplicate (saturating sub)"
    )
    _ = store._config
    print("  test_clock_regression_treats_old_entry_as_live: PASS")


def test_lru_eviction_bounds_memory() raises:
    """AC lru-eviction-bounds-memory: insert A,B,C,D,E with max_entries=4;
    A is evicted; calling with A again returns accept."""
    var cfg = default_early_data_store_config()
    cfg.max_entries = UInt32(4)
    var store = InMemoryEarlyDataStore(config=cfg)
    var a = _fill_auth(UInt8(0x01))
    var b = _fill_auth(UInt8(0x02))
    var c = _fill_auth(UInt8(0x03))
    var d = _fill_auth(UInt8(0x04))
    var e = _fill_auth(UInt8(0x05))
    _ = store.check_and_record(Span(a), UInt64(1000))
    _ = store.check_and_record(Span(b), UInt64(1000))
    _ = store.check_and_record(Span(c), UInt64(1000))
    _ = store.check_and_record(Span(d), UInt64(1000))
    _ = store.check_and_record(Span(e), UInt64(1000))
    var d_a2 = store.check_and_record(Span(a), UInt64(1000))
    assert_true(d_a2.is_accept(), "A must accept again — was evicted")
    _ = store._config
    print("  test_lru_eviction_bounds_memory: PASS")


def test_lru_eviction_preserves_recently_touched() raises:
    """AC lru-eviction-preserves-recently-touched."""
    var cfg = default_early_data_store_config()
    cfg.max_entries = UInt32(4)
    var store = InMemoryEarlyDataStore(config=cfg)
    var a = _fill_auth(UInt8(0x01))
    var b = _fill_auth(UInt8(0x02))
    var c = _fill_auth(UInt8(0x03))
    var d = _fill_auth(UInt8(0x04))
    var e = _fill_auth(UInt8(0x05))
    _ = store.check_and_record(Span(a), UInt64(1000))
    _ = store.check_and_record(Span(b), UInt64(1000))
    _ = store.check_and_record(Span(c), UInt64(1000))
    _ = store.check_and_record(Span(d), UInt64(1000))
    # Touch A → duplicate, but moved to MRU.
    var touch = store.check_and_record(Span(a), UInt64(1000))
    assert_true(touch.is_duplicate(), "touch of A returns duplicate")
    # Now insert E. B should be evicted (LRU front after A's touch).
    _ = store.check_and_record(Span(e), UInt64(1000))
    var key_b = KeyTag.from_span(Span(b))
    var key_a = KeyTag.from_span(Span(a))
    assert_false(key_b in store._entries, "B must be evicted (oldest)")
    assert_true(key_a in store._entries, "A must remain (recently touched)")
    _ = store._config
    print("  test_lru_eviction_preserves_recently_touched: PASS")


def test_clock_eviction_terminates_when_all_referenced() raises:
    """AC eviction-terminates-when-all-referenced: with every resident
    entry's `referenced` bit set, one at-capacity insert performs
    exactly one eviction (n re-appends + one evicting pop), evicts the
    clock-order front, and clears the survivors' bits — no spin, no
    over-eviction. Reads `EarlyDataEntry.referenced` directly, so this
    test is compile-blocked on the pre-CLOCK code (Red-Gate exempt,
    compile-blocked class)."""
    var cfg = default_early_data_store_config()
    cfg.max_entries = UInt32(4)
    var store = InMemoryEarlyDataStore(config=cfg)
    var a = _fill_auth(UInt8(0x01))
    var b = _fill_auth(UInt8(0x02))
    var c = _fill_auth(UInt8(0x03))
    var d = _fill_auth(UInt8(0x04))
    var e = _fill_auth(UInt8(0x05))
    _ = store.check_and_record(Span(a), UInt64(1000))
    _ = store.check_and_record(Span(b), UInt64(1000))
    _ = store.check_and_record(Span(c), UInt64(1000))
    _ = store.check_and_record(Span(d), UInt64(1000))
    _ = store.check_and_record(Span(a), UInt64(1000))
    _ = store.check_and_record(Span(b), UInt64(1000))
    _ = store.check_and_record(Span(c), UInt64(1000))
    _ = store.check_and_record(Span(d), UInt64(1000))
    var d_e = store.check_and_record(Span(e), UInt64(1000))
    assert_true(d_e.is_accept(), "E must accept after one eviction")
    assert_equal_int(len(store._entries), 4, "exactly one eviction (dict)")
    assert_equal_int(len(store._lru), 4, "exactly one eviction (deque)")
    var key_a = KeyTag.from_span(Span(a))
    assert_false(key_a in store._entries, "A (clock front) must be evicted")
    var key_b = KeyTag.from_span(Span(b))
    var key_c = KeyTag.from_span(Span(c))
    var key_d = KeyTag.from_span(Span(d))
    assert_false(store._entries[key_b].referenced, "B bit cleared by the pass")
    assert_false(store._entries[key_c].referenced, "C bit cleared by the pass")
    assert_false(store._entries[key_d].referenced, "D bit cleared by the pass")
    _ = store._config
    print("  test_clock_eviction_terminates_when_all_referenced: PASS")


def test_default_store_field_populated_when_zero_rtt_enabled() raises:
    """AC default-store-field-populated-when-zero-rtt-enabled."""
    from navette.tls.lib import TlsBackend
    from navette.tls.config import QuicServerConfig
    from tests._test_util import load_test_cert

    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    assert_true(
        cfg._early_data_store is not None,
        "max_early_data != 0 must populate _early_data_store",
    )
    _ = cfg._handle  # extend lifetime
    print("  test_default_store_field_populated_when_zero_rtt_enabled: PASS")


def test_no_store_field_when_zero_rtt_disabled() raises:
    """AC no-store-field-when-zero-rtt-disabled."""
    from navette.tls.lib import TlsBackend
    from navette.tls.config import QuicServerConfig
    from tests._test_util import load_test_cert

    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0),
    )
    assert_true(
        cfg._early_data_store is None,
        "max_early_data == 0 must leave _early_data_store None",
    )
    _ = cfg._handle
    print("  test_no_store_field_when_zero_rtt_disabled: PASS")


def main() raises:
    test_in_memory_lru_default_constructs()
    test_in_memory_lru_refuses_degenerate_config()
    test_key_tag_roundtrip()
    test_first_authenticator_accepts()
    test_second_authenticator_rejects_duplicate()
    test_per_key_quota_exhausts()
    test_global_ceiling_exhausts()
    test_global_ceiling_window_slides()
    test_global_window_boundary_half_open()
    test_ttl_expiry_resets_authenticator()
    test_clock_regression_treats_old_entry_as_live()
    test_lru_eviction_bounds_memory()
    test_lru_eviction_preserves_recently_touched()
    test_clock_eviction_terminates_when_all_referenced()
    test_default_store_field_populated_when_zero_rtt_enabled()
    test_no_store_field_when_zero_rtt_disabled()
