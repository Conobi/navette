"""Pure-core tests for `navette.tls.early_data_policy.EarlyDataPolicy`.

Covers eight ACs from the public-API spec:
- policy-off-is-default
- policy-off-static-factory
- policy-idempotent-only-static-factory
- policy-tuned-static-factory-with-valid-config
- policy-tuned-static-factory-raises-on-degenerate
- policy-variants-mutually-exclusive
- policy-is-enabled-matches-non-off
- policy-copyable
"""

from navette.tls.early_data_policy import EarlyDataPolicy
from navette.tls.early_data_store import (
    EarlyDataStoreConfig,
    default_early_data_store_config,
)
from tests._test_util import assert_true, assert_false


def test_policy_off_is_default() raises:
    """AC policy-off-is-default: default-constructed policy is Off."""
    var p = EarlyDataPolicy()
    assert_true(p.is_off(), String("default policy must be Off"))
    assert_false(p.is_enabled(), String("default policy must not be enabled"))
    print("  test_policy_off_is_default: PASS")


def test_policy_off_static_factory() raises:
    """AC policy-off-static-factory: `.off()` builds an Off policy."""
    var p = EarlyDataPolicy.off()
    assert_true(p.is_off(), String("off() must be Off"))
    assert_false(p.is_idempotent_only(), String("off() must not be IdempotentOnly"))
    assert_false(p.is_tuned(), String("off() must not be Tuned"))
    assert_false(p.is_enabled(), String("off() must not be enabled"))
    print("  test_policy_off_static_factory: PASS")


def test_policy_idempotent_only_static_factory() raises:
    """AC policy-idempotent-only-static-factory: `.idempotent_only()` is
    non-raising, builds an IdempotentOnly policy, exposes the default
    store config wrapped in Optional.Some."""
    var p = EarlyDataPolicy.idempotent_only()
    assert_true(p.is_idempotent_only(), String("idempotent_only() must be IdempotentOnly"))
    assert_true(p.is_enabled(), String("idempotent_only() must be enabled"))
    var sc_opt = p.store_config()
    assert_true(sc_opt.__bool__(), String("idempotent_only() must expose Some(store_config)"))
    # Per the round-3 minor: compare against
    # `Optional[EarlyDataStoreConfig](default_early_data_store_config())`
    # by unwrapping with .value() and comparing fields.
    var sc = sc_opt.value().copy()
    var default = default_early_data_store_config()
    assert_true(
        sc.max_entries == default.max_entries
        and sc.entry_ttl_ms == default.entry_ttl_ms
        and sc.per_key_max_attempts == default.per_key_max_attempts
        and sc.global_window_ms == default.global_window_ms
        and sc.global_window_max_accepts == default.global_window_max_accepts,
        String("idempotent_only().store_config() must equal default"),
    )
    print("  test_policy_idempotent_only_static_factory: PASS")


def test_policy_off_store_config_is_none() raises:
    """`store_config()` on Off returns None — eliminates the
    sentinel-default-value footgun called out by round-2 adversary."""
    var p = EarlyDataPolicy.off()
    var sc_opt = p.store_config()
    assert_false(sc_opt.__bool__(), String("off().store_config() must be None"))
    print("  test_policy_off_store_config_is_none: PASS")


def test_policy_tuned_static_factory_with_valid_config() raises:
    """AC policy-tuned-static-factory-with-valid-config: `.tuned(cfg)`
    with valid config builds a Tuned policy whose `store_config()`
    returns the user-supplied config wrapped in Optional.Some."""
    var cfg = EarlyDataStoreConfig(
        max_entries=UInt32(64),
        entry_ttl_ms=UInt64(60_000),
        per_key_max_attempts=UInt32(2),
        global_window_ms=UInt64(500),
        global_window_max_accepts=UInt32(100),
    )
    var p = EarlyDataPolicy.tuned(cfg)
    assert_true(p.is_tuned(), String("tuned(valid) must be Tuned"))
    assert_true(p.is_enabled(), String("tuned(valid) must be enabled"))
    var sc_opt = p.store_config()
    assert_true(sc_opt.__bool__(), String("tuned(valid).store_config() must be Some"))
    var sc = sc_opt.value().copy()
    assert_true(
        sc.max_entries == UInt32(64)
        and sc.entry_ttl_ms == UInt64(60_000)
        and sc.per_key_max_attempts == UInt32(2)
        and sc.global_window_ms == UInt64(500)
        and sc.global_window_max_accepts == UInt32(100),
        String("tuned(cfg).store_config() must equal cfg"),
    )
    print("  test_policy_tuned_static_factory_with_valid_config: PASS")


def _tuned_with_field_zero(which: Int32) raises -> Bool:
    """Helper: build a config with one of the 5 numerics set to zero,
    pass to `.tuned()`, return True iff it raised."""
    var max_entries = UInt32(1) if which != Int32(0) else UInt32(0)
    var entry_ttl_ms = UInt64(1) if which != Int32(1) else UInt64(0)
    var per_key = UInt32(1) if which != Int32(2) else UInt32(0)
    var global_ms = UInt64(1) if which != Int32(3) else UInt64(0)
    var global_max = UInt32(1) if which != Int32(4) else UInt32(0)
    var cfg = EarlyDataStoreConfig(
        max_entries=max_entries,
        entry_ttl_ms=entry_ttl_ms,
        per_key_max_attempts=per_key,
        global_window_ms=global_ms,
        global_window_max_accepts=global_max,
    )
    var raised = False
    try:
        var _p = EarlyDataPolicy.tuned(cfg)
        _ = _p.is_tuned()
    except:
        raised = True
    return raised


def test_policy_tuned_static_factory_raises_on_degenerate() raises:
    """AC policy-tuned-static-factory-raises-on-degenerate: each of the 5
    numerics set to zero individually MUST raise from `.tuned()`."""
    for i in range(5):
        assert_true(
            _tuned_with_field_zero(Int32(i)),
            String("tuned() must raise when field ") + String(i) + String(" is zero"),
        )
    print("  test_policy_tuned_static_factory_raises_on_degenerate: PASS")


def test_policy_variants_mutually_exclusive() raises:
    """AC policy-variants-mutually-exclusive: exactly one of is_off /
    is_idempotent_only / is_tuned returns True for each constructed
    variant."""
    var off = EarlyDataPolicy.off()
    assert_true(off.is_off() and not off.is_idempotent_only() and not off.is_tuned(),
                String("Off must be exclusively Off"))
    var io = EarlyDataPolicy.idempotent_only()
    assert_true(not io.is_off() and io.is_idempotent_only() and not io.is_tuned(),
                String("IdempotentOnly must be exclusively IdempotentOnly"))
    var cfg = default_early_data_store_config()
    var tuned = EarlyDataPolicy.tuned(cfg)
    assert_true(not tuned.is_off() and not tuned.is_idempotent_only() and tuned.is_tuned(),
                String("Tuned must be exclusively Tuned"))
    print("  test_policy_variants_mutually_exclusive: PASS")


def test_policy_is_enabled_matches_non_off() raises:
    """AC policy-is-enabled-matches-non-off: `is_enabled()` is equivalent
    to `is_idempotent_only() or is_tuned()` for each variant."""
    var off = EarlyDataPolicy.off()
    assert_true(
        off.is_enabled() == (off.is_idempotent_only() or off.is_tuned()),
        String("Off: is_enabled must equal (io or tuned)"),
    )
    var io = EarlyDataPolicy.idempotent_only()
    assert_true(
        io.is_enabled() == (io.is_idempotent_only() or io.is_tuned()),
        String("IdempotentOnly: is_enabled must equal (io or tuned)"),
    )
    var cfg = default_early_data_store_config()
    var tuned = EarlyDataPolicy.tuned(cfg)
    assert_true(
        tuned.is_enabled() == (tuned.is_idempotent_only() or tuned.is_tuned()),
        String("Tuned: is_enabled must equal (io or tuned)"),
    )
    print("  test_policy_is_enabled_matches_non_off: PASS")


def test_policy_copyable() raises:
    """AC policy-copyable: copy-ctor preserves variant AND store config."""
    var cfg = EarlyDataStoreConfig(
        max_entries=UInt32(7),
        entry_ttl_ms=UInt64(99),
        per_key_max_attempts=UInt32(5),
        global_window_ms=UInt64(123),
        global_window_max_accepts=UInt32(456),
    )
    var src = EarlyDataPolicy.tuned(cfg)
    var dst = EarlyDataPolicy(other=src)
    assert_true(dst.is_tuned(), String("copy of Tuned must be Tuned"))
    var dst_sc = dst.store_config().value().copy()
    assert_true(
        dst_sc.max_entries == UInt32(7) and dst_sc.entry_ttl_ms == UInt64(99),
        String("copy must preserve store config fields"),
    )
    print("  test_policy_copyable: PASS")


def main() raises:
    print("test_early_data_policy")
    test_policy_off_is_default()
    test_policy_off_static_factory()
    test_policy_idempotent_only_static_factory()
    test_policy_off_store_config_is_none()
    test_policy_tuned_static_factory_with_valid_config()
    test_policy_tuned_static_factory_raises_on_degenerate()
    test_policy_variants_mutually_exclusive()
    test_policy_is_enabled_matches_non_off()
    test_policy_copyable()
    print("test_early_data_policy: PASS")
