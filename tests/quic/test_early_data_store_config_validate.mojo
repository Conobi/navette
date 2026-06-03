"""Pure-core tests for `EarlyDataStoreConfig.validate()`.

The five zero-checks live on `EarlyDataStoreConfig.validate()` as a
value-type method on the config struct so the public
`EarlyDataPolicy.tuned(config)` factory can validate without allocating.
"""

from navette.tls.early_data_store import (
    EarlyDataStoreConfig,
    default_early_data_store_config,
)
from tests._test_util import assert_true


def test_validate_default_config_does_not_raise() raises:
    """The default config produced by `default_early_data_store_config()`
    must pass `validate()` — used by the non-raising static factories
    `EarlyDataPolicy.off()` and `.idempotent_only()`."""
    var cfg = default_early_data_store_config()
    cfg.validate()
    print("  test_validate_default_config_does_not_raise: PASS")


def test_validate_raises_on_zero_max_entries() raises:
    var cfg = EarlyDataStoreConfig(
        max_entries=UInt32(0), entry_ttl_ms=UInt64(1),
        per_key_max_attempts=UInt32(1), global_window_ms=UInt64(1),
        global_window_max_accepts=UInt32(1),
    )
    var raised = False
    try:
        cfg.validate()
    except:
        raised = True
    assert_true(raised, String("max_entries=0 must raise"))
    print("  test_validate_raises_on_zero_max_entries: PASS")


def test_validate_raises_on_zero_entry_ttl_ms() raises:
    var cfg = EarlyDataStoreConfig(
        max_entries=UInt32(1), entry_ttl_ms=UInt64(0),
        per_key_max_attempts=UInt32(1), global_window_ms=UInt64(1),
        global_window_max_accepts=UInt32(1),
    )
    var raised = False
    try:
        cfg.validate()
    except:
        raised = True
    assert_true(raised, String("entry_ttl_ms=0 must raise"))
    print("  test_validate_raises_on_zero_entry_ttl_ms: PASS")


def test_validate_raises_on_zero_per_key_max_attempts() raises:
    var cfg = EarlyDataStoreConfig(
        max_entries=UInt32(1), entry_ttl_ms=UInt64(1),
        per_key_max_attempts=UInt32(0), global_window_ms=UInt64(1),
        global_window_max_accepts=UInt32(1),
    )
    var raised = False
    try:
        cfg.validate()
    except:
        raised = True
    assert_true(raised, String("per_key_max_attempts=0 must raise"))
    print("  test_validate_raises_on_zero_per_key_max_attempts: PASS")


def test_validate_raises_on_zero_global_window_ms() raises:
    var cfg = EarlyDataStoreConfig(
        max_entries=UInt32(1), entry_ttl_ms=UInt64(1),
        per_key_max_attempts=UInt32(1), global_window_ms=UInt64(0),
        global_window_max_accepts=UInt32(1),
    )
    var raised = False
    try:
        cfg.validate()
    except:
        raised = True
    assert_true(raised, String("global_window_ms=0 must raise"))
    print("  test_validate_raises_on_zero_global_window_ms: PASS")


def test_validate_raises_on_zero_global_window_max_accepts() raises:
    var cfg = EarlyDataStoreConfig(
        max_entries=UInt32(1), entry_ttl_ms=UInt64(1),
        per_key_max_attempts=UInt32(1), global_window_ms=UInt64(1),
        global_window_max_accepts=UInt32(0),
    )
    var raised = False
    try:
        cfg.validate()
    except:
        raised = True
    assert_true(raised, String("global_window_max_accepts=0 must raise"))
    print("  test_validate_raises_on_zero_global_window_max_accepts: PASS")


def main() raises:
    print("test_early_data_store_config_validate")
    test_validate_default_config_does_not_raise()
    test_validate_raises_on_zero_max_entries()
    test_validate_raises_on_zero_entry_ttl_ms()
    test_validate_raises_on_zero_per_key_max_attempts()
    test_validate_raises_on_zero_global_window_ms()
    test_validate_raises_on_zero_global_window_max_accepts()
    print("test_early_data_store_config_validate: PASS")
