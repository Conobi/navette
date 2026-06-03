"""Tests for the `policy` ctor kwarg on `QuicServerConfig`.

Covers six ACs for the public-API surface that threads
`EarlyDataPolicy` through `QuicServerConfig.__init__`:

- ctor-with-policy-off:                       `.off()` matches the
                                              "kwarg omitted" baseline.
- ctor-with-policy-idempotent-only:           `.idempotent_only()`
                                              enables 0-RTT and
                                              populates both Optionals.
- ctor-with-policy-tuned:                     `.tuned(custom)` threads
                                              the user's store config
                                              into the in-memory store.
- ctor-policy-with-legacy-zero-honors-policy: legacy `max_early_data=0`
                                              + policy enabled is not
                                              contradictory.
- ctor-policy-off-with-legacy-non-zero-raises: legacy
                                              `max_early_data > 0` +
                                              `policy.off()` fails fast.
- ctor-legacy-max-early-data-still-works:     prior callers that pass
                                              only `max_early_data=
                                              u32::MAX` keep working.

The contradictory-kwargs message includes the stable substring
`"contradictory early-data kwargs"` — pinned here so future ctor
refactors cannot silently break the operator-facing diagnostic.
"""

from std.memory import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig
from navette.tls.early_data_policy import EarlyDataPolicy
from navette.tls.early_data_store import EarlyDataStoreConfig
from tests._test_util import assert_true, assert_false, load_test_cert


def test_ctor_with_policy_off() raises:
    """AC ctor-with-policy-off: `policy=EarlyDataPolicy.off()` produces
    the same state as omitting the kwarg — `_max_early_data == 0`, both
    Optionals None. Off must remain the safe default posture."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        policy=EarlyDataPolicy.off(),
    )
    assert_true(
        cfg.max_early_data() == UInt32(0),
        String("policy=off must produce max_early_data=0"),
    )
    assert_true(
        cfg._early_data_store is None,
        String("policy=off store must be None"),
    )
    assert_true(
        cfg._early_data_filter is None,
        String("policy=off filter must be None"),
    )
    _ = cfg._handle
    print("  test_ctor_with_policy_off: PASS")


def test_ctor_with_policy_idempotent_only() raises:
    """AC ctor-with-policy-idempotent-only: `EarlyDataPolicy
    .idempotent_only()` enables 0-RTT — `_max_early_data == u32::MAX`
    (rustls QUIC, RFC 9001 §4.6.1) and both Optionals carry the
    default-configured store + the IdempotentOnly HTTP filter."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        policy=EarlyDataPolicy.idempotent_only(),
    )
    assert_true(
        cfg.max_early_data() == UInt32(0xFFFFFFFF),
        String("policy=idempotent_only must produce max_early_data=u32::MAX"),
    )
    assert_true(
        cfg._early_data_store is not None,
        String("policy=idempotent_only store must be Some"),
    )
    assert_true(
        cfg._early_data_filter is not None,
        String("policy=idempotent_only filter must be Some"),
    )
    _ = cfg._handle
    print("  test_ctor_with_policy_idempotent_only: PASS")


def test_ctor_with_policy_tuned() raises:
    """AC ctor-with-policy-tuned: `EarlyDataPolicy.tuned(custom)`
    enables 0-RTT AND threads the caller's tuning knobs into the
    in-memory store. Verifies all five `EarlyDataStoreConfig` fields
    round-trip into `InMemoryEarlyDataStore._config`."""
    var custom = EarlyDataStoreConfig(
        max_entries=UInt32(99),
        entry_ttl_ms=UInt64(7_777),
        per_key_max_attempts=UInt32(11),
        global_window_ms=UInt64(2_222),
        global_window_max_accepts=UInt32(333),
    )
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        policy=EarlyDataPolicy.tuned(custom),
    )
    assert_true(
        cfg.max_early_data() == UInt32(0xFFFFFFFF),
        String("policy=tuned must produce max_early_data=u32::MAX"),
    )
    assert_true(
        cfg._early_data_store is not None,
        String("policy=tuned store must be Some"),
    )
    assert_true(
        cfg._early_data_filter is not None,
        String("policy=tuned filter must be Some"),
    )
    var store_cfg = cfg._early_data_store.value()._config.copy()
    assert_true(
        store_cfg.max_entries == UInt32(99)
        and store_cfg.entry_ttl_ms == UInt64(7_777)
        and store_cfg.per_key_max_attempts == UInt32(11)
        and store_cfg.global_window_ms == UInt64(2_222)
        and store_cfg.global_window_max_accepts == UInt32(333),
        String(
            "tuned ctor must thread store_config to the in-memory store"
        ),
    )
    _ = cfg._handle
    print("  test_ctor_with_policy_tuned: PASS")


def test_ctor_policy_with_legacy_zero_honors_policy() raises:
    """AC ctor-policy-with-legacy-zero-honors-policy: passing
    `max_early_data=0` AND `policy=EarlyDataPolicy.idempotent_only()`
    is NOT contradictory — the legacy kwarg's "disable" reading is
    superseded by the explicit policy. Operator intent is to enable;
    the legacy default leaks through harmlessly."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0),
        policy=EarlyDataPolicy.idempotent_only(),
    )
    assert_true(
        cfg.max_early_data() == UInt32(0xFFFFFFFF),
        String(
            "policy=idempotent_only + max_early_data=0 must enable via policy"
        ),
    )
    assert_true(
        cfg._early_data_store is not None,
        String("store must be Some when policy enables"),
    )
    assert_true(
        cfg._early_data_filter is not None,
        String("filter must be Some when policy enables"),
    )
    _ = cfg._handle
    print("  test_ctor_policy_with_legacy_zero_honors_policy: PASS")


def test_ctor_policy_off_with_legacy_non_zero_raises() raises:
    """AC ctor-policy-off-with-legacy-non-zero-raises: passing
    `max_early_data > 0` AND `policy=EarlyDataPolicy.off()` MUST raise
    before the rustls FFI ctor runs. The two kwargs encode opposite
    operator intent; refusing the combination prevents a config that
    silently disables 0-RTT after the caller explicitly requested it
    (or vice-versa). The error message MUST contain the stable
    substring `"contradictory early-data kwargs"` — that substring is
    the API contract documented in the ctor docstring."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var raised = False
    var msg = String("")
    try:
        var _cfg = QuicServerConfig(
            tls.shared(), Span(cert_pem), Span(key_pem),
            max_early_data=UInt32(0xFFFFFFFF),
            policy=EarlyDataPolicy.off(),
        )
        _ = _cfg.max_early_data()
    except e:
        raised = True
        msg = String(e)
    assert_true(raised, String("contradictory kwargs must raise"))
    assert_true(
        msg.find("contradictory early-data kwargs") >= 0,
        String("error message must include the stable substring; got: ") + msg,
    )
    print("  test_ctor_policy_off_with_legacy_non_zero_raises: PASS")


def test_ctor_legacy_max_early_data_still_works() raises:
    """AC ctor-legacy-max-early-data-still-works: omitting `policy=`
    and passing only `max_early_data=u32::MAX` MUST yield the same
    observable state — `_max_early_data`, store/filter populated — as
    the explicit `policy=EarlyDataPolicy.idempotent_only()` form.
    Backward compatibility for the existing legacy-kwarg call sites."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls1 = TlsBackend()
    var legacy = QuicServerConfig(
        tls1.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    var tls2 = TlsBackend()
    var policied = QuicServerConfig(
        tls2.shared(), Span(cert_pem), Span(key_pem),
        policy=EarlyDataPolicy.idempotent_only(),
    )
    assert_true(
        legacy.max_early_data() == policied.max_early_data(),
        String("legacy max_early_data=u32::MAX must match policy enabled"),
    )
    assert_true(
        (legacy._early_data_store is not None)
        and (policied._early_data_store is not None),
        String("both ctors must populate the store"),
    )
    assert_true(
        (legacy._early_data_filter is not None)
        and (policied._early_data_filter is not None),
        String("both ctors must populate the filter"),
    )
    _ = legacy._handle
    _ = policied._handle
    print("  test_ctor_legacy_max_early_data_still_works: PASS")


def main() raises:
    print("test_quic_server_config_policy")
    test_ctor_with_policy_off()
    test_ctor_with_policy_idempotent_only()
    test_ctor_with_policy_tuned()
    test_ctor_policy_with_legacy_zero_honors_policy()
    test_ctor_policy_off_with_legacy_non_zero_raises()
    test_ctor_legacy_max_early_data_still_works()
    print("test_quic_server_config_policy: PASS")
