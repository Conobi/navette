"""Tests for the early-data ctor kwargs on `QuicServerConfig`.

Pins the TOTAL nine-cell resolution table for the
(`max_early_data: Optional[UInt32]`, `policy: Optional[EarlyDataPolicy]`)
kwarg pair — every cell has a test, here or in
`tests/tls/test_quic_server_config_predicate.mojo` (the Predicate
enabling cell):

- (omitted, omitted)        -> 0-RTT off (default).
- (Some(0), omitted)        -> legacy semantics, off.
- (Some(v>0), omitted)      -> legacy semantics, effective = v.
- (omitted, off)            -> 0-RTT off (kwargs agree).
- (omitted, enabling)       -> policy decides, u32::MAX.
- (Some(0), off)            -> 0-RTT off (kwargs agree, no raise).
- (Some(v>0), off)          -> raise (contradictory).
- (Some(0), enabling)       -> raise (contradictory) — DELIBERATE
                               inversion of the former
                               "legacy-zero honors policy" pin, made
                               possible by the Optional legacy kwarg.
- (Some(v>0), enabling)     -> policy wins, u32::MAX.

Both contradictory-kwargs messages include the stable substring
`"contradictory early-data kwargs"` — pinned here so future ctor
refactors cannot silently break the operator-facing diagnostic.
"""

from std.memory import Span

from navette.http.headers import Headers
from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig
from navette.tls.early_data_filter import FilterDecision
from navette.tls.early_data_policy import EarlyDataPolicy
from navette.tls.early_data_store import EarlyDataStoreConfig
from tests._test_util import assert_true, assert_false, load_test_cert


def _policy_table_predicate(
    method: String, path: String, headers: Headers
) raises -> FilterDecision:
    """Accept-all predicate used purely to build a Predicate-variant
    policy for the kwarg-resolution-table tests. Never invoked."""
    return FilterDecision.accept()


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


def test_ctor_policy_with_legacy_zero_raises() raises:
    """AC explicit-zero-plus-enabling-policy-raises: passing an explicit
    `max_early_data=UInt32(0)` (disable intent) AND an enabling policy
    MUST raise with the stable substring, for ALL THREE enabling
    variants (idempotent_only / tuned / predicate).

    DELIBERATE INVERSION of the former
    "legacy-zero honors policy" pin: with the legacy kwarg now
    `Optional[UInt32]`, explicit-0 is distinguishable from omitted, so
    the symmetric contradictory-kwargs guard applies — the same
    operator-confusion class the (max_early_data>0, off) guard already
    rejects in the other direction."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()

    # Variant 1: idempotent_only().
    var tls1 = TlsBackend()
    var raised = False
    var msg = String("")
    try:
        var _cfg = QuicServerConfig(
            tls1.shared(), Span(cert_pem), Span(key_pem),
            max_early_data=UInt32(0),
            policy=EarlyDataPolicy.idempotent_only(),
        )
        _ = _cfg.max_early_data()
    except e:
        raised = True
        msg = String(e)
    assert_true(raised, String("explicit zero + idempotent_only must raise"))
    assert_true(
        msg.find("contradictory early-data kwargs") >= 0,
        String("error must include the stable substring; got: ") + msg,
    )

    # Variant 2: tuned(...).
    var tls2 = TlsBackend()
    raised = False
    msg = String("")
    try:
        var _cfg = QuicServerConfig(
            tls2.shared(), Span(cert_pem), Span(key_pem),
            max_early_data=UInt32(0),
            policy=EarlyDataPolicy.tuned(EarlyDataStoreConfig(
                max_entries=UInt32(16),
                entry_ttl_ms=UInt64(1_000),
                per_key_max_attempts=UInt32(3),
                global_window_ms=UInt64(1_000),
                global_window_max_accepts=UInt32(100),
            )),
        )
        _ = _cfg.max_early_data()
    except e:
        raised = True
        msg = String(e)
    assert_true(raised, String("explicit zero + tuned must raise"))
    assert_true(
        msg.find("contradictory early-data kwargs") >= 0,
        String("error must include the stable substring; got: ") + msg,
    )

    # Variant 3: predicate(...).
    var tls3 = TlsBackend()
    raised = False
    msg = String("")
    try:
        var _cfg = QuicServerConfig(
            tls3.shared(), Span(cert_pem), Span(key_pem),
            max_early_data=UInt32(0),
            policy=EarlyDataPolicy.predicate(_policy_table_predicate),
        )
        _ = _cfg.max_early_data()
    except e:
        raised = True
        msg = String(e)
    assert_true(raised, String("explicit zero + predicate must raise"))
    assert_true(
        msg.find("contradictory early-data kwargs") >= 0,
        String("error must include the stable substring; got: ") + msg,
    )
    print("  test_ctor_policy_with_legacy_zero_raises: PASS")


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


def test_ctor_both_kwargs_omitted_is_off() raises:
    """Kwarg-table cell (omitted, omitted): omitting both kwargs keeps
    0-RTT off — `max_early_data() == 0` and all three population slots
    None. The unchanged safe default."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var cfg = QuicServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    assert_true(
        cfg.max_early_data() == UInt32(0),
        String("both kwargs omitted must produce max_early_data=0"),
    )
    assert_true(cfg._early_data_store is None, String("default store must be None"))
    assert_true(cfg._early_data_filter is None, String("default filter must be None"))
    assert_true(
        cfg._early_data_predicate_fn is None,
        String("default predicate-fn must be None"),
    )
    _ = cfg._handle
    print("  test_ctor_both_kwargs_omitted_is_off: PASS")


def test_ctor_legacy_explicit_zero_without_policy_is_off() raises:
    """Kwarg-table cell (Some(0), omitted): explicit
    `max_early_data=UInt32(0)` with the policy kwarg omitted keeps the
    legacy semantics — 0-RTT off, NO raise. Only an explicitly-enabling
    policy makes explicit-zero contradictory."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0),
    )
    assert_true(
        cfg.max_early_data() == UInt32(0),
        String("explicit zero without policy must stay off"),
    )
    assert_true(
        cfg._early_data_store is None,
        String("explicit zero without policy: store must be None"),
    )
    _ = cfg._handle
    print("  test_ctor_legacy_explicit_zero_without_policy_is_off: PASS")


def test_ctor_explicit_zero_with_policy_off_agrees() raises:
    """Kwarg-table cell (Some(0), off): both kwargs agree on "disabled"
    — valid, NO raise, 0-RTT off."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0),
        policy=EarlyDataPolicy.off(),
    )
    assert_true(
        cfg.max_early_data() == UInt32(0),
        String("explicit zero + off must stay off (kwargs agree)"),
    )
    assert_true(
        cfg._early_data_filter is None,
        String("explicit zero + off: filter must be None"),
    )
    _ = cfg._handle
    print("  test_ctor_explicit_zero_with_policy_off_agrees: PASS")


def test_ctor_legacy_nonzero_with_enabling_policy_policy_wins() raises:
    """Kwarg-table cell (Some(v>0), enabling): policy wins — effective
    max_early_data is u32::MAX, store + filter populated. v is
    u32::MAX here because rustls QUIC constrains the legacy knob to
    {0, u32::MAX}; the cell's semantics (policy wins, no raise) are
    independent of v's exact non-zero value."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
        policy=EarlyDataPolicy.idempotent_only(),
    )
    assert_true(
        cfg.max_early_data() == UInt32(0xFFFFFFFF),
        String("legacy non-zero + enabling policy must yield u32::MAX"),
    )
    assert_true(
        cfg._early_data_store is not None,
        String("policy-wins cell must populate the store"),
    )
    assert_true(
        cfg._early_data_filter is not None,
        String("policy-wins cell must populate the filter"),
    )
    _ = cfg._handle
    print("  test_ctor_legacy_nonzero_with_enabling_policy_policy_wins: PASS")


def main() raises:
    print("test_quic_server_config_policy")
    test_ctor_with_policy_off()
    test_ctor_with_policy_idempotent_only()
    test_ctor_with_policy_tuned()
    test_ctor_policy_with_legacy_zero_raises()
    test_ctor_policy_off_with_legacy_non_zero_raises()
    test_ctor_legacy_max_early_data_still_works()
    test_ctor_both_kwargs_omitted_is_off()
    test_ctor_legacy_explicit_zero_without_policy_is_off()
    test_ctor_explicit_zero_with_policy_off_agrees()
    test_ctor_legacy_nonzero_with_enabling_policy_policy_wins()
    print("test_quic_server_config_policy: PASS")
