"""`QuicServerConfig` Predicate-variant tests.

Covers:
  - the Predicate variant installs the default store
  - the policy ctor kwarg stays behaviourally stable when extended with
    the Predicate variant
"""

from std.memory import Span

from navette.http.headers import Headers
from navette.tls.config import QuicServerConfig
from navette.tls.early_data_filter import FilterDecision
from navette.tls.early_data_policy import EarlyDataPolicy
from navette.tls.lib import TlsBackend
from tests._test_util import assert_true, load_test_cert


def my_test_config_predicate(method: String, path: String, headers: Headers) raises -> FilterDecision:
    return FilterDecision.accept()


def test_ctor_with_policy_predicate() raises:
    """AC predicate-variant-default-store-installed: a Predicate-built
    config has store=Some(default) and predicate_fn=Some; filter is
    None (mutual exclusion with the struct filter path)."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        policy=EarlyDataPolicy.predicate(my_test_config_predicate),
    )
    assert_true(
        cfg.max_early_data() == UInt32(0xFFFFFFFF),
        String("policy=predicate must produce max_early_data=u32::MAX"),
    )
    assert_true(
        cfg._early_data_store is not None,
        String("Predicate must install default store"),
    )
    assert_true(
        cfg._early_data_filter is None,
        String("Predicate must NOT install IdempotentOnlyFilter"),
    )
    assert_true(
        cfg._early_data_predicate_fn is not None,
        String("Predicate must populate predicate-fn slot"),
    )
    _ = cfg._handle
    print("  test_ctor_with_policy_predicate: PASS")


def test_ctor_with_policy_off_predicate_fn_none() raises:
    """A non-Predicate policy leaves _early_data_predicate_fn None."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        policy=EarlyDataPolicy.off(),
    )
    assert_true(
        cfg._early_data_predicate_fn is None,
        String("Off must leave predicate-fn None"),
    )
    _ = cfg._handle
    print("  test_ctor_with_policy_off_predicate_fn_none: PASS")


def test_ctor_with_policy_idempotent_only_predicate_fn_none() raises:
    """IdempotentOnly leaves predicate-fn None; filter is Some."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        policy=EarlyDataPolicy.idempotent_only(),
    )
    assert_true(
        cfg._early_data_predicate_fn is None,
        String("IdempotentOnly must leave predicate-fn None"),
    )
    assert_true(
        cfg._early_data_filter is not None,
        String("IdempotentOnly must populate filter slot"),
    )
    _ = cfg._handle
    print("  test_ctor_with_policy_idempotent_only_predicate_fn_none: PASS")


def test_ctor_legacy_max_early_data_predicate_fn_none() raises:
    """Legacy `max_early_data > 0` without `policy` kwarg: predicate-fn
    None. Backward-compat preserved."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var tls = TlsBackend()
    var cfg = QuicServerConfig(
        tls.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    assert_true(
        cfg._early_data_predicate_fn is None,
        String("Legacy max_early_data must leave predicate-fn None"),
    )
    _ = cfg._handle
    print("  test_ctor_legacy_max_early_data_predicate_fn_none: PASS")


def main() raises:
    print("test_quic_server_config_predicate")
    test_ctor_with_policy_predicate()
    test_ctor_with_policy_off_predicate_fn_none()
    test_ctor_with_policy_idempotent_only_predicate_fn_none()
    test_ctor_legacy_max_early_data_predicate_fn_none()
    print("test_quic_server_config_predicate: PASS")
