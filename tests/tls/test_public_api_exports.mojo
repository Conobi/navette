"""Public re-export ACs for `navette.tls`.

Covers two ACs from the public-API spec:
- public-re-exports-compile-with-trait-bound
- trait-names-accessible-without-submodule-path

Imports MUST come from `navette.tls`, not from
`navette.tls.early_data_filter` / `early_data_store`. The trait-bound
generic functions verify the trait names resolve in a USE context,
not just a re-export string match.
"""

from std.memory import Span

from navette.http.headers import Headers
from navette.tls import (
    EarlyDataPolicy,
    EarlyDataFilter,
    FilterDecision,
    IdempotentOnlyFilter,
    EarlyDataStore,
    EarlyDataStoreConfig,
    InMemoryEarlyDataStore,
    ReplayDecision,
    default_early_data_store_config,
)
from tests._test_util import assert_true


def takes_filter[F: EarlyDataFilter](f: F) raises -> Bool:
    """Generic function with a trait bound. If `EarlyDataFilter` isn't
    name-resolvable from `navette.tls`, the function fails to compile
    — that compile failure IS the AC verification."""
    var d = f.should_accept_for_0rtt(String("GET"), String(""), Headers())
    return d.is_accept()


def takes_store[S: EarlyDataStore](mut s: S) raises -> Bool:
    """Same pattern for the store trait — verifies `EarlyDataStore`
    is a usable bound from the public surface. Takes `mut s` (borrow)
    rather than `var s` (own) because `EarlyDataStore` is not declared
    `ImplicitlyDestructible`; consuming the store inside a generic
    function would leave Mojo 1.0.0b1 with no way to drop it."""
    var auth = List[UInt8]()
    for _ in range(32):
        auth.append(UInt8(0x42))
    var decision = s.check_and_record(Span(auth), UInt64(1_000))
    return decision.is_accept()


def test_filter_trait_bound_resolves() raises:
    """AC public-re-exports-compile-with-trait-bound for EarlyDataFilter."""
    assert_true(takes_filter(IdempotentOnlyFilter()),
                String("IdempotentOnlyFilter must accept GET"))
    print("  test_filter_trait_bound_resolves: PASS")


def test_store_trait_bound_resolves() raises:
    """AC public-re-exports-compile-with-trait-bound for EarlyDataStore."""
    var store = InMemoryEarlyDataStore()
    assert_true(takes_store(store),
                String("InMemoryEarlyDataStore must accept a fresh authenticator"))
    _ = store._config  # extend lifetime past the FFI-free generic call.
    print("  test_store_trait_bound_resolves: PASS")


def test_policy_imported_from_navette_tls() raises:
    """AC trait-names-accessible-without-submodule-path for EarlyDataPolicy."""
    var p = EarlyDataPolicy.idempotent_only()
    assert_true(p.is_enabled(), String("EarlyDataPolicy imported from navette.tls works"))
    print("  test_policy_imported_from_navette_tls: PASS")


def test_decision_types_imported() raises:
    """FilterDecision + ReplayDecision must be importable from
    `navette.tls` for downstream code that needs to express the
    decision enums in its own signatures."""
    var fd = FilterDecision.accept()
    var rd = ReplayDecision.accept()
    assert_true(fd.is_accept(), String("FilterDecision import works"))
    assert_true(rd.is_accept(), String("ReplayDecision import works"))
    print("  test_decision_types_imported: PASS")


def test_default_config_factory_imported() raises:
    """The `default_early_data_store_config` free function must be
    importable from `navette.tls` so callers can build a `Tuned`
    policy by tweaking the default."""
    var cfg = default_early_data_store_config()
    cfg.validate()
    print("  test_default_config_factory_imported: PASS")


def main() raises:
    print("test_public_api_exports")
    test_filter_trait_bound_resolves()
    test_store_trait_bound_resolves()
    test_policy_imported_from_navette_tls()
    test_decision_types_imported()
    test_default_config_factory_imported()
    print("test_public_api_exports: PASS")
