"""Predicate-variant tests for `EarlyDataPolicy`.

Covers ACs:
  - predicate-variant-takes-fn-pointer
  - predicate-variant-mutually-exclusive
  - predicate-variant-is-enabled
  - predicate-variant-store-config-is-none
  - predicate-fn-lifetime-static
  - policy-copy-preserves-predicate-fn (also in test_early_data_policy)
"""

from navette.http.headers import Headers
from navette.tls.early_data_filter import FilterDecision
from navette.tls.early_data_policy import EarlyDataPolicy
from tests._test_util import assert_true, assert_false


def my_test_predicate(method: String, path: String, headers: Headers) raises -> FilterDecision:
    """Stub predicate at module scope (static lifetime). Returns
    accept for GET, reject_425 otherwise."""
    if method == "GET":
        return FilterDecision.accept()
    return FilterDecision.reject_425()


def test_predicate_factory_builds_predicate_variant() raises:
    """AC predicate-variant-takes-fn-pointer: factory builds a policy
    whose `predicate_fn()` accessor returns Some(fn) and whose direct
    call matches the input predicate's behaviour."""
    var p = EarlyDataPolicy.predicate(my_test_predicate)
    assert_true(p.is_predicate(), String("is_predicate must be True"))
    var fn_opt = p.predicate_fn()
    assert_true(fn_opt.__bool__(), String("predicate_fn() must be Some"))
    var via_policy = fn_opt.value()(String("GET"), String("/x"), Headers())
    var direct = my_test_predicate(String("GET"), String("/x"), Headers())
    assert_true(via_policy == direct, String("policy-stored fn must behave identically"))
    print("  test_predicate_factory_builds_predicate_variant: PASS")


def test_predicate_variant_mutually_exclusive() raises:
    """AC predicate-variant-mutually-exclusive: a Predicate-built policy
    has is_off/is_idempotent_only/is_tuned all False; conversely, each
    other variant has is_predicate == False."""
    var p = EarlyDataPolicy.predicate(my_test_predicate)
    assert_false(p.is_off(), String("Predicate is not Off"))
    assert_false(p.is_idempotent_only(), String("Predicate is not IdempotentOnly"))
    assert_false(p.is_tuned(), String("Predicate is not Tuned"))

    var off = EarlyDataPolicy.off()
    var io = EarlyDataPolicy.idempotent_only()
    assert_false(off.is_predicate(), String("Off is not Predicate"))
    assert_false(io.is_predicate(), String("IdempotentOnly is not Predicate"))
    print("  test_predicate_variant_mutually_exclusive: PASS")


def test_predicate_variant_is_enabled() raises:
    """AC predicate-variant-is-enabled: `is_enabled()` returns True for
    the Predicate variant (kind != KIND_OFF)."""
    var p = EarlyDataPolicy.predicate(my_test_predicate)
    assert_true(p.is_enabled(), String("Predicate must be enabled"))
    print("  test_predicate_variant_is_enabled: PASS")


def test_predicate_variant_store_config_is_none() raises:
    """AC predicate-variant-store-config-is-none: the Predicate variant
    uses the default store; `store_config()` returns None (distinct
    from Tuned, which returns Some)."""
    var p = EarlyDataPolicy.predicate(my_test_predicate)
    var sc = p.store_config()
    assert_false(sc.__bool__(), String("Predicate store_config must be None"))
    print("  test_predicate_variant_store_config_is_none: PASS")


def test_predicate_fn_lifetime_static() raises:
    """AC predicate-fn-lifetime-static: module-scope fn values survive
    a move + outlive their originating call stack."""
    var p = EarlyDataPolicy.predicate(my_test_predicate)
    var moved = p^
    var fn_opt = moved.predicate_fn()
    var d = fn_opt.value()(String("GET"), String("/x"), Headers())
    assert_true(d.is_accept(), String("post-move call must still work"))
    print("  test_predicate_fn_lifetime_static: PASS")


def test_predicate_factory_then_call_returns_reject_for_post() raises:
    """Smoke: factory + stored-fn call returns the predicate's actual
    decision for a non-matching method."""
    var p = EarlyDataPolicy.predicate(my_test_predicate)
    var d = p.predicate_fn().value()(String("POST"), String("/x"), Headers())
    assert_true(d.is_reject(), String("POST must reject through stored fn"))
    print("  test_predicate_factory_then_call_returns_reject_for_post: PASS")


def main() raises:
    print("test_early_data_policy_predicate")
    test_predicate_factory_builds_predicate_variant()
    test_predicate_variant_mutually_exclusive()
    test_predicate_variant_is_enabled()
    test_predicate_variant_store_config_is_none()
    test_predicate_fn_lifetime_static()
    test_predicate_factory_then_call_returns_reject_for_post()
    print("test_early_data_policy_predicate: PASS")
