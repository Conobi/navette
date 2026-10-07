"""Widened-dispatch-helper tests.

Covers ACs:
  - dispatch-helper-takes-path-and-predicate-fn
  - dispatch-helper-predicate-takes-precedence
  - dispatch-helper-injects-early-data-on-predicate-accept
  - predicate-fn-raise-is-fail-closed
"""

from std.collections import Optional
from std.memory import Pointer

from navette.h3.early_data_filter_dispatch import (
    apply_early_data_filter,
    FilterDispatchOutcome,
)
from navette.http.headers import Headers
from navette.tls.early_data_filter import (
    EarlyDataPredicateFn,
    FilterDecision,
    IdempotentOnlyFilter,
)
from tests._test_util import assert_true


def accept_all_predicate(method: String, path: String, headers: Headers) raises -> FilterDecision:
    return FilterDecision.accept()


def reject_all_predicate(method: String, path: String, headers: Headers) raises -> FilterDecision:
    return FilterDecision.reject_425()


def raising_predicate(method: String, path: String, headers: Headers) raises -> FilterDecision:
    raise Error("simulated predicate raise")


def test_dispatch_predicate_path_accept() raises:
    """Predicate variant, accept-returning predicate: outcome=proceed;
    Early-Data:1 injected."""
    var headers = Headers()
    var filter_opt = Optional[Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]](None)
    var pred_opt = Optional[EarlyDataPredicateFn](accept_all_predicate)
    var outcome = apply_early_data_filter(
        String("POST"), String("/x"),
        True,
        filter_opt, pred_opt,
        headers,
    )
    assert_true(outcome.should_proceed(), String("predicate accept must proceed"))
    assert_true(headers.get(String("early-data")) == "1", String("Early-Data:1 injected"))
    print("  test_dispatch_predicate_path_accept: PASS")


def test_dispatch_predicate_path_reject() raises:
    """Predicate variant, reject-returning predicate: outcome=send_425;
    Early-Data not injected."""
    var headers = Headers()
    var filter_opt = Optional[Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]](None)
    var pred_opt = Optional[EarlyDataPredicateFn](reject_all_predicate)
    var outcome = apply_early_data_filter(
        String("POST"), String("/x"),
        True,
        filter_opt, pred_opt,
        headers,
    )
    assert_true(outcome.should_send_425(), String("predicate reject must send_425"))
    assert_true(not headers.has(String("early-data")), String("Early-Data NOT injected"))
    print("  test_dispatch_predicate_path_reject: PASS")


def test_dispatch_predicate_raises_fail_closed() raises:
    """AC predicate-fn-raise-is-fail-closed. Raising predicate:
    outcome=send_425; Early-Data:1 NOT injected."""
    var headers = Headers()
    var filter_opt = Optional[Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]](None)
    var pred_opt = Optional[EarlyDataPredicateFn](raising_predicate)
    var outcome = apply_early_data_filter(
        String("POST"), String("/x"),
        True,
        filter_opt, pred_opt,
        headers,
    )
    assert_true(outcome.should_send_425(), String("raising predicate must send_425"))
    assert_true(not headers.has(String("early-data")), String("Early-Data NOT injected on raise"))
    print("  test_dispatch_predicate_raises_fail_closed: PASS")


def test_dispatch_filter_path_unchanged() raises:
    """Filter-only path: predicate_fn=None, filter_ptr=Some. Behaviour
    matches the legacy dispatch shape."""
    var headers = Headers()
    var f = IdempotentOnlyFilter()
    var filter_opt = Optional[Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]](
        Pointer(to=f).unsafe_origin_cast[
            MutUntrackedOrigin
        ]()
    )
    var pred_opt = Optional[EarlyDataPredicateFn](None)
    var outcome = apply_early_data_filter(
        String("GET"), String("/x"),
        True,
        filter_opt, pred_opt,
        headers,
    )
    assert_true(outcome.should_proceed(), String("filter GET must accept"))
    assert_true(headers.get(String("early-data")) == "1", String("Early-Data:1 injected"))
    _ = f
    print("  test_dispatch_filter_path_unchanged: PASS")


def test_dispatch_both_none_fail_closed() raises:
    """is_zero_rtt=True with both filter_ptr=None and predicate_fn=None:
    fail closed with send_425."""
    var headers = Headers()
    var filter_opt = Optional[Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]](None)
    var pred_opt = Optional[EarlyDataPredicateFn](None)
    var outcome = apply_early_data_filter(
        String("GET"), String("/x"),
        True,
        filter_opt, pred_opt,
        headers,
    )
    assert_true(outcome.should_send_425(), String("both-None must send_425"))
    assert_true(not headers.has(String("early-data")), String("Early-Data NOT injected"))
    print("  test_dispatch_both_none_fail_closed: PASS")


def test_dispatch_1rtt_bypass() raises:
    """is_zero_rtt=False: helper short-circuits to proceed without
    consulting the predicate or injecting Early-Data."""
    var headers = Headers()
    var filter_opt = Optional[Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]](None)
    var pred_opt = Optional[EarlyDataPredicateFn](accept_all_predicate)
    var outcome = apply_early_data_filter(
        String("POST"), String("/x"),
        False,
        filter_opt, pred_opt,
        headers,
    )
    assert_true(outcome.should_proceed(), String("1-RTT must proceed"))
    assert_true(not headers.has(String("early-data")), String("Early-Data NOT injected on 1-RTT"))
    print("  test_dispatch_1rtt_bypass: PASS")


def test_dispatch_predicate_takes_precedence_when_both_some() raises:
    """AC dispatch-helper-predicate-takes-precedence: defensive test.
    Production §3.4 invariant guarantees mutual exclusion; this test
    asserts that if both ever appear, the predicate wins (the filter
    pointer is never dereferenced)."""
    var headers = Headers()
    var f = IdempotentOnlyFilter()
    var filter_opt = Optional[Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]](
        Pointer(to=f).unsafe_origin_cast[
            MutUntrackedOrigin
        ]()
    )
    # Predicate accepts POST (a method IdempotentOnlyFilter would reject)
    # — outcome must be proceed (predicate wins) with Early-Data injected.
    var pred_opt = Optional[EarlyDataPredicateFn](accept_all_predicate)
    var outcome = apply_early_data_filter(
        String("POST"), String("/x"),
        True,
        filter_opt, pred_opt,
        headers,
    )
    assert_true(outcome.should_proceed(), String("predicate wins on POST"))
    assert_true(headers.get(String("early-data")) == "1", String("Early-Data:1 injected by predicate"))
    _ = f
    print("  test_dispatch_predicate_takes_precedence_when_both_some: PASS")


def main() raises:
    print("test_early_data_filter_dispatch_widened")
    test_dispatch_predicate_path_accept()
    test_dispatch_predicate_path_reject()
    test_dispatch_predicate_raises_fail_closed()
    test_dispatch_filter_path_unchanged()
    test_dispatch_both_none_fail_closed()
    test_dispatch_1rtt_bypass()
    test_dispatch_predicate_takes_precedence_when_both_some()
    print("test_early_data_filter_dispatch_widened: PASS")
