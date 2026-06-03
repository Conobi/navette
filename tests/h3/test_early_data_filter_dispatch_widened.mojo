"""Widened-dispatch-helper tests.

Covers ACs:
  - dispatch-helper-takes-path-and-predicate-fn
  - dispatch-helper-predicate-takes-precedence
  - dispatch-helper-routes-to-correct-counter
  - dispatch-helper-injects-early-data-on-predicate-accept
  - predicate-fn-raise-is-fail-closed
  - zero-rtt-http-filter-user-raised-counter-routes-on-raise
"""

from std.collections import Optional
from std.memory import UnsafePointer

from navette.h3.early_data_filter_dispatch import (
    apply_early_data_filter,
    FilterDispatchOutcome,
)
from navette.http.headers import Headers
from navette.quic.profile import AcceptProfile
from navette.tls.early_data_filter import (
    EarlyDataPredicateFn,
    FilterDecision,
    IdempotentOnlyFilter,
)
from tests._test_util import assert_true, assert_equal_int


def accept_all_predicate(method: String, path: String, headers: Headers) raises -> FilterDecision:
    return FilterDecision.accept()


def reject_all_predicate(method: String, path: String, headers: Headers) raises -> FilterDecision:
    return FilterDecision.reject_425()


def raising_predicate(method: String, path: String, headers: Headers) raises -> FilterDecision:
    raise Error("simulated predicate raise")


def test_dispatch_predicate_path_accept() raises:
    """Predicate variant, accept-returning predicate: outcome=proceed;
    Early-Data:1 injected; accept counter +=1."""
    var prof = AcceptProfile()
    var prof_ptr = Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]](
        UnsafePointer(to=prof)
    )
    var headers = Headers()
    var filter_opt = Optional[UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]](None)
    var pred_opt = Optional[EarlyDataPredicateFn](accept_all_predicate)
    var outcome = apply_early_data_filter(
        String("POST"), String("/x"),
        True,
        filter_opt, pred_opt,
        headers,
        prof_ptr,
    )
    assert_true(outcome.should_proceed(), String("predicate accept must proceed"))
    assert_true(headers.get(String("early-data")) == "1", String("Early-Data:1 injected"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_accept), 1, String("accept+=1"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_user_raised), 0, String("user_raised unchanged"))
    _ = prof.zero_rtt_http_filter_reject_425
    print("  test_dispatch_predicate_path_accept: PASS")


def test_dispatch_predicate_path_reject() raises:
    """Predicate variant, reject-returning predicate: outcome=send_425;
    reject_425 counter +=1; user_raised counter unchanged."""
    var prof = AcceptProfile()
    var prof_ptr = Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]](
        UnsafePointer(to=prof)
    )
    var headers = Headers()
    var filter_opt = Optional[UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]](None)
    var pred_opt = Optional[EarlyDataPredicateFn](reject_all_predicate)
    var outcome = apply_early_data_filter(
        String("POST"), String("/x"),
        True,
        filter_opt, pred_opt,
        headers,
        prof_ptr,
    )
    assert_true(outcome.should_send_425(), String("predicate reject must send_425"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_reject_425), 1, String("reject+=1"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_user_raised), 0, String("user_raised unchanged"))
    _ = prof.zero_rtt_http_filter_accept
    print("  test_dispatch_predicate_path_reject: PASS")


def test_dispatch_predicate_raises_fail_closed() raises:
    """AC predicate-fn-raise-is-fail-closed + zero-rtt-http-filter-
    user-raised-counter-routes-on-raise. Raising predicate: outcome=
    send_425; user_raised counter +=1; Early-Data:1 NOT injected."""
    var prof = AcceptProfile()
    var prof_ptr = Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]](
        UnsafePointer(to=prof)
    )
    var headers = Headers()
    var filter_opt = Optional[UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]](None)
    var pred_opt = Optional[EarlyDataPredicateFn](raising_predicate)
    var outcome = apply_early_data_filter(
        String("POST"), String("/x"),
        True,
        filter_opt, pred_opt,
        headers,
        prof_ptr,
    )
    assert_true(outcome.should_send_425(), String("raising predicate must send_425"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_user_raised), 1, String("user_raised+=1"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_accept), 0, String("accept unchanged"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_reject_425), 0, String("reject unchanged"))
    assert_true(not headers.has(String("early-data")), String("Early-Data NOT injected on raise"))
    print("  test_dispatch_predicate_raises_fail_closed: PASS")


def test_dispatch_filter_path_unchanged() raises:
    """Filter-only path: predicate_fn=None, filter_ptr=Some. Behaviour
    matches the legacy dispatch shape."""
    var prof = AcceptProfile()
    var prof_ptr = Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]](
        UnsafePointer(to=prof)
    )
    var headers = Headers()
    var f = IdempotentOnlyFilter()
    var filter_opt = Optional[UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]](
        UnsafePointer(to=f)
    )
    var pred_opt = Optional[EarlyDataPredicateFn](None)
    var outcome = apply_early_data_filter(
        String("GET"), String("/x"),
        True,
        filter_opt, pred_opt,
        headers,
        prof_ptr,
    )
    assert_true(outcome.should_proceed(), String("filter GET must accept"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_accept), 1, String("accept+=1"))
    _ = f
    print("  test_dispatch_filter_path_unchanged: PASS")


def test_dispatch_both_none_fail_closed() raises:
    """is_zero_rtt=True with both filter_ptr=None and predicate_fn=None:
    misconfig_fail_closed."""
    var prof = AcceptProfile()
    var prof_ptr = Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]](
        UnsafePointer(to=prof)
    )
    var headers = Headers()
    var filter_opt = Optional[UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]](None)
    var pred_opt = Optional[EarlyDataPredicateFn](None)
    var outcome = apply_early_data_filter(
        String("GET"), String("/x"),
        True,
        filter_opt, pred_opt,
        headers,
        prof_ptr,
    )
    assert_true(outcome.should_send_425(), String("both-None must send_425"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_misconfig_fail_closed), 1, String("misconfig+=1"))
    print("  test_dispatch_both_none_fail_closed: PASS")


def test_dispatch_1rtt_bypass() raises:
    """is_zero_rtt=False: helper short-circuits to proceed; bumps
    1rtt_bypassed regardless of predicate / filter presence."""
    var prof = AcceptProfile()
    var prof_ptr = Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]](
        UnsafePointer(to=prof)
    )
    var headers = Headers()
    var filter_opt = Optional[UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]](None)
    var pred_opt = Optional[EarlyDataPredicateFn](accept_all_predicate)
    var outcome = apply_early_data_filter(
        String("POST"), String("/x"),
        False,
        filter_opt, pred_opt,
        headers,
        prof_ptr,
    )
    assert_true(outcome.should_proceed(), String("1-RTT must proceed"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_1rtt_bypassed), 1, String("1rtt+=1"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_accept), 0, String("accept untouched on 1-RTT"))
    print("  test_dispatch_1rtt_bypass: PASS")


def test_dispatch_predicate_takes_precedence_when_both_some() raises:
    """AC dispatch-helper-predicate-takes-precedence: defensive test.
    Production §3.4 invariant guarantees mutual exclusion; this test
    asserts that if both ever appear, the predicate wins (the filter
    pointer is never dereferenced)."""
    var prof = AcceptProfile()
    var prof_ptr = Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]](
        UnsafePointer(to=prof)
    )
    var headers = Headers()
    var f = IdempotentOnlyFilter()
    var filter_opt = Optional[UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]](
        UnsafePointer(to=f)
    )
    # Predicate accepts POST (a method IdempotentOnlyFilter would reject)
    # — outcome must be proceed (predicate wins) AND accept counter +=1.
    var pred_opt = Optional[EarlyDataPredicateFn](accept_all_predicate)
    var outcome = apply_early_data_filter(
        String("POST"), String("/x"),
        True,
        filter_opt, pred_opt,
        headers,
        prof_ptr,
    )
    assert_true(outcome.should_proceed(), String("predicate wins on POST"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_accept), 1, String("accept+=1 from predicate"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_reject_425), 0, String("reject untouched"))
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
