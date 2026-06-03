"""Widened-trait + `IdempotentOnlyFilter` pass-through tests.

Covers ACs from the trait-widening family:
  - filter-trait-takes-method-path-headers
  - idempotent-only-filter-still-method-only
  - idempotent-only-unchanged-with-non-trivial-args
Plus a stub raising filter exercising the new fail-closed signature shape.
"""

from navette.http.headers import Headers
from navette.tls.early_data_filter import (
    EarlyDataFilter,
    FilterDecision,
    IdempotentOnlyFilter,
)
from tests._test_util import assert_true, assert_false


struct AlwaysRaisesFilter(EarlyDataFilter):
    """Stub filter that raises unconditionally — exercises the new
    `raises` annotation on the trait method."""

    def __init__(out self): pass
    def __init__(out self, *, other: Self): pass
    def __init__(out self, *, deinit take: Self): pass

    def should_accept_for_0rtt(
        self,
        method: String,
        _path: String,
        _headers: Headers,
    ) raises -> FilterDecision:
        raise Error("always-raises-stub")


def test_widened_trait_signature_compiles() raises:
    """AC filter-trait-takes-method-path-headers: trait-bound use of
    the widened signature compiles and runs."""
    var f = IdempotentOnlyFilter()
    var d = f.should_accept_for_0rtt(String("GET"), String("/x"), Headers())
    assert_true(d.is_accept(), String("GET widened-signature accept"))
    print("  test_widened_trait_signature_compiles: PASS")


def test_idempotent_only_ignores_path() raises:
    """AC idempotent-only-filter-still-method-only: path argument does
    NOT change the decision for any safe or unsafe method."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("GET"), String("/some/long/path"), Headers()).is_accept(),
        String("GET with non-empty path still accepts"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("HEAD"), String("/a/b/c"), Headers()).is_accept(),
        String("HEAD with non-empty path still accepts"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("OPTIONS"), String("/"), Headers()).is_accept(),
        String("OPTIONS with non-empty path still accepts"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("POST"), String("/orders"), Headers()).is_reject(),
        String("POST with non-empty path still rejects"),
    )
    print("  test_idempotent_only_ignores_path: PASS")


def test_idempotent_only_ignores_headers() raises:
    """AC idempotent-only-filter-still-method-only: headers argument
    does NOT change the decision for any safe or unsafe method."""
    var f = IdempotentOnlyFilter()
    var h = Headers()
    h.add(String("authorization"), String("Bearer x"))
    h.add(String("idempotency-key"), String("abc"))
    assert_true(
        f.should_accept_for_0rtt(String("GET"), String(""), h).is_accept(),
        String("GET with auth+idempotency headers still accepts"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("POST"), String(""), h).is_reject(),
        String("POST with idempotency header still rejects (method-only policy)"),
    )
    print("  test_idempotent_only_ignores_headers: PASS")


def test_idempotent_only_unchanged_with_idempotency_key() raises:
    """AC idempotent-only-unchanged-with-non-trivial-args: presence of
    Idempotency-Key does NOT promote POST to accept (filter is method-
    only by design; predicates do the promotion)."""
    var f = IdempotentOnlyFilter()
    var h = Headers()
    h.add(String("idempotency-key"), String("stripe-key-123"))
    var d = f.should_accept_for_0rtt(String("POST"), String("/charges"), h)
    assert_true(d.is_reject(), String("POST+Idempotency-Key still rejects under IdempotentOnly"))
    print("  test_idempotent_only_unchanged_with_idempotency_key: PASS")


def test_widened_trait_raises_propagates() raises:
    """The widened signature gains `raises`. A stub impl that raises
    surfaces the error to the caller. The dispatch helper's fail-closed
    branch consumes this; here we assert the raise actually escapes a
    non-catching call site."""
    var f = AlwaysRaisesFilter()
    var caught = False
    try:
        _ = f.should_accept_for_0rtt(String("GET"), String("/x"), Headers())
    except:
        caught = True
    assert_true(caught, String("AlwaysRaisesFilter must raise"))
    print("  test_widened_trait_raises_propagates: PASS")


def main() raises:
    print("test_early_data_filter_widening")
    test_widened_trait_signature_compiles()
    test_idempotent_only_ignores_path()
    test_idempotent_only_ignores_headers()
    test_idempotent_only_unchanged_with_idempotency_key()
    test_widened_trait_raises_propagates()
    print("test_early_data_filter_widening: PASS")
