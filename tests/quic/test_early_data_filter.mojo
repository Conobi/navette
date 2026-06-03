"""Pure-core unit tests for `navette.tls.early_data_filter`."""

from navette.tls.early_data_filter import (
    FilterDecision, IdempotentOnlyFilter,
)
from tests._test_util import assert_true, assert_false, assert_equal_int


def test_filter_decision_accept_round_trip() raises:
    """Trait surface: accept().is_accept() is True; is_reject() is False."""
    var d = FilterDecision.accept()
    assert_true(d.is_accept(), String("accept() should be accept"))
    assert_false(d.is_reject(), String("accept() should not be reject"))
    print("  test_filter_decision_accept_round_trip: PASS")


def test_filter_decision_reject_round_trip() raises:
    """Trait surface: reject_425().is_reject() is True; is_accept() is False."""
    var d = FilterDecision.reject_425()
    assert_true(d.is_reject(), String("reject_425() should be reject"))
    assert_false(d.is_accept(), String("reject_425() should not be accept"))
    print("  test_filter_decision_reject_round_trip: PASS")


def test_filter_decision_equatable() raises:
    """Equality is by variant: accept == accept, reject == reject, accept != reject."""
    assert_true(
        FilterDecision.accept() == FilterDecision.accept(),
        String("accept == accept"),
    )
    assert_true(
        FilterDecision.reject_425() == FilterDecision.reject_425(),
        String("reject == reject"),
    )
    assert_true(
        FilterDecision.accept() != FilterDecision.reject_425(),
        String("accept != reject"),
    )
    print("  test_filter_decision_equatable: PASS")


def test_idempotent_only_accepts_get() raises:
    """AC idempotent-only-accepts-get."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("GET")).is_accept(),
        String("GET should accept"),
    )
    print("  test_idempotent_only_accepts_get: PASS")


def test_idempotent_only_accepts_head() raises:
    """AC idempotent-only-accepts-head."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("HEAD")).is_accept(),
        String("HEAD should accept"),
    )
    print("  test_idempotent_only_accepts_head: PASS")


def test_idempotent_only_accepts_options() raises:
    """AC idempotent-only-accepts-options."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("OPTIONS")).is_accept(),
        String("OPTIONS should accept"),
    )
    print("  test_idempotent_only_accepts_options: PASS")


def test_idempotent_only_rejects_post() raises:
    """AC idempotent-only-rejects-post."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("POST")).is_reject(),
        String("POST should reject"),
    )
    print("  test_idempotent_only_rejects_post: PASS")


def test_idempotent_only_rejects_put() raises:
    """AC idempotent-only-rejects-put."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("PUT")).is_reject(),
        String("PUT should reject"),
    )
    print("  test_idempotent_only_rejects_put: PASS")


def test_idempotent_only_rejects_delete() raises:
    """AC idempotent-only-rejects-delete."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("DELETE")).is_reject(),
        String("DELETE should reject"),
    )
    print("  test_idempotent_only_rejects_delete: PASS")


def test_idempotent_only_rejects_patch() raises:
    """AC idempotent-only-rejects-patch."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("PATCH")).is_reject(),
        String("PATCH should reject"),
    )
    print("  test_idempotent_only_rejects_patch: PASS")


def test_idempotent_only_rejects_connect() raises:
    """AC idempotent-only-rejects-connect."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("CONNECT")).is_reject(),
        String("CONNECT should reject"),
    )
    print("  test_idempotent_only_rejects_connect: PASS")


def test_idempotent_only_rejects_trace() raises:
    """AC idempotent-only-rejects-trace."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("TRACE")).is_reject(),
        String("TRACE should reject"),
    )
    print("  test_idempotent_only_rejects_trace: PASS")


def test_idempotent_only_rejects_unknown_extension_method() raises:
    """AC idempotent-only-rejects-unknown-extension-method.
    PROPFIND, MOVE, FROBNICATE all reject."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("PROPFIND")).is_reject(),
        String("PROPFIND should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("MOVE")).is_reject(),
        String("MOVE should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("FROBNICATE")).is_reject(),
        String("FROBNICATE should reject"),
    )
    print("  test_idempotent_only_rejects_unknown_extension_method: PASS")


def test_idempotent_only_rejects_empty_method() raises:
    """AC idempotent-only-rejects-empty-method."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("")).is_reject(),
        String("empty method should reject (fail-closed)"),
    )
    print("  test_idempotent_only_rejects_empty_method: PASS")


def test_idempotent_only_case_sensitive() raises:
    """AC idempotent-only-case-sensitive. Lowercase variants reject."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("get")).is_reject(),
        String("lowercase 'get' should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("Get")).is_reject(),
        String("mixed-case 'Get' should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("head")).is_reject(),
        String("lowercase 'head' should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("options")).is_reject(),
        String("lowercase 'options' should reject"),
    )
    print("  test_idempotent_only_case_sensitive: PASS")


def test_idempotent_only_rejects_whitespace_padded() raises:
    """AC idempotent-only-rejects-whitespace-padded. Tokens are exact bytes."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String(" GET")).is_reject(),
        String("leading-space 'GET' should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("GET ")).is_reject(),
        String("trailing-space 'GET' should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("\tGET")).is_reject(),
        String("tab-prefixed 'GET' should reject"),
    )
    print("  test_idempotent_only_rejects_whitespace_padded: PASS")


def main() raises:
    """Driver for `scripts/run_tests.sh`: each test must be invoked here."""
    test_filter_decision_accept_round_trip()
    test_filter_decision_reject_round_trip()
    test_filter_decision_equatable()
    test_idempotent_only_accepts_get()
    test_idempotent_only_accepts_head()
    test_idempotent_only_accepts_options()
    test_idempotent_only_rejects_post()
    test_idempotent_only_rejects_put()
    test_idempotent_only_rejects_delete()
    test_idempotent_only_rejects_patch()
    test_idempotent_only_rejects_connect()
    test_idempotent_only_rejects_trace()
    test_idempotent_only_rejects_unknown_extension_method()
    test_idempotent_only_rejects_empty_method()
    test_idempotent_only_case_sensitive()
    test_idempotent_only_rejects_whitespace_padded()
