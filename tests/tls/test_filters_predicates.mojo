"""Reference-predicate decision-matrix tests.

Covers ACs from the reference-predicate family:
  - idempotency-key-accepts-safe-methods-without-key
  - idempotency-key-accepts-state-methods-with-key
  - idempotency-key-rejects-state-methods-without-key
  - idempotency-key-rejects-empty-key-value
  - idempotency-key-case-insensitive-header-lookup
  - idempotency-key-rejects-non-state-methods-without-key
  - unauth-only-accepts-bare-safe-methods
  - unauth-only-rejects-with-authorization
  - unauth-only-rejects-with-cookie
  - unauth-only-rejects-unsafe-method-regardless
"""

from navette.http.headers import Headers
from navette.tls.filters import (
    idempotency_key_predicate,
    unauthenticated_only_predicate,
)
from tests._test_util import assert_true


def _headers_with(name: String, value: String) raises -> Headers:
    var h = Headers()
    h.add(name, value)
    return h^


def test_idempotency_key_accepts_get() raises:
    var d = idempotency_key_predicate(String("GET"), String("/x"), Headers())
    assert_true(d.is_accept(), String("GET without key should accept"))
    print("  test_idempotency_key_accepts_get: PASS")


def test_idempotency_key_accepts_head() raises:
    var d = idempotency_key_predicate(String("HEAD"), String("/x"), Headers())
    assert_true(d.is_accept(), String("HEAD without key should accept"))
    print("  test_idempotency_key_accepts_head: PASS")


def test_idempotency_key_accepts_options() raises:
    var d = idempotency_key_predicate(String("OPTIONS"), String("/x"), Headers())
    assert_true(d.is_accept(), String("OPTIONS without key should accept"))
    print("  test_idempotency_key_accepts_options: PASS")


def test_idempotency_key_accepts_post_with_key() raises:
    var h = _headers_with(String("idempotency-key"), String("abc-123"))
    var d = idempotency_key_predicate(String("POST"), String("/orders"), h)
    assert_true(d.is_accept(), String("POST+Idempotency-Key should accept"))
    print("  test_idempotency_key_accepts_post_with_key: PASS")


def test_idempotency_key_accepts_put_with_key() raises:
    var h = _headers_with(String("idempotency-key"), String("k"))
    var d = idempotency_key_predicate(String("PUT"), String("/x"), h)
    assert_true(d.is_accept(), String("PUT+Idempotency-Key should accept"))
    print("  test_idempotency_key_accepts_put_with_key: PASS")


def test_idempotency_key_accepts_patch_and_delete_with_key() raises:
    var h = _headers_with(String("idempotency-key"), String("k"))
    assert_true(
        idempotency_key_predicate(String("PATCH"), String("/x"), h).is_accept(),
        String("PATCH+key accepts"),
    )
    var h2 = _headers_with(String("idempotency-key"), String("k"))
    assert_true(
        idempotency_key_predicate(String("DELETE"), String("/x"), h2).is_accept(),
        String("DELETE+key accepts"),
    )
    print("  test_idempotency_key_accepts_patch_and_delete_with_key: PASS")


def test_idempotency_key_rejects_post_without_key() raises:
    var d = idempotency_key_predicate(String("POST"), String("/x"), Headers())
    assert_true(d.is_reject(), String("POST without key should reject"))
    print("  test_idempotency_key_rejects_post_without_key: PASS")


def test_idempotency_key_rejects_state_methods_without_key() raises:
    for m in [String("POST"), String("PUT"), String("PATCH"), String("DELETE")]:
        var d = idempotency_key_predicate(m, String("/x"), Headers())
        assert_true(d.is_reject(), m + String(" without key should reject"))
    print("  test_idempotency_key_rejects_state_methods_without_key: PASS")


def test_idempotency_key_rejects_empty_key() raises:
    var h = _headers_with(String("idempotency-key"), String(""))
    var d = idempotency_key_predicate(String("POST"), String("/x"), h)
    assert_true(d.is_reject(), String("Empty key should not satisfy non-empty requirement"))
    print("  test_idempotency_key_rejects_empty_key: PASS")


def test_idempotency_key_case_insensitive_lookup() raises:
    """Headers stores names lowercased on insert; the predicate's
    lowercase lookup matches regardless of insertion case."""
    var h = _headers_with(String("Idempotency-Key"), String("abc"))
    var d = idempotency_key_predicate(String("POST"), String("/x"), h)
    assert_true(d.is_accept(), String("Mixed-case header should still match"))
    print("  test_idempotency_key_case_insensitive_lookup: PASS")


def test_idempotency_key_rejects_unknown_method() raises:
    """CONNECT, TRACE, and any method outside the known set should
    reject regardless of header presence."""
    var h = _headers_with(String("idempotency-key"), String("abc"))
    assert_true(
        idempotency_key_predicate(String("CONNECT"), String("/x"), h).is_reject(),
        String("CONNECT+key should still reject"),
    )
    var h2 = _headers_with(String("idempotency-key"), String("abc"))
    assert_true(
        idempotency_key_predicate(String("TRACE"), String("/x"), h2).is_reject(),
        String("TRACE+key should still reject"),
    )
    assert_true(
        idempotency_key_predicate(String("FROBNICATE"), String("/x"), Headers()).is_reject(),
        String("Unknown method should reject"),
    )
    print("  test_idempotency_key_rejects_unknown_method: PASS")


def test_idempotency_key_accepts_query() raises:
    """QUERY is accepted without an idempotency key (safe-method baseline)."""
    var d = idempotency_key_predicate(String("QUERY"), String("/search"), Headers())
    assert_true(d.is_accept(), String("QUERY without key should accept"))
    print("  test_idempotency_key_accepts_query: PASS")


def test_unauth_only_accepts_bare_safe_methods() raises:
    for m in [String("GET"), String("HEAD"), String("OPTIONS")]:
        var d = unauthenticated_only_predicate(m, String("/x"), Headers())
        assert_true(d.is_accept(), m + String(" without auth should accept"))
    print("  test_unauth_only_accepts_bare_safe_methods: PASS")


def test_unauth_only_rejects_with_authorization() raises:
    var h = _headers_with(String("authorization"), String("Bearer x"))
    var d = unauthenticated_only_predicate(String("GET"), String("/x"), h)
    assert_true(d.is_reject(), String("GET+Authorization should reject"))
    print("  test_unauth_only_rejects_with_authorization: PASS")


def test_unauth_only_rejects_with_cookie() raises:
    var h = _headers_with(String("cookie"), String("session=abc"))
    var d = unauthenticated_only_predicate(String("GET"), String("/x"), h)
    assert_true(d.is_reject(), String("GET+Cookie should reject"))
    print("  test_unauth_only_rejects_with_cookie: PASS")


def test_unauth_only_accepts_query_bare() raises:
    """QUERY without auth headers is accepted (safe-method baseline)."""
    var d = unauthenticated_only_predicate(String("QUERY"), String("/search"), Headers())
    assert_true(d.is_accept(), String("QUERY without auth should accept"))
    print("  test_unauth_only_accepts_query_bare: PASS")


def test_unauth_only_rejects_query_with_cookie() raises:
    """QUERY with Cookie header is rejected (auth-gating still applies)."""
    var h = _headers_with(String("cookie"), String("session=abc"))
    var d = unauthenticated_only_predicate(String("QUERY"), String("/search"), h)
    assert_true(d.is_reject(), String("QUERY+Cookie should reject"))
    print("  test_unauth_only_rejects_query_with_cookie: PASS")


def test_unauth_only_rejects_unsafe_method() raises:
    var d = unauthenticated_only_predicate(String("POST"), String("/x"), Headers())
    assert_true(d.is_reject(), String("POST should reject regardless of headers"))
    print("  test_unauth_only_rejects_unsafe_method: PASS")


def main() raises:
    print("test_filters_predicates")
    test_idempotency_key_accepts_get()
    test_idempotency_key_accepts_head()
    test_idempotency_key_accepts_options()
    test_idempotency_key_accepts_post_with_key()
    test_idempotency_key_accepts_put_with_key()
    test_idempotency_key_accepts_patch_and_delete_with_key()
    test_idempotency_key_rejects_post_without_key()
    test_idempotency_key_rejects_state_methods_without_key()
    test_idempotency_key_rejects_empty_key()
    test_idempotency_key_case_insensitive_lookup()
    test_idempotency_key_rejects_unknown_method()
    test_idempotency_key_accepts_query()
    test_unauth_only_accepts_bare_safe_methods()
    test_unauth_only_rejects_with_authorization()
    test_unauth_only_rejects_with_cookie()
    test_unauth_only_accepts_query_bare()
    test_unauth_only_rejects_query_with_cookie()
    test_unauth_only_rejects_unsafe_method()
    print("test_filters_predicates: PASS")
