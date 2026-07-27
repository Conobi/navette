"""Pure-core unit tests for `navette.tls.early_data_filter`."""

from navette.http.headers import Headers
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
        f.should_accept_for_0rtt(String("GET"), String(""), Headers()).is_accept(),
        String("GET should accept"),
    )
    print("  test_idempotent_only_accepts_get: PASS")


def test_idempotent_only_accepts_head() raises:
    """AC idempotent-only-accepts-head."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("HEAD"), String(""), Headers()).is_accept(),
        String("HEAD should accept"),
    )
    print("  test_idempotent_only_accepts_head: PASS")


def test_idempotent_only_accepts_options() raises:
    """AC idempotent-only-accepts-options."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("OPTIONS"), String(""), Headers()).is_accept(),
        String("OPTIONS should accept"),
    )
    print("  test_idempotent_only_accepts_options: PASS")


def test_idempotent_only_accepts_query() raises:
    """AC idempotent-only-accepts-query (RFC 10008)."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("QUERY"), String(""), Headers()).is_accept(),
        String("QUERY should accept"),
    )
    print("  test_idempotent_only_accepts_query: PASS")


def test_idempotent_only_rejects_post() raises:
    """AC idempotent-only-rejects-post."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("POST"), String(""), Headers()).is_reject(),
        String("POST should reject"),
    )
    print("  test_idempotent_only_rejects_post: PASS")


def test_idempotent_only_rejects_put() raises:
    """AC idempotent-only-rejects-put."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("PUT"), String(""), Headers()).is_reject(),
        String("PUT should reject"),
    )
    print("  test_idempotent_only_rejects_put: PASS")


def test_idempotent_only_rejects_delete() raises:
    """AC idempotent-only-rejects-delete."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("DELETE"), String(""), Headers()).is_reject(),
        String("DELETE should reject"),
    )
    print("  test_idempotent_only_rejects_delete: PASS")


def test_idempotent_only_rejects_patch() raises:
    """AC idempotent-only-rejects-patch."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("PATCH"), String(""), Headers()).is_reject(),
        String("PATCH should reject"),
    )
    print("  test_idempotent_only_rejects_patch: PASS")


def test_idempotent_only_rejects_connect() raises:
    """AC idempotent-only-rejects-connect."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("CONNECT"), String(""), Headers()).is_reject(),
        String("CONNECT should reject"),
    )
    print("  test_idempotent_only_rejects_connect: PASS")


def test_idempotent_only_rejects_trace() raises:
    """AC idempotent-only-rejects-trace."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("TRACE"), String(""), Headers()).is_reject(),
        String("TRACE should reject"),
    )
    print("  test_idempotent_only_rejects_trace: PASS")


def test_idempotent_only_rejects_unknown_extension_method() raises:
    """AC idempotent-only-rejects-unknown-extension-method.
    PROPFIND, MOVE, FROBNICATE all reject."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("PROPFIND"), String(""), Headers()).is_reject(),
        String("PROPFIND should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("MOVE"), String(""), Headers()).is_reject(),
        String("MOVE should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("FROBNICATE"), String(""), Headers()).is_reject(),
        String("FROBNICATE should reject"),
    )
    print("  test_idempotent_only_rejects_unknown_extension_method: PASS")


def test_idempotent_only_rejects_empty_method() raises:
    """AC idempotent-only-rejects-empty-method."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String(""), String(""), Headers()).is_reject(),
        String("empty method should reject (fail-closed)"),
    )
    print("  test_idempotent_only_rejects_empty_method: PASS")


def test_idempotent_only_case_sensitive() raises:
    """AC idempotent-only-case-sensitive. Lowercase variants reject."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("get"), String(""), Headers()).is_reject(),
        String("lowercase 'get' should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("Get"), String(""), Headers()).is_reject(),
        String("mixed-case 'Get' should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("head"), String(""), Headers()).is_reject(),
        String("lowercase 'head' should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("options"), String(""), Headers()).is_reject(),
        String("lowercase 'options' should reject"),
    )
    print("  test_idempotent_only_case_sensitive: PASS")


def test_idempotent_only_rejects_whitespace_padded() raises:
    """AC idempotent-only-rejects-whitespace-padded. Tokens are exact bytes."""
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String(" GET"), String(""), Headers()).is_reject(),
        String("leading-space 'GET' should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("GET "), String(""), Headers()).is_reject(),
        String("trailing-space 'GET' should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("\tGET"), String(""), Headers()).is_reject(),
        String("tab-prefixed 'GET' should reject"),
    )
    print("  test_idempotent_only_rejects_whitespace_padded: PASS")


def test_idempotent_only_rejects_embedded_nul() raises:
    """Method-string boundary edge case: embedded NUL.

    `"GET\\0"` is not bytewise-equal to `"GET"`, so the filter must
    reject. This closes the structured-property generator's blind spot
    for NUL bytes (the printable-ASCII random pool spans 0x20..0x7E and
    never produces NUL).
    """
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("GET\0"), String(""), Headers()).is_reject(),
        String("embedded-NUL 'GET\\0' should reject"),
    )
    print("  test_idempotent_only_rejects_embedded_nul: PASS")


def test_idempotent_only_rejects_non_ascii() raises:
    """Method-string boundary edge case: multi-byte UTF-8.

    Mojo `String` equality is byte-wise, so `"GÉT"` (UTF-8: 0x47 0xC3
    0x89 0x54) is not equal to `"GET"` (0x47 0x45 0x54). The filter
    must reject. Closes the structured-property generator's blind spot
    for high-bit bytes (>0x7E).
    """
    var f = IdempotentOnlyFilter()
    assert_true(
        f.should_accept_for_0rtt(String("GÉT"), String(""), Headers()).is_reject(),
        String("multi-byte UTF-8 'GÉT' should reject"),
    )
    assert_true(
        f.should_accept_for_0rtt(String("GETé"), String(""), Headers()).is_reject(),
        String("trailing multi-byte UTF-8 'GETé' should reject"),
    )
    print("  test_idempotent_only_rejects_non_ascii: PASS")


def _splitmix64(mut state: UInt64) -> UInt64:
    """SplitMix64 PRNG (Vigna 2014); deterministic given a seed.

    Mutates `state` in place; returns the next pseudo-random UInt64.
    The plus-and-mix structure makes each call O(1) with no allocations.
    """
    state = state + UInt64(0x9E3779B97F4A7C15)
    var z = state
    z = (z ^ (z >> 30)) * UInt64(0xBF58476D1CE4E5B9)
    z = (z ^ (z >> 27)) * UInt64(0x94D049BB133111EB)
    return z ^ (z >> 31)


def _draw_method(mut state: UInt64) -> String:
    """Draw one HTTP-method-shaped String for the property test.

    70% chance: draw from a 14-element fixed pool that exercises both
    accept paths (GET/HEAD/OPTIONS/QUERY) and reject paths (other RFC 9110
    methods, case variants, whitespace-padded, unknown extension).
    30% chance: generate a random 1-20 byte ASCII printable string so
    rare bytewise neighbours of accept tokens are reached.
    """
    var pool = List[String]()
    pool.append(String("GET"))
    pool.append(String("HEAD"))
    pool.append(String("OPTIONS"))
    pool.append(String("POST"))
    pool.append(String("PUT"))
    pool.append(String("DELETE"))
    pool.append(String("PATCH"))
    pool.append(String("CONNECT"))
    pool.append(String("TRACE"))
    pool.append(String("QUERY"))
    pool.append(String("get"))
    pool.append(String("Get"))
    pool.append(String("GET "))
    pool.append(String("FROBNICATE"))

    var r = _splitmix64(state)
    if (r % UInt64(100)) < UInt64(70):
        var idx = Int((_splitmix64(state)) % UInt64(14))
        return pool[idx]

    # Random 1-20 byte ASCII printable string (bytes 0x20..0x7E).
    var nlen = Int(((_splitmix64(state)) % UInt64(20)) + UInt64(1))
    var buf = List[UInt8]()
    for _ in range(nlen):
        var byte = UInt8(((_splitmix64(state)) % UInt64(95)) + UInt64(32))
        buf.append(byte)
    return String(unsafe_from_utf8=buf)


def test_idempotent_only_structured_property() raises:
    """AC idempotent-only-structured-property.

    10000 trials, SplitMix64-seeded (deterministic). Property: the
    filter accepts iff the drawn method is exactly one of `GET`,
    `HEAD`, `OPTIONS`. The 70/30 split between a structured pool and
    a random byte generator covers both common reject neighbours and
    rare bytewise drift.
    """
    var f = IdempotentOnlyFilter()
    var state = UInt64(0xC0FFEE12345678)
    var trials = 10000
    for i in range(trials):
        var m = _draw_method(state)
        var d = f.should_accept_for_0rtt(m, String(""), Headers())
        var expected_accept = (m == "GET") or (m == "HEAD") or (m == "OPTIONS") or (m == "QUERY")
        if expected_accept:
            assert_true(
                d.is_accept(),
                String("trial ") + String(i) + String(": expected accept for ") + m,
            )
        else:
            assert_true(
                d.is_reject(),
                String("trial ") + String(i) + String(": expected reject for ") + m,
            )
    print("  test_idempotent_only_structured_property: PASS (10000 trials)")


def main() raises:
    """Driver for `scripts/run_tests.sh`: each test must be invoked here."""
    test_filter_decision_accept_round_trip()
    test_filter_decision_reject_round_trip()
    test_filter_decision_equatable()
    test_idempotent_only_accepts_get()
    test_idempotent_only_accepts_head()
    test_idempotent_only_accepts_options()
    test_idempotent_only_accepts_query()
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
    test_idempotent_only_rejects_embedded_nul()
    test_idempotent_only_rejects_non_ascii()
    test_idempotent_only_structured_property()
