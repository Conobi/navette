"""Referential-transparency property tests for the two reference
predicates. 1k trials each; SplitMix64-seeded for determinism.

Covers AC reference-predicate-purity-property.
"""

from navette.http.headers import Headers
from navette.tls.filters import (
    idempotency_key_predicate,
    unauthenticated_only_predicate,
)
from tests._test_util import assert_true


fn _splitmix64(mut state: UInt64) -> UInt64:
    state = state + UInt64(0x9E3779B97F4A7C15)
    var z = state
    z = (z ^ (z >> 30)) * UInt64(0xBF58476D1CE4E5B9)
    z = (z ^ (z >> 27)) * UInt64(0x94D049BB133111EB)
    return z ^ (z >> 31)


def _draw_method(mut state: UInt64) -> String:
    var idx = Int(_splitmix64(state) % UInt64(9))
    var pool = List[String]()
    pool.append(String("GET"))
    pool.append(String("HEAD"))
    pool.append(String("OPTIONS"))
    pool.append(String("POST"))
    pool.append(String("PUT"))
    pool.append(String("PATCH"))
    pool.append(String("DELETE"))
    pool.append(String("CONNECT"))
    pool.append(String("TRACE"))
    return pool[idx]


def _draw_headers(mut state: UInt64) raises -> Headers:
    var h = Headers()
    var which = _splitmix64(state) % UInt64(4)
    if which == UInt64(0):
        pass  # empty
    elif which == UInt64(1):
        h.add(String("idempotency-key"), String("k") + String(_splitmix64(state) % UInt64(1000)))
    elif which == UInt64(2):
        h.add(String("authorization"), String("Bearer abc"))
    else:
        h.add(String("cookie"), String("s=") + String(_splitmix64(state) % UInt64(1000)))
    return h^


def test_idempotency_key_referentially_transparent() raises:
    """Same (method, path, headers) → same decision across two calls."""
    var state = UInt64(0xC0FFEE12345678)
    for i in range(1000):
        var m = _draw_method(state)
        var path = String("/path/") + String(_splitmix64(state) % UInt64(100))
        var h1 = _draw_headers(state)
        var h2 = Headers(other=h1)
        var d1 = idempotency_key_predicate(m, path, h1)
        var d2 = idempotency_key_predicate(m, path, h2)
        assert_true(
            d1 == d2,
            String("trial ") + String(i) + String(": idempotency_key not transparent"),
        )
    print("  test_idempotency_key_referentially_transparent: PASS (1000 trials)")


def test_unauth_only_referentially_transparent() raises:
    """Same (method, path, headers) → same decision across two calls."""
    var state = UInt64(0xBADCAFE0FBADCAFE)
    for i in range(1000):
        var m = _draw_method(state)
        var path = String("/path/") + String(_splitmix64(state) % UInt64(100))
        var h1 = _draw_headers(state)
        var h2 = Headers(other=h1)
        var d1 = unauthenticated_only_predicate(m, path, h1)
        var d2 = unauthenticated_only_predicate(m, path, h2)
        assert_true(
            d1 == d2,
            String("trial ") + String(i) + String(": unauth_only not transparent"),
        )
    print("  test_unauth_only_referentially_transparent: PASS (1000 trials)")


def main() raises:
    print("test_filters_predicates_property")
    test_idempotency_key_referentially_transparent()
    test_unauth_only_referentially_transparent()
    print("test_filters_predicates_property: PASS")
