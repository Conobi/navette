"""Reference predicates for `EarlyDataPolicy.predicate(...)`.

Stateless free functions covering the two most common operator-grade
0-RTT acceptance patterns:

  - idempotency_key_predicate     — Stripe / AWS / PayPal pattern.
  - unauthenticated_only_predicate — conservative auth-gating pattern.

Path-prefix allowlists are deliberately NOT shipped here. Operators
wanting a path-prefix policy either: (a) author their own predicate
with a hardcoded prefix list, or (b) wait for a future change landing
struct-based filter pluggability with runtime configuration.
"""

from navette.http.headers import Headers
from navette.tls.early_data_filter import FilterDecision, is_rfc_safe_method


def idempotency_key_predicate(
    method: String,
    _path: String,
    headers: Headers,
) raises -> FilterDecision:
    """Idempotency-Key-aware predicate (Stripe / AWS / PayPal pattern).

    Accepts:
      - GET, HEAD, OPTIONS (the IdempotentOnly baseline);
      - POST, PUT, PATCH, DELETE that carry a non-empty
        `Idempotency-Key` header.

    Rejects everything else with 425 Too Early.

    Spec reference: IETF httpapi-idempotency-key (draft) §3, §4.

    Header lookup is case-insensitive (Headers stores names lowercased
    on insert). Empty-value `Idempotency-Key:` MUST reject — the
    header must be non-empty to count as a key (draft §3).

    NOTE: an `Idempotency-Key` header on a safe (GET/HEAD/OPTIONS)
    request is IGNORED — the draft §3 says the header MUST NOT be
    sent on safe methods, but the predicate's safe-method baseline
    accepts unconditionally. Over-acceptance on safe methods matches
    the IdempotentOnly floor; under-acceptance would regress that floor.

    Args:
        method: The `:method` pseudo-header value verbatim.
        _path: The `:path` pseudo-header value verbatim. Not consulted
            (underscore-prefixed per Mojo unused-parameter convention).
        headers: The post-QPACK-walk request headers.

    Returns:
        FilterDecision.accept() iff the method is safe-by-default OR
        carries a non-empty idempotency key. FilterDecision.reject_425()
        otherwise.
    """
    if is_rfc_safe_method(method):
        return FilterDecision.accept()
    if (
        method == "POST"
        or method == "PUT"
        or method == "PATCH"
        or method == "DELETE"
    ):
        var key = headers.get(String("idempotency-key"))
        if len(key) > 0:
            return FilterDecision.accept()
    return FilterDecision.reject_425()


def unauthenticated_only_predicate(
    method: String,
    _path: String,
    headers: Headers,
) raises -> FilterDecision:
    """Accept only safe-method requests that carry no authentication header.

    Accepts:
      - GET, HEAD, OPTIONS requests that carry neither `Authorization`
        nor `Cookie` headers.

    Rejects:
      - any request carrying `Authorization` or `Cookie` (even GET/HEAD/OPTIONS);
      - any non-safe method, regardless of headers.

    Rationale: replays of unauthenticated read traffic at worst
    re-fetch a public resource; authenticated traffic (even a GET)
    could reveal user-specific state, so the conservative posture is
    to block 0-RTT for any request that may interact with a session.

    Header lookup is case-insensitive.

    Args:
        method: The `:method` pseudo-header value verbatim.
        _path: The `:path` pseudo-header value verbatim. Not consulted.
        headers: The post-QPACK-walk request headers.

    Returns:
        FilterDecision.accept() iff the method is safe AND neither auth
        header is present. FilterDecision.reject_425() otherwise.
    """
    if not is_rfc_safe_method(method):
        return FilterDecision.reject_425()
    if headers.has(String("authorization")):
        return FilterDecision.reject_425()
    if headers.has(String("cookie")):
        return FilterDecision.reject_425()
    return FilterDecision.accept()
