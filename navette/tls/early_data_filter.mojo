"""RFC 8470 HTTP early-data filter — pure-core implementation.

Decides whether an HTTP request whose first bytes arrived via TLS 1.3
0-RTT (RFC 9001 §4.6) is safe to dispatch to a handler, or whether it
should be rejected with `425 Too Early` (RFC 8470 §5.2).

Implementations MUST be deterministic given a method string; they MUST
NOT consult mutable state, perform I/O, or yield. Method strings are
compared byte-wise per RFC 9110 §5.6.2 (tokens are exact bytes) and are
case-sensitive per RFC 9110 §9.1.

The trait surface here is implementation-internal for this cycle; the
public `EarlyDataPolicy` surface that wraps it lives in a follow-up
cycle.
"""


@fieldwise_init
struct FilterDecision(Copyable, Movable, Equatable):
    """Outcome of `EarlyDataFilter.should_accept_for_0rtt`.

    Two variants only — anomaly paths (e.g. filter pointer is None on a
    0-RTT request) do NOT produce a FilterDecision; the H3-layer
    dispatch helper short-circuits to a fail-closed 425 BEFORE ever
    calling the filter.
    """
    var kind: UInt8

    comptime KIND_ACCEPT     = UInt8(0)
    comptime KIND_REJECT_425 = UInt8(1)

    @staticmethod
    def accept() -> Self:
        """Build an accept variant — dispatch the request normally."""
        return Self(kind=Self.KIND_ACCEPT)

    @staticmethod
    def reject_425() -> Self:
        """Build a reject variant — H3 layer MUST emit 425 Too Early."""
        return Self(kind=Self.KIND_REJECT_425)

    def is_accept(self) -> Bool:
        """True iff this decision is the accept variant."""
        return self.kind == Self.KIND_ACCEPT

    def is_reject(self) -> Bool:
        """True iff this decision is the reject_425 variant."""
        return self.kind == Self.KIND_REJECT_425

    def __eq__(self, other: Self) -> Bool:
        """Variant equality — two decisions are equal iff their kinds match."""
        return self.kind == other.kind

    def __ne__(self, other: Self) -> Bool:
        """Logical negation of `__eq__`."""
        return self.kind != other.kind


trait EarlyDataFilter(Movable):
    """Predicate that decides whether a 0-RTT-arrived HTTP request
    should be dispatched or rejected with 425 Too Early.

    Implementations MUST be deterministic. They MUST NOT consult mutable
    state, perform I/O, or yield.

    Receives `method: String` because the H3 adapters extract `:method`
    from the QPACK walk as a String BEFORE building the `Method` tag
    struct; running the filter on that pre-normalisation string keeps
    the original wire bytes accessible.
    """
    def should_accept_for_0rtt(self, method: String) -> FilterDecision: ...


struct IdempotentOnlyFilter(EarlyDataFilter):
    """Conservative default filter: accepts GET, HEAD, OPTIONS; rejects
    everything else with 425. RFC 9110 §9.2.1 (safe) + §9.2.2
    (idempotent) — these three methods are both, so a replay produces no
    new server-observable effect.

    Case-sensitive: lowercase "get" is NOT GET (RFC 9110 §9.1).
    Whitespace-padded " GET" / "GET " also reject.
    """

    def __init__(out self):
        """Default constructor — no state to initialise."""
        pass

    def __init__(out self, *, other: Self):
        """Copy-like constructor for trait-bound generic code; stateless."""
        pass

    def __init__(out self, *, deinit take: Self):
        """Move-from constructor for trait-bound generic code; stateless."""
        pass

    def should_accept_for_0rtt(self, method: String) -> FilterDecision:
        """Return accept iff `method` is exactly "GET", "HEAD", or
        "OPTIONS"; otherwise return reject_425.

        Case- and whitespace-sensitive per RFC 9110 §9.1 + §5.6.2.
        """
        if method == "GET":
            return FilterDecision.accept()
        if method == "HEAD":
            return FilterDecision.accept()
        if method == "OPTIONS":
            return FilterDecision.accept()
        return FilterDecision.reject_425()
