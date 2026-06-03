"""Shared H3 early-data filter dispatch helper.

Three H3 server adapters (`H3HandlerServer`, `H3SyncServer`,
`H3StreamingServer`) each parse `:method` from the QPACK walk during
`_on_request`. Without a shared seam every adapter would duplicate the
filter-consult-then-inject-or-425 logic; this module is that seam.

The helper is called AFTER the QPACK walk completes (so `method_str`
is final) and AFTER the post-walk `Headers` object is built (so the
header that will reach the handler is the one mutated), but BEFORE
`Method.custom(method_str)` normalisation and BEFORE
`handler.on_request(...)`.

Decision tree:
  1. is_zero_rtt == False                        -> proceed; bump 1rtt_bypassed.
  2. is_zero_rtt == True, filter_ptr is None    -> send_425; bump misconfig_fail_closed (defensive fail-closed).
  3. is_zero_rtt == True, filter accepts        -> proceed; inject Early-Data: 1; bump accept.
  4. is_zero_rtt == True, filter rejects        -> send_425; bump reject_425.

The fail-closed posture on (2) enforces the safe-by-default-when-on
goal: a connection that opted into 0-RTT must NEVER see non-idempotent
requests reach handlers without filtering. If wiring is broken, 425
responses are emitted and the dedicated counter increments for
operator visibility; the client retries over 1-RTT with zero functional
loss.

Counter routing is unconditional (gated only on the profile pointer
being Some); the recorders themselves are no-cost when PROFILE_ACCEPT
is off because `AcceptProfile` is sans-IO. This matches the
unconditional pattern used by the existing
`record_zero_rtt_http_filter_*` call sites in the test suite.
"""

from std.collections import Optional
from std.memory import UnsafePointer

from navette.h3.connection import H3Connection
from navette.h3.qpack import QpackHeaderField
from navette.http.headers import Headers
from navette.quic.connection import QuicConnection
from navette.quic.profile import AcceptProfile
from navette.tls.early_data_filter import (
    FilterDecision,
    IdempotentOnlyFilter,
)


def stream_is_zero_rtt(
    ref quic: QuicConnection, stream_id: UInt64
) raises -> Bool:
    """Return True iff the given stream was tagged as 0-RTT-arrived
    during its creation in `QuicConnection._handle_stream_frame`.

    Reads `Stream.is_zero_rtt` from the QUIC connection's stream map.
    Stream IDs are monotonic per RFC 9000 §2.1; absent streams (rarely
    possible if dispatch fires twice on the same id) return False as a
    defensive fallback so the dispatch path stays fail-safe.

    Marked `raises` because `Dict.__getitem__` is `raises` even though
    the `not in` guard makes the subscript safe.

    Args:
      quic: The QUIC connection whose `stream_map` is consulted.
      stream_id: The peer-initiated stream id reported by the inbound
        H3 HEADERS event.

    Returns:
      True iff `Stream.is_zero_rtt` is set on the matching stream.
    """
    var key = Int(stream_id)
    if key not in quic.stream_map.streams:
        return False
    return quic.stream_map.streams[key].is_zero_rtt


@fieldwise_init
struct FilterDispatchOutcome(Copyable, Movable, Equatable):
    """Outcome of `apply_early_data_filter`.

    Mirrors `FilterDecision` shape but is a DIFFERENT type because it
    covers anomaly paths (filter_ptr=None) that do NOT produce a
    FilterDecision. Two variants only — `proceed` (caller continues
    with handler dispatch; headers may have been mutated with
    Early-Data: 1) or `send_425` (caller MUST synthesise a 425 response
    via `send_425_response` and skip the handler).
    """
    var kind: UInt8

    comptime KIND_PROCEED  = UInt8(0)
    comptime KIND_SEND_425 = UInt8(1)

    @staticmethod
    def proceed() -> Self:
        """Return the `proceed` variant."""
        return Self(kind=Self.KIND_PROCEED)

    @staticmethod
    def send_425() -> Self:
        """Return the `send_425` variant."""
        return Self(kind=Self.KIND_SEND_425)

    def should_proceed(self) -> Bool:
        """True iff the caller should continue with handler dispatch."""
        return self.kind == Self.KIND_PROCEED

    def should_send_425(self) -> Bool:
        """True iff the caller must synthesise a 425 response."""
        return self.kind == Self.KIND_SEND_425

    def __eq__(self, other: Self) -> Bool:
        """Variant equality — two outcomes match iff their kinds match."""
        return self.kind == other.kind

    def __ne__(self, other: Self) -> Bool:
        """Logical negation of `__eq__`."""
        return self.kind != other.kind


def apply_early_data_filter(
    method_str: String,
    is_zero_rtt: Bool,
    filter_ptr: Optional[UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]],
    mut headers: Headers,
    profile_ptr: Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]],
) -> FilterDispatchOutcome:
    """Consult the early-data filter for a request that may have
    arrived via 0-RTT.

    Args:
      method_str: The `:method` pseudo-header value (the original wire
        bytes, pre-`Method.custom()` normalisation).
      is_zero_rtt: True iff the request's first STREAM frame arrived
        inside a 0-RTT-decrypted packet (sourced from
        `Stream.is_zero_rtt`).
      filter_ptr: Optional pointer to the connection's filter
        instance. Populated when the server config has 0-RTT enabled;
        None when 0-RTT is disabled OR if wiring is broken
        (fail-closed branch).
      headers: The post-QPACK-walk Headers that will be threaded into
        Request. On accept, `Early-Data: 1` is injected via
        `Headers.set` (overwrites any client-supplied early-data).
      profile_ptr: Optional pointer to the connection's AcceptProfile.
        Used to bump exactly one of the four outcome counters.

    Returns:
      `FilterDispatchOutcome.proceed` if the handler should be
      invoked, or `FilterDispatchOutcome.send_425` if the caller must
      synthesise a 425 Too Early response and skip the handler.
    """
    if not is_zero_rtt:
        # Path 1: 1-RTT request. Filter is NOT consulted (the filter
        # has no business deciding 1-RTT requests). Bump the
        # 1rtt_bypassed counter so operators see the 0-RTT-vs-1-RTT
        # mix. Headers are NOT mutated — any client-supplied
        # `early-data` field flows untouched to the handler;
        # handlers MUST consult `caps.is_early_data` as the
        # authoritative signal rather than trust the header.
        if profile_ptr is not None:
            profile_ptr.value()[].record_zero_rtt_http_filter_1rtt_bypassed()
        return FilterDispatchOutcome.proceed()

    if filter_ptr is None:
        # Path 2: defensive fail-closed. Stream is tagged 0-RTT but
        # the adapter never received a filter pointer (config
        # invariant violation). Emit 425 + bump the dedicated
        # misconfig counter so this is distinguishable from real
        # wire-level rejections.
        if profile_ptr is not None:
            profile_ptr.value()[].record_zero_rtt_http_filter_misconfig_fail_closed()
        return FilterDispatchOutcome.send_425()

    var decision = filter_ptr.value()[].should_accept_for_0rtt(method_str)
    if decision.is_accept():
        # Path 3: 0-RTT accepted. Inject `Early-Data: 1` per RFC 8470
        # §3 so upstream backends know the request rode 0-RTT.
        # `Headers.set` overwrites any client-supplied `early-data`
        # — the server's authoritative "1" wins.
        headers.set(String("early-data"), String("1"))
        if profile_ptr is not None:
            profile_ptr.value()[].record_zero_rtt_http_filter_accept()
        return FilterDispatchOutcome.proceed()

    # Path 4: 0-RTT rejected. Bump reject counter; caller emits 425.
    if profile_ptr is not None:
        profile_ptr.value()[].record_zero_rtt_http_filter_reject_425()
    return FilterDispatchOutcome.send_425()


def send_425_response(stream_id: UInt64, mut h3_conn: H3Connection) raises:
    """Synthesise a 425 Too Early response per RFC 8470 §5.2.

    Status-only response with no body; FIN closes the stream. Uses the
    real `H3Connection.send_headers(stream_id, fields, fin=True)` API.
    """
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(String(":status"), String("425")))
    h3_conn.send_headers(stream_id, fields, True)
