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

Decision tree (§3.5 truth-table, first match wins):
  1. is_zero_rtt == False                          -> proceed.
  2. is_zero_rtt == True, both None                -> send_425 (fail closed).
  3. is_zero_rtt == True, predicate_fn Some        -> call predicate; route on outcome.
  4. is_zero_rtt == True, filter_ptr Some          -> call filter; route on outcome.

Both call paths catch raises and send_425, so user-supplied predicate
failures fail closed without surfacing exceptions to the H3 adapter.

The fail-closed posture on (2) enforces the safe-by-default-when-on
goal: a connection that opted into 0-RTT must NEVER see non-idempotent
requests reach handlers without filtering. If wiring is broken, 425
responses are emitted; the client retries over 1-RTT with zero
functional loss.
"""

from std.collections import Optional
from std.memory import Pointer

from navette.h3.connection import H3Connection
from navette.h3.error import H3_REQUEST_CANCELLED
from navette.h3.qpack import QpackHeaderField
from navette.http.headers import Headers
from navette.quic.connection import QuicConnection
from navette.tls.early_data_filter import (
    EarlyDataPredicateFn,
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
    return quic.stream_map.streams[key][].is_zero_rtt


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
    path_str: String,
    is_zero_rtt: Bool,
    filter_ptr: Optional[Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]],
    predicate_fn: Optional[EarlyDataPredicateFn],
    mut headers: Headers,
) raises -> FilterDispatchOutcome:
    """Consult the early-data filter or predicate for a request that
    may have arrived via 0-RTT.

    The §3.5 dispatch truth-table (first-match wins):

    | is_zero_rtt | predicate_fn | filter_ptr | action |
    |---|---|---|---|
    | False       | *            | *          | proceed |
    | True        | None         | None       | send_425 (fail closed) |
    | True        | Some(pred)   | *          | call pred; route on outcome |
    | True        | None         | Some(ptr)  | call ptr; route on outcome |

    The `(predicate_fn=Some, filter_ptr=Some)` row resolves to the
    predicate path (defensive AC `dispatch-helper-predicate-takes-
    precedence`). The §3.4 population invariant in `QuicServerConfig`
    ensures this row cannot arise in production.

    Args:
        method_str: The `:method` pseudo-header value verbatim.
        path_str: The `:path` pseudo-header value verbatim.
        is_zero_rtt: True iff the request's first STREAM frame
          arrived inside a 0-RTT-decrypted packet.
        filter_ptr: Optional pointer to the connection's struct-
          based filter. Populated when the server config has 0-RTT
          enabled via IdempotentOnly / Tuned (Off populates nothing).
        predicate_fn: Optional user-supplied predicate function.
          Populated when the server config has 0-RTT enabled via
          Predicate.
        headers: The post-QPACK-walk Headers. On accept,
          `Early-Data: 1` is injected via `Headers.set`.

    Returns:
        `FilterDispatchOutcome.proceed` if the handler should be
        invoked, or `FilterDispatchOutcome.send_425` otherwise.
    """
    if not is_zero_rtt:
        return FilterDispatchOutcome.proceed()

    if predicate_fn is None and filter_ptr is None:
        # Both None: defensive fail-closed.
        return FilterDispatchOutcome.send_425()

    var decision: FilterDecision
    if predicate_fn is not None:
        # Predicate path takes precedence (defensive invariant on the
        # both-Some row; §3.4 guarantees mutual exclusion).
        try:
            decision = predicate_fn.value()(method_str, path_str, headers)
        except:
            return FilterDispatchOutcome.send_425()
    else:
        # Filter-ptr path (filter_ptr is Some).
        try:
            decision = filter_ptr.value()[].should_accept_for_0rtt(
                method_str, path_str, headers
            )
        except:
            # IdempotentOnlyFilter does not raise today; the defensive
            # catch fails closed for future user-supplied filter variants.
            return FilterDispatchOutcome.send_425()

    if decision.is_accept():
        headers.set(String("early-data"), String("1"))
        return FilterDispatchOutcome.proceed()

    return FilterDispatchOutcome.send_425()


def send_425_response(stream_id: UInt64, mut h3_conn: H3Connection) raises:
    """Synthesise a 425 Too Early response per RFC 8470 §5.2.

    Status-only response with no body; FIN closes the stream. Uses the
    real `H3Connection.send_headers(stream_id, fields, fin=True)` API.

    After queuing the 425 response, emit a `STOP_SENDING`
    (RFC 9000 §3.5) on the request stream with H3 error
    `H3_REQUEST_CANCELLED` (0x010C per RFC 9114 §8.1) so the QUIC
    recv buffer is reclaimed immediately. Without this, a 0-RTT POST
    whose body is still in flight would continue to fill the
    per-stream recv buffer up to `fc_recv_limit` (default 1 MiB) even
    though those bytes are dropped at the H3 layer.
    """
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(String(":status"), String("425")))
    h3_conn.send_headers(stream_id, fields, True)
    h3_conn._quic.stop_sending(stream_id, H3_REQUEST_CANCELLED)
