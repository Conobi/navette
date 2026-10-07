# src/h3/h3_sync_server.mojo
#
# HTTP/3 server-side adapter — sans-IO codec wrapper. Feed inbound QUIC
# datagrams via `feed_datagram_from_buffer()`; drain outbound datagrams via
# `drain()`. Translates H3Connection events into a per-stream hand-written
# state machine, NOT stackful coroutines (mirrors the H2CoroServer design
# over QUIC).
#
# The "Coro" in `CoroStreamCtx` is preserved to mirror the H2 sister-file's
# naming (left that way to minimise churn). A future
# rename pass can unify both names — out of scope here.

from std.collections import Dict, Optional
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc
from std.sys.info import size_of

from navette.quic.connection import QuicConnection
from navette.h3.connection import H3Connection, H3Event
from navette.h3.early_data_filter_dispatch import (
    apply_early_data_filter, send_425_response, stream_is_zero_rtt,
)
from navette.http.handler import Capabilities, RecvBody, ResponseWriter
from navette.http.body import BodyFrame
from navette.http.handler_driver import pump_or_fail
from navette.http.headers import Headers
from navette.http.request import Request
from navette.tls.early_data_filter import (
    EarlyDataPredicateFn,
    IdempotentOnlyFilter,
)
from navette.util.ctx_pool import CtxPool
from navette.util.ptrbox import PtrBox
from navette.util.null_ptr import null_ptr


# ---------------------------------------------------------------------------
# H3BodyFn — synchronous handler invoked once per request.
# ---------------------------------------------------------------------------
#
# The handler receives a pointer to the per-stream context, reads
# `ctx.request` (or for streaming POST bodies, polls `ctx.recv_body`),
# and writes the response into `ctx.resp_writer`. It runs to completion
# in one call — it never suspends. Streaming-handler use cases are
# served by `src/h3/h3_streaming_server.mojo`.

comptime H3BodyFn = def (
    Pointer[CoroStreamCtx, MutUntrackedOrigin]
) thin raises -> None


# ---------------------------------------------------------------------------
# CoroStreamCtx — per-stream state (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct CoroStreamCtx(Movable):
    """Per-stream context for H3 serving. Heap-allocated so the
    adapter and the handler can reach it via pointer. Holds the
    request, body receiver, response writer, capabilities, and
    request/response bookkeeping.

    No `coro_addr` field (handler runs synchronously).
    No `unacked_bytes` (QUIC handles flow control internally).
    Stream IDs are UInt64 (QUIC uses 62-bit stream IDs, wider than H2's UInt32).
    """

    var request: Request
    var recv_body: RecvBody
    var resp_writer: ResponseWriter
    var caps: Capabilities
    var stream_id: UInt64
    var extra_data: Pointer[NoneType, MutUntrackedOrigin]
    var request_ended: Bool
    var response_ended: Bool
    var headers_sent: Bool
    var failure: Optional[String]
    """A handler raise, resolved by the next response drain."""

    def __init__(
        out self,
        var request: Request,
        caps: Capabilities,
        stream_id: UInt64,
        extra_data: Pointer[NoneType, MutUntrackedOrigin],
    ):
        self.request = request^
        self.recv_body = RecvBody()
        self.resp_writer = ResponseWriter()
        self.caps = Capabilities(copy=caps)
        self.stream_id = stream_id
        self.extra_data = extra_data
        self.request_ended = False
        self.response_ended = False
        self.headers_sent = False
        self.failure = None


# ---------------------------------------------------------------------------
# Per-stream memory budget (R8 in the sprint roadmap)
# ---------------------------------------------------------------------------
#
# H3 omits `unacked_bytes: Int` and `coro_addr: UInt64` vs. the H3 coro
# version; gains `stream_id: UInt64` vs. H2's `UInt32` (+4 B).
# Expected to land comfortably under 1024 B given H2 baseline ~608 B.
#
# The check fires inside `_check_stream_ctx_size` below, called at the
# top of every H3CoroServer constructor.


def _check_stream_ctx_size():
    comptime assert size_of[CoroStreamCtx]() < 1024, (
        "H3 CoroStreamCtx exceeded R8 budget (1024 B) — investigate"
        " before raising the cap"
    )


# ---------------------------------------------------------------------------
# _free_stream — single cleanup path for CoroStreamCtx
# ---------------------------------------------------------------------------


def _free_stream(ctx_ptr: Pointer[CoroStreamCtx, MutUntrackedOrigin]):
    """Hard-destroy the CoroStreamCtx allocation."""
    ctx_ptr.unsafe_deinit_pointee()
    ctx_ptr.unsafe_free()




# ---------------------------------------------------------------------------
# H3CoroServer — server adapter using a per-stream state machine
# ---------------------------------------------------------------------------


struct H3CoroServer(Movable):
    """Drive per-stream state from an HTTP/3 H3Connection. Sans-IO:
    the caller feeds inbound QUIC datagrams via `feed_datagram_from_buffer()`
    and drains outbound datagrams via `drain()`. Each stream's user handler
    runs synchronously when the request arrives (no
    stackful coroutines).

    Note: `_h3: H3Connection` already wraps and owns the `QuicConnection`
    internally (H3Connection._quic field). A separate top-level `_quic`
    field is intentionally absent to avoid double-ownership — mirrors
    H3CoroServer and H3HandlerServer patterns.
    """

    var _h3: H3Connection
    var _body_fn: H3BodyFn
    var _extra_data: Pointer[NoneType, MutUntrackedOrigin]
    var _outbuf: List[List[Byte]]
    var _streams: Dict[Int, PtrBox[CoroStreamCtx]]
    var _ctx_pool: CtxPool[CoroStreamCtx]
    # Optional pointer to the RFC 8470 idempotent-only filter owned by
    # the `QuicServerConfig` that birthed this connection. Populated
    # only when 0-RTT is enabled in the config; None for rejection-mode
    # servers (and any path that doesn't plumb it). When None, the
    # filter dispatch helper takes the fail-closed branch for 0-RTT
    # requests.
    var _early_data_filter_ptr: Optional[
        Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]
    ]
    var _early_data_predicate_fn: Optional[EarlyDataPredicateFn]
    """User-supplied 0-RTT predicate fn, propagated from
    `QuicServerConfig._early_data_predicate_fn` via `H3UdpServer`'s
    per-connection construction. Populated only when the policy is
    Predicate. The dispatch helper consults this field in preference
    to `_early_data_filter_ptr` per the truth-table for the predicate
    variant of the 0-RTT policy."""
    var _pending_response_streams: List[Int]
    """Stream IDs whose handler has returned with pending response data
    awaiting drain. Replaces the O(all-streams) key scan in
    `_drain_responses` with an O(pending-only) iteration."""

    # --- Constructors -------------------------------------------------------

    def __init__(
        out self,
        *,
        var quic: QuicConnection,
        body_fn: H3BodyFn,
        extra_data: Pointer[NoneType, MutUntrackedOrigin] = null_ptr[
            NoneType, MutUntrackedOrigin
        ](),
        early_data_filter_ptr: Optional[
            Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]
        ] = None,
        predicate_fn: Optional[EarlyDataPredicateFn] = None,
    ) raises:
        """Create with a server-side QuicConnection."""
        _check_stream_ctx_size()
        self._h3 = H3Connection.server(quic^)
        self._body_fn = body_fn
        self._extra_data = extra_data
        self._outbuf = List[List[Byte]]()
        self._streams = Dict[Int, PtrBox[CoroStreamCtx]]()
        self._ctx_pool = CtxPool[CoroStreamCtx](capacity=16)
        self._early_data_filter_ptr = early_data_filter_ptr
        self._early_data_predicate_fn = predicate_fn
        self._pending_response_streams = List[Int]()

    def __deinit__(deinit self):
        """Destroy and free all heap-allocated stream contexts."""
        var keys = List[Int](capacity=len(self._streams))
        for key in self._streams.keys():
            keys.append(key)
        for ref key in keys:
            try:
                var ctx_ptr = self._streams[key].ptr()
                _free_stream(ctx_ptr)
            except:
                pass

    # --- Transport bridging API ---------------------------------------------

    def feed_datagram_from_buffer(
        mut self,
        buf: Pointer[UInt8, MutUntrackedOrigin],
        buf_len: Int,
        now: UInt64,
    ) raises:
        """Feed one inbound QUIC datagram from a mutable buffer (zero-copy).
        Dispatches H3 events, drains responses, accumulates outbound datagrams."""
        self._h3.feed_datagram_from_buffer(buf, buf_len, now)
        self._dispatch_h3_events(now)
        if self._h3.is_established():
            self._drain_responses(now)
        self._flush_outbound(now)

    def feed_datagram(mut self, data: Span[Byte, _], now: UInt64) raises:
        """Feed one inbound QUIC datagram. Dispatches H3 events and drains
        pending response data."""
        self._h3.feed_datagram(data, now)
        self._dispatch_h3_events(now)
        if self._h3.is_established():
            self._drain_responses(now)
        self._flush_outbound(now)

    def drain(mut self, now: UInt64 = 0) -> List[List[Byte]]:
        """Drain queued outbound QUIC datagrams for the transport to write.

        Also pulls whatever the connection can send right now, so egress
        queued outside the ingress path (GOAWAY, timer-driven frames)
        leaves without waiting for the peer's next datagram. Pass the
        caller's clock; the default 0 cannot fire any armed timer.
        """
        try:
            self._flush_outbound(now)
        except:
            pass
        var out = self._outbuf^
        self._outbuf = List[List[Byte]]()
        return out^

    def should_close(self) -> Bool:
        """True when the H3 connection has reached terminal state."""
        return self._h3.is_closed()

    def send_goaway(mut self, last_stream_id: UInt64) raises:
        """Send GOAWAY via the underlying H3Connection."""
        self._h3.send_goaway(last_stream_id)

    # --- Internal -----------------------------------------------------------

    def _has_stream(self, sid: Int) -> Bool:
        return sid in self._streams

    def _release_stream(
        mut self, ctx_ptr: Pointer[CoroStreamCtx, MutUntrackedOrigin]
    ):
        """Destroy the CoroStreamCtx pointee and return its memory block to the
        per-connection pool (or free if over capacity)."""
        ctx_ptr.unsafe_deinit_pointee()
        self._ctx_pool.release(ctx_ptr)

    def _flush_outbound(mut self, now: UInt64) raises:
        """Append pending outbound QUIC datagrams to the outbound buffer."""
        self._h3.drain_datagrams(now, self._outbuf)

    def _run_handler(mut self, stream_id: Int) raises:
        """Invoke the user handler synchronously; its response waits in `ctx.resp_writer` for `_drain_responses`, and a raise is recorded for `_drain_responses`."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        try:
            self._body_fn(ctx_ptr)
        except e:
            ctx_ptr[].failure = String(e)

    def _cleanup_stream(mut self, stream_id: Int) raises:
        """Unconditionally free stream context and remove from dict."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        _ = self._streams.pop(stream_id)
        _free_stream(ctx_ptr)

    def _maybe_cleanup_stream(mut self, stream_id: Int) raises:
        """Free stream context if both request and response sides are done."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        if ctx_ptr[].request_ended and ctx_ptr[].response_ended:
            _ = self._streams.pop(stream_id)
            _free_stream(ctx_ptr)

    # --- Event dispatch -----------------------------------------------------

    def _dispatch_h3_events(mut self, now: UInt64) raises:
        """Poll and dispatch all pending H3 events."""
        while True:
            var ev_opt = self._h3.poll_event()
            if not ev_opt:
                break
            var ev = ev_opt.unsafe_take()
            var sid = Int(ev.stream_id)
            if ev.kind == H3Event.HEADERS_RECEIVED:
                self._on_request(ev^)
            elif ev.kind == H3Event.TRAILERS_RECEIVED:
                self._on_trailers(sid, ev^.take_section().take_headers())
            elif ev.kind == H3Event.DATA_RECEIVED:
                self._on_data(sid, ev^.take_data())
            elif ev.kind == H3Event.STREAM_ENDED:
                self._on_stream_ended(ev)
            elif ev.kind == H3Event.STREAM_RESET:
                self._on_stream_reset(ev)
            elif ev.kind == H3Event.GOAWAY_RECEIVED or ev.kind == H3Event.CONNECTION_CLOSED:
                self._on_goaway(ev)
            # H3Event.HANDSHAKE_COMPLETE and H3Event.SETTINGS_RECEIVED are
            # informational only — no per-stream action needed in the sync path.

    def _on_request(mut self, var ev: H3Event) raises:
        """Build the Request from the stream's head, allocate
        CoroStreamCtx on heap, register in streams dict, and run the handler
        synchronously (no coroutine spawn)."""
        var sid = ev.stream_id
        var req = ev^.take_section().into_request()

        # RFC 8470 0-RTT HTTP filter dispatch, gated on the connection's
        # cached `zrtt.enabled` opt-in (the authoritative O(1) signal
        # set from QuicServerConfig.max_early_data() at conn creation).
        #
        # When 0-RTT is DISABLED (rejection-mode listener), no stream can
        # ever carry the is_zero_rtt tag — the 0-RTT packet space is never
        # keyed, so `stream_is_zero_rtt` would always return False. The
        # whole dispatch is therefore dead weight: we skip both the
        # per-request Dict probe AND the apply_early_data_filter call,
        # leaving `stream_is_zr=False` so the request flows straight to the
        # handler with caps.is_early_data=False. Gating here (not on
        # filter-pointer presence) keeps the fail-closed misconfig row
        # intact: a 0-RTT-ENABLED connection with both filter pointers None
        # still runs the dispatch and fail-closes with a 425.
        #
        # On reject (0-RTT request whose method is non-idempotent OR
        # fail-closed misconfig), synthesise a 425 Too Early and skip the
        # handler. On accept, the helper has already injected
        # `Early-Data: 1` into the request headers.
        var stream_is_zr = False
        if self._h3._quic.zrtt.enabled:
            stream_is_zr = stream_is_zero_rtt(self._h3._quic, sid)
            var outcome = apply_early_data_filter(
                String(req.method),
                req.target,
                stream_is_zr,
                self._early_data_filter_ptr,
                self._early_data_predicate_fn,
                req.headers,
            )
            if outcome.should_send_425():
                send_425_response(sid, self._h3)
                return

        var stream_id = Int(sid)

        var ctx_ptr = self._ctx_pool.acquire()
        var ctx = CoroStreamCtx(
            request=req^,
            caps=Capabilities.for_h3(is_early_data=stream_is_zr),
            stream_id=sid,
            extra_data=self._extra_data,
        )

        ctx_ptr.unsafe_write(ctx^)
        self._streams[stream_id] = PtrBox[CoroStreamCtx](ctx_ptr)

        # Run handler synchronously — Path A simplification.
        self._run_handler(stream_id)
        # Mark this stream for draining (handler may have queued response data).
        if self._has_stream(stream_id):
            self._pending_response_streams.append(stream_id)

    def _on_trailers(mut self, sid: Int, var trailers: Headers) raises:
        """Push the request trailers into the RecvBody and end it."""
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.unsafe_take_pointee()
        ctx.recv_body._push(BodyFrame.trailers(trailers^))
        if not ctx.request_ended:
            ctx.request_ended = True
            ctx.recv_body._set_end()
        ctx_ptr.unsafe_write(ctx^)
        self._maybe_cleanup_stream(sid)

    def _on_data(mut self, sid: Int, var data: List[Byte]) raises:
        """DATA_RECEIVED: push data into RecvBody.
        No flow-control ACK — QUIC handles FC internally."""
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.unsafe_take_pointee()
        ctx.recv_body._push(BodyFrame.data(data^))
        ctx_ptr.unsafe_write(ctx^)

    def _on_stream_ended(mut self, ev: H3Event) raises:
        """STREAM_ENDED: mark the body as ended."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        if ctx_ptr[].request_ended:
            return
        var ctx = ctx_ptr.unsafe_take_pointee()
        ctx.request_ended = True
        ctx.recv_body._set_end()
        ctx_ptr.unsafe_write(ctx^)
        self._maybe_cleanup_stream(sid)

    def _on_stream_reset(mut self, ev: H3Event) raises:
        """STREAM_RESET: tear down the stream and cancel any unfinished
        response, so the QUIC stream can be freed."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        self._h3.cancel_send_side(ev.stream_id)
        var ctx_ptr = self._streams[sid].ptr()
        _ = self._streams.pop(sid)
        _free_stream(ctx_ptr)

    def _on_goaway(mut self, ev: H3Event) raises:
        """GOAWAY_RECEIVED / CONNECTION_CLOSED: free all open streams.
        The handler has already returned synchronously, so there is nothing
        to wake up — just reclaim memory."""
        var keys = List[Int](capacity=len(self._streams))
        for key in self._streams.keys():
            keys.append(key)
        for ref sid in keys:
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            _ = self._streams.pop(sid)
            _free_stream(ctx_ptr)

    # --- Response draining --------------------------------------------------

    def _drain_responses(mut self, now: UInt64) raises:
        """Send what the handlers that ran since the last pass staged (1xx, head, body, end); a raise or send error fails only that stream."""
        var pending = self._pending_response_streams^
        self._pending_response_streams = List[Int]()
        for sid in pending:
            if not self._has_stream(sid):
                continue
            ref ctx = self._streams[sid].ptr()[]
            if pump_or_fail(self._h3, sid, ctx.resp_writer, ctx.headers_sent, ctx.response_ended, ctx.failure, ctx.request_ended):
                self._cleanup_stream(sid)
