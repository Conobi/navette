# src/h3/h3_streaming_server.mojo
#
# HTTP/3 server-side adapter for STREAMING handlers. Each stream gets a
# 64 KiB stackful coroutine (bouclette.coroutine) so the handler can suspend
# across upstream I/O boundaries (LLM token emission, SSE, gRPC server-
# streaming, reverse proxy, file upload). Companion to
# `src/h3/h3_sync_server.mojo` — that's the default tier; this is opt-in.
#
# R8' compile-time budget: size_of[H3StreamingCtx]() < 96 KiB.
# R1' grep gate: this file IS allowed to import bouclette.coroutine.
#
# Backpressure note: write_chunk calls H3Connection.send_data
# directly and returns. H3 does not surface FC backpressure to the caller;
# QUIC's per-stream FC absorbs slow consumers transparently. No WouldBlock
# handling is needed at this layer. If the handler emits faster than the
# QUIC stream window can accept, the data accumulates in QuicConnection's
# send buffers (bounded by the QUIC stream window). Production rate
# limiting is the handler's responsibility, not the streaming-server's.
#
# API note: bouclette's coroutine handle is `Coroutine[State]`, parametric on a
# typed state value that both the caller and the body can reach. This adapter
# instantiates it with `State = Pointer[H3StreamingCtx, MutUntrackedOrigin]`,
# so a body declared as `CoroutineBody[H3StreamingState]`, i.e.
#   def (mut Yielder[H3StreamingState]) raises -> None
# recovers its per-stream ctx with a plain `yld.state()[]` — no untyped
# `user_data()` pointer and no `bitcast`, so a handler written against the
# wrong ctx type is a compile error rather than a type confusion at runtime.
#
# `Yielder.suspend()` is the suspension primitive. The helper functions
# next_chunk / write_chunk / finish wrap it, so handlers call them directly.
#
# `Coroutine` is a LINEAR type (`@explicit_destroy`, `Deinitable where False`):
# it has no destructor, and every path that drops one must call `close()` or
# the 64 KiB mmap'd stack leaks. `close()` further requires the coroutine to be
# in CREATED or DONE state, so every teardown path here calls `cancel()` first
# — that drains a SUSPENDED body to DONE, swallowing errors. See
# `_free_streaming_stream` (both the method and the module-level twin), which
# are the only two places that release a coroutine.
#
# HANDLER CONTRACT: a body must never suspend unconditionally. `cancel()`
# resumes the body in a loop until it returns, so a body that suspends
# without ever checking `yld.is_cancelled()` (or `ctx.cancelled`) makes
# connection teardown spin — bouclette's 1000-iteration debug_assert catches
# that in a checked build, but a release build would livelock. The
# next_chunk / write_chunk helpers below poll both flags, so handlers built
# from them are safe by construction; handlers that call `yld.suspend()`
# directly must poll one of the two themselves.

from std.collections import Dict, Optional
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc
from std.sys.info import size_of

from bouclette.coroutine import (
    Coroutine,
    CoroutineBody,
    StackPool,
    Yielder,
)

from navette.quic.connection import QuicConnection
from navette.h3.connection import H3Connection, H3Event
from navette.h3.early_data_filter_dispatch import (
    apply_early_data_filter, send_425_response, stream_is_zero_rtt,
)
from navette.h3.error import H3_REQUEST_CANCELLED
from navette.h3.qpack import QpackHeaderField
from navette.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from navette.http.body import BodyFrame
from navette.http.headers import Headers
from navette.http.method import Method
from navette.http.request import Request
from navette.http.status import StatusCode
from navette.http.version import Version
from navette.quic.profile import AcceptProfile
from navette.tls.early_data_filter import (
    EarlyDataPredicateFn,
    IdempotentOnlyFilter,
)
from navette.util.ctx_pool import CtxPool
from navette.util.ptrbox import PtrBox
from navette.util.null_ptr import null_ptr


# ---------------------------------------------------------------------------
# Coroutine type aliases — typed state channel
# ---------------------------------------------------------------------------
#
# The coroutine's typed state IS the per-stream ctx pointer. The ctx itself
# stays owned by the adapter (`_streams` + `CtxPool`) because
# non-coroutine code must reach it while the body is suspended AND after the
# body has returned — `_drain_responses` flushes the frames buffered by
# `finish()` on a later event-loop pass, which is strictly after the coroutine
# reaches DONE.
#
# Inside the body, access the per-stream ctx via:
#   var ctx_ptr = yld.state()[]
#
# The handler may call next_chunk(ctx_ptr, yld) / write_chunk(ctx_ptr, yld, bytes)
# / finish(ctx_ptr, yld) to suspend across event-loop passes.

comptime H3StreamingState = Pointer[H3StreamingCtx, MutUntrackedOrigin]
"""Typed coroutine state for H3 streaming: a pointer to the per-stream ctx."""

comptime H3StreamingCoro = Coroutine[H3StreamingState]
"""Caller-side coroutine handle for one H3 request stream (linear type)."""

comptime H3StreamingYielder = Yielder[H3StreamingState]
"""Coroutine-side handle handed to an H3 streaming handler body."""

comptime H3StreamingHandlerFn = CoroutineBody[H3StreamingState]
"""Handler signature: `def (mut Yielder[H3StreamingState]) raises -> None`."""


# ---------------------------------------------------------------------------
# H3StreamingCtx — per-stream state (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct H3StreamingCtx(Movable):
    """Per-stream context for H3 streaming serving. Heap-allocated so
    both the adapter and the coroutine body can access it via pointer.

    Extends the sync-server CoroStreamCtx shape with:
      - body_frame_ring: incoming body frames drained by next_chunk()
      - cancelled:       set true by adapter on peer reset / GOAWAY
      - coro_addr:       address of the heap slot holding this stream's
                         H3StreamingCoro (null = none). The slot is owned by
                         the ctx; `_free_streaming_stream` is the only place
                         that cancel()s + close()s and frees it.

    No writer_pending_chunk field — Option A: write_chunk does not suspend
    on backpressure; QUIC's send_data absorbs output transparently.
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
    var body_frame_ring: List[BodyFrame]
    var cancelled: Bool
    var coro_addr: PtrBox[H3StreamingCoro]

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
        self.body_frame_ring = List[BodyFrame]()
        self.cancelled = False
        self.coro_addr = PtrBox[H3StreamingCoro].null()

    def coro_ptr(self) -> Pointer[H3StreamingCoro, MutUntrackedOrigin]:
        """Typed pointer into the coro's heap slot (null if none)."""
        return self.coro_addr.ptr()


# ---------------------------------------------------------------------------
# Per-stream memory budget (R8' in the sprint roadmap)
# ---------------------------------------------------------------------------
#
# The 64 KiB stack (bouclette.coroutine default) is mmap'd by the StackPool and
# reached through coro_addr; it is not counted toward H3StreamingCtx's
# direct size. The struct itself holds: Request + RecvBody + ResponseWriter +
# Capabilities + stream_id + extra_data + coro_addr + 3 bools + body_frame_ring +
# cancelled bool. Should land around the same size as the sync ctx (~600 B)
# plus the body_frame_ring overhead (List[BodyFrame] = pointer + len + cap = ~24 B
# header + variable content). Streaming ctx total: well under 96 KiB.


def _check_streaming_ctx_size():
    comptime assert size_of[H3StreamingCtx]() < 96 * 1024, (
        "H3StreamingCtx exceeded R8' budget (96 KiB) — investigate"
        " before raising the cap"
    )


# ---------------------------------------------------------------------------
# Streaming-handler API helpers (Option A — direct call, no WouldBlock)
# ---------------------------------------------------------------------------


def next_chunk(
    ctx_ptr: Pointer[mut=True, T=H3StreamingCtx, origin=_],
    mut yld: H3StreamingYielder,
) raises -> Optional[BodyFrame]:
    """Yield the next body chunk. Suspends if none ready. Returns None on EOF.

    Polls cancellation between suspends, from BOTH sources: `ctx.cancelled`
    (set by the adapter on peer reset / GOAWAY) and `yld.is_cancelled()` (set
    by `Coroutine.cancel()`). Honouring the coroutine's own flag is what makes
    `cancel()` terminate — it resumes the body in a loop until DONE, so a body
    that only watched `ctx.cancelled` would spin forever if the adapter ever
    cancelled without setting it.

    Args:
        ctx_ptr: Pointer to this stream's context.
        yld: The coroutine-side yielder for this stream.

    Returns:
        The next BodyFrame, or None once the request body has ended.

    Raises:
        `H3StreamCancelled` if the stream is cancelled while waiting.
    """
    while not ctx_ptr[].request_ended and len(ctx_ptr[].body_frame_ring) == 0:
        if ctx_ptr[].cancelled or yld.is_cancelled():
            raise Error("H3StreamCancelled")
        yld.suspend()
    if len(ctx_ptr[].body_frame_ring) > 0:
        # FIFO: pop(0) preserves arrival order. Default pop() is LIFO and
        # would deliver multi-chunk bodies to the handler in reverse order.
        var frame = ctx_ptr[].body_frame_ring.pop(0)
        return Optional[BodyFrame](frame^)
    return Optional[BodyFrame](None)


def write_chunk(
    ctx_ptr: Pointer[mut=True, T=H3StreamingCtx, origin=_],
    mut yld: H3StreamingYielder,
    var bytes: List[Byte],
) raises:
    """Buffer a body chunk for the adapter to send. Does NOT suspend on
    backpressure — H3's send_data does not surface WouldBlock; QUIC's
    per-stream FC absorbs slow consumers internally. If the handler emits
    faster than the QUIC stream window can accept, data accumulates in
    QuicConnection's internal buffers.

    The actual H3Connection.send_data call happens in the streaming server's
    _drain_responses on the next event-loop pass — write_chunk just buffers
    the chunk into ctx.resp_writer for the drain to pick up.

    Args:
        ctx_ptr: Pointer to this stream's context.
        yld: The coroutine-side yielder; consulted for cancellation only,
            since this helper never suspends.
        bytes: The chunk to buffer (ownership transferred in).

    Raises:
        `H3StreamCancelled` if the stream has been cancelled.
    """
    if ctx_ptr[].cancelled or yld.is_cancelled():
        raise Error("H3StreamCancelled")
    # Buffer the data into resp_writer via try_send_body.
    # The adapter's _drain_responses calls H3Connection.send_data with
    # this content + fin=False on each event-loop pass.
    var frame = BodyFrame.data(bytes^)
    _ = ctx_ptr[].resp_writer.try_send_body(frame^)


def finish(
    ctx_ptr: Pointer[mut=True, T=H3StreamingCtx, origin=_],
    mut yld: H3StreamingYielder,
) raises:
    """Close the response body. The handler should return immediately after
    this call. Adapter's _drain_responses sends the final FIN on the next
    event-loop pass.

    Design note: finish() is synchronous — it buffers the end BodyFrame into
    resp_writer but does NOT suspend. The handler returns and the coro reaches
    DONE state. On the next feed_datagram call, _drain_responses processes the
    buffered end frame and sets response_ended=True.

    Why no suspend here? If finish() suspended, the coro would be SUSPENDED
    when _maybe_cleanup_stream (called from _on_stream_ended) runs, and
    `Coroutine.close()` debug_asserts on a non-CREATED/DONE phase. Keeping
    finish() synchronous avoids that invariant violation and is simpler: the
    handler just returns and the coro is DONE.

    Args:
        ctx_ptr: Pointer to this stream's context.
        yld: The coroutine-side yielder, accepted for API symmetry with
            next_chunk / write_chunk; unused because finish never suspends.
    """
    ctx_ptr[].resp_writer.end()


def cancelled(ctx_ptr: Pointer[mut=True, T=H3StreamingCtx, origin=_]) -> Bool:
    """Report whether the adapter has cancelled this stream.

    Args:
        ctx_ptr: Pointer to this stream's context.

    Returns:
        True once the adapter has flagged the stream cancelled.
    """
    return ctx_ptr[].cancelled


# ---------------------------------------------------------------------------
# _free_streaming_stream — DESTRUCTOR-PATH-ONLY cleanup for H3StreamingCtx
# ---------------------------------------------------------------------------


def _release_coro(ctx_ptr: Pointer[mut=True, T=H3StreamingCtx, origin=_]):
    """Cancel, close and free this stream's coroutine, if it still has one.

    `Coroutine` is linear: it has no destructor, so dropping the heap slot
    without `close()` leaks a 64 KiB mmap'd stack — one per request, which on
    a server is an unbounded DoS vector. `close()` in turn debug_asserts
    unless the coroutine is CREATED or DONE, so a still-SUSPENDED body must
    first be drained by `cancel()`, which resumes it until it returns and
    swallows any error it raises on the way out. `cancel()` is a no-op on an
    already-DONE coroutine, so this is safe to call on every path.

    `ctx.cancelled` is set first so handlers that poll the ctx flag (rather
    than `yld.is_cancelled()`) also unwind on the very first resume.

    Idempotent: clears `coro_addr` so a double call cannot double-free.

    Args:
        ctx_ptr: Pointer to the stream context owning the coroutine slot.
    """
    if not ctx_ptr[].coro_addr.is_some():
        return
    var coro_p = ctx_ptr[].coro_ptr()
    ctx_ptr[].coro_addr = PtrBox[H3StreamingCoro].null()
    ctx_ptr[].cancelled = True
    coro_p[].cancel()
    var coro = coro_p.unsafe_take_pointee()
    coro^.close()
    coro_p.unsafe_free()


def _free_streaming_stream(ctx_ptr: Pointer[mut=True, T=H3StreamingCtx, origin=_]):
    """DESTRUCTOR PATH ONLY. Bypasses the ctx pool. Runtime sites must use
    H3StreamingServer._free_streaming_stream() instead — this module-level
    variant exists only because __deinit__(deinit self) cannot call mut-self
    methods. ALWAYS call _streams.pop(sid) BEFORE calling this function.

    Args:
        ctx_ptr: Pointer to the stream context to tear down and free.
    """
    _release_coro(ctx_ptr)
    ctx_ptr.unsafe_deinit_pointee()
    ctx_ptr.unsafe_free()




# ---------------------------------------------------------------------------
# H3StreamingServer — server adapter using per-stream stackful coroutines
# ---------------------------------------------------------------------------


struct H3StreamingServer(Movable):
    """Drive per-stream stackful coroutines from an HTTP/3 H3Connection.
    Sans-IO: the caller feeds inbound QUIC datagrams via
    `feed_datagram_from_buffer()` and drains outbound datagrams via `drain()`.
    Each new request spawns an H3StreamingCoro on a stack borrowed from a
    per-connection `StackPool`, which suspends and resumes as body data and
    write-drains occur.

    Note: `_h3: H3Connection` already wraps and owns the `QuicConnection`
    internally (H3Connection._quic field). A separate top-level `_quic`
    field is intentionally absent to avoid double-ownership — mirrors
    H3CoroServer and H3HandlerServer patterns.

    The handler function must match H3StreamingHandlerFn:
        def (mut Yielder[H3StreamingState]) raises -> None
    Access per-stream ctx inside the handler via:
        var ctx_ptr = yld.state()[]
    """

    var _h3: H3Connection
    var _handler_fn: H3StreamingHandlerFn
    var _extra_data: Pointer[NoneType, MutUntrackedOrigin]
    var _outbuf: List[List[Byte]]
    var _streams: Dict[Int, PtrBox[H3StreamingCtx]]
    var _ctx_pool: CtxPool[H3StreamingCtx]
    var _coro_pool: StackPool
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

    # --- Constructors -------------------------------------------------------

    def __init__(
        out self,
        *,
        var quic: QuicConnection,
        handler_fn: H3StreamingHandlerFn,
        extra_data: Pointer[NoneType, MutUntrackedOrigin] = null_ptr[
            NoneType, MutUntrackedOrigin
        ](),
        early_data_filter_ptr: Optional[
            Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]
        ] = None,
        predicate_fn: Optional[EarlyDataPredicateFn] = None,
    ) raises:
        """Create with a server-side QuicConnection."""
        _check_streaming_ctx_size()
        self._h3 = H3Connection.server(quic^)
        self._handler_fn = handler_fn
        self._extra_data = extra_data
        self._outbuf = List[List[Byte]]()
        self._streams = Dict[Int, PtrBox[H3StreamingCtx]]()
        self._ctx_pool = CtxPool[H3StreamingCtx](capacity=4)
        self._coro_pool = StackPool(capacity=4)
        self._early_data_filter_ptr = early_data_filter_ptr
        self._early_data_predicate_fn = predicate_fn

    def __deinit__(deinit self):
        """Close every live coroutine and free all heap-allocated contexts.

        Uses the module-level `_free_streaming_stream`, which drains each
        coroutine to DONE via `cancel()` before `close()`. Without that, a
        connection torn down mid-request would drop SUSPENDED coroutines and
        leak their stacks.
        """
        var keys = List[Int](capacity=len(self._streams))
        for key in self._streams.keys():
            keys.append(key)
        for ref key in keys:
            try:
                _free_streaming_stream(self._streams[key].ptr())
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

    def drain(mut self) -> List[List[Byte]]:
        """Drain queued outbound QUIC datagrams for the transport to write."""
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

    def _free_streaming_stream(
        mut self, ctx_ptr: Pointer[H3StreamingCtx, MutUntrackedOrigin]
    ):
        """Cancel + close the stream's coroutine, destroy the H3StreamingCtx,
        and return the
        ctx slot to the per-connection pool. The pool's release() decides
        whether to keep the slot for reuse (under capacity) or free it
        (beyond capacity), so this restores the freelist that earlier
        revisions silently bypassed by calling ctx_ptr.free() directly.
        ALWAYS call _streams.pop(sid) BEFORE invoking this method.

        Args:
            ctx_ptr: Pointer to the stream context to tear down.
        """
        _release_coro(ctx_ptr)
        ctx_ptr.unsafe_deinit_pointee()
        self._ctx_pool.release(ctx_ptr)

    def _flush_outbound(mut self, now: UInt64) raises:
        """Move pending outbound QUIC datagrams from H3Connection into buffer."""
        var pending = self._h3.drain_datagrams(now)
        for ref pkt in pending:
            self._outbuf.append(pkt.copy())

    def _cleanup_stream(mut self, stream_id: Int) raises:
        """Unconditionally free stream context and remove from dict."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        _ = self._streams.pop(stream_id)
        self._free_streaming_stream(ctx_ptr)

    def _maybe_cleanup_stream(mut self, stream_id: Int) raises:
        """Free stream if both request and response sides are done."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        if ctx_ptr[].request_ended and ctx_ptr[].response_ended:
            _ = self._streams.pop(stream_id)
            self._free_streaming_stream(ctx_ptr)

    def _resume_stream(mut self, sid: Int) raises:
        """Resume the coroutine for stream sid. On error, set cancelled + free.

        When the coro finishes normally (DONE after finish() returns), the
        stream is NOT freed here. Instead, _drain_responses will drain the
        queued end BodyFrame, set response_ended=True, and _maybe_cleanup_stream
        will free the stream. This deferred cleanup ensures response data is
        actually sent before the H3StreamingCtx is freed."""
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        if not ctx_ptr[].coro_addr.is_some():
            return
        var coro_p = ctx_ptr[].coro_ptr()
        if not coro_p[].can_resume():
            # Coroutine already done — nothing to do here; drain will handle cleanup
            return
        try:
            coro_p[].resume()
        except e:
            # Handler raised an error — send RST, clean up
            try:
                self._h3.reset_stream(UInt64(sid), H3_REQUEST_CANCELLED)
            except:
                pass
            _ = self._streams.pop(sid)
            self._free_streaming_stream(ctx_ptr)
            return
        # Coro finished or suspended — if done, drain will clean up via
        # _maybe_cleanup_stream (called at end of _drain_responses).
        # No immediate pop/free here.

    # --- Event dispatch -----------------------------------------------------

    def _dispatch_h3_events(mut self, now: UInt64) raises:
        """Poll and dispatch all pending H3 events."""
        while True:
            var ev_opt = self._h3.poll_event()
            if not ev_opt:
                break
            var ev = ev_opt.unsafe_take()
            if ev.kind == H3Event.HEADERS_RECEIVED:
                if Int(ev.stream_id) not in self._streams:
                    self._on_request(ev)
                else:
                    self._on_trailers(ev)
            elif ev.kind == H3Event.DATA_RECEIVED:
                self._on_data(ev)
            elif ev.kind == H3Event.STREAM_ENDED:
                self._on_stream_ended(ev)
            elif ev.kind == H3Event.STREAM_RESET:
                self._on_stream_reset(ev)
            elif ev.kind == H3Event.GOAWAY_RECEIVED or ev.kind == H3Event.CONNECTION_CLOSED:
                self._on_goaway(ev)
            # H3Event.HANDSHAKE_COMPLETE and H3Event.SETTINGS_RECEIVED are
            # informational only — no per-stream action needed.

    def _on_request(mut self, ev: H3Event) raises:
        """First HEADERS_RECEIVED: parse pseudo-fields into Request, allocate
        an H3StreamingCtx plus its H3StreamingCoro (on a stack borrowed from
        the per-connection StackPool), register in the streams dict, and do
        the first resume.
        If ev.fin==True (bodyless GET), set request_ended + recv_body._set_end().

        Args:
            ev: The HEADERS_RECEIVED event opening this stream.

        Raises:
            If coroutine creation fails; the partially built context is
            released before the error propagates, so no stream is leaked.
        """
        var method_str = String("GET")
        var path_str = String("/")
        var authority_str = String("")
        var user_headers = Headers()
        for ref field in ev.fields:
            var name = field.name
            var value = field.value
            if name == ":method":
                method_str = value
            elif name == ":path":
                path_str = value
            elif name == ":authority":
                authority_str = value
            elif name == ":scheme":
                pass
            else:
                user_headers.add_lowercase(name, value)

        var req_headers = Headers()
        if authority_str != "":
            req_headers.add_lowercase("host", authority_str)
        for i in range(len(user_headers)):
            req_headers.add_lowercase(user_headers.name_at(i), user_headers.value_at(i))

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
        # `Early-Data: 1` into req_headers. The streaming adapter has no
        # profile_ptr field (counter routing is owned by H3HandlerServer),
        # so the helper is called with `profile_ptr=None`.
        var stream_is_zr = False
        if self._h3._quic.zrtt.enabled:
            stream_is_zr = stream_is_zero_rtt(self._h3._quic, ev.stream_id)
            var _no_profile = Optional[
                Pointer[AcceptProfile, MutUntrackedOrigin]
            ](None)
            var outcome = apply_early_data_filter(
                method_str,
                path_str,
                stream_is_zr,
                self._early_data_filter_ptr,
                self._early_data_predicate_fn,
                req_headers,
                _no_profile,
            )
            if outcome.should_send_425():
                send_425_response(ev.stream_id, self._h3)
                return

        var req = Request(
            method=Method.custom(method_str),
            target=path_str,
            version=Version.http_3(),
            headers=req_headers^,
        )

        var stream_id = Int(ev.stream_id)

        # Allocate ctx from pool
        var ctx_ptr = self._ctx_pool.acquire()
        var ctx = H3StreamingCtx(
            request=req^,
            caps=Capabilities.for_h3(is_early_data=stream_is_zr),
            stream_id=ev.stream_id,
            extra_data=self._extra_data,
        )

        # FIN on HEADERS = bodyless request (e.g. GET) — mark ended immediately
        if ev.fin:
            ctx.request_ended = True
            ctx.recv_body._set_end()

        ctx_ptr.unsafe_write(ctx^)

        # Spawn the coroutine on a pooled stack. Its typed state IS ctx_ptr,
        # so the body reaches the context with yld.state()[] — no untyped
        # user_data pointer and no bitcast.
        #
        # The coroutine is a linear type and cannot live in a Dict, so it is
        # boxed in its own heap slot that the ctx owns. If either the slot
        # allocation or the coroutine construction fails, the already-written
        # ctx would otherwise be orphaned (it is not yet in self._streams and
        # nothing else holds its pointer), so unwind it here before re-raising.
        var coro_heap = _heap_alloc[H3StreamingCoro](1)
        try:
            coro_heap.unsafe_write(
                H3StreamingCoro(self._handler_fn, ctx_ptr, self._coro_pool)
            )
        except e:
            coro_heap.unsafe_free()
            ctx_ptr.unsafe_deinit_pointee()
            self._ctx_pool.release(ctx_ptr)
            raise e^
        ctx_ptr[].coro_addr = PtrBox[H3StreamingCoro](coro_heap)

        # Insert BEFORE first resume so _drain_responses can find the stream
        self._streams[stream_id] = PtrBox[H3StreamingCtx](ctx_ptr)

        # First resume: runs handler until first suspend or completion
        self._resume_stream(stream_id)

    def _on_trailers(mut self, ev: H3Event) raises:
        """Second HEADERS_RECEIVED on an open stream = trailers.
        Push as BodyFrame.trailers into body_frame_ring, resume coroutine."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.unsafe_take_pointee()
        var trailer_headers = Headers()
        for ref field in ev.fields:
            var name = field.name
            if not name.startswith(":"):
                trailer_headers.add(name, field.value)
        ctx.body_frame_ring.append(BodyFrame.trailers(trailer_headers^))
        if not ctx.request_ended:
            ctx.request_ended = True
            ctx.recv_body._set_end()
        ctx_ptr.unsafe_write(ctx^)
        self._resume_stream(sid)

    def _on_data(mut self, ev: H3Event) raises:
        """DATA_RECEIVED: push data into body_frame_ring, resume coroutine.
        No flow-control ACK — QUIC handles FC internally."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.unsafe_take_pointee()
        var data_copy = List[Byte](copy=ev.data)
        ctx.body_frame_ring.append(BodyFrame.data(data_copy^))
        ctx_ptr.unsafe_write(ctx^)
        self._resume_stream(sid)

    def _on_stream_ended(mut self, ev: H3Event) raises:
        """STREAM_ENDED: mark body ended, resume coroutine."""
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
        self._resume_stream(sid)
        self._maybe_cleanup_stream(sid)

    def _on_stream_reset(mut self, ev: H3Event) raises:
        """STREAM_RESET / STOP_SENDING: pop the stream, then tear it down.

        `_free_streaming_stream` sets ctx.cancelled and drains the coroutine
        to DONE with `cancel()` before closing it, so a handler suspended
        mid-body unwinds instead of leaving a SUSPENDED coroutine that
        `close()` would refuse. An unfinished response is cancelled so the
        QUIC stream can be freed.
        """
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        self._h3.cancel_send_side(ev.stream_id)
        var ctx_ptr = self._streams[sid].ptr()
        _ = self._streams.pop(sid)  # pop BEFORE free
        # _free_streaming_stream sets cancelled and drains the coro to DONE.
        self._free_streaming_stream(ctx_ptr)

    def _on_goaway(mut self, ev: H3Event) raises:
        """GOAWAY_RECEIVED / CONNECTION_CLOSED: tear down ALL streams.

        Each stream is popped before being freed; `_free_streaming_stream`
        cancels and drains its coroutine to DONE before closing it.

        Args:
            ev: The GOAWAY / CONNECTION_CLOSED event (unused; the whole
                connection is going away).
        """
        var keys = List[Int](capacity=len(self._streams))
        for key in self._streams.keys():
            keys.append(key)
        for ref sid in keys:
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            _ = self._streams.pop(sid)  # pop BEFORE free
            # _free_streaming_stream sets cancelled and drains the coro to DONE.
            self._free_streaming_stream(ctx_ptr)

    # --- Response draining --------------------------------------------------

    def _drain_responses(mut self, now: UInt64) raises:
        """Drain pending response data from stream contexts into H3Connection.
        Uses take_pointee/init_pointee_move to safely interleave ctx access
        with self._h3 mutations.

        For streaming: the handler may have written multiple chunks via
        write_chunk (buffered into resp_writer) across several suspends.
        This drain sends them in order with fin=False; when response_ended
        is set (by finish()), the next drain sends the terminal FIN."""
        var stream_ids = List[Int](capacity=len(self._streams))
        for key in self._streams.keys():
            stream_ids.append(key)
        for ref sid in stream_ids:
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            var ctx = ctx_ptr.unsafe_take_pointee()
            if not ctx.headers_sent and not ctx.resp_writer._has_status():
                ctx_ptr.unsafe_write(ctx^)
                continue
            # Send response headers if not yet sent
            if not ctx.headers_sent and ctx.resp_writer._has_status():
                var status_opt = ctx.resp_writer._take_status()
                var headers_opt = ctx.resp_writer._take_headers()
                var status = status_opt.unsafe_take()
                var resp_headers: Headers
                if Bool(headers_opt):
                    resp_headers = headers_opt.unsafe_take()
                else:
                    resp_headers = Headers()
                var fields = List[QpackHeaderField]()
                fields.append(QpackHeaderField(":status", String(Int(status.code()))))
                for j in range(len(resp_headers)):
                    fields.append(QpackHeaderField(resp_headers.name_at(j), resp_headers.value_at(j)))
                try:
                    self._h3.send_headers(UInt64(sid), fields, False)
                except:
                    pass
                ctx.headers_sent = True
            # Drain body frames written by write_chunk / finish
            while True:
                var f_opt = ctx.resp_writer._pop_body_frame()
                if not Bool(f_opt):
                    break
                var f = f_opt.unsafe_take()
                if f.is_data():
                    var data_copy = f.data().copy()
                    try:
                        self._h3.send_data(UInt64(sid), data_copy^, False)
                    except:
                        pass
                elif f.is_end():
                    try:
                        self._h3.send_data(UInt64(sid), List[Byte](), True)
                    except:
                        pass
                    ctx.response_ended = True
                    break
                elif f.is_trailers():
                    var trailer_hdrs = f.trailers().copy()
                    var t_fields = List[QpackHeaderField]()
                    for j in range(len(trailer_hdrs)):
                        t_fields.append(QpackHeaderField(trailer_hdrs.name_at(j), trailer_hdrs.value_at(j)))
                    try:
                        self._h3.send_headers(UInt64(sid), t_fields, True)
                    except:
                        pass
                    ctx.response_ended = True
                    break
            ctx_ptr.unsafe_write(ctx^)
            self._maybe_cleanup_stream(sid)
