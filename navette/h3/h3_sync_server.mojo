# src/h3/h3_sync_server.mojo
#
# HTTP/3 server-side adapter — sans-IO codec wrapper. Feed inbound QUIC
# datagrams via `feed_datagram_from_buffer()`; drain outbound datagrams via
# `drain()`. Translates H3Connection events into a per-stream hand-written
# state machine, NOT stackful coroutines (Sprint 2A Path A — mirrors
# Sprint 1's H2CoroServer over QUIC).
#
# The "Coro" in `CoroStreamCtx` is preserved to mirror the H2 sister-file's
# naming (Sprint 1 chose to leave it that way to minimise churn). A future
# rename pass can unify both names — out of scope here.
#
# See plans/2026-04-27-sprint-2a-h1h3-sync.md.

from std.collections import Dict, Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.sys.info import size_of

from navette.quic.connection import QuicConnection
from navette.h3.connection import H3Connection, H3Event
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
from navette.util.ptrbox import PtrBox


# ---------------------------------------------------------------------------
# H3BodyFn — synchronous handler invoked once per request.
# ---------------------------------------------------------------------------
#
# The handler receives a pointer to the per-stream context, reads
# `ctx.request` (or for streaming POST bodies, polls `ctx.recv_body`),
# and writes the response into `ctx.resp_writer`. It runs to completion
# in one call — no `yield_to_caller`. Streaming-handler use cases are
# served by `src/h3/h3_streaming_server.mojo` (Plan 2B).

comptime H3BodyFn = def (
    UnsafePointer[CoroStreamCtx, MutAnyOrigin]
) thin raises -> None


# ---------------------------------------------------------------------------
# CoroStreamCtx — per-stream state (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct CoroStreamCtx(Movable):
    """Per-stream context for H3 serving. Heap-allocated so the
    adapter and the handler can reach it via pointer. Holds the
    request, body receiver, response writer, capabilities, and
    request/response bookkeeping.

    No `coro_addr` field (Sprint 2A Path A — handler runs synchronously).
    No `unacked_bytes` (QUIC handles flow control internally).
    Stream IDs are UInt64 (QUIC uses 62-bit stream IDs, wider than H2's UInt32).
    """

    var request: Request
    var recv_body: RecvBody
    var resp_writer: ResponseWriter
    var caps: Capabilities
    var stream_id: UInt64
    var extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var request_ended: Bool
    var response_ended: Bool
    var headers_sent: Bool

    def __init__(
        out self,
        var request: Request,
        caps: Capabilities,
        stream_id: UInt64,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin],
    ):
        self.request = request^
        self.recv_body = RecvBody()
        self.resp_writer = ResponseWriter()
        self.caps = Capabilities(other=caps)
        self.stream_id = stream_id
        self.extra_data = extra_data
        self.request_ended = False
        self.response_ended = False
        self.headers_sent = False

    def __init__(out self, *, deinit take: Self):
        self.request = take.request^
        self.recv_body = take.recv_body^
        self.resp_writer = take.resp_writer^
        self.caps = take.caps^
        self.stream_id = take.stream_id
        self.extra_data = take.extra_data
        self.request_ended = take.request_ended
        self.response_ended = take.response_ended
        self.headers_sent = take.headers_sent


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


def _free_stream(ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]):
    """Hard-destroy the CoroStreamCtx allocation."""
    ctx_ptr.destroy_pointee()
    ctx_ptr.free()


# ---------------------------------------------------------------------------
# CoroStreamCtxPool — per-connection allocation pool
# ---------------------------------------------------------------------------
#
# Recycles `CoroStreamCtx`-sized heap blocks across requests on the same
# connection. Capacity 16 mirrors the prior H2 default and matches
# typical h2load / h3load `-m 10` active-streams-per-connection.


struct CoroStreamCtxPool(Movable):
    """Free-list of typed `CoroStreamCtx`-sized heap blocks. Caller
    owns initialisation/destruction of the pointee; the pool only
    manages the underlying memory."""

    var _free: List[UnsafePointer[CoroStreamCtx, MutAnyOrigin]]
    var _capacity: Int

    def __init__(out self, *, capacity: Int = 16):
        self._free = List[UnsafePointer[CoroStreamCtx, MutAnyOrigin]]()
        self._capacity = capacity

    def __init__(out self, *, deinit take: Self):
        self._free = take._free^
        self._capacity = take._capacity

    def __del__(deinit self):
        for i in range(len(self._free)):
            self._free[i].free()

    def acquire(mut self) raises -> UnsafePointer[CoroStreamCtx, MutAnyOrigin]:
        """Take a free slot if one is available, else allocate fresh."""
        if len(self._free) > 0:
            return self._free.pop()
        return _heap_alloc[CoroStreamCtx](1).as_any_origin()

    def release(
        mut self, ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]
    ):
        """Return a slot whose pointee has already been destroyed.
        Beyond capacity → free; under capacity → keep for reuse."""
        if len(self._free) < self._capacity:
            self._free.append(ptr)
        else:
            ptr.free()

    def idle_count(self) -> Int:
        return len(self._free)


# ---------------------------------------------------------------------------
# H3CoroServer — server adapter using a per-stream state machine
# ---------------------------------------------------------------------------


struct H3CoroServer(Movable):
    """Drive per-stream state from an HTTP/3 H3Connection. Sans-IO:
    the caller feeds inbound QUIC datagrams via `feed_datagram_from_buffer()`
    and drains outbound datagrams via `drain()`. Each stream's user handler
    runs synchronously when the request arrives (Sprint 2A Path A — no
    stackful coroutines).

    Note: `_h3: H3Connection` already wraps and owns the `QuicConnection`
    internally (H3Connection._quic field). A separate top-level `_quic`
    field is intentionally absent to avoid double-ownership — mirrors
    H3CoroServer and H3HandlerServer patterns.
    """

    var _h3: H3Connection
    var _body_fn: H3BodyFn
    var _extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var _outbuf: List[List[UInt8]]
    var _streams: Dict[Int, PtrBox[CoroStreamCtx]]
    var _ctx_pool: CoroStreamCtxPool

    # --- Constructors -------------------------------------------------------

    def __init__(
        out self,
        *,
        var quic: QuicConnection,
        body_fn: H3BodyFn,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin] = UnsafePointer[
            NoneType, MutExternalOrigin
        ](unsafe_from_address=0),
    ) raises:
        """Create with a server-side QuicConnection."""
        _check_stream_ctx_size()
        self._h3 = H3Connection.server(quic^)
        self._body_fn = body_fn
        self._extra_data = extra_data
        self._outbuf = List[List[UInt8]]()
        self._streams = Dict[Int, PtrBox[CoroStreamCtx]]()
        self._ctx_pool = CoroStreamCtxPool(capacity=16)

    def __init__(out self, *, deinit take: Self):
        self._h3 = take._h3^
        self._body_fn = take._body_fn
        self._extra_data = take._extra_data
        self._outbuf = take._outbuf^
        self._streams = take._streams^
        self._ctx_pool = take._ctx_pool^

    def __del__(deinit self):
        """Destroy and free all heap-allocated stream contexts."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            try:
                var ctx_ptr = self._streams[keys[i]].ptr()
                _free_stream(ctx_ptr)
            except:
                pass

    # --- Transport bridging API ---------------------------------------------

    def feed_datagram_from_buffer(
        mut self,
        buf: UnsafePointer[UInt8, MutAnyOrigin],
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

    def feed_datagram(mut self, data: Span[UInt8, _], now: UInt64) raises:
        """Feed one inbound QUIC datagram. Dispatches H3 events and drains
        pending response data."""
        self._h3.feed_datagram(data, now)
        self._dispatch_h3_events(now)
        if self._h3.is_established():
            self._drain_responses(now)
        self._flush_outbound(now)

    def drain(mut self) -> List[List[UInt8]]:
        """Drain queued outbound QUIC datagrams for the transport to write."""
        var out = self._outbuf^
        self._outbuf = List[List[UInt8]]()
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
        mut self, ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]
    ):
        """Destroy the CoroStreamCtx pointee and return its memory block to the
        per-connection pool (or free if over capacity)."""
        ctx_ptr.destroy_pointee()
        self._ctx_pool.release(ctx_ptr)

    def _flush_outbound(mut self, now: UInt64) raises:
        """Move pending outbound QUIC datagrams from the H3Connection into our
        buffer."""
        var pending = self._h3.drain_datagrams(now)
        for i in range(len(pending)):
            self._outbuf.append(pending[i].copy())

    def _run_handler(mut self, stream_id: Int) raises:
        """Invoke the user handler synchronously. On error, send RST_STREAM
        and clean up. On success, response data is in `ctx.resp_writer` for
        `_drain_responses` to flush."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        try:
            self._body_fn(ctx_ptr)
        except e:
            try:
                self._h3.reset_stream(UInt64(stream_id), H3_REQUEST_CANCELLED)
            except:
                pass
            self._cleanup_stream(stream_id)

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
            # informational only — no per-stream action needed in the sync path.

    def _on_request(mut self, ev: H3Event) raises:
        """First HEADERS_RECEIVED: parse pseudo-fields into Request, allocate
        CoroStreamCtx on heap, register in streams dict, and run the handler
        synchronously (Path A — no coroutine spawn).
        If ev.fin==True (bodyless GET), set request_ended + recv_body._set_end()."""
        var method_str = String("GET")
        var path_str = String("/")
        var authority_str = String("")
        var user_headers = Headers()

        for i in range(len(ev.fields)):
            var name = ev.fields[i].name
            var value = ev.fields[i].value
            if name == ":method":
                method_str = value
            elif name == ":path":
                path_str = value
            elif name == ":authority":
                authority_str = value
            elif name == ":scheme":
                pass
            else:
                user_headers.add(name, value)

        var req_headers = Headers()
        if authority_str != "":
            req_headers.add("host", authority_str)
        for i in range(len(user_headers)):
            req_headers.add(user_headers.name_at(i), user_headers.value_at(i))

        var req = Request(
            method=Method.custom(method_str),
            target=path_str,
            version=Version.http_3(),
            headers=req_headers^,
        )

        var stream_id = Int(ev.stream_id)

        var ctx_ptr = self._ctx_pool.acquire()
        var ctx = CoroStreamCtx(
            request=req^,
            caps=Capabilities.for_h3(),
            stream_id=ev.stream_id,
            extra_data=self._extra_data,
        )

        # FIN on HEADERS = bodyless request (e.g. GET) — mark ended immediately
        if ev.fin:
            ctx.recv_body._set_end()
            ctx.request_ended = True

        ctx_ptr.init_pointee_move(ctx^)
        self._streams[stream_id] = PtrBox[CoroStreamCtx](ctx_ptr)

        # Run handler synchronously — Path A simplification.
        self._run_handler(stream_id)

    def _on_trailers(mut self, ev: H3Event) raises:
        """Second HEADERS_RECEIVED on an open stream = trailers.
        Push as BodyFrame.trailers (skip pseudo-headers)."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var trailer_headers = Headers()
        for i in range(len(ev.fields)):
            var name = ev.fields[i].name
            if not name.startswith(":"):
                trailer_headers.add(name, ev.fields[i].value)
        ctx.recv_body._push(BodyFrame.trailers(trailer_headers^))
        if not ctx.request_ended:
            ctx.request_ended = True
            ctx.recv_body._set_end()
        ctx_ptr.init_pointee_move(ctx^)
        self._maybe_cleanup_stream(sid)

    def _on_data(mut self, ev: H3Event) raises:
        """DATA_RECEIVED: push data into RecvBody.
        No flow-control ACK — QUIC handles FC internally."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var data_copy = List[UInt8](copy=ev.data)
        ctx.recv_body._push(BodyFrame.data(data_copy^))
        ctx_ptr.init_pointee_move(ctx^)

    def _on_stream_ended(mut self, ev: H3Event) raises:
        """STREAM_ENDED: mark the body as ended."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        if ctx_ptr[].request_ended:
            return
        var ctx = ctx_ptr.take_pointee()
        ctx.request_ended = True
        ctx.recv_body._set_end()
        ctx_ptr.init_pointee_move(ctx^)
        self._maybe_cleanup_stream(sid)

    def _on_stream_reset(mut self, ev: H3Event) raises:
        """STREAM_RESET: tear down the stream."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        _ = self._streams.pop(sid)
        _free_stream(ctx_ptr)

    def _on_goaway(mut self, ev: H3Event) raises:
        """GOAWAY_RECEIVED / CONNECTION_CLOSED: free all open streams.
        The handler has already returned synchronously, so there is nothing
        to wake up — just reclaim memory."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            var sid = keys[i]
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            _ = self._streams.pop(sid)
            _free_stream(ctx_ptr)

    # --- Response draining --------------------------------------------------

    def _drain_responses(mut self, now: UInt64) raises:
        """Drain pending response data from stream contexts into the H3Connection.
        Uses take_pointee/init_pointee_move to safely interleave ctx access
        with self._h3 mutations.

        R-2A-3: H3HandlerServer._drain_responses has identical logic but operates
        on _H3StreamCtx (not CoroStreamCtx) so it cannot be called directly here.
        Ported verbatim from h3_coro_server.mojo; flagged for Sprint 4 dedup pass."""
        var stream_ids = List[Int]()
        for key in self._streams.keys():
            stream_ids.append(key)
        for i in range(len(stream_ids)):
            var sid = stream_ids[i]
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            var ctx = ctx_ptr.take_pointee()
            if ctx.response_ended:
                ctx_ptr.init_pointee_move(ctx^)
                self._maybe_cleanup_stream(sid)
                continue
            if not ctx.headers_sent and not ctx.resp_writer._has_status():
                ctx_ptr.init_pointee_move(ctx^)
                continue
            # Send response headers
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
            # Drain body frames
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
                        self._h3.send_data(UInt64(sid), List[UInt8](), True)
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
            ctx_ptr.init_pointee_move(ctx^)
            self._maybe_cleanup_stream(sid)
