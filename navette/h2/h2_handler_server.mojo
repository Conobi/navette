# src/h2/h2_handler_server.mojo
#
# HTTP/2 server-side handler adapter.  Sans-I/O: feed inbound wire bytes,
# drain outbound bytes.  Translates H2Connection events into StreamHandler
# lifecycle callbacks.  (M5.5 Task 4)

from std.collections import Dict
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from .connection import (
    H2Connection,
    H2Config,
    H2Event,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_TRAILERS_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
)
from navette.http.handler import (
    StreamHandler,
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
    ALPN_H2,
)
from navette.http.body import BodyFrame
from navette.http.headers import Headers
from navette.http.request import Request
from navette.h2.config import h2_production_config
from navette.h2.pseudo_headers import (
    request_from_h2_headers,
    response_to_h2_headers,
    headers_from_h2,
    headers_to_h2,
)


# ---------------------------------------------------------------------------
# _StreamCtx — per-stream context (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct _StreamCtx(Movable):
    """Per-stream state that lives on the heap.  RecvBody and ResponseWriter
    are move-only, so this struct cannot go in a Dict directly."""

    var recv_body: RecvBody
    var resp_writer: ResponseWriter
    var detached: Bool
    var request_ended: Bool
    var response_ended: Bool
    var headers_sent: Bool
    var unacked_bytes: Int

    def __init__(out self):
        self.recv_body = RecvBody()
        self.resp_writer = ResponseWriter()
        self.detached = False
        self.request_ended = False
        self.response_ended = False
        self.headers_sent = False
        self.unacked_bytes = 0

    def __init__(out self, *, deinit take: Self):
        self.recv_body = take.recv_body^
        self.resp_writer = take.resp_writer^
        self.detached = take.detached
        self.request_ended = take.request_ended
        self.response_ended = take.response_ended
        self.headers_sent = take.headers_sent
        self.unacked_bytes = take.unacked_bytes


# ---------------------------------------------------------------------------
# _StreamPtr — thin wrapper so Dict[Int, _StreamPtr] satisfies
# CollectionElement (Copyable + Movable) even if UnsafePointer does not.
# ---------------------------------------------------------------------------


struct _StreamPtr(Copyable, Movable):
    """Holds the address of a heap-allocated _StreamCtx as a UInt64."""

    var addr: UInt64

    def __init__(out self, addr: UInt64):
        self.addr = addr

    def __init__(out self, *, other: Self):
        self.addr = other.addr

    def __init__(out self, *, deinit take: Self):
        self.addr = take.addr

    def ptr(self) -> UnsafePointer[_StreamCtx, MutAnyOrigin]:
        return UnsafePointer[_StreamCtx, MutAnyOrigin](
            unsafe_from_address=Int(self.addr)
        )


# ---------------------------------------------------------------------------
# H2HandlerServer — server adapter
# ---------------------------------------------------------------------------


struct H2HandlerServer[H: StreamHandler](Movable):
    """Drive a StreamHandler from an HTTP/2 H2Connection.  Sans-I/O:
    the caller feeds inbound bytes via `feed()` and drains outbound bytes
    via `drain()`.  Multiplexed streams are tracked in a Dict keyed by
    stream ID."""

    var _conn: H2Connection
    var handler: Self.H
    var _outbuf: List[UInt8]
    var _streams: Dict[Int, _StreamPtr]

    # --- Constructors -------------------------------------------------------

    def __init__(out self, *, var handler: Self.H) raises:
        """Create with default production config (server-side)."""
        self._conn = H2Connection(
            client_side=False,
            config=h2_production_config(client_side=False),
        )
        self._conn.initiate_connection()
        self.handler = handler^
        self._outbuf = List[UInt8]()
        self._streams = Dict[Int, _StreamPtr]()
        self._flush_outbound()

    def __init__(out self, *, var handler: Self.H, config: H2Config) raises:
        """Create with a custom H2Config (server-side)."""
        self._conn = H2Connection(client_side=False, config=config)
        self._conn.initiate_connection()
        self.handler = handler^
        self._outbuf = List[UInt8]()
        self._streams = Dict[Int, _StreamPtr]()
        self._flush_outbound()

    def __init__(out self, *, deinit take: Self):
        self._conn = take._conn^
        self.handler = take.handler^
        self._outbuf = take._outbuf^
        self._streams = take._streams^

    fn __del__(deinit self):
        """Destroy and free all heap-allocated stream contexts."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            try:
                var p = self._streams[keys[i]].ptr()
                p.destroy_pointee()
                p.free()
            except:
                pass

    # --- Transport bridging API ---------------------------------------------

    def feed(mut self, data: Span[UInt8, _]) raises:
        """Feed inbound transport bytes, dispatch events, drain responses."""
        var data_list = List[UInt8]()
        for i in range(len(data)):
            data_list.append(data[i])
        var events = self._conn.receive_data(data_list)
        self._dispatch_events(events)
        self._drain_responses()
        self._flush_outbound()

    def drain(mut self) -> List[UInt8]:
        """Drain queued outbound bytes for the transport to write."""
        var out = self._outbuf^
        self._outbuf = List[UInt8]()
        return out^

    def should_close(self) -> Bool:
        """True when the H2 connection has reached terminal state."""
        return self._conn.is_closed()

    # --- Internal -----------------------------------------------------------

    def _has_stream(self, sid: Int) -> Bool:
        """Check whether stream ID is present in the streams dict."""
        return sid in self._streams

    def _flush_outbound(mut self):
        """Move pending outbound bytes from the H2Connection into our buffer."""
        var pending = self._conn.data_to_send()
        for i in range(len(pending)):
            self._outbuf.append(pending[i])

    def _dispatch_events(mut self, mut events: List[H2Event]) raises:
        """Dispatch H2 events to handler callbacks."""
        for i in range(len(events)):
            var evt = H2Event(other=events[i])
            if evt.kind == H2_EVT_REQUEST_RECEIVED:
                self._on_request_received(evt)
            elif evt.kind == H2_EVT_DATA_RECEIVED:
                self._on_data_received(evt)
            elif evt.kind == H2_EVT_TRAILERS_RECEIVED:
                self._on_trailers_received(evt)
            elif evt.kind == H2_EVT_STREAM_ENDED:
                self._on_stream_ended(evt)
            elif evt.kind == H2_EVT_STREAM_RESET:
                self._on_stream_reset(evt)

    def _on_request_received(mut self, evt: H2Event) raises:
        """Handle a REQUEST_RECEIVED event: parse headers, allocate stream
        context, invoke handler.on_request, and optionally on_request_end."""
        var req = request_from_h2_headers(evt.stream_id, evt.headers)
        var stream_id = Int(evt.stream_id)
        var stream_ended = evt.stream_ended

        # Create RecvBody and ResponseWriter as locals.  We keep them local
        # through all handler callbacks, then move into the heap context at
        # the end.  This avoids the Mojo 0.26.2 limitation where you cannot
        # take a mut borrow through UnsafePointer dereference.
        var body = RecvBody()
        var resp = ResponseWriter()

        # If the request had END_STREAM, mark body as ended.
        if stream_ended:
            body._set_end()

        # Invoke handler with local mut borrows.
        self.handler.on_request(req^, body, resp, Capabilities.for_h2())

        # Check if handler detached the body (try_detach sets _state to 3).
        # RecvBody._state == 3 means _BODY_DETACHED (not publicly exported).
        var detached = body._state == 3

        # If stream already ended and handler didn't detach, fire on_request_end.
        if stream_ended and not detached:
            self.handler.on_request_end(body, resp)

        # Now allocate stream context on the heap and move locals in.
        var ctx_ptr = _heap_alloc[_StreamCtx](1).as_any_origin()
        var ctx = _StreamCtx()
        ctx.recv_body = body^
        ctx.resp_writer = resp^
        ctx.detached = detached
        ctx.request_ended = stream_ended
        ctx_ptr.init_pointee_move(ctx^)

        # Store in streams dict.
        self._streams[stream_id] = _StreamPtr(UInt64(Int(ctx_ptr)))

    def _on_data_received(mut self, evt: H2Event) raises:
        """Handle DATA_RECEIVED: push data into RecvBody, manage flow control,
        notify handler via on_body_available.  If the event carries
        END_STREAM, also mark the body ended and invoke on_request_end."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        # take_pointee moves the entire _StreamCtx out of the heap so we can
        # get mut borrows on body/resp without going through UnsafePointer.
        var ctx = ctx_ptr.take_pointee()
        # Push data into RecvBody
        if len(evt.data) > 0:
            var data_copy = evt.data.copy()
            ctx.recv_body._push(BodyFrame.data(data_copy^))
        # Flow control: acknowledge unless paused
        if not ctx.recv_body.is_paused():
            self._conn.acknowledge_received_data(
                evt.flow_controlled_length, evt.stream_id
            )
        else:
            ctx.unacked_bytes += evt.flow_controlled_length
        # Notify handler (if body not detached)
        if not ctx.detached:
            self.handler.on_body_available(ctx.recv_body, ctx.resp_writer)
        # Check if paused state cleared after handler consumed
        if ctx.unacked_bytes > 0 and not ctx.recv_body.is_paused():
            self._conn.acknowledge_received_data(
                ctx.unacked_bytes, evt.stream_id
            )
            ctx.unacked_bytes = 0
        # If END_STREAM was set on the DATA frame, mark body ended and
        # fire on_request_end.
        if evt.stream_ended and not ctx.request_ended:
            ctx.request_ended = True
            ctx.recv_body._set_end()
            if not ctx.detached:
                self.handler.on_request_end(ctx.recv_body, ctx.resp_writer)
        # Move back into the heap
        ctx_ptr.init_pointee_move(ctx^)
        # Check if both sides are done — if so, free the context
        if evt.stream_ended:
            self._maybe_cleanup_stream(sid)

    def _on_trailers_received(mut self, evt: H2Event) raises:
        """Handle TRAILERS_RECEIVED: convert headers, push as trailer BodyFrame.
        Trailers always carry END_STREAM (enforced by H2Connection), so also
        notify via on_body_available, mark body ended, fire on_request_end."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var trailer_headers = headers_from_h2(evt.headers)
        # take_pointee to get mut access to recv_body/resp_writer
        var ctx = ctx_ptr.take_pointee()
        ctx.recv_body._push(BodyFrame.trailers(trailer_headers^))
        # Notify handler that new body frames (trailers) are available
        if not ctx.detached:
            self.handler.on_body_available(ctx.recv_body, ctx.resp_writer)
        # Trailers always carry END_STREAM — mark body ended
        if not ctx.request_ended:
            ctx.request_ended = True
            ctx.recv_body._set_end()
            if not ctx.detached:
                self.handler.on_request_end(ctx.recv_body, ctx.resp_writer)
        ctx_ptr.init_pointee_move(ctx^)
        # Trailers carry END_STREAM — check if both sides done
        self._maybe_cleanup_stream(sid)

    def _on_stream_ended(mut self, evt: H2Event) raises:
        """Handle STREAM_ENDED: mark the body as ended, notify handler via
        on_request_end if not detached."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        # Read request_ended through the pointer (Bool is trivially copyable)
        if ctx_ptr[].request_ended:
            return  # already ended (e.g. END_STREAM on HEADERS)
        # take_pointee to get mut access to body/resp
        var ctx = ctx_ptr.take_pointee()
        ctx.request_ended = True
        ctx.recv_body._set_end()
        if not ctx.detached:
            self.handler.on_request_end(ctx.recv_body, ctx.resp_writer)
        # Move back into the heap
        ctx_ptr.init_pointee_move(ctx^)
        # Check if both sides done — if response already finished, free now
        self._maybe_cleanup_stream(sid)

    def _on_stream_reset(mut self, evt: H2Event) raises:
        """Handle STREAM_RESET: notify handler, clean up stream context."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var err = StreamError.rst_stream(evt.error_code)
        ctx.recv_body._set_error(StreamError(other=err))
        self.handler.on_reset(err)
        # Free heap memory — both directions are dead after RST.
        # ctx was already taken out; just free the allocation.
        ctx_ptr.free()
        # Remove from Dict.
        _ = self._streams.pop(sid)

    def _maybe_cleanup_stream(mut self, stream_id: Int) raises:
        """Free stream context if both request and response sides are done."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        # Read through pointer — Bool is trivially copyable
        if ctx_ptr[].request_ended and ctx_ptr[].response_ended:
            ctx_ptr.destroy_pointee()
            ctx_ptr.free()
            _ = self._streams.pop(stream_id)

    def _drain_responses(mut self) raises:
        """Drain pending response data from stream contexts into the H2
        connection.  For each open stream, send response headers if ready,
        then drain body frames (data, trailers, end)."""
        # Snapshot stream IDs to avoid mutating dict while iterating
        var stream_ids = List[Int]()
        for key in self._streams.keys():
            stream_ids.append(key)
        for i in range(len(stream_ids)):
            var sid = stream_ids[i]
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            # Use take_pointee to get mut access
            var ctx = ctx_ptr.take_pointee()
            var made_progress = False
            # Skip if response not started
            if not ctx.headers_sent and not ctx.resp_writer._has_status():
                ctx_ptr.init_pointee_move(ctx^)
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
                var h2_hdrs = response_to_h2_headers(status^, resp_headers^)
                self._conn.send_headers(UInt32(sid), h2_hdrs^, end_stream=False)
                ctx.headers_sent = True
                made_progress = True
            # Drain body frames
            while True:
                var f_opt = ctx.resp_writer._pop_body_frame()
                if not Bool(f_opt):
                    break
                var f = f_opt.unsafe_take()
                if f.is_data():
                    self._conn.send_data(
                        UInt32(sid), f.data().copy(), end_stream=False
                    )
                    made_progress = True
                elif f.is_end():
                    self._conn.send_data(
                        UInt32(sid), List[UInt8](), end_stream=True
                    )
                    ctx.response_ended = True
                    made_progress = True
                    break
                elif f.is_trailers():
                    var trailer_h2 = headers_to_h2(f.trailers())
                    self._conn.send_headers(
                        UInt32(sid), trailer_h2^, end_stream=True
                    )
                    ctx.response_ended = True
                    made_progress = True
                    break
            # Move back into the heap and maybe cleanup
            ctx_ptr.init_pointee_move(ctx^)
            if made_progress:
                self._maybe_cleanup_stream(sid)
