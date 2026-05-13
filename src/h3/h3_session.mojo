# src/h3/h3_session.mojo
#
# H3Session — HTTP/3 client session implementing the Session trait.
# Mirrors src/h2/h2_session.mojo patterns for the QUIC/H3 stack.

from std.collections import Dict
from std.collections.deque import Deque
from std.collections.optional import Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from src.quic.connection import QuicConnection
from src.h3.connection import H3Connection, H3Event
from src.h3.qpack import QpackHeaderField
from src.http.handler import Capabilities, StreamError, ALPN_H3
from src.http.session import Session, RequestHandle
from src.http.request import Request
from src.http.response import Response
from src.http.headers import Headers
from src.http.status import StatusCode
from src.http.version import Version
from src.http.body import BodyFrame
from src.http.method import Method


# ---------------------------------------------------------------------------
# _H3ClientCtx — per-stream client context (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct _H3ClientCtx(Movable):
    """Per-stream client state that lives on the heap.  Move-only types
    prevent direct Dict storage, so we heap-allocate and store via
    _H3ClientPtr."""

    var handle_id:  UInt64
    var status_code: Int
    var headers:    Headers
    var body_data:  List[UInt8]
    var complete:   Bool
    var errored:    Bool
    var error_code: UInt64

    def __init__(out self, *, handle_id: UInt64):
        self.handle_id = handle_id
        self.status_code = -1
        self.headers = Headers()
        self.body_data = List[UInt8]()
        self.complete = False
        self.errored = False
        self.error_code = UInt64(0)

    def __init__(out self, *, deinit take: Self):
        self.handle_id = take.handle_id
        self.status_code = take.status_code
        self.headers = take.headers^
        self.body_data = take.body_data^
        self.complete = take.complete
        self.errored = take.errored
        self.error_code = take.error_code


# ---------------------------------------------------------------------------
# _H3ClientPtr — thin Copyable+Movable wrapper around heap pointer
# ---------------------------------------------------------------------------


struct _H3ClientPtr(Copyable, Movable):
    """Holds the address of a heap-allocated _H3ClientCtx as a UInt64."""

    var addr: UInt64

    def __init__(out self, addr: UInt64):
        self.addr = addr

    def __init__(out self, *, other: Self):
        self.addr = other.addr

    def __init__(out self, *, deinit take: Self):
        self.addr = take.addr

    def ptr(self) -> UnsafePointer[_H3ClientCtx, MutAnyOrigin]:
        return UnsafePointer[_H3ClientCtx, MutAnyOrigin](
            unsafe_from_address=Int(self.addr)
        )


# ---------------------------------------------------------------------------
# H3Session — client session adapter
# ---------------------------------------------------------------------------


struct H3Session(Session):
    """HTTP/3 client session.  Sans-I/O: the caller feeds/drains datagrams.
    Supports multiple concurrent streams (multiplexed over QUIC)."""

    var _h3:               H3Connection
    var _streams:          Dict[Int, _H3ClientPtr]
    var _handle_to_stream: Dict[Int, Int]
    var _next_id:          UInt64
    var received_goaway:   Bool

    # --- Constructors -------------------------------------------------------

    def __init__(out self, *, var quic: QuicConnection) raises:
        """Wrap a client-side QuicConnection."""
        self._h3 = H3Connection.client(quic^)
        self._streams = Dict[Int, _H3ClientPtr]()
        self._handle_to_stream = Dict[Int, Int]()
        self._next_id = UInt64(0)
        self.received_goaway = False

    def __init__(out self, *, deinit take: Self):
        self._h3 = take._h3^
        self._streams = take._streams^
        self._handle_to_stream = take._handle_to_stream^
        self._next_id = take._next_id
        self.received_goaway = take.received_goaway

    fn __del__(deinit self):
        """Free all heap-allocated client stream contexts."""
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

    # --- Transport API (called by test pumps) --------------------------------

    def feed_datagram(mut self, data: Span[UInt8, _], now: UInt64) raises:
        """Feed one inbound QUIC datagram; dispatches resulting H3Events."""
        self._h3.feed_datagram(data, now)
        self._dispatch_events()

    def drain_datagrams(mut self, now: UInt64) raises -> List[List[UInt8]]:
        """Drain outbound QUIC datagrams."""
        return self._h3.drain_datagrams(now)

    # --- Session trait API --------------------------------------------------

    def submit(mut self, var req: Request) raises -> RequestHandle:
        """Open a new bidi stream, send request headers (+body), return a handle."""
        self._next_id += UInt64(1)
        var handle_id = self._next_id

        # Build QPACK pseudo-headers
        var fields = List[QpackHeaderField]()
        fields.append(QpackHeaderField(":method", String(req.method)))
        fields.append(QpackHeaderField(":path", req.target))
        fields.append(QpackHeaderField(":scheme", "https"))
        fields.append(QpackHeaderField(":authority", "localhost"))
        # Forward any regular (non-pseudo) headers
        for i in range(len(req.headers)):
            var name = req.headers.name_at(i)
            var value = req.headers.value_at(i)
            if not name.startswith(":"):
                fields.append(QpackHeaderField(name, value))

        # Determine if there is a body
        var is_stream = req.body.is_stream()
        var has_body = req.body.is_buffered() and len(req.body.bytes()) > 0
        # For stream bodies: send headers without fin, skip body
        # (caller will use feed_body to send data frames).
        var fin_on_headers = not has_body and not is_stream

        var stream_id = self._h3.open_bidi_stream()
        self._h3.send_headers(stream_id, fields, fin_on_headers)

        if has_body:
            var body_bytes = req.body.bytes().copy()
            self._h3.send_data(stream_id, body_bytes, True)

        # Allocate client context on heap
        var ctx_ptr = _heap_alloc[_H3ClientCtx](1).as_any_origin()
        var ctx = _H3ClientCtx(handle_id=handle_id)
        ctx_ptr.init_pointee_move(ctx^)
        self._streams[Int(stream_id)] = _H3ClientPtr(UInt64(Int(ctx_ptr)))
        self._handle_to_stream[Int(handle_id)] = Int(stream_id)

        return RequestHandle(id=handle_id)

    def run_until(mut self, mut handle_ids: Deque[UInt64]) raises:
        """Dispatch any pending H3 events (transport pump is caller-driven)."""
        self._dispatch_events()

    def run_one(mut self, mut handle: RequestHandle) raises:
        """Deliver a completed response to handle if the stream is done."""
        var hid = Int(handle.id())
        var stream_id: Int
        try:
            stream_id = self._handle_to_stream[hid]
        except:
            return

        # Dispatch any pending events first
        self._dispatch_events()

        var ctx_wrap: _H3ClientPtr
        try:
            ctx_wrap = _H3ClientPtr(other=self._streams[stream_id])
        except:
            return
        var ctx_ptr = ctx_wrap.ptr()

        # Error path: stream was reset before response headers arrived
        if ctx_ptr[].errored and not handle.is_complete():
            var ec = UInt32(ctx_ptr[].error_code)
            handle._set_error(StreamError.rst_stream(ec))
            ctx_ptr.destroy_pointee()
            ctx_ptr.free()
            try:
                _ = self._streams.pop(stream_id)
                _ = self._handle_to_stream.pop(hid)
            except:
                pass
            return

        # Happy path: response complete, not yet delivered
        if ctx_ptr[].status_code >= 0 and ctx_ptr[].complete and not handle.has_headers():
            var ctx = ctx_ptr.take_pointee()
            # Swap owned fields out of ctx so ctx can drop cleanly with empty fields
            var resp_headers = ctx.headers^
            ctx.headers = Headers()
            var body_data = ctx.body_data^
            ctx.body_data = List[UInt8]()
            var status_code = ctx.status_code
            # Build response
            var body_frames = List[BodyFrame]()
            if len(body_data) > 0:
                body_frames.append(BodyFrame.data(body_data^))
            var resp = Response(
                status=StatusCode(status_code),
                reason=String(""),
                version=Version.http_3(),
                headers=resp_headers^,
                body=body_frames^,
            )
            handle._set_response(resp^)
            handle._mark_complete()
            # Remove from Dicts then free heap allocation; ctx drops with empty fields
            _ = self._streams.pop(stream_id)
            _ = self._handle_to_stream.pop(hid)
            ctx_ptr.free()

    def capabilities(self) -> Capabilities:
        return Capabilities.for_h3()

    def alpn(self) -> Int:
        return ALPN_H3

    def close(deinit self) raises:
        """Send GOAWAY and free all heap-allocated stream contexts."""
        if not self._h3.is_closed():
            try:
                self._h3.send_goaway(UInt64(0))
            except:
                pass
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

    def feed_body(mut self, handle_id: UInt64, var frame: BodyFrame) raises:
        var hid = Int(handle_id)
        if hid not in self._handle_to_stream:
            raise Error("H3Session.feed_body: unknown handle")
        var stream_id = UInt64(self._handle_to_stream[hid])
        if frame.is_data():
            var bytes_copy = frame.data().copy()
            self._h3.send_data(stream_id, bytes_copy^, False)
        elif frame.is_end():
            self._h3.send_data(stream_id, List[UInt8](), True)

    # --- Internal: event dispatch --------------------------------------------

    def _dispatch_events(mut self) raises:
        """Drain all pending H3Events and route to per-stream handlers."""
        while True:
            var ev_opt = self._h3.poll_event()
            if not ev_opt:
                break
            var ev = ev_opt.unsafe_take()
            if ev.kind == H3Event.HEADERS_RECEIVED:
                self._on_response_headers(ev)
            elif ev.kind == H3Event.DATA_RECEIVED:
                self._on_response_data(ev)
            elif ev.kind == H3Event.STREAM_ENDED:
                self._on_stream_ended(ev)
            elif ev.kind == H3Event.STREAM_RESET:
                self._on_stream_reset(ev)
            elif ev.kind == H3Event.GOAWAY_RECEIVED:
                self.received_goaway = True

    def _on_response_headers(mut self, ev: H3Event) raises:
        """Parse :status and regular headers from HEADERS_RECEIVED event."""
        var sid = Int(ev.stream_id)
        var ctx_ptr: UnsafePointer[_H3ClientCtx, MutAnyOrigin]
        try:
            ctx_ptr = self._streams[sid].ptr()
        except:
            return
        var ctx = ctx_ptr.take_pointee()
        for i in range(len(ev.fields)):
            var name = ev.fields[i].name
            var value = ev.fields[i].value
            if name == ":status":
                try:
                    ctx.status_code = atol(value)
                except:
                    ctx.status_code = 200
            elif not name.startswith(":"):
                ctx.headers.add(name, value)
        if ev.fin:
            ctx.complete = True
        ctx_ptr.init_pointee_move(ctx^)

    def _on_response_data(mut self, ev: H3Event) raises:
        """Accumulate DATA_RECEIVED payload; mark complete on fin."""
        var sid = Int(ev.stream_id)
        var ctx_ptr: UnsafePointer[_H3ClientCtx, MutAnyOrigin]
        try:
            ctx_ptr = self._streams[sid].ptr()
        except:
            return
        var ctx = ctx_ptr.take_pointee()
        for i in range(len(ev.data)):
            ctx.body_data.append(ev.data[i])
        if ev.fin:
            ctx.complete = True
        ctx_ptr.init_pointee_move(ctx^)

    def _on_stream_ended(mut self, ev: H3Event) raises:
        """STREAM_ENDED: mark stream complete."""
        var sid = Int(ev.stream_id)
        var ctx_ptr: UnsafePointer[_H3ClientCtx, MutAnyOrigin]
        try:
            ctx_ptr = self._streams[sid].ptr()
        except:
            return
        var ctx = ctx_ptr.take_pointee()
        ctx.complete = True
        ctx_ptr.init_pointee_move(ctx^)

    def _on_stream_reset(mut self, ev: H3Event) raises:
        """STREAM_RESET: mark stream errored."""
        var sid = Int(ev.stream_id)
        var ctx_ptr: UnsafePointer[_H3ClientCtx, MutAnyOrigin]
        try:
            ctx_ptr = self._streams[sid].ptr()
        except:
            return
        var ctx = ctx_ptr.take_pointee()
        ctx.errored = True
        ctx.error_code = ev.error_code
        ctx.complete = True
        ctx_ptr.init_pointee_move(ctx^)
