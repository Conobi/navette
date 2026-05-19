# src/h3/h3_handler_server.mojo
#
# H3HandlerServer[H: StreamHandler] — server adapter.
# Drives a StreamHandler from an H3Connection. Sans-I/O.
# Mirrors src/h2/h2_handler_server.mojo patterns.

from std.collections import Dict, Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.quic.connection import QuicConnection
from navette.quic.profile import AcceptProfile, monotonic_us, PROFILE_ACCEPT
from navette.h3.connection import H3Connection, H3Event
from navette.h3.qpack import QpackHeaderField
from navette.http.handler import (
    StreamHandler,
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
    ALPN_H3,
)
from navette.http.request import Request, RequestBody
from navette.http.headers import Headers
from navette.http.method import Method
from navette.http.version import Version
from navette.http.body import BodyFrame


# ---------------------------------------------------------------------------
# _H3StreamCtx — per-stream context (heap-allocated, Movable)
# ---------------------------------------------------------------------------


struct _H3StreamCtx(Movable):
    var recv_body:      RecvBody
    var resp_writer:    ResponseWriter
    var detached:       Bool
    var request_ended:  Bool
    var response_ended: Bool
    var headers_sent:   Bool

    def __init__(out self):
        self.recv_body = RecvBody()
        self.resp_writer = ResponseWriter()
        self.detached = False
        self.request_ended = False
        self.response_ended = False
        self.headers_sent = False

    def __init__(out self, *, deinit take: Self):
        self.recv_body = take.recv_body^
        self.resp_writer = take.resp_writer^
        self.detached = take.detached
        self.request_ended = take.request_ended
        self.response_ended = take.response_ended
        self.headers_sent = take.headers_sent


# ---------------------------------------------------------------------------
# _H3StreamPtr — thin Copyable+Movable wrapper around heap pointer
# ---------------------------------------------------------------------------


struct _H3StreamPtr(Copyable, Movable):
    var addr: UInt64

    def __init__(out self, addr: UInt64):
        self.addr = addr

    def __init__(out self, *, other: Self):
        self.addr = other.addr

    def __init__(out self, *, deinit take: Self):
        self.addr = take.addr

    def ptr(self) -> UnsafePointer[_H3StreamCtx, MutAnyOrigin]:
        return UnsafePointer[_H3StreamCtx, MutAnyOrigin](unsafe_from_address=Int(self.addr))


# ---------------------------------------------------------------------------
# H3HandlerServer
# ---------------------------------------------------------------------------


struct H3HandlerServer[H: StreamHandler](Movable):
    """Drive a StreamHandler from an H3Connection. Sans-I/O."""

    var _h3:      H3Connection
    var handler:  Self.H
    var _streams: Dict[Int, _H3StreamPtr]
    var profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]

    def __init__(
        out self,
        *,
        var quic: QuicConnection,
        var handler: Self.H,
        profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]
            = UnsafePointer[AcceptProfile, MutAnyOrigin](unsafe_from_address=0),
    ) raises:
        self._h3 = H3Connection.server(quic^)
        self.handler = handler^
        self._streams = Dict[Int, _H3StreamPtr]()
        self.profile_ptr = profile_ptr
        # Shape B threading: H3Connection.server/.client have ~15 call sites
        # in src/h3/ and tests/; we set profile_ptr post-construction here
        # rather than threading it through 15 call sites.
        self._h3.profile_ptr = profile_ptr

    def __init__(out self, *, deinit take: Self):
        self._h3 = take._h3^
        self.handler = take.handler^
        self._streams = take._streams^
        self.profile_ptr = take.profile_ptr

    def __del__(deinit self):
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

    # --- Transport API -------------------------------------------------------

    def feed_datagram(mut self, data: Span[UInt8, _], now: UInt64) raises:
        self._h3.feed_datagram(data, now)
        self._dispatch_h3_events(now)
        if self._h3.is_established():
            self._drain_responses(now)

    def feed_datagram_from_buffer(
        mut self,
        buf: UnsafePointer[UInt8, MutAnyOrigin],
        buf_len: Int,
        now: UInt64,
    ) raises:
        """Feed one inbound QUIC datagram from a mutable buffer (zero-copy)."""
        self._h3.feed_datagram_from_buffer(buf, buf_len, now)

        # Bracket _dispatch_h3_events
        var t_dispatch_start: UInt64 = 0
        comptime if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                t_dispatch_start = monotonic_us()
        self._dispatch_h3_events(now)
        comptime if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                self.profile_ptr[].record_h3_dispatch(monotonic_us() - t_dispatch_start)

        # Bracket _drain_responses (only when established)
        if self._h3.is_established():
            var t_drain_resp_start: UInt64 = 0
            comptime if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    t_drain_resp_start = monotonic_us()
            self._drain_responses(now)
            comptime if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    self.profile_ptr[].record_h3_drain_resp(monotonic_us() - t_drain_resp_start)

    def drain_datagrams(mut self, now: UInt64) raises -> List[List[UInt8]]:
        return self._h3.drain_datagrams(now)

    def should_close(self) -> Bool:
        return self._h3.is_closed()

    def send_goaway(mut self, last_stream_id: UInt64) raises:
        """Send GOAWAY via the underlying H3Connection."""
        self._h3.send_goaway(last_stream_id)

    # --- Internal: event dispatch --------------------------------------------

    def _dispatch_h3_events(mut self, now: UInt64) raises:
        while True:
            var ev_opt = self._h3.poll_event()
            if not ev_opt:
                break
            var ev = ev_opt.unsafe_take()
            if ev.kind == H3Event.HEADERS_RECEIVED:
                self._on_request(ev, now)
            elif ev.kind == H3Event.DATA_RECEIVED:
                self._on_data(ev)
            elif ev.kind == H3Event.STREAM_ENDED:
                self._on_stream_ended(ev)
            elif ev.kind == H3Event.STREAM_RESET:
                self._on_stream_reset(ev)

    def _on_request(mut self, ev: H3Event, now: UInt64) raises:
        """Parse pseudo-headers from QPACK fields, build Request, invoke handler."""
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

        var body = RecvBody()
        var resp = ResponseWriter()

        try:
            self.handler.on_request(req^, body, resp, Capabilities.for_h3())
        except:
            pass

        var detached = body._state == 3

        var ctx_ptr = _heap_alloc[_H3StreamCtx](1).as_any_origin()
        var ctx = _H3StreamCtx()
        ctx.recv_body = body^
        ctx.resp_writer = resp^
        ctx.detached = detached
        ctx_ptr.init_pointee_move(ctx^)
        self._streams[Int(ev.stream_id)] = _H3StreamPtr(UInt64(Int(ctx_ptr)))

    def _on_data(mut self, ev: H3Event) raises:
        var sid = Int(ev.stream_id)
        if sid not in self._streams:
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var data_copy = List[UInt8](copy=ev.data)
        ctx.recv_body._push(BodyFrame.data(data_copy^))
        if not ctx.detached:
            try:
                self.handler.on_body_available(ctx.recv_body, ctx.resp_writer)
            except:
                pass
        ctx_ptr.init_pointee_move(ctx^)

    def _on_stream_ended(mut self, ev: H3Event) raises:
        var sid = Int(ev.stream_id)
        if sid not in self._streams:
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        if ctx.request_ended:
            ctx_ptr.init_pointee_move(ctx^)
            return
        ctx.request_ended = True
        ctx.recv_body._set_end()
        if not ctx.detached:
            try:
                self.handler.on_request_end(ctx.recv_body, ctx.resp_writer)
            except:
                pass
        ctx_ptr.init_pointee_move(ctx^)

    def _on_stream_reset(mut self, ev: H3Event) raises:
        var sid = Int(ev.stream_id)
        if sid not in self._streams:
            return
        var p = self._streams[sid].copy()
        var ctx_ptr = p.ptr()
        var ctx = ctx_ptr.take_pointee()
        var err = StreamError.rst_stream(UInt32(ev.error_code))
        self.handler.on_reset(err)
        _ = self._streams.pop(sid)
        ctx_ptr.free()

    # --- Internal: response drain --------------------------------------------

    def _drain_responses(mut self, now: UInt64) raises:
        """For each open stream: send response headers then body frames."""
        var sids = List[Int]()
        for key in self._streams.keys():
            sids.append(key)
        for i in range(len(sids)):
            var sid = sids[i]
            if sid not in self._streams:
                continue
            var ctx_ptr = self._streams[sid].ptr()
            var ctx = ctx_ptr.take_pointee()
            if ctx.response_ended:
                ctx_ptr.init_pointee_move(ctx^)
                self._maybe_cleanup(sid)
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
                # Build QPACK fields: :status first, then headers
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
            self._maybe_cleanup(sid)

    def _maybe_cleanup(mut self, sid: Int) raises:
        """Free stream context if both sides are done."""
        if sid not in self._streams:
            return
        var p = self._streams[sid].copy()
        var ctx_ptr = p.ptr()
        if ctx_ptr[].request_ended and ctx_ptr[].response_ended:
            _ = self._streams.pop(sid)
            ctx_ptr.destroy_pointee()
            ctx_ptr.free()
