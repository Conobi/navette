# src/h3/h3_handler_server.mojo
#
# H3HandlerServer[H: StreamHandler] — server adapter.
# Drives a StreamHandler from an H3Connection. Sans-I/O.
# Mirrors src/h2/h2_handler_server.mojo patterns.

from std.collections import Dict, Optional
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc

from navette.quic.connection import QuicConnection
from navette.quic.cid import dcid_to_u64
from navette.quic.path import PathKey
from navette.quic.profile import AcceptProfile, monotonic_us, rdtsc, CallId, PROFILE_ACCEPT
from navette.h3.connection import H3Connection, H3Event
from navette.h3.early_data_filter_dispatch import (
    apply_early_data_filter, send_425_response, stream_is_zero_rtt,
)
from navette.h3.qpack import QpackHeaderField, QpackCodecTables
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
from navette.http.status import StatusCode
from navette.http.version import Version
from navette.http.body import BodyFrame
from navette.tls.early_data_filter import (
    EarlyDataPredicateFn,
    IdempotentOnlyFilter,
)
from navette.util.ptrbox import PtrBox


# ---------------------------------------------------------------------------
# PathKey → peer_addr string helper
# ---------------------------------------------------------------------------


def _hex_digit(v: Int) -> String:
    """Return a single lowercase hex character for a 4-bit value (0-15)."""
    if v < 10:
        return chr(ord("0") + v)
    return chr(ord("a") + v - 10)


def _path_key_to_peer_addr(key: PathKey) -> String:
    """Convert a PathKey to a human-readable peer address string.

    IPv4 addresses are formatted as ``a.b.c.d:port``.
    IPv6 addresses are formatted as ``[xxxx:xxxx:...]:port``.
    Zero/unknown families return an empty string.
    """
    if key.family == Int32(2):
        # AF_INET: last 4 bytes of the 16-byte addr buffer (PathKey.from_v4 layout).
        return (
            String(Int(key.addr[12])) + "." +
            String(Int(key.addr[13])) + "." +
            String(Int(key.addr[14])) + "." +
            String(Int(key.addr[15])) + ":" +
            String(Int(key.port))
        )
    elif key.family == Int32(10):
        # AF_INET6: all 16 bytes, grouped as 8 big-endian 16-bit words.
        var s = String("[")
        for i in range(8):
            if i > 0:
                s += ":"
            var hi = Int(key.addr[i * 2])
            var lo = Int(key.addr[i * 2 + 1])
            var word = hi * 256 + lo
            s += _hex_digit((word >> 12) & 0xF)
            s += _hex_digit((word >> 8) & 0xF)
            s += _hex_digit((word >> 4) & 0xF)
            s += _hex_digit(word & 0xF)
        s += "]:" + String(Int(key.port))
        return s
    return String("")


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


# ---------------------------------------------------------------------------
# H3HandlerServer
# ---------------------------------------------------------------------------


struct H3HandlerServer[H: StreamHandler](Movable):
    """Drive a StreamHandler from an H3Connection. Sans-I/O."""

    var _h3:      H3Connection
    var handler:  Self.H
    var _streams: Dict[Int, PtrBox[_H3StreamCtx]]
    var profile_ptr: Optional[Pointer[AcceptProfile, MutUntrackedOrigin]]
    # Optional pointer to the RFC 8470 idempotent-only filter owned by
    # the `QuicServerConfig` that birthed this connection. Populated
    # only when 0-RTT is enabled via the IdempotentOnly / Tuned
    # policy variants (struct-filter path); Off populates nothing.
    # Mutually exclusive with
    # `_early_data_predicate_fn`: at most one is Some when 0-RTT is on,
    # and both are None when 0-RTT is off. When BOTH are None on a
    # 0-RTT-arrived request, the dispatch helper takes the fail-closed
    # branch (a config-invariant violation; misconfig_fail_closed bumps).
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

    # Test-only: when True the next `drain_datagrams` clears it and raises
    # before touching the connection, so the server's refresh-on-raise
    # path can be exercised. Never set by production code.
    var _raise_on_next_drain: Bool

    def __init__(
        out self,
        *,
        var quic: QuicConnection,
        var handler: Self.H,
        codec_tables: Optional[Pointer[QpackCodecTables, MutUntrackedOrigin]] = None,
        profile_ptr: Optional[Pointer[AcceptProfile, MutUntrackedOrigin]] = None,
        early_data_filter_ptr: Optional[
            Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]
        ] = None,
        predicate_fn: Optional[EarlyDataPredicateFn] = None,
    ) raises:
        self._h3 = H3Connection.server(quic^, codec_tables)
        self.handler = handler^
        self._streams = Dict[Int, PtrBox[_H3StreamCtx]]()
        self.profile_ptr = profile_ptr
        # Shape B threading: H3Connection.server/.client have ~15 call sites
        # in src/h3/ and tests/; we set profile_ptr post-construction here
        # rather than threading it through 15 call sites.
        self._h3.profile_ptr = profile_ptr
        self._early_data_filter_ptr = early_data_filter_ptr
        self._early_data_predicate_fn = predicate_fn
        self._raise_on_next_drain = False

    def __deinit__(deinit self):
        var keys = List[Int](capacity=len(self._streams))
        for key in self._streams.keys():
            keys.append(key)
        for ref key in keys:
            try:
                var p = self._streams[key].ptr()
                p.unsafe_deinit_pointee()
                p.unsafe_free()
            except:
                pass

    # --- Transport API -------------------------------------------------------

    def feed_datagram(mut self, data: Span[Byte, _], now: UInt64) raises:
        self._h3.feed_datagram(data, now)
        self._dispatch_h3_events(now)
        if self._h3.is_established():
            self._drain_responses(now)

    def feed_datagram_from_buffer(
        mut self,
        buf: Pointer[UInt8, MutUntrackedOrigin],
        buf_len: Int,
        now: UInt64,
        ecn_mark: UInt8 = UInt8(0),
    ) raises:
        """Feed one inbound QUIC datagram from a mutable buffer (zero-copy)."""
        self._h3.feed_datagram_from_buffer(buf, buf_len, now, ecn_mark)

        # Bracket _dispatch_h3_events
        comptime if PROFILE_ACCEPT:
            var t_dispatch_start: UInt64 = 0
            if self.profile_ptr is not None:
                t_dispatch_start = monotonic_us()
            self._dispatch_h3_events(now)
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_h3_dispatch(monotonic_us() - t_dispatch_start)
        else:
            self._dispatch_h3_events(now)

        # Bracket _drain_responses (only when established)
        if self._h3.is_established():
            comptime if PROFILE_ACCEPT:
                var t_drain_resp_start: UInt64 = 0
                if self.profile_ptr is not None:
                    t_drain_resp_start = monotonic_us()
                self._drain_responses(now)
                if self.profile_ptr is not None:
                    self.profile_ptr.value()[].record_h3_drain_resp(monotonic_us() - t_drain_resp_start)
            else:
                self._drain_responses(now)

    def drain_datagrams(mut self, now: UInt64) raises -> List[List[Byte]]:
        """Send-until-empty drain, capped; see `H3Connection.drain_datagrams`.

        Test-only: with `_raise_on_next_drain` set, clears it and raises
        before the connection is touched, so no datagram is produced and no
        state moves.
        """
        if self._raise_on_next_drain:
            self._raise_on_next_drain = False
            raise "H3HandlerServer: forced drain failure (test-only)"
        return self._h3.drain_datagrams(now)

    def should_close(self) -> Bool:
        return self._h3.is_closed()

    def is_closing_or_draining(self) -> Bool:
        """True once CLOSING, DRAINING or CLOSED (peer address is frozen)."""
        return self._h3.is_closing_or_draining()

    def timeout(self, now: UInt64) -> Optional[UInt64]:
        """Earliest absolute deadline (µs) this connection needs servicing at."""
        return self._h3.timeout(now)

    def has_pending_egress(self) -> Bool:
        """True when the last drain hit the cap and datagrams are still owed."""
        return self._h3.has_pending_egress()

    def send_goaway(mut self, last_stream_id: UInt64) raises:
        """Send GOAWAY via the underlying H3Connection."""
        self._h3.send_goaway(last_stream_id)

    # --- Path-validation pass-through (RFC 9000 §8 + §9) ---------------------

    def quic(ref self) -> ref [self._h3._quic] QuicConnection:
        """The connection's QUIC layer: the UDP server's demux, path and handshake bookkeeping read it directly."""
        return self._h3._quic

    def set_current_recv_addr(mut self, var addr: PathKey):
        """Stamp the per-receive source-addr cursor on the QUIC layer."""
        self._h3.set_current_recv_addr(addr^)

    def bootstrap_peer_addr(mut self, var addr: PathKey):
        """Seed `peer_addr` on a freshly-accepted connection."""
        self._h3.bootstrap_peer_addr(addr^)

    def peer_addr_copy(self) -> PathKey:
        """Return a copy of the currently-validated peer 4-tuple."""
        return self._h3.peer_addr_copy()

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
        var _ct_start = UInt64(0)
        comptime if PROFILE_ACCEPT:
            _ct_start = rdtsc()
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
        # `Early-Data: 1` into req_headers.
        var stream_is_zr = False
        if self._h3._quic.zrtt.enabled:
            stream_is_zr = stream_is_zero_rtt(self._h3._quic, ev.stream_id)
            var outcome = apply_early_data_filter(
                method_str,
                path_str,
                stream_is_zr,
                self._early_data_filter_ptr,
                self._early_data_predicate_fn,
                req_headers,
                self.profile_ptr,
            )
            if outcome.should_send_425():
                send_425_response(ev.stream_id, self._h3)
                comptime if PROFILE_ACCEPT:
                    if self.profile_ptr is not None:
                        self.profile_ptr.value()[].call_tracker.record(CallId.ON_REQUEST, rdtsc() - _ct_start)
                return

        var req = Request(
            method=Method.custom(method_str),
            target=path_str,
            version=Version.http_3(),
            headers=req_headers^,
        )

        var body = RecvBody()
        var resp = ResponseWriter()

        # Surface a stable connection identity (the server SCID as a u64)
        # plus the request stream id to the handler. A handler that defers
        # the response across an out-of-band round-trip (e.g. a reverse
        # proxy forwarding to a different transport) records this pair and
        # later addresses the open stream via `inject_response`.
        var conn_id_u64 = dcid_to_u64(self._h3._quic.local_cid.as_span())
        # Read peer address at request dispatch time (not connection time)
        # because QUIC connections can migrate (RFC 9000 §9).
        var peer_key = self._h3.peer_addr_copy()
        var peer_addr_str = _path_key_to_peer_addr(peer_key)
        try:
            self.handler.on_request(
                req^,
                body,
                resp,
                Capabilities.for_h3(
                    is_early_data=stream_is_zr,
                    stream_id=ev.stream_id,
                    conn_id=conn_id_u64,
                    peer_addr=peer_addr_str^,
                ),
            )
        except:
            pass

        var detached = body._state == 3

        var ctx_ptr = _heap_alloc[_H3StreamCtx](1)
        var ctx = _H3StreamCtx()
        ctx.recv_body = body^
        ctx.resp_writer = resp^
        ctx.detached = detached
        ctx_ptr.unsafe_write(ctx^)
        self._streams[Int(ev.stream_id)] = PtrBox[_H3StreamCtx](ctx_ptr)
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].call_tracker.record(CallId.ON_REQUEST, rdtsc() - _ct_start)

    def _on_data(mut self, ev: H3Event) raises:
        var sid = Int(ev.stream_id)
        if sid not in self._streams:
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.unsafe_take_pointee()
        var data_copy = List[Byte](copy=ev.data)
        ctx.recv_body._push(BodyFrame.data(data_copy^))
        if not ctx.detached:
            try:
                self.handler.on_body_available(ctx.recv_body, ctx.resp_writer)
            except:
                pass
        ctx_ptr.unsafe_write(ctx^)

    def _on_stream_ended(mut self, ev: H3Event) raises:
        var sid = Int(ev.stream_id)
        if sid not in self._streams:
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.unsafe_take_pointee()
        if ctx.request_ended:
            ctx_ptr.unsafe_write(ctx^)
            return
        ctx.request_ended = True
        ctx.recv_body._set_end()
        if not ctx.detached:
            try:
                self.handler.on_request_end(ctx.recv_body, ctx.resp_writer)
            except:
                pass
        ctx_ptr.unsafe_write(ctx^)

    def _on_stream_reset(mut self, ev: H3Event) raises:
        """Drop the request and cancel any unfinished response, so the QUIC
        stream can be freed."""
        var sid = Int(ev.stream_id)
        if sid not in self._streams:
            return
        self._h3.cancel_send_side(ev.stream_id)
        var ctx_ptr = self._streams[sid].ptr()
        # Taken out of the slot purely so it is destroyed; nothing below
        # reads it, and nothing it owns is touched before the block ends.
        _ = ctx_ptr.unsafe_take_pointee()
        var err = StreamError.rst_stream(UInt32(ev.error_code))
        self.handler.on_reset(err)
        _ = self._streams.pop(sid)
        ctx_ptr.unsafe_free()

    # --- Internal: response drain --------------------------------------------

    def _drain_responses(mut self, now: UInt64) raises:
        """For each open stream: send response headers then body frames."""
        var _ct_start = UInt64(0)
        comptime if PROFILE_ACCEPT:
            _ct_start = rdtsc()
        var sids = List[Int](capacity=len(self._streams))
        for key in self._streams.keys():
            sids.append(key)
        for ref sid in sids:
            if sid not in self._streams:
                continue
            var ctx_ptr = self._streams[sid].ptr()
            var ctx = ctx_ptr.unsafe_take_pointee()
            if ctx.response_ended:
                ctx_ptr.unsafe_write(ctx^)
                self._maybe_cleanup(sid)
                continue
            if not ctx.headers_sent and not ctx.resp_writer._has_status():
                ctx_ptr.unsafe_write(ctx^)
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
            self._maybe_cleanup(sid)
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].call_tracker.record(CallId.DRAIN_RESPONSES, rdtsc() - _ct_start)

    def _maybe_cleanup(mut self, sid: Int) raises:
        """Free stream context if both sides are done."""
        if sid not in self._streams:
            return
        var ctx_ptr = self._streams[sid].ptr()
        if ctx_ptr[].request_ended and ctx_ptr[].response_ended:
            _ = self._streams.pop(sid)
            ctx_ptr.unsafe_deinit_pointee()
            ctx_ptr.unsafe_free()

    # --- Out-of-band response injection (cross-transport wake) ---------------

    def has_stream(self, sid: Int) -> Bool:
        """Return True if `sid` is an open stream awaiting a response.

        A reverse-proxy driver consults this before `inject_response` to
        confirm the stream survived (it could have been reset or torn down
        while the backend round-trip was in flight)."""
        return sid in self._streams

    def inject_response(
        mut self,
        sid: Int,
        var status: StatusCode,
        var headers: Headers,
        var body: List[Byte],
        end: Bool,
    ) raises:
        """Write a response into an open stream's `ResponseWriter` from
        OUTSIDE a `StreamHandler` callback.

        This is the sync analog of `H2StreamingServer.resume_stream`: it
        lets an event-loop driver complete a request whose backend leg ran
        on a different transport (TCP) and woke on a different io_uring
        token — a token that carries no `StreamHandler` callback to ride in
        on. The stream must have been left open by the handler
        (`request_ended` True, `response_ended` False); the writer is
        re-polled by `_drain_responses` on the next egress pass, which
        emits `:status` + DATA + FIN over QPACK/H3.

        A no-op (returns cleanly) if `sid` is not an open stream — the
        stream may have been reset or the connection torn down while the
        backend round-trip was in flight. Internal write errors are
        swallowed so a malformed backend response cannot crash the loop.

        Args:
            sid: H3 request stream id (from `caps.stream_id`).
            status: Response status code.
            headers: Response headers (hop-by-hop already stripped by the
                caller; this method writes them verbatim).
            body: Full response body bytes; emitted as a single DATA frame
                when non-empty.
            end: When True, terminates the response (FIN). Pass True for a
                buffered backend response (the whole body is in `body`).
        """
        if sid not in self._streams:
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.unsafe_take_pointee()
        try:
            ctx.resp_writer.send_status(status^, headers^)
            if len(body) > 0:
                var data = body^
                _ = ctx.resp_writer.try_send_body(BodyFrame.data(data^))
            if end:
                ctx.resp_writer.end()
        except:
            pass
        ctx_ptr.unsafe_write(ctx^)
