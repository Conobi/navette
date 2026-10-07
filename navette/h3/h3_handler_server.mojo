# src/h3/h3_handler_server.mojo
#
# H3HandlerServer[H: StreamHandler] — server adapter.
# Drives a StreamHandler from an H3Connection through the shared handler
# driver (as `H2HandlerServer` does). Sans-I/O.

from std.collections import Optional
from std.memory import Pointer
from std.collections import Span

from navette.quic.connection import QuicConnection
from navette.quic.cid import dcid_to_u64
from navette.quic.path import PathKey
from navette.quic.profile import AcceptProfile, monotonic_us, rdtsc, CallId, PROFILE_ACCEPT
from navette.h3.connection import H3Connection, H3Event
from navette.h3.early_data_filter_dispatch import (
    apply_early_data_filter, send_425_response, stream_is_zero_rtt,
)
from navette.h3.qpack import QpackCodecTables
from navette.http.body import BodyFrame
from navette.http.handler import StreamHandler, Capabilities
from navette.http.handler_driver import HandlerDriver
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.tls.early_data_filter import (
    EarlyDataPredicateFn,
    IdempotentOnlyFilter,
)


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
# H3HandlerServer
# ---------------------------------------------------------------------------


struct H3HandlerServer[H: StreamHandler](Movable):
    """Drive a StreamHandler from an H3Connection. Sans-I/O. A handler that raises fails only its own stream."""

    var _h3:      H3Connection
    var driver:   HandlerDriver[Self.H]
    var profile_ptr: Optional[Pointer[AcceptProfile, MutUntrackedOrigin]]
    # Optional pointer to the RFC 8470 idempotent-only filter owned by
    # the `QuicServerConfig` that birthed this connection. Populated
    # only when 0-RTT is enabled via the IdempotentOnly / Tuned
    # policy variants (struct-filter path); Off populates nothing.
    # Mutually exclusive with
    # `_early_data_predicate_fn`: at most one is Some when 0-RTT is on,
    # and both are None when 0-RTT is off. When BOTH are None on a
    # 0-RTT-arrived request, the dispatch helper takes the fail-closed
    # branch (a config-invariant violation).
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
    # after draining, so the server's refresh-on-raise and drop-on-raise
    # paths can be exercised. Never set by production code.
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
        self.driver = HandlerDriver[Self.H](handler^)
        self.profile_ptr = profile_ptr
        # Shape B threading: H3Connection.server/.client have ~15 call sites
        # in src/h3/ and tests/; we set profile_ptr post-construction here
        # rather than threading it through 15 call sites.
        self._h3.profile_ptr = profile_ptr
        self._early_data_filter_ptr = early_data_filter_ptr
        self._early_data_predicate_fn = predicate_fn
        self._raise_on_next_drain = False

    # --- Transport API -------------------------------------------------------

    def feed_datagram(mut self, data: Span[Byte, _], now: UInt64) raises:
        self._h3.feed_datagram(data, now)
        self._serve()

    def feed_datagram_from_buffer(
        mut self,
        buf: Pointer[UInt8, MutUntrackedOrigin],
        buf_len: Int,
        now: UInt64,
        ecn_mark: UInt8 = UInt8(0),
    ) raises:
        """Feed one inbound QUIC datagram from a mutable buffer (zero-copy)."""
        self._h3.feed_datagram_from_buffer(buf, buf_len, now, ecn_mark)
        self._serve()

    def drain_datagrams(mut self, now: UInt64, mut out: List[List[Byte]], hold: Bool = False) raises:
        """Send-until-empty drain appended to `out`, capped, or held; see `H3Connection.drain_datagrams`.

        Test-only: with `_raise_on_next_drain` set, clears it and raises
        after the drain, as a `send()` raising mid-drain would: the
        datagrams already in `out` are built but never sent.
        """
        self._h3.drain_datagrams(now, out, hold)
        if self._raise_on_next_drain:
            self._raise_on_next_drain = False
            raise "H3HandlerServer: forced drain failure (test-only)"

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

    def h3(ref self) -> ref [self._h3] H3Connection:
        """The connection's HTTP/3 layer: the UDP server's governor wiring tallies it and hands it its share."""
        return self._h3

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

    def _serve(mut self) raises:
        """Hand each pending event to the driver, then send what the handlers staged (only once established).

        With PROFILE_ACCEPT on and a profile wired, the dispatch and drain
        phases are timed into `h3_dispatch` / `h3_drain_resp`.
        """
        comptime if PROFILE_ACCEPT:
            var t_dispatch_start: UInt64 = 0
            if self.profile_ptr is not None:
                t_dispatch_start = monotonic_us()
            self._dispatch_h3_events()
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_h3_dispatch(monotonic_us() - t_dispatch_start)
        else:
            self._dispatch_h3_events()

        if self._h3.is_established():
            comptime if PROFILE_ACCEPT:
                var t_drain_resp_start: UInt64 = 0
                var ct_start: UInt64 = 0
                if self.profile_ptr is not None:
                    t_drain_resp_start = monotonic_us()
                    ct_start = rdtsc()
                self.driver.drain(self._h3)
                if self.profile_ptr is not None:
                    self.profile_ptr.value()[].call_tracker.record(CallId.DRAIN_RESPONSES, rdtsc() - ct_start)
                    self.profile_ptr.value()[].record_h3_drain_resp(monotonic_us() - t_drain_resp_start)
            else:
                self.driver.drain(self._h3)
        self._h3.long_lived = self.driver.detached

    def _dispatch_h3_events(mut self) raises:
        """Hand each pending H3 event to the driver."""
        while True:
            var ev_opt = self._h3.poll_event()
            if not ev_opt:
                break
            var ev = ev_opt.take()
            var sid = Int(ev.stream_id)
            if ev.kind == H3Event.HEADERS_RECEIVED:
                self._on_request(ev^)
            elif ev.kind == H3Event.DATA_RECEIVED:
                _ = self.driver.on_body(sid, BodyFrame.data(ev^.take_data()))
            elif ev.kind == H3Event.TRAILERS_RECEIVED:
                _ = self.driver.on_body(sid, BodyFrame.trailers(ev^.take_section().take_headers()))
            elif ev.kind == H3Event.STREAM_ENDED:
                self.driver.on_end(sid)
            elif ev.kind == H3Event.STREAM_RESET:
                # Cancel our side too, so the QUIC stream can be freed.
                if self.driver.on_reset(sid, UInt32(ev.error_code)):
                    self._h3.cancel_send_side(ev.stream_id)

    def _on_request(mut self, var ev: H3Event) raises:
        """Build the Request from the stream's head and open it in the driver (unless the connection sheds it or 0-RTT refuses it)."""
        var sid = ev.stream_id
        if self._h3.shed_if_over_share(sid):
            return
        var _ct_start = UInt64(0)
        comptime if PROFILE_ACCEPT:
            _ct_start = rdtsc()
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
                comptime if PROFILE_ACCEPT:
                    if self.profile_ptr is not None:
                        self.profile_ptr.value()[].call_tracker.record(CallId.ON_REQUEST, rdtsc() - _ct_start)
                return

        # Surface a stable connection identity (the server SCID as a u64)
        # plus the request stream id to the handler. A handler that defers
        # the response across an out-of-band round-trip (e.g. a reverse
        # proxy forwarding to a different transport) records this pair and
        # later addresses the open stream via `inject_response`. The peer
        # address is read per request: QUIC connections can migrate
        # (RFC 9000 Section 9).
        var caps = Capabilities.for_h3(
            is_early_data=stream_is_zr,
            stream_id=sid,
            conn_id=dcid_to_u64(self._h3._quic.local_cid.as_span()),
            peer_addr=_path_key_to_peer_addr(self._h3.peer_addr_copy()),
        )
        self.driver.on_request(Int(sid), req^, caps, False)
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].call_tracker.record(CallId.ON_REQUEST, rdtsc() - _ct_start)

    # --- Out-of-band response injection (cross-transport wake) ---------------

    def has_stream(self, sid: Int) -> Bool:
        """Return True if `sid` is an open stream awaiting a response.

        A reverse-proxy driver consults this before `inject_response` to
        confirm the stream survived (it could have been reset or torn down
        while the backend round-trip was in flight)."""
        return sid in self.driver.streams

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
        on. The stream must have been left open by the handler (request
        ended, response not); once established the response is staged
        straight onto the stream: `:status` + DATA + FIN over QPACK/H3.

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
        self.driver.respond(sid, status^, headers^, body^, end)
        if self._h3.is_established():
            self.driver.drain(self._h3)
        self._h3.long_lived = self.driver.detached
