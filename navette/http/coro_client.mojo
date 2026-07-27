# src/http/coro_client.mojo
#
# HttpCoroClient — coroutine-based HTTP client adapter (M6c §11).
# Sans-I/O: caller drives byte pump via feed/drain.
# Wraps HttpClient with Alt-Svc integration and content decoding hooks.

from std.collections.optional import Optional
from std.memory import Span

from navette.http.alt_svc import Origin, AltSvcCache, AltSvcEntry, parse_alt_svc
from navette.http.client import HttpClient
from navette.http.session_slot import SessionSlot, SessionSlotPtr, SLOT_H1, SLOT_H2, SLOT_H3
from navette.http.session import RequestHandle
from navette.http.request import Request, RequestBody
from navette.http.response import Response
from navette.http.method import Method
from navette.http.headers import Headers
from navette.http.url import ParsedUrl, parse_url


struct HttpCoroClient(Movable):
    """Coroutine-friendly HTTP client wrapping HttpClient.

    Sans-I/O: caller drives the byte pump externally via feed/drain.
    Adds Alt-Svc caching on top of HttpClient's pool management.

    Usage:
      1. attach_session(origin, slot) — inject a connected session
      2. get/post/request — submit request, get handle
      3. drain(origin) → bytes to send to network
      4. network recv → feed(data, origin)
      5. run_one(origin, handle) — advance until complete
      6. handle.take_response() → Response
    """

    var _client: HttpClient
    var _alt_svc: AltSvcCache

    def __init__(
        out self,
        *,
        max_conns_h1: Int = 6,
        max_conns_mux: Int = 1,
        idle_timeout_ms: UInt64 = UInt64(90_000),
    ):
        self._client = HttpClient.with_config(
            max_conns_h1=max_conns_h1,
            max_conns_mux=max_conns_mux,
            idle_timeout_ms=idle_timeout_ms,
        )
        self._alt_svc = AltSvcCache()

    def __init__(out self, *, deinit take: Self):
        self._client = take._client^
        self._alt_svc = take._alt_svc^

    # --- Session management ---

    def attach_session(mut self, var origin: Origin, var slot: SessionSlot) raises:
        """Inject a connected session into the pool."""
        self._client.attach_session(origin^, slot^)

    def detach_session(mut self, origin: Origin) raises -> SessionSlot:
        """Pop the first pooled session for `origin` and return it by value.

        The inverse of `attach_session`: lifts ownership of the underlying
        `SessionSlot` back out of the internal pool so a downstream
        connection pool (e.g. requette's per-origin keep-alive cache) can
        hold the session across requests instead of letting the slot
        evaporate when the next `attach_session` overwrites it.

        Raises if no session is pooled for `origin`. The heap allocation
        backing the slot is freed; the returned value is move-only.
        """
        if origin not in self._client._pool:
            raise Error("HttpCoroClient.detach_session: no session for origin")
        var slots = self._client._pool.pop(Origin(other=origin))
        if len(slots) == 0:
            raise Error("HttpCoroClient.detach_session: empty slot list for origin")
        # Pull the first slot, then re-insert the remainder so the pool
        # state is consistent before we touch the heap allocation.
        var ptr = SessionSlotPtr(other=slots[0])
        var keep = List[SessionSlotPtr]()
        for i in range(1, len(slots)):
            keep.append(SessionSlotPtr(other=slots[i]))
        if len(keep) > 0:
            self._client._pool[Origin(other=origin)] = keep^
        var slot_p = ptr.ptr()
        var moved = slot_p.take_pointee()
        slot_p.free()
        # Drop any handle-routing entries that pointed at the freed slot
        # so a future attach_session reusing the address cannot misroute.
        var stale_addr = Int(ptr.addr)
        var hids = List[Int]()
        for kv in self._client._handle_slot.items():
            if kv.value == stale_addr:
                hids.append(kv.key)
        for i in range(len(hids)):
            _ = self._client._handle_slot.pop(hids[i])
        return moved^

    # --- Transport API (caller drives I/O) ---

    def feed(mut self, data: Span[UInt8, _], origin: Origin) raises:
        """Feed inbound bytes from network for the given origin."""
        if origin in self._client._pool:
            ref slots = self._client._pool[origin]
            if len(slots) > 0:
                slots[0].ptr()[].feed(data)

    def drain(mut self, origin: Origin) raises -> List[UInt8]:
        """Drain outbound bytes to send to network."""
        if origin in self._client._pool:
            ref slots = self._client._pool[origin]
            if len(slots) > 0:
                return slots[0].ptr()[].drain()
        return List[UInt8]()

    def feed_datagram(
        mut self, data: Span[UInt8, _], origin: Origin, now: UInt64,
    ) raises:
        """Feed an inbound network buffer with QUIC framing intact.

        For H1/H2 origins this is byte-stream feed (and `now` is ignored).
        For H3 origins the datagram and the wall-clock `now` flow into the
        QUIC state machine so PTO + loss detection get accurate samples.
        """
        if origin in self._client._pool:
            ref slots = self._client._pool[origin]
            if len(slots) > 0:
                slots[0].ptr()[].feed_datagram(data, now)

    def drain_datagrams(
        mut self, origin: Origin, now: UInt64,
    ) raises -> List[List[UInt8]]:
        """Drain outbound bytes preserving QUIC datagram boundaries.

        For H1/H2 returns a single-element list wrapping the byte stream
        (or empty when there's nothing to send). For H3 returns one
        element per QUIC packet so the caller can `send(2)` each one
        with the right framing.
        """
        if origin in self._client._pool:
            ref slots = self._client._pool[origin]
            if len(slots) > 0:
                return slots[0].ptr()[].drain_datagrams(now)
        return List[List[UInt8]]()

    # --- Request API ---

    def submit(
        mut self, var origin: Origin, var req: Request,
    ) raises -> RequestHandle:
        """Submit a pre-built Request to a pooled session.

        Use this when you've constructed a `Request` yourself (custom
        headers, body, method) rather than calling one of the
        `get`/`post`/`put`/`delete`/`head`/`query` convenience methods
        which only let you pass a URL.
        """
        return self._client.submit(origin^, req^)

    def get(mut self, url: String) raises -> RequestHandle:
        """Submit a GET request."""
        return self._client.get(url)

    def post(mut self, url: String, var body: List[UInt8]) raises -> RequestHandle:
        """Submit a POST request."""
        return self._client.post(url, body^)

    def put(mut self, url: String, var body: List[UInt8]) raises -> RequestHandle:
        """Submit a PUT request."""
        return self._client.put(url, body^)

    def delete(mut self, url: String) raises -> RequestHandle:
        """Submit a DELETE request."""
        return self._client.delete(url)

    def head(mut self, url: String) raises -> RequestHandle:
        """Submit a HEAD request."""
        return self._client.head(url)

    def query(mut self, url: String, var body: List[UInt8]) raises -> RequestHandle:
        """Submit a QUERY request (RFC 10008)."""
        return self._client.query(url, body^)

    def run_one(mut self, var origin: Origin, mut handle: RequestHandle) raises:
        """Advance a request handle after feeding response bytes."""
        self._client.run_one(origin^, handle)

    # --- Alt-Svc integration ---

    def update_alt_svc(mut self, var origin: Origin, resp: Response, now: UInt) raises:
        """Parse Alt-Svc header from response and cache entries."""
        if resp.headers.has("alt-svc"):
            var value = resp.headers.get("alt-svc")
            if len(value) > 0:
                var entries = parse_alt_svc(value)
                self._alt_svc.insert(origin^, entries^, now)

    def inject_alt_svc_entries(
        mut self, var origin: Origin, var entries: List[AltSvcEntry], received_at: UInt,
    ) raises:
        """Seed pre-built Alt-Svc entries directly, bypassing header parsing.

        Mirrors `update_alt_svc` but takes entries the caller already built
        (e.g. an `h3` entry synthesized from a DNS HTTPS RR) instead of an
        `Alt-Svc` response header. Used by requette's DNS-based H3 discovery so
        the existing `_cache_has_h3 -> _via_h3` promotion path fires on the first
        request, with no new attempt logic.
        """
        self._alt_svc.insert(origin^, entries^, received_at)

    def lookup_alt_svc(self, origin: Origin, now: UInt) raises -> List[AltSvcEntry]:
        """Check if an upgraded protocol is available for this origin."""
        return self._alt_svc.lookup(origin, now)

    def clear_alt_svc(mut self, origin: Origin) raises:
        """Drop any cached Alt-Svc entries for `origin`. Used by CLI
        callers to invalidate a stale advertisement after a failed
        upgrade attempt."""
        self._alt_svc.clear(origin)

    def dump_alt_svc(self) raises -> String:
        """Serialize the in-memory Alt-Svc cache to a text representation
        suitable for on-disk persistence. See `AltSvcCache.dump`."""
        return self._alt_svc.dump()

    def load_alt_svc(mut self, content: String, now: UInt) raises:
        """Load previously-dumped Alt-Svc cache content. Expired entries
        are dropped at the supplied `now`. See `AltSvcCache.load_text`."""
        self._alt_svc.load_text(content, now)

    # --- Pool inspection (for testing) ---

    def has_connection(self, origin: Origin) raises -> Bool:
        """Check if a session is pooled for origin."""
        if origin in self._client._pool:
            ref slots = self._client._pool[origin]
            return len(slots) > 0
        return False
