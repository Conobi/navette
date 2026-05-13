# src/http/coro_client.mojo
#
# HttpCoroClient — coroutine-based HTTP client adapter (M6c §11).
# Sans-I/O: caller drives byte pump via feed/drain.
# Wraps HttpClient with Alt-Svc integration and content decoding hooks.

from std.collections.optional import Optional
from std.memory import Span

from mojo_net.http.alt_svc import Origin, AltSvcCache, AltSvcEntry, parse_alt_svc
from mojo_net.http.client import HttpClient
from mojo_net.http.session_slot import SessionSlot, SessionSlotPtr, SLOT_H1, SLOT_H2, SLOT_H3
from mojo_net.http.session import RequestHandle
from mojo_net.http.request import Request, RequestBody
from mojo_net.http.response import Response
from mojo_net.http.method import Method
from mojo_net.http.headers import Headers
from mojo_net.http.url import ParsedUrl, parse_url


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
        `get`/`post`/`put`/`delete`/`head` convenience methods which
        only let you pass a URL.
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
