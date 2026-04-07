# src/h1/connection.mojo
#
# H1Connection: sans-I/O HTTP/1.1 connection state machine.
#
# Handles both request and response parsing on the inbound side and queues
# serialized messages on the outbound side. The wrappers in src/h1/server.mojo
# and src/h1/client.mojo expose role-specific subsets of this API.
#
# Responsibilities:
#   * buffer incoming bytes and feed the incremental parser;
#   * track connection lifecycle (idle, must-close, upgraded, error);
#   * track keep-alive across HTTP/1.0 and HTTP/1.1 + Connection header;
#   * track the in-flight request method on the server side so HEAD response
#     bodies are stripped after serialization (RFC 9112 Section 6.3 rule 1);
#   * serialize responses / requests / 1xx informationals into wire bytes.

from std.collections.optional import Optional
from std.memory import Span

from src.http.method import Method
from src.http.status import StatusCode
from src.http.version import Version
from src.http.headers import Headers
from src.http.body import BodyFrame
from src.http.request import Request
from src.http.response import Response
from src.h1.config import ParseConfig
from src.h1.parser import (
    try_parse_request,
    try_parse_response,
    ParseResult,
    _iequals,
    _icontains,
)
from src.h1.serializer import (
    serialize_request,
    serialize_response,
    serialize_informational,
)


# Connection phase tags. The phase is a coarse-grained state describing what
# the state machine is currently allowed to do. Inbound parsing is only
# attempted in PHASE_IDLE; everything else is a terminal or quiescent state.
comptime PHASE_IDLE = 0
comptime PHASE_MUST_CLOSE = 1
comptime PHASE_CLOSED = 2
comptime PHASE_UPGRADED = 3
comptime PHASE_ERROR = 4


struct H1Connection(Movable):
    """Sans-I/O HTTP/1.1 connection state machine.

    Feed received bytes with ``receive_data``, extract parsed messages with
    ``next_request`` / ``next_response``. Queue outbound messages with
    ``send_request`` / ``send_response`` / ``send_informational`` and extract
    serialized wire bytes with ``drain``.
    """

    var _inbound_buf: List[UInt8]
    var _outbound_buf: List[UInt8]
    var _phase: Int
    var _keep_alive: Bool
    var _config: ParseConfig
    var _last_scanned: Int
    var _inbound_cursor: Int
    var _messages_parsed: Int
    var _version_seen: Bool
    var _is_http10: Bool
    # Server-side: the method of the most recently parsed request that has
    # not yet been responded to. Drives HEAD body suppression at send time.
    var _pending_method: Optional[Method]

    # --- Construction ---

    def __init__(out self, var config: ParseConfig):
        """Build a fresh state machine in the IDLE phase."""
        self._inbound_buf = List[UInt8]()
        self._outbound_buf = List[UInt8]()
        self._phase = PHASE_IDLE
        self._keep_alive = True  # HTTP/1.1 default.
        self._config = config^
        self._last_scanned = 0
        self._inbound_cursor = 0
        self._messages_parsed = 0
        self._version_seen = False
        self._is_http10 = False
        self._pending_method = Optional[Method]()

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self._inbound_buf = take._inbound_buf^
        self._outbound_buf = take._outbound_buf^
        self._phase = take._phase
        self._keep_alive = take._keep_alive
        self._config = take._config^
        self._last_scanned = take._last_scanned
        self._inbound_cursor = take._inbound_cursor
        self._messages_parsed = take._messages_parsed
        self._version_seen = take._version_seen
        self._is_http10 = take._is_http10
        self._pending_method = take._pending_method^

    # --- Inbound API ---

    def receive_data(mut self, data: Span[UInt8, _]):
        """Append received bytes to the inbound buffer."""
        for i in range(len(data)):
            self._inbound_buf.append(data[i])

    def next_request(mut self) -> Optional[Request]:
        """Try to parse one complete request from the inbound buffer.

        Returns ``None`` when no full message is buffered yet. On a parse
        error the connection transitions into ``PHASE_ERROR`` and ``None``
        is returned.
        """
        if self._phase != PHASE_IDLE:
            return Optional[Request]()

        var result = try_parse_request(
            self._inbound_buf,
            self._inbound_cursor,
            self._last_scanned,
            self._config,
        )

        if len(result.error) > 0:
            self._phase = PHASE_ERROR
            return Optional[Request]()

        if not result.has_request():
            self._last_scanned = result.new_last_scanned
            return Optional[Request]()

        # Consume bytes from the inbound buffer.
        self._inbound_cursor += result.bytes_consumed
        self._compact_inbound()
        self._last_scanned = 0

        var req = result.request.take()

        # Version tracking — first message wins.
        if not self._version_seen:
            self._version_seen = True
            if req.version.is_http_1_0():
                self._is_http10 = True
                self._keep_alive = False

        # Connection header may flip keep-alive in either direction.
        self._update_keep_alive(req.headers)

        # Track the in-flight method so the matching response can suppress
        # the body when the request was HEAD.
        self._pending_method = Optional[Method](Method(other=req.method))

        if not self._keep_alive:
            self._phase = PHASE_MUST_CLOSE
        else:
            self._phase = PHASE_IDLE

        self._messages_parsed += 1
        return Optional[Request](req^)

    def next_response(mut self, var request_method: Method) -> Optional[Response]:
        """Try to parse one complete response from the inbound buffer.

        ``request_method`` is the method of the matching in-flight request.
        It is required for HEAD / CONNECT body framing decisions per RFC
        9112 Section 6.3. 1xx informational responses are returned one at
        a time and leave the connection in the IDLE phase so the caller can
        loop until a non-1xx response arrives.
        """
        if self._phase != PHASE_IDLE:
            return Optional[Response]()

        var method_for_parser = Method(other=request_method)
        var result = try_parse_response(
            self._inbound_buf,
            self._inbound_cursor,
            self._last_scanned,
            method_for_parser^,
            self._config,
        )

        if len(result.error) > 0:
            self._phase = PHASE_ERROR
            return Optional[Response]()

        if not result.has_response():
            self._last_scanned = result.new_last_scanned
            return Optional[Response]()

        # Consume bytes from the inbound buffer.
        self._inbound_cursor += result.bytes_consumed
        self._compact_inbound()
        self._last_scanned = 0

        var resp = result.response.take()
        var status_int = Int(resp.status.code())

        # 1xx interim: do NOT update keep-alive, do NOT count as final.
        # 101 Switching Protocols flips the connection into the upgraded
        # phase. All other 1xx responses keep the connection idle.
        if status_int >= 100 and status_int <= 199:
            if status_int == 101:
                self._phase = PHASE_UPGRADED
                self._keep_alive = False
            return Optional[Response](resp^)

        # CONNECT 2xx: tunnel — connection becomes upgraded.
        if request_method.is_connect() and status_int >= 200 and status_int <= 299:
            self._phase = PHASE_UPGRADED
            self._keep_alive = False
            self._messages_parsed += 1
            return Optional[Response](resp^)

        # Version tracking on first message.
        if not self._version_seen:
            self._version_seen = True
            if resp.version.is_http_1_0():
                self._is_http10 = True
                self._keep_alive = False

        self._update_keep_alive(resp.headers)

        if not self._keep_alive:
            self._phase = PHASE_MUST_CLOSE
        else:
            self._phase = PHASE_IDLE

        self._messages_parsed += 1
        return Optional[Response](resp^)

    # --- Outbound API ---

    def send_response(mut self, var response: Response):
        """Serialize a response and append wire bytes to the outbound buffer.

        If the in-flight request method is HEAD the response body bytes are
        truncated after serialization, leaving the framing headers (e.g.
        Content-Length) intact per RFC 9112 Section 6.3 rule 1.
        """
        var head_in_flight = False
        if self._pending_method.__bool__():
            head_in_flight = self._pending_method.value().is_head()

        var pre_len = len(self._outbound_buf)
        var wire = serialize_response(response^)
        for i in range(len(wire)):
            self._outbound_buf.append(wire[i])

        if head_in_flight:
            self._truncate_outbound_to_headers(pre_len)

        # The response satisfies the in-flight request: clear the pending
        # method so the next request gets a fresh tracking slot.
        self._pending_method = Optional[Method]()

    def send_informational(mut self, var status: StatusCode, var headers: Headers):
        """Serialize a 1xx interim response and append it to the outbound buffer."""
        var wire = serialize_informational(status^, headers^)
        for i in range(len(wire)):
            self._outbound_buf.append(wire[i])

    def send_request(mut self, var request: Request):
        """Serialize a request and append wire bytes to the outbound buffer."""
        var wire = serialize_request(request^)
        for i in range(len(wire)):
            self._outbound_buf.append(wire[i])

    def drain(mut self) -> List[UInt8]:
        """Remove and return all bytes currently in the outbound buffer."""
        var out = self._outbound_buf^
        self._outbound_buf = List[UInt8]()
        return out^

    # --- Connection state queries ---

    def should_close(self) -> Bool:
        """True if the transport should be closed after the current exchange."""
        return (
            self._phase == PHASE_MUST_CLOSE
            or self._phase == PHASE_CLOSED
            or self._phase == PHASE_ERROR
        )

    def is_keep_alive(self) -> Bool:
        """True if the connection is currently considered persistent."""
        return self._keep_alive

    def wants_read(self) -> Bool:
        """True if the state machine is ready to accept more inbound bytes."""
        return self._phase == PHASE_IDLE

    def wants_write(self) -> Bool:
        """True if the outbound buffer has bytes pending."""
        return len(self._outbound_buf) > 0

    # --- Internal helpers ---

    def _compact_inbound(mut self):
        """Drop consumed bytes from the front of the inbound buffer.

        Called after every successful parse so the cursor stays at zero
        and the buffer does not grow without bound across many messages.
        """
        if self._inbound_cursor == 0:
            return
        var new_buf = List[UInt8]()
        var i = self._inbound_cursor
        var n = len(self._inbound_buf)
        while i < n:
            new_buf.append(self._inbound_buf[i])
            i += 1
        self._inbound_buf = new_buf^
        self._inbound_cursor = 0

    def _update_keep_alive(mut self, headers: Headers):
        """Apply the Connection header to the keep-alive flag."""
        var n = len(headers)
        for i in range(n):
            var name = headers.name_at(i)
            if _iequals(name, "connection"):
                var value = headers.value_at(i)
                if _icontains(value, "close"):
                    self._keep_alive = False
                    return
                if _icontains(value, "keep-alive"):
                    self._keep_alive = True
                    return

    def _truncate_outbound_to_headers(mut self, region_start: Int):
        """Truncate the outbound buffer at the first CRLF CRLF after region_start.

        Used to strip body bytes from a HEAD response after the serializer
        has emitted the full message. The four-byte header terminator
        itself is preserved so the wire ends in CRLF CRLF.
        """
        var n = len(self._outbound_buf)
        if n - region_start < 4:
            return
        var i = region_start
        while i <= n - 4:
            if (
                self._outbound_buf[i] == UInt8(0x0D)
                and self._outbound_buf[i + 1] == UInt8(0x0A)
                and self._outbound_buf[i + 2] == UInt8(0x0D)
                and self._outbound_buf[i + 3] == UInt8(0x0A)
            ):
                var end = i + 4
                # Drop everything from `end` to the buffer's tail.
                while len(self._outbound_buf) > end:
                    _ = self._outbound_buf.pop()
                return
            i += 1
