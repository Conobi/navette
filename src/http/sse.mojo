# src/http/sse.mojo
#
# Server-Sent Events (text/event-stream) — M2.5b §7.3.
#
# WHATWG HTML Living Standard §9.2 "Server-sent events" subset:
#   https://html.spec.whatwg.org/multipage/server-sent-events.html
#
# Not implemented in v1: UTF-8 BOM stripping (assume UTF-8 input),
# cross-field UTF-8 validation (the reader treats input as bytes),
# reconnection policy (that lives in M6's HttpClient).

from std.collections.optional import Optional


struct ServerSentEvent(Copyable, Movable):
    """One dispatched Server-Sent Event. Matches the WHATWG `event` dispatch
    step output: a UTF-8 `data` string, an optional type, optional last-event
    id, and an optional reconnection-time hint."""

    var event: Optional[String]
    var data: String
    var id: Optional[String]
    var retry: Optional[UInt]

    def __init__(out self):
        self.event = Optional[String]()
        self.data = String("")
        self.id = Optional[String]()
        self.retry = Optional[UInt]()

    def __init__(out self, *, other: Self):
        self.event = other.event
        self.data = other.data.copy()
        self.id = other.id
        self.retry = other.retry

    def __init__(out self, *, deinit take: Self):
        self.event = take.event^
        self.data = take.data^
        self.id = take.id^
        self.retry = take.retry^


from src.http.body import BodyFrame
from src.http.handler import DetachedBody


struct EventStreamReader(Movable):
    """Incremental parser over a DetachedBody carrying a text/event-stream
    response. Pull model: the caller invokes `try_next_event()` which drains
    any newly-arrived BodyFrames from the underlying body and returns the
    next dispatched event if one is now available.

    Frame ordering invariants come from the body: zero-or-more Data frames
    followed by a terminal End or Error. Trailers frames are ignored (SSE
    has no use for them). Terminal errors cause `is_end()` to return True
    without raising — handlers read `is_end()` and stop polling."""

    var _body: DetachedBody
    var _buffer: List[UInt8]   # undispatched bytes
    var _body_ended: Bool

    def __init__(out self, var body: DetachedBody):
        self._body = body^
        self._buffer = List[UInt8]()
        self._body_ended = False

    def __init__(out self, *, deinit take: Self):
        self._body = take._body^
        self._buffer = take._buffer^
        self._body_ended = take._body_ended

    def is_end(self) -> Bool:
        """True once the underlying body is terminated AND the parse buffer
        has no complete event left to dispatch. Callers should poll
        `try_next_event` while this returns False."""
        return self._body_ended and len(self._buffer) == 0

    def try_next_event(mut self) raises -> Optional[ServerSentEvent]:
        # 1. Drain any newly-available frames from the body into the buffer.
        while True:
            var frame_opt = self._body.try_read()
            if not Bool(frame_opt):
                break
            var frame = frame_opt.value().copy()
            if frame.is_data():
                ref data = frame.data()
                var di = 0
                while di < len(data):
                    self._buffer.append(data[di])
                    di += 1
            elif frame.is_end() or frame.is_error():
                self._body_ended = True

        # 2. Scan the buffer for a complete event (blank line terminated).
        var boundary = _find_event_boundary(self._buffer)
        if boundary < 0:
            # If the body has ended and no complete event remains, discard
            # any trailing partial event per WHATWG §9.2 (the dispatch step
            # only fires on a blank-line boundary). Clearing the buffer lets
            # is_end() return True so callers exit their poll loop instead
            # of spinning forever.
            if self._body_ended:
                self._buffer = List[UInt8]()
            return Optional[ServerSentEvent]()

        # 3. Parse the prefix (up to but not including the blank line).
        var event_bytes = _slice_bytes(self._buffer, 0, boundary)
        var event = _parse_event_bytes(event_bytes)

        # 4. Advance the buffer past the blank line.
        var consumed = _blank_line_len(self._buffer, boundary)
        self._buffer = _slice_bytes(self._buffer, boundary + consumed, len(self._buffer))
        return Optional[ServerSentEvent](event^)


# --- Parsing helpers ---


def _find_event_boundary(buf: List[UInt8]) -> Int:
    """Return the index in `buf` of the first byte of a blank-line terminator
    (`\\n\\n` or `\\r\\n\\r\\n` or `\\n\\r\\n` etc), or -1 if none yet. The
    returned index is the position of the *terminator*, so the event bytes
    are `buf[0:index]`."""
    var n = len(buf)
    var i = 0
    while i < n:
        # Look for two consecutive line endings at i.
        var first = _line_end_len(buf, i)
        if first > 0:
            var second = _line_end_len(buf, i + first)
            if second > 0:
                return i
            if i + first >= n:
                return -1
            i += first
            continue
        i += 1
    return -1


def _line_end_len(buf: List[UInt8], at: Int) -> Int:
    """Return 2 for `\\r\\n` at `at`, 1 for `\\n` or `\\r` alone, 0 otherwise."""
    if at >= len(buf):
        return 0
    var b = buf[at]
    if b == UInt8(0x0D):
        if at + 1 < len(buf) and buf[at + 1] == UInt8(0x0A):
            return 2
        return 1
    if b == UInt8(0x0A):
        return 1
    return 0


def _blank_line_len(buf: List[UInt8], at: Int) -> Int:
    """Length of the two consecutive line endings that form an event
    boundary starting at `at`. Assumes `_find_event_boundary` placed `at`
    at a valid boundary."""
    var first = _line_end_len(buf, at)
    var second = _line_end_len(buf, at + first)
    return first + second


def _slice_bytes(buf: List[UInt8], start: Int, end: Int) -> List[UInt8]:
    var out = List[UInt8]()
    var i = start
    while i < end:
        out.append(buf[i])
        i += 1
    return out^


def _parse_event_bytes(bytes: List[UInt8]) raises -> ServerSentEvent:
    """Parse one event's worth of bytes (the prefix before the blank line)
    into a ServerSentEvent per WHATWG §9.2."""
    var event = ServerSentEvent()
    var pos = 0
    var n = len(bytes)
    while pos < n:
        # Find the end of this line.
        var line_start = pos
        while pos < n and bytes[pos] != UInt8(0x0A) and bytes[pos] != UInt8(0x0D):
            pos += 1
        var line_end = pos
        # Skip the line ending.
        pos += _line_end_len(bytes, pos)

        if line_start == line_end:
            continue  # blank line inside a multi-line event — ignore

        # Comment line (`:` prefix) — ignore.
        if bytes[line_start] == UInt8(0x3A):  # ':'
            continue

        # Split on ':'
        var colon = -1
        var ci = line_start
        while ci < line_end:
            if bytes[ci] == UInt8(0x3A):
                colon = ci
                break
            ci += 1

        var field_end = line_end
        if colon >= 0:
            field_end = colon
        var field_name = _bytes_to_string(bytes, line_start, field_end)
        var value_start = line_end
        if colon >= 0:
            value_start = colon + 1
        # Per WHATWG: skip a single leading space after the colon.
        if value_start < line_end and bytes[value_start] == UInt8(0x20):
            value_start += 1
        var value = _bytes_to_string(bytes, value_start, line_end)

        if field_name == String("event"):
            event.event = Optional[String](value^)
        elif field_name == String("data"):
            if len(event.data) > 0:
                event.data += String("\n")
            event.data += value
        elif field_name == String("id"):
            event.id = Optional[String](value^)
        elif field_name == String("retry"):
            # WHATWG: ignore non-integer values silently.
            var parsed = _try_parse_uint(value)
            if Bool(parsed):
                event.retry = parsed
        # unknown fields ignored
    return event^


def _bytes_to_string(buf: List[UInt8], start: Int, end: Int) -> String:
    var out = String("")
    var i = start
    while i < end:
        out += chr(Int(buf[i]))
        i += 1
    return out^


def _try_parse_uint(s: String) -> Optional[UInt]:
    var bytes = s.as_bytes()
    if len(bytes) == 0:
        return Optional[UInt]()
    var acc = UInt(0)
    var i = 0
    while i < len(bytes):
        var c = Int(bytes[i])
        if c < 0x30 or c > 0x39:
            return Optional[UInt]()
        acc = acc * UInt(10) + UInt(c - 0x30)
        i += 1
    return Optional[UInt](acc)


from src.http.handler import ResponseWriter, WriteResult


def try_write_event(
    mut resp: ResponseWriter,
    event: ServerSentEvent,
) raises -> WriteResult:
    """Serialize `event` into the response body as a text/event-stream
    frame. Stateless — the caller holds the ResponseWriter and passes it
    in on each call. Returns the underlying `try_send_body` result so the
    caller can observe backpressure.

    Spec deviation note: the original §7.3 sketch proposed a stateful
    EventStreamWriter struct wrapping an `UnsafePointer[ResponseWriter]`,
    but that contradicts the sketch's own "does NOT take ownership" line
    and adds lifetime risk in Mojo 0.26.2. SSE writers need no per-call
    state, so a free function is both simpler and safer. HC-4/M5 can
    promote this to a struct if a real use case for state emerges."""
    var buf = String("")

    if Bool(event.event):
        buf += String("event: ")
        buf += event.event.value()
        buf += String("\n")

    if Bool(event.id):
        buf += String("id: ")
        buf += event.id.value()
        buf += String("\n")

    if Bool(event.retry):
        buf += String("retry: ")
        buf += String(Int(event.retry.value()))
        buf += String("\n")

    # data: lines — split on '\n' so each chunk becomes its own "data:" line.
    if len(event.data) > 0:
        var data_bytes = event.data.as_bytes()
        var n = len(data_bytes)
        var start = 0
        var i = 0
        while i < n:
            if data_bytes[i] == UInt8(0x0A):  # '\n'
                buf += String("data: ")
                var seg_i = start
                while seg_i < i:
                    buf += chr(Int(data_bytes[seg_i]))
                    seg_i += 1
                buf += String("\n")
                start = i + 1
            i += 1
        # Final segment (after the last '\n' or the whole string if no '\n')
        buf += String("data: ")
        var seg_i = start
        while seg_i < n:
            buf += chr(Int(data_bytes[seg_i]))
            seg_i += 1
        buf += String("\n")

    # Event terminator.
    buf += String("\n")

    # Convert to bytes and hand off to SendBody.
    var bytes = List[UInt8]()
    var as_bytes = buf.as_bytes()
    var k = 0
    while k < len(as_bytes):
        bytes.append(as_bytes[k])
        k += 1
    return resp.try_send_body(BodyFrame.data(bytes^))
