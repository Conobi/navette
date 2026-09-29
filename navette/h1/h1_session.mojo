# src/h1/h1_session.mojo
#
# Session implementation backed by ClientConnection. Exposes a feed/drain
# byte interface for tests and example I/O loops; the actual transport is
# the caller's responsibility (bouclette, raw socket, mock).

from std.collections.deque import Deque
from std.collections.optional import Optional
from std.collections import Span
from navette.h1.client import ClientConnection
from navette.h1.config import ParseConfig
from navette.http.body import BodyFrame
from navette.http.headers import Headers
from navette.http.handler import Capabilities, RecvBody
from navette.http.method import Method
from navette.http.request import Request, RequestBody
from navette.http.version import Version
from navette.http.session import Session, RequestHandle


def _int_to_hex(n: Int) -> String:
    """Convert a non-negative integer to lowercase hex string (no 0x prefix)."""
    if n == 0:
        return String("0")
    comptime HEX = "0123456789abcdef"
    var result = String()
    var val = n
    while val > 0:
        var d = val % 16
        result = chr(Int(HEX.as_bytes()[d])) + result
        val //= 16
    return result^


struct H1Session(Session):
    """H1 client session — single in-flight request per connection."""

    var _conn: ClientConnection
    var _outbuf: List[Byte]
    var _next_id: UInt64
    var _pending_handle_id: UInt64
    var _has_inflight: Bool
    var _inflight_method: Optional[Method]
    var _streaming: Bool

    def __init__(out self):
        self._conn = ClientConnection(ParseConfig())
        self._outbuf = List[Byte]()
        self._next_id = UInt64(0)
        self._pending_handle_id = UInt64(0)
        self._has_inflight = False
        self._inflight_method = Optional[Method]()
        self._streaming = False

    # --- Session trait API ---

    def submit(mut self, var req: Request) raises -> RequestHandle:
        if self._has_inflight:
            raise Error("H1Session.submit: H1 has only one in-flight request per connection")
        self._next_id += UInt64(1)
        self._inflight_method = Optional[Method](Method(copy=req.method))
        if req.body.is_stream():
            # Streaming body: send headers only with Transfer-Encoding: chunked.
            # Replace the stream body with empty so send_request serializes
            # headers without a Content-Length, then body comes via feed_body.
            req.headers.add("Transfer-Encoding", "chunked")
            var stream_req = Request(
                method=Method(copy=req.method),
                target=req.target,
                version=Version(copy=req.version),
                headers=Headers(copy=req.headers),
                body=RequestBody.empty(),
            )
            self._conn.send_request(stream_req^)
            self._conn.drain_into(self._outbuf)
            self._streaming = True
        else:
            self._conn.send_request(req^)
            self._conn.drain_into(self._outbuf)
            self._streaming = False
        self._pending_handle_id = self._next_id
        self._has_inflight = True
        return RequestHandle(id=self._next_id)

    def run_until(mut self, mut handle_ids: Deque[UInt64]) raises:
        # H1 has at most one in-flight request, so this is a no-op once the
        # request has completed. Real callers drive the byte pump themselves.
        pass

    def run_one(mut self, mut handle: RequestHandle) raises:
        if not Bool(self._inflight_method):
            return
        var method_opt = self._inflight_method^
        var method = method_opt.take()
        var resp_opt = self._conn.next_response(Method(copy=method))
        if not Bool(resp_opt):
            # Response not yet available — restore the method for the next
            # poll attempt and bail out.
            self._inflight_method = Optional[Method](method^)
            return
        if handle.id() != self._pending_handle_id:
            self._inflight_method = Optional[Method](method^)
            raise Error("H1Session.run_one: handle id does not match pending request")
        var resp = resp_opt.take()
        handle._set_response(resp^)
        handle._mark_complete()
        self._has_inflight = False
        self._inflight_method = Optional[Method]()

    def capabilities(self) -> Capabilities:
        return Capabilities.for_h1()

    def alpn(self) -> Int:
        return Capabilities.for_h1().alpn

    def close(deinit self) raises:
        pass

    def feed_body(mut self, handle_id: UInt64, var frame: BodyFrame) raises:
        if not self._streaming:
            raise Error("H1Session.feed_body: no streaming request in progress")
        if handle_id != self._pending_handle_id:
            raise Error("H1Session.feed_body: handle id does not match pending request")
        if frame.is_data():
            var data_len = len(frame.data())
            var hex_str = _int_to_hex(data_len)
            self._outbuf.extend(hex_str.as_bytes())
            self._outbuf.extend(String("\r\n").as_bytes())
            for i in range(data_len):
                self._outbuf.append(frame.data()[i])
            self._outbuf.extend(String("\r\n").as_bytes())
        elif frame.is_end():
            # Terminal chunk: 0\r\n\r\n
            self._outbuf.extend(String("0\r\n\r\n").as_bytes())
            self._streaming = False

    # --- Transport bridging API ---

    def feed(mut self, data: Span[Byte, _]) raises:
        self._conn.receive_data(data)

    def drain(mut self) -> List[Byte]:
        var out = List[Byte]()
        self.drain_into(out)
        return out^

    def drain_into(mut self, mut sink: List[Byte]):
        """Append queued outbound bytes into ``sink`` and clear ``_outbuf`` in
        place, preserving its backing allocation across requests."""
        sink.extend(Span(self._outbuf))
        self._outbuf.clear()
