# src/http/request.mojo
#
# HTTP request (RFC 9110).
# Pure data — no socket, no connection reference.

from std.collections.optional import Optional
from .method import Method
from .version import Version
from .headers import Headers
from .body import BodyFrame
from .handler import DetachedBody


# ---------------------------------------------------------------------------
# RequestBody — tagged union for request bodies (§5.12)
# ---------------------------------------------------------------------------

comptime _REQ_BODY_BUFFERED = 0
comptime _REQ_BODY_STREAM   = 1
comptime _REQ_BODY_EMPTY    = 2


struct RequestBody(Movable):
    """Tagged union for request bodies: in-memory bytes, streaming
    DetachedBody, or empty. See spec §5.12."""

    var _tag: Int
    var _bytes: List[UInt8]
    var _stream: Optional[DetachedBody]

    def __init__(
        out self,
        *,
        _tag: Int,
        var _bytes: List[UInt8],
        var _stream: Optional[DetachedBody],
    ):
        self._tag = _tag
        self._bytes = _bytes^
        self._stream = _stream^

    def __init__(out self, *, deinit take: Self):
        self._tag = take._tag
        self._bytes = take._bytes^
        self._stream = take._stream^

    @staticmethod
    def buffered(var bytes: List[UInt8]) -> Self:
        return Self(_tag=_REQ_BODY_BUFFERED, _bytes=bytes^, _stream=Optional[DetachedBody]())

    @staticmethod
    def stream(var detached: DetachedBody) -> Self:
        return Self(
            _tag=_REQ_BODY_STREAM,
            _bytes=List[UInt8](),
            _stream=Optional[DetachedBody](detached^),
        )

    @staticmethod
    def empty() -> Self:
        return Self(_tag=_REQ_BODY_EMPTY, _bytes=List[UInt8](), _stream=Optional[DetachedBody]())

    def is_buffered(self) -> Bool:
        return self._tag == _REQ_BODY_BUFFERED

    def is_stream(self) -> Bool:
        return self._tag == _REQ_BODY_STREAM

    def is_empty(self) -> Bool:
        return self._tag == _REQ_BODY_EMPTY

    def bytes(ref self) -> ref [self._bytes] List[UInt8]:
        """Borrowed view of the buffered bytes. Only valid when is_buffered()."""
        return self._bytes

    def take_stream(deinit self) -> DetachedBody:
        """Consume self and return the inner DetachedBody. Only valid when is_stream()."""
        var s = self._stream^
        return s.take()

    def _clone_buffered(self) raises -> Self:
        if self._tag != _REQ_BODY_BUFFERED:
            raise Error("RequestBody._clone_buffered: not a buffered body")
        return Self(
            _tag=_REQ_BODY_BUFFERED,
            _bytes=self._bytes.copy(),
            _stream=Optional[DetachedBody](),
        )

    def _clone_empty(self) -> Self:
        return Self(_tag=_REQ_BODY_EMPTY, _bytes=List[UInt8](), _stream=Optional[DetachedBody]())


struct Request(Movable):
    """HTTP request message.

    Fields:
      method  HTTP method (GET, POST, etc.).
      target  Request-target (e.g., "/index.html").
      version HTTP version (defaults to HTTP/1.1).
      headers Header fields (no pseudo-headers).
      body    Request body — buffered bytes, streaming DetachedBody, or empty.
    """
    var method: Method
    var target: String
    var version: Version
    var headers: Headers
    var body: RequestBody

    def __init__(
        out self,
        var method: Method,
        target: String,
        var version: Version = Version.http_1_1(),
        var headers: Headers = Headers(),
        var body: RequestBody = RequestBody.empty(),
    ):
        """Construct a Request with the given fields."""
        self.method = method^
        self.target = target
        self.version = version^
        self.headers = headers^
        self.body = body^

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self.method = take.method^
        self.target = take.target^
        self.version = take.version^
        self.headers = take.headers^
        self.body = take.body^
