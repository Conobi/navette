# src/http/body.mojo
#
# HTTP body frame (version-agnostic).
# Tagged struct: Data(bytes) | Trailers(headers) | End | Error(StreamError).

from std.collections.optional import Optional
from .headers import Headers
from .handler import StreamError

comptime _TAG_DATA = 0
comptime _TAG_TRAILERS = 1
comptime _TAG_END = 2
comptime _TAG_ERROR = 3


struct BodyFrame(Copyable, Movable):
    """A single body frame.

    Variants:
      Data — bytes payload (tag = 0)
      Trailers — trailing headers after the body (tag = 1)
      End — terminal end-of-stream marker (tag = 2)
      Error — terminal stream error (tag = 3)

    Frame ordering rule: zero-or-more Data, optional Trailers, then exactly
    one terminal frame (End or Error).

    Use factory functions data() / trailers() / end() / error() to construct.
    Use is_data() / is_trailers() / is_end() / is_error() to discriminate.
    Use data() / trailers() / error() accessors to read the payload.
    """
    var _tag: Int
    var _data: List[UInt8]
    var _headers: Headers
    var _error: Optional[StreamError]

    # --- Private constructor ---

    def __init__(
        out self,
        *,
        _tag: Int,
        var _data: List[UInt8],
        var _headers: Headers,
        var _error: Optional[StreamError],
    ):
        """Private constructor used by factory methods."""
        self._tag = _tag
        self._data = _data^
        self._headers = _headers^
        self._error = _error^

    # --- Copy / Move ---

    def __init__(out self, *, other: Self):
        """Copy constructor."""
        self._tag = other._tag
        self._data = other._data.copy()
        self._headers = Headers(other=other._headers)
        self._error = other._error.copy()

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self._tag = take._tag
        self._data = take._data^
        self._headers = take._headers^
        self._error = take._error^

    # --- Factory methods ---

    @staticmethod
    def data(var bytes: List[UInt8]) -> Self:
        """Construct a Data body frame from a byte buffer."""
        return Self(
            _tag=_TAG_DATA,
            _data=bytes^,
            _headers=Headers(),
            _error=Optional[StreamError](),
        )

    @staticmethod
    def trailers(var headers: Headers) -> Self:
        """Construct a Trailers body frame from trailing headers."""
        return Self(
            _tag=_TAG_TRAILERS,
            _data=List[UInt8](),
            _headers=headers^,
            _error=Optional[StreamError](),
        )

    @staticmethod
    def end() -> Self:
        """Construct an End terminal body frame."""
        return Self(
            _tag=_TAG_END,
            _data=List[UInt8](),
            _headers=Headers(),
            _error=Optional[StreamError](),
        )

    @staticmethod
    def error(var err: StreamError) -> Self:
        """Construct an Error terminal body frame."""
        return Self(
            _tag=_TAG_ERROR,
            _data=List[UInt8](),
            _headers=Headers(),
            _error=Optional[StreamError](err^),
        )

    # --- Predicates ---

    def is_data(self) -> Bool:
        """Return whether this frame is a Data variant."""
        return self._tag == _TAG_DATA

    def is_trailers(self) -> Bool:
        """Return whether this frame is a Trailers variant."""
        return self._tag == _TAG_TRAILERS

    def is_end(self) -> Bool:
        """Return whether this frame is an End variant."""
        return self._tag == _TAG_END

    def is_error(self) -> Bool:
        """Return whether this frame is an Error variant."""
        return self._tag == _TAG_ERROR

    # --- Accessors ---

    def data(ref self) -> ref [self._data] List[UInt8]:
        """Access the data bytes. Only valid when is_data() is True."""
        return self._data

    def trailers(ref self) -> ref [self._headers] Headers:
        """Access the trailing headers. Only valid when is_trailers() is True."""
        return self._headers

    def error(self) -> StreamError:
        """Return a copy of the stream error. Only valid when is_error() is True."""
        return self._error.value().copy()
