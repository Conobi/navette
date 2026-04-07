# src/http/body.mojo
#
# HTTP body frame (version-agnostic).
# Tagged struct: Data(bytes) | Trailers(headers).

from .headers import Headers

comptime _TAG_DATA = 0
comptime _TAG_TRAILERS = 1


struct BodyFrame(Copyable, Movable):
    """A single body frame: either a chunk of data or trailing headers.

    Variants:
      Data — bytes payload (tag = 0)
      Trailers — trailing headers after the body (tag = 1)

    Use factory functions data() / trailers() to construct.
    Use is_data() / is_trailers() to discriminate.
    Use data() / trailers() accessors to read the payload.
    """
    var _tag: Int
    var _data: List[UInt8]
    var _headers: Headers

    # --- Private constructor ---

    def __init__(out self, *, _tag: Int, var _data: List[UInt8], var _headers: Headers):
        """Private constructor used by factory methods."""
        self._tag = _tag
        self._data = _data^
        self._headers = _headers^

    # --- Copy / Move ---

    def __init__(out self, *, other: Self):
        """Copy constructor."""
        self._tag = other._tag
        self._data = other._data.copy()
        self._headers = Headers(other=other._headers)

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self._tag = take._tag
        self._data = take._data^
        self._headers = take._headers^

    # --- Factory methods ---

    @staticmethod
    def data(var bytes: List[UInt8]) -> Self:
        """Construct a Data body frame from a byte buffer."""
        return Self(_tag=_TAG_DATA, _data=bytes^, _headers=Headers())

    @staticmethod
    def trailers(var headers: Headers) -> Self:
        """Construct a Trailers body frame from trailing headers."""
        return Self(_tag=_TAG_TRAILERS, _data=List[UInt8](), _headers=headers^)

    # --- Predicates ---

    def is_data(self) -> Bool:
        """Return whether this frame is a Data variant."""
        return self._tag == _TAG_DATA

    def is_trailers(self) -> Bool:
        """Return whether this frame is a Trailers variant."""
        return self._tag == _TAG_TRAILERS

    # --- Accessors ---

    def data(ref self) -> ref [self._data] List[UInt8]:
        """Access the data bytes. Only valid when is_data() is True."""
        return self._data

    def trailers(ref self) -> ref [self._headers] Headers:
        """Access the trailing headers. Only valid when is_trailers() is True."""
        return self._headers
