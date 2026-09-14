# src/http/body.mojo
#
# HTTP body frame (version-agnostic).
# Tagged union: Data(bytes) | Trailers(headers) | End | Error(StreamError).

from std.utils import Variant
from .headers import Headers
from .handler import StreamError

comptime BodyPayload = Variant[List[UInt8], Headers, NoneType, StreamError]


struct BodyFrame(Copyable, Movable):
    """Version-agnostic HTTP body frame.

    Variants: Data(bytes) | Trailers(headers) | End | Error(StreamError).
    Frame ordering rule: zero-or-more Data, optional Trailers, then exactly
    one terminal frame (End or Error).
    """
    var payload: BodyPayload

    def __init__(out self, var payload: BodyPayload):
        """Construct from a payload variant."""
        self.payload = payload^

    def __init__(out self, *, other: Self):
        self.payload = BodyPayload(copy=other.payload)

    # -- Factory methods --

    @staticmethod
    def data(var bytes: List[UInt8]) -> Self:
        """Construct a Data body frame from a byte buffer."""
        return Self(BodyPayload(bytes^))

    @staticmethod
    def trailers(var headers: Headers) -> Self:
        """Construct a Trailers body frame from trailing headers."""
        return Self(BodyPayload(headers^))

    @staticmethod
    def end() -> Self:
        """Construct an End terminal body frame."""
        return Self(BodyPayload(NoneType()))

    @staticmethod
    def error(var err: StreamError) -> Self:
        """Construct an Error terminal body frame."""
        return Self(BodyPayload(err^))

    # -- Predicates --

    def is_data(self) -> Bool:
        """Return whether this frame is a Data variant."""
        return self.payload.isa[List[UInt8]]()

    def is_trailers(self) -> Bool:
        """Return whether this frame is a Trailers variant."""
        return self.payload.isa[Headers]()

    def is_end(self) -> Bool:
        """Return whether this frame is an End variant."""
        return self.payload.isa[NoneType]()

    def is_error(self) -> Bool:
        """Return whether this frame is an Error variant."""
        return self.payload.isa[StreamError]()

    # -- Accessors --

    def data(ref self) -> ref [self.payload] List[UInt8]:
        """Access the data bytes. Only valid when is_data() is True."""
        return self.payload.unsafe_get[List[UInt8]]()

    def trailers(ref self) -> ref [self.payload] Headers:
        """Access the trailing headers. Only valid when is_trailers() is True."""
        return self.payload.unsafe_get[Headers]()

    def error(self) -> StreamError:
        """Return a copy of the stream error. Only valid when is_error() is True."""
        return self.payload.unsafe_get[StreamError]().copy()
