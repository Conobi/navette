# navette/quic/cid_buf.mojo

from std.collections import Span
from std.os import abort
from std.sys.info import size_of


@fieldwise_init
struct CidBuf(Copyable, Movable, Sized, Equatable):
    """Fixed-capacity connection ID buffer (max 20 bytes per RFC 9000)."""

    var data: InlineArray[UInt8, 20]
    var len: UInt8

    @staticmethod
    def empty() -> Self:
        """Zero-length CID."""
        _check_cid_buf_size()
        return Self(data=InlineArray[UInt8, 20](fill=Byte(0)), len=UInt8(0))

    @staticmethod
    def from_span(src: Span[Byte, _]) -> Self:
        """Copy up to 20 bytes from a byte span. Aborts if len > 20."""
        if len(src) > 20:
            abort("CID exceeds 20 bytes")
        var buf = Self.empty()
        var i = 0
        for ref byte in src:
            buf.data[i] = byte
            i += 1
        buf.len = UInt8(len(src))
        return buf^

    def as_span(self) -> Span[Byte, origin_of(self.data)]:
        """Borrow as a byte span of the active bytes."""
        return Span(unsafe_ptr=self.data.unsafe_ptr(), length=Int(self.len))

    def __len__(self) -> Int:
        return Int(self.len)

    def __eq__(self, other: Self) -> Bool:
        if self.len != other.len:
            return False
        for i in range(Int(self.len)):
            if self.data[i] != other.data[i]:
                return False
        return True

    def __ne__(self, other: Self) -> Bool:
        return not (self == other)


def _check_cid_buf_size():
    """Compile-time size gate: CidBuf must stay small enough to pass and
    copy by value cheaply (no hidden heap allocation should creep back in
    via a wider field)."""
    comptime assert size_of[CidBuf]() <= 24, "CidBuf exceeds 24 bytes"
