"""Adopt arbitrary header octets into a String without forging invalid UTF-8.

SECURITY INVARIANT (shared with `navette.h1.parser._bytes_to_string`):
`String(unsafe_from_utf8=...)` is reached ONLY for all-ASCII input.

The name reads like a validation-free constructor, but its UTF-8 check is a
`debug_assert`: it is live under `-D ASSERT=all` -- which is exactly mojox's
dev and test profile -- and compiled out otherwise. So handing it a non-ASCII
byte run has two failure modes, neither acceptable in a networking stack:

  * under the test profile, the process ABORTS;
  * under a release profile, the String silently holds invalid UTF-8, and any
    later operation that assumes validity inherits the problem.

That matters because header octets are not ASCII by contract. RFC 7541 (HPACK)
and RFC 9204 (QPACK) impose no character restriction on field values at the
codec layer, and RFC 9110 explicitly admits `obs-text` (0x80-0xFF) in a field
value. A peer may therefore send bytes that are perfectly legal HTTP and not
valid UTF-8 -- so this cannot be treated as a malformed-input case and rejected.

Resolution: transcode. Bytes 0x00-0x7F are copied verbatim; a byte >= 0x80 is
emitted as the two-byte UTF-8 encoding of the code point of the same value,
i.e. the octet string is read as Latin-1. The result is always valid UTF-8 and
round-trips back to the original octets through `_string_to_bytes`. This
mirrors, byte for byte, what the HTTP/1.1 parser has always done.
"""

from std.collections import Span


def bytes_to_string(var data: List[Byte]) -> String:
    """Adopt `data` as a String without copying when it is all ASCII.

    A byte >= 0x80 falls back to the transcoding `Span` overload.
    """
    for ref byte in data:
        if byte >= UInt8(0x80):
            return bytes_to_string(Span(data))
    return String(unsafe_from_utf8=data^)


def bytes_to_string(data: Span[Byte, _]) -> String:
    """Copy `data` into a String, transcoding any byte >= 0x80 as Latin-1.

    All-ASCII input is copied in bulk (inline, no allocation, up to 23 bytes);
    otherwise each byte >= 0x80 becomes the two-byte UTF-8 encoding of the
    code point with that value, so the result is always valid UTF-8.
    """
    for ref byte in data:
        if byte >= UInt8(0x80):
            var out = String()
            for ref b in data:
                out += chr(Int(b))
            return out^
    return String(unsafe_from_utf8=data)


def string_to_bytes(s: String) -> List[Byte]:
    """Recover the original octets from a String built by `bytes_to_string`.

    Args:
        s: A String produced by `bytes_to_string`.

    Returns:
        The octet sequence that was passed in. Code points U+0080-U+00FF are
        folded back to their single-byte value; everything else is copied as
        its UTF-8 bytes. Delegates to string_to_bytes_into.
    """
    var out = List[Byte]()
    string_to_bytes_into(out, s)
    return out^


def string_to_bytes_into(mut buf: List[Byte], s: String):
    """Append the original octets of a String built by `bytes_to_string` onto `buf`.

    Code points U+0080-U+00FF are folded back to their single-byte value;
    everything else is copied as its UTF-8 bytes.
    """
    for cp in s.codepoints():
        var v = Int(cp)
        if v <= 0xFF:
            buf.append(UInt8(v))
        else:
            # Not producible by bytes_to_string, but keep the function total
            # rather than silently truncating.
            var enc = String(cp).as_bytes()
            for ref byte in enc:
                buf.append(byte)
