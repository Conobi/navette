# src/h2/hpack_integer.mojo
#
# HPACK variable-length prefix integer codec per RFC 7541 Section 5.1.


def decode_integer(
    wire: List[UInt8], pos: Int, prefix_bits: Int
) -> Tuple[Int, Int, String]:
    """Decode an HPACK prefix-encoded integer from wire bytes.

    Args:
        wire: The byte buffer to read from.
        pos: Starting offset in the buffer.
        prefix_bits: Number of prefix bits (4, 5, 6, 7, or 8).

    Returns:
        (value, bytes_consumed, error) where error is empty on success.

    Overflow protection: if the decoded value exceeds 2^31 - 1
    (2147483647), returns an error string.
    """
    comptime MAX_VALUE = 2147483647  # 2^31 - 1

    if pos >= len(wire):
        return (0, 0, "truncated: no bytes available")

    var max_prefix = (1 << prefix_bits) - 1
    var value = Int(wire[pos]) & max_prefix
    var consumed = 1

    if value < max_prefix:
        return (value, consumed, String())

    # Multi-byte decoding
    var shift = 0
    while True:
        var idx = pos + consumed
        if idx >= len(wire):
            return (0, 0, "truncated: incomplete integer")
        var b = Int(wire[idx])
        consumed += 1
        value += (b & 0x7F) << shift
        shift += 7

        if value > MAX_VALUE:
            return (0, 0, "integer overflow")

        if (b & 0x80) == 0:
            break

    return (value, consumed, String())
