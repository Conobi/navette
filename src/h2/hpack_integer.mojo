# src/h2/hpack_integer.mojo
#
# HPACK variable-length prefix integer codec per RFC 7541 Section 5.1.


def encode_integer(value: Int, prefix_bits: Int) -> List[UInt8]:
    """Encode an integer using HPACK prefix encoding.

    Returns a list of bytes. The first byte contains only the low
    `prefix_bits` bits (caller must OR-in any higher bits for the
    opcode byte).

    Algorithm (RFC 7541 Section 5.1):
      1. max_prefix = (1 << prefix_bits) - 1
      2. If value < max_prefix: return [value]
      3. Else: first byte = max_prefix, then encode (value - max_prefix)
         as continuation bytes with 7 data bits + high continuation bit.
    """
    var max_prefix = (1 << prefix_bits) - 1
    var result = List[UInt8]()

    if value < max_prefix:
        result.append(UInt8(value))
        return result^

    result.append(UInt8(max_prefix))
    var remaining = value - max_prefix
    while remaining >= 128:
        result.append(UInt8((remaining & 0x7F) | 0x80))
        remaining >>= 7
    result.append(UInt8(remaining))
    return result^


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
