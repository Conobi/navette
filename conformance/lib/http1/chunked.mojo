# conformance/lib/http1/chunked.mojo
#
# Chunked transfer encoding codec per RFC 9112 section 7.

from .types import ParseConfig, Header, ChunkedResult


def _hex_char_value(b: UInt8) -> Int:
    """Return the numeric value of a hex ASCII byte, or -1 if invalid."""
    if b >= UInt8(ord("0")) and b <= UInt8(ord("9")):
        return Int(b) - ord("0")
    if b >= UInt8(ord("a")) and b <= UInt8(ord("f")):
        return Int(b) - ord("a") + 10
    if b >= UInt8(ord("A")) and b <= UInt8(ord("F")):
        return Int(b) - ord("A") + 10
    return -1


def _int_to_hex(value: Int) -> List[UInt8]:
    """Convert a non-negative integer to lowercase hex ASCII bytes."""
    if value == 0:
        var out = List[UInt8]()
        out.append(UInt8(ord("0")))
        return out^

    var hex_chars = String("0123456789abcdef")
    var hex_bytes = hex_chars.as_bytes()

    # Build digits in reverse order.
    var digits = List[UInt8]()
    var v = value
    while v > 0:
        var nibble = v & 0xF
        digits.append(hex_bytes[nibble])
        v >>= 4

    # Reverse into output.
    var out = List[UInt8]()
    var i = len(digits) - 1
    while i >= 0:
        out.append(digits[i])
        i -= 1
    return out^


def decode_chunked(
    data: List[UInt8], config: ParseConfig = ParseConfig()
) -> ChunkedResult:
    """Decode a chunked transfer-encoded body per RFC 9112 section 7.

    Returns a ChunkedResult with the reassembled body, any trailers, and
    an error string (empty on success).
    """
    var result = ChunkedResult()
    var pos = 0
    var data_len = len(data)

    while True:
        # ---- Step 1: Read hex digits for the chunk size ----
        var hex_start = pos
        var found_crlf = False
        var found_semi = False
        var semi_pos = -1

        # Scan forward until we hit CRLF.
        while pos < data_len - 1:
            if data[pos] == UInt8(ord("\r")) and data[pos + 1] == UInt8(ord("\n")):
                found_crlf = True
                break
            if data[pos] == UInt8(ord(";")) and not found_semi:
                found_semi = True
                semi_pos = pos
            pos += 1

        if not found_crlf:
            result.error = "missing CRLF after chunk size"
            result.bytes_consumed = pos
            return result^

        # The hex digits end at either the semicolon or the CRLF position.
        var hex_end = semi_pos if found_semi else pos

        # ---- Step 2/3: Handle chunk extensions ----
        if found_semi:
            if not config.strictness.allow_chunk_extensions:
                result.error = "chunk extensions not allowed in strict mode"
                result.bytes_consumed = pos
                return result^
            # In lenient mode we simply ignore everything from ';' to CRLF.

        # ---- Step 4: Parse hex string to chunk_size ----
        if hex_end == hex_start:
            result.error = "empty chunk size"
            result.bytes_consumed = pos
            return result^

        var chunk_size = 0
        # Cap at 2^53 to prevent silent overflow
        comptime MAX_SAFE = 9007199254740992
        var hi = hex_start
        while hi < hex_end:
            var v = _hex_char_value(data[hi])
            if v < 0:
                result.error = "invalid hex digit in chunk size"
                result.bytes_consumed = pos
                return result^
            # Overflow check: chunk_size * 16 + v > MAX_SAFE
            if chunk_size > (MAX_SAFE - v) // 16:
                result.error = "chunk size overflow"
                result.bytes_consumed = pos
                return result^
            chunk_size = chunk_size * 16 + v
            hi += 1

        # Skip past the CRLF after the size line.
        pos += 2  # skip \r\n

        # ---- Step 5: Check max_chunk_size ----
        if chunk_size > config.max_chunk_size:
            result.error = "chunk size exceeds maximum"
            result.bytes_consumed = pos
            return result^

        # ---- Step 6: Last chunk (size == 0) ----
        if chunk_size == 0:
            # Parse optional trailer section: header lines until empty CRLF.
            while pos < data_len - 1:
                if data[pos] == UInt8(ord("\r")) and data[pos + 1] == UInt8(ord("\n")):
                    # Empty line terminates trailer section.
                    pos += 2
                    break

                # Read a trailer header line until CRLF.
                var line_start = pos
                var line_crlf = False
                while pos < data_len - 1:
                    if data[pos] == UInt8(ord("\r")) and data[pos + 1] == UInt8(ord("\n")):
                        line_crlf = True
                        break
                    pos += 1

                if not line_crlf:
                    result.error = "missing CRLF in trailer"
                    result.bytes_consumed = pos
                    return result^

                # Parse "Name: Value" from line_start..pos.
                var colon_pos = -1
                var ci = line_start
                while ci < pos:
                    if data[ci] == UInt8(ord(":")):
                        colon_pos = ci
                        break
                    ci += 1

                if colon_pos >= 0:
                    # Build name string char by char
                    var name = String()
                    var vi2 = line_start
                    while vi2 < colon_pos:
                        name += chr(Int(data[vi2]))
                        vi2 += 1

                    # Skip optional whitespace after colon.
                    var val_start = colon_pos + 1
                    while val_start < pos and (
                        data[val_start] == UInt8(ord(" "))
                        or data[val_start] == UInt8(ord("\t"))
                    ):
                        val_start += 1

                    # Strip trailing OWS from value
                    var val_end = pos
                    while val_end > val_start and (
                        data[val_end - 1] == UInt8(ord(" "))
                        or data[val_end - 1] == UInt8(ord("\t"))
                    ):
                        val_end -= 1

                    # Build value string char by char
                    var value = String()
                    var vi3 = val_start
                    while vi3 < val_end:
                        value += chr(Int(data[vi3]))
                        vi3 += 1

                    result.trailers.append(Header(name^, value^))

                pos += 2  # skip CRLF

            result.bytes_consumed = pos
            return result^

        # ---- Step 7: Read chunk_size bytes of data ----
        if pos + chunk_size > data_len:
            result.error = "not enough data for chunk"
            result.bytes_consumed = pos
            return result^

        var di = 0
        while di < chunk_size:
            result.body.append(data[pos + di])
            di += 1
        pos += chunk_size

        # ---- Step 8: Expect CRLF after chunk data ----
        if pos + 2 > data_len:
            result.error = "missing CRLF after chunk data"
            result.bytes_consumed = pos
            return result^
        if data[pos] != UInt8(ord("\r")) or data[pos + 1] != UInt8(ord("\n")):
            result.error = "missing CRLF after chunk data"
            result.bytes_consumed = pos
            return result^
        pos += 2

        # ---- Step 9: Loop back for next chunk ----


def encode_chunked(data: List[UInt8], chunk_size: Int = 1024) -> List[UInt8]:
    """Encode data using chunked transfer encoding.

    Each slice of *chunk_size* bytes is emitted as:
        hex(len) CRLF data CRLF
    followed by the last-chunk marker "0\\r\\n\\r\\n".
    """
    var result = List[UInt8]()
    var data_len = len(data)
    var offset = 0

    while offset < data_len:
        var remaining = data_len - offset
        var this_chunk = remaining if remaining < chunk_size else chunk_size

        # Write hex size.
        var hex_bytes = _int_to_hex(this_chunk)
        for i in range(len(hex_bytes)):
            result.append(hex_bytes[i])

        # CRLF after size.
        result.append(UInt8(ord("\r")))
        result.append(UInt8(ord("\n")))

        # Chunk data.
        var i = 0
        while i < this_chunk:
            result.append(data[offset + i])
            i += 1
        offset += this_chunk

        # CRLF after data.
        result.append(UInt8(ord("\r")))
        result.append(UInt8(ord("\n")))

    # Last chunk: "0\r\n\r\n"
    result.append(UInt8(ord("0")))
    result.append(UInt8(ord("\r")))
    result.append(UInt8(ord("\n")))
    result.append(UInt8(ord("\r")))
    result.append(UInt8(ord("\n")))

    return result^
