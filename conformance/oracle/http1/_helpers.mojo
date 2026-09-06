# conformance/lib/http1/_helpers.mojo
#
# Shared utility functions for HTTP/1.1 request and response parsers.

from .types import ParseConfig, Header


def _is_token_char(b: UInt8) -> Bool:
    """Check if byte is a valid HTTP token character (RFC 9110 section 5.6.2).

    tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
            "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
    """
    var c = Int(b)
    # A-Z
    if c >= 65 and c <= 90:
        return True
    # a-z
    if c >= 97 and c <= 122:
        return True
    # 0-9
    if c >= 48 and c <= 57:
        return True
    # Special token characters: !#$%&'*+-.^_`|~
    if c == 33:  # !
        return True
    if c == 35:  # #
        return True
    if c == 36:  # $
        return True
    if c == 37:  # %
        return True
    if c == 38:  # &
        return True
    if c == 39:  # '
        return True
    if c == 42:  # *
        return True
    if c == 43:  # +
        return True
    if c == 45:  # -
        return True
    if c == 46:  # .
        return True
    if c == 94:  # ^
        return True
    if c == 95:  # _
        return True
    if c == 96:  # `
        return True
    if c == 124:  # |
        return True
    if c == 126:  # ~
        return True
    return False


def _to_lower(b: UInt8) -> UInt8:
    """Convert ASCII uppercase to lowercase."""
    if b >= UInt8(65) and b <= UInt8(90):
        return b + 32
    return b


def _bytes_to_string(data: List[UInt8], start: Int, end: Int) -> String:
    """Extract bytes from data[start:end] into a String."""
    var result = String()
    var i = start
    while i < end:
        result += chr(Int(data[i]))
        i += 1
    return result^


def _iequals(a: String, b: String) -> Bool:
    """Case-insensitive string comparison."""
    var a_bytes = a.as_bytes()
    var b_bytes = b.as_bytes()
    if len(a_bytes) != len(b_bytes):
        return False
    for i in range(len(a_bytes)):
        if _to_lower(a_bytes[i]) != _to_lower(b_bytes[i]):
            return False
    return True


def _icontains(haystack: String, needle: String) -> Bool:
    """Case-insensitive substring check."""
    var h_bytes = haystack.as_bytes()
    var n_bytes = needle.as_bytes()
    var h_len = len(h_bytes)
    var n_len = len(n_bytes)
    if n_len == 0:
        return True
    if n_len > h_len:
        return False
    for i in range(h_len - n_len + 1):
        var found = True
        for j in range(n_len):
            if _to_lower(h_bytes[i + j]) != _to_lower(n_bytes[j]):
                found = False
                break
        if found:
            return True
    return False


def _parse_int(s: String) -> Int:
    """Parse a non-negative integer from a string. Returns -1 on failure.
    Returns -2 on overflow (value exceeds 2^53).
    """
    var bytes = s.as_bytes()
    if len(bytes) == 0:
        return -1
    var result = 0
    # Cap at 2^53 (9007199254740992) to prevent silent overflow
    comptime MAX_SAFE = 9007199254740992
    for i in range(len(bytes)):
        var b = bytes[i]
        if b < UInt8(48) or b > UInt8(57):
            return -1
        var digit = Int(b) - 48
        # Overflow check: result * 10 + digit > MAX_SAFE
        if result > (MAX_SAFE - digit) // 10:
            return -2
        result = result * 10 + digit
    return result


def _find_crlf(data: List[UInt8], start: Int) -> Int:
    """Find the position of the next CRLF starting from `start`.
    Returns the index of CR, or -1 if not found.
    """
    var data_len = len(data)
    if data_len < 2 or start > data_len - 2:
        return -1
    var i = start
    while i < data_len - 1:
        if data[i] == UInt8(0x0D) and data[i + 1] == UInt8(0x0A):
            return i
        i += 1
    return -1


def _find_line_end(data: List[UInt8], start: Int, allow_lf: Bool) -> Tuple[Int, Int]:
    """Find next line ending. Returns (position, skip_bytes).
    CRLF: returns (pos_of_CR, 2). Bare LF (if allowed): returns (pos_of_LF, 1).
    Not found: returns (-1, 0).
    """
    var data_len = len(data)
    var i = start
    while i < data_len:
        if i + 1 < data_len and data[i] == UInt8(0x0D) and data[i + 1] == UInt8(0x0A):
            return (i, 2)
        if allow_lf and data[i] == UInt8(0x0A):
            return (i, 1)
        i += 1
    return (-1, 0)


def _strip_ows_bounds(data: List[UInt8], start: Int, end: Int) -> Tuple[Int, Int]:
    """Return (new_start, new_end) with leading/trailing OWS (SP/HTAB) removed."""
    var s = start
    var e = end
    while s < e and (data[s] == UInt8(0x20) or data[s] == UInt8(0x09)):
        s += 1
    while e > s and (data[e - 1] == UInt8(0x20) or data[e - 1] == UInt8(0x09)):
        e -= 1
    return (s, e)


def _contains_nul(data: List[UInt8], start: Int, end: Int) -> Bool:
    """Check if data[start:end] contains a NUL byte."""
    var i = start
    while i < end:
        if data[i] == UInt8(0x00):
            return True
        i += 1
    return False


def _contains_ctl_in_value(data: List[UInt8], start: Int, end: Int, skip_cr: Bool = False) -> Bool:
    """Check if data[start:end] contains control characters invalid in header values.
    Valid bytes: HTAB (0x09), SP (0x20), VCHAR (0x21-0x7E), obs-text (0x80-0xFF).
    Invalid: 0x00-0x08, 0x0A-0x0C, 0x0E-0x1F, 0x7F.
    When skip_cr is True, 0x0D (CR) is also allowed (for allow_bare_cr_in_value).
    """
    var i = start
    while i < end:
        var c = Int(data[i])
        if c == 0x09:
            # HTAB is allowed
            i += 1
            continue
        if skip_cr and c == 0x0D:
            i += 1
            continue
        if c <= 0x1F or c == 0x7F:
            return True
        i += 1
    return False


def _has_whitespace_before_colon(data: List[UInt8], name_start: Int, colon_pos: Int) -> Bool:
    """Check if there's whitespace between the field-name and the colon.
    The name runs from name_start to where we need to check for trailing ws
    before colon_pos.
    """
    if colon_pos <= name_start:
        return False
    var b = data[colon_pos - 1]
    return b == UInt8(0x20) or b == UInt8(0x09)


def _parse_headers(
    wire: List[UInt8],
    start_pos: Int,
    config: ParseConfig,
) -> Tuple[List[Header], Int, String]:
    """Parse HTTP header block starting at start_pos.

    Returns a 3-element tuple:
    - [0]: List[Header] — parsed headers (empty on error)
    - [1]: Int — byte offset after the final empty line (first byte of body)
    - [2]: String — error message (empty on success)
    """
    var headers = List[Header]()
    var pos = start_pos
    var data_len = len(wire)
    var allow_lf = config.strictness.allow_bare_lf
    var header_count = 0
    var headers_total_size = 0

    while pos < data_len:
        # Check for empty line (end of headers)
        if pos + 1 < data_len and wire[pos] == UInt8(0x0D) and wire[pos + 1] == UInt8(0x0A):
            pos += 2  # skip the final CRLF
            break
        if allow_lf and pos < data_len and wire[pos] == UInt8(0x0A):
            pos += 1  # skip the bare LF
            break

        # Check for obs-fold (line starting with SP or HTAB)
        if wire[pos] == UInt8(0x20) or wire[pos] == UInt8(0x09):
            if not config.strictness.allow_obs_fold:
                return (List[Header](), start_pos, String("obs-fold not allowed"))
            # Lenient: append to previous header's value
            if len(headers) == 0:
                return (List[Header](), start_pos, String("obs-fold with no previous header"))

            var fold_result = _find_line_end(wire, pos, allow_lf)
            var fold_end = fold_result[0]
            var fold_skip = fold_result[1]
            if fold_end < 0:
                return (List[Header](), start_pos, String("missing CRLF in obs-fold line"))

            # Trim leading whitespace from the fold line
            var fold_start = pos
            while fold_start < fold_end and (wire[fold_start] == UInt8(0x20) or wire[fold_start] == UInt8(0x09)):
                fold_start += 1

            var fold_text = _bytes_to_string(wire, fold_start, fold_end)

            # Append to previous header value with a space separator
            var prev_idx = len(headers) - 1
            var old_val = headers[prev_idx].value
            headers[prev_idx].value = old_val + " " + fold_text

            pos = fold_end + fold_skip
            continue

        # Find end of this header line
        var hdr_line_result = _find_line_end(wire, pos, allow_lf)
        var line_end = hdr_line_result[0]
        var line_skip = hdr_line_result[1]
        if line_end < 0:
            return (List[Header](), start_pos, String("missing CRLF in header line"))

        var line_len = line_end - pos

        # Check header line size limit
        if line_len > config.max_header_size:
            return (List[Header](), start_pos, String("header line exceeds maximum size"))

        # Find the colon
        var colon_pos = -1
        var ci = pos
        while ci < line_end:
            if wire[ci] == UInt8(0x3A):  # ':'
                colon_pos = ci
                break
            ci += 1

        if colon_pos < 0:
            return (List[Header](), start_pos, String("missing colon in header line"))

        # Check for whitespace between field-name and colon
        if not config.strictness.allow_space_before_colon and _has_whitespace_before_colon(wire, pos, colon_pos):
            return (List[Header](), start_pos, String("whitespace before colon in header"))

        # Extract field name: [pos, name_end)
        # If lenient and there's ws before colon, strip it from name
        var name_end = colon_pos
        if config.strictness.allow_space_before_colon:
            while name_end > pos and (wire[name_end - 1] == UInt8(0x20) or wire[name_end - 1] == UInt8(0x09)):
                name_end -= 1

        # Validate field name: must be all token characters (RFC 9110 section 5.6.2)
        if name_end == pos:
            return (List[Header](), start_pos, String("empty header field name"))
        var name_valid = True
        var ni = pos
        while ni < name_end:
            if not _is_token_char(wire[ni]):
                if config.strictness.ignore_invalid_header_names:
                    name_valid = False
                    break
                return (List[Header](), start_pos, String("invalid character in header field name"))
            ni += 1

        if not name_valid:
            # Skip this header line entirely (but still count it for limits)
            header_count += 1
            if header_count > config.max_header_count:
                return (List[Header](), start_pos, String("too many headers"))
            headers_total_size += line_len
            if headers_total_size > config.max_headers_total:
                return (List[Header](), start_pos, String("headers total size exceeds maximum"))
            pos = line_end + line_skip
            continue

        var field_name = _bytes_to_string(wire, pos, name_end)

        # Field value: everything after colon, with OWS stripped
        var val_bounds = _strip_ows_bounds(wire, colon_pos + 1, line_end)
        var val_start = val_bounds[0]
        var val_end = val_bounds[1]

        # Check for NUL in field value (always)
        if _contains_nul(wire, colon_pos + 1, line_end):
            return (List[Header](), start_pos, String("NUL byte in header field value"))

        # In strict mode, reject control characters in header values
        # When allow_bare_cr_in_value is set, skip CR (0x0D) in ctl check
        if not config.strictness.allow_header_value_ctl and _contains_ctl_in_value(wire, colon_pos + 1, line_end, skip_cr=config.strictness.allow_bare_cr_in_value):
            return (List[Header](), start_pos, String("control character in header field value"))

        var field_value = _bytes_to_string(wire, val_start, val_end)

        # Count headers
        header_count += 1
        if header_count > config.max_header_count:
            return (List[Header](), start_pos, String("too many headers"))

        headers_total_size += line_len
        if headers_total_size > config.max_headers_total:
            return (List[Header](), start_pos, String("headers total size exceeds maximum"))

        headers.append(Header(field_name^, field_value^))
        pos = line_end + line_skip  # skip line ending

    return (headers^, pos, String(""))
