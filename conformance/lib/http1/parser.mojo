# conformance/lib/http1/parser.mojo
#
# HTTP/1.1 request parser per RFC 9112.

from .types import ParseConfig, Header, ParsedRequest
from .chunked import decode_chunked


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


def parse_request(
    wire: List[UInt8], config: ParseConfig = ParseConfig()
) -> ParsedRequest:
    """Parse a complete HTTP/1.1 request message from raw bytes.

    Returns a ParsedRequest with fields populated, or with .error set on failure.
    """
    var result = ParsedRequest()
    var data_len = len(wire)

    # ---- Step 1: Find and parse request line ----
    var allow_lf = config.strictness.allow_bare_lf
    var req_line_result = _find_line_end(wire, 0, allow_lf)
    var req_line_end = req_line_result[0]
    var req_line_skip = req_line_result[1]
    if req_line_end < 0:
        result.error = "missing CRLF in request line"
        return result^

    var req_line_len = req_line_end  # length from start (0) to line end marker
    if req_line_len > config.max_request_line:
        result.error = "request line exceeds maximum length"
        return result^

    # Split request line by SP (0x20) — must have exactly 3 parts.
    # Find first SP
    var sp1 = -1
    var i = 0
    while i < req_line_end:
        if wire[i] == UInt8(0x20):
            sp1 = i
            break
        i += 1

    if sp1 < 0:
        result.error = "invalid request line: missing SP after method"
        return result^

    if sp1 == 0:
        result.error = "empty method in request line"
        return result^

    # Skip consecutive spaces after method if allow_multiple_spaces
    var target_start = sp1 + 1
    if config.strictness.allow_multiple_spaces:
        while target_start < req_line_end and wire[target_start] == UInt8(0x20):
            target_start += 1

    # Find second SP — search backward from end when allow_multiple_spaces
    var sp2 = -1
    var target_end_pos = -1
    if config.strictness.allow_multiple_spaces:
        # Find the last SP by searching backward from end
        i = req_line_end - 1
        while i > target_start:
            if wire[i] == UInt8(0x20):
                sp2 = i
                break
            i -= 1
        # Walk backward past consecutive spaces to find actual target end
        if sp2 > 0:
            target_end_pos = sp2
            while target_end_pos > target_start and wire[target_end_pos - 1] == UInt8(0x20):
                target_end_pos -= 1
    else:
        i = target_start
        while i < req_line_end:
            if wire[i] == UInt8(0x20):
                sp2 = i
                break
            i += 1
        target_end_pos = sp2

    if sp2 < 0:
        result.error = "invalid request line: missing SP after target"
        return result^

    # Method: bytes [0, sp1)
    var method = _bytes_to_string(wire, 0, sp1)

    # Validate method characters
    i = 0
    while i < sp1:
        if not _is_token_char(wire[i]):
            result.error = "invalid character in method"
            return result^
        i += 1

    # Target: bytes [target_start, target_end_pos)
    if target_end_pos == target_start:
        result.error = "empty target in request line"
        return result^

    # Validate target: reject NUL bytes always, control chars in strict mode
    var ti = target_start
    while ti < target_end_pos:
        var tb = Int(wire[ti])
        if tb == 0x00:
            result.error = "NUL byte in request target"
            return result^
        if not config.strictness.allow_target_ctl and (tb <= 0x1F or tb == 0x7F):
            result.error = "control character in request target"
            return result^
        ti += 1

    var target = _bytes_to_string(wire, target_start, target_end_pos)

    # Version: bytes [sp2+1, req_line_end)
    var version_str = _bytes_to_string(wire, sp2 + 1, req_line_end)

    # Must be "HTTP/1.0" or "HTTP/1.1" (unless relaxed)
    if version_str == "HTTP/1.1":
        result.version = String("1.1")
    elif version_str == "HTTP/1.0":
        result.version = String("1.0")
    elif version_str == "HTTP/0.9" and config.strictness.allow_http_09:
        result.version = String("0.9")
    elif config.strictness.allow_nonstandard_version:
        # Accept any HTTP/X.Y format — version starts after "HTTP/"
        # sp2+1 is start of version_str, sp2+1+5 is start of version number
        var ver_prefix_end = sp2 + 1 + 5  # skip past "HTTP/"
        if ver_prefix_end <= req_line_end:
            var vb = version_str.as_bytes()
            if len(vb) >= 6 and vb[0] == UInt8(72) and vb[1] == UInt8(84) and vb[2] == UInt8(84) and vb[3] == UInt8(80) and vb[4] == UInt8(47):
                result.version = _bytes_to_string(wire, ver_prefix_end, req_line_end)
            else:
                result.error = "unsupported HTTP version: " + version_str
                return result^
        else:
            result.error = "unsupported HTTP version: " + version_str
            return result^
    else:
        result.error = "unsupported HTTP version: " + version_str
        return result^

    result.method = method^
    result.target = target^

    # ---- Step 2: Parse headers ----
    var pos = req_line_end + req_line_skip  # skip past line ending of request line
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
                result.error = "obs-fold not allowed"
                return result^
            # Lenient: append to previous header's value
            if len(result.headers) == 0:
                result.error = "obs-fold with no previous header"
                return result^

            var fold_result = _find_line_end(wire, pos, allow_lf)
            var fold_end = fold_result[0]
            var fold_skip = fold_result[1]
            if fold_end < 0:
                result.error = "missing CRLF in obs-fold line"
                return result^

            # Trim leading whitespace from the fold line
            var fold_start = pos
            while fold_start < fold_end and (wire[fold_start] == UInt8(0x20) or wire[fold_start] == UInt8(0x09)):
                fold_start += 1

            var fold_text = _bytes_to_string(wire, fold_start, fold_end)

            # Append to previous header value with a space separator
            var prev_idx = len(result.headers) - 1
            var old_val = result.headers[prev_idx].value
            result.headers[prev_idx].value = old_val + " " + fold_text

            pos = fold_end + fold_skip
            continue

        # Find end of this header line
        var hdr_line_result = _find_line_end(wire, pos, allow_lf)
        var line_end = hdr_line_result[0]
        var line_skip = hdr_line_result[1]
        if line_end < 0:
            result.error = "missing CRLF in header line"
            return result^

        var line_len = line_end - pos

        # Check header line size limit
        if line_len > config.max_header_size:
            result.error = "header line exceeds maximum size"
            return result^

        # Find the colon
        var colon_pos = -1
        var ci = pos
        while ci < line_end:
            if wire[ci] == UInt8(0x3A):  # ':'
                colon_pos = ci
                break
            ci += 1

        if colon_pos < 0:
            result.error = "missing colon in header line"
            return result^

        # Check for whitespace between field-name and colon
        if not config.strictness.allow_space_before_colon and _has_whitespace_before_colon(wire, pos, colon_pos):
            result.error = "whitespace before colon in header"
            return result^

        # Extract field name: [pos, name_end)
        # If lenient and there's ws before colon, strip it from name
        var name_end = colon_pos
        if config.strictness.allow_space_before_colon:
            while name_end > pos and (wire[name_end - 1] == UInt8(0x20) or wire[name_end - 1] == UInt8(0x09)):
                name_end -= 1

        # Validate field name: must be all token characters (RFC 9110 section 5.6.2)
        if name_end == pos:
            result.error = "empty header field name"
            return result^
        var name_valid = True
        var ni = pos
        while ni < name_end:
            if not _is_token_char(wire[ni]):
                if config.strictness.ignore_invalid_header_names:
                    name_valid = False
                    break
                result.error = "invalid character in header field name"
                return result^
            ni += 1

        if not name_valid:
            # Skip this header line entirely (but still count it for limits)
            header_count += 1
            if header_count > config.max_header_count:
                result.error = "too many headers"
                return result^
            headers_total_size += line_len
            if headers_total_size > config.max_headers_total:
                result.error = "headers total size exceeds maximum"
                return result^
            pos = line_end + line_skip
            continue

        var field_name = _bytes_to_string(wire, pos, name_end)

        # Field value: everything after colon, with OWS stripped
        var val_bounds = _strip_ows_bounds(wire, colon_pos + 1, line_end)
        var val_start = val_bounds[0]
        var val_end = val_bounds[1]

        # Check for NUL in field value (always)
        if _contains_nul(wire, colon_pos + 1, line_end):
            result.error = "NUL byte in header field value"
            return result^

        # In strict mode, reject control characters in header values
        # When allow_bare_cr_in_value is set, skip CR (0x0D) in ctl check
        if not config.strictness.allow_header_value_ctl and _contains_ctl_in_value(wire, colon_pos + 1, line_end, skip_cr=config.strictness.allow_bare_cr_in_value):
            result.error = "control character in header field value"
            return result^

        var field_value = _bytes_to_string(wire, val_start, val_end)

        # Count headers
        header_count += 1
        if header_count > config.max_header_count:
            result.error = "too many headers"
            return result^

        headers_total_size += line_len
        if headers_total_size > config.max_headers_total:
            result.error = "headers total size exceeds maximum"
            return result^

        result.headers.append(Header(field_name^, field_value^))
        pos = line_end + line_skip  # skip line ending

    # ---- Step 3: Semantic validation ----
    var cl_value = String("")
    var cl_count = 0
    var te_value = String("")
    var te_count = 0
    var host_count = 0

    for hi in range(len(result.headers)):
        var hdr_name = result.headers[hi].name
        var hdr_val = result.headers[hi].value
        if _iequals(hdr_name, "content-length"):
            cl_count += 1
            if cl_count == 1:
                cl_value = hdr_val
            else:
                # Check if values differ
                if hdr_val != cl_value:
                    result.error = "multiple Content-Length headers with different values"
                    return result^
        if _iequals(hdr_name, "transfer-encoding"):
            te_count += 1
            te_value = hdr_val
        if _iequals(hdr_name, "host"):
            host_count += 1

    # CL + TE conflict (ALWAYS reject)
    if cl_count > 0 and te_count > 0:
        result.error = "CL+TE conflict"
        return result^

    # Multiple identical CL in strict mode
    if cl_count > 1 and not config.strictness.allow_duplicate_cl:
        result.error = "multiple Content-Length headers"
        return result^

    # CL value validation
    if cl_count > 0:
        # I5: Reject leading zeros in strict mode
        var cl_bytes = cl_value.as_bytes()
        if not config.strictness.allow_cl_leading_zeros and len(cl_bytes) > 1 and cl_bytes[0] == UInt8(ord("0")):
            result.error = "Content-Length has leading zeros"
            return result^

        var cl_int = _parse_int(cl_value)
        if cl_int == -2:
            result.error = "Content-Length overflow"
            return result^
        if cl_int < 0:
            result.error = "invalid Content-Length value"
            return result^

        # I7: Check against max_body_size
        if cl_int > config.max_body_size:
            result.error = "Content-Length exceeds max body size"
            return result^

    # Host header checks (HTTP/1.1 only)
    if not config.strictness.allow_missing_host_11 and result.version == "1.1" and host_count == 0:
        result.error = "missing Host header"
        return result^
    if not config.strictness.allow_duplicate_host and result.version == "1.1" and host_count > 1:
        result.error = "duplicate Host header"
        return result^

    # TE strict validation
    if not config.strictness.allow_non_chunked_te and te_count > 0:
        if te_value != "chunked":
            result.error = "Transfer-Encoding must be exactly 'chunked'"
            return result^

    # ---- Step 4: Read body ----
    if te_count > 0:
        # C3: In lenient mode, check TE value contains "chunked" (case-insensitive)
        # In strict mode, we already validated it's exactly "chunked"
        if config.strictness.allow_non_chunked_te:
            if not _icontains(te_value, "chunked"):
                result.error = "unsupported Transfer-Encoding"
                return result^

        var remaining = List[UInt8]()
        var ri = pos
        while ri < data_len:
            remaining.append(wire[ri])
            ri += 1

        var chunk_result = decode_chunked(remaining, config)
        if len(chunk_result.error) > 0:
            result.error = chunk_result.error
            return result^
        # Copy decoded body bytes
        for bi in range(len(chunk_result.body)):
            result.body.append(chunk_result.body[bi])

        # I7: Check total body size against max_body_size
        if len(result.body) > config.max_body_size:
            result.error = "chunked body exceeds max body size"
            return result^

        # C2: Copy trailers from chunk result
        for ti2 in range(len(chunk_result.trailers)):
            result.trailers.append(
                Header(chunk_result.trailers[ti2].name, chunk_result.trailers[ti2].value)
            )
        _ = chunk_result^
    elif cl_count > 0:
        var cl_int = _parse_int(cl_value)
        # cl_int is guaranteed >= 0 here since we validated above
        var remaining_bytes = data_len - pos
        if remaining_bytes < cl_int:
            result.error = "truncated body"
            return result^
        var bi = 0
        while bi < cl_int:
            result.body.append(wire[pos + bi])
            bi += 1
    # else: no body

    return result^
