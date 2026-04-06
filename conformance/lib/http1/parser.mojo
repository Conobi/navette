# conformance/lib/http1/parser.mojo
#
# HTTP/1.1 request parser per RFC 9112.

from .types import ParseConfig, Header, ParsedRequest
from .chunked import decode_chunked
from ._helpers import (
    _is_token_char,
    _to_lower,
    _bytes_to_string,
    _iequals,
    _icontains,
    _parse_int,
    _find_crlf,
    _find_line_end,
    _strip_ows_bounds,
    _contains_nul,
    _contains_ctl_in_value,
    _has_whitespace_before_colon,
    _parse_headers,
)


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
        # Reject non-ASCII bytes in strict mode (should be percent-encoded per RFC 3986)
        if not config.strictness.allow_target_ctl and tb > 0x7E:
            result.error = "non-ASCII byte in request target"
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

    var header_result = _parse_headers(wire, pos, config)
    var hdr_error = header_result[2]
    if len(hdr_error) > 0:
        result.error = hdr_error
        return result^
    pos = header_result[1]
    var parsed_headers = header_result[0].copy()
    for hi in range(len(parsed_headers)):
        result.headers.append(Header(parsed_headers[hi].name, parsed_headers[hi].value))

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
        result.bytes_consumed = pos + chunk_result.bytes_consumed
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
        result.bytes_consumed = pos + cl_int
    else:
        # No body
        result.bytes_consumed = pos

    return result^
