# conformance/lib/http1/response.mojo
#
# HTTP/1.1 response parser per RFC 9112.

from .types import ParseConfig, Header, ParsedResponse
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
    _parse_headers,
)


def parse_response(
    wire: List[UInt8],
    request_method: String = "GET",
    config: ParseConfig = ParseConfig(),
) -> ParsedResponse:
    """Parse a complete HTTP/1.1 response message from raw bytes.

    Returns a ParsedResponse with fields populated, or with .error set on failure.
    """
    var result = ParsedResponse()
    var data_len = len(wire)

    # ---- Step 1: Find and parse status line (RFC 9112 section 4) ----
    var allow_lf = config.strictness.allow_bare_lf
    var status_line_result = _find_line_end(wire, 0, allow_lf)
    var status_line_end = status_line_result[0]
    var status_line_skip = status_line_result[1]
    if status_line_end < 0:
        result.error = "missing CRLF in status line"
        return result^

    var status_line_len = status_line_end  # length from start (0) to line end marker
    if status_line_len > config.max_request_line:
        result.error = "status line exceeds maximum length"
        return result^

    # Find first SP to separate version from status code
    var sp1 = -1
    var i = 0
    while i < status_line_end:
        if wire[i] == UInt8(0x20):
            sp1 = i
            break
        i += 1

    if sp1 < 0:
        result.error = "invalid status line: missing SP after version"
        return result^

    if sp1 == 0:
        result.error = "empty version in status line"
        return result^

    # Parse version: bytes [0, sp1)
    var version_str = _bytes_to_string(wire, 0, sp1)

    if version_str == "HTTP/1.1":
        result.version = String("1.1")
    elif version_str == "HTTP/1.0":
        result.version = String("1.0")
    elif version_str == "HTTP/0.9" and config.strictness.allow_http_09:
        result.version = String("0.9")
    elif config.strictness.allow_nonstandard_version:
        var vb = version_str.as_bytes()
        if len(vb) >= 6 and vb[0] == UInt8(72) and vb[1] == UInt8(84) and vb[2] == UInt8(84) and vb[3] == UInt8(80) and vb[4] == UInt8(47):
            result.version = _bytes_to_string(wire, 5, sp1)
        else:
            result.error = "unsupported HTTP version: " + version_str
            return result^
    else:
        result.error = "unsupported HTTP version: " + version_str
        return result^

    # Handle allow_multiple_spaces_in_status_line: skip consecutive SPs after version
    var code_start = sp1 + 1
    if config.strictness.allow_multiple_spaces_in_status_line:
        while code_start < status_line_end and wire[code_start] == UInt8(0x20):
            code_start += 1
    else:
        # In strict mode, check if the byte after the first SP is another SP
        if code_start < status_line_end and wire[code_start] == UInt8(0x20):
            result.error = "extra whitespace in status line"
            return result^

    # Read exactly 3 digits for status code
    if code_start + 3 > status_line_end:
        # Not enough bytes for 3 digits before line end
        # But could be exactly at end if no reason phrase
        if code_start + 3 > status_line_end:
            # Check if the remaining bytes are exactly at line end
            var remaining_for_code = status_line_end - code_start
            if remaining_for_code < 3:
                result.error = "status code too short"
                return result^

    # Validate each digit and parse status code
    var status_code = 0
    var di = 0
    while di < 3:
        var b = wire[code_start + di]
        if b < UInt8(48) or b > UInt8(57):  # not ASCII 0-9
            result.error = "invalid character in status code"
            return result^
        status_code = status_code * 10 + (Int(b) - 48)
        di += 1

    # Reject status code < 100
    if status_code < 100:
        result.error = "status code below 100"
        return result^

    result.status_code = status_code

    # After the 3 digits: check what follows
    var after_code = code_start + 3
    if after_code < status_line_end:
        # There are bytes after the status code before line end
        if wire[after_code] == UInt8(0x20):
            # SP after status code — reason is everything after SP to line end
            var reason_start = after_code + 1
            # Handle multiple spaces between status code and reason
            if config.strictness.allow_multiple_spaces_in_status_line:
                while reason_start < status_line_end and wire[reason_start] == UInt8(0x20):
                    reason_start += 1
            # Validate reason: no NUL bytes
            if _contains_nul(wire, reason_start, status_line_end):
                result.error = "NUL byte in reason phrase"
                return result^
            result.reason = _bytes_to_string(wire, reason_start, status_line_end)
        else:
            # Not a SP after status code — this means the status code is not exactly 3 digits
            # (e.g. "0200 OK" where after reading "020", next byte is "0" not SP)
            result.error = "status code is not exactly 3 digits"
            return result^
    elif after_code == status_line_end:
        # Nothing after status code — no SP, no reason
        if not config.strictness.allow_missing_reason_sp:
            result.error = "missing SP after status code"
            return result^
        result.reason = String("")
    else:
        result.error = "status code too short"
        return result^

    # ---- Step 2: Parse headers ----
    var pos = status_line_end + status_line_skip  # skip past line ending of status line

    # Handle allow_space_before_first_header: check if there's a blank line right after
    # the status line. If the flag is True, skip it. If False, it terminates headers normally.
    if config.strictness.allow_space_before_first_header:
        # Check for an extra blank line (CRLF or bare LF) right after status line
        if pos + 1 < data_len and wire[pos] == UInt8(0x0D) and wire[pos + 1] == UInt8(0x0A):
            # Check if this blank line is followed by header-like content
            # (i.e., not another blank line). If so, skip this blank line.
            var after_blank = pos + 2
            if after_blank < data_len and wire[after_blank] != UInt8(0x0D) and wire[after_blank] != UInt8(0x0A):
                pos = after_blank
        elif allow_lf and pos < data_len and wire[pos] == UInt8(0x0A):
            var after_blank = pos + 1
            if after_blank < data_len and wire[after_blank] != UInt8(0x0D) and wire[after_blank] != UInt8(0x0A):
                pos = after_blank

    var header_result = _parse_headers(wire, pos, config)
    var hdr_error = header_result[2]
    if len(hdr_error) > 0:
        result.error = hdr_error
        return result^
    var body_start = header_result[1]
    var parsed_headers = header_result[0].copy()
    for hi in range(len(parsed_headers)):
        result.headers.append(Header(parsed_headers[hi].name, parsed_headers[hi].value))

    # ---- Step 3: Semantic validation ----
    var cl_value = String("")
    var cl_count = 0
    var te_value = String("")
    var te_count = 0

    for hi in range(len(result.headers)):
        var hdr_name = result.headers[hi].name
        var hdr_val = result.headers[hi].value
        if _iequals(hdr_name, "content-length"):
            cl_count += 1
            if cl_count == 1:
                cl_value = hdr_val
            else:
                # Check if values differ — invariant: always error
                if hdr_val != cl_value:
                    result.error = "multiple Content-Length values that differ"
                    return result^
        if _iequals(hdr_name, "transfer-encoding"):
            te_count += 1
            te_value = hdr_val

    # ---- Step 4: Body determination (8 rules in priority order) ----

    # Rule 1: HEAD request — no body
    if _iequals(request_method, "HEAD"):
        result.bytes_consumed = body_start
        return result^

    # Rule 2: CONNECT with 2xx — no body, upgrade=True
    if _iequals(request_method, "CONNECT") and status_code >= 200 and status_code <= 299:
        result.upgrade = True
        result.bytes_consumed = body_start
        return result^

    # Rule 3: 1xx informational — no body
    if status_code >= 100 and status_code <= 199:
        if te_count > 0:
            result.error = "Transfer-Encoding in 1xx response"
            return result^
        if status_code == 101:
            result.upgrade = True
        result.bytes_consumed = body_start
        return result^

    # Rule 4: 204 No Content — no body
    if status_code == 204:
        if te_count > 0:
            result.error = "Transfer-Encoding in 204 response"
            return result^
        result.bytes_consumed = body_start
        return result^

    # Rule 5: 304 Not Modified — no body, TE is IGNORED (not rejected), CL preserved
    if status_code == 304:
        result.bytes_consumed = body_start
        return result^

    # Rule 6: TE present
    if te_count > 0:
        # CL+TE coexistence check
        if cl_count > 0:
            if not config.strictness.allow_response_cl_te:
                result.error = "response has both Content-Length and Transfer-Encoding"
                return result^
            # else: TE takes precedence, CL ignored

        if _icontains(te_value, "chunked"):
            # Strict: TE must be exactly "chunked"
            if not config.strictness.allow_non_chunked_te:
                if te_value != "chunked":
                    result.error = "Transfer-Encoding without chunked as final encoding"
                    return result^

            # Decode chunked body
            var remaining = List[UInt8]()
            var ri = body_start
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

            # Check total body size against max_body_size
            if len(result.body) > config.max_body_size:
                result.error = "chunked body exceeds max body size"
                return result^

            # Copy trailers from chunk result
            for ti2 in range(len(chunk_result.trailers)):
                result.trailers.append(
                    Header(chunk_result.trailers[ti2].name, chunk_result.trailers[ti2].value)
                )

            result.bytes_consumed = body_start + chunk_result.bytes_consumed
            _ = chunk_result^
            return result^
        else:
            # TE does NOT contain "chunked"
            if not config.strictness.allow_non_chunked_te:
                result.error = "Transfer-Encoding without chunked as final encoding"
                return result^
            # Read until end of wire
            var ri = body_start
            while ri < data_len:
                result.body.append(wire[ri])
                ri += 1
            result.body_terminated_by_close = True
            result.bytes_consumed = data_len
            return result^

    # Rule 7: CL present
    if cl_count > 0:
        # Multiple identical CL in strict mode
        if cl_count > 1 and not config.strictness.allow_duplicate_cl:
            result.error = "duplicate Content-Length header"
            return result^

        # CL leading zeros
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

        # Check against max_body_size
        if cl_int > config.max_body_size:
            result.error = "Content-Length exceeds max body size"
            return result^

        # Check if enough bytes available
        var remaining_bytes = data_len - body_start
        if remaining_bytes < cl_int:
            result.error = "body shorter than Content-Length"
            return result^

        # Read exactly cl_int bytes
        var bi = 0
        while bi < cl_int:
            result.body.append(wire[body_start + bi])
            bi += 1

        result.bytes_consumed = body_start + cl_int
        return result^

    # Rule 8: Neither TE nor CL — read all remaining bytes as body
    var ri = body_start
    while ri < data_len:
        result.body.append(wire[ri])
        ri += 1
    result.body_terminated_by_close = True
    result.bytes_consumed = data_len
    return result^
