# src/h1/parser.mojo
#
# Incremental HTTP/1.1 parser used by H1Connection.
#
# This module is intentionally NOT a public API surface. It exposes two entry
# points -- ``try_parse_request`` and ``try_parse_response`` -- which return a
# ``ParseResult``. The result reports one of three outcomes:
#
#   * a complete message was parsed (``request`` or ``response`` set);
#   * the buffer is incomplete (no message, no error, ``new_last_scanned``
#     advanced so the next call resumes scanning where this one stopped);
#   * the wire data is malformed (``error`` populated).
#
# The parser implements the security invariants and the 9-step body length
# determination algorithm from RFC 9112 Section 6. Validation logic is shared
# with the conformance reference parser at conformance/lib/http1/.

from std.collections.optional import Optional
from std.memory import Span

from navette.http.method import Method
from navette.http.status import StatusCode
from navette.http.version import Version
from navette.http.headers import Headers
from navette.http.body import BodyFrame
from navette.http.request import Request, RequestBody
from navette.http.response import Response
from navette.h1.config import ParseConfig


# IEEE 754 double-precision integer-safe ceiling. Used to bound Content-Length
# and chunk-size parsing so a hostile peer cannot push us into Int overflow.
comptime _MAX_SAFE_INT = 9007199254740992


# --- Byte-level scanning helpers ---


def _find_header_end(
    buf: List[UInt8], start: Int, last_scanned: Int
) -> Int:
    """Scan for CRLF CRLF starting at max(start, last_scanned).

    Returns the index of the first CR of the terminator, or -1 if absent.
    This is the picohttpparser O(n)-amortized trick: callers track how far
    they have already scanned and only re-examine the freshly buffered bytes.
    """
    var scan_from = last_scanned if last_scanned > start else start
    var buf_len = len(buf)
    if buf_len < 4:
        return -1
    if scan_from < start:
        scan_from = start
    var i = scan_from
    while i <= buf_len - 4:
        if (
            buf[i] == UInt8(0x0D)
            and buf[i + 1] == UInt8(0x0A)
            and buf[i + 2] == UInt8(0x0D)
            and buf[i + 3] == UInt8(0x0A)
        ):
            return i
        i += 1
    return -1


def _find_header_end_lf(
    buf: List[UInt8], start: Int, last_scanned: Int
) -> Tuple[Int, Bool]:
    """Scan for the header terminator allowing bare LF.

    First tries CRLF CRLF; if absent, falls back to LF LF. Returns
    ``(position, is_crlf)``; ``position`` is -1 when nothing is found.
    """
    var crlf_pos = _find_header_end(buf, start, last_scanned)
    if crlf_pos >= 0:
        return (crlf_pos, True)
    var scan_from = last_scanned if last_scanned > start else start
    if scan_from < start:
        scan_from = start
    var buf_len = len(buf)
    if buf_len < 2:
        return (-1, False)
    var i = scan_from
    while i <= buf_len - 2:
        if buf[i] == UInt8(0x0A) and buf[i + 1] == UInt8(0x0A):
            return (i, False)
        i += 1
    return (-1, False)


# --- Character-class and string helpers (mirrors conformance/_helpers.mojo) ---


def _is_token_char(b: UInt8) -> Bool:
    """Return True if ``b`` is a valid HTTP token character (RFC 9110 5.6.2)."""
    var c = Int(b)
    if c >= 65 and c <= 90:
        return True
    if c >= 97 and c <= 122:
        return True
    if c >= 48 and c <= 57:
        return True
    if c == 33: return True
    if c == 35: return True
    if c == 36: return True
    if c == 37: return True
    if c == 38: return True
    if c == 39: return True
    if c == 42: return True
    if c == 43: return True
    if c == 45: return True
    if c == 46: return True
    if c == 94: return True
    if c == 95: return True
    if c == 96: return True
    if c == 124: return True
    if c == 126: return True
    return False


def _to_lower(b: UInt8) -> UInt8:
    """Return the ASCII lowercase form of ``b``."""
    if b >= UInt8(65) and b <= UInt8(90):
        return b + UInt8(32)
    return b


@always_inline
def _bytes_to_string(data: List[UInt8], start: Int, end: Int) -> String:
    """Build a String from an ASCII byte slice (caller guarantees ASCII)."""
    var n = end - start
    if n <= 0:
        return String()
    var out = List[UInt8](capacity=n)
    out.extend(Span(data)[start:end])
    return String(unsafe_from_utf8=out^)


def _iequals(a: String, b: String) -> Bool:
    """Return True if ``a`` and ``b`` compare equal under ASCII case folding."""
    var ab = a.as_bytes()
    var bb = b.as_bytes()
    if len(ab) != len(bb):
        return False
    for i in range(len(ab)):
        if _to_lower(ab[i]) != _to_lower(bb[i]):
            return False
    return True


def _icontains(haystack: String, needle: String) -> Bool:
    """Return True if ``needle`` occurs in ``haystack`` (ASCII case-insensitive)."""
    var h = haystack.as_bytes()
    var n = needle.as_bytes()
    var hl = len(h)
    var nl = len(n)
    if nl == 0:
        return True
    if nl > hl:
        return False
    for i in range(hl - nl + 1):
        var found = True
        for j in range(nl):
            if _to_lower(h[i + j]) != _to_lower(n[j]):
                found = False
                break
        if found:
            return True
    return False


def _parse_int(s: String) -> Int:
    """Parse a non-negative decimal integer.

    Returns the value, ``-1`` for malformed input, ``-2`` for overflow beyond
    the IEEE 754 safe-integer ceiling.
    """
    var b = s.as_bytes()
    if len(b) == 0:
        return -1
    var result = 0
    for i in range(len(b)):
        if b[i] < UInt8(48) or b[i] > UInt8(57):
            return -1
        var digit = Int(b[i]) - 48
        if result > (_MAX_SAFE_INT - digit) // 10:
            return -2
        result = result * 10 + digit
    return result


def _find_line_end(data: List[UInt8], start: Int, allow_lf: Bool) -> Tuple[Int, Int]:
    """Find the next line terminator.

    Returns ``(position, skip_bytes)`` where ``skip_bytes`` is 2 for CRLF and 1
    for bare LF (only when ``allow_lf`` is True). Returns ``(-1, 0)`` when no
    terminator is present.
    """
    var i = start
    var data_len = len(data)
    while i < data_len:
        if i + 1 < data_len and data[i] == UInt8(0x0D) and data[i + 1] == UInt8(0x0A):
            return (i, 2)
        if allow_lf and data[i] == UInt8(0x0A):
            return (i, 1)
        i += 1
    return (-1, 0)


def _strip_ows_bounds(data: List[UInt8], start: Int, end: Int) -> Tuple[Int, Int]:
    """Strip leading and trailing OWS (SP / HTAB) from a byte range."""
    var s = start
    var e = end
    while s < e and (data[s] == UInt8(0x20) or data[s] == UInt8(0x09)):
        s += 1
    while e > s and (data[e - 1] == UInt8(0x20) or data[e - 1] == UInt8(0x09)):
        e -= 1
    return (s, e)


def _contains_nul(data: List[UInt8], start: Int, end: Int) -> Bool:
    """Return True if any byte in ``data[start:end]`` is NUL."""
    var i = start
    while i < end:
        if data[i] == UInt8(0x00):
            return True
        i += 1
    return False


def _contains_ctl_in_value(
    data: List[UInt8], start: Int, end: Int, skip_cr: Bool = False
) -> Bool:
    """Return True if a non-HTAB control character is present in a header value.

    HTAB (0x09) is always permitted. CR (0x0D) is permitted when ``skip_cr``
    is True (used by ``allow_bare_cr_in_value`` lenient mode).
    """
    var i = start
    while i < end:
        var c = Int(data[i])
        if c == 0x09:
            i += 1
            continue
        if skip_cr and c == 0x0D:
            i += 1
            continue
        if c <= 0x1F or c == 0x7F:
            return True
        i += 1
    return False


# --- Header block parser ---


def _parse_headers(
    wire: List[UInt8], start_pos: Int, config: ParseConfig
) -> Tuple[Headers, Int, String]:
    """Parse the header block beginning at ``start_pos``.

    Returns ``(headers, body_start_pos, error)``. On error the returned
    ``Headers`` is empty and ``body_start_pos`` equals ``start_pos``.

    Headers are parsed into parallel name/value lists during the loop so that
    obs-fold continuations can rewrite the most recent value in place; the
    final ``Headers`` is built in insertion order at the end.
    """
    var names = List[String]()
    var values = List[String]()
    var pos = start_pos
    var data_len = len(wire)
    var allow_lf = config.strictness.allow_bare_lf
    var header_count = 0
    var headers_total_size = 0

    while pos < data_len:
        # Empty line terminates the header block.
        if pos + 1 < data_len and wire[pos] == UInt8(0x0D) and wire[pos + 1] == UInt8(0x0A):
            pos += 2
            break
        if allow_lf and pos < data_len and wire[pos] == UInt8(0x0A):
            pos += 1
            break

        # obs-fold continuation line.
        if wire[pos] == UInt8(0x20) or wire[pos] == UInt8(0x09):
            if not config.strictness.allow_obs_fold:
                return (Headers(), start_pos, String("obs-fold not allowed"))
            if len(names) == 0:
                return (Headers(), start_pos, String("obs-fold with no previous header"))
            var fold_result = _find_line_end(wire, pos, allow_lf)
            var fold_end = fold_result[0]
            var fold_skip = fold_result[1]
            if fold_end < 0:
                return (Headers(), start_pos, String("missing CRLF in obs-fold line"))
            var fold_start = pos
            while fold_start < fold_end and (wire[fold_start] == UInt8(0x20) or wire[fold_start] == UInt8(0x09)):
                fold_start += 1
            var fold_text = _bytes_to_string(wire, fold_start, fold_end)
            var prev_idx = len(values) - 1
            values[prev_idx] = values[prev_idx] + " " + fold_text
            pos = fold_end + fold_skip
            continue

        # Regular header line.
        var hdr_result = _find_line_end(wire, pos, allow_lf)
        var line_end = hdr_result[0]
        var line_skip = hdr_result[1]
        if line_end < 0:
            return (Headers(), start_pos, String("missing CRLF in header line"))

        var line_len = line_end - pos
        if line_len > config.max_header_size:
            return (Headers(), start_pos, String("header line exceeds maximum size"))

        # Locate the colon.
        var colon_pos = -1
        var ci = pos
        while ci < line_end:
            if wire[ci] == UInt8(0x3A):
                colon_pos = ci
                break
            ci += 1
        if colon_pos < 0:
            return (Headers(), start_pos, String("missing colon in header line"))

        # Whitespace before the colon (security invariant unless explicitly allowed).
        if not config.strictness.allow_space_before_colon:
            if colon_pos > pos and (wire[colon_pos - 1] == UInt8(0x20) or wire[colon_pos - 1] == UInt8(0x09)):
                return (Headers(), start_pos, String("whitespace before colon in header"))

        # Field-name bounds.
        var name_end = colon_pos
        if config.strictness.allow_space_before_colon:
            while name_end > pos and (wire[name_end - 1] == UInt8(0x20) or wire[name_end - 1] == UInt8(0x09)):
                name_end -= 1

        if name_end == pos:
            return (Headers(), start_pos, String("empty header field name"))

        # Validate field-name token characters.
        var name_valid = True
        var ni = pos
        while ni < name_end:
            if not _is_token_char(wire[ni]):
                if config.strictness.ignore_invalid_header_names:
                    name_valid = False
                    break
                return (Headers(), start_pos, String("invalid character in header field name"))
            ni += 1

        if not name_valid:
            header_count += 1
            if header_count > config.max_header_count:
                return (Headers(), start_pos, String("too many headers"))
            headers_total_size += line_len
            if headers_total_size > config.max_headers_total:
                return (Headers(), start_pos, String("headers total size exceeds maximum"))
            pos = line_end + line_skip
            continue

        var field_name = _bytes_to_string(wire, pos, name_end)

        # Field-value bounds and validation.
        var val_bounds = _strip_ows_bounds(wire, colon_pos + 1, line_end)
        var val_start = val_bounds[0]
        var val_end = val_bounds[1]

        if _contains_nul(wire, colon_pos + 1, line_end):
            return (Headers(), start_pos, String("NUL byte in header field value"))
        if not config.strictness.allow_header_value_ctl and _contains_ctl_in_value(
            wire, colon_pos + 1, line_end, skip_cr=config.strictness.allow_bare_cr_in_value
        ):
            return (Headers(), start_pos, String("control character in header field value"))

        var field_value = _bytes_to_string(wire, val_start, val_end)

        header_count += 1
        if header_count > config.max_header_count:
            return (Headers(), start_pos, String("too many headers"))
        headers_total_size += line_len
        if headers_total_size > config.max_headers_total:
            return (Headers(), start_pos, String("headers total size exceeds maximum"))

        names.append(field_name^)
        values.append(field_value^)
        pos = line_end + line_skip

    # Build the final Headers from the parallel arrays. ``Headers.add`` will
    # lowercase each name on insert.
    var headers = Headers()
    for i in range(len(names)):
        headers.add(names[i], values[i])
    return (headers^, pos, String(""))


# --- Chunked transfer-encoding decoder ---


def _hex_char_value(b: UInt8) -> Int:
    """Return the numeric value of a hex digit, or -1 if ``b`` is not hex."""
    if b >= UInt8(48) and b <= UInt8(57):
        return Int(b) - 48
    if b >= UInt8(97) and b <= UInt8(102):
        return Int(b) - 97 + 10
    if b >= UInt8(65) and b <= UInt8(70):
        return Int(b) - 65 + 10
    return -1


def _decode_chunked(
    data: List[UInt8], start: Int, config: ParseConfig
) -> Tuple[List[UInt8], Headers, Int, String]:
    """Decode a chunked body starting at ``start``.

    Returns ``(body, trailers, bytes_consumed, error)``. The error string uses
    one of three sentinel prefixes for incomplete buffers so that the caller
    can distinguish "need more data" from a hard parse failure:

      * "missing CRLF after chunk size"
      * "not enough data for chunk"
      * "missing CRLF after chunk data"
      * "missing CRLF in trailer"
    """
    var body = List[UInt8]()
    var trailers = Headers()
    var pos = start
    var data_len = len(data)

    while True:
        # Read the chunk-size line.
        var hex_start = pos
        var found_crlf = False
        var found_semi = False
        var semi_pos = -1

        while pos < data_len - 1:
            if data[pos] == UInt8(0x0D) and data[pos + 1] == UInt8(0x0A):
                found_crlf = True
                break
            if data[pos] == UInt8(0x3B) and not found_semi:
                found_semi = True
                semi_pos = pos
            pos += 1

        if not found_crlf:
            return (body^, trailers^, pos - start, String("missing CRLF after chunk size"))

        var hex_end = semi_pos if found_semi else pos

        if found_semi and not config.strictness.allow_chunk_extensions:
            return (body^, trailers^, pos - start, String("chunk extensions not allowed"))

        if hex_end == hex_start:
            return (body^, trailers^, pos - start, String("empty chunk size"))

        var chunk_size = 0
        var hi = hex_start
        while hi < hex_end:
            var v = _hex_char_value(data[hi])
            if v < 0:
                return (body^, trailers^, pos - start, String("invalid hex digit in chunk size"))
            if chunk_size > (_MAX_SAFE_INT - v) // 16:
                return (body^, trailers^, pos - start, String("chunk size overflow"))
            chunk_size = chunk_size * 16 + v
            hi += 1

        pos += 2  # skip CRLF after the chunk-size line

        if chunk_size > config.max_chunk_size:
            return (body^, trailers^, pos - start, String("chunk size exceeds maximum"))

        # Last chunk: parse trailers terminated by an empty CRLF.
        if chunk_size == 0:
            while True:
                if pos + 1 >= data_len:
                    return (body^, trailers^, pos - start, String("missing CRLF in trailer"))
                if data[pos] == UInt8(0x0D) and data[pos + 1] == UInt8(0x0A):
                    pos += 2
                    break
                var line_start = pos
                var line_crlf = False
                while pos < data_len - 1:
                    if data[pos] == UInt8(0x0D) and data[pos + 1] == UInt8(0x0A):
                        line_crlf = True
                        break
                    pos += 1
                if not line_crlf:
                    return (body^, trailers^, pos - start, String("missing CRLF in trailer"))
                var colon_pos = -1
                var ci = line_start
                while ci < pos:
                    if data[ci] == UInt8(0x3A):
                        colon_pos = ci
                        break
                    ci += 1
                if colon_pos >= 0:
                    var name = _bytes_to_string(data, line_start, colon_pos)
                    var vs = colon_pos + 1
                    while vs < pos and (data[vs] == UInt8(0x20) or data[vs] == UInt8(0x09)):
                        vs += 1
                    var ve = pos
                    while ve > vs and (data[ve - 1] == UInt8(0x20) or data[ve - 1] == UInt8(0x09)):
                        ve -= 1
                    var value = _bytes_to_string(data, vs, ve)
                    trailers.add(name, value)
                pos += 2
            return (body^, trailers^, pos - start, String(""))

        # Read chunk data.
        if pos + chunk_size > data_len:
            return (body^, trailers^, pos - start, String("not enough data for chunk"))
        var di = 0
        while di < chunk_size:
            body.append(data[pos + di])
            di += 1
        pos += chunk_size

        # Trailing CRLF after chunk data.
        if pos + 2 > data_len:
            return (body^, trailers^, pos - start, String("missing CRLF after chunk data"))
        if data[pos] != UInt8(0x0D) or data[pos + 1] != UInt8(0x0A):
            return (body^, trailers^, pos - start, String("missing CRLF after chunk data"))
        pos += 2


# --- Helpers shared by request / response framing ---


def _is_incomplete_chunk_error(err: String) -> Bool:
    """Return True if a chunked-decoder error means "buffer truncated"."""
    if err == "missing CRLF after chunk size":
        return True
    if err == "not enough data for chunk":
        return True
    if err == "missing CRLF after chunk data":
        return True
    if err == "missing CRLF in trailer":
        return True
    return False


def _scan_back_pos(buf_len: Int, cursor: Int) -> Int:
    """Compute a safe ``last_scanned`` value when the header block is incomplete.

    We back off three bytes from the buffer end so the next scan still catches
    a CRLF CRLF terminator that may straddle this read and the next.
    """
    if buf_len - 3 > cursor:
        return buf_len - 3
    return cursor


# --- Public ParseResult ---


struct ParseResult(Movable):
    """Outcome of a single ``try_parse_*`` call.

    Fields:
        request: Some(Request) when a complete request was parsed.
        response: Some(Response) when a complete response was parsed.
        bytes_consumed: Number of bytes consumed from ``cursor``.
        new_last_scanned: Updated scan watermark for the next call.
        error: Non-empty when the wire data is malformed.
    """

    var request: Optional[Request]
    var response: Optional[Response]
    var bytes_consumed: Int
    var new_last_scanned: Int
    var error: String

    def __init__(out self):
        """Construct an empty pending result."""
        self.request = Optional[Request]()
        self.response = Optional[Response]()
        self.bytes_consumed = 0
        self.new_last_scanned = 0
        self.error = String("")

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self.request = take.request^
        self.response = take.response^
        self.bytes_consumed = take.bytes_consumed
        self.new_last_scanned = take.new_last_scanned
        self.error = take.error^

    def ok(self) -> Bool:
        """Return True if no parse error was recorded."""
        return len(self.error) == 0

    def has_request(self) -> Bool:
        """Return True if a complete request was parsed."""
        return self.request.__bool__()

    def has_response(self) -> Bool:
        """Return True if a complete response was parsed."""
        return self.response.__bool__()


# --- Request parser entry point ---


def try_parse_request(
    buf: List[UInt8],
    cursor: Int,
    last_scanned: Int,
    config: ParseConfig,
) -> ParseResult:
    """Try to parse a complete request from ``buf[cursor:]``.

    On success ``result.request`` is populated and ``result.bytes_consumed``
    reports how many bytes were consumed from ``cursor``. When more data is
    needed the result is empty and ``result.new_last_scanned`` advances so the
    caller can resume scanning efficiently. Malformed wire data populates
    ``result.error``.
    """
    var result = ParseResult()
    var buf_len = len(buf)

    if cursor >= buf_len:
        result.new_last_scanned = last_scanned
        return result^

    # Locate end of header block (incremental scan).
    var header_end: Int
    if config.strictness.allow_bare_lf:
        var lf_result = _find_header_end_lf(buf, cursor, last_scanned)
        header_end = lf_result[0]
    else:
        header_end = _find_header_end(buf, cursor, last_scanned)

    if header_end < 0:
        result.new_last_scanned = _scan_back_pos(buf_len, cursor)
        if buf_len - cursor > config.max_headers_total:
            result.error = String("header block exceeds maximum size")
        return result^

    # --- Request line ---
    var allow_lf = config.strictness.allow_bare_lf
    var req_line_result = _find_line_end(buf, cursor, allow_lf)
    var req_line_end = req_line_result[0]
    var req_line_skip = req_line_result[1]
    if req_line_end < 0:
        result.error = String("missing CRLF in request line")
        return result^

    var req_line_len = req_line_end - cursor
    if req_line_len > config.max_request_line:
        result.error = String("request line exceeds maximum length")
        return result^

    # First SP separates the method.
    var sp1 = -1
    var i = cursor
    while i < req_line_end:
        if buf[i] == UInt8(0x20):
            sp1 = i
            break
        i += 1
    if sp1 < 0 or sp1 == cursor:
        result.error = String("invalid request line")
        return result^

    # Validate method tokens.
    i = cursor
    while i < sp1:
        if not _is_token_char(buf[i]):
            result.error = String("invalid character in method")
            return result^
        i += 1

    var target_start = sp1 + 1
    if config.strictness.allow_multiple_spaces:
        while target_start < req_line_end and buf[target_start] == UInt8(0x20):
            target_start += 1

    var sp2 = -1
    var target_end_pos = -1
    if config.strictness.allow_multiple_spaces:
        i = req_line_end - 1
        while i > target_start:
            if buf[i] == UInt8(0x20):
                sp2 = i
                break
            i -= 1
        if sp2 > 0:
            target_end_pos = sp2
            while target_end_pos > target_start and buf[target_end_pos - 1] == UInt8(0x20):
                target_end_pos -= 1
    else:
        i = target_start
        while i < req_line_end:
            if buf[i] == UInt8(0x20):
                sp2 = i
                break
            i += 1
        target_end_pos = sp2

    if sp2 < 0:
        result.error = String("invalid request line: missing SP after target")
        return result^

    if target_end_pos == target_start:
        result.error = String("empty target in request line")
        return result^

    # Validate request-target bytes (security invariant 8).
    var ti = target_start
    while ti < target_end_pos:
        var tb = Int(buf[ti])
        if tb == 0x00:
            result.error = String("NUL byte in request target")
            return result^
        if tb == 0x20 or tb == 0x09 or tb == 0x0D or tb == 0x0A:
            result.error = String("whitespace in request target")
            return result^
        if not config.strictness.allow_target_ctl and (tb <= 0x1F or tb == 0x7F):
            result.error = String("control character in request target")
            return result^
        if not config.strictness.allow_target_ctl and tb > 0x7E:
            result.error = String("non-ASCII byte in request target")
            return result^
        ti += 1

    var method_str = _bytes_to_string(buf, cursor, sp1)
    var target = _bytes_to_string(buf, target_start, target_end_pos)

    # Version.
    var version_str = _bytes_to_string(buf, sp2 + 1, req_line_end)
    var version: Version
    if version_str == "HTTP/1.1":
        version = Version.http_1_1()
    elif version_str == "HTTP/1.0":
        version = Version.http_1_0()
    else:
        result.error = String("unsupported HTTP version: ") + version_str
        return result^

    # --- Headers ---
    var pos = req_line_end + req_line_skip
    var hdr_result = _parse_headers(buf, pos, config)
    var hdr_error = hdr_result[2]
    if hdr_error.byte_length() > 0:
        result.error = hdr_error^
        return result^
    var headers = hdr_result[0].copy()
    var body_start = hdr_result[1]

    # --- Semantic header analysis ---
    var cl_value = String("")
    var cl_count = 0
    var te_value = String("")
    var te_count = 0
    var host_count = 0

    for hi in range(len(headers)):
        var hname = headers.name_at(hi)
        var hvalue = headers.value_at(hi)
        if _iequals(hname, "content-length"):
            cl_count += 1
            if cl_count == 1:
                cl_value = hvalue
            else:
                if hvalue != cl_value:
                    result.error = String("multiple Content-Length headers with different values")
                    return result^
        if _iequals(hname, "transfer-encoding"):
            te_count += 1
            te_value = hvalue
        if _iequals(hname, "host"):
            host_count += 1

    # Security invariant 1: CL+TE conflict (always rejected for requests).
    if cl_count > 0 and te_count > 0:
        result.error = String("CL+TE conflict")
        return result^

    # Security invariant 2: duplicate CL with same value is allowed only when
    # explicitly relaxed via the strictness flag.
    if cl_count > 1 and not config.strictness.allow_duplicate_cl:
        result.error = String("multiple Content-Length headers")
        return result^

    if not config.strictness.allow_missing_host_11 and version_str == "HTTP/1.1" and host_count == 0:
        result.error = String("missing Host header")
        return result^
    if not config.strictness.allow_duplicate_host and version_str == "HTTP/1.1" and host_count > 1:
        result.error = String("duplicate Host header")
        return result^

    # Security invariant 5: only "chunked" is accepted as the Transfer-Encoding.
    if not config.strictness.allow_non_chunked_te and te_count > 0 and te_value != "chunked":
        result.error = String("Transfer-Encoding must be exactly 'chunked'")
        return result^

    # Content-Length numeric validation (security invariants 7).
    if cl_count > 0:
        var cl_bytes = cl_value.as_bytes()
        if not config.strictness.allow_cl_leading_zeros and len(cl_bytes) > 1 and cl_bytes[0] == UInt8(48):
            result.error = String("Content-Length has leading zeros")
            return result^
        var cl_int = _parse_int(cl_value)
        if cl_int == -2:
            result.error = String("Content-Length overflow")
            return result^
        if cl_int < 0:
            result.error = String("invalid Content-Length value")
            return result^
        if cl_int > config.max_body_size:
            result.error = String("Content-Length exceeds max body size")
            return result^

    # --- Body framing (RFC 9112 Section 6, request side) ---
    # M2.5a: Request.body is a RequestBody (buffered bytes or empty). Trailers
    # on the request side are dropped here — see spec §5.12. Streaming variant
    # is only produced by H1Session in M2.5a Task 19.
    var body_bytes = List[UInt8]()
    var msg_end: Int

    if te_count > 0:
        # Rule 3 / 4: Transfer-Encoding present. For requests we require
        # ``chunked`` to be the final coding (and only coding under strict mode).
        if config.strictness.allow_non_chunked_te and not _icontains(te_value, "chunked"):
            result.error = String("unsupported Transfer-Encoding")
            return result^

        var chunk_result = _decode_chunked(buf, body_start, config)
        var chunk_err = chunk_result[3]
        if chunk_err.byte_length() > 0:
            if _is_incomplete_chunk_error(chunk_err):
                result.new_last_scanned = header_end
                return result^
            result.error = chunk_err^
            return result^
        var chunk_body = chunk_result[0].copy()
        var chunk_consumed = chunk_result[2]

        if len(chunk_body) > config.max_body_size:
            result.error = String("chunked body exceeds max body size")
            return result^

        body_bytes = chunk_body^
        msg_end = body_start + chunk_consumed

    elif cl_count > 0:
        # Rule 7: Content-Length present.
        var cl_int = _parse_int(cl_value)
        var remaining = buf_len - body_start
        if remaining < cl_int:
            result.new_last_scanned = header_end
            return result^
        if cl_int > 0:
            var bi = 0
            while bi < cl_int:
                body_bytes.append(buf[body_start + bi])
                bi += 1
        msg_end = body_start + cl_int
    else:
        # Rule 8: request without TE/CL has no body.
        msg_end = body_start

    var req_body: RequestBody
    if len(body_bytes) > 0:
        req_body = RequestBody.buffered(body_bytes^)
    else:
        req_body = RequestBody.empty()

    var req = Request(
        method=Method.custom(method_str),
        target=target,
        version=version^,
        headers=headers^,
        body=req_body^,
    )
    result.request = Optional[Request](req^)
    result.bytes_consumed = msg_end - cursor
    result.new_last_scanned = 0
    return result^


# --- Response parser entry point ---


def try_parse_response(
    buf: List[UInt8],
    cursor: Int,
    last_scanned: Int,
    request_method: Method,
    config: ParseConfig,
) -> ParseResult:
    """Try to parse a complete response from ``buf[cursor:]``.

    Implements the 9-step body length determination algorithm from RFC 9112
    Section 6. ``request_method`` is the method of the matching in-flight
    request and is required for HEAD / CONNECT framing decisions.
    """
    var result = ParseResult()
    var buf_len = len(buf)

    if cursor >= buf_len:
        result.new_last_scanned = last_scanned
        return result^

    # Locate end of header block (incremental scan).
    var header_end: Int
    if config.strictness.allow_bare_lf:
        var lf_result = _find_header_end_lf(buf, cursor, last_scanned)
        header_end = lf_result[0]
    else:
        header_end = _find_header_end(buf, cursor, last_scanned)

    if header_end < 0:
        result.new_last_scanned = _scan_back_pos(buf_len, cursor)
        if buf_len - cursor > config.max_headers_total:
            result.error = String("header block exceeds maximum size")
        return result^

    # --- Status line ---
    var allow_lf = config.strictness.allow_bare_lf
    var status_line_result = _find_line_end(buf, cursor, allow_lf)
    var sl_end = status_line_result[0]
    var sl_skip = status_line_result[1]
    if sl_end < 0:
        result.error = String("missing CRLF in status line")
        return result^

    if sl_end - cursor > config.max_request_line:
        result.error = String("status line exceeds maximum length")
        return result^

    # First SP -- after the version.
    var sp1 = -1
    var i = cursor
    while i < sl_end:
        if buf[i] == UInt8(0x20):
            sp1 = i
            break
        i += 1
    if sp1 < 0 or sp1 == cursor:
        result.error = String("invalid status line")
        return result^

    # Version.
    var version_str = _bytes_to_string(buf, cursor, sp1)
    var version: Version
    if version_str == "HTTP/1.1":
        version = Version.http_1_1()
    elif version_str == "HTTP/1.0":
        version = Version.http_1_0()
    else:
        result.error = String("unsupported HTTP version: ") + version_str
        return result^

    # Status code (3 digits).
    var code_start = sp1 + 1
    if config.strictness.allow_multiple_spaces_in_status_line:
        while code_start < sl_end and buf[code_start] == UInt8(0x20):
            code_start += 1

    if code_start + 3 > sl_end:
        result.error = String("status code too short")
        return result^

    var status_code = 0
    var di = 0
    while di < 3:
        var b = buf[code_start + di]
        if b < UInt8(48) or b > UInt8(57):
            result.error = String("invalid character in status code")
            return result^
        status_code = status_code * 10 + (Int(b) - 48)
        di += 1

    if status_code < 100:
        result.error = String("status code below 100")
        return result^

    # Reason phrase.
    var reason = String("")
    var after_code = code_start + 3
    if after_code < sl_end:
        if buf[after_code] == UInt8(0x20):
            var reason_start = after_code + 1
            reason = _bytes_to_string(buf, reason_start, sl_end)
        else:
            result.error = String("status code is not exactly 3 digits")
            return result^
    elif after_code == sl_end:
        if not config.strictness.allow_missing_reason_sp:
            result.error = String("missing SP after status code")
            return result^

    # --- Headers ---
    var pos = sl_end + sl_skip
    var hdr_result = _parse_headers(buf, pos, config)
    var hdr_error = hdr_result[2]
    if len(hdr_error) > 0:
        result.error = hdr_error^
        return result^
    var headers = hdr_result[0].copy()
    var body_start = hdr_result[1]

    # --- Semantic header analysis ---
    var cl_value = String("")
    var cl_count = 0
    var te_value = String("")
    var te_count = 0

    for hi in range(len(headers)):
        var hname = headers.name_at(hi)
        var hvalue = headers.value_at(hi)
        if _iequals(hname, "content-length"):
            cl_count += 1
            if cl_count == 1:
                cl_value = hvalue
            else:
                if hvalue != cl_value:
                    result.error = String("multiple Content-Length values that differ")
                    return result^
        if _iequals(hname, "transfer-encoding"):
            te_count += 1
            te_value = hvalue

    # --- 9-step body length determination ---

    # Rule 1: HEAD response -- no body regardless of headers.
    if request_method.is_head():
        var resp_head = Response(
            status=StatusCode(status_code),
            reason=reason,
            version=version^,
            headers=headers^,
            body=List[BodyFrame](),
        )
        result.response = Optional[Response](resp_head^)
        result.bytes_consumed = body_start - cursor
        result.new_last_scanned = 0
        return result^

    # Rule 2: 2xx response to CONNECT -- tunnel, no body framing.
    if request_method.is_connect() and status_code >= 200 and status_code <= 299:
        var resp_conn = Response(
            status=StatusCode(status_code),
            reason=reason,
            version=version^,
            headers=headers^,
            body=List[BodyFrame](),
        )
        result.response = Optional[Response](resp_conn^)
        result.bytes_consumed = body_start - cursor
        result.new_last_scanned = 0
        return result^

    # Rule 1 (continued): 1xx informational responses -- no body, no framing.
    if status_code >= 100 and status_code <= 199:
        if te_count > 0:
            result.error = String("Transfer-Encoding in 1xx response")
            return result^
        var resp_1xx = Response(
            status=StatusCode(status_code),
            reason=reason,
            version=version^,
            headers=headers^,
            body=List[BodyFrame](),
        )
        result.response = Optional[Response](resp_1xx^)
        result.bytes_consumed = body_start - cursor
        result.new_last_scanned = 0
        return result^

    # 204 No Content -- no body, TE forbidden.
    if status_code == 204:
        if te_count > 0:
            result.error = String("Transfer-Encoding in 204 response")
            return result^
        var resp_204 = Response(
            status=StatusCode(status_code),
            reason=reason,
            version=version^,
            headers=headers^,
            body=List[BodyFrame](),
        )
        result.response = Optional[Response](resp_204^)
        result.bytes_consumed = body_start - cursor
        result.new_last_scanned = 0
        return result^

    # 304 Not Modified -- headers may include CL but no body is sent.
    if status_code == 304:
        var resp_304 = Response(
            status=StatusCode(status_code),
            reason=reason,
            version=version^,
            headers=headers^,
            body=List[BodyFrame](),
        )
        result.response = Optional[Response](resp_304^)
        result.bytes_consumed = body_start - cursor
        result.new_last_scanned = 0
        return result^

    # Rule 3 / 4: Transfer-Encoding present.
    if te_count > 0:
        if cl_count > 0 and not config.strictness.allow_response_cl_te:
            # Security invariant 1: CL+TE conflict (response side).
            result.error = String("response has both Content-Length and Transfer-Encoding")
            return result^
        # When relaxed, TE wins and CL is silently dropped.

        if _icontains(te_value, "chunked"):
            if not config.strictness.allow_non_chunked_te and te_value != "chunked":
                result.error = String("Transfer-Encoding without chunked as final encoding")
                return result^

            var chunk_result = _decode_chunked(buf, body_start, config)
            var chunk_err = chunk_result[3]
            if len(chunk_err) > 0:
                if _is_incomplete_chunk_error(chunk_err):
                    result.new_last_scanned = header_end
                    return result^
                result.error = chunk_err^
                return result^

            var chunk_body = chunk_result[0].copy()
            var chunk_trailers = chunk_result[1].copy()
            var chunk_consumed = chunk_result[2]

            if len(chunk_body) > config.max_body_size:
                result.error = String("chunked body exceeds max body size")
                return result^

            var body_te = List[BodyFrame]()
            if len(chunk_body) > 0:
                body_te.append(BodyFrame.data(chunk_body^))
            if len(chunk_trailers) > 0:
                body_te.append(BodyFrame.trailers(chunk_trailers^))
            var msg_end = body_start + chunk_consumed

            var resp_te = Response(
                status=StatusCode(status_code),
                reason=reason,
                version=version^,
                headers=headers^,
                body=body_te^,
            )
            result.response = Optional[Response](resp_te^)
            result.bytes_consumed = msg_end - cursor
            result.new_last_scanned = 0
            return result^
        else:
            if not config.strictness.allow_non_chunked_te:
                result.error = String("Transfer-Encoding without chunked as final encoding")
                return result^
            # Rule 4 (response side): non-chunked TE -- treat as close-delimited.
            # In M2's fully-buffered model the caller hands us the entire wire,
            # so we consume everything that remains.
            var body_close = List[BodyFrame]()
            var body_bytes = List[UInt8]()
            var ri = body_start
            while ri < buf_len:
                body_bytes.append(buf[ri])
                ri += 1
            if len(body_bytes) > 0:
                body_close.append(BodyFrame.data(body_bytes^))
            var resp_close = Response(
                status=StatusCode(status_code),
                reason=reason,
                version=version^,
                headers=headers^,
                body=body_close^,
            )
            result.response = Optional[Response](resp_close^)
            result.bytes_consumed = buf_len - cursor
            result.new_last_scanned = 0
            return result^

    # Rule 5 / 6 / 7: Content-Length present.
    if cl_count > 0:
        if cl_count > 1 and not config.strictness.allow_duplicate_cl:
            result.error = String("duplicate Content-Length header")
            return result^

        var cl_bytes = cl_value.as_bytes()
        if not config.strictness.allow_cl_leading_zeros and len(cl_bytes) > 1 and cl_bytes[0] == UInt8(48):
            result.error = String("Content-Length has leading zeros")
            return result^

        var cl_int = _parse_int(cl_value)
        if cl_int == -2:
            result.error = String("Content-Length overflow")
            return result^
        if cl_int < 0:
            result.error = String("invalid Content-Length value")
            return result^
        if cl_int > config.max_body_size:
            result.error = String("Content-Length exceeds max body size")
            return result^

        var remaining = buf_len - body_start
        if remaining < cl_int:
            result.new_last_scanned = header_end
            return result^

        var body_cl = List[BodyFrame]()
        if cl_int > 0:
            var body_bytes = List[UInt8]()
            var bi = 0
            while bi < cl_int:
                body_bytes.append(buf[body_start + bi])
                bi += 1
            body_cl.append(BodyFrame.data(body_bytes^))

        var resp_cl = Response(
            status=StatusCode(status_code),
            reason=reason,
            version=version^,
            headers=headers^,
            body=body_cl^,
        )
        result.response = Optional[Response](resp_cl^)
        result.bytes_consumed = body_start + cl_int - cursor
        result.new_last_scanned = 0
        return result^

    # Rule 9: response with neither TE nor CL -- close-delimited.
    var body_def = List[BodyFrame]()
    var body_bytes_def = List[UInt8]()
    var ri = body_start
    while ri < buf_len:
        body_bytes_def.append(buf[ri])
        ri += 1
    if len(body_bytes_def) > 0:
        body_def.append(BodyFrame.data(body_bytes_def^))

    var resp_def = Response(
        status=StatusCode(status_code),
        reason=reason,
        version=version^,
        headers=headers^,
        body=body_def^,
    )
    result.response = Optional[Response](resp_def^)
    result.bytes_consumed = buf_len - cursor
    result.new_last_scanned = 0
    return result^
