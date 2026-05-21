# src/h1/serializer.mojo
#
# HTTP/1.1 wire format serialization per RFC 9112.
# Pure functions — no state, no I/O. Each entry point takes a production
# Request/Response and returns a freshly allocated `List[UInt8]` containing
# the message ready to be written to a transport.
#
# Framing rules implemented here:
#   * If a Request/Response body contains a Trailers frame, chunked
#     transfer-encoding is used and a `transfer-encoding: chunked` header
#     is appended (overriding any user-provided value).
#   * Otherwise, if the body has any Data bytes, a `content-length` header
#     is appended with the total byte count.
#   * Otherwise, no framing header is added.
#   * 1xx and 204 responses MUST NOT include a body, Content-Length, or
#     Transfer-Encoding (only the user-provided headers are emitted).
#   * 304 MAY include a user-provided Content-Length but MUST NOT carry a
#     body, so the serializer trusts the headers as-is and emits no body.

from std.memory import Span

from navette.http.method import Method
from navette.http.status import StatusCode
from navette.http.version import Version
from navette.http.headers import Headers
from navette.http.body import BodyFrame
from navette.http.request import Request
from navette.http.response import Response


# --- Low-level buffer helpers ---

def _append_str(mut buf: List[UInt8], s: String):
    """Append all bytes of a string to the buffer."""
    buf.extend(s.as_bytes())


def _append_crlf(mut buf: List[UInt8]):
    """Append CRLF to the buffer."""
    buf.append(UInt8(0x0D))
    buf.append(UInt8(0x0A))


def _append_colon_sp(mut buf: List[UInt8]):
    """Append `: ` (colon, space) to the buffer."""
    buf.append(UInt8(0x3A))
    buf.append(UInt8(0x20))


def _version_string(version: Version) -> String:
    """Return the wire form of an HTTP version."""
    if version.is_http_1_0():
        return String("HTTP/1.0")
    # Default to HTTP/1.1 for any non-1.0 (H1 only ever serializes 1.0/1.1).
    return String("HTTP/1.1")


def _method_string(method: Method) -> String:
    """Return the wire form of an HTTP method (uses Method's Writable impl)."""
    return String(method)


def _int_to_string(value: Int) -> String:
    """Convert a non-negative integer to its decimal string representation."""
    if value == 0:
        return String("0")
    var digits = List[UInt8]()
    var v = value
    while v > 0:
        digits.append(UInt8(v % 10 + 48))
        v //= 10
    var result = String()
    var i = len(digits) - 1
    while i >= 0:
        result += chr(Int(digits[i]))
        i -= 1
    return result^


def _int_to_hex_lower(value: Int) -> String:
    """Convert a non-negative integer to a lowercase hex string."""
    if value == 0:
        return String("0")
    var hex_chars = String("0123456789abcdef")
    var hb = hex_chars.as_bytes()
    var digits = List[UInt8]()
    var v = value
    while v > 0:
        digits.append(hb[v & 0xF])
        v >>= 4
    var result = String()
    var i = len(digits) - 1
    while i >= 0:
        result += chr(Int(digits[i]))
        i -= 1
    return result^


# --- Header / body helpers ---

def _serialize_headers(mut buf: List[UInt8], headers: Headers):
    """Emit each header as `name: value\\r\\n` in insertion order."""
    for i in range(len(headers)):
        _append_str(buf, headers.name_at(i))
        _append_colon_sp(buf)
        _append_str(buf, headers.value_at(i))
        _append_crlf(buf)


def _append_framing_header(mut buf: List[UInt8], name: String, value: String):
    """Append a single `name: value\\r\\n` line."""
    _append_str(buf, name)
    _append_colon_sp(buf)
    _append_str(buf, value)
    _append_crlf(buf)


def _total_data_len(body: List[BodyFrame]) -> Int:
    """Sum the byte length of every Data frame in the body."""
    var total = 0
    for i in range(len(body)):
        if body[i].is_data():
            total += len(body[i].data())
    return total


def _has_trailers(body: List[BodyFrame]) -> Bool:
    """Return True if any frame in the body is a Trailers variant."""
    for i in range(len(body)):
        if body[i].is_trailers():
            return True
    return False


def _append_data_frames(mut buf: List[UInt8], body: List[BodyFrame]):
    """Append the bytes of every Data frame in order (no framing)."""
    for i in range(len(body)):
        if body[i].is_data():
            ref chunk = body[i].data()
            buf.extend(Span(chunk))


def _append_chunked_body(mut buf: List[UInt8], body: List[BodyFrame]):
    """Encode body frames using chunked transfer-encoding.

    Each non-empty Data frame becomes one chunk. After the final chunk
    marker, every Trailers frame's headers are emitted, followed by the
    terminating CRLF.
    """
    for i in range(len(body)):
        if body[i].is_data():
            ref chunk = body[i].data()
            var chunk_len = len(chunk)
            if chunk_len > 0:
                _append_str(buf, _int_to_hex_lower(chunk_len))
                _append_crlf(buf)
                buf.extend(Span(chunk))
                _append_crlf(buf)

    # Final zero-length chunk marker.
    buf.append(UInt8(0x30))  # '0'
    _append_crlf(buf)

    # Trailers (concatenated if multiple Trailers frames are present).
    for i in range(len(body)):
        if body[i].is_trailers():
            _serialize_headers(buf, body[i].trailers())

    # Terminating CRLF that closes the trailer section.
    _append_crlf(buf)


# --- Public entry points ---

def serialize_request(request: Request) raises -> List[UInt8]:
    """Serialize a Request into HTTP/1.1 wire bytes.

    M2.5a: Request.body is a RequestBody. Buffered bodies are emitted with a
    content-length header. Streaming bodies are not yet supported by the
    sans-I/O serializer (the H1Session adapter handles streaming separately).
    """
    var buf = List[UInt8]()

    # Request-line: method SP target SP version CRLF.
    _append_str(buf, _method_string(request.method))
    buf.append(UInt8(0x20))
    _append_str(buf, request.target)
    buf.append(UInt8(0x20))
    _append_str(buf, _version_string(request.version))
    _append_crlf(buf)

    if request.body.is_stream():
        raise Error("serialize_request: streaming RequestBody not supported by sans-I/O serializer")

    var body_len: Int
    if request.body.is_buffered():
        body_len = len(request.body.bytes())
    else:
        body_len = 0

    _serialize_headers(buf, request.headers)
    if body_len > 0 and not request.headers.has("content-length"):
        _append_framing_header(buf, String("content-length"), _int_to_string(body_len))

    # End of header block.
    _append_crlf(buf)

    # Body.
    if body_len > 0:
        ref chunk = request.body.bytes()
        buf.extend(Span(chunk))

    return buf^


def serialize_response(response: Response) -> List[UInt8]:
    """Serialize a Response into HTTP/1.1 wire bytes.

    The SP after the status code is always emitted, even when the reason
    phrase is empty (RFC 9112 Section 4). 1xx and 204 responses MUST NOT
    carry a body or framing headers; 304 MUST NOT carry a body but MAY
    keep a user-provided Content-Length.

    NOTE: This serializer is method-agnostic. For HEAD-request responses,
    the caller (H1Connection) MUST suppress the body bytes after this
    function returns. The serializer does not see the request method.
    """
    var buf = List[UInt8]()
    var status_int = Int(response.status.code())

    # Status-line: version SP status-code SP reason-phrase CRLF.
    _append_str(buf, _version_string(response.version))
    buf.append(UInt8(0x20))
    _append_str(buf, _int_to_string(status_int))
    buf.append(UInt8(0x20))  # SP after status, even with empty reason.
    _append_str(buf, response.reason)
    _append_crlf(buf)

    var bodyless = (
        (status_int >= 100 and status_int <= 199)
        or status_int == 204
        or status_int == 304
    )

    if bodyless:
        # Pass user headers through verbatim. No framing header inserted,
        # no body emitted regardless of what BodyFrames are attached.
        _serialize_headers(buf, response.headers)
        _append_crlf(buf)
        return buf^

    var use_chunked = _has_trailers(response.body)
    var body_len = _total_data_len(response.body)

    _serialize_headers(buf, response.headers)
    if use_chunked:
        _append_framing_header(buf, String("transfer-encoding"), String("chunked"))
    elif body_len > 0 and not response.headers.has("content-length"):
        _append_framing_header(buf, String("content-length"), _int_to_string(body_len))

    _append_crlf(buf)

    if use_chunked:
        _append_chunked_body(buf, response.body)
    elif body_len > 0:
        _append_data_frames(buf, response.body)

    return buf^


def serialize_informational(status: StatusCode, headers: Headers) -> List[UInt8]:
    """Serialize a 1xx interim response.

    Always uses HTTP/1.1, an empty reason phrase (with the mandatory SP
    after the status code), no body, and no framing headers.
    """
    var buf = List[UInt8]()
    _append_str(buf, String("HTTP/1.1"))
    buf.append(UInt8(0x20))
    _append_str(buf, _int_to_string(Int(status.code())))
    buf.append(UInt8(0x20))  # SP after status, even with empty reason.
    _append_crlf(buf)
    _serialize_headers(buf, headers)
    _append_crlf(buf)
    return buf^
