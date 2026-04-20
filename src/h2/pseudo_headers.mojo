# src/h2/pseudo_headers.mojo
#
# Bidirectional translation between H2 pseudo-headers (List[Header])
# and production types (Request, Response, Headers, StatusCode).
#
# RFC 9113 Section 8.3: pseudo-headers must appear before regular
# headers, no duplicates allowed (except :method/:path validation).

from .header import Header
from src.http.method import Method
from src.http.version import Version
from src.http.headers import Headers
from src.http.request import Request, RequestBody
from src.http.response import Response
from src.http.status import StatusCode


def _is_pseudo(name: String) -> Bool:
    """Return True if the header name starts with ':'."""
    var b = name.as_bytes()
    if len(b) == 0:
        return False
    return b[0] == UInt8(0x3A)


def request_from_h2_headers(
    stream_id: UInt32, h2_headers: List[Header]
) raises -> Request:
    """Convert H2 pseudo-headers + regular headers into a Request.

    Validates:
      - Pseudo-headers appear before regular headers
      - No duplicate pseudo-headers
      - :method required
      - :path required (except CONNECT)
    Maps:
      - :authority -> host header
      - :scheme -> x-h2-scheme synthetic header
    """
    var method_val = String("")
    var path_val = String("")
    var scheme_val = String("")
    var authority_val = String("")

    var has_method = False
    var has_path = False
    var has_scheme = False
    var has_authority = False

    var past_pseudo = False
    var headers = Headers()

    for i in range(len(h2_headers)):
        var name = h2_headers[i].name
        var value = h2_headers[i].value

        if _is_pseudo(name):
            if past_pseudo:
                raise Error(
                    "pseudo-header '" + name + "' after regular header"
                )

            if name == ":method":
                if has_method:
                    raise Error("duplicate :method pseudo-header")
                method_val = value
                has_method = True
            elif name == ":path":
                if has_path:
                    raise Error("duplicate :path pseudo-header")
                path_val = value
                has_path = True
            elif name == ":scheme":
                if has_scheme:
                    raise Error("duplicate :scheme pseudo-header")
                scheme_val = value
                has_scheme = True
            elif name == ":authority":
                if has_authority:
                    raise Error("duplicate :authority pseudo-header")
                authority_val = value
                has_authority = True
            else:
                raise Error("unknown request pseudo-header: " + name)
        else:
            past_pseudo = True
            headers.add(name, value)

    if not has_method:
        raise Error("missing required :method pseudo-header")

    # CONNECT requests do not require :path
    var method = Method.custom(method_val)
    if not method.is_connect() and not has_path:
        raise Error("missing required :path pseudo-header")

    # Map :authority -> host header if no host already present
    if has_authority and not headers.has("host"):
        headers.add("host", authority_val)

    # Map :scheme -> x-h2-scheme synthetic header
    if has_scheme:
        headers.set("x-h2-scheme", scheme_val)

    return Request(
        method=method^,
        target=path_val,
        version=Version.http_2(),
        headers=headers^,
        body=RequestBody.empty(),
    )


def request_to_h2_headers(req: Request) raises -> List[Header]:
    """Convert a Request into H2 pseudo-headers + regular headers.

    Builds pseudo-headers:
      - :method from req.method
      - :path from req.target
      - :scheme from x-h2-scheme header (default "https")
      - :authority from host header
    Skips host and x-h2-scheme from regular headers (already mapped).
    """
    var result = List[Header]()

    # :method
    result.append(Header(":method", String(req.method)))

    # :path (skip for CONNECT)
    if not req.method.is_connect():
        result.append(Header(":path", req.target))

    # :scheme from x-h2-scheme or default "https" (skip for CONNECT)
    if not req.method.is_connect():
        var scheme = req.headers.get("x-h2-scheme")
        if len(scheme) == 0:
            scheme = "https"
        result.append(Header(":scheme", scheme))

    # :authority from host header
    var host = req.headers.get("host")
    if len(host) > 0:
        result.append(Header(":authority", host))

    # Regular headers, skipping host and x-h2-scheme
    for i in range(len(req.headers)):
        var name = req.headers.name_at(i)
        if name == "host" or name == "x-h2-scheme":
            continue
        result.append(Header(name, req.headers.value_at(i)))

    return result^


def response_from_h2_headers(
    h2_headers: List[Header],
) raises -> Response:
    """Convert H2 pseudo-headers + regular headers into a Response.

    Extracts :status, parses with atol, builds Response with Version.http_2().
    """
    var status_val = String("")
    var has_status = False
    var past_pseudo = False
    var headers = Headers()

    for i in range(len(h2_headers)):
        var name = h2_headers[i].name
        var value = h2_headers[i].value

        if _is_pseudo(name):
            if past_pseudo:
                raise Error(
                    "pseudo-header '" + name + "' after regular header"
                )

            if name == ":status":
                if has_status:
                    raise Error("duplicate :status pseudo-header")
                status_val = value
                has_status = True
            else:
                raise Error("unknown response pseudo-header: " + name)
        else:
            past_pseudo = True
            headers.add(name, value)

    if not has_status:
        raise Error("missing required :status pseudo-header")

    var code = atol(status_val)
    return Response(
        status=StatusCode(code),
        version=Version.http_2(),
        headers=headers^,
    )


def response_to_h2_headers(
    status: StatusCode, headers: Headers
) -> List[Header]:
    """Convert a StatusCode + Headers into H2 pseudo-headers + regular headers.

    Builds :status pseudo-header followed by all regular headers.
    """
    var result = List[Header]()

    # :status
    result.append(Header(":status", String(status)))

    # Regular headers
    for i in range(len(headers)):
        result.append(Header(headers.name_at(i), headers.value_at(i)))

    return result^


def headers_from_h2(h2_headers: List[Header]) -> Headers:
    """Convert List[Header] to Headers, skipping pseudo-headers."""
    var result = Headers()
    for i in range(len(h2_headers)):
        if not _is_pseudo(h2_headers[i].name):
            result.add(h2_headers[i].name, h2_headers[i].value)
    return result^


def headers_to_h2(headers: Headers) -> List[Header]:
    """Convert Headers to List[Header]."""
    var result = List[Header]()
    for i in range(len(headers)):
        result.append(Header(headers.name_at(i), headers.value_at(i)))
    return result^
