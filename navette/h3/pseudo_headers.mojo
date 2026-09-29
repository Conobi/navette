"""Bidirectional translation between H3/QPACK pseudo-headers and navette types.

Mirrors h2/pseudo_headers.mojo for the HTTP/3 wire format (QPACK header
fields with QpackHeaderField vs H2's List[Header]).
"""

from navette.h3.qpack import QpackHeaderField
from navette.http.headers import Headers
from navette.http.method import Method
from navette.http.request import Request
from navette.http.status import StatusCode
from navette.http.version import Version


def request_from_h3_fields(
    stream_id: UInt64, fields: List[QpackHeaderField], fin: Bool
) -> Request:
    """Parse QPACK pseudo-headers into a Request.

    Extracts :method, :path, :authority from QPACK fields and builds a
    Request with HTTP/3 version. Maps :authority to a host header.
    """
    var method_str = String("GET")
    var path_str = String("/")
    var authority_str = String("")
    var user_headers = Headers()

    for ref field in fields:
        var name = field.name
        var value = field.value
        if name == ":method":
            method_str = value
        elif name == ":path":
            path_str = value
        elif name == ":authority":
            authority_str = value
        elif name == ":scheme":
            pass
        else:
            user_headers.add_lowercase(name, value)

    var req_headers = Headers()
    if authority_str != "":
        req_headers.add_lowercase("host", authority_str)
    for i in range(len(user_headers)):
        req_headers.add_lowercase(user_headers.name_at(i), user_headers.value_at(i))

    return Request(
        method=Method.custom(method_str),
        target=path_str,
        version=Version.http_3(),
        headers=req_headers^,
    )


def response_to_h3_fields(
    status: StatusCode, headers: Headers
) -> List[QpackHeaderField]:
    """Convert a StatusCode + Headers into QPACK fields for H3 response."""
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(":status", String(Int(status.code()))))
    for i in range(len(headers)):
        fields.append(QpackHeaderField(headers.name_at(i), headers.value_at(i)))
    return fields^


def trailers_to_h3_fields(trailers: Headers) -> List[QpackHeaderField]:
    """Convert trailer Headers into QPACK fields."""
    var fields = List[QpackHeaderField]()
    for i in range(len(trailers)):
        fields.append(QpackHeaderField(trailers.name_at(i), trailers.value_at(i)))
    return fields^


struct ParsedPseudo(Movable):
    """Result of parsing QPACK pseudo-headers from a field list."""

    var method: String
    var path: String
    var authority: String
    var user_headers: Headers

    def __init__(out self, var method: String, var path: String,
                 var authority: String, var user_headers: Headers):
        self.method = method^
        self.path = path^
        self.authority = authority^
        self.user_headers = user_headers^


def parsed_pseudo_headers(fields: List[QpackHeaderField]) -> ParsedPseudo:
    """Extract pseudo-headers from QPACK fields."""
    var method_str = String("GET")
    var path_str = String("/")
    var authority_str = String("")
    var user_headers = Headers()

    for ref field in fields:
        var name = field.name
        var value = field.value
        if name == ":method":
            method_str = value
        elif name == ":path":
            path_str = value
        elif name == ":authority":
            authority_str = value
        elif name == ":scheme":
            pass
        else:
            user_headers.add_lowercase(name, value)

    return ParsedPseudo(method_str^, path_str^, authority_str^, user_headers^)
