# interop/http09.mojo
#
# HTTP/0.9 over QUIC — minimal request/response helpers for the QUIC
# Interop Runner.  HTTP/0.9 is the simplest possible HTTP dialect:
#   client sends: GET /path\r\n   (with FIN)
#   server sends: <file bytes>   (with FIN)

from std.memory import Span
from src.quic.connection import QuicConnection
from interop.file_io import read_file


# ── Client side ────────────────────────────────────────────────────────────


def http09_request(mut quic: QuicConnection, path: String) raises -> UInt64:
    """Open a bidi stream, send `GET {path}\\r\\n` with fin=True, return stream_id."""
    var stream_id = quic.open_stream(bidi=True)
    var req = String("GET " + path + "\r\n")
    var req_bytes = req.as_bytes()
    quic.send_stream_data(stream_id, Span(req_bytes), fin=True)
    return stream_id


def http09_collect(
    mut quic: QuicConnection, stream_id: UInt64
) raises -> Tuple[List[UInt8], Bool]:
    """Read available data from a stream.  Returns (bytes, is_fin)."""
    return quic.recv_stream_data(stream_id)


# ── Server side ────────────────────────────────────────────────────────────


def http09_parse_path(request_data: Span[UInt8, _]) raises -> String:
    """Parse `GET /path\\r\\n` and return path with leading `/` stripped.

    Raises on malformed input.
    """
    var n = len(request_data)
    if n < 6:
        raise "http09_parse_path: request too short"

    # Must start with "GET "
    if (
        request_data[0] != UInt8(ord("G"))
        or request_data[1] != UInt8(ord("E"))
        or request_data[2] != UInt8(ord("T"))
        or request_data[3] != UInt8(ord(" "))
    ):
        raise "http09_parse_path: expected 'GET ' prefix"

    # Must end with \r\n
    if request_data[n - 2] != UInt8(ord("\r")) or request_data[n - 1] != UInt8(ord("\n")):
        raise "http09_parse_path: missing \\r\\n terminator"

    # Extract path between "GET " and "\r\n", skip leading '/'
    var start = 4
    if start < n - 2 and request_data[start] == UInt8(ord("/")):
        start = 5

    var path = String()
    for i in range(start, n - 2):
        path += chr(Int(request_data[i]))
    return path^


def http09_serve(
    mut quic: QuicConnection,
    stream_id: UInt64,
    request_data: Span[UInt8, _],
    www_dir: String,
) raises:
    """Parse request, read file from `{www_dir}/{path}`, send file bytes with fin=True."""
    var rel_path = http09_parse_path(request_data)
    var full_path = www_dir + "/" + rel_path
    var file_data = read_file(full_path)
    quic.send_stream_data(stream_id, Span(file_data), fin=True)
