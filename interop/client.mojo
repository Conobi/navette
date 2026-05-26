# interop/client.mojo
#
# QUIC Interop Runner client binary.  Fetches files over QUIC using
# HTTP/0.9 (hq-interop ALPN).
#
# Environment variables:
#   TESTCASE  — "handshake" or "transfer" (unsupported → exit 127)
#   REQUESTS  — space-separated https://host:port/path URLs
#
# Build:
#   LD_LIBRARY_PATH=lib uv run mojo build -I . interop/client.mojo -o /tmp/interop-client

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicClientConfig
from navette.quic.connection import QuicConnection, QuicEvent
from navette.quic.trans_param import default_transport_params
from interop.file_io import read_file, write_file, getenv, getenv_opt, basename, setenv
from interop.http09 import http09_request, http09_collect
from interop.udp import udp_connect, udp_poll, udp_close, monotonic_us


# ── String helpers ────────────────────────────────────────────────────────


def _split_spaces(s: String) raises -> List[String]:
    """Split string by spaces.  Skips consecutive spaces."""
    var parts = List[String]()
    var current = String()
    var s_bytes = s.as_bytes()
    for i in range(len(s_bytes)):
        if s_bytes[i] == UInt8(ord(" ")):
            if len(current) > 0:
                parts.append(current)
                current = String()
        else:
            current += chr(Int(s_bytes[i]))
    if len(current) > 0:
        parts.append(current)
    return parts^


def _parse_url(url: String) raises -> Tuple[String, Int, String]:
    """Parse https://host:port/path.  Returns (host, port, path).

    Port defaults to 443 if not specified.
    """
    var url_bytes = url.as_bytes()
    var n = len(url_bytes)

    # Must start with "https://"
    var prefix = String("https://")
    var prefix_bytes = prefix.as_bytes()
    var prefix_len = len(prefix_bytes)
    if n < prefix_len:
        raise "URL too short: " + url
    for i in range(prefix_len):
        if url_bytes[i] != prefix_bytes[i]:
            raise "URL must start with https://: " + url

    # Find end of host (first ':' or '/' after scheme)
    var host_start = prefix_len
    var host_end = n
    var has_port = False
    var port_start = 0
    var path_start = n

    for i in range(host_start, n):
        if url_bytes[i] == UInt8(ord(":")):
            host_end = i
            has_port = True
            port_start = i + 1
            break
        if url_bytes[i] == UInt8(ord("/")):
            host_end = i
            path_start = i
            break

    # Extract host
    var host = String()
    for i in range(host_start, host_end):
        host += chr(Int(url_bytes[i]))

    # Parse port if present
    var port = 443
    if has_port:
        port = 0
        for i in range(port_start, n):
            if url_bytes[i] == UInt8(ord("/")):
                path_start = i
                break
            port = port * 10 + Int(url_bytes[i]) - Int(UInt8(ord("0")))
            if i == n - 1:
                path_start = n

    # Extract path (including leading '/')
    var path = String()
    if path_start < n:
        for i in range(path_start, n):
            path += chr(Int(url_bytes[i]))
    else:
        path = "/"

    return (host^, port, path^)


# ── UDP helpers ───────────────────────────────────────────────────────────


def _send_datagrams(fd: Int32, datagrams: List[List[UInt8]]) raises:
    """Send each datagram on the connected UDP socket."""
    for i in range(len(datagrams)):
        var dlen = len(datagrams[i])
        if dlen > 0:
            var buf = _heap_alloc[UInt8](dlen).as_any_origin()
            for j in range(dlen):
                buf[j] = datagrams[i][j]
            _ = external_call["send", Int](fd, buf, dlen, Int32(0))
            buf.free()


def _recv_datagram(fd: Int32) raises -> List[UInt8]:
    """Non-blocking recv on connected UDP socket.  Returns empty list on EAGAIN."""
    var buf = _heap_alloc[UInt8](65536).as_any_origin()
    # MSG_DONTWAIT = 0x40
    var n = external_call["recv", Int](fd, buf, 65536, Int32(0x40))
    if n <= 0:
        buf.free()
        return List[UInt8]()
    var result = List[UInt8](capacity=n)
    for i in range(n):
        result.append(buf[i])
    buf.free()
    return result^


# ── QUIC driving ──────────────────────────────────────────────────────────


def _drive_handshake(mut quic: QuicConnection, fd: Int32) raises:
    """Pump send/recv until the QUIC handshake completes."""
    for _ in range(600):  # 600 × 100ms poll = 60s max (interop runner default)
        var now = monotonic_us()
        var out = quic.send(now)
        _send_datagrams(fd, out)
        if quic.is_established():
            return
        if udp_poll(fd, 100):
            var data = _recv_datagram(fd)
            if len(data) > 0:
                now = monotonic_us()
                quic.recv(Span(data), now)
                if quic.is_established():
                    return
    raise "handshake failed"


def _fetch_file(
    mut quic: QuicConnection, fd: Int32, path: String
) raises -> List[UInt8]:
    """Send HTTP/0.9 GET for path, collect the full response."""
    var stream_id = http09_request(quic, path)
    var response = List[UInt8]()

    for _ in range(1000):
        var now = monotonic_us()
        var out = quic.send(now)
        _send_datagrams(fd, out)

        # Poll for incoming data
        if udp_poll(fd, 50):
            var data = _recv_datagram(fd)
            if len(data) > 0:
                quic.recv(Span(data), monotonic_us())

        # Check for stream events
        while True:
            var ev = quic.poll()
            if not ev:
                break
            if ev.value().type_id == QuicEvent.STREAM_READABLE:
                if ev.value().stream_id == stream_id:
                    var result = http09_collect(quic, stream_id)
                    var fin = result[1]
                    for j in range(len(result[0])):
                        response.append(result[0][j])
                    if fin:
                        return response^

    raise "fetch timeout for " + path


# ── Main ──────────────────────────────────────────────────────────────────


def main() raises:
    # ── Testcase dispatch ─────────────────────────────────────────────────
    var testcase = getenv("TESTCASE")
    if testcase != "handshake" and testcase != "transfer":
        _ = external_call["exit", Int32](Int32(127))

    # ── Parse request URLs ────────────────────────────────────────────────
    var requests_str = getenv("REQUESTS")
    var urls = _split_spaces(requests_str)
    if len(urls) == 0:
        raise "REQUESTS is empty"

    # Configurable paths (env var overrides for local testing).
    var certs_opt = getenv_opt("CERTS_DIR")
    var certs_dir = certs_opt.value() if certs_opt else String("/certs")
    var dl_opt = getenv_opt("DOWNLOADS_DIR")
    var downloads_dir = dl_opt.value() if dl_opt else String("/downloads")

    # ── Load TLS library + CA cert ────────────────────────────────────────
    var tls = TlsBackend()

    var ca_pem = read_file(certs_dir + "/ca.pem")
    var client_config = QuicClientConfig.with_ca(
        tls.shared(), Span(ca_pem), alpn="hq-interop",
    )

    # ── Parse first URL for host:port (all URLs share the same server) ───
    var parsed0 = _parse_url(urls[0])
    var host = parsed0[0]
    var port = parsed0[1]

    # ── Transport parameters ──────────────────────────────────────────────
    var params = default_transport_params()
    params.max_idle_timeout = UInt64(30_000)
    params.initial_max_data = UInt64(10_485_760)
    params.initial_max_stream_data_bidi_local = UInt64(1_048_576)
    params.initial_max_stream_data_bidi_remote = UInt64(1_048_576)
    params.initial_max_streams_bidi = UInt64(100)

    # ── Connect + handshake ───────────────────────────────────────────────
    var fd = udp_connect(host, port)
    var now = monotonic_us()
    var quic = QuicConnection.client(tls.shared(), client_config, host, params, now)

    _drive_handshake(quic, fd)

    # ── Fetch all requested files ─────────────────────────────────────────
    for i in range(len(urls)):
        var parsed = _parse_url(urls[i])
        var path = parsed[2]
        var filename = basename(path)
        var data = _fetch_file(quic, fd, path)
        write_file(downloads_dir + "/" + filename, Span(data))

    # ── Clean up ──────────────────────────────────────────────────────────
    udp_close(fd)
    _ = external_call["exit", Int32](Int32(0))
