# examples/fetch/main.mojo
#
# `fetch` — HTTP/3 native CLI built on mojo-net.
# Default transport is QUIC/H3 (UDP). Falls back to TCP+TLS (H2/H1) with flags.
#
# Build + run:
#   LD_LIBRARY_PATH=lib uv run mojo run -I . examples/fetch/main.mojo [OPTIONS] <URL>
#
# Options:
#   -X METHOD        HTTP method (default: GET, or POST if -d given)
#   -H "Name: Val"   Add request header (repeatable)
#   -d DATA          Request body string
#   -v               Verbose: show request + response headers
#   -I               HEAD request, print headers only
#   -L               Follow redirects (up to 10 hops)
#   -s               Silent: suppress progress/info messages
#   --compressed     Request + decode gzip/brotli content-encoding
#   --http1.1        Force HTTP/1.1 over TCP+TLS
#   --http2          Force HTTP/2 over TCP+TLS
#   --json DATA      Shorthand: POST with Content-Type: application/json
#   -w FORMAT        Write timing stats after response:
#                      %{time_connect} %{time_tls} %{time_total}
#                      %{http_code} %{size_download} %{alpn}
#
# Examples:
#   fetch https://1.1.1.1/cdn-cgi/trace
#   fetch -v --http2 https://1.1.1.1/cdn-cgi/trace
#   fetch --json '{"q":"hello"}' https://httpbin.org/post
#   fetch --compressed https://example.com
#   fetch -w "\n%{http_code} %{size_download}B via %{alpn} in %{time_total}ms\n" https://1.1.1.1/

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.collections.optional import Optional

from src.tls import RustlsLibrary, TlsClientConfig, TlsConnection
from src.http import Method, Version, Headers, Request
from src.http.request import RequestBody
from src.http.response import Response
from src.http.session import RequestHandle
from src.http.body import BodyFrame
from src.http.url import parse_url, ParsedUrl
from src.h1.h1_session import H1Session
from src.h2.h2_session import H2Session
from src.h3.h3_session import H3Session
from src.quic.connection import QuicConnection
from src.quic.trans_param import TransportParams, default_transport_params
from src.http.decode import ContentDecoder, ContentEncoding

comptime _RECV_BUF: Int = 16384
comptime _MAX_ITERS: Int = 500
comptime _MAX_REDIRECTS: Int = 10


# ---------------------------------------------------------------------------
# Blocking POSIX socket + timing helpers
# ---------------------------------------------------------------------------


def _monotonic_ms() -> UInt64:
    """Get monotonic time in milliseconds via clock_gettime."""
    # struct timespec { time_t tv_sec; long tv_nsec; }  — 16 bytes on x86_64
    var ts = _heap_alloc[UInt8](16).as_any_origin()
    _ = external_call["clock_gettime", Int32](
        Int32(1),  # CLOCK_MONOTONIC
        ts,
    )
    # Read tv_sec (8 bytes LE) and tv_nsec (8 bytes LE)
    var sec_ptr = ts.bitcast[Int64]()
    var nsec_ptr = UnsafePointer[Int64, MutAnyOrigin](
        unsafe_from_address=Int(ts) + 8
    )
    var sec = Int(sec_ptr[])
    var nsec = Int(nsec_ptr[])
    ts.free()
    return UInt64(sec * 1000 + nsec // 1_000_000)


@always_inline
fn _is_dotted_ipv4(host: String) -> Bool:
    """True if `host` looks like a dotted-IPv4 literal (digits + dots only)."""
    var bytes = host.as_bytes()
    if len(bytes) == 0:
        return False
    for i in range(len(bytes)):
        var b = bytes[i]
        if b != UInt8(46) and (b < UInt8(48) or b > UInt8(57)):
            return False
    return True


def _resolve_ipv4(host: String) raises -> String:
    """Resolve a hostname to a dotted-IPv4 string via getaddrinfo(3).

    Pass-through for inputs that already look like IPv4 literals.
    Special-cases `localhost` to `127.0.0.1` so the resolver works on
    minimal containers without an `/etc/hosts` entry.

    IPv6 not yet supported (the rest of fetch is IPv4-only — _tcp_connect
    builds a 16-byte sockaddr_in).
    """
    if host == String("localhost"):
        return String("127.0.0.1")
    if _is_dotted_ipv4(host):
        return host

    # struct addrinfo on Linux x86_64 is 48 bytes:
    #   int ai_flags (4) + int ai_family (4) + int ai_socktype (4)
    #   + int ai_protocol (4) + socklen_t ai_addrlen (4) + 4-byte pad
    #   + struct sockaddr *ai_addr (8) + char *ai_canonname (8)
    #   + struct addrinfo *ai_next (8)
    # We zero hints and set ai_family = AF_INET (2) at offset 4.
    var hints = _heap_alloc[UInt8](48).as_any_origin()
    for i in range(48):
        hints[i] = 0
    hints[4] = 2  # ai_family = AF_INET (LE i32)

    # Null-terminated host C-string.
    var host_bytes = host.as_bytes()
    var host_cstr = _heap_alloc[UInt8](len(host_bytes) + 1).as_any_origin()
    for i in range(len(host_bytes)):
        host_cstr[i] = host_bytes[i]
    host_cstr[len(host_bytes)] = 0

    var out_res = _heap_alloc[UInt64](1).as_any_origin()
    out_res[0] = 0
    var rc = external_call["getaddrinfo", Int32](
        host_cstr,
        UnsafePointer[UInt8, MutAnyOrigin](),  # service = NULL
        hints,
        out_res,
    )
    host_cstr.free()
    hints.free()

    if rc != 0:
        out_res.free()
        raise (
            "getaddrinfo(" + host + ") failed: rc=" + String(Int(rc))
            + " (use IP literal as workaround)"
        )

    var res_addr = out_res[0]
    out_res.free()
    if res_addr == 0:
        raise "getaddrinfo(" + host + "): empty result"

    # First addrinfo node: read ai_addr (sockaddr * at offset 24).
    var res_ptr = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=Int(res_addr))
    var ai_addr_lo = UInt64(res_ptr[24])
    var ai_addr_b1 = UInt64(res_ptr[25]) << 8
    var ai_addr_b2 = UInt64(res_ptr[26]) << 16
    var ai_addr_b3 = UInt64(res_ptr[27]) << 24
    var ai_addr_b4 = UInt64(res_ptr[28]) << 32
    var ai_addr_b5 = UInt64(res_ptr[29]) << 40
    var ai_addr_b6 = UInt64(res_ptr[30]) << 48
    var ai_addr_b7 = UInt64(res_ptr[31]) << 56
    var ai_addr_val = (
        ai_addr_lo | ai_addr_b1 | ai_addr_b2 | ai_addr_b3
        | ai_addr_b4 | ai_addr_b5 | ai_addr_b6 | ai_addr_b7
    )

    # sockaddr_in layout: family(2) port(2 BE) addr(4) zero-pad(8) = 16 bytes.
    # We want bytes 4..8 = the 4 IPv4 octets.
    var sa_ptr = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=Int(ai_addr_val))
    var oct1 = Int(sa_ptr[4])
    var oct2 = Int(sa_ptr[5])
    var oct3 = Int(sa_ptr[6])
    var oct4 = Int(sa_ptr[7])

    _ = external_call["freeaddrinfo", Int32](res_addr)

    return (
        String(oct1) + "." + String(oct2) + "."
        + String(oct3) + "." + String(oct4)
    )


def _fill_sockaddr_in(addr: UnsafePointer[UInt8, MutAnyOrigin], host_ip: String, port: Int):
    """Populate a 16-byte sockaddr_in for AF_INET / dotted-IPv4 host."""
    for i in range(16):
        addr[i] = 0
    addr[0] = 2  # AF_INET
    addr[1] = 0
    var port_be = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    addr[2] = UInt8(port_be & 0xFF)
    addr[3] = UInt8((port_be >> 8) & 0xFF)
    var octet = 0
    var octet_idx = 4
    var host_bytes = host_ip.as_bytes()
    for ci in range(len(host_bytes)):
        var b = host_bytes[ci]
        if b == 46:
            addr[octet_idx] = UInt8(octet)
            octet_idx += 1
            octet = 0
        else:
            octet = octet * 10 + (Int(b) - 48)
    addr[octet_idx] = UInt8(octet)


def _tcp_connect(host: String, port: Int) raises -> Int32:
    """Open a blocking TCP socket and connect to host:port (IPv4 only)."""
    var fd = external_call["socket", Int32](Int32(2), Int32(1), Int32(0))
    if fd < 0:
        raise "socket() failed: " + String(Int(fd))

    var host_ip = _resolve_ipv4(host)
    var addr = _heap_alloc[UInt8](16).as_any_origin()
    _fill_sockaddr_in(addr, host_ip, port)

    var rc = external_call["connect", Int32](fd, addr, Int32(16))
    addr.free()
    if rc < 0:
        _ = external_call["close", Int32](fd)
        raise "connect() failed: " + String(Int(rc))
    return fd


def _udp_connect(host: String, port: Int) raises -> Int32:
    """Open a connected UDP socket to host:port (IPv4 only)."""
    var fd = external_call["socket", Int32](Int32(2), Int32(2), Int32(0))  # SOCK_DGRAM=2
    if fd < 0:
        raise "socket(UDP) failed: " + String(Int(fd))

    var host_ip = _resolve_ipv4(host)
    var addr = _heap_alloc[UInt8](16).as_any_origin()
    _fill_sockaddr_in(addr, host_ip, port)

    var rc = external_call["connect", Int32](fd, addr, Int32(16))
    addr.free()
    if rc < 0:
        _ = external_call["close", Int32](fd)
        raise "connect(UDP) failed: " + String(Int(rc))
    return fd


def _udp_send(fd: Int32, data: List[UInt8]) raises:
    """Send a single UDP datagram."""
    if len(data) == 0:
        return
    var buf = _heap_alloc[UInt8](len(data)).as_any_origin()
    for i in range(len(data)):
        buf[i] = data[i]
    var rc = external_call["send", Int](fd, buf, len(data), Int32(0))
    buf.free()
    if rc <= 0:
        raise "send(UDP) returned " + String(rc)


def _udp_recv(fd: Int32) raises -> List[UInt8]:
    """Receive a single UDP datagram (non-blocking attempt with MSG_DONTWAIT)."""
    var buf = _heap_alloc[UInt8](65536).as_any_origin()
    var rc = external_call["recv", Int](fd, buf, 65536, Int32(0x40))  # MSG_DONTWAIT
    var result = List[UInt8]()
    if rc > 0:
        for i in range(rc):
            result.append(buf[i])
    buf.free()
    return result^


def _udp_recv_blocking(fd: Int32) raises -> List[UInt8]:
    """Receive a single UDP datagram (blocking)."""
    var buf = _heap_alloc[UInt8](65536).as_any_origin()
    var rc = external_call["recv", Int](fd, buf, 65536, Int32(0))
    var result = List[UInt8]()
    if rc > 0:
        for i in range(rc):
            result.append(buf[i])
    buf.free()
    if rc < 0:
        raise "recv(UDP) returned " + String(rc)
    return result^


def _send_all(fd: Int32, data: List[UInt8]) raises:
    var remaining = List[UInt8]()
    for i in range(len(data)):
        remaining.append(data[i])
    while len(remaining) > 0:
        var m = len(remaining)
        var buf = _heap_alloc[UInt8](m).as_any_origin()
        for i in range(m):
            buf[i] = remaining[i]
        var rc = external_call["send", Int](fd, buf, m, Int32(0))
        buf.free()
        if rc <= 0:
            raise "send() returned " + String(rc)
        var next = List[UInt8]()
        for i in range(rc, m):
            next.append(remaining[i])
        remaining = next^


def _recv_some(fd: Int32) raises -> List[UInt8]:
    var buf = _heap_alloc[UInt8](_RECV_BUF).as_any_origin()
    var rc = external_call["recv", Int](fd, buf, _RECV_BUF, Int32(0))
    var result = List[UInt8]()
    if rc > 0:
        for i in range(rc):
            result.append(buf[i])
    buf.free()
    if rc < 0:
        raise "recv() returned " + String(rc)
    return result^


# ---------------------------------------------------------------------------
# TLS helpers
# ---------------------------------------------------------------------------


def _tls_send(fd: Int32, mut tls: TlsConnection) raises:
    var ct = tls.drain_ciphertext()
    if len(ct) > 0:
        _send_all(fd, ct)


def _tls_recv(fd: Int32, mut tls: TlsConnection) raises -> List[UInt8]:
    var raw = _recv_some(fd)
    if len(raw) == 0:
        return List[UInt8]()
    tls.receive_data(Span(raw))
    _tls_send(fd, tls)
    return tls.drain_plaintext()


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


struct CliArgs(Movable):
    var url: String
    var method: String
    var headers: List[String]
    var body: String
    var verbose: Bool
    var head_only: Bool
    var follow_redirects: Bool
    var compressed: Bool
    var force_h1: Bool
    var force_h2: Bool
    var write_format: String
    var silent: Bool

    def __init__(out self):
        self.url = String("")
        self.method = String("")
        self.headers = List[String]()
        self.body = String("")
        self.verbose = False
        self.head_only = False
        self.follow_redirects = False
        self.compressed = False
        self.force_h1 = False
        self.force_h2 = False
        self.write_format = String("")
        self.silent = False

    def __init__(out self, *, deinit take: Self):
        self.url = take.url^
        self.method = take.method^
        self.headers = take.headers^
        self.body = take.body^
        self.verbose = take.verbose
        self.head_only = take.head_only
        self.follow_redirects = take.follow_redirects
        self.compressed = take.compressed
        self.force_h1 = take.force_h1
        self.force_h2 = take.force_h2
        self.write_format = take.write_format^
        self.silent = take.silent


def _parse_args() raises -> CliArgs:
    from sys import argv
    var args = argv()
    var result = CliArgs()
    var i = 1
    while i < len(args):
        var arg = args[i]
        if arg == "-X" and i + 1 < len(args):
            i += 1
            result.method = args[i]
        elif arg == "-H" and i + 1 < len(args):
            i += 1
            result.headers.append(args[i])
        elif arg == "-d" and i + 1 < len(args):
            i += 1
            result.body = args[i]
        elif arg == "--json" and i + 1 < len(args):
            i += 1
            result.body = args[i]
            result.headers.append("Content-Type: application/json")
            result.headers.append("Accept: application/json")
        elif arg == "-v":
            result.verbose = True
        elif arg == "-I":
            result.head_only = True
        elif arg == "-L":
            result.follow_redirects = True
        elif arg == "-s":
            result.silent = True
        elif arg == "--compressed":
            result.compressed = True
        elif arg == "--http1.1":
            result.force_h1 = True
        elif arg == "--http2":
            result.force_h2 = True
        elif arg == "-w" and i + 1 < len(args):
            i += 1
            result.write_format = args[i]
        elif not arg.startswith("-"):
            result.url = arg
        i += 1

    if len(result.url) == 0:
        raise "Usage: fetch [OPTIONS] <URL>\nTry: fetch -v https://1.1.1.1/cdn-cgi/trace"

    if len(result.method) == 0:
        if len(result.body) > 0:
            result.method = "POST"
        elif result.head_only:
            result.method = "HEAD"
        else:
            result.method = "GET"

    return result^


def _str_to_method(s: String) -> Method:
    if s == "GET":
        return Method.get()
    if s == "POST":
        return Method.post()
    if s == "PUT":
        return Method.put()
    if s == "DELETE":
        return Method.delete()
    if s == "HEAD":
        return Method.head()
    return Method.get()


# ---------------------------------------------------------------------------
# Write format (-w) expansion
# ---------------------------------------------------------------------------


def _expand_write_format(
    fmt: String,
    http_code: Int,
    size_download: Int,
    alpn_str: String,
    time_connect_ms: UInt64,
    time_tls_ms: UInt64,
    time_total_ms: UInt64,
) -> String:
    """Expand %{variable} placeholders in the -w format string."""
    var result = String()
    var bytes = fmt.as_bytes()
    var n = len(bytes)
    var i = 0
    while i < n:
        if i + 1 < n and bytes[i] == UInt8(37) and bytes[i + 1] == UInt8(123):
            # Found %{ — scan for closing }
            var end = i + 2
            while end < n and bytes[end] != UInt8(125):
                end += 1
            if end < n:
                var varname = String()
                for j in range(i + 2, end):
                    varname += chr(Int(bytes[j]))
                if varname == "http_code":
                    result += String(http_code)
                elif varname == "size_download":
                    result += String(size_download)
                elif varname == "alpn":
                    result += alpn_str
                elif varname == "time_connect":
                    result += String(Int(time_connect_ms))
                elif varname == "time_tls":
                    result += String(Int(time_tls_ms))
                elif varname == "time_total":
                    result += String(Int(time_total_ms))
                else:
                    result += "?"
                i = end + 1
                continue
        # Handle \n escape
        if i + 1 < n and bytes[i] == UInt8(92) and bytes[i + 1] == UInt8(110):
            result += "\n"
            i += 2
            continue
        result += chr(Int(bytes[i]))
        i += 1
    return result^


def _is_redirect(code: UInt16) -> Bool:
    return code == UInt16(301) or code == UInt16(302) or code == UInt16(307) or code == UInt16(308)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _build_request(args: CliArgs, parsed: ParsedUrl) raises -> Request:
    """Build the HTTP request from CLI args."""
    var hdrs = Headers()
    hdrs.add("host", parsed.host)
    hdrs.add("user-agent", "mojo-fetch/1.0")
    hdrs.add("accept", "*/*")
    if args.compressed:
        hdrs.add("accept-encoding", "gzip, br")
    for i in range(len(args.headers)):
        var h = args.headers[i]
        var hbytes = h.as_bytes()
        var colon_pos = -1
        for j in range(len(hbytes)):
            if hbytes[j] == UInt8(58):
                colon_pos = j
                break
        if colon_pos > 0:
            var name = String()
            for j in range(colon_pos):
                name += chr(Int(hbytes[j]))
            var value = String()
            var vstart = colon_pos + 1
            if vstart < len(hbytes) and hbytes[vstart] == UInt8(32):
                vstart += 1
            for j in range(vstart, len(hbytes)):
                value += chr(Int(hbytes[j]))
            hdrs.add(name, value)

    var body: RequestBody
    if len(args.body) > 0:
        var body_bytes = List[UInt8]()
        body_bytes.extend(args.body.as_bytes())
        body = RequestBody.buffered(body_bytes^)
    else:
        body = RequestBody.empty()

    var method = _str_to_method(args.method)
    return Request(method=method^, target=parsed.path, headers=hdrs^, body=body^)


struct FetchResult(Movable):
    var resp: Response
    var alpn: String
    var t_connect: UInt64
    var t_tls: UInt64
    var t_total: UInt64

    def __init__(out self, var resp: Response, alpn: String, t_connect: UInt64, t_tls: UInt64, t_total: UInt64):
        self.resp = resp^
        self.alpn = alpn
        self.t_connect = t_connect
        self.t_tls = t_tls
        self.t_total = t_total

    def __init__(out self, *, deinit take: Self):
        self.resp = take.resp^
        self.alpn = take.alpn^
        self.t_connect = take.t_connect
        self.t_tls = take.t_tls
        self.t_total = take.t_total


def _h3_default_params() -> TransportParams:
    """QUIC transport params for the client."""
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    p.initial_max_data = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_local = UInt64(65_536)
    p.initial_max_stream_data_bidi_remote = UInt64(65_536)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


def _request_via_h3(
    args: CliArgs, parsed: ParsedUrl, var req: Request,
) raises -> FetchResult:
    """Execute request over QUIC/H3."""
    var t_start = _monotonic_ms()

    if args.verbose:
        print("* Connecting to " + parsed.host + ":" + String(Int(parsed.port)) + " (UDP/QUIC)...")

    var fd = _udp_connect(parsed.host, Int(parsed.port))
    var t_connect = _monotonic_ms()

    if args.verbose:
        print("* UDP socket ready in " + String(Int(t_connect - t_start)) + "ms")

    # Heap-allocate library (same Mojo compiler bug workaround as TCP path)
    var lib_ptr = _heap_alloc[RustlsLibrary](1).as_any_origin()
    lib_ptr.init_pointee_move(RustlsLibrary())
    var lib_addr = UInt64(Int(lib_ptr))

    # Create QUIC client TLS config with h3 ALPN. Insecure variant
    # (accepts any server cert) — matches the TCP/TLS path's
    # `TlsClientConfig(lib, insecure=True)` so fetch works against
    # self-signed local servers.
    var alpn_buf = _heap_alloc[UInt8](2).as_any_origin()
    alpn_buf[0] = UInt8(0x68)  # 'h'
    alpn_buf[1] = UInt8(0x33)  # '3'
    var cfg_out = _heap_alloc[Int32](1).as_any_origin()
    var rc = lib_ptr[].quic_client_config_new_insecure(alpn_buf, Int32(2), cfg_out)
    if rc != 0:
        raise "quic_client_config_new_insecure failed"
    var quic_cfg = cfg_out[0]
    cfg_out.free()
    alpn_buf.free()

    var now = _monotonic_ms() * UInt64(1000)  # microseconds
    var params = _h3_default_params()
    var quic = QuicConnection.client(lib_addr, quic_cfg, parsed.host, params, now)

    # QUIC handshake: exchange datagrams until established
    for _ in range(100):
        now = _monotonic_ms() * UInt64(1000)
        var out_dgs = quic.send(now)
        for i in range(len(out_dgs)):
            _udp_send(fd, out_dgs[i])
        if quic.is_established():
            break
        var dgram = _udp_recv_blocking(fd)
        if len(dgram) > 0:
            now = _monotonic_ms() * UInt64(1000)
            quic.recv(Span(dgram), now)
    if not quic.is_established():
        raise "QUIC handshake failed"

    var t_tls = _monotonic_ms()
    if args.verbose:
        print("* QUIC handshake in " + String(Int(t_tls - t_connect)) + "ms")

    # Wrap in H3Session
    var session = H3Session(quic=quic^)

    # Bootstrap H3 (SETTINGS exchange)
    now = _monotonic_ms() * UInt64(1000)
    var boot_dgs = session.drain_datagrams(now)
    for i in range(len(boot_dgs)):
        _udp_send(fd, boot_dgs[i])

    # Submit request
    if args.verbose:
        print("> " + args.method + " " + parsed.path + " h3")

    var handle = session.submit(req^)
    now = _monotonic_ms() * UInt64(1000)
    var req_dgs = session.drain_datagrams(now)
    for i in range(len(req_dgs)):
        _udp_send(fd, req_dgs[i])

    # Pump until response
    for _ in range(_MAX_ITERS):
        session.run_one(handle)
        if handle.is_complete():
            break
        var dgram = _udp_recv_blocking(fd)
        if len(dgram) > 0:
            now = _monotonic_ms() * UInt64(1000)
            session.feed_datagram(Span(dgram), now)
        now = _monotonic_ms() * UInt64(1000)
        var out_dgs = session.drain_datagrams(now)
        for i in range(len(out_dgs)):
            _udp_send(fd, out_dgs[i])

    if not handle.is_complete():
        raise "H3 response not received (timeout)"

    var t_total = _monotonic_ms()
    _ = external_call["close", Int32](fd)
    return FetchResult(handle^.take_response(), String("h3"), t_connect - t_start, t_tls - t_start, t_total - t_start)


def _request_via_plain_tcp(
    args: CliArgs, parsed: ParsedUrl, var req: Request,
) raises -> FetchResult:
    """Execute request over plaintext TCP (HTTP/1.1 — no TLS, no ALPN)."""
    var t_start = _monotonic_ms()

    if args.verbose:
        print(
            "* Connecting to " + parsed.host + ":" + String(Int(parsed.port))
            + " (TCP, plaintext)..."
        )

    var fd = _tcp_connect(parsed.host, Int(parsed.port))
    var t_connect = _monotonic_ms()

    if args.verbose:
        print("* Connected in " + String(Int(t_connect - t_start)) + "ms")
        print("> " + args.method + " " + parsed.path + " http/1.1")

    var session = H1Session()
    var handle = session.submit(req^)
    var out = session.drain()
    _send_all(fd, out)
    for _ in range(_MAX_ITERS):
        session.run_one(handle)
        if handle.is_complete():
            break
        var data = _recv_some(fd)
        if len(data) > 0:
            session.feed(Span(data))
    if not handle.is_complete():
        raise "response not received (timeout)"
    var resp = handle^.take_response()

    var t_total = _monotonic_ms()
    _ = external_call["close", Int32](fd)
    # t_tls === t_connect on plaintext — TLS handshake elapsed time is 0.
    return FetchResult(
        resp^, String("http/1.1"),
        t_connect - t_start, t_connect - t_start, t_total - t_start,
    )


def _request_via_tcp(
    args: CliArgs, parsed: ParsedUrl, var req: Request,
) raises -> FetchResult:
    """Execute request over TCP+TLS (H2 or H1)."""
    var t_start = _monotonic_ms()

    if args.verbose:
        print("* Connecting to " + parsed.host + ":" + String(Int(parsed.port)) + " (TCP)...")

    var fd = _tcp_connect(parsed.host, Int(parsed.port))
    var t_connect = _monotonic_ms()

    if args.verbose:
        print("* Connected in " + String(Int(t_connect - t_start)) + "ms")

    # Heap-allocate RustlsLibrary (Mojo compiler bug workaround)
    var lib_ptr = _heap_alloc[RustlsLibrary](1).as_any_origin()
    lib_ptr.init_pointee_move(RustlsLibrary())
    ref lib = lib_ptr[]
    var cli_cfg = TlsClientConfig(lib, insecure=True)
    var alpn_protos = List[String]()
    if args.force_h1:
        alpn_protos.append("http/1.1")
    else:
        alpn_protos.append("h2")
        alpn_protos.append("http/1.1")
    cli_cfg.set_alpn_protocols(lib, alpn_protos)
    var tls = TlsConnection.new_client(lib, cli_cfg, parsed.host)

    _tls_send(fd, tls)
    while tls.is_handshaking():
        _ = _tls_recv(fd, tls)
    _tls_send(fd, tls)
    var t_tls = _monotonic_ms()

    var alpn_str = String("http/1.1")
    var alpn_opt = tls.alpn()
    if alpn_opt:
        alpn_str = alpn_opt.value()

    if args.verbose:
        print("* TLS handshake in " + String(Int(t_tls - t_connect)) + "ms (ALPN: " + alpn_str + ")")
        print("> " + args.method + " " + parsed.path + " " + alpn_str)

    # Execute via H2 or H1
    var resp: Response
    if alpn_str == "h2":
        var session = H2Session()
        var preface = session.drain()
        tls.send_data(Span(preface))
        _tls_send(fd, tls)
        var handle = session.submit(req^)
        var out = session.drain()
        tls.send_data(Span(out))
        _tls_send(fd, tls)
        for _ in range(_MAX_ITERS):
            session.run_one(handle)
            if handle.is_complete():
                break
            var plaintext = _tls_recv(fd, tls)
            if len(plaintext) > 0:
                session.feed(Span(plaintext))
            var h2_out = session.drain()
            if len(h2_out) > 0:
                tls.send_data(Span(h2_out))
                _tls_send(fd, tls)
        if handle.is_errored():
            raise "request failed: stream error"
        if not handle.is_complete():
            raise "response not received (timeout)"
        resp = handle^.take_response()
    else:
        var session = H1Session()
        var handle = session.submit(req^)
        var out = session.drain()
        tls.send_data(Span(out))
        _tls_send(fd, tls)
        for _ in range(_MAX_ITERS):
            session.run_one(handle)
            if handle.is_complete():
                break
            var plaintext = _tls_recv(fd, tls)
            if len(plaintext) > 0:
                session.feed(Span(plaintext))
        if not handle.is_complete():
            raise "response not received (timeout)"
        resp = handle^.take_response()

    var t_total = _monotonic_ms()
    _ = external_call["close", Int32](fd)
    return FetchResult(resp^, alpn_str, t_connect - t_start, t_tls - t_start, t_total - t_start)


def main() raises:
    var args = _parse_args()
    var parsed = parse_url(args.url)

    var req = _build_request(args, parsed)
    if args.verbose:
        for i in range(len(req.headers)):
            print("> " + req.headers.name_at(i) + ": " + req.headers.value_at(i))
        print(">")

    # Dispatch:
    #   http://   → plaintext TCP + HTTP/1.1 (no TLS, no QUIC).
    #   https:// + --http1.1 / --http2 → TCP+TLS with ALPN-negotiated H1/H2.
    #   https://  (default)            → UDP+QUIC + HTTP/3.
    var result: FetchResult
    if parsed.scheme == String("http"):
        result = _request_via_plain_tcp(args, parsed, req^)
    elif args.force_h1 or args.force_h2:
        result = _request_via_tcp(args, parsed, req^)
    else:
        result = _request_via_h3(args, parsed, req^)

    ref resp = result.resp
    var alpn_str = result.alpn
    var t_connect = result.t_connect
    var t_tls = result.t_tls
    var t_total = result.t_total

    # 6. Content-Encoding decoding
    var body_bytes = List[UInt8]()
    for i in range(len(resp.body)):
        var frame = BodyFrame(other=resp.body[i])
        if frame.is_data():
            ref data = frame.data()
            for bi in range(len(data)):
                body_bytes.append(data[bi])

    var content_encoding = resp.headers.get("content-encoding")
    if args.compressed and len(content_encoding) > 0 and content_encoding != "identity":
        if args.verbose:
            print("* Decoding content-encoding: " + content_encoding)
        var enc = ContentEncoding.from_header(content_encoding)
        var decoder = ContentDecoder(enc)
        var decoded = decoder.feed(body_bytes^)
        var remaining = decoder.finish()
        body_bytes = decoded^
        body_bytes.extend(remaining^)

    # 7. Output response
    if args.verbose or args.head_only:
        print("< HTTP " + String(Int(resp.status.code())))
        for i in range(len(resp.headers)):
            print("< " + resp.headers.name_at(i) + ": " + resp.headers.value_at(i))
        print("<")

    if not args.head_only:
        var body_str = String()
        for i in range(len(body_bytes)):
            body_str += chr(Int(body_bytes[i]))
        print(body_str)

    # 8. -w format output
    if len(args.write_format) > 0:
        var out = _expand_write_format(
            args.write_format,
            Int(resp.status.code()),
            len(body_bytes),
            alpn_str,
            t_connect,
            t_tls,
            t_total,
        )
        print(out, end="")

    if not args.silent and args.verbose:
        print("")
        print("* Total time: " + String(Int(t_total)) + "ms")
