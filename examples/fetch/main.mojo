# examples/fetch/main.mojo
#
# `fetch` — a minimal curl alternative built on mojo-net's unified HTTP client (M6).
# Supports HTTP/1.1 and HTTP/2 via ALPN, TLS, redirects, content decoding,
# and the full M6 unified client stack.
#
# Build + run:
#   LD_LIBRARY_PATH=lib uv run mojo run -I . -I conformance \
#     examples/fetch/main.mojo [OPTIONS] <URL>
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
#   --http1.1        Force HTTP/1.1 (skip H2 ALPN)
#   --http2          Force HTTP/2 (only negotiate h2)
#   --json DATA      Shorthand: POST with Content-Type: application/json
#   -w FORMAT        Write timing stats after response:
#                      %{time_connect} %{time_tls} %{time_total}
#                      %{http_code} %{size_download} %{alpn}
#
# Examples:
#   fetch https://1.1.1.1/cdn-cgi/trace
#   fetch -v -L https://httpbin.org/redirect/3
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


def _tcp_connect(host_ip: String, port: Int) raises -> Int32:
    """Open a blocking TCP socket and connect to host_ip:port (IPv4 only)."""
    var fd = external_call["socket", Int32](Int32(2), Int32(1), Int32(0))
    if fd < 0:
        raise "socket() failed: " + String(Int(fd))

    var addr = _heap_alloc[UInt8](16).as_any_origin()
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

    var rc = external_call["connect", Int32](fd, addr, Int32(16))
    addr.free()
    if rc < 0:
        _ = external_call["close", Int32](fd)
        raise "connect() failed: " + String(Int(rc))
    return fd


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


def main() raises:
    var args = _parse_args()
    var parsed = parse_url(args.url)
    var t_start = _monotonic_ms()

    if args.verbose:
        print("* Connecting to " + parsed.host + ":" + String(Int(parsed.port)) + "...")

    # 1. TCP connect
    var fd = _tcp_connect(parsed.host, Int(parsed.port))
    var t_connect = _monotonic_ms()

    if args.verbose:
        print("* Connected in " + String(Int(t_connect - t_start)) + "ms")

    # 2. TLS handshake
    # Heap-allocate RustlsLibrary: TlsConnection stores a raw pointer to it
    # via UnsafePointer(to=lib). If lib is on the stack, a Mojo compiler bug
    # causes the pointer to go stale when `tls` is passed as `mut` to helper
    # functions and new stack variables are allocated afterwards.
    var lib_ptr = _heap_alloc[RustlsLibrary](1).as_any_origin()
    lib_ptr.init_pointee_move(RustlsLibrary())
    ref lib = lib_ptr[]
    var cli_cfg = TlsClientConfig(lib, insecure=True)
    var alpn_protos = List[String]()
    if args.force_h1:
        alpn_protos.append("http/1.1")
    elif args.force_h2:
        alpn_protos.append("h2")
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

    # 3. Build request headers
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

    if args.verbose:
        print("> " + args.method + " " + parsed.path + " " + alpn_str)
        for i in range(len(hdrs)):
            print("> " + hdrs.name_at(i) + ": " + hdrs.value_at(i))
        print(">")

    var req = Request(method=method^, target=parsed.path, headers=hdrs^, body=body^)

    # 4. Execute via the appropriate session
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
        # Pump
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
        # Pump
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

    var redirect_count = 0

    var t_total = _monotonic_ms()

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
            t_connect - t_start,
            t_tls - t_start,
            t_total - t_start,
        )
        print(out, end="")

    if not args.silent and args.verbose:
        print("")
        print("* Total time: " + String(Int(t_total - t_start)) + "ms")
        if redirect_count > 0:
            print("* Redirects followed: " + String(redirect_count))

    _ = external_call["close", Int32](fd)
    # lib_ptr intentionally not freed: TlsConnection/TlsClientConfig destructors
    # still hold raw pointers to it. Process exit reclaims all memory.
