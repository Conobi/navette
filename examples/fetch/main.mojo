# examples/fetch/main.mojo
#
# `fetch` — HTTP CLI built on navette.
#
# Transport selection (default → safe TCP+TLS, upgrade to H3 only when the
# origin has advertised it):
#   http://                       → plaintext TCP + HTTP/1.1.
#   https:// (default)            → TCP+TLS with ALPN-negotiated H2/H1.
#                                   On startup, the on-disk Alt-Svc cache
#                                   (~/.cache/mojo-fetch/alt_svc.txt) is
#                                   consulted: if a live `h3` advertisement
#                                   exists for the origin, fetch will try
#                                   QUIC/H3 first and fall back with a
#                                   helpful error if the handshake fails.
#                                   After every response, any Alt-Svc
#                                   header is parsed and persisted so the
#                                   next invocation can upgrade.
#   https:// + --http3            → force QUIC/H3 regardless of cache.
#   https:// + --http2 / --http1.1 → force TCP+TLS at that ALPN.
#
# Build + run
#
#   $ cd examples/fetch
#   $ uv sync
#   $ uv run mojox build main.mojo -o fetch
#   $ ./fetch https://example.com/
#
# Options:
#   -X METHOD        HTTP method (default: GET, or POST if -d given)
#   -H "Name: Val"   Add request header (repeatable)
#   -d DATA          Request body string
#   -v               Verbose: show request + response headers
#   -I               HEAD request, print headers only
#   -L               Follow redirects (up to 10 hops)
#   -s               Silent: suppress progress/info messages
#   -k, --insecure   Skip TLS cert verification (self-signed origins).
#                    Requires the shipped librustls_mojo.so to include the
#                    `*_insecure` symbol (release/dev profile, default).
#                    Hardened-profile installs will abort if you pass this.
#   --compressed     Request + decode gzip/brotli content-encoding
#   --http1.1        Force HTTP/1.1 over TCP+TLS
#   --http2          Force HTTP/2 over TCP+TLS
#   --http3          Force HTTP/3 over QUIC (UDP)
#   --json DATA      Shorthand: POST with Content-Type: application/json
#   -w FORMAT        Write timing stats after response:
#                      %{time_connect} %{time_tls} %{time_total}
#                      %{http_code} %{size_download} %{alpn}
#
# Examples:
#   fetch https://1.1.1.1/cdn-cgi/trace
#   fetch -v --http3 https://www.cloudflare.com/
#   fetch --json '{"q":"hello"}' https://httpbin.org/post
#   fetch --compressed https://example.com
#   fetch -w "\n%{http_code} %{size_download}B via %{alpn} in %{time_total}ms\n" https://1.1.1.1/

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.collections.optional import Optional
from std.os.env import getenv
from std.os import makedirs
from std.pathlib import Path

from boucle.handle import OwnedHandle

from navette.tls import RustlsLibrary, TlsClientConfig, TlsConnection
from navette.tls.lib import librustls_supports_insecure
from navette.http import Method, Version, Headers, Request
from navette.http.request import RequestBody
from navette.http.response import Response
from navette.http.session import RequestHandle
from navette.http.body import BodyFrame
from navette.http.url import parse_url, ParsedUrl
from navette.http.alt_svc import Origin, AltSvcEntry
from navette.http.coro_client import HttpCoroClient
from navette.http.session_slot import SessionSlot
from navette.h1.h1_session import H1Session
from navette.h2.h2_session import H2Session
from navette.h3.h3_session import H3Session
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.http.decode import ContentDecoder, ContentEncoding
from navette.io import resolve_host, tcp_connect, udp_connect

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


def _realtime_secs() -> UInt:
    """Wall-clock seconds since the Unix epoch (CLOCK_REALTIME).

    The Alt-Svc cache uses this as both the `received_at` timestamp on
    insert and the `now` reference on lookup so entries remain valid
    across process restarts (monotonic clocks reset on reboot and can't
    be persisted).
    """
    var ts = _heap_alloc[UInt8](16).as_any_origin()
    _ = external_call["clock_gettime", Int32](
        Int32(0),  # CLOCK_REALTIME
        ts,
    )
    var sec_ptr = ts.bitcast[Int64]()
    var sec = Int(sec_ptr[])
    ts.free()
    return UInt(sec)


def _connect_tcp_resolved(host: String, port: Int) raises -> OwnedHandle:
    """Resolve `host:port` via dual-stack getaddrinfo + connect the first
    address that succeeds.

    Tries each address from `resolve_host` in glibc's RFC 6724 order
    (typically IPv6 first, then IPv4) and returns the first connected
    `OwnedHandle`. On a host with broken IPv6 routing this means the
    first attempt blocks until the kernel times out (~75s), but with
    working dual-stack the v6 attempt succeeds immediately.
    """
    var addrs = resolve_host(host, port)
    for i in range(len(addrs) - 1):
        try:
            return tcp_connect(addrs[i])
        except e:
            pass  # try next address
    return tcp_connect(addrs[len(addrs) - 1])


def _connect_udp_resolved(host: String, port: Int) raises -> OwnedHandle:
    """Resolve `host:port` and pin a UDP socket to the first reachable addr.

    Same iteration strategy as `_connect_tcp_resolved`. UDP `connect(2)`
    only stores the peer addr (no network handshake) so failures are
    almost always synthetic (e.g. AF mismatch), but the fallback is
    free and matches the TCP path's shape.
    """
    var addrs = resolve_host(host, port)
    for i in range(len(addrs) - 1):
        try:
            return udp_connect(addrs[i])
        except e:
            pass
    return udp_connect(addrs[len(addrs) - 1])


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
    """Receive a single UDP datagram.

    Blocks for up to the socket's `SO_RCVTIMEO` (set per-call site via
    `_set_recv_timeout_ms`). Returns an empty list on timeout, EAGAIN,
    or any other `rc < 0` — fetch's outer handshake loop relies on a
    wall-clock deadline rather than per-recv errno disambiguation, so
    we don't raise here. Without errno access from Mojo's
    `external_call`, we can't distinguish a real socket error from a
    benign timeout; the deadline catches both.
    """
    var buf = _heap_alloc[UInt8](65536).as_any_origin()
    var rc = external_call["recv", Int](fd, buf, 65536, Int32(0))
    var result = List[UInt8]()
    if rc > 0:
        for i in range(rc):
            result.append(buf[i])
    buf.free()
    return result^


def _set_recv_timeout_ms(fd: Int32, ms: Int) raises:
    """Set `SO_RCVTIMEO` on `fd` so blocking `recv(2)` returns periodically.

    Without this, an unsolicited recv on a UDP socket whose peer never
    answers (e.g. an H3 request to a host that only serves H1/H2 on the
    URL port) blocks forever. With a positive timeout, the kernel
    surfaces `EAGAIN` after `ms` milliseconds and our outer loop can
    enforce a wall-clock deadline.
    """
    # struct timeval { time_t tv_sec; suseconds_t tv_usec; }  — 16 bytes on x86_64.
    var tv = _heap_alloc[UInt8](16).as_any_origin()
    for i in range(16):
        tv[i] = UInt8(0)
    var sec_ptr = tv.bitcast[Int64]()
    sec_ptr[] = Int64(ms // 1000)
    var usec_ptr = UnsafePointer[Int64, MutAnyOrigin](
        unsafe_from_address=Int(tv) + 8
    )
    usec_ptr[] = Int64((ms % 1000) * 1000)
    # SOL_SOCKET=1, SO_RCVTIMEO=20, optlen=16 bytes.
    var rc = external_call["setsockopt", Int32](
        fd, Int32(1), Int32(20), tv, Int32(16),
    )
    tv.free()
    if rc < 0:
        raise "setsockopt(SO_RCVTIMEO) failed: rc=" + String(Int(rc))


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
    var force_h3: Bool
    var write_format: String
    var silent: Bool
    var insecure: Bool

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
        self.force_h3 = False
        self.write_format = String("")
        self.silent = False
        self.insecure = False

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
        self.force_h3 = take.force_h3
        self.write_format = take.write_format^
        self.silent = take.silent
        self.insecure = take.insecure


def _parse_args() raises -> CliArgs:
    from std.sys import argv
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
        elif arg == "--http3":
            result.force_h3 = True
        elif arg == "-k" or arg == "--insecure":
            result.insecure = True
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


struct _CachePaths(Movable):
    """Cache file + its parent dir, resolved once per process."""
    var dir: String
    var file: String

    def __init__(out self, *, dir: String, file: String):
        self.dir = dir
        self.file = file

    def __init__(out self, *, deinit take: Self):
        self.dir = take.dir^
        self.file = take.file^


def _alt_svc_cache_paths() -> _CachePaths:
    """Resolve on-disk cache locations.

    Prefers `$HOME/.cache/mojo-fetch/alt_svc.txt`. Falls back to
    `/tmp/mojo-fetch-alt-svc.txt` (no parent to create) when `$HOME`
    is unset.
    """
    var home = getenv("HOME", "")
    if len(home) > 0:
        var dir = home + "/.cache/mojo-fetch"
        return _CachePaths(dir=dir, file=dir + "/alt_svc.txt")
    return _CachePaths(dir=String("/tmp"), file=String("/tmp/mojo-fetch-alt-svc.txt"))


def _load_alt_svc_from_disk(mut client: HttpCoroClient, verbose: Bool) raises:
    """Best-effort load of the persisted Alt-Svc cache. Failures are
    swallowed silently (in `-v` mode the reason is surfaced) so a
    missing or unreadable cache never blocks the request."""
    var paths = _alt_svc_cache_paths()
    var path = Path(paths.file)
    if not path.exists():
        return
    try:
        var content = path.read_text()
        client.load_alt_svc(content, _realtime_secs())
        if verbose:
            print("* Loaded Alt-Svc cache from " + paths.file)
    except:
        if verbose:
            print("* Alt-Svc cache at " + paths.file + " unreadable; ignoring")


def _save_alt_svc_to_disk(mut client: HttpCoroClient, verbose: Bool) raises:
    """Best-effort save of the in-memory Alt-Svc cache. Creates the
    parent directory if needed. Failures are swallowed (mentioned in
    verbose mode) so a read-only home or full disk never blocks the
    response from being printed."""
    var paths = _alt_svc_cache_paths()
    try:
        makedirs(Path(paths.dir), exist_ok=True)
        var content = client.dump_alt_svc()
        Path(paths.file).write_text(content)
        if verbose:
            print("* Saved Alt-Svc cache to " + paths.file)
    except:
        if verbose:
            print("* Could not persist Alt-Svc cache to " + paths.file)


def _cache_has_live_h3(
    mut client: HttpCoroClient, origin: Origin, now: UInt
) raises -> Bool:
    """True iff the Alt-Svc cache currently has an unexpired `h3`
    advertisement for `origin`. Drives the default-https dispatch:
    when set, fetch upgrades to QUIC; when unset, it stays on TCP+TLS."""
    var entries = client.lookup_alt_svc(origin, now)
    for i in range(len(entries)):
        if entries[i].protocol == String("h3"):
            return True
    return False


def _print_alt_svc_if_verbose(
    mut client: HttpCoroClient, origin: Origin, now_uint: UInt, verbose: Bool,
) raises:
    """Surface any Alt-Svc advertisements the server returned (verbose only).

    The parsed entries live in `client._alt_svc` (an in-process
    `AltSvcCache`). In a one-shot CLI the cache dies with the process,
    but printing the entries proves the integration is live and gives
    the user the line they'd act on (e.g. `h3=":443"` ⇒ retry over QUIC).
    """
    if not verbose:
        return
    var entries = client.lookup_alt_svc(origin, now_uint)
    if len(entries) == 0:
        return
    print("* Alt-Svc advertised by server:")
    for i in range(len(entries)):
        ref e = entries[i]
        var hp: String
        if len(e.host) == 0:
            hp = ":" + String(Int(e.port))
        else:
            hp = e.host + ":" + String(Int(e.port))
        print(
            "*   " + e.protocol + "=" + hp
            + " ma=" + String(Int(e.max_age_secs))
            + (" persist=1" if e.persist else "")
        )


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
    mut client: HttpCoroClient,
    args: CliArgs, parsed: ParsedUrl, var req: Request,
) raises -> FetchResult:
    """Execute request over QUIC/H3."""
    var t_start = _monotonic_ms()

    if args.verbose:
        print("* Connecting to " + parsed.host + ":" + String(Int(parsed.port)) + " (UDP/QUIC)...")

    var sock = _connect_udp_resolved(parsed.host, Int(parsed.port))
    # Bound each recv to 500ms so a non-responsive UDP peer (e.g. a
    # server that only listens on TCP/443 and silently drops the QUIC
    # initial) doesn't hang fetch forever. The outer handshake loop
    # below enforces a 3s wall-clock deadline on top of this.
    _set_recv_timeout_ms(sock.raw(), 500)
    var t_connect = _monotonic_ms()

    if args.verbose:
        print("* UDP socket ready in " + String(Int(t_connect - t_start)) + "ms")

    # Heap-allocate library (same Mojo compiler bug workaround as TCP path)
    var lib_ptr = _heap_alloc[RustlsLibrary](1).as_any_origin()
    lib_ptr.init_pointee_move(RustlsLibrary())
    var lib_addr = UInt64(Int(lib_ptr))

    # Create QUIC client TLS config with h3 ALPN. Cert verification
    # mirrors the `-k`/`--insecure` flag: default = Mozilla WebPKI roots
    # (matches curl), `-k` = accept any server cert (self-signed dev).
    var alpn_buf = _heap_alloc[UInt8](2).as_any_origin()
    alpn_buf[0] = UInt8(0x68)  # 'h'
    alpn_buf[1] = UInt8(0x33)  # '3'
    var cfg_out = _heap_alloc[Int32](1).as_any_origin()
    var rc: Int32
    if args.insecure:
        rc = lib_ptr[].quic_client_config_new_insecure(alpn_buf, Int32(2), cfg_out)
    else:
        rc = lib_ptr[].quic_client_config_new(alpn_buf, Int32(2), cfg_out)
    if rc != 0:
        raise "quic_client_config_new failed"
    var quic_cfg = cfg_out[0]
    cfg_out.free()
    alpn_buf.free()

    var now = _monotonic_ms() * UInt64(1000)  # microseconds
    var params = _h3_default_params()
    var quic = QuicConnection.client(lib_addr, quic_cfg, parsed.host, params, now)

    # QUIC handshake: send/recv loop with a 3s wall-clock deadline.
    #
    # SO_RCVTIMEO above gates each recv at 500ms; the deadline below
    # bails out when the server is unreachable on UDP/<port> (silent
    # drop = no QUIC reply forever, which used to hang the whole CLI).
    # The QUIC stack handles its own PTO-driven retransmits as long as
    # we keep calling send(now) with the current clock each iteration.
    var hs_deadline = _monotonic_ms() + UInt64(3000)
    while not quic.is_established():
        if _monotonic_ms() > hs_deadline:
            raise (
                "QUIC handshake timed out after 3s — the server may not "
                "support HTTP/3 on UDP/" + String(Int(parsed.port))
                + ". Retry with --http2 or --http1.1."
            )
        now = _monotonic_ms() * UInt64(1000)
        var out_dgs = quic.send(now)
        for i in range(len(out_dgs)):
            _udp_send(sock.raw(), out_dgs[i])
        if quic.is_established():
            break
        var dgram = _udp_recv_blocking(sock.raw())
        if len(dgram) > 0:
            now = _monotonic_ms() * UInt64(1000)
            quic.recv(Span(dgram), now)

    var t_tls = _monotonic_ms()
    if args.verbose:
        print("* QUIC handshake in " + String(Int(t_tls - t_connect)) + "ms")

    # Wrap in H3Session, then in SessionSlot, attach to coro_client.
    # The QUIC handshake stayed direct above (sans-I/O contract:
    # fetch owns the socket); from here on the byte pump goes
    # through `client.drain_datagrams` / `client.feed_datagram` which
    # preserves UDP framing one packet per element.
    var origin = parsed.to_origin()
    var session = H3Session(quic=quic^)
    client.attach_session(
        Origin(other=origin), SessionSlot.from_h3(session^),
    )

    if args.verbose:
        print("> " + args.method + " " + parsed.path + " h3")

    var handle = client.submit(Origin(other=origin), req^)

    # Pump until response.
    for _ in range(_MAX_ITERS):
        now = _monotonic_ms() * UInt64(1000)
        var out_dgs = client.drain_datagrams(Origin(other=origin), now)
        for i in range(len(out_dgs)):
            _udp_send(sock.raw(), out_dgs[i])

        client.run_one(Origin(other=origin), handle)
        if handle.is_complete():
            break

        var dgram = _udp_recv_blocking(sock.raw())
        if len(dgram) > 0:
            now = _monotonic_ms() * UInt64(1000)
            client.feed_datagram(
                Span(dgram), Origin(other=origin), now,
            )

    if not handle.is_complete():
        raise "H3 response not received (timeout)"
    var resp = handle^.take_response()

    var now_uint = _realtime_secs()
    client.update_alt_svc(Origin(other=origin), resp, now_uint)
    _print_alt_svc_if_verbose(client, origin, now_uint, args.verbose)

    var t_total = _monotonic_ms()
    # OwnedHandle's drop closes the fd at scope exit.
    return FetchResult(resp^, String("h3"), t_connect - t_start, t_tls - t_start, t_total - t_start)


def _request_via_plain_tcp(
    mut client: HttpCoroClient,
    args: CliArgs, parsed: ParsedUrl, var req: Request,
) raises -> FetchResult:
    """Execute request over plaintext TCP (HTTP/1.1 — no TLS, no ALPN).

    Connection establishment stays in fetch (sans-I/O contract for the
    coro_client). After the TCP socket is connected we wrap a fresh
    H1Session in a SessionSlot and hand it to the client; the per-byte
    pump runs through `client.drain_datagrams` / `client.feed_datagram`
    which gives us the Alt-Svc + future-pool plumbing for free.
    """
    var t_start = _monotonic_ms()

    if args.verbose:
        print(
            "* Connecting to " + parsed.host + ":" + String(Int(parsed.port))
            + " (TCP, plaintext)..."
        )

    var sock = _connect_tcp_resolved(parsed.host, Int(parsed.port))
    var t_connect = _monotonic_ms()

    if args.verbose:
        print("* Connected in " + String(Int(t_connect - t_start)) + "ms")
        print("> " + args.method + " " + parsed.path + " http/1.1")

    var origin = parsed.to_origin()
    var session = H1Session()
    client.attach_session(Origin(other=origin), SessionSlot.from_h1(session^))
    var handle = client.submit(Origin(other=origin), req^)

    for _ in range(_MAX_ITERS):
        var dgs = client.drain_datagrams(Origin(other=origin), UInt64(0))
        for i in range(len(dgs)):
            _send_all(sock.raw(), dgs[i])
        client.run_one(Origin(other=origin), handle)
        if handle.is_complete():
            break
        var data = _recv_some(sock.raw())
        if len(data) > 0:
            client.feed_datagram(Span(data), Origin(other=origin), UInt64(0))
    if not handle.is_complete():
        raise "response not received (timeout)"
    var resp = handle^.take_response()

    var now_uint = _realtime_secs()
    client.update_alt_svc(Origin(other=origin), resp, now_uint)
    _print_alt_svc_if_verbose(client, origin, now_uint, args.verbose)

    var t_total = _monotonic_ms()
    # OwnedHandle's drop closes the fd at scope exit.
    # t_tls === t_connect on plaintext — TLS handshake elapsed time is 0.
    return FetchResult(
        resp^, String("http/1.1"),
        t_connect - t_start, t_connect - t_start, t_total - t_start,
    )


def _request_via_tcp(
    mut client: HttpCoroClient,
    args: CliArgs, parsed: ParsedUrl, var req: Request,
) raises -> FetchResult:
    """Execute request over TCP+TLS (H2 or H1)."""
    var t_start = _monotonic_ms()

    if args.verbose:
        print("* Connecting to " + parsed.host + ":" + String(Int(parsed.port)) + " (TCP)...")

    var sock = _connect_tcp_resolved(parsed.host, Int(parsed.port))
    var t_connect = _monotonic_ms()

    if args.verbose:
        print("* Connected in " + String(Int(t_connect - t_start)) + "ms")

    # Heap-allocate RustlsLibrary (Mojo compiler bug workaround)
    var lib_ptr = _heap_alloc[RustlsLibrary](1).as_any_origin()
    lib_ptr.init_pointee_move(RustlsLibrary())
    ref lib = lib_ptr[]
    var cli_cfg = TlsClientConfig(lib, insecure=args.insecure)
    var alpn_protos = List[String]()
    if args.force_h1:
        alpn_protos.append("http/1.1")
    else:
        alpn_protos.append("h2")
        alpn_protos.append("http/1.1")
    cli_cfg.set_alpn_protocols(lib, alpn_protos)
    var tls = TlsConnection.new_client(lib, cli_cfg, parsed.host)

    _tls_send(sock.raw(), tls)
    while tls.is_handshaking():
        _ = _tls_recv(sock.raw(), tls)
    _tls_send(sock.raw(), tls)
    var t_tls = _monotonic_ms()

    var alpn_str = String("http/1.1")
    var alpn_opt = tls.alpn()
    if alpn_opt:
        alpn_str = alpn_opt.value()

    if args.verbose:
        print("* TLS handshake in " + String(Int(t_tls - t_connect)) + "ms (ALPN: " + alpn_str + ")")
        print("> " + args.method + " " + parsed.path + " " + alpn_str)

    # Wrap the appropriate H1/H2 session in a slot, attach to the
    # coro_client, then drive the byte pump through it. Application
    # bytes round-trip through `tls.send_data` / `_tls_recv` for
    # encryption; `client.drain_datagrams` returns at most one
    # byte-blob per tick (datagrams aren't a meaningful concept for
    # a TCP+TLS origin — the wrapper preserves the 1-blob shape).
    var origin = parsed.to_origin()
    if alpn_str == "h2":
        var session = H2Session()
        client.attach_session(
            Origin(other=origin), SessionSlot.from_h2(session^),
        )
    else:
        var session = H1Session()
        client.attach_session(
            Origin(other=origin), SessionSlot.from_h1(session^),
        )

    var handle = client.submit(Origin(other=origin), req^)

    for _ in range(_MAX_ITERS):
        var dgs = client.drain_datagrams(Origin(other=origin), UInt64(0))
        for i in range(len(dgs)):
            tls.send_data(Span(dgs[i]))
        _tls_send(sock.raw(), tls)

        client.run_one(Origin(other=origin), handle)
        if handle.is_complete():
            break
        if handle.is_errored():
            raise "request failed: stream error"

        var plaintext = _tls_recv(sock.raw(), tls)
        if len(plaintext) > 0:
            client.feed_datagram(
                Span(plaintext), Origin(other=origin), UInt64(0),
            )

    if handle.is_errored():
        raise "request failed: stream error"
    if not handle.is_complete():
        raise "response not received (timeout)"
    var resp = handle^.take_response()

    var now_uint = _realtime_secs()
    client.update_alt_svc(Origin(other=origin), resp, now_uint)
    _print_alt_svc_if_verbose(client, origin, now_uint, args.verbose)

    var t_total = _monotonic_ms()
    # OwnedHandle's drop closes the fd at scope exit.
    return FetchResult(resp^, alpn_str, t_connect - t_start, t_tls - t_start, t_total - t_start)


def main() raises:
    var args = _parse_args()

    # Fail fast on `--insecure` against a hardened-profile librustls
    # so the user gets a useful diagnostic instead of `dlsym` aborting
    # inside OwnedDLHandle.get_function later in the TLS path.
    if args.insecure and not librustls_supports_insecure():
        raise (
            "this fetch binary was built against a hardened librustls_mojo.so "
            "that does not export the `*_insecure` symbols. Rebuild without "
            "MOJOX_BUILD_PROFILE=hardened (default `release` exports them), "
            "or drop -k / --insecure to use full WebPKI verification."
        )

    var parsed = parse_url(args.url)

    var req = _build_request(args, parsed)
    if args.verbose:
        for i in range(len(req.headers)):
            print("> " + req.headers.name_at(i) + ": " + req.headers.value_at(i))
        print(">")

    # Dispatch:
    #   http://                       → plaintext TCP + HTTP/1.1.
    #   https:// + --http3            → forced QUIC + HTTP/3.
    #   https:// + --http1.1/--http2  → TCP+TLS with that ALPN.
    #   https:// (default)            → TCP+TLS unless the on-disk Alt-Svc
    #                                   cache advertises a live `h3` entry
    #                                   for this origin, in which case we
    #                                   try QUIC and surface a clear-cache
    #                                   error if the handshake fails (the
    #                                   stale advert is dropped so the next
    #                                   run uses TCP).
    #
    # The HttpCoroClient owns the connection pool + Alt-Svc cache. Cache
    # is loaded from disk at startup and persisted after the response so
    # subsequent invocations can perform the H3 upgrade on their own.
    var client = HttpCoroClient()
    var origin = parsed.to_origin()
    _load_alt_svc_from_disk(client, args.verbose)

    var result: FetchResult
    if parsed.scheme == String("http"):
        result = _request_via_plain_tcp(client, args, parsed, req^)
    elif args.force_h3:
        result = _request_via_h3(client, args, parsed, req^)
    elif args.force_h1 or args.force_h2:
        result = _request_via_tcp(client, args, parsed, req^)
    else:
        # Default https: ask the Alt-Svc cache whether H3 is on the table.
        var now_secs = _realtime_secs()
        if _cache_has_live_h3(client, origin, now_secs):
            if args.verbose:
                print("* Alt-Svc cache has live h3 for " + origin.host
                      + ":" + String(Int(origin.port)) + " — upgrading to QUIC.")
            try:
                result = _request_via_h3(client, args, parsed, req^)
            except e:
                # Advertised h3 is dead — purge the entry, persist, and
                # surface a friendly message so the user can re-run.
                client.clear_alt_svc(origin)
                _save_alt_svc_to_disk(client, args.verbose)
                raise (
                    "QUIC handshake failed despite a cached Alt-Svc "
                    "advertisement of h3 on " + origin.host + ":"
                    + String(Int(origin.port))
                    + ". The stale entry has been removed; rerun the "
                    + "command and fetch will use TCP+TLS instead.\n"
                    + "(underlying error: " + String(e) + ")"
                )
        else:
            result = _request_via_tcp(client, args, parsed, req^)

    # Persist any Alt-Svc advertisements the response carried so the
    # next invocation can upgrade.
    _save_alt_svc_to_disk(client, args.verbose)

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
