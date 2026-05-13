# examples/h2_client/main.mojo
#
# Smoke test: connect to 1.1.1.1:443 with TLS + ALPN h2, send a GET request
# using H2Session, print the response body.
#
# Uses blocking POSIX sockets (no boucle event loop needed for a one-shot
# request). The TLS and H2 layers stay sans-I/O; we just shuttle bytes
# synchronously.
#
# Build + run
#
#   $ cd examples/h2_client
#   $ uv sync
#   $ uv run mojox build main.mojo -o h2_client
#   $ ./h2_client https://example.com/

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.collections.optional import Optional

from mojo_net.tls import RustlsLibrary, TlsClientConfig, TlsConnection
from mojo_net.http import Method, Version, Headers, Request
from mojo_net.http.request import RequestBody
from mojo_net.h2.h2_session import H2Session
from mojo_net.http.session import RequestHandle
from mojo_net.http.body import BodyFrame

comptime _HOST: String = "1.1.1.1"
comptime _PATH: String = "/cdn-cgi/trace"
comptime _PORT: Int = 443
comptime _RECV_BUF: Int = 16384
comptime _MAX_ITERS: Int = 200


# ---------------------------------------------------------------------------
# Blocking POSIX socket helpers
# ---------------------------------------------------------------------------


def _tcp_connect(host_ip: String, port: Int) raises -> Int32:
    """Open a blocking TCP socket and connect to host_ip:port.

    host_ip must be a dotted-decimal IPv4 string (no DNS lookup performed).
    """
    var fd = external_call["socket", Int32](
        Int32(2),   # AF_INET
        Int32(1),   # SOCK_STREAM
        Int32(0),
    )
    if fd < 0:
        raise "socket() failed: " + String(Int(fd))

    # Build sockaddr_in (16 bytes) inline in a heap buffer.
    # Layout: sin_family(2) | sin_port(2) | sin_addr(4) | sin_zero(8)
    var addr = _heap_alloc[UInt8](16).as_any_origin()
    for i in range(16):
        addr[i] = 0

    # sin_family = AF_INET = 2 (little-endian uint16)
    addr[0] = 2
    addr[1] = 0

    # sin_port = htons(port): swap bytes so the wire sees big-endian port.
    # htons(443) = 0xBB01 → stored on LE as bytes [0x01, 0xBB]
    var port_be = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    addr[2] = UInt8(port_be & 0xFF)
    addr[3] = UInt8((port_be >> 8) & 0xFF)

    # sin_addr: parse dotted-decimal into 4 bytes (network order = big-endian).
    # 1.1.1.1 → bytes [1, 1, 1, 1] (endianness is irrelevant when all equal,
    # but we parse generically for correctness).
    var octet = 0
    var octet_idx = 4
    var host_bytes = host_ip.as_bytes()
    for ci in range(len(host_bytes)):
        var b = host_bytes[ci]
        if b == 46:  # ord('.')
            addr[octet_idx] = UInt8(octet)
            octet_idx += 1
            octet = 0
        else:
            octet = octet * 10 + (Int(b) - 48)
    addr[octet_idx] = UInt8(octet)   # last octet

    var rc = external_call["connect", Int32](fd, addr, Int32(16))
    addr.free()
    if rc < 0:
        _ = external_call["close", Int32](fd)
        raise "connect() failed: " + String(Int(rc))
    return fd


def _send_all(fd: Int32, data: List[UInt8]) raises:
    var n = len(data)
    if n == 0:
        return
    # Copy the remaining slice into a fresh buffer each retry to avoid
    # pointer arithmetic (UnsafePointer has no .offset() in 0.26.2).
    var remaining = List[UInt8]()
    for i in range(n):
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
# TLS send/recv helpers
# ---------------------------------------------------------------------------


def _tls_send(fd: Int32, mut tls: TlsConnection) raises:
    """Drain buffered ciphertext from tls and send it to the socket."""
    var ct = tls.drain_ciphertext()
    if len(ct) > 0:
        _send_all(fd, ct)


def _tls_recv(fd: Int32, mut tls: TlsConnection) raises -> List[UInt8]:
    """Read a chunk from the socket, feed it to tls, return decrypted plaintext."""
    var raw = _recv_some(fd)
    if len(raw) == 0:
        return List[UInt8]()
    tls.receive_data(Span(raw))
    _tls_send(fd, tls)   # flush any handshake/alert ciphertext
    return tls.drain_plaintext()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() raises:
    print("=== H2 smoke test: GET https://" + _HOST + _PATH + " ===")

    # 1. TCP connect
    print("[1] TCP connect to " + _HOST + ":" + String(_PORT) + " ...")
    var fd = _tcp_connect(_HOST, _PORT)
    print("    connected (fd=" + String(Int(fd)) + ")")

    # 2. TLS with ALPN h2
    print("[2] TLS handshake (ALPN: h2, insecure=True) ...")
    var lib = RustlsLibrary()
    var cli_cfg = TlsClientConfig(lib, insecure=True)
    var alpn_protos = List[String]()
    alpn_protos.append("h2")
    cli_cfg.set_alpn_protocols(lib, alpn_protos)
    var tls = TlsConnection.new_client(lib, cli_cfg, _HOST)

    # Send ClientHello (already buffered by new_client)
    _tls_send(fd, tls)

    while tls.is_handshaking():
        var plain = _tls_recv(fd, tls)
        _ = plain  # plaintext during handshake is empty; ciphertext handled inside

    # Drain any final handshake ciphertext (Finished etc.)
    _tls_send(fd, tls)

    var proto = tls.alpn()
    if proto:
        print("    ALPN negotiated: " + proto.value())
    else:
        print("    ALPN: none (server may not support h2)")

    # 3. H2 session — send preface (already in drain() from __init__)
    print("[3] Sending H2 client preface ...")
    var session = H2Session()
    var preface_bytes = session.drain()
    tls.send_data(Span(preface_bytes))
    _tls_send(fd, tls)

    # 4. Submit GET /cdn-cgi/trace
    print("[4] Submitting GET " + _PATH + " ...")
    var hdrs = Headers()
    hdrs.add("host", _HOST)          # maps to :authority pseudo-header
    hdrs.add("user-agent", "mojo-net/h2-smoke")
    var req = Request(
        method=Method.get(),
        target=_PATH,
        version=Version.http_2(),
        headers=hdrs^,
        body=RequestBody.empty(),
    )
    var handle = session.submit(req^)
    var out_bytes = session.drain()
    tls.send_data(Span(out_bytes))
    _tls_send(fd, tls)

    # 5. Pump until response is complete
    print("[5] Reading response ...")
    for _ in range(_MAX_ITERS):
        session.run_one(handle)
        if handle.is_complete():
            break
        var plaintext = _tls_recv(fd, tls)
        if len(plaintext) > 0:
            session.feed(Span(plaintext))
        # Flush any H2 protocol frames (SETTINGS ACK, WINDOW_UPDATE, etc.)
        var h2_out = session.drain()
        if len(h2_out) > 0:
            tls.send_data(Span(h2_out))
            _tls_send(fd, tls)

    if handle.is_errored():
        print("ERROR: stream error")
    elif not handle.is_complete():
        print("ERROR: response not received in " + String(_MAX_ITERS) + " iterations")
    else:
        var resp = handle^.take_response()
        print("")
        print("HTTP/2 " + String(Int(resp.status.code())))
        print("")
        # Reconstruct body bytes from frames
        var body_str = String()
        for i in range(len(resp.body)):
            var frame = BodyFrame(other=resp.body[i])
            if frame.is_data():
                for bi in range(len(frame.data())):
                    body_str += chr(Int(frame.data()[bi]))
        print(body_str)

    _ = external_call["close", Int32](fd)
