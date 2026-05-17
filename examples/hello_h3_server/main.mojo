"""hello_h3_server.mojo — minimal end-to-end H3 server.

Demonstrates the full navette library surface:

  * `udp_listener()`          — owns the listening UDP socket
  * `RustlsLibrary`           — loads librustls_mojo.so for the TLS handshake
  * `quic_server_config_new`  — builds a rustls server config from PEM
  * `default_transport_params` — sane QUIC transport params for v1
  * `H3UdpServer[HelloHandler]` — the generic server
  * `serve_forever`            — bootstraps io_uring + runs the loop

# Build + run

  $ ./scripts/gen_test_certs.sh   # one-time: populate repo-root certs/
  $ cd examples/hello_h3_server
  $ uv sync
  $ uv run mojox build main.mojo -o hello_h3_server
  $ ./hello_h3_server

By default binds `[::]:4433`. Override with HELLO_H3_PORT env var.
Override cert paths with HELLO_H3_CERT / HELLO_H3_KEY (defaults
`certs/server.crt` / `certs/server.key`).

# Test the running server

With `h2load` from nghttp2:

  $ h2load --h3 -n 4 -c 1 https://127.0.0.1:4433/

You should see 4× 200 responses with "Hello, H3!" payloads.
"""

from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.h3.h3_udp_server import H3UdpServer, serve_forever
from navette.http.handler import (
    StreamHandler,
    Request,
    RecvBody,
    ResponseWriter,
    Capabilities,
    StreamError,
    BodyFrame,
)
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.io.udp_socket import udp_listener
from navette.quic.trans_param import default_transport_params
from navette.tls.lib import RustlsLibrary

from std.ffi import external_call
from std.collections.optional import Optional


fn _getenv_opt(name: String) -> Optional[String]:
    """Read environment variable; return None if unset."""
    var nbuf = _heap_alloc[UInt8](len(name) + 1)
    var name_bytes = name.as_bytes()
    for i in range(len(name_bytes)):
        nbuf[i] = name_bytes[i]
    nbuf[len(name_bytes)] = 0
    var ptr_int = external_call["getenv", Int](nbuf)
    nbuf.free()
    if ptr_int == 0:
        return None
    var ptr = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=ptr_int)
    var s = String()
    var i = 0
    while ptr[i] != 0:
        s += chr(Int(ptr[i]))
        i += 1
    return Optional(s^)


fn _read_file(path: String) raises -> List[UInt8]:
    """Read entire file via open/fstat64/pread64/close (Linux x86_64)."""
    var pbuf = _heap_alloc[UInt8](len(path) + 1)
    var path_bytes = path.as_bytes()
    for i in range(len(path_bytes)):
        pbuf[i] = path_bytes[i]
    pbuf[len(path_bytes)] = 0
    var fd = external_call["open", Int32](pbuf, Int32(0), Int32(0))  # O_RDONLY
    pbuf.free()
    if fd < 0:
        raise "_read_file: open failed for " + path
    var statbuf = _heap_alloc[UInt8](144).as_any_origin()
    var fstat_rc = external_call["fstat64", Int32](fd, statbuf)
    if fstat_rc < 0:
        _ = external_call["close", Int32](fd)
        statbuf.free()
        raise "_read_file: fstat64 failed"
    var file_size: Int = 0
    for i in range(8):
        file_size |= Int(statbuf[48 + i]) << (i * 8)
    statbuf.free()
    var result = List[UInt8](capacity=file_size)
    var chunk_size = 65536
    var buf = _heap_alloc[UInt8](chunk_size).as_any_origin()
    var offset = 0
    while offset < file_size:
        var to_read = min(chunk_size, file_size - offset)
        var n = external_call["pread64", Int](Int32(fd), buf, to_read, offset)
        if n < 0:
            buf.free()
            _ = external_call["close", Int32](fd)
            raise "_read_file: pread64 failed"
        if n == 0:
            break
        for i in range(n):
            result.append(buf[i])
        offset += n
    buf.free()
    _ = external_call["close", Int32](fd)
    return result^


# ── Hello handler ────────────────────────────────────────────────────────────


struct HelloHandler(StreamHandler):
    """Responds `200 Hello, H3!` to every request."""

    fn __init__(out self):
        pass

    fn __init__(out self, *, deinit take: Self):
        pass

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        var hdrs = Headers()
        hdrs.set(String("content-type"), String("text/plain"))
        resp.send_status(StatusCode(200), hdrs^)

        var msg = String("Hello, H3!\n")
        var msg_bytes = msg.as_bytes()
        var body_bytes = List[UInt8](capacity=len(msg_bytes))
        for i in range(len(msg_bytes)):
            body_bytes.append(msg_bytes[i])
        _ = resp.try_send_body(BodyFrame.data(body_bytes^))
        _ = resp.try_send_body(BodyFrame.end())

    def on_body_available(
        mut self, mut body: RecvBody, mut resp: ResponseWriter
    ) raises:
        pass

    def on_request_end(
        mut self, mut body: RecvBody, mut resp: ResponseWriter
    ) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


fn make_hello_handler() raises -> HelloHandler:
    """Factory called once per QUIC connection by `H3UdpServer`."""
    return HelloHandler()


# ── Entry point ──────────────────────────────────────────────────────────────


fn main() raises:
    var port_env = _getenv_opt(String("HELLO_H3_PORT"))
    var port: Int = 4433
    if port_env:
        port = atol(port_env.value())

    var cert_path_env = _getenv_opt(String("HELLO_H3_CERT"))
    var cert_path: String = String("certs/server.crt")
    if cert_path_env:
        cert_path = cert_path_env.value()

    var key_path_env = _getenv_opt(String("HELLO_H3_KEY"))
    var key_path: String = String("certs/server.key")
    if key_path_env:
        key_path = key_path_env.value()

    print("hello_h3_server: binding [::]:" + String(port))
    print("  cert: " + cert_path)
    print("  key:  " + key_path)

    # 1. Load PEM cert + key from disk.
    var cert = _read_file(cert_path)
    var key = _read_file(key_path)

    # 2. Bring up the rustls FFI library + a QUIC server config with
    #    ALPN=h3 and TLS 1.3 session resumption (always-on per rustls
    #    config builder).
    var lib = RustlsLibrary()

    var cert_buf = _heap_alloc[UInt8](len(cert)).as_any_origin()
    for i in range(len(cert)):
        cert_buf[i] = cert[i]
    var key_buf = _heap_alloc[UInt8](len(key)).as_any_origin()
    for i in range(len(key)):
        key_buf[i] = key[i]

    var alpn = String("h3")
    var alpn_bytes = alpn.as_bytes()
    var alpn_buf = _heap_alloc[UInt8](len(alpn_bytes)).as_any_origin()
    for i in range(len(alpn_bytes)):
        alpn_buf[i] = alpn_bytes[i]

    var out_handle = _heap_alloc[Int32](1).as_any_origin()
    out_handle[0] = Int32(-1)
    var rc = lib.quic_server_config_new(
        cert_buf, Int32(len(cert)),
        key_buf, Int32(len(key)),
        alpn_buf, Int32(len(alpn_bytes)),
        Int32(0),  # max_early_data — disable 0-RTT for this example
        out_handle,
    )
    cert_buf.free()
    key_buf.free()
    alpn_buf.free()
    if rc != 0:
        out_handle.free()
        raise "quic_server_config_new failed: " + lib.last_error()

    var server_config = out_handle[0]
    out_handle.free()

    # 3. Bind the listening UDP socket and hand ownership to the
    #    server. H3UdpServer's OwnedHandle field RAII-closes the fd
    #    when the server is destroyed.
    var sock = udp_listener(port)
    print("hello_h3_server: listening (fd=" + String(Int(sock.raw())) + ")")

    # 4. Construct the server + run forever.
    var tp = default_transport_params()
    var server = H3UdpServer[HelloHandler](
        sock^,
        UInt64(Int(UnsafePointer(to=lib))),
        server_config,
        tp^,
        make_hello_handler,
    )
    serve_forever(server^)
