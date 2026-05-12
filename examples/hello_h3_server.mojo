"""hello_h3_server.mojo — minimal end-to-end H3 server.

Demonstrates the full mojo-net library surface:

  * `udp_listener()`          — owns the listening UDP socket
  * `RustlsLibrary`           — loads librustls_mojo.so for the TLS handshake
  * `quic_server_config_new`  — builds a rustls server config from PEM
  * `default_transport_params` — sane QUIC transport params for v1
  * `H3UdpServer[HelloHandler]` — the generic server
  * `serve_forever`            — bootstraps io_uring + runs the loop

# Build + run

  $ ./scripts/gen_test_certs.sh     # one-time: generate certs/server.{crt,key}
  $ mojo build -I . -I ../boucle -I ../json-simd-mojo \\
          examples/hello_h3_server.mojo -o hello_h3_server
  $ LD_LIBRARY_PATH=./lib ./hello_h3_server

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

from src.h3.h3_udp_server import H3UdpServer, serve_forever
from src.http.handler import (
    StreamHandler,
    Request,
    RecvBody,
    ResponseWriter,
    Capabilities,
    StreamError,
    BodyFrame,
)
from src.http.headers import Headers
from src.http.status import StatusCode
from src.io.udp_socket import udp_listener
from src.quic.trans_param import default_transport_params
from src.tls.lib import RustlsLibrary

from interop.file_io import read_file, getenv_opt


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
    var port_env = getenv_opt(String("HELLO_H3_PORT"))
    var port: Int = 4433
    if port_env:
        port = atol(port_env.value())

    var cert_path_env = getenv_opt(String("HELLO_H3_CERT"))
    var cert_path: String = String("certs/server.crt")
    if cert_path_env:
        cert_path = cert_path_env.value()

    var key_path_env = getenv_opt(String("HELLO_H3_KEY"))
    var key_path: String = String("certs/server.key")
    if key_path_env:
        key_path = key_path_env.value()

    print("hello_h3_server: binding [::]:" + String(port))
    print("  cert: " + cert_path)
    print("  key:  " + key_path)

    # 1. Load PEM cert + key from disk.
    var cert = read_file(cert_path)
    var key = read_file(key_path)

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
