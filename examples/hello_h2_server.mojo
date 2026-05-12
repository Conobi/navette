"""hello_h2_server.mojo — minimal end-to-end HTTP/2 over TLS server.

`https://[::]:8443` by default (override via `HELLO_H2_PORT`).
Demonstrates:

  * `tcp_listener(port)`         — owns the listening TCP socket
  * `RustlsLibrary`               — loads librustls_mojo.so
  * `TlsServerConfig`             — PEM cert+key + ALPN=h2
  * `H2TcpServer[HelloHandler]`   — generic h2 server
  * `serve_forever(server)`       — io_uring event loop

# Build + run

  $ ./scripts/gen_test_certs.sh
  $ mojo build -I . -I ../boucle -I ../json-simd-mojo \\
         examples/hello_h2_server.mojo -o hello_h2_server
  $ LD_LIBRARY_PATH=./lib ./hello_h2_server

# Test

  $ curl -v --http2 -k https://localhost:8443/
"""

from src.h2.h2_tcp_server import H2TcpServer, serve_forever
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
from src.io.tcp_socket import tcp_listener
from src.tls import RustlsLibrary, TlsServerConfig

from interop.file_io import read_file, getenv_opt


struct HelloHandler(StreamHandler):
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

        var msg = String("Hello, H2!\n")
        var msg_bytes = msg.as_bytes()
        var body_bytes = List[UInt8](capacity=len(msg_bytes))
        for i in range(len(msg_bytes)):
            body_bytes.append(msg_bytes[i])
        _ = resp.try_send_body(BodyFrame.data(body_bytes^))
        _ = resp.try_send_body(BodyFrame.end())

    def on_body_available(
        mut self, mut body: RecvBody, mut resp: ResponseWriter,
    ) raises:
        pass

    def on_request_end(
        mut self, mut body: RecvBody, mut resp: ResponseWriter,
    ) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


fn make_hello_handler() raises -> HelloHandler:
    return HelloHandler()


fn main() raises:
    var port_env = getenv_opt(String("HELLO_H2_PORT"))
    var port: Int = 8443
    if port_env:
        port = atol(port_env.value())

    var cert_path_env = getenv_opt(String("HELLO_H2_CERT"))
    var cert_path: String = String("certs/server.crt")
    if cert_path_env:
        cert_path = cert_path_env.value()

    var key_path_env = getenv_opt(String("HELLO_H2_KEY"))
    var key_path: String = String("certs/server.key")
    if key_path_env:
        key_path = key_path_env.value()

    print("hello_h2_server: binding [::]:" + String(port))
    print("  cert: " + cert_path)
    print("  key:  " + key_path)

    var cert = read_file(cert_path)
    var key = read_file(key_path)

    var tls_lib = RustlsLibrary()
    var server_config = TlsServerConfig(tls_lib, Span(cert), Span(key))
    var alpn = List[String]()
    alpn.append(String("h2"))
    server_config.set_alpn_protocols(tls_lib, alpn)

    var sock = tcp_listener(port)
    print("hello_h2_server: listening (fd=" + String(Int(sock.raw())) + ")")

    var server = H2TcpServer[HelloHandler](
        sock^,
        make_hello_handler,
        tls_lib^,
        server_config^,
    )
    serve_forever(server^)
