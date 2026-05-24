"""hello_h3_server.mojo — minimal end-to-end H3 server.

Demonstrates the full navette library surface:

  * `udp_listener()`          — owns the listening UDP socket
  * `TlsBackend`              — loads librustls_mojo.so for the TLS handshake
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

from std.memory import Span
from std.io.file import open as open_file
from std.os.env import getenv

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
from navette.runtime.socket_helpers import udp_listener
from navette.quic.trans_param import default_transport_params
from navette.tls import TlsBackend
from navette.tls.config import QuicServerConfig


# ── Hello handler ────────────────────────────────────────────────────────────


struct HelloHandler(StreamHandler):
    """Responds `200 Hello, H3!` to every request."""

    def __init__(out self):
        pass

    def __init__(out self, *, deinit take: Self):
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


def make_hello_handler() raises -> HelloHandler:
    """Factory called once per QUIC connection by `H3UdpServer`."""
    return HelloHandler()


# ── Entry point ──────────────────────────────────────────────────────────────


def main() raises:
    var port_str = getenv("HELLO_H3_PORT")
    var port = atol(port_str) if port_str else 4433
    var cert_path = getenv("HELLO_H3_CERT", "certs/server.crt")
    var key_path = getenv("HELLO_H3_KEY", "certs/server.key")

    print("hello_h3_server: binding [::]:" + String(port))
    print("  cert: " + cert_path)
    print("  key:  " + key_path)

    var cert = open_file(cert_path, "r").read_bytes()
    var key = open_file(key_path, "r").read_bytes()

    var tls = TlsBackend()
    var config = QuicServerConfig(tls.shared(), Span(cert), Span(key))

    var sock = udp_listener(port)
    print("hello_h3_server: listening (fd=" + String(Int(sock.raw())) + ")")

    var tp = default_transport_params()
    var server = H3UdpServer[HelloHandler](
        sock^, TlsBackend(other=tls), config^, tp^, make_hello_handler,
    )
    serve_forever(server^)
