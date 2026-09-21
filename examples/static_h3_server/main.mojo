"""Fast static-payload HTTP/3 server.

Serves a fixed-size response body to every request. Demonstrates
the navette H3UdpServer in its simplest form: one handler, one
socket, one event loop.

  $ cd examples/static_h3_server
  $ uv sync && uv run mojox build main.mojo -o static_h3_server
  $ ./static_h3_server

Binds `[::]:8443` by default.  Override with env vars:
  STATIC_PORT       — listen port (default 8443)
  STATIC_BODY_SIZE  — response body in bytes (default 1024)
  STATIC_CERT       — PEM certificate path (default certs/server.crt)
  STATIC_KEY        — PEM private key path (default certs/server.key)
"""

from std.collections import Span
from std.io.file import open as open_file
from std.os.env import getenv
from std.memory.alloc import unsafe_alloc as _heap_alloc

from navette.h3.h3_udp_server import H3UdpServer, TIMER_CEILING_MS
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
from bouclette import WatchLoop


struct StaticHandler(StreamHandler):
    """Responds 200 with a pre-allocated payload on every request."""

    var payload: List[Byte]

    def __init__(out self):
        var size = 1024
        try:
            var size_str = getenv("STATIC_BODY_SIZE", "1024")
            if size_str:
                size = atol(size_str)
        except:
            pass
        self.payload = List[Byte](capacity=size)
        for _ in range(size):
            self.payload.append(UInt8(0x41))

    def __init__(out self, *, deinit move: Self):
        self.payload = move.payload^

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        var hdrs = Headers()
        hdrs.set(String("content-type"), String("application/octet-stream"))
        resp.send_status(StatusCode(200), hdrs^)
        var data = List[Byte](copy=self.payload)
        _ = resp.try_send_body(BodyFrame.data(data^))
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


def make_handler() raises -> StaticHandler:
    """Factory called once per QUIC connection."""
    return StaticHandler()


def main() raises:
    var port_str = getenv("STATIC_PORT")
    var port = atol(port_str) if port_str else 8443
    var cert_path = getenv("STATIC_CERT", "certs/server.crt")
    var key_path = getenv("STATIC_KEY", "certs/server.key")
    var body_size = getenv("STATIC_BODY_SIZE", "1024")

    print("static_h3_server: binding [::]:" + String(port))
    print("  cert:      " + cert_path)
    print("  key:       " + key_path)
    print("  body_size: " + body_size + " bytes")

    var cert = open_file(cert_path, "r").read_bytes()
    var key = open_file(key_path, "r").read_bytes()

    var tls = TlsBackend()
    var config = QuicServerConfig(tls.shared(), Span(cert), Span(key))

    var sock = udp_listener(port)
    print("static_h3_server: listening (fd=" + String(Int(sock.raw())) + ")")

    var tp = default_transport_params()
    tp.max_idle_timeout = UInt64(30_000)

    var server = H3UdpServer[StaticHandler](
        sock^, TlsBackend(copy=tls), config^, tp^, make_handler,
    )
    var srv_ptr = _heap_alloc[H3UdpServer[StaticHandler]](1)
    srv_ptr.unsafe_write(server^)
    srv_ptr[].wire_context()

    var loop_ptr = _heap_alloc[WatchLoop](1)
    loop_ptr.unsafe_write(WatchLoop(capacity=256))
    srv_ptr[].start(loop_ptr[])

    while True:
        _ = loop_ptr[].step(Int(TIMER_CEILING_MS))
        srv_ptr[].flush()
