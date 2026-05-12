"""hello_h1_server.mojo — minimal end-to-end HTTP/1.1 server.

Plaintext HTTP/1.1 on `[::]:8080` by default (override via
`HELLO_H1_PORT`). Demonstrates:

  * `tcp_listener(port)`     — owns the listening TCP socket
  * `H1TcpServer[HelloHandler]` — generic plaintext H1 server
  * `serve_forever(server)`     — io_uring event loop

# Build + run

  $ mojo build -I . -I ../boucle -I ../json-simd-mojo \\
         examples/hello_h1_server.mojo -o hello_h1_server
  $ ./hello_h1_server

# Test the running server

  $ curl -v http://localhost:8080/

Expected: `HTTP/1.1 200 OK` with `Hello, H1!\\n` body.
"""

from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from src.h1.config import ParseConfig
from src.h1.h1_tcp_server import H1TcpServer, serve_forever
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

from interop.file_io import getenv_opt


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

        var msg = String("Hello, H1!\n")
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
    var port_env = getenv_opt(String("HELLO_H1_PORT"))
    var port: Int = 8080
    if port_env:
        port = atol(port_env.value())

    print("hello_h1_server: binding [::]:" + String(port))

    var sock = tcp_listener(port)
    print("hello_h1_server: listening (fd=" + String(Int(sock.raw())) + ")")

    var server = H1TcpServer[HelloHandler](
        sock^,
        make_hello_handler,
        ParseConfig(),
    )
    serve_forever(server^)
