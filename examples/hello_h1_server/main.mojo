"""hello_h1_server.mojo — minimal end-to-end HTTP/1.1 server.

Plaintext HTTP/1.1 on `[::]:8080` by default (override via
`HELLO_H1_PORT`). Demonstrates:

  * `tcp_listener(port)`     — owns the listening TCP socket
  * `H1TcpServer[HelloHandler]` — generic plaintext H1 server
  * `serve_forever(server)`     — io_uring event loop

# Build + run

  $ cd examples/hello_h1_server
  $ uv sync
  $ LD_LIBRARY_PATH=../../lib uv run mojox build main.mojo -o hello_h1_server
  $ LD_LIBRARY_PATH=../../lib ./hello_h1_server

# Test the running server

  $ curl -v http://localhost:8080/

Expected: `HTTP/1.1 200 OK` with `Hello, H1!\\n` body.
"""

from std.ffi import external_call
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.h1.config import ParseConfig
from navette.h1.h1_tcp_server import H1TcpServer, serve_forever
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
from navette.io.tcp_socket import tcp_listener


def _getenv_int(name: String, default: Int) -> Int:
    """Read an integer environment variable; fall back to default if unset/invalid."""
    var nbuf = _heap_alloc[UInt8](len(name) + 1)
    var name_bytes = name.as_bytes()
    for i in range(len(name_bytes)):
        nbuf[i] = name_bytes[i]
    nbuf[len(name_bytes)] = 0
    var ptr_int = external_call["getenv", Int](nbuf)
    nbuf.free()
    if ptr_int == 0:
        return default
    var ptr = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=ptr_int)
    var s = String()
    var i = 0
    while ptr[i] != 0:
        s += chr(Int(ptr[i]))
        i += 1
    try:
        return atol(s)
    except:
        return default


struct HelloHandler(StreamHandler):
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


def make_hello_handler() raises -> HelloHandler:
    return HelloHandler()


def main() raises:
    var port = _getenv_int(String("HELLO_H1_PORT"), 8080)

    print("hello_h1_server: binding [::]:" + String(port))

    var sock = tcp_listener(port)
    print("hello_h1_server: listening (fd=" + String(Int(sock.raw())) + ")")

    var server = H1TcpServer[HelloHandler](
        sock^,
        make_hello_handler,
        ParseConfig(),
    )
    serve_forever(server^)
