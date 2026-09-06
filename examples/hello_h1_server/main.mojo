"""hello_h1_server.mojo — minimal end-to-end HTTP/1.1 server.

Plaintext HTTP/1.1 on `[::]:8080` by default (override via
`HELLO_H1_PORT`). Demonstrates:

  * `tcp_listener(port)`         — owns the listening TCP socket
  * `H1TcpServer[HelloHandler]`  — generic plaintext H1 server
  * Proactor lifecycle: heap-alloc → wire_context → start → tick loop

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
from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc

from navette.h1.config import ParseConfig
from navette.h1.h1_tcp_server import H1TcpServer
from boucle.drivers.io_uring import IoUringDriver
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
from navette.runtime.socket_helpers import tcp_listener


def _getenv_int(name: String, default: Int) -> Int:
    """Read an integer environment variable; fall back to default if unset/invalid."""
    var nbuf = _heap_alloc[UInt8](name.byte_length() + 1)
    var name_bytes = name.as_bytes()
    for i in range(len(name_bytes)):
        nbuf[unsafe_offset=i] = name_bytes[i]
    nbuf[unsafe_offset= len(name_bytes)] = 0
    var ptr_int = external_call["getenv", Int](nbuf)
    nbuf.unsafe_free()
    if ptr_int == 0:
        return default
    var ptr = Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=ptr_int)
    var s = String()
    var i = 0
    while ptr[unsafe_offset=i] != 0:
        s += chr(Int(ptr[unsafe_offset=i]))
        i += 1
    try:
        return atol(s)
    except:
        return default


struct HelloHandler(StreamHandler):
    def __init__(out self):
        pass

    def __init__(out self, *, deinit move: Self):
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

    var srv_ptr = _heap_alloc[H1TcpServer[HelloHandler]](1)
    srv_ptr.unsafe_write(server^)
    srv_ptr[].wire_context()

    var driver = IoUringDriver(capacity=4096)
    srv_ptr[].start(driver)

    print("hello_h1_server: serving")
    while True:
        _ = driver.tick(wait=True)
        srv_ptr[].reap_closed()
