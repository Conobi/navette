"""hello_h2_server.mojo — minimal end-to-end HTTP/2 over TLS server.

`https://[::]:8443` by default (override via `HELLO_H2_PORT`).
Demonstrates:

  * `tcp_listener(port)`         — owns the listening TCP socket
  * `TlsBackend`                  — loads librustls_mojo.so
  * `TlsServerConfig`             — PEM cert+key + ALPN=h2
  * `H2TcpServer[HelloHandler]`   — generic h2 server
  * `serve_forever(server)`       — io_uring event loop

# Build + run

  $ ./scripts/gen_test_certs.sh   # one-time: populate repo-root certs/
  $ cd examples/hello_h2_server
  $ uv sync
  $ uv run mojox build main.mojo -o hello_h2_server
  $ ./hello_h2_server

# Test the running server

  $ curl -v --http2 -k https://localhost:8443/

Expected: `HTTP/2 200` with `Hello, H2!\\n` body.
"""

from navette.h2.h2_tcp_server import H2TcpServer, serve_forever
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
from navette.tls import TlsBackend, TlsServerConfig

from std.ffi import external_call
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.collections.optional import Optional


def _getenv_opt(name: String) -> Optional[String]:
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


def _read_file(path: String) raises -> List[UInt8]:
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


def make_hello_handler() raises -> HelloHandler:
    return HelloHandler()


def main() raises:
    var port_env = _getenv_opt(String("HELLO_H2_PORT"))
    var port: Int = 8443
    if port_env:
        port = atol(port_env.value())

    var cert_path_env = _getenv_opt(String("HELLO_H2_CERT"))
    var cert_path: String = String("certs/server.crt")
    if cert_path_env:
        cert_path = cert_path_env.value()

    var key_path_env = _getenv_opt(String("HELLO_H2_KEY"))
    var key_path: String = String("certs/server.key")
    if key_path_env:
        key_path = key_path_env.value()

    print("hello_h2_server: binding [::]:" + String(port))
    print("  cert: " + cert_path)
    print("  key:  " + key_path)

    var cert = _read_file(cert_path)
    var key = _read_file(key_path)

    var tls = TlsBackend()
    var server_config = TlsServerConfig(tls.shared(), Span(cert), Span(key))
    var alpn = List[String]()
    alpn.append(String("h2"))
    server_config.set_alpn_protocols(alpn)

    var sock = tcp_listener(port)
    print("hello_h2_server: listening (fd=" + String(Int(sock.raw())) + ")")

    var server = H2TcpServer[HelloHandler](
        sock^,
        make_hello_handler,
        TlsBackend(other=tls),
        server_config^,
    )
    serve_forever(server^)
