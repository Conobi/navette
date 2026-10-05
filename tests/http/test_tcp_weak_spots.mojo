"""Connection deadlines of the H1 and H2 TCP servers.

Drives a real server on an ephemeral loopback port with in-process
blocking clients. Timeouts are 1 s and the sweep runs once per second,
so a held connection must be gone within ~2.5 s; every wait is bounded.
"""

from std.ffi import external_call
from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc
from std.testing import assert_equal, assert_true

from bouclette import WatchLoop
from bouclette.handle import OwnedHandle

from navette.h1.h1_tcp_server import H1TcpServer
from navette.h1.config import ParseConfig
from navette.h2.h2_tcp_server import H2TcpServer
from navette.http.handler import (
    StreamHandler,
    Request,
    RecvBody,
    ResponseWriter,
    Capabilities,
    StreamError,
)
from navette.net.resolver import resolve_host
from navette.quic.profile import monotonic_us
from navette.runtime.socket_helpers import tcp_connect, tcp_listener
from navette.tls import TlsBackend, TlsServerConfig
from navette.util.owned_alloc import Owned
from interop.file_io import read_file


struct StubHandler(StreamHandler):
    """Never answers: every request stays open from the server's side."""

    def __init__(out self):
        pass

    def on_request(
        mut self, var req: Request, mut body: RecvBody,
        mut resp: ResponseWriter, caps: Capabilities,
    ) raises:
        pass

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


def make_stub() raises -> StubHandler:
    return StubHandler()


def _port_of(srv: OwnedHandle) raises -> Int:
    """The bound port of a listener, from getsockname."""
    var sa_buf = Owned[UInt8](28)
    var alen_buf = Owned[Int32](1)
    alen_buf.ptr()[unsafe_offset=0] = Int32(28)
    _ = external_call["getsockname", Int32](srv.raw(), sa_buf.ptr(), alen_buf.ptr())
    var port = (Int(sa_buf.ptr()[unsafe_offset=2]) << 8) | Int(sa_buf.ptr()[unsafe_offset=3])
    _ = sa_buf
    _ = alen_buf
    return port


def _connect(port: Int) raises -> OwnedHandle:
    return tcp_connect(resolve_host(String("localhost"), port)[0])


def _send(fd: OwnedHandle, s: String) raises:
    var b = s.as_bytes()
    var rc = external_call["send", Int](fd.raw(), b.unsafe_ptr(), len(b), Int32(0))
    if rc != len(b):
        raise "send() returned " + String(rc)


def _pump_h1(mut loop: WatchLoop, srv: Pointer[H1TcpServer[StubHandler], MutUntrackedOrigin], ms: Int) raises:
    """Run the example run loop for `ms` milliseconds of wall time."""
    var end = monotonic_us() + UInt64(ms * 1000)
    while monotonic_us() < end:
        _ = loop.step(timeout_ms=50)
        srv[].poll_accept()
        srv[].poll_connections()
        srv[].reap_closed()


def _pump_h2(mut loop: WatchLoop, srv: Pointer[H2TcpServer[StubHandler], MutUntrackedOrigin], ms: Int) raises:
    """Run the example run loop for `ms` milliseconds of wall time."""
    var end = monotonic_us() + UInt64(ms * 1000)
    while monotonic_us() < end:
        _ = loop.step(timeout_ms=50)
        srv[].poll_accept()
        srv[].poll_connections()
        srv[].reap_closed()


def _h1_server(
    request_secs: Int, idle_secs: Int,
) raises -> Tuple[Pointer[H1TcpServer[StubHandler], MutUntrackedOrigin], Int]:
    var sock = tcp_listener(0)
    var port = _port_of(sock)
    var srv = _heap_alloc[H1TcpServer[StubHandler]](1)
    srv.unsafe_write(H1TcpServer[StubHandler](
        sock^, make_stub, ParseConfig(),
        request_timeout_secs=request_secs,
        keep_alive_timeout_secs=idle_secs,
    ))
    return (srv, port)


def _h2_server(
    idle_secs: Int,
) raises -> Tuple[Pointer[H2TcpServer[StubHandler], MutUntrackedOrigin], Int]:
    var cert = read_file(String("certs/server.crt"))
    var key = read_file(String("certs/server.key"))
    var tls = TlsBackend()
    var config = TlsServerConfig(tls.shared(), Span(cert), Span(key))
    var sock = tcp_listener(0)
    var port = _port_of(sock)
    var srv = _heap_alloc[H2TcpServer[StubHandler]](1)
    srv.unsafe_write(H2TcpServer[StubHandler](
        listen_handle=sock^, make_handler=make_stub, tls=tls^,
        server_tls_config=config^,
        request_timeout_secs=30,
        keep_alive_timeout_secs=idle_secs,
    ))
    return (srv, port)


def test_h1_slowloris_headers_hit_request_deadline() raises:
    """Trickled header bytes do not extend the request deadline."""
    var loop = WatchLoop(capacity=64)
    var sp = _h1_server(request_secs=1, idle_secs=30)
    var srv = sp[0]
    srv[].start(loop)
    var c = _connect(sp[1])
    _send(c, "GET / HTTP/1.1\r\n")
    _pump_h1(loop, srv, 200)
    assert_equal(len(srv[].connections), 1)
    for _ in range(10):  # one header byte every 250 ms, never terminated
        _send(c, "X")
        _pump_h1(loop, srv, 250)
        if len(srv[].connections) == 0:
            break
    assert_equal(len(srv[].connections), 0, "slowloris conn still held")
    _ = c.raw()  # keep the client open until the server gave up
    srv.unsafe_deinit_pointee()
    srv.unsafe_free()


def test_h1_silent_connection_hits_idle_deadline() raises:
    """A connection that never sends a byte closes after the keep-alive timeout."""
    var loop = WatchLoop(capacity=64)
    var sp = _h1_server(request_secs=30, idle_secs=1)
    var srv = sp[0]
    srv[].start(loop)
    var c = _connect(sp[1])
    _pump_h1(loop, srv, 300)
    assert_equal(len(srv[].connections), 1)
    _pump_h1(loop, srv, 2500)
    assert_equal(len(srv[].connections), 0, "idle conn still held")
    _ = c.raw()
    srv.unsafe_deinit_pointee()
    srv.unsafe_free()


def test_h2_idle_connection_hits_idle_deadline() raises:
    """An H2 connection with no open stream closes after the keep-alive timeout."""
    var loop = WatchLoop(capacity=64)
    var sp = _h2_server(idle_secs=1)
    var srv = sp[0]
    srv[].start(loop)
    var c = _connect(sp[1])
    _pump_h2(loop, srv, 300)
    assert_equal(len(srv[].connections), 1)
    _pump_h2(loop, srv, 2500)
    assert_equal(len(srv[].connections), 0, "idle h2 conn still held")
    _ = c.raw()
    srv.unsafe_deinit_pointee()
    srv.unsafe_free()


def main() raises:
    test_h1_slowloris_headers_hit_request_deadline()
    print("PASS: test_h1_slowloris_headers_hit_request_deadline")
    test_h1_silent_connection_hits_idle_deadline()
    print("PASS: test_h1_silent_connection_hits_idle_deadline")
    test_h2_idle_connection_hits_idle_deadline()
    print("PASS: test_h2_idle_connection_hits_idle_deadline")
