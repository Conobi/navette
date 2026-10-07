"""Connection deadlines and the accept cap of the H1 and H2 TCP servers.

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
from navette.h2.connection import H2Connection, H2_EVT_DATA_RECEIVED
from navette.h2.header import Header
from navette.http.body import BodyFrame
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.http.handler import (
    StreamHandler,
    Request,
    RecvBody,
    ResponseWriter,
    Capabilities,
    StreamError,
)
from navette.net.resolver import resolve_host
from navette.util.clock import monotonic_us
from navette.runtime.socket_helpers import tcp_connect, tcp_listener
from navette.tls import TlsBackend, TlsClientConfig, TlsConnection, TlsServerConfig
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


comptime BIG_BODY = 640 * 1024  # ~10 initial 64 KiB windows


struct BigHandler(StreamHandler):
    """Answers every request with a `BIG_BODY` download."""

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
        resp.send_status(StatusCode.ok(), Headers())
        _ = resp.try_send_body(BodyFrame.data(List[Byte](length=BIG_BODY, fill=0x61)))
        resp.end()

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


def make_big() raises -> BigHandler:
    return BigHandler()


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


def _send_bytes(fd: OwnedHandle, b: List[Byte]) raises:
    var off = 0
    while off < len(b):
        var rc = external_call["send", Int](fd.raw(), b.unsafe_ptr().unsafe_offset(off), len(b) - off, Int32(0))
        if rc <= 0:
            raise "send() returned " + String(rc)
        off += rc


def _recv_now(fd: OwnedHandle) raises -> Tuple[List[Byte], Bool]:
    """Everything the socket holds right now (MSG_DONTWAIT), and whether the peer closed."""
    var out = List[Byte]()
    var buf = List[Byte](length=65536, fill=0)
    while True:
        var rc = external_call["recv", Int](fd.raw(), buf.unsafe_ptr(), len(buf), Int32(0x40))
        if rc == 0:
            return (out^, True)
        if rc < 0:
            return (out^, False)
        out.extend(Span(buf)[:rc])


def _tls_in(mut tls: TlsConnection, data: List[Byte]) raises -> List[Byte]:
    """Decrypts in 4 KiB slices: rustls refuses ciphertext once its plaintext buffer is full."""
    var plain = List[Byte]()
    var off = 0
    while off < len(data):
        var end = min(off + 4096, len(data))
        tls.receive_data(Span(data)[off:end])
        plain.extend(Span(tls.drain_plaintext()))
        off = end
    return plain^


def _tls_flush(fd: OwnedHandle, mut tls: TlsConnection, var plain: List[Byte]) raises:
    if len(plain) > 0:
        tls.send_data(Span(plain))
    _send_bytes(fd, tls.drain_ciphertext())


def _pump_h1(mut loop: WatchLoop, srv: Pointer[H1TcpServer[StubHandler], MutUntrackedOrigin], ms: Int) raises:
    """Run the example run loop for `ms` milliseconds of wall time."""
    var end = monotonic_us() + UInt64(ms * 1000)
    while monotonic_us() < end:
        _ = loop.step(timeout_ms=50)
        srv[].poll_accept()
        srv[].poll_connections()
        srv[].reap_closed()


def _pump_h2[H: StreamHandler](mut loop: WatchLoop, srv: Pointer[H2TcpServer[H], MutUntrackedOrigin], ms: Int) raises:
    """Run the example run loop for `ms` milliseconds of wall time."""
    var end = monotonic_us() + UInt64(ms * 1000)
    while monotonic_us() < end:
        _ = loop.step(timeout_ms=50)
        srv[].poll_accept()
        srv[].poll_connections()
        srv[].reap_closed()


def _h1_server(
    request_secs: Int, idle_secs: Int, max_conns: Int = 1024,
) raises -> Tuple[Pointer[H1TcpServer[StubHandler], MutUntrackedOrigin], Int]:
    var sock = tcp_listener(0)
    var port = _port_of(sock)
    var srv = _heap_alloc[H1TcpServer[StubHandler]](1)
    srv.unsafe_write(H1TcpServer[StubHandler](
        sock^, make_stub, ParseConfig(),
        request_timeout_secs=request_secs,
        keep_alive_timeout_secs=idle_secs,
        max_connections=max_conns,
    ))
    return (srv, port)


def _h2_server[H: StreamHandler](
    make_handler: def () thin raises -> H, idle_secs: Int, request_secs: Int = 30, max_conns: Int = 1024,
) raises -> Tuple[Pointer[H2TcpServer[H], MutUntrackedOrigin], Int]:
    var cert = read_file(String("certs/server.crt"))
    var key = read_file(String("certs/server.key"))
    var tls = TlsBackend()
    var config = TlsServerConfig(tls.shared(), Span(cert), Span(key))
    var sock = tcp_listener(0)
    var port = _port_of(sock)
    var srv = _heap_alloc[H2TcpServer[H]](1)
    srv.unsafe_write(H2TcpServer[H](
        listen_handle=sock^, make_handler=make_handler, tls=tls^,
        server_tls_config=config^,
        request_timeout_secs=request_secs,
        keep_alive_timeout_secs=idle_secs,
        max_connections=max_conns,
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
    var sp = _h2_server(make_stub, idle_secs=1)
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


def test_h1_accept_cap() raises:
    """Past the cap, accept parks until a connection frees a slot."""
    var loop = WatchLoop(capacity=64)
    var sp = _h1_server(request_secs=30, idle_secs=30, max_conns=2)
    var srv = sp[0]
    srv[].start(loop)
    var c1 = _connect(sp[1])
    var c2 = _connect(sp[1])
    var c3 = _connect(sp[1])  # completes in the kernel backlog
    _pump_h1(loop, srv, 300)
    assert_equal(len(srv[].connections), 2, "cap exceeded")
    _ = c1^  # free one slot: the parked accept must pick up c3
    _pump_h1(loop, srv, 300)
    assert_equal(len(srv[].connections), 2, "slot not reused")
    _ = c2.raw()
    _ = c3.raw()
    srv.unsafe_deinit_pointee()
    srv.unsafe_free()


def test_h2_accept_cap() raises:
    """Past the cap, accept parks until a connection frees a slot."""
    var loop = WatchLoop(capacity=64)
    var sp = _h2_server(make_stub, idle_secs=30, max_conns=2)
    var srv = sp[0]
    srv[].start(loop)
    var c1 = _connect(sp[1])
    var c2 = _connect(sp[1])
    var c3 = _connect(sp[1])
    _pump_h2(loop, srv, 300)
    assert_equal(len(srv[].connections), 2, "cap exceeded")
    _ = c1^
    _pump_h2(loop, srv, 300)
    assert_equal(len(srv[].connections), 2, "slot not reused")
    _ = c2.raw()
    _ = c3.raw()
    srv.unsafe_deinit_pointee()
    srv.unsafe_free()


def _h2_client_handshake[H: StreamHandler](
    mut loop: WatchLoop, srv: Pointer[H2TcpServer[H], MutUntrackedOrigin],
    fd: OwnedHandle, mut tls: TlsConnection, mut h2: H2Connection,
) raises:
    """Completes TLS, then sends the H2 preface; the server's replies are left unread."""
    for _ in range(40):
        _send_bytes(fd, tls.drain_ciphertext())
        _pump_h2(loop, srv, 50)
        tls.receive_data(Span(_recv_now(fd)[0]))
        if not tls.is_handshaking():
            break
    assert_true(not tls.is_handshaking(), "TLS handshake did not finish")
    h2.initiate_connection()
    _tls_flush(fd, tls, h2.data_to_send())


def test_h2_slow_reader_outlives_request_deadline() raises:
    """A download paced by the client's WINDOW_UPDATEs runs past the request budget."""
    var loop = WatchLoop(capacity=64)
    var sp = _h2_server(make_big, idle_secs=30, request_secs=1)
    var srv = sp[0]
    srv[].start(loop)
    var fd = _connect(sp[1])
    var tls_lib = TlsBackend()
    var cfg = TlsClientConfig(tls_lib.shared(), insecure=True)
    var tls = TlsConnection.new_client(tls_lib.shared(), cfg, "localhost")
    var h2 = H2Connection(client_side=True)
    _h2_client_handshake(loop, srv, fd, tls, h2)
    var hdrs = List[Header]()
    hdrs.append(Header(":method", "GET"))
    hdrs.append(Header(":scheme", "https"))
    hdrs.append(Header(":path", "/"))
    hdrs.append(Header(":authority", "localhost"))
    h2.send_headers(UInt32(1), hdrs^, end_stream=True)
    _tls_flush(fd, tls, h2.data_to_send())
    var start = monotonic_us()
    var got = 0
    var ended = False
    for _ in range(30):  # one window grant per 400 ms round
        _pump_h2(loop, srv, 400)
        var r = _recv_now(fd)
        for ref ev in h2.receive_data(_tls_in(tls, r[0])):
            if ev.kind == H2_EVT_DATA_RECEIVED:
                got += len(ev.data)
                h2.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                ended = ended or ev.stream_ended
        if ended or r[1]:
            break
        _tls_flush(fd, tls, h2.data_to_send())
    assert_true(monotonic_us() - start > 2_000_000, "download did not outlast the budget")
    assert_equal(got, BIG_BODY, "slow reader cut off")
    assert_true(ended, "stream did not end")
    _ = fd.raw()
    _ = cfg^
    srv.unsafe_deinit_pointee()
    srv.unsafe_free()


def test_h2_pings_do_not_hold_idle_connection() raises:
    """PINGs (and our PING ACKs) are not progress: the keep-alive timeout still fires."""
    var loop = WatchLoop(capacity=64)
    var sp = _h2_server(make_stub, idle_secs=1)
    var srv = sp[0]
    srv[].start(loop)
    var fd = _connect(sp[1])
    var tls_lib = TlsBackend()
    var cfg = TlsClientConfig(tls_lib.shared(), insecure=True)
    var tls = TlsConnection.new_client(tls_lib.shared(), cfg, "localhost")
    var h2 = H2Connection(client_side=True)
    _h2_client_handshake(loop, srv, fd, tls, h2)
    for _ in range(10):  # a PING every 300 ms for 3 s
        if len(srv[].connections) == 0:
            break
        h2.send_ping(List[Byte](length=8, fill=0))
        _tls_flush(fd, tls, h2.data_to_send())
        _pump_h2(loop, srv, 300)
        _ = h2.receive_data(_tls_in(tls, _recv_now(fd)[0]))
    assert_equal(len(srv[].connections), 0, "PINGs kept the h2 conn alive")
    _ = fd.raw()
    _ = cfg^
    srv.unsafe_deinit_pointee()
    srv.unsafe_free()


def main() raises:
    test_h1_slowloris_headers_hit_request_deadline()
    print("PASS: test_h1_slowloris_headers_hit_request_deadline")
    test_h1_silent_connection_hits_idle_deadline()
    print("PASS: test_h1_silent_connection_hits_idle_deadline")
    test_h2_idle_connection_hits_idle_deadline()
    print("PASS: test_h2_idle_connection_hits_idle_deadline")
    test_h1_accept_cap()
    print("PASS: test_h1_accept_cap")
    test_h2_accept_cap()
    print("PASS: test_h2_accept_cap")
    test_h2_slow_reader_outlives_request_deadline()
    print("PASS: test_h2_slow_reader_outlives_request_deadline")
    test_h2_pings_do_not_hold_idle_connection()
    print("PASS: test_h2_pings_do_not_hold_idle_connection")
