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
  STATIC_MAX_STREAMS — initial_max_streams_bidi transport parameter
                       (default: library default)
  STATIC_MAX_QUEUE_DELAY_US — overload governor dial in µs; 0 turns it
                       off (default: library default, 5000)
  STATIC_OVERLOAD_STATS — `1` prints the governor's stats as one JSON
                       line per second on stdout
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
from navette.quic.profile import monotonic_us
from navette.protect.config import ProtectionConfig, DEFAULT_MAX_QUEUE_DELAY_US
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
        hdrs.set(String("content-length"), String(len(self.payload)))
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


def overload_line(server: H3UdpServer[StaticHandler], now_us: UInt64) -> String:
    """One JSON object: the governor's last close plus the door counters an overload test watches."""
    var g = server.governor.stats.copy()
    var p = server.protection_stats()
    var d = g.decision
    return String(
        '{"t_us":', now_us, ',"intervals":', g.intervals, ',"mode":', g.state.mode._v,
        ',"queue_delay_us":', g.queue_delay_us, ',"kernel_wait_us":', g.kernel_wait_us,
        ',"budget":', d.budget, ',"share":', d.share, ',"shed_above":', d.shed_above, ',"refuse_new":', "true" if d.refuse_new else "false",
        ',"cuts":', g.state.cuts, ',"grows":', g.state.grows, ',"releases":', g.state.releases,
        ',"refused_503":', g.refused_streams_503, ',"slow_handler_warnings":', g.slow_handler_warnings,
        ',"dropped_overload":', p.dropped_overload, ',"refused_closes":', p.refused_closes, "}",
    )


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
    var max_streams = getenv("STATIC_MAX_STREAMS")
    if max_streams:
        tp.initial_max_streams_bidi = UInt64(atol(max_streams))
    print("  max_streams_bidi: " + String(tp.initial_max_streams_bidi))

    var dial_str = getenv("STATIC_MAX_QUEUE_DELAY_US")
    var dial = UInt64(atol(dial_str)) if dial_str else DEFAULT_MAX_QUEUE_DELAY_US
    print("  max_queue_delay_us: " + String(dial))

    var server = H3UdpServer[StaticHandler](
        sock^, TlsBackend(copy=tls), config^, tp^, make_handler,
        protection=ProtectionConfig(max_queue_delay_us=dial),
    )
    var srv_ptr = _heap_alloc[H3UdpServer[StaticHandler]](1)
    srv_ptr.unsafe_write(server^)
    srv_ptr[].wire_context()

    var loop_ptr = _heap_alloc[WatchLoop](1)
    loop_ptr.unsafe_write(WatchLoop(capacity=256))
    srv_ptr[].start(loop_ptr[])

    if getenv("STATIC_OVERLOAD_STATS") != "1":
        while True:
            srv_ptr[].run_once(Int(TIMER_CEILING_MS))
    var next_print = monotonic_us() + 1_000_000
    while True:
        srv_ptr[].run_once(Int(TIMER_CEILING_MS))
        var now = monotonic_us()
        if now >= next_print:
            print(overload_line(srv_ptr[], now), flush=True)
            next_print = now + 1_000_000
