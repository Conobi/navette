"""Smoke test for H1TcpServer bootstrap (WatchLoop model).

Doesn't require an external HTTP/1.1 client: spins the proactor lifecycle
through start() + one non-blocking step + reap_closed(), and exits. Catches
regressions in:

  * H1TcpServer construction (field init order)
  * start() SQE sequence (initial accept submission on listener fd)
  * one step cycle (non-blocking — no client connects, accept stays pending)
  * reap_closed() (no-op on empty connection list, verifies no crash)

No TLS setup needed — H1TcpServer is plaintext-only.
"""

from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc

from bouclette import WatchLoop

from navette.h1.h1_tcp_server import H1TcpServer
from navette.h1.config import ParseConfig
from navette.http.handler import (
    StreamHandler,
    Request,
    RecvBody,
    ResponseWriter,
    Capabilities,
    StreamError,
)
from navette.runtime.socket_helpers import tcp_listener


# Stub handler — the smoke test never reaches a request, so all five
# StreamHandler methods are `pass`.
struct StubHandler(StreamHandler):
    """No-op handler for the bootstrap smoke test."""

    def __init__(out self):
        pass

    def __init__(out self, *, deinit move: Self):
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


def make_stub_handler() raises -> StubHandler:
    """Per-conn factory handed to H1TcpServer."""
    return StubHandler()


def test_h1_tcp_server_init_and_tick() raises:
    """Spin the server through the full proactor lifecycle.

    Exercises start (initial accept submission on the listener fd),
    one non-blocking step (no client connects, so the accept stays
    pending and step returns immediately), poll_accept (no-op since
    accept is not done), poll_connections (no-op since no connections
    exist), and reap_closed (no-op on empty connection list) — without
    requiring a real HTTP/1.1 client.
    """
    # -- 1. TCP listener on ephemeral port --
    var sock = tcp_listener(0)  # kernel picks a free port
    print("test_h1_tcp_server: bound fd =", Int(sock.raw()))

    # -- 2. Server construction (no TLS — plaintext H1) --
    var server = H1TcpServer[StubHandler](
        listen_handle=sock^,
        make_handler=make_stub_handler,
        parse_config=ParseConfig(),
    )

    # -- 3. Heap-allocate for pointer stability --
    var srv_ptr = _heap_alloc[H1TcpServer[StubHandler]](1)
    srv_ptr.init_pointee_move(server^)

    # -- 4. WatchLoop + start --
    var loop = WatchLoop(capacity=64)
    srv_ptr[].start(loop)

    # -- 5. One non-blocking step — no client, accept stays pending --
    _ = loop.step(timeout_ms=0)

    # -- 6. Poll accept + connections + reap closed — no-op on empty list --
    srv_ptr[].poll_accept()
    srv_ptr[].poll_connections()
    srv_ptr[].reap_closed()

    # -- 7. Teardown --
    srv_ptr.destroy_pointee()
    srv_ptr.free()

    print("PASS: test_h1_tcp_server_init_and_tick")


def main() raises:
    test_h1_tcp_server_init_and_tick()
