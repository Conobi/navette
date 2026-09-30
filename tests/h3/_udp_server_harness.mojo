"""Loopback harness for `H3UdpServer` tests.

Stands up a real server (heap-allocated, on its own `WatchLoop`) bound
to an ephemeral port, and hands out in-process clients: a `QuicConnection`
+ `H3Connection` pair whose datagrams travel over a non-blocking UDP
socket connected to the server. Protocol time is the server's `_now()`,
pinned through `_set_clock_for_tests`, so a test crosses a 30 s deadline
by calling `advance()` rather than sleeping; only tests that need an SQE
to reach the kernel call `step()`, always with a bound.

`pump()` is one round trip: client drains and sends, the server takes one
bounded `step()` and a `flush()`, then the client polls its socket for up
to `recv_ms` and feeds whatever arrived. A poll timeout is a normal
outcome — the server legitimately emits nothing in the delayed-ACK,
idle-reap and "second drain is empty" cases.
"""

from std.collections import InlineArray, Optional, Span
from std.ffi import external_call
from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc

from bouclette import WatchLoop, Socket, SocketAddrV6

from navette.h3.connection import H3Connection
from navette.h3.h3_handler_server import H3HandlerServer
from navette.h3.h3_udp_server import H3UdpServer
from navette.http.handler import StreamHandler
from navette.protect.config import ProtectionConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import TransportParams
from navette.runtime.socket_helpers import udp_listener
from navette.tls.config import QuicClientConfig, QuicServerConfig
from navette.tls.lib import TlsBackend

from tests._test_util import assert_true, load_test_ca, load_test_cert


comptime _POLLIN: Int16 = 1
comptime _RECV_BUF: Int = 2048
# Initial test clock. Non-zero so `Optional`-free "0 = unset" sentinels in
# the QUIC core cannot collide with a real timestamp.
comptime HARNESS_CLOCK_START_US: UInt64 = 1_000_000


def _poll_readable(fd: Int32, timeout_ms: Int) -> Bool:
    """`poll(2)` one descriptor for POLLIN; False on timeout or error."""
    # struct pollfd { int fd; short events; short revents; } — 8 bytes,
    # events in the low half of the second word (little-endian host).
    var pfd = InlineArray[Int32, 2](fill=Int32(0))
    pfd[0] = fd
    pfd[1] = Int32(_POLLIN)
    var rc = external_call["poll", Int32](
        Pointer(to=pfd).unsafe_bitcast[UInt8](), Int(1), Int32(timeout_ms),
    )
    return rc > 0


struct HarnessClient(Movable):
    """One in-process QUIC/H3 client behind its own connected loopback socket.

    `last_recv` keeps the raw datagrams of the most recent `client_recv`
    so tests can inspect the wire without decrypting.
    """
    var sock: Socket
    var h3: H3Connection
    var last_recv: List[List[Byte]]
    var recv_total: Int
    var recv_bytes: Int

    def __init__(out self, var sock: Socket, var h3: H3Connection):
        self.sock = sock^
        self.h3 = h3^
        self.last_recv = List[List[Byte]]()
        self.recv_total = 0
        self.recv_bytes = 0

    def __init__(out self, *, deinit move: Self):
        self.sock = move.sock^
        self.h3 = move.h3^
        self.last_recv = move.last_recv^
        self.recv_total = move.recv_total
        self.recv_bytes = move.recv_bytes

    def fd(self) raises -> Int32:
        """Raw descriptor of the loopback socket, for `poll(2)`."""
        return Int32(Int(self.sock.raw()))


struct UdpServerHarness[H: StreamHandler](Movable):
    """A live `H3UdpServer[H]` plus the loop and TLS material clients need.

    The server and loop live on the heap for pointer stability (the
    server stores a pointer to the loop, and the loop is moved during
    `step()` if left on the stack). Teardown destroys the server before
    the loop.
    """
    var srv: Pointer[H3UdpServer[Self.H, test_hooks=True], MutUntrackedOrigin]
    var loop: Pointer[WatchLoop, MutUntrackedOrigin]
    var tls: TlsBackend
    var cli_cfg: QuicClientConfig
    var client_params: TransportParams
    var port: UInt16

    def __init__(
        out self,
        make_handler: def () thin raises -> Self.H,
        var server_params: TransportParams,
        var client_params: TransportParams,
        loop_capacity: Int = 256,
        disable_gro: Bool = False,
        fail_first_start: Bool = False,
        protection: ProtectionConfig = ProtectionConfig(),
    ) raises:
        """Bind an ephemeral port, start the server and pin its clock.

        `disable_gro` pins the non-coalesced receive path (one datagram per
        buffer) whatever the kernel supports. `fail_first_start` leaves the
        server as a `start()` that raised after arming its receive stream
        leaves it; the test completes it with `start()`. `protection` goes
        to the server as is.
        """
        self.tls = TlsBackend("lib/librustls_mojo.so")
        var ck = load_test_cert()
        var cert_bytes = ck[0].copy()
        var key_bytes = ck[1].copy()
        var ca_bytes = load_test_ca()
        var srv_cfg = QuicServerConfig(
            self.tls.shared(), Span(cert_bytes), Span(key_bytes),
        )
        self.cli_cfg = QuicClientConfig.with_ca(
            self.tls.shared(), Span(ca_bytes),
        )
        self.client_params = client_params^

        var sock = udp_listener(0)
        var server = H3UdpServer[Self.H, test_hooks=True](
            sock^,
            TlsBackend(copy=self.tls),
            srv_cfg^,
            server_params^,
            make_handler,
            protection=protection,
        )
        self.srv = _heap_alloc[H3UdpServer[Self.H, test_hooks=True]](1)
        self.srv.unsafe_write(server^)
        self.srv[].wire_context()

        self.loop = _heap_alloc[WatchLoop](1)
        self.loop.unsafe_write(WatchLoop(capacity=loop_capacity))
        self.srv[]._set_clock_for_tests(HARNESS_CLOCK_START_US)
        self.srv[]._test_disable_gro = disable_gro
        self.port = self.srv[].udp_socket.local_addr_v6().port
        if fail_first_start:
            self.srv[]._test_fail_start_after_recv = True
            var failed = False
            try:
                self.srv[].start(self.loop[])
            except:
                failed = True
            self.srv[]._test_fail_start_after_recv = False
            assert_true(failed, "the injected start() failure surfaced")
        else:
            self.start()

    def start(mut self) raises:
        """`srv.start()`, then send every datagram whole.

        The GSO probe leaves a socket-level UDP_SEGMENT armed, which would
        have the kernel split any datagram over 1200 bytes on the way to
        the client. The loopback client is not segment-aware.
        """
        self.srv[].start(self.loop[])
        self.srv[].udp_socket.set_gso_segment_size(UInt16(0))
        self.srv[]._gso_max_segments = 1

    def __init__(out self, *, deinit move: Self):
        self.srv = move.srv
        self.loop = move.loop
        self.tls = move.tls^
        self.cli_cfg = move.cli_cfg^
        self.client_params = move.client_params^
        self.port = move.port

    def __deinit__(deinit self):
        _ = self.srv.unsafe_take_pointee()
        self.srv.unsafe_free()
        _ = self.loop.unsafe_take_pointee()
        self.loop.unsafe_free()

    # ── Clock ─────────────────────────────────────────────────────

    def now(self) -> UInt64:
        """The shared protocol clock (the server's `_now()`)."""
        return self.srv[]._now()

    def advance(mut self, us: UInt64):
        """Move the shared clock forward by `us` microseconds."""
        self.srv[]._set_clock_for_tests(self.now() + us)

    # ── Server side ───────────────────────────────────────────────

    def step(mut self, ms: Int = 20) raises -> Int:
        """One bounded loop step; returns the completion count."""
        return self.loop[].step(ms)

    def flush(mut self) raises:
        """`srv.flush()` followed by the cache-vs-oracle check every test inherits."""
        self.srv[].flush()
        assert_true(
            self.srv[]._deadline_cache_matches_oracle(),
            "deadline cache matches oracle after flush",
        )

    def slot_count(self) -> Int:
        return len(self.srv[].conn_slots)

    def server_conn(
        self, i: Int
    ) -> Pointer[H3HandlerServer[Self.H], MutUntrackedOrigin]:
        """The per-connection adapter behind slot `i` (no bounds check)."""
        return self.srv[].conn_slots[i].h3

    def server_addr(self, i: Int) -> List[Byte]:
        """Copy of slot `i`'s raw sockaddr blob."""
        return List[Byte](copy=self.srv[].conn_slots[i].addr)

    # ── Client side ───────────────────────────────────────────────

    def new_socket(self) raises -> Socket:
        """A fresh non-blocking UDP socket connected to the server port."""
        var addr = SocketAddrV6(
            UInt16(0), UInt16(0), UInt16(0), UInt16(0),
            UInt16(0), UInt16(0), UInt16(0), UInt16(1),
            port=self.port,
        )
        var sock = Socket.udp_connect(addr)
        sock.set_blocking(False)
        return sock^

    def new_client(self) raises -> HarnessClient:
        """A client connection on its own socket, clock-aligned with the server."""
        var quic = QuicConnection.client(
            self.tls.shared(),
            self.cli_cfg,
            "localhost",
            self.client_params.copy(),
            self.now(),
        )
        return HarnessClient(self.new_socket(), H3Connection.client(quic^))

    def client_send(mut self, mut client: HarnessClient) raises -> Int:
        """Drain the client's datagrams onto its socket; returns the count."""
        var dgs = client.h3.drain_datagrams(self.now())
        for i in range(len(dgs)):
            _ = client.sock.send(Span(dgs[i]))
        return len(dgs)

    def client_capture(mut self, mut client: HarnessClient) raises -> List[List[Byte]]:
        """Drain the client's datagrams without sending them, so a test can replay them from any socket."""
        return client.h3.drain_datagrams(self.now())

    def send_raw(self, ref sock: Socket, dg: List[Byte]) raises:
        """Write one prebuilt datagram on an arbitrary socket."""
        _ = sock.send(Span(dg))

    def recv_raw(self, ref sock: Socket, timeout_ms: Int) raises -> List[List[Byte]]:
        """Datagrams readable on `sock` within `timeout_ms` (empty on timeout)."""
        var out = List[List[Byte]]()
        var fd = Int32(Int(sock.raw()))
        if not _poll_readable(fd, timeout_ms):
            return out^
        var buf = List[Byte](capacity=_RECV_BUF)
        for _ in range(_RECV_BUF):
            buf.append(Byte(0))
        while True:
            var n: Int
            try:
                n = sock.recv(Span(buf))
            except:
                break  # EAGAIN: drained.
            if n <= 0:
                break
            var dg = List[Byte](capacity=n)
            for i in range(n):
                dg.append(buf[i])
            out.append(dg^)
        return out^

    def client_recv(
        mut self, mut client: HarnessClient, timeout_ms: Int = 50, feed: Bool = True,
    ) raises -> Int:
        """Receive everything pending on the client's socket, feeding it in.

        Returns the datagram count (0 on poll timeout). Raw copies land
        in `client.last_recv`.
        """
        client.last_recv = self.recv_raw(client.sock, timeout_ms)
        var n = len(client.last_recv)
        client.recv_total += n
        for i in range(n):
            client.recv_bytes += len(client.last_recv[i])
        if feed:
            for i in range(n):
                try:
                    client.h3.feed_datagram(Span(client.last_recv[i]), self.now())
                except:
                    pass
        return n

    def pump(
        mut self,
        mut client: HarnessClient,
        step_ms: Int = 20,
        recv_ms: Int = 50,
        advance_us: UInt64 = 1000,
    ) raises -> Int:
        """One client → server → client round trip; returns datagrams received."""
        _ = self.client_send(client)
        _ = self.step(step_ms)
        self.flush()
        self.advance(advance_us)
        return self.client_recv(client, recv_ms)

    def handshake(mut self, mut client: HarnessClient, rounds: Int = 20) raises -> Bool:
        """Pump until the client reports an established connection."""
        for _ in range(rounds):
            _ = self.pump(client)
            if client.h3.is_established():
                # One more round lets the client's Handshake ACK/finished
                # reach the server so its side is established too.
                _ = self.pump(client)
                return True
        return False


def raw_initial(dcid: List[Byte], total_len: Int, token: List[Byte] = List[Byte]()) -> List[Byte]:
    """A `total_len`-byte QUIC v1 long-header Initial carrying `dcid` and `token`, zero-filled.

    It does not decrypt, but the server creates a connection slot for
    any admitted Initial before touching its payload, so a slot
    appearing proves the datagram got through receive and demux intact.
    """
    var p = List[Byte](capacity=total_len)
    p.append(0xC3)  # long header, fixed bit, Initial, 4-byte packet number
    p.append(0x00)
    p.append(0x00)
    p.append(0x00)
    p.append(0x01)  # version 1
    p.append(UInt8(len(dcid)))
    for b in dcid:
        p.append(b)
    p.append(8)  # SCID length
    for i in range(8):
        p.append(UInt8(0xA0 + i))
    if len(token) < 64:
        p.append(UInt8(len(token)))
    else:
        p.append(UInt8(0x40 | (len(token) >> 8)))
        p.append(UInt8(len(token) & 0xFF))
    for b in token:
        p.append(b)
    var rest = total_len - len(p) - 2
    p.append(UInt8(0x40 | ((rest >> 8) & 0x3F)))  # 2-byte varint length
    p.append(UInt8(rest & 0xFF))
    while len(p) < total_len:
        p.append(0x00)
    return p^


def raw_long(version: UInt32, dcid: List[Byte], total_len: Int) -> List[Byte]:
    """A `total_len`-byte long-header packet of any `version` carrying `dcid` and an 8-byte SCID, zero-filled."""
    var p = List[Byte](capacity=total_len)
    p.append(0xC3)
    for i in range(4):
        p.append(UInt8((version >> UInt32(8 * (3 - i))) & 0xFF))
    p.append(UInt8(len(dcid)))
    for b in dcid:
        p.append(b)
    p.append(8)
    for i in range(8):
        p.append(UInt8(0xA0 + i))
    while len(p) < total_len:
        p.append(0x00)
    return p^
