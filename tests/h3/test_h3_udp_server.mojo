"""Server-level tests for `H3UdpServer`: timer policy, lifecycle, egress.

Every test but the pure-helper one runs a real server through the
loopback harness in `tests/h3/_udp_server_harness.mojo`, with protocol
time pinned by `_set_clock_for_tests`. Tests that only need the clock
gate call `flush()` without `step()`; tests that need an SQE to reach
the kernel call a bounded `step()`.

Cert + key come from `tests/fixtures/tls` via `load_test_cert()`.
"""

from std.memory import Pointer
from std.collections import Optional, Span
from std.memory.alloc import unsafe_alloc as _heap_alloc

from boucle import WatchLoop, TimerFuture

from navette.h3.h3_udp_server import (
    H3UdpServer,
    ConnSlot,
    EgressPacket,
    NO_DEADLINE_US,
    TIMER_FLOOR_MS,
    TIMER_CEILING_MS,
    SERVER_DEFAULT_IDLE_TIMEOUT_MS,
    _earliest_cached_deadline,
    _timer_arm_ms,
)
from navette.h3.h3_handler_server import H3HandlerServer
from navette.util.null_ptr import null_ptr
from navette.h3.connection import MAX_DATAGRAMS_PER_DRAIN
from navette.h3.qpack import QpackHeaderField
from navette.http.handler import (
    StreamHandler,
    Request,
    RecvBody,
    ResponseWriter,
    Capabilities,
    StreamError,
)
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.http.body import BodyFrame
from navette.quic.cc.cc_trait import AckedPacket
from navette.runtime.socket_helpers import udp_listener
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig

from interop.file_io import read_file
from tests._test_util import assert_true, assert_equal_int
from tests.h3._udp_server_harness import UdpServerHarness, HarnessClient


# ── Handlers ─────────────────────────────────────────────────────────────


struct StubHandler(StreamHandler):
    """No-op handler: never answers, so a request stays unanswered."""

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
    """Per-conn factory handed to H3UdpServer."""
    return StubHandler()


comptime BIG_BODY_BYTES: Int = 200_000


struct BigHandler(StreamHandler):
    """Answers every request with `BIG_BODY_BYTES` bytes of 'x'."""

    def __init__(out self):
        pass

    def __init__(out self, *, deinit move: Self):
        pass

    def on_request(
        mut self, var req: Request, mut body: RecvBody,
        mut resp: ResponseWriter, caps: Capabilities,
    ) raises:
        resp.send_status(StatusCode.ok(), Headers())
        var body_bytes = List[UInt8](capacity=BIG_BODY_BYTES)
        for _ in range(BIG_BODY_BYTES):
            body_bytes.append(UInt8(120))
        _ = resp.try_send_body(BodyFrame.data(body_bytes^))
        resp.end()

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


def make_big_handler() raises -> BigHandler:
    """Per-conn factory for the large-response tests."""
    return BigHandler()


struct OkHandler(StreamHandler):
    """Answers every request at once with a two-byte 200 body."""

    def __init__(out self):
        pass

    def __init__(out self, *, deinit move: Self):
        pass

    def on_request(
        mut self, var req: Request, mut body: RecvBody,
        mut resp: ResponseWriter, caps: Capabilities,
    ) raises:
        resp.send_status(StatusCode.ok(), Headers())
        var body_bytes = List[UInt8]()
        body_bytes.append(UInt8(111))
        body_bytes.append(UInt8(107))
        _ = resp.try_send_body(BodyFrame.data(body_bytes^))
        resp.end()

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


def make_ok_handler() raises -> OkHandler:
    """Per-conn factory for the small-response tests."""
    return OkHandler()


# ── Helpers ──────────────────────────────────────────────────────────────


def _params(idle_ms: UInt64 = 30_000) -> TransportParams:
    """Transport params with generous windows and the given idle timeout."""
    var p = default_transport_params()
    p.max_idle_timeout = idle_ms
    p.initial_max_data = UInt64(4_194_304)
    p.initial_max_stream_data_bidi_local = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_remote = UInt64(1_048_576)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


def _send_partial_request(mut client: HarnessClient) raises -> UInt64:
    """Queue an ack-eliciting 1-RTT packet that draws no response.

    Two bytes of a HEADERS frame without its end: the server buffers
    them and waits, so the only thing it owes back is an ACK.
    """
    var sid = client.h3.open_bidi_stream()
    var partial = List[UInt8]()
    partial.append(UInt8(0x01))  # HEADERS frame type
    partial.append(UInt8(0x20))  # declared length 32; payload withheld
    client.h3._quic.send_stream_data(sid, Span(partial), False)
    return sid


def _warm_ack_eliciting[H: StreamHandler](
    mut harness: UdpServerHarness[H], mut client: HarnessClient, slot: Int,
) raises:
    """One ack-eliciting 1-RTT packet, acknowledged before returning.

    RFC 9000 section 13.2.1 acknowledges an out-of-order packet at once, and the
    first ack-eliciting one after the handshake counts as such (nothing
    precedes it). After this, the client's next packet is contiguous with
    the last acknowledged one, so only the delayed-ACK timer applies.
    """
    _ = _send_partial_request(client)
    _ = harness.client_send(client)
    _ = harness.step(20)
    harness.flush()
    harness.advance(harness.srv[].transport_params.max_ack_delay * UInt64(1_000) + UInt64(1_000))
    harness.flush()
    _ = harness.step(20)
    assert_true(harness.client_recv(client, 50) >= 1, "warm-up ACK delivered")
    assert_true(
        not harness.server_conn(slot)[]._h3._quic.spaces[2].has_unacked_ack_eliciting(),
        "warm-up acknowledged",
    )


def _send_get(mut client: HarnessClient) raises -> UInt64:
    """Queue `GET /` with FIN on a fresh bidi stream."""
    var sid = client.h3.open_bidi_stream()
    var fields = List[QpackHeaderField]()
    fields.append(QpackHeaderField(":method", "GET"))
    fields.append(QpackHeaderField(":path", "/"))
    fields.append(QpackHeaderField(":scheme", "https"))
    fields.append(QpackHeaderField(":authority", "localhost"))
    client.h3.send_headers(sid, fields, True)
    return sid


def _open_cwnd[H: StreamHandler](
    mut harness: UdpServerHarness[H], slot: Int, bytes: Int,
) raises:
    """Grow slot `slot`'s cwnd by `bytes` with synthetic ACKs and unpace it."""
    var conn = harness.server_conn(slot)
    var acked = 0
    var i = 0
    while acked < bytes:
        var pkt = AckedPacket(
            pkt_num=UInt64(100_000 + i),
            size=UInt64(1200),
            time_sent=UInt64(i * 1000),
            time_acked=UInt64(i * 1000 + 500),
            rtt_sample=UInt64(500),
        )
        conn[]._h3._quic.recovery.cc.on_packet_acked(
            pkt, UInt64(500), UInt64(i * 1000 + 500)
        )
        acked += 1200
        i += 1
    conn[]._h3._quic.recovery.pacer.enabled = False


def _server_pto_us[H: StreamHandler](harness: UdpServerHarness[H], slot: Int) -> UInt64:
    """Slot `slot`'s current PTO in µs, as the QUIC core computes it."""
    var conn = harness.server_conn(slot)
    var mad = conn[]._h3._quic.local_params.max_ack_delay * UInt64(1000)
    return conn[]._h3._quic.recovery.pto_timeout(mad)


def _addrs_eq(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def _alloc_clients[H: StreamHandler](
    mut harness: UdpServerHarness[H], n: Int,
) raises -> List[Pointer[HarnessClient, MutUntrackedOrigin]]:
    """`n` handshaken, settled clients on the heap (`HarnessClient` is not Copyable)."""
    var out = List[Pointer[HarnessClient, MutUntrackedOrigin]]()
    for i in range(n):
        var p = _heap_alloc[HarnessClient](1)
        p.unsafe_write(harness.new_client())
        assert_true(harness.handshake(p[]), "handshake client " + String(i))
        for _ in range(3):
            _ = harness.pump(p[])
        out.append(p)
    assert_equal_int(harness.slot_count(), n, "one slot per client")
    return out^


def _free_clients(mut clients: List[Pointer[HarnessClient, MutUntrackedOrigin]]):
    """Destroy and free every client allocated by `_alloc_clients`."""
    for i in range(len(clients)):
        _ = clients[i].unsafe_take_pointee()
        clients[i].unsafe_free()
    clients.clear()


def _settle[H: StreamHandler](mut harness: UdpServerHarness[H], max_flushes: Int = 16) raises:
    """Flush with a frozen clock until one flush issues no deadline refresh."""
    for _ in range(max_flushes):
        var before = harness.srv[]._deadline_refresh_count
        harness.flush()
        if harness.srv[]._deadline_refresh_count == before:
            return
    raise "settle: refresh count still moving after " + String(max_flushes) + " flushes"


def _expected_arm_ms[H: StreamHandler](harness: UdpServerHarness[H]) -> UInt64:
    """Timer target recomputed from every live connection, independent of any cache."""
    var now = harness.now()
    var earliest = Optional[UInt64](None)
    for i in range(harness.slot_count()):
        var conn = harness.server_conn(i)
        var d: Optional[UInt64]
        if conn[].has_pending_egress():
            d = Optional[UInt64](now)
        else:
            d = conn[].timeout(now)
        if d is None:
            continue
        if earliest is None or d.value() < earliest.value():
            earliest = d
    return _timer_arm_ms(earliest, now)


# ── Tests ────────────────────────────────────────────────────────────────


def test_h3_udp_server_init_and_tick() raises:
    """Spin the server through the full proactor lifecycle without a client.

    wire_context + start (UdpSocketState probe, BufferPool +
    DatagramStream, timer armed to the ceiling), one bounded step, and
    one flush (no ingress, no deadline: the timer is left alone).
    """
    var cert = read_file(String("certs/server.crt"))
    var key = read_file(String("certs/server.key"))
    var tls = TlsBackend()
    var config = QuicServerConfig(tls.shared(), Span(cert), Span(key))

    var sock = udp_listener(0)  # kernel picks a free port
    var tp = default_transport_params()
    var server = H3UdpServer[StubHandler](
        sock^, tls^, config^, tp^, make_stub_handler,
    )

    var srv_ptr = _heap_alloc[H3UdpServer[StubHandler]](1)
    srv_ptr.unsafe_write(server^)
    srv_ptr[].wire_context()

    var loop_ptr = _heap_alloc[WatchLoop](1)
    loop_ptr.unsafe_write(WatchLoop(capacity=64))
    srv_ptr[].start(loop_ptr[])
    assert_equal_int(srv_ptr[]._timeout_count, 1, "start() arms exactly one timer")
    assert_true(
        srv_ptr[]._last_armed_ms == TIMER_CEILING_MS,
        "no connections: timer armed to the ceiling",
    )

    _ = loop_ptr[].step(20)
    srv_ptr[].flush()
    assert_equal_int(srv_ptr[]._timeout_count, 1, "live timer with unchanged target is not re-armed")
    assert_equal_int(srv_ptr[]._reset_count, 0, "no reset without an earlier deadline")

    _ = srv_ptr.unsafe_take_pointee()
    srv_ptr.unsafe_free()
    _ = loop_ptr.unsafe_take_pointee()
    loop_ptr.unsafe_free()
    print("PASS: test_h3_udp_server_init_and_tick")


def test_timer_arm_is_min() raises:
    """timer-arm-is-min: `_timer_arm_ms` == clamp(ceil((d-now)/1000), 1, 1000)."""
    var now = UInt64(5_000_000)
    assert_true(_timer_arm_ms(Optional[UInt64](None), now) == TIMER_CEILING_MS, "None -> ceiling")
    assert_true(_timer_arm_ms(Optional[UInt64](now - 1), now) == TIMER_FLOOR_MS, "past -> floor")
    assert_true(_timer_arm_ms(Optional[UInt64](now), now) == TIMER_FLOOR_MS, "now -> floor")
    assert_true(_timer_arm_ms(Optional[UInt64](now + 1), now) == UInt64(1), "1 us -> 1 ms (ceil)")
    assert_true(_timer_arm_ms(Optional[UInt64](now + 1000), now) == UInt64(1), "1000 us -> 1 ms")
    assert_true(_timer_arm_ms(Optional[UInt64](now + 1001), now) == UInt64(2), "1001 us -> 2 ms (ceil)")
    assert_true(_timer_arm_ms(Optional[UInt64](now + 999_999), now) == UInt64(1000), "just under ceiling")
    assert_true(_timer_arm_ms(Optional[UInt64](now + 1_000_000), now) == UInt64(1000), "exactly ceiling")
    assert_true(_timer_arm_ms(Optional[UInt64](now + 30_000_000), now) == TIMER_CEILING_MS, "30 s -> ceiling")

    # Random deltas against the reference formula.
    var seed = UInt64(0x9E3779B97F4A7C15)
    for _ in range(2000):
        seed = seed * UInt64(6364136223846793005) + UInt64(1442695040888963407)
        var delta = (seed >> 20) % UInt64(3_000_000)
        var d = now + delta
        var expect = (delta + UInt64(999)) // UInt64(1000)
        if expect < TIMER_FLOOR_MS:
            expect = TIMER_FLOOR_MS
        if expect > TIMER_CEILING_MS:
            expect = TIMER_CEILING_MS
        assert_true(
            _timer_arm_ms(Optional[UInt64](d), now) == expect,
            "random delta " + String(delta) + " expected " + String(expect),
        )
    print("PASS: test_timer_arm_is_min")


def test_idle_timeout_nonzero_on_server_runtimes() raises:
    """idle-timeout-nonzero-on-server-runtimes: 0 becomes 30 000 on the first connection."""
    var h = UdpServerHarness[StubHandler](
        make_stub_handler, default_transport_params(), _params(),
    )
    var c = h.new_client()
    _ = h.pump(c)  # one Initial reaches the server
    assert_equal_int(h.slot_count(), 1, "Initial creates one slot")
    assert_true(
        h.server_conn(0)[]._h3._quic.local_params.max_idle_timeout
        == SERVER_DEFAULT_IDLE_TIMEOUT_MS,
        "advertised max_idle_timeout must be the server default (30 000 ms)",
    )
    print("PASS: test_idle_timeout_nonzero_on_server_runtimes")


def test_idle_reaps_abandoned_handshake() raises:
    """idle-reaps-abandoned-handshake: one Initial, then silence, reaped after idle."""
    var h = UdpServerHarness[StubHandler](
        make_stub_handler, default_transport_params(), _params(),
    )
    var c = h.new_client()
    _ = h.pump(c)
    assert_equal_int(h.slot_count(), 1, "Initial creates one slot")

    # Just short of the idle deadline: still there.
    h.advance(SERVER_DEFAULT_IDLE_TIMEOUT_MS * UInt64(1000) - UInt64(5000))
    h.flush()
    assert_equal_int(h.slot_count(), 1, "slot survives before the idle deadline")

    # Past it: the clock gate runs the pass, expiry closes, the pass reaps.
    h.advance(UInt64(10_000))
    h.flush()
    assert_equal_int(h.slot_count(), 0, "slot reaped once idle expired")
    print("PASS: test_idle_reaps_abandoned_handshake")


def test_closed_reaped_on_expiry() raises:
    """closed-reaped-on-expiry: peer CLOSE -> slot gone within 3 PTO + 2 ms, no ingress."""
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params())
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    assert_equal_int(h.slot_count(), 1, "one established slot")

    var pto = _server_pto_us(h, 0)
    c.h3._quic.close_app(UInt64(0x100), String("done"), h.now())
    _ = h.pump(c)  # CLOSE reaches the server: draining now
    assert_true(
        h.server_conn(0)[].is_closing_or_draining(),
        "server enters draining on the peer's CLOSE",
    )

    h.advance(UInt64(3) * pto + UInt64(2000))
    h.flush()
    assert_equal_int(h.slot_count(), 0, "slot reaped on the pass that observed the drain expiry")
    print("PASS: test_closed_reaped_on_expiry")


def test_timer_rearm_only_on_change() raises:
    """timer-rearm-only-on-change: reset only for an earlier target; re-arm after a fire."""
    # (a) A new earlier deadline: exactly one reset, zero timeout calls.
    #     The server arms the ceiling at start(); a 100 ms server idle
    #     makes the first connection's deadline earlier by far more
    #     than 1 ms, inside one flush.
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(100), _params())
    var c = h.new_client()
    assert_equal_int(h.srv[]._timeout_count, 1, "start() armed once")
    _ = h.client_send(c)
    _ = h.step(20)
    var resets = h.srv[]._reset_count
    var timeouts = h.srv[]._timeout_count
    h.flush()
    assert_equal_int(h.slot_count(), 1, "Initial created the slot")
    assert_equal_int(h.srv[]._reset_count, resets + 1, "earlier deadline -> exactly one reset")
    assert_equal_int(h.srv[]._timeout_count, timeouts, "earlier deadline -> no timeout() call")
    assert_true(h.srv[]._last_armed_ms <= UInt64(100), "armed to the 100 ms idle deadline")

    # (b) Fired with an unchanged minimum: the done future is replaced by
    #     a fresh timeout(); no reset. The clock is frozen, so nothing
    #     expires and the minimum does not move.
    resets = h.srv[]._reset_count
    timeouts = h.srv[]._timeout_count
    var waited = 0
    while waited < 1000 and not h.srv[]._timer.value().done():
        _ = h.step(50)
        waited += 50
    assert_true(h.srv[]._timer.value().done(), "the 100 ms timer fired")
    h.flush()
    assert_equal_int(h.slot_count(), 1, "frozen clock: nothing expired")
    assert_equal_int(h.srv[]._timeout_count, timeouts + 1, "fire -> exactly one timeout()")
    assert_equal_int(h.srv[]._reset_count, resets, "fire -> no reset")

    # (c) A deadline far out across three flushes: zero reset, zero timeout.
    var h2 = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params())
    var c2 = h2.new_client()
    _ = h2.pump(c2)
    resets = h2.srv[]._reset_count
    timeouts = h2.srv[]._timeout_count
    for _ in range(3):
        h2.flush()
    assert_equal_int(h2.srv[]._reset_count, resets, "30 s deadline: no reset across three flushes")
    assert_equal_int(h2.srv[]._timeout_count, timeouts, "30 s deadline: no timeout() across three flushes")
    print("PASS: test_timer_rearm_only_on_change")


def test_timer_reserved_before_egress() raises:
    """Timer SQE is reserved before egress can exhaust the submission queue.

    With no live timer and a backlog several times the loop capacity,
    the flush must still issue its `timeout()` (counted) — i.e. arming
    happens before `_submit_egress`.
    """
    var h = UdpServerHarness[StubHandler](
        make_stub_handler, _params(), _params(), loop_capacity=64,
    )
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    var addr = h.server_addr(0)

    # Drop the live timer so the re-arm must call timeout() this flush.
    h.srv[]._timer = Optional[TimerFuture](None)
    var timeouts = h.srv[]._timeout_count
    for i in range(600):
        var payload = List[UInt8](capacity=64)
        for j in range(64):
            payload.append(UInt8((i + j) & 0xFF))
        h.srv[]._egress_backlog.append(
            EgressPacket(payload^, List[UInt8](copy=addr), 0, UInt8(0))
        )
    h.flush()
    assert_equal_int(h.srv[]._timeout_count, timeouts + 1, "timeout() issued before egress submission")
    assert_true(h.srv[]._timer is not None, "a timer is live after the flush")
    print(
        "  (egress packets left in the backlog after the flush: "
        + String(len(h.srv[]._egress_backlog)) + ")"
    )
    # Let the kernel drain what was submitted.
    for _ in range(5):
        _ = h.step(10)
        h.flush()
    print("PASS: test_timer_reserved_before_egress")


def test_flush_order_timer_before_egress() raises:
    """flush-order-timer-before-egress: a timer-owed ACK leaves in the same flush.

    After a warm-up packet (so the one under test is in-order and only
    the delayed-ACK timer applies), the client sends one ack-eliciting
    1-RTT packet that draws no response; with the clock advanced past
    the server's delayed-ACK deadline and no ingress, one flush() + one
    step() delivers the ACK.
    """
    var sp = _params()
    sp.max_ack_delay = UInt64(5)
    var h = UdpServerHarness[StubHandler](make_stub_handler, sp^, _params())
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    # Settle: nothing left owed in either direction.
    for _ in range(3):
        _ = h.pump(c)
    assert_equal_int(h.slot_count(), 1, "one slot")
    _warm_ack_eliciting(h, c, 0)

    _ = _send_partial_request(c)
    _ = h.client_send(c)
    _ = h.step(20)
    h.flush()
    # Nothing must have left yet: a lone packet is delayed, not ACKed at once.
    _ = h.step(5)
    var early = h.client_recv(c, 10, feed=False)
    assert_equal_int(early, 0, "no immediate ACK for a lone ack-eliciting packet")

    h.advance(UInt64(5_000) + UInt64(1_000))
    h.flush()
    _ = h.step(20)
    var got = h.client_recv(c, 50, feed=False)
    assert_true(got >= 1, "ACK datagram delivered by the flush that observed the deadline")
    print("PASS: test_flush_order_timer_before_egress")


def test_timer_pass_runs_when_deadline_passed() raises:
    """timer-pass-runs-when-deadline-passed: an ACK deadline is honoured under load.

    Slot A (warmed up so its packet is in-order and timer-owed, not
    ACKed at once) holds a 5 ms ACK deadline; slot B receives a datagram
    every 100 µs of test-clock time for 20 ms. The ACK to A must leave
    within 1 ms of its deadline even though the kernel timer never gets
    a chance to fire between wakes.
    """
    var sp = _params()
    sp.max_ack_delay = UInt64(5)
    var h = UdpServerHarness[StubHandler](make_stub_handler, sp^, _params())
    var a = h.new_client()
    var b = h.new_client()
    assert_true(h.handshake(a), "handshake A")
    assert_true(h.handshake(b), "handshake B")
    for _ in range(3):
        _ = h.pump(a)
        _ = h.pump(b)
    assert_equal_int(h.slot_count(), 2, "two slots")
    _warm_ack_eliciting(h, a, 0)

    # B streams one byte at a time on a uni stream of a reserved type
    # (0x21): the server ignores it, so every datagram is ack-eliciting
    # ingress for slot B and nothing else happens.
    var b_sid = b.h3._quic.open_stream(False)
    var chunk = List[UInt8]()
    chunk.append(UInt8(0x21))

    _ = _send_partial_request(a)
    _ = h.client_send(a)
    _ = h.step(20)
    h.flush()
    var t0 = h.now()
    var deadline = t0 + UInt64(5_000)

    var ack_at = Optional[UInt64](None)
    for _ in range(200):
        h.advance(UInt64(100))
        b.h3._quic.send_stream_data(b_sid, Span(chunk), False)
        _ = h.client_send(b)
        _ = h.step(5)
        h.flush()
        _ = h.client_recv(b, 0)
        if ack_at is None and h.client_recv(a, 0, feed=False) > 0:
            ack_at = Optional[UInt64](h.now())
    assert_true(ack_at is not None, "A never received its ACK during 20 ms of load")
    assert_true(
        ack_at.value() <= deadline + UInt64(1_000),
        "ACK left at +" + String(ack_at.value() - t0) + " us, deadline +5000 us (+1 ms slack)",
    )
    print("PASS: test_timer_pass_runs_when_deadline_passed")


def test_drain_cap_schedules_continuation() raises:
    """drain-cap-schedules-continuation: a capped response finishes without ingress.

    One flush drains at most 2 × MAX_DATAGRAMS_PER_DRAIN for the slot
    (ingress drain, then the same flush's timer pass); after each capped
    flush the minimum deadline is `now` and the timer is armed to the
    floor, so successive flushes with no ingress complete the response.
    """
    var h = UdpServerHarness[BigHandler](make_big_handler, _params(), _params())
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    for _ in range(3):
        _ = h.pump(c)
    _open_cwnd(h, 0, 2 * BIG_BODY_BYTES)

    _ = _send_get(c)
    _ = h.client_send(c)
    _ = h.step(20)
    h.flush()
    var received = 0
    var capped_flushes = 0
    var conn = h.server_conn(0)
    if conn[].has_pending_egress():
        capped_flushes += 1
        assert_true(
            h.srv[]._next_deadline_us(h.now()) is not None
            and h.srv[]._next_deadline_us(h.now()).value() == h.now(),
            "capped slot reports deadline == now",
        )
        assert_true(h.srv[]._last_armed_ms == TIMER_FLOOR_MS, "capped slot arms the floor")
    _ = h.step(10)
    received += h.client_recv(c, 20, feed=False)
    var first_flush_dgs = received
    assert_true(
        first_flush_dgs <= 2 * MAX_DATAGRAMS_PER_DRAIN,
        "one flush emits at most two capped drains: " + String(first_flush_dgs),
    )

    # Continue with flushes only (no ingress): the pass gate fires on the
    # `now` deadline until the drain runs dry.
    var flushes = 0
    while conn[].has_pending_egress() and flushes < 64:
        capped_flushes += 1
        h.flush()
        flushes += 1
        _ = h.step(10)
        received += h.client_recv(c, 20, feed=False)
    assert_true(not conn[].has_pending_egress(), "response fully emitted")
    assert_true(capped_flushes >= 1, "the 200 kB response must hit the cap at least once")
    # The loopback socket's receive buffer (net.core.rmem_max, ~212 kB by
    # default) cannot hold two capped drains at once, so wire delivery
    # is checked for at least one full capped drain and completeness is
    # checked on the sender: everything the drain emitted is in flight.
    assert_true(
        received >= MAX_DATAGRAMS_PER_DRAIN,
        "client received only " + String(received) + " datagrams",
    )
    assert_true(
        Int(conn[]._h3._quic.recovery.bytes_in_flight) >= BIG_BODY_BYTES,
        "server emitted " + String(conn[]._h3._quic.recovery.bytes_in_flight)
        + " bytes; too few for the body (cwnd="
        + String(conn[]._h3._quic.recovery.cc.cwnd()) + ")",
    )
    print("PASS: test_drain_cap_schedules_continuation")


def test_closing_conn_addr_frozen() raises:
    """closing-conn-addr-frozen: a spoofed source cannot redirect the reflected CLOSE.

    Case 1: the connection is already CLOSING; a valid datagram from a
    new source yields a CLOSE to the old address only. Case 2: the
    datagram that itself triggers the close (migration disabled, new
    source) leaves the address untouched and the CLOSE goes to the old
    address.
    """
    # ── Case 1: datagram from a new source while CLOSING ──
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params())
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    for _ in range(3):
        _ = h.pump(c)
    var old_addr = h.server_addr(0)

    # A valid client datagram, held back for later replay from elsewhere.
    _ = _send_partial_request(c)
    var held = c.h3.drain_datagrams(h.now())
    assert_true(len(held) >= 1, "client produced a datagram to replay")

    # Provoke a server-side close through ingress (SETTINGS on a request
    # stream is H3_FRAME_UNEXPECTED); the CLOSE goes to the old address.
    var bad_sid = c.h3.open_bidi_stream()
    var settings_on_request = List[UInt8]()
    settings_on_request.append(UInt8(0x04))
    settings_on_request.append(UInt8(0x00))
    c.h3._quic.send_stream_data(bad_sid, Span(settings_on_request), False)
    _ = h.client_send(c)
    _ = h.step(20)
    h.flush()
    _ = h.step(20)
    assert_true(h.server_conn(0)[].is_closing_or_draining(), "server is closing")
    assert_true(h.client_recv(c, 50, feed=False) >= 1, "CLOSE delivered to the old address")

    # Replay from a second socket after a PTO (so a reflected CLOSE is owed).
    var pto = _server_pto_us(h, 0)
    h.advance(pto + UInt64(1000))
    var spoof = h.new_socket()
    h.send_raw(spoof, held[0])
    _ = h.step(20)
    h.flush()
    _ = h.step(20)
    assert_true(_addrs_eq(h.server_addr(0), old_addr), "address frozen while closing")
    var to_spoof = h.recv_raw(spoof, 30)
    assert_equal_int(len(to_spoof), 0, "nothing goes to the spoofed source")
    var to_old = h.client_recv(c, 30, feed=False)
    assert_true(to_old >= 1, "the reflected CLOSE goes to the old address")

    # ── Case 2: the transition datagram itself (migration disabled) ──
    var sp = _params()
    sp.disable_active_migration = True
    var h2 = UdpServerHarness[StubHandler](make_stub_handler, sp^, _params())
    var c2 = h2.new_client()
    assert_true(h2.handshake(c2), "handshake 2")
    for _ in range(3):
        _ = h2.pump(c2)
    var old_addr2 = h2.server_addr(0)
    assert_true(not h2.server_conn(0)[].is_closing_or_draining(), "open before the spoof")

    _ = _send_partial_request(c2)
    var held2 = c2.h3.drain_datagrams(h2.now())
    var spoof2 = h2.new_socket()
    h2.send_raw(spoof2, held2[0])
    _ = h2.step(20)
    h2.flush()
    _ = h2.step(20)
    assert_true(
        h2.server_conn(0)[].is_closing_or_draining(),
        "a new source with migration disabled closes the connection",
    )
    assert_true(_addrs_eq(h2.server_addr(0), old_addr2), "transition datagram did not move the address")
    assert_equal_int(len(h2.recv_raw(spoof2, 30)), 0, "nothing goes to the new source")
    assert_true(h2.client_recv(c2, 30, feed=False) >= 1, "CLOSE goes to the old address")
    print("PASS: test_closing_conn_addr_frozen")


def test_freed_minimum_slot_rearms_to_next() raises:
    """freed-minimum-slot-rearms-to-next: reaping the earliest slot re-aims at the survivors' min."""
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params())
    var clients = _alloc_clients(h, 3)
    _settle(h)

    var pto = _server_pto_us(h, 0)
    clients[0][].h3._quic.close_app(UInt64(0x100), String("done"), h.now())
    _ = h.pump(clients[0][])
    assert_true(h.server_conn(0)[].is_closing_or_draining(), "slot 0 drains on the peer CLOSE")
    assert_equal_int(h.slot_count(), 3, "draining slot still present")

    h.advance(UInt64(3) * pto + UInt64(2_000))
    h.flush()
    assert_equal_int(h.slot_count(), 2, "the minimum's slot was reaped")

    # A fresh arm makes the new target observable (a live timer whose
    # target already passed is left alone by policy).
    h.srv[]._timer = Optional[TimerFuture](None)
    var timeouts = h.srv[]._timeout_count
    h.flush()
    assert_equal_int(h.srv[]._timeout_count, timeouts + 1, "re-arm issued a fresh timeout()")
    assert_true(
        h.srv[]._last_armed_ms == _expected_arm_ms(h),
        "timer targets the surviving minimum: armed " + String(h.srv[]._last_armed_ms)
        + " expected " + String(_expected_arm_ms(h)),
    )
    # Keep the harness alive past the server derefs above (ASAP destruction).
    _ = h.slot_count()
    _free_clients(clients)
    print("PASS: test_freed_minimum_slot_rearms_to_next")


def test_capped_egress_slot_not_starved() raises:
    """capped-egress-slot-not-starved: a capped slot arms the floor next to a 30 s slot and completes."""
    var h = UdpServerHarness[BigHandler](make_big_handler, _params(), _params())
    var a = h.new_client()
    var b = h.new_client()
    assert_true(h.handshake(a), "handshake A")
    assert_true(h.handshake(b), "handshake B")
    for _ in range(3):
        _ = h.pump(a)
        _ = h.pump(b)
    assert_equal_int(h.slot_count(), 2, "two slots")
    var b_addr = h.server_addr(1)
    _open_cwnd(h, 0, 2 * BIG_BODY_BYTES)

    _ = _send_get(a)
    _ = h.client_send(a)
    _ = h.step(20)
    h.flush()
    var conn = h.server_conn(0)
    var capped_flushes = 0
    if conn[].has_pending_egress():
        capped_flushes += 1
        assert_true(h.srv[]._last_armed_ms == TIMER_FLOOR_MS, "capped slot arms the floor despite B's 30 s deadline")
    _ = h.step(10)
    var received = h.client_recv(a, 20, feed=False)

    var flushes = 0
    while conn[].has_pending_egress() and flushes < 64:
        capped_flushes += 1
        h.flush()
        # The flush that drains the last datagram may re-arm past the
        # floor; only a still-capped slot must keep the floor.
        if conn[].has_pending_egress():
            assert_true(h.srv[]._last_armed_ms == TIMER_FLOOR_MS, "still capped: floor")
        flushes += 1
        _ = h.step(10)
        received += h.client_recv(a, 20, feed=False)
    assert_true(not conn[].has_pending_egress(), "response fully emitted by flush-only progress")
    assert_true(capped_flushes >= 1, "the 200 kB response must hit the cap at least once")
    assert_true(received >= MAX_DATAGRAMS_PER_DRAIN, "client received only " + String(received))
    assert_equal_int(h.slot_count(), 2, "B untouched")
    assert_true(_addrs_eq(h.server_addr(1), b_addr), "slot 1 is still B")
    var b_conn = h.server_conn(1)
    var b_closing = b_conn[].is_closing_or_draining()
    assert_true(
        not b_closing,
        "B still open: state=" + String(b_conn[]._h3._quic.state)
        + " h3=" + String(b_conn[]._h3.is_closing_or_draining())
        + " closing=" + String(b_conn[]._h3._quic.is_closing())
        + " draining=" + String(b_conn[]._h3._quic.is_draining())
        + " closed=" + String(b_conn[]._h3._quic.is_closed()),
    )
    # Keep the harness alive past the slot derefs above (ASAP destruction
    # would otherwise free the server between `server_conn()` and `[]`).
    _ = h.slot_count()
    print("PASS: test_capped_egress_slot_not_starved")


def test_closed_in_feed_reaped_before_rearm() raises:
    """closed-in-feed-reaped-before-rearm: a datagram whose drain expires the drain timer frees the slot in that flush."""
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params())
    var a = h.new_client()
    var b = h.new_client()
    assert_true(h.handshake(a), "handshake A")
    assert_true(h.handshake(b), "handshake B")
    for _ in range(3):
        _ = h.pump(a)
        _ = h.pump(b)
    assert_equal_int(h.slot_count(), 2, "two slots")
    var b_addr = h.server_addr(1)

    # A valid datagram from A, held back for replay after A is draining.
    _ = _send_partial_request(a)
    var held = a.h3.drain_datagrams(h.now())
    assert_true(len(held) >= 1, "client A produced a datagram to replay")

    var pto = _server_pto_us(h, 0)
    a.h3._quic.close_app(UInt64(0x100), String("done"), h.now())
    _ = h.pump(a)
    assert_true(h.server_conn(0)[].is_closing_or_draining(), "A drains on the peer CLOSE")

    # Past the drain timer without a flush, then the replay: the drain
    # inside the feed path observes the expiry and the slot is reaped
    # before the timer is re-armed.
    h.advance(UInt64(3) * pto + UInt64(2_000))
    h.send_raw(a.sock, held[0])
    _ = h.step(20)
    h.flush()
    assert_equal_int(h.slot_count(), 1, "A reaped in the flush that fed the datagram")
    assert_true(_addrs_eq(h.server_addr(0), b_addr), "B moved into slot 0")

    h.srv[]._timer = Optional[TimerFuture](None)
    var timeouts = h.srv[]._timeout_count
    h.flush()
    assert_equal_int(h.srv[]._timeout_count, timeouts + 1, "fresh arm")
    assert_true(
        h.srv[]._last_armed_ms == _expected_arm_ms(h),
        "timer targets the remaining slot: armed " + String(h.srv[]._last_armed_ms)
        + " expected " + String(_expected_arm_ms(h)),
    )
    # Keep the harness alive past the server derefs above (ASAP destruction).
    _ = h.slot_count()
    print("PASS: test_closed_in_feed_reaped_before_rearm")


def test_forward_clock_jump() raises:
    """forward-clock-jump: +10 s drains every armed slot once, none twice, and re-arms to the new min."""
    var h = UdpServerHarness[OkHandler](make_ok_handler, _params(), _params())
    var clients = _alloc_clients(h, 3)
    _settle(h)

    # One unacknowledged response per slot: every slot holds a PTO.
    # One request per client, delivered one at a time so a bounded step
    # cannot leave a GET behind in the socket.
    for i in range(3):
        _ = _send_get(clients[i][])
        _ = h.client_send(clients[i][])
        _ = h.step(20)
        h.flush()
    for i in range(3):
        assert_true(
            h.server_conn(i)[]._h3._quic.spaces[2].ae_in_flight > 0,
            "slot " + String(i) + " holds an unacked response",
        )
        assert_equal_int(h.server_conn(i)[]._h3._quic.recovery.pto_count, 0, "no PTO fired yet")

    h.advance(UInt64(10_000_000))
    h.srv[]._timer = Optional[TimerFuture](None)
    var timeouts = h.srv[]._timeout_count
    h.flush()
    assert_equal_int(h.slot_count(), 3, "no slot closed by a 10 s jump under a 30 s idle")
    for i in range(3):
        assert_equal_int(
            h.server_conn(i)[]._h3._quic.recovery.pto_count, 1,
            "slot " + String(i) + " fired its PTO exactly once in the pass",
        )
    assert_equal_int(h.srv[]._timeout_count, timeouts + 1, "fresh arm after the pass")
    assert_true(
        h.srv[]._last_armed_ms == _expected_arm_ms(h),
        "re-armed to the new min: armed " + String(h.srv[]._last_armed_ms)
        + " expected " + String(_expected_arm_ms(h)),
    )
    # Let the probes leave the socket before teardown.
    _ = h.step(20)
    _free_clients(clients)
    print("PASS: test_forward_clock_jump")


def _slot_with(deadline: UInt64) -> ConnSlot[StubHandler]:
    """A `ConnSlot` around a null `h3` pointer carrying one cached deadline."""
    var s = ConnSlot[StubHandler](
        null_ptr[H3HandlerServer[StubHandler], MutUntrackedOrigin](),
        List[UInt8](),
        List[UInt64](),
        UInt64(0),
    )
    s.next_deadline_us = deadline
    return s^


def test_earliest_cached_deadline_pure() raises:
    """Scan == min over the multiset with the sentinel filtered; empty / all-sentinel -> None."""
    var slots = List[ConnSlot[StubHandler]]()
    assert_true(_earliest_cached_deadline(slots) is None, "empty -> None")
    slots.append(_slot_with(NO_DEADLINE_US))
    slots.append(_slot_with(NO_DEADLINE_US))
    assert_true(_earliest_cached_deadline(slots) is None, "all sentinel -> None")
    slots.append(_slot_with(UInt64(7_000)))
    slots.append(_slot_with(UInt64(5_000)))
    slots.append(_slot_with(UInt64(9_000)))
    var d = _earliest_cached_deadline(slots)
    assert_true(d is not None and d.value() == UInt64(5_000), "mixed -> min 5000")
    slots.append(_slot_with(UInt64(5_000)))
    d = _earliest_cached_deadline(slots)
    assert_true(d is not None and d.value() == UInt64(5_000), "duplicate minimum -> 5000")

    # Property: random multisets with sentinels against the reference min.
    var seed = UInt64(0x9E3779B97F4A7C15)
    for _ in range(500):
        var rnd = List[ConnSlot[StubHandler]]()
        var ref_min = NO_DEADLINE_US
        seed = seed * UInt64(6364136223846793005) + UInt64(1442695040888963407)
        var n = Int((seed >> 40) % UInt64(8))
        for _ in range(n):
            seed = seed * UInt64(6364136223846793005) + UInt64(1442695040888963407)
            var v = (seed >> 24) % UInt64(1_000_000)
            if (seed >> 16) % UInt64(4) == UInt64(0):
                v = NO_DEADLINE_US
            rnd.append(_slot_with(v))
            if v < ref_min:
                ref_min = v
        var got = _earliest_cached_deadline(rnd)
        if ref_min == NO_DEADLINE_US:
            assert_true(got is None, "random: no real deadline -> None")
        else:
            assert_true(
                got is not None and got.value() == ref_min,
                "random: expected " + String(ref_min),
            )
    print("PASS: test_earliest_cached_deadline_pure")


def main() raises:
    test_h3_udp_server_init_and_tick()
    test_timer_arm_is_min()
    test_idle_timeout_nonzero_on_server_runtimes()
    test_idle_reaps_abandoned_handshake()
    test_closed_reaped_on_expiry()
    test_timer_rearm_only_on_change()
    test_timer_reserved_before_egress()
    test_drain_cap_schedules_continuation()
    test_closing_conn_addr_frozen()
    test_flush_order_timer_before_egress()
    test_timer_pass_runs_when_deadline_passed()

    # Cached-deadline tests: run every one, report every failure, then raise.
    var failed = List[String]()
    try:
        test_earliest_cached_deadline_pure()
    except e:
        failed.append(String("test_earliest_cached_deadline_pure: ") + String(e))
    try:
        test_freed_minimum_slot_rearms_to_next()
    except e:
        failed.append(String("test_freed_minimum_slot_rearms_to_next: ") + String(e))
    try:
        test_capped_egress_slot_not_starved()
    except e:
        failed.append(String("test_capped_egress_slot_not_starved: ") + String(e))
    try:
        test_closed_in_feed_reaped_before_rearm()
    except e:
        failed.append(String("test_closed_in_feed_reaped_before_rearm: ") + String(e))
    try:
        test_forward_clock_jump()
    except e:
        failed.append(String("test_forward_clock_jump: ") + String(e))
    if len(failed) > 0:
        for i in range(len(failed)):
            print("FAILED " + failed[i])
        raise "test_h3_udp_server: " + String(len(failed)) + " failure(s)"
