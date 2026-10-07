"""`H3UdpServer` wiring of the overload controls: the egress hold and its rotation, the governor's interval close, the
silent drop of new Initials. Loopback harness, pinned clock, no sleeps.
"""

from std.collections import Span

from navette.h3.h3_udp_server import EgressPacket
from navette.h3.ingress_guard import EGRESS_HOLD_AT
from navette.h3.qpack import FieldSection
from navette.http.body import BodyFrame
from navette.http.handler import StreamHandler, Request, RecvBody, ResponseWriter, Capabilities, StreamError
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.protect.config import ProtectionConfig
from navette.protect.governor import Mode, UNLIMITED
from navette.quic.path import PathKey
from navette.quic.trans_param import TransportParams, default_transport_params

from tests._test_util import assert_true
from tests.h3._udp_server_harness import UdpServerHarness, HarnessClient, raw_initial


struct OkHandler(StreamHandler):
    """Answers every request at once with a two-byte 200 body."""

    def __init__(out self):
        pass

    def on_request(mut self, var req: Request, mut body: RecvBody, mut resp: ResponseWriter, caps: Capabilities) raises:
        resp.send_status(StatusCode.ok(), Headers())
        var b: List[Byte] = [111, 107]
        _ = resp.try_send_body(BodyFrame.data(b^))
        resp.end()

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


def make_ok_handler() raises -> OkHandler:
    return OkHandler()


def _params() -> TransportParams:
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    p.initial_max_data = UInt64(4_194_304)
    p.initial_max_stream_data_bidi_local = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_remote = UInt64(1_048_576)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


def _send_get(mut client: HarnessClient, fin: Bool = True) raises -> UInt64:
    var sid = client.h3.open_bidi_stream()
    var fields = FieldSection(method="GET", scheme="https", authority="localhost", path="/")
    client.h3.send_headers(sid, fields, fin)
    return sid


def _fill_backlog(mut h: UdpServerHarness[OkHandler], n: Int, addr: PathKey):
    """Replace the egress backlog with `n` dummies (connection index -1) for `addr`."""
    h.srv[]._egress_backlog.clear()
    for _ in range(n):
        h.srv[]._egress_backlog.append(EgressPacket(List[Byte](length=40, fill=0), PathKey(copy=addr), -1, UInt8(0)))


def _served(h: UdpServerHarness[OkHandler], conn_idx: Int) -> Bool:
    for i in range(len(h.srv[]._egress_backlog)):
        if h.srv[]._egress_backlog[i].conn_idx == conn_idx:
            return True
    return False


def test_egress_hold_and_rotation() raises:
    """At `EGRESS_HOLD_AT` queued datagrams a drain is held, the slot stays due; the timer pass resumes at the held one."""
    var h = UdpServerHarness[OkHandler](make_ok_handler, _params(), _params())
    var c0 = h.new_client()
    assert_true(h.handshake(c0), "handshake 0")
    var c1 = h.new_client()
    assert_true(h.handshake(c1), "handshake 1")
    var junk = h.new_socket()  # dummies land here, never on a client
    var addr = h.server_addr(0)
    var port = junk.local_addr_v6().port
    addr.port = port
    _fill_backlog(h, EGRESS_HOLD_AT, addr)
    _ = _send_get(c0)
    _ = _send_get(c1)
    _ = h.client_send(c0)
    _ = h.client_send(c1)
    _ = h.step(20)
    _ = h.step(5)
    h.flush()
    assert_true(not _served(h, 0) and not _served(h, 1), "both held: none of their packets queued")
    for i in range(2):
        ref slot = h.srv[].conn_slots[i]
        assert_true(slot.h3[].has_pending_egress() and slot.next_deadline_us == h.now(), "held slot stays due")
    _fill_backlog(h, EGRESS_HOLD_AT - 1, addr)
    h.flush()
    var first = 0 if _served(h, 0) else 1
    assert_true(_served(h, first) and not _served(h, 1 - first), "one served, the other held again")
    # A second later the served connection's loss timer is due too; serving it first would hold the other again.
    h.advance(1_000_000)
    _fill_backlog(h, EGRESS_HOLD_AT - 1, addr)
    h.flush()
    assert_true(_served(h, 1 - first), "the next pass starts at the held one")
    _ = junk^


def _close_with_wait(mut h: UdpServerHarness[OkHandler], wait_us: UInt64) raises:
    """Run one flush that closes a governor interval whose requests all waited `wait_us` (0: a clear interval)."""
    for _ in range(25 if wait_us else 0):
        h.srv[].governor.hist.insert(wait_us)
    h.srv[].governor.last_close_us = 0
    h.flush()


comptime _T: UInt64 = 1_000_000
"""Dial of the governor tests: the longest interval (500 ms), so only `_close_with_wait` closes one while the clients pump."""


def _governed() raises -> UdpServerHarness[OkHandler]:
    """A harness whose clock is past one interval, so a zero `last_close_us` makes a close due."""
    var h = UdpServerHarness[OkHandler](make_ok_handler, _params(), _params(), protection=ProtectionConfig(max_queue_delay_us=_T))
    h.advance(20 * _T)
    return h^


def _streams(c: HarnessClient) -> UInt64:
    return c.h3._quic.stream_map.peer_max_streams_bidi


def test_interval_close_applies_share_and_drains_raises() raises:
    """An over-target close narrows each connection's window and share, and new ones' credit; the release grants at once."""
    var h = _governed()
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    _close_with_wait(h, 2 * _T)  # over t, under 4 t: pressure without refusing connections
    ref d = h.srv[].governor.decision
    assert_true(h.srv[].governor.state.mode == Mode.CUTTING and d.share == 32 and not d.refuse_new, "pressure, share 32")
    ref conn = h.server_conn(0)[].h3()
    assert_true(conn.shed_above == d.shed_above and conn._quic.stream_map.regrant_window < 100, "the close applied share and window")
    for _ in range(3):
        _ = _send_get(c)
    for _ in range(10):
        _ = h.pump(c, advance_us=30_000)  # past the client's delayed ACK, so the streams complete
    assert_true(conn._quic.stream_map.peer_completed_bidi == 3 and _streams(c) == 100, "3 done, no grant under the window: D=" + String(conn._quic.stream_map.peer_completed_bidi) + " limit=" + String(_streams(c)) + " w=" + String(conn._quic.stream_map.regrant_window))
    var fresh = h.new_client()
    assert_true(h.handshake(fresh), "a new connection is admitted under pressure")
    assert_true(_streams(fresh) == 32, "and starts at the share: " + String(_streams(fresh)))
    _close_with_wait(h, 0)
    assert_true(h.srv[].governor.decision.budget == UNLIMITED, "released")
    _ = h.step(5)
    _ = h.client_recv(c)
    _ = h.client_recv(fresh)
    assert_true(_streams(c) == 103 and _streams(fresh) == 100, "MAX_STREAMS without a client datagram")


def test_refuse_new_drops_new_initials() raises:
    """After a streak above 4 t new Initials are dropped unanswered and counted; existing clients are served; release reopens."""
    var h = _governed()
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    for _ in range(3):  # REFUSE_AFTER closes above 4 t, the budget at its floor after the first
        _close_with_wait(h, 10 * _T)
    assert_true(h.srv[].governor.decision.refuse_new, "refusing new connections")
    var sock = h.new_socket()
    h.send_raw(sock, raw_initial(List[Byte](length=8, fill=0x5A), 1200))
    _ = h.step(20)
    h.flush()
    assert_true(h.slot_count() == 1 and h.srv[].protection_stats().dropped_overload == 1, "dropped and counted")
    _ = h.step(5)
    assert_true(len(h.recv_raw(sock, 50)) == 0, "no reply")
    var before = c.recv_total
    _ = _send_get(c)
    for _ in range(3):
        _ = h.pump(c)
    assert_true(c.recv_total > before, "the existing client is still served")
    h.advance(20 * _T)  # a whole interval without a close: the refusal is stale
    var late = h.new_socket()
    h.send_raw(late, raw_initial(List[Byte](length=8, fill=0x6B), 1200))
    _ = h.step(20)
    h.flush()
    assert_true(h.srv[].protection_stats().dropped_overload == 1, "a stale refusal drops nothing")
    _close_with_wait(h, 0)
    var fresh = h.new_client()
    assert_true(h.handshake(fresh) and _streams(fresh) == 100, "after release a new client gets full credit")
    assert_true(h.srv[].protection_stats().refused_closes == 0, "never CONNECTION_REFUSED")


def test_freed_connection_reaches_the_tally() raises:
    """A connection freed mid-interval hands its completions to the next close, and its open streams are not work."""
    var h = _governed()
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    for _ in range(3):
        _ = _send_get(c)
    for _ in range(10):
        _ = h.pump(c, advance_us=30_000)
    _ = _send_get(c, fin=False)  # the request never ends: an open stream when the connection dies
    _ = h.pump(c)
    h.srv[]._free_slot(0)
    ref acc = h.srv[]._gov_acc
    assert_true(acc.done == 3 and acc.work == 0 and acc.active == 0, "done=" + String(acc.done) + " work=" + String(acc.work))


def main() raises:
    var failed = 0
    try:
        test_egress_hold_and_rotation()
    except e:
        print("FAIL test_egress_hold_and_rotation:", e)
        failed += 1
    try:
        test_interval_close_applies_share_and_drains_raises()
    except e:
        print("FAIL test_interval_close_applies_share_and_drains_raises:", e)
        failed += 1
    try:
        test_refuse_new_drops_new_initials()
    except e:
        print("FAIL test_refuse_new_drops_new_initials:", e)
        failed += 1
    try:
        test_freed_connection_reaches_the_tally()
    except e:
        print("FAIL test_freed_connection_reaches_the_tally:", e)
        failed += 1
    if failed:
        raise Error(String(failed) + " failed")
    print("PASS: test_h3_governor_wiring")
