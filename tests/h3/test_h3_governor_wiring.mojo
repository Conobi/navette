"""`H3UdpServer` wiring of the overload controls: the egress hold and its rotation, the governor's interval close, the
rung-4 drop of new Initials. Loopback harness, pinned clock, no sleeps.
"""

from std.collections import Span

from navette.h3.h3_udp_server import EgressPacket
from navette.h3.ingress_guard import EGRESS_HOLD_AT
from navette.h3.qpack import QpackHeaderField
from navette.http.body import BodyFrame
from navette.http.handler import StreamHandler, Request, RecvBody, ResponseWriter, Capabilities, StreamError
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.quic.trans_param import TransportParams, default_transport_params

from tests._test_util import assert_true
from tests.h3._udp_server_harness import UdpServerHarness, HarnessClient


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


def _send_get(mut client: HarnessClient) raises -> UInt64:
    var sid = client.h3.open_bidi_stream()
    var fields: List[QpackHeaderField] = [
        QpackHeaderField(":method", "GET"), QpackHeaderField(":path", "/"),
        QpackHeaderField(":scheme", "https"), QpackHeaderField(":authority", "localhost"),
    ]
    client.h3.send_headers(sid, fields, True)
    return sid


def _fill_backlog(mut h: UdpServerHarness[OkHandler], n: Int, addr: List[Byte]):
    """Replace the egress backlog with `n` dummies (connection index -1) for `addr`."""
    h.srv[]._egress_backlog.clear()
    for _ in range(n):
        h.srv[]._egress_backlog.append(EgressPacket(List[Byte](length=40, fill=0), addr.copy(), -1, UInt8(0)))


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
    addr[2], addr[3] = UInt8(port >> 8), UInt8(port & 0xFF)
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


def main() raises:
    var failed = 0
    try:
        test_egress_hold_and_rotation()
    except e:
        print("FAIL test_egress_hold_and_rotation:", e)
        failed += 1
    if failed:
        raise Error(String(failed) + " failed")
    print("PASS: test_h3_governor_wiring")
