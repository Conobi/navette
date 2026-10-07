"""Out-of-band responses obey the same send gate as ordinary egress (RFC 9000 Sections 8.1, 9.3.2).

`inject_response` (a reverse proxy answering from another transport) must
not become an amplifier: toward an address that is only under validation it
may send at most 3x what that address sent, and toward an address whose
validation expired it must fall back to the last validated one.

Every harness test ends with `_ = h.slot_count()` (ASAP destruction).
"""

from bouclette import Socket

from tests._test_util import assert_true, assert_equal_int
from tests.h3._udp_server_harness import UdpServerHarness, HarnessClient
from tests.h3.test_h3_udp_server import (
    StubHandler,
    make_stub_handler,
    _params,
    _send_get,
    _send_partial_request,
)
from navette.http.status import StatusCode
from navette.http.headers import Headers
from navette.quic.cid import dcid_to_u64


def _body(n: Int) -> List[Byte]:
    return List[Byte](length=n, fill=0x78)


def _unanswered_request(mut h: UdpServerHarness[StubHandler], mut c: HarnessClient) raises -> Int:
    """Handshake, then a GET the stub never answers; returns its stream id."""
    assert_true(h.handshake(c), "handshake")
    for _ in range(3):
        _ = h.pump(c)
    var sid = _send_get(c)
    _ = h.pump(c)
    _ = h.pump(c)
    return Int(sid)


def _move_to(mut h: UdpServerHarness[StubHandler], mut c: HarnessClient, ref sock: Socket) raises -> Int:
    """Resend one of the client's non-probing datagrams from `sock`; returns the bytes sent."""
    _ = _send_partial_request(c)
    var sent = 0
    for ref d in h.client_capture(c):
        h.send_raw(sock, d)
        sent += len(d)
    _ = h.step(20)
    h.flush()
    return sent


def _bytes_at(mut h: UdpServerHarness[StubHandler], ref sock: Socket, rounds: Int) raises -> Int:
    var got = 0
    for _ in range(rounds):
        _ = h.step(20)
        h.flush()
        for ref d in h.recv_raw(sock, 20):
            got += len(d)
    return got


def test_inject_to_pending_address_is_budgeted() raises:
    """With the destination moved to an address under validation, an injected response sends it at most 3x its bytes."""
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params())
    var c = h.new_client()
    var sid = _unanswered_request(h, c)
    var conn_id = dcid_to_u64(h.server_conn(0)[]._h3._quic.local_cid.as_span())
    var other = h.new_socket()
    var sent = _move_to(h, c, other)
    assert_true(
        not h.server_addr(0) == h.server_conn(0)[].peer_addr_copy(),
        "destination moved to the address under validation",
    )
    var before = _bytes_at(h, other, 2)
    h.srv[].inject_response(conn_id, sid, StatusCode.ok(), Headers(), _body(30_000), True)
    var got = before + _bytes_at(h, other, 4)
    assert_true(got <= 3 * sent, "pending address got " + String(got) + " bytes for " + String(sent) + " sent")
    _ = other^
    _ = c^
    _ = h.slot_count()
    print("PASS: test_inject_to_pending_address_is_budgeted")


def test_inject_after_expiry_falls_back() raises:
    """Once validation of the new address expired, an injected response goes to the validated address."""
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params())
    var c = h.new_client()
    var sid = _unanswered_request(h, c)
    var conn_id = dcid_to_u64(h.server_conn(0)[]._h3._quic.local_cid.as_span())
    var other = h.new_socket()
    _ = _move_to(h, c, other)
    _ = _bytes_at(h, other, 2)
    _ = h.client_recv(c, 20)
    # Past 3 x max(PTO, 1 s): the challenge is stale, but no pass has run yet.
    h.advance(UInt64(4_000_000))
    h.srv[].inject_response(conn_id, sid, StatusCode.ok(), Headers(), _body(2_000), True)
    var at_other = _bytes_at(h, other, 2)
    var home = h.client_recv(c, 50)
    assert_equal_int(at_other, 0, "nothing goes to the expired address")
    assert_true(home > 0, "the response goes to the validated address")
    assert_true(
        h.server_addr(0) == h.server_conn(0)[].peer_addr_copy(),
        "destination reverted to the validated address",
    )
    _ = other^
    _ = c^
    _ = h.slot_count()
    print("PASS: test_inject_after_expiry_falls_back")


def main() raises:
    test_inject_to_pending_address_is_budgeted()
    test_inject_after_expiry_falls_back()
