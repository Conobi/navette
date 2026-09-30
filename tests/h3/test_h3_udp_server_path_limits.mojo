"""H3UdpServer never sends more than 3x what an unvalidated address sent (RFC 9000 Sections 8.1, 9.3).

A peer's authenticated datagrams resent from spoofed sources must not turn
the server into an amplifier towards a victim: with the pending-challenge
cap full a new source is dropped, a replay is discarded, pending
challenges expire, and the send destination then falls back to the last
validated address.

Every harness test ends with `_ = h.slot_count()` (ASAP destruction).
"""

from bouclette import Socket

from tests._test_util import assert_true, assert_equal_int
from tests.h3._udp_server_harness import UdpServerHarness, HarnessClient
from tests.h3.test_h3_udp_server import (
    BigHandler,
    make_big_handler,
    _params,
    _send_get,
    _send_partial_request,
    _addrs_eq,
)
from navette.quic.path import MAX_PENDING_CHALLENGES


def _drain_victim(mut h: UdpServerHarness[BigHandler], ref victim: Socket, rounds: Int) raises -> Int:
    """Run the server for `rounds` passes (clock moving past PTOs) and count bytes that reach `victim`."""
    var got = 0
    for _ in range(rounds):
        _ = h.step(20)
        h.flush()
        _ = h.step(20)
        for ref d in h.recv_raw(victim, 20):
            got += len(d)
        h.advance(UInt64(300_000))
    return got


def _established(mut h: UdpServerHarness[BigHandler]) raises -> HarnessClient:
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    for _ in range(3):
        _ = h.pump(c)
    return c^


def test_full_cap_victim_gets_nothing() raises:
    """Four fresh client datagrams from junk sources, then a GET from the victim: no amplified egress to it."""
    var h = UdpServerHarness[BigHandler](make_big_handler, _params(), _params())
    var c = _established(h)
    var home = h.server_addr(0)
    var junk = List[Socket]()
    for _ in range(MAX_PENDING_CHALLENGES):
        junk.append(h.new_socket())
    for i in range(MAX_PENDING_CHALLENGES):
        _ = _send_partial_request(c)
        for ref d in h.client_capture(c):
            h.send_raw(junk[i], d)
        _ = h.step(20)
        h.flush()
    var victim = h.new_socket()
    _ = _send_get(c)
    var sent = 0
    for ref d in h.client_capture(c):
        h.send_raw(victim, d)
        sent += len(d)
    var got = _drain_victim(h, victim, 6)
    assert_true(got <= 3 * sent, "victim got " + String(got) + " bytes for " + String(sent) + " sent")

    # The challenges expire (3 x max(PTO, 1 s)); the destination falls back home.
    h.advance(UInt64(4_000_000))
    _ = _drain_victim(h, victim, 2)
    assert_equal_int(len(h.server_conn(0)[]._h3._quic.path.validator.pending), 0, "pending challenges expired")
    assert_true(_addrs_eq(h.server_addr(0), home), "destination reverted to the validated address")
    _ = junk^
    _ = victim^
    _ = c^
    _ = h.slot_count()
    print("PASS: test_full_cap_victim_gets_nothing")


def test_replayed_request_amplifies_nothing() raises:
    """One GET datagram sent from four junk sources, then from the victim: the replays are discarded."""
    var h = UdpServerHarness[BigHandler](make_big_handler, _params(), _params())
    var c = _established(h)
    var junk = List[Socket]()
    for _ in range(MAX_PENDING_CHALLENGES):
        junk.append(h.new_socket())
    var victim = h.new_socket()
    _ = _send_get(c)
    var dgs = h.client_capture(c)
    for i in range(MAX_PENDING_CHALLENGES):
        for ref d in dgs:
            h.send_raw(junk[i], d)
        _ = h.step(20)
        h.flush()
    assert_true(
        len(h.server_conn(0)[]._h3._quic.path.validator.pending) <= 1,
        "replays start no challenge",
    )
    var sent = 0
    for ref d in dgs:
        h.send_raw(victim, d)
        sent += len(d)
    var got = _drain_victim(h, victim, 6)
    assert_true(got <= 3 * sent, "victim got " + String(got) + " bytes for " + String(sent) + " replayed")
    _ = junk^
    _ = victim^
    _ = c^
    _ = h.slot_count()
    print("PASS: test_replayed_request_amplifies_nothing")


def main() raises:
    test_full_cap_victim_gets_nothing()
    test_replayed_request_amplifies_nothing()
