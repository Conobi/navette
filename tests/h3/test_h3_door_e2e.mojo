"""H3UdpServer's door end to end: Initial size, Version Negotiation, Retry, stateless closes, the Retry threshold and the handshake timeout.

Every harness test ends with `_ = h.slot_count()`: Mojo destroys the
harness (and the server) right after its last use, so the last read must
come after every assertion that dereferences `h.srv`.
"""

from std.collections import Span

from navette.protect.config import ProtectionConfig
from navette.quic.cid import demux_key
from navette.quic.cid_buf import CidBuf
from navette.h3.conn_table import KEYS_PER_CONN
from navette.quic.event import QuicEvent, ConnectionClosedPayload
from navette.quic.packet import PacketType, parse_packet_header

from tests._test_util import assert_true, assert_equal_int
from tests.h3._udp_server_harness import UdpServerHarness, HarnessClient, raw_initial, raw_long
from tests.h3.test_h3_udp_server import StubHandler, make_stub_handler, _params, _send_partial_request


def _harness(protection: ProtectionConfig = ProtectionConfig()) raises -> UdpServerHarness[StubHandler]:
    return UdpServerHarness[StubHandler](make_stub_handler, _params(), _params(), protection=protection)


def _dcid(first: UInt8, n: Int) -> List[Byte]:
    var d = List[Byte](length=n, fill=Byte(0x5A))
    d[0] = first
    return d^


def _settle(mut h: UdpServerHarness[StubHandler], rounds: Int = 4) raises:
    """A few bounded steps and flushes, so every datagram already sent is processed; the last step submits the last flush's egress."""
    for _ in range(rounds):
        _ = h.step(20)
        h.flush()
    _ = h.step(20)


def _type_of(dg: List[Byte]) raises -> PacketType:
    return parse_packet_header(Span(dg), 8)[0].packet_type


def _close_code(mut c: HarnessClient, dg: List[Byte], now: UInt64) raises -> Int:
    """Feed `dg` to the client's QUIC connection; the error code of the CONNECTION_CLOSE it carried, -1 if none."""
    c.h3._quic.recv(Span(dg), now)
    while True:
        var ev = c.h3._quic.poll()
        if not ev:
            return -1
        if ev.value().type_id == QuicEvent.CONNECTION_CLOSED:
            return Int(ev.value().payload[ConnectionClosedPayload].error_code)


def _token_offset(dg: List[Byte]) -> Int:
    """Offset of the first token byte of a v1 Initial with a 2-byte token-length varint."""
    var at = 6 + Int(dg[5])
    at += 1 + Int(dg[at])
    return at + 2


def _retried_client(mut h: UdpServerHarness[StubHandler]) raises -> HarnessClient:
    """A client that sent its first flight, got the server's Retries and followed the first (its next Initial is not sent).

    A ClientHello over one datagram (post-quantum key share) spans two
    token-less Initials, and each gets its own Retry: one per datagram.
    """
    var c = h.new_client()
    _ = h.pump(c)
    for _ in range(5):
        if c.h3._quic._retry_scid:
            break
        _settle(h, 1)
        _ = h.client_recv(c, 50)
    assert_true(Bool(c.h3._quic._retry_scid), "the client followed a Retry")
    assert_true(h.srv[].protection_stats().retry_sent >= 1, "at least one Retry")
    return c^


def test_small_initials_dropped() raises:
    var h = _harness()
    var sock = h.new_socket()
    h.send_raw(sock, raw_initial(_dcid(0xA1, 8), 1199))
    _settle(h)
    assert_equal_int(h.slot_count(), 0, "1,199 B new-DCID Initial made no slot")
    h.send_raw(sock, raw_initial(_dcid(0xA2, 8), 1200))
    _settle(h)
    assert_equal_int(h.slot_count(), 1, "1,200 B Initial made a slot")
    h.send_raw(sock, raw_initial(_dcid(0xA2, 8), 1199))
    _settle(h)
    assert_equal_int(Int(h.srv[].protection_stats().dropped_initial_size), 2, "known-DCID 1,199 B dropped too")
    _ = sock^
    _ = h.slot_count()
    print("PASS: test_small_initials_dropped")


def test_version_negotiation() raises:
    var h = _harness()
    var sock = h.new_socket()
    h.send_raw(sock, raw_long(0x1A2A3A4A, _dcid(0xB1, 8), 1200))
    _settle(h)
    var got = h.recv_raw(sock, 50)
    assert_equal_int(len(got), 1, "one VN")
    assert_true(_type_of(got[0]) == PacketType.version_negotiation(), "it is a VN")
    h.send_raw(sock, raw_long(0x1A2A3A4A, _dcid(0xB2, 8), 1199))
    h.send_raw(sock, raw_long(0, _dcid(0xB3, 8), 1200))
    _settle(h)
    assert_equal_int(len(h.recv_raw(sock, 20)), 0, "no answer to a small datagram or to version 0")
    assert_equal_int(Int(h.srv[].protection_stats().dropped_vn_small), 1, "dropped_vn_small")
    for i in range(6):
        h.send_raw(sock, raw_long(0x1A2A3A4A, _dcid(0xC0 + UInt8(i), 8), 1200))
    _settle(h)
    var stats = h.srv[].protection_stats()
    assert_equal_int(Int(stats.vn_sent), 4, "burst 4 at one instant")
    assert_equal_int(Int(stats.stateless_bucket_empty_vn), 3, "the rest paced")
    assert_equal_int(h.slot_count(), 0, "no state")
    _ = sock^
    _ = h.slot_count()
    print("PASS: test_version_negotiation")


def test_retry_round_trip() raises:
    var h = _harness()
    h.srv[].set_require_validation(True)
    var c = _retried_client(h)
    assert_equal_int(h.slot_count(), 0, "a Retry keeps no state")
    assert_true(h.handshake(c), "handshake completes after Retry")
    assert_equal_int(Int(h.srv[].protection_stats().tokens_valid), 1, "token VALID")
    assert_equal_int(h.slot_count(), 1, "one connection")
    assert_equal_int(h.srv[].unvalidated_handshaking(), 0, "Retry-validated slot is never unvalidated")
    _ = c^
    _ = h.slot_count()
    print("PASS: test_retry_round_trip")


def test_invalid_token_close_wrong_port() raises:
    var h = _harness()
    h.srv[].set_require_validation(True)
    var c = _retried_client(h)
    var dgs = h.client_capture(c)
    assert_true(len(dgs) > 0, "the client has its token-carrying Initial ready")
    var other = h.new_socket()
    h.send_raw(other, dgs[0])
    _settle(h)
    var got = h.recv_raw(other, 50)
    assert_equal_int(len(got), 1, "the other port gets one datagram")
    assert_equal_int(_close_code(c, got[0], h.now()), 0x0B, "INVALID_TOKEN")
    assert_equal_int(Int(h.srv[].protection_stats().invalid_token_closes), 1, "counted")
    assert_equal_int(h.slot_count(), 0, "no state")
    _ = other^
    _ = c^
    _ = h.slot_count()
    print("PASS: test_invalid_token_close_wrong_port")


def test_expired_token_close() raises:
    var h = _harness()
    h.srv[].set_require_validation(True)
    var c = _retried_client(h)
    var dgs = h.client_capture(c)
    h.advance(11_000_000)
    h.send_raw(c.sock, dgs[0])
    _settle(h)
    var got = h.recv_raw(c.sock, 50)
    assert_equal_int(len(got), 1, "one reply")
    assert_equal_int(_close_code(c, got[0], h.now()), 0x0B, "an expired token is INVALID_TOKEN")
    assert_equal_int(h.slot_count(), 0, "no state")
    _ = c^
    _ = h.slot_count()
    print("PASS: test_expired_token_close")


def test_corrupted_token_gets_retry() raises:
    """RFC 9000 erratum 7861: a token that does not decrypt is treated as absent."""
    var h = _harness()
    h.srv[].set_require_validation(True)
    var c = _retried_client(h)
    var none_before = Int(h.srv[].protection_stats().tokens_none)
    var dgs = h.client_capture(c)
    dgs[0][_token_offset(dgs[0]) + 20] ^= 0x01
    h.send_raw(c.sock, dgs[0])
    _settle(h)
    var got = h.recv_raw(c.sock, 50)
    assert_equal_int(len(got), 1, "one reply")
    assert_true(_type_of(got[0]) == PacketType.retry(), "a Retry, not a close")
    var stats = h.srv[].protection_stats()
    assert_equal_int(Int(stats.tokens_none), none_before + 1, "the corrupted token counts as none")
    assert_equal_int(Int(stats.invalid_token_closes), 0, "no close")
    _ = c^
    _ = h.slot_count()
    print("PASS: test_corrupted_token_gets_retry")


def test_foreign_token_gets_retry() raises:
    var h = _harness()
    h.srv[].set_require_validation(True)
    var sock = h.new_socket()
    var token = List[Byte](length=61, fill=Byte(0x33))
    token[0] = 0x02
    h.send_raw(sock, raw_initial(_dcid(0xC1, 8), 1200, token))
    _settle(h)
    var got = h.recv_raw(sock, 50)
    assert_equal_int(len(got), 1, "one reply")
    assert_true(_type_of(got[0]) == PacketType.retry(), "a Retry")
    assert_equal_int(Int(h.srv[].protection_stats().tokens_none), 1, "a foreign token counts as none")
    _ = sock^
    _ = h.slot_count()
    print("PASS: test_foreign_token_gets_retry")


def test_retry_threshold() raises:
    var h = _harness()
    h.srv[]._test_retry_threshold(4)
    var sock = h.new_socket()
    for i in range(5):
        h.send_raw(sock, raw_initial(_dcid(0xD0 + UInt8(i), 8), 1200))
    _settle(h)
    assert_equal_int(h.slot_count(), 4, "4 unvalidated slots")
    assert_equal_int(h.srv[].unvalidated_handshaking(), 4, "all unvalidated")
    assert_equal_int(Int(h.srv[].protection_stats().retry_sent), 1, "the 5th got a Retry")
    var got = h.recv_raw(sock, 50)
    assert_equal_int(len(got), 1, "one datagram back")
    assert_true(_type_of(got[0]) == PacketType.retry(), "the Retry")
    _ = sock^
    _ = h.slot_count()
    print("PASS: test_retry_threshold")


def test_unvalidated_slot_created_below_threshold() raises:
    """Pin: a token-less Initial below every threshold opens an unvalidated slot."""
    var h = _harness()
    var sock = h.new_socket()
    h.send_raw(sock, raw_initial(_dcid(0xE1, 8), 1200))
    _settle(h)
    assert_equal_int(h.slot_count(), 1, "slot")
    assert_equal_int(h.srv[].unvalidated_handshaking(), 1, "unvalidated")
    var stats = h.srv[].protection_stats()
    assert_equal_int(Int(stats.unvalidated_handshaking_peak), 1, "unvalidated peak")
    assert_equal_int(Int(stats.handshaking_peak), 1, "handshaking peak")
    _ = sock^
    _ = h.slot_count()
    print("PASS: test_unvalidated_slot_created_below_threshold")


def test_handshake_timeout_frees_unvalidated() raises:
    var h = _harness()
    var sock = h.new_socket()
    for i in range(3):
        h.send_raw(sock, raw_initial(_dcid(0xF0 + UInt8(i), 8), 1200))
    _settle(h)
    assert_equal_int(h.slot_count(), 3, "3 slots")
    h.advance(9_000_000)
    _settle(h, 1)
    assert_equal_int(h.slot_count(), 3, "still there after 9 s")
    h.advance(1_001_000)
    _settle(h, 1)
    assert_equal_int(h.slot_count(), 0, "abandoned 10 s after creation")
    assert_equal_int(h.srv[].unvalidated_handshaking(), 0, "count back to 0")
    assert_equal_int(Int(h.srv[].protection_stats().handshake_timeouts), 3, "3 handshake timeouts counted")
    assert_equal_int(len(h.recv_raw(sock, 20)), 0, "nothing sent to an unvalidated peer")
    _ = sock^
    _ = h.slot_count()
    print("PASS: test_handshake_timeout_frees_unvalidated")


def test_refused_when_no_free_id() raises:
    var h = _harness(ProtectionConfig(conn_cap=64))
    var sock = h.new_socket()
    for i in range(64):
        h.send_raw(sock, raw_initial(_dcid(UInt8(i), 8), 1200))
        if i % 16 == 15:
            _settle(h, 2)
    _settle(h)
    assert_equal_int(h.slot_count(), 64, "at the cap")
    var c = _retried_client(h)
    var dgs = h.client_capture(c)
    h.send_raw(c.sock, dgs[0])
    _settle(h)
    var got = h.recv_raw(c.sock, 50)
    assert_equal_int(len(got), 1, "one reply")
    assert_equal_int(_close_code(c, got[0], h.now()), 0x02, "CONNECTION_REFUSED")
    var stats = h.srv[].protection_stats()
    assert_equal_int(Int(stats.cap_rejections), 1, "cap_rejections")
    assert_equal_int(Int(stats.refused_closes), 1, "refused_closes")
    assert_equal_int(h.slot_count(), 64, "no slot over the cap")
    _ = sock^
    _ = c^
    _ = h.slot_count()
    print("PASS: test_refused_when_no_free_id")


def test_quic_leak_single_slot() raises:
    """Pin: long-header packets with foreign DCIDs coalesced after a client's first Initial create no state."""
    var h = _harness()
    var c = h.new_client()
    var dgs = h.client_capture(c)
    var dg = dgs[0].copy()
    for i in range(10):
        dg.extend(Span(raw_initial(_dcid(0x40 + UInt8(i), 8), 26)))
    assert_true(len(dg) <= 1472, "fits the receive window")
    h.send_raw(c.sock, dg)
    _settle(h)
    assert_equal_int(h.slot_count(), 1, "one connection, for the first packet's DCID")
    assert_equal_int(
        h.srv[]._find_conn_by_dcid(demux_key(Span(_dcid(0x40, 8)), h.srv[]._demux_sip)), -1, "foreign DCID not routed"
    )
    _ = c^
    _ = h.slot_count()
    print("PASS: test_quic_leak_single_slot")


def _remote_cid(mut c: HarnessClient, seq: UInt64) raises -> List[Byte]:
    """The server-issued CID the client holds under `seq`."""
    for ref e in c.h3._quic.cid_mgr.remote_cids:
        if e.sequence == seq:
            return e.cid.copy()
    raise Error("client holds no remote CID with seq " + String(seq))


def _cid_harness() raises -> UdpServerHarness[StubHandler]:
    """A harness whose client accepts 4 active CIDs, so the server issues seq 1 to 3 at once."""
    var cp = _params()
    cp.active_connection_id_limit = 4
    return UdpServerHarness[StubHandler](make_stub_handler, _params(), cp^)


def _established_with_cids(mut h: UdpServerHarness[StubHandler]) raises -> HarnessClient:
    """A handshaken client that has received the server's NEW_CONNECTION_ID frames for seq 1 and 2."""
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    for _ in range(3):
        _ = h.pump(c)
    _ = _remote_cid(c, 1)
    _ = _remote_cid(c, 2)
    return c^


def _switch_and_send(mut h: UdpServerHarness[StubHandler], mut c: HarnessClient, seq: UInt64) raises -> Bool:
    """Point the client's DCID at the CID issued under `seq`, send one ack-eliciting packet; True when it reached slot 0."""
    c.h3._quic.peer_cid = CidBuf.from_span(Span(_remote_cid(c, seq)))
    var before = h.server_conn(0)[]._h3._quic.bytes_received
    _ = _send_partial_request(c)
    _ = h.pump(c)
    return h.server_conn(0)[]._h3._quic.bytes_received > before


def _raw_short(dcid: List[Byte], total_len: Int) -> List[Byte]:
    """A `total_len`-byte short-header packet for `dcid`, zero-filled (never decrypts)."""
    var p = List[Byte](capacity=total_len)
    p.append(0x43)
    for b in dcid:
        p.append(b)
    while len(p) < total_len:
        p.append(0x00)
    return p^


def test_client_rotates_to_issued_cids() raises:
    var h = _cid_harness()
    var c = _established_with_cids(h)
    for seq in range(1, 3):
        assert_true(_switch_and_send(h, c, UInt64(seq)), "seq " + String(seq) + " reaches the connection")
    assert_equal_int(h.slot_count(), 1, "no new slot")
    _ = c^
    _ = h.slot_count()
    print("PASS: test_client_rotates_to_issued_cids")


def test_retired_cid_no_longer_routes() raises:
    var h = _cid_harness()
    var c = _established_with_cids(h)
    assert_true(_switch_and_send(h, c, 1), "seq 1 routes")
    var retired = _remote_cid(c, 1)
    assert_true(c.h3._quic.cid_mgr.retire_remote(1), "client queues RETIRE_CONNECTION_ID for seq 1")
    assert_true(_switch_and_send(h, c, 2), "seq 2 routes and carries the retirement")
    _ = h.pump(c)
    var dropped = h.srv[].protection_stats().dropped_unknown_dcid
    h.send_raw(c.sock, _raw_short(retired, 60))
    _settle(h, 1)
    assert_equal_int(
        Int(h.srv[].protection_stats().dropped_unknown_dcid), Int(dropped) + 1, "retired CID dropped as unknown"
    )
    assert_true(_switch_and_send(h, c, 2), "the live CID still routes")
    assert_equal_int(h.slot_count(), 1, "no new slot")
    _ = c^
    _ = h.slot_count()
    print("PASS: test_retired_cid_no_longer_routes")


def test_initial_dcid_key_removed_after_handshake() raises:
    var h = _cid_harness()
    var c = _established_with_cids(h)
    var orig = List[Byte](c.h3._quic.initial_dcid.as_span())
    ref table = h.srv[]._table
    assert_true(table.key_count(h.srv[].conn_slots[0].id) <= KEYS_PER_CONN, "keys within the per-connection bound")
    assert_equal_int(
        h.srv[]._find_conn_by_dcid(demux_key(Span(orig), h.srv[]._demux_sip)), -1, "Initial DCID no longer routes"
    )
    h.send_raw(c.sock, raw_initial(orig, 1200))
    _settle(h, 1)
    assert_equal_int(h.slot_count(), 2, "a fresh Initial for the old DCID makes a new slot")
    assert_equal_int(h.srv[]._table.invariant_violation().byte_length(), 0, "table invariants hold")
    _ = c^
    _ = h.slot_count()
    print("PASS: test_initial_dcid_key_removed_after_handshake")


def main() raises:
    test_small_initials_dropped()
    test_version_negotiation()
    test_retry_round_trip()
    test_invalid_token_close_wrong_port()
    test_expired_token_close()
    test_corrupted_token_gets_retry()
    test_foreign_token_gets_retry()
    test_retry_threshold()
    test_unvalidated_slot_created_below_threshold()
    test_handshake_timeout_frees_unvalidated()
    test_refused_when_no_free_id()
    test_quic_leak_single_slot()
    test_client_rotates_to_issued_cids()
    test_retired_cid_no_longer_routes()
    test_initial_dcid_key_removed_after_handshake()
