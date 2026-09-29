"""H3UdpServer ingress fixes: receive window vs advertised payload, DCID demux and length floor, and flush before start.

Every harness test ends with `_ = h.slot_count()`: Mojo destroys the
harness (and the server) right after its last use, so the last read must
come after every assertion that dereferences `h.srv`.
"""

from navette.quic.cid import demux_key

from tests._test_util import assert_true, assert_equal_int
from tests.h3._udp_server_harness import UdpServerHarness, raw_initial
from tests.h3.test_h3_udp_server import StubHandler, make_stub_handler, _params


def _dcid(first: UInt8, n: Int) -> List[Byte]:
    var d = List[Byte](length=n, fill=Byte(0x5A))
    d[0] = first
    return d^


def test_non_gro_window_accepts_1350_and_1472() raises:
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params(), disable_gro=True)
    assert_true(h.srv[].recv_window >= 1472, "window >= 1472 with GRO off")
    assert_true(
        h.srv[].transport_params.max_udp_payload_size == UInt64(h.srv[].recv_window),
        "advertised max_udp_payload_size clamped to the window",
    )
    var sock = h.new_socket()
    h.send_raw(sock, raw_initial(_dcid(0x01, 8), 1350))
    h.send_raw(sock, raw_initial(_dcid(0x02, 8), 1472))
    for _ in range(4):
        _ = h.step(20)
        h.flush()
    assert_equal_int(h.slot_count(), 2, "both datagrams reached demux untruncated")
    _ = sock^
    _ = h.slot_count()  # keep the harness alive past the last read (ASAP destruction)
    print("PASS: test_non_gro_window_accepts_1350_and_1472")


def test_long_dcids_route_to_distinct_connections() raises:
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params())
    var a = _dcid(0x77, 20)
    var b = a.copy()
    b[19] = 0x78  # same first 8 bytes, different tail
    var sock = h.new_socket()
    h.send_raw(sock, raw_initial(a, 1200))
    h.send_raw(sock, raw_initial(b, 1200))
    for _ in range(4):
        _ = h.step(20)
        h.flush()
    assert_equal_int(h.slot_count(), 2, "two 20-byte DCIDs sharing a prefix: two connections")
    var ia = h.srv[]._find_conn_by_dcid(demux_key(Span(a), h.srv[]._demux_sip))
    var ib = h.srv[]._find_conn_by_dcid(demux_key(Span(b), h.srv[]._demux_sip))
    assert_true(ia >= 0 and ib >= 0 and ia != ib, "each DCID resolves to its own slot")
    _ = sock^
    _ = h.slot_count()  # keep the harness alive past the last read (ASAP destruction)
    print("PASS: test_long_dcids_route_to_distinct_connections")


def test_non_gro_window_drops_1473() raises:
    """With GRO off the window is 1,472 bytes: a 1,473-byte datagram is truncated and dropped."""
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params(), disable_gro=True)
    assert_equal_int(h.srv[].recv_window, 1472, "window is exactly 1472 with GRO off")
    var sock = h.new_socket()
    h.send_raw(sock, raw_initial(_dcid(0x03, 8), 1473))
    for _ in range(4):
        _ = h.step(20)
        h.flush()
    assert_equal_int(h.slot_count(), 0, "a truncated datagram creates no connection")
    h.send_raw(sock, raw_initial(_dcid(0x04, 8), 1472))
    for _ in range(4):
        _ = h.step(20)
        h.flush()
    assert_equal_int(h.slot_count(), 1, "the socket still delivers a 1,472-byte datagram")
    _ = sock^
    _ = h.slot_count()  # keep the harness alive past the last read (ASAP destruction)
    print("PASS: test_non_gro_window_drops_1473")


def test_gro_window_holds_a_full_coalesced_delivery() raises:
    """With coalesced receive the window covers any GRO delivery, and a 50 x 1,309-byte burst is served.

    GRO merges until the IP packet reaches 65,536 bytes, so one delivery
    carries up to 65,487 B of UDP payload over IPv6. The old 65,443-byte
    window returned this 65,450-byte burst MSG_TRUNC and dropped all 50
    datagrams. The advertised per-datagram limit stays the configured one.
    """
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params())
    if not h.srv[]._socket_state.value().supports_coalesced_recv():
        print("SKIP: test_gro_window_holds_a_full_coalesced_delivery (kernel lacks UDP_GRO)")
        return
    var sock = h.new_socket()
    sock.set_gso_segment_size(UInt16(1309))
    var burst = List[Byte](capacity=50 * 1309)
    var one = raw_initial(_dcid(0x09, 8), 1309)
    for _ in range(50):
        burst.extend(Span(one))
    h.send_raw(sock, burst)
    for _ in range(4):
        _ = h.step(20)
        h.flush()
    assert_equal_int(h.slot_count(), 1, "the coalesced burst reached demux untruncated")
    assert_true(h.srv[].recv_window >= 65535, "GRO window >= 65,535")
    assert_true(
        h.srv[].transport_params.max_udp_payload_size == _params().max_udp_payload_size,
        "advertised max_udp_payload_size is the configured per-datagram limit",
    )
    _ = sock^
    _ = h.slot_count()  # keep the harness alive past the last read (ASAP destruction)
    print("PASS: test_gro_window_holds_a_full_coalesced_delivery")


def test_short_initial_dcids_create_no_connection() raises:
    """RFC 9000 Section 7.2: Initials with a 0- or 7-byte DCID are dropped; 8 bytes still connect.

    Two clients sending zero-length DCIDs would otherwise share one slot.
    """
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params())
    var s1 = h.new_socket()
    var s2 = h.new_socket()
    h.send_raw(s1, raw_initial(List[Byte](), 1200))
    h.send_raw(s2, raw_initial(List[Byte](), 1200))
    h.send_raw(s1, raw_initial(_dcid(0x07, 7), 1200))
    h.send_raw(s2, raw_initial(_dcid(0x04, 4), 1200))
    for _ in range(4):
        _ = h.step(20)
        h.flush()
    assert_equal_int(h.slot_count(), 0, "no slot for a DCID shorter than 8 bytes")
    h.send_raw(s1, raw_initial(_dcid(0x08, 8), 1200))
    for _ in range(4):
        _ = h.step(20)
        h.flush()
    assert_equal_int(h.slot_count(), 1, "an 8-byte DCID still creates a slot")
    _ = s1^
    _ = s2^
    _ = h.slot_count()  # keep the harness alive past the last read (ASAP destruction)
    print("PASS: test_short_initial_dcids_create_no_connection")


def test_flush_before_start_is_a_no_op() raises:
    """After a start() that failed past arming the receive stream, flush() leaves received Initials queued.

    Processing them would queue egress for a send sink that does not exist
    yet. Once start() is retried, the queued Initial is served.
    """
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params(), fail_first_start=True)
    assert_true(not h.srv[]._send_sink, "the failed start() created no send sink")
    var client = h.new_client()
    assert_true(h.client_send(client) > 0, "the client sent its Initial")
    for _ in range(4):
        _ = h.step(20)
        h.flush()
    assert_equal_int(h.slot_count(), 0, "flush() before start() processes nothing")
    h.start()
    assert_true(h.handshake(client), "the handshake completes once start() succeeds")
    assert_equal_int(h.slot_count(), 1, "one connection")
    _ = client^
    _ = h.slot_count()  # keep the harness alive past the last read (ASAP destruction)
    print("PASS: test_flush_before_start_is_a_no_op")


def main() raises:
    test_non_gro_window_accepts_1350_and_1472()
    test_long_dcids_route_to_distinct_connections()
    test_non_gro_window_drops_1473()
    test_gro_window_holds_a_full_coalesced_delivery()
    test_short_initial_dcids_create_no_connection()
    test_flush_before_start_is_a_no_op()
