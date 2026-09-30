"""H3UdpServer keeps routing the client's Initial DCID for the connection's life.

A reordered or duplicated original Initial arriving after confirmation
must reach the existing connection (which drops it: its Initial keys are
gone), not create a second, zombie connection.

Every harness test ends with `_ = h.slot_count()` (ASAP destruction).
"""

from navette.quic.cid import demux_key

from tests._test_util import assert_true, assert_equal_int
from tests.h3._udp_server_harness import UdpServerHarness
from tests.h3.test_h3_udp_server import StubHandler, make_stub_handler, _params


def test_late_original_initial_creates_no_zombie() raises:
    var h = UdpServerHarness[StubHandler](make_stub_handler, _params(), _params())
    var c = h.new_client()
    var first = h.client_capture(c)
    assert_true(len(first) >= 1, "client built its first Initial")
    var odcid = List[Byte](c.h3._quic.initial_dcid.as_span())
    for ref d in first:
        h.send_raw(c.sock, d)
    _ = h.step(20)
    h.flush()
    _ = h.client_recv(c, 50)
    assert_true(h.handshake(c), "handshake")
    for _ in range(3):
        _ = h.pump(c)
    assert_true(h.server_conn(0)[]._h3._quic.handshake_confirmed, "confirmed")

    # The original Initial, late: it must reach the live connection.
    for ref d in first:
        h.send_raw(c.sock, d)
    _ = h.step(20)
    h.flush()
    assert_equal_int(h.slot_count(), 1, "a late original Initial creates no second connection")
    var key = demux_key(Span(odcid), h.srv[]._demux_sip)
    assert_true(h.srv[]._find_conn_by_dcid(key) >= 0, "Initial DCID still routes")

    # Much later, the same.
    h.advance(UInt64(5_000_000))
    for _ in range(3):
        _ = h.pump(c)
    for ref d in first:
        h.send_raw(c.sock, d)
    _ = h.step(20)
    h.flush()
    assert_true(h.srv[]._find_conn_by_dcid(key) >= 0, "Initial DCID routes for the connection's life")
    assert_equal_int(h.slot_count(), 1, "still no second connection")
    _ = c^
    _ = h.slot_count()
    print("PASS: test_late_original_initial_creates_no_zombie")


def main() raises:
    test_late_original_initial_creates_no_zombie()
