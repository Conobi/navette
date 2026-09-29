"""A full DatagramSink is backpressure, not a GSO failure.

`DatagramSink.push_msg` raises ENOSPC when every slot is taken — a
transient state under overload. The GSO egress path must keep the batch
in the backlog for the next flush and leave segmentation offload
enabled; downgrading on a full sink would slow the server down exactly
when it is overloaded.
"""

from std.collections import Span

from bouclette import Message

from navette.h3.h3_udp_server import EgressPacket, _set_msg_peer_raw
from navette.http.handler import (
    StreamHandler,
    Request,
    RecvBody,
    ResponseWriter,
    Capabilities,
    StreamError,
)
from navette.quic.trans_param import TransportParams, default_transport_params

from tests._test_util import assert_true, assert_equal_int
from tests.h3._udp_server_harness import UdpServerHarness


struct StubHandler(StreamHandler):
    """No-op handler; the test only drives the egress path."""

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
    return StubHandler()


def _params() -> TransportParams:
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    return p^


def _payload(tag: Int, size: Int) -> List[Byte]:
    """`size` bytes whose first byte is `tag`, to check identity and order."""
    var p = List[Byte](capacity=size)
    p.append(UInt8(tag))
    for j in range(1, size):
        p.append(UInt8(j & 0xFF))
    return p^


def test_full_sink_keeps_gso_and_backlog() raises:
    """ENOSPC on a GSO batch retains every datagram, in order, and keeps GSO."""
    var h = UdpServerHarness[StubHandler](
        make_stub_handler, _params(), _params(),
    )
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    var addr = h.server_addr(0)
    h.srv[]._egress_backlog.clear()

    comptime GSO_SEGMENTS = 4
    h.srv[]._gso_max_segments = GSO_SEGMENTS

    # Fill every sink slot so the next push_msg raises ENOSPC.
    var filled = 0
    while filled < 4096:
        var msg = Message(_payload(0xEE, 32), control_capacity=24)
        _set_msg_peer_raw(msg, addr)
        try:
            h.srv[]._send_sink.value().push_msg(msg^)
        except:
            break
        filled += 1
    assert_true(filled > 0 and filled < 4096, "sink filled to capacity")

    # A 3-packet GSO run (same size, same peer) plus one odd-sized tail.
    for k in range(3):
        h.srv[]._egress_backlog.append(
            EgressPacket(_payload(k, 100), List[Byte](copy=addr), 0, UInt8(0))
        )
    h.srv[]._egress_backlog.append(
        EgressPacket(_payload(3, 60), List[Byte](copy=addr), 0, UInt8(0))
    )

    h.srv[]._submit_egress()

    assert_equal_int(
        h.srv[]._gso_max_segments, GSO_SEGMENTS,
        "full sink must not downgrade GSO",
    )
    assert_equal_int(
        len(h.srv[]._egress_backlog), 4, "all four datagrams retained",
    )
    for k in range(4):
        assert_equal_int(
            Int(h.srv[]._egress_backlog[k].data[0]), k,
            "backlog order preserved at " + String(k),
        )
        assert_equal_int(
            len(h.srv[]._egress_backlog[k].addr), len(addr),
            "peer address retained at " + String(k),
        )
    assert_equal_int(len(h.srv[]._egress_backlog[0].data), 100, "payload intact")
    assert_equal_int(len(h.srv[]._egress_backlog[3].data), 60, "tail intact")

    # Once the filler sends complete, the retained batch leaves with GSO on.
    for _ in range(20):
        if (h.srv[]._send_sink.value().pending()
                + h.srv[]._send_sink.value().in_flight() == 0):
            break
        _ = h.step(10)
    var pushed_before = (
        h.srv[]._send_sink.value().completed()
        + h.srv[]._send_sink.value().failed()
    )
    h.srv[]._submit_egress()
    assert_equal_int(len(h.srv[]._egress_backlog), 0, "backlog drained")
    assert_equal_int(
        h.srv[]._gso_max_segments, GSO_SEGMENTS, "GSO still enabled",
    )
    for _ in range(20):
        if (h.srv[]._send_sink.value().pending()
                + h.srv[]._send_sink.value().in_flight() == 0):
            break
        _ = h.step(10)
    assert_equal_int(
        h.srv[]._send_sink.value().completed()
        + h.srv[]._send_sink.value().failed() - pushed_before,
        2,
        "one GSO super-buffer plus one single datagram",
    )
    _ = c.recv_total
    print("PASS: test_full_sink_keeps_gso_and_backlog")


def main() raises:
    test_full_sink_keeps_gso_and_backlog()
