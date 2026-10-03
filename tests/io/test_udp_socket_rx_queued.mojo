"""`UdpSocketState.rx_queued_bytes`: the kernel receive-queue size (`SO_MEMINFO` rmem_alloc) of a UDP socket."""

from bouclette.net.socket import Socket
from bouclette.net.addr import SocketAddrV4

from navette.runtime.udp_socket_state import UdpSocketState
from tests._test_util import assert_true


def _send(ref tx: Socket, ref to: SocketAddrV4, n: Int) raises:
    var payload = List[Byte](length=1200, fill=Byte(0x5A))
    for _ in range(n):
        _ = tx.send_to(Span(payload), to)


def test_queue_grows_and_drains() raises:
    var rx = Socket.udp_v4()
    rx.bind(SocketAddrV4(127, 0, 0, 1, port=0))
    var to = rx.local_addr_v4()
    var tx = Socket.udp_v4()
    var empty = UdpSocketState.rx_queued_bytes(rx)
    assert_true(empty and empty.value() == 0, "empty socket reads 0")
    _send(tx, to, 10)
    var ten = UdpSocketState.rx_queued_bytes(rx).value()
    assert_true(ten > 0, "10 queued datagrams read > 0")
    _send(tx, to, 30)
    var forty = UdpSocketState.rx_queued_bytes(rx).value()
    assert_true(forty > ten, "40 queued read more than 10: " + String(forty) + " vs " + String(ten))
    var buf = List[Byte](length=2048, fill=Byte(0))
    for _ in range(40):
        _ = rx.recv_from_v4(Span(buf))
    assert_true(UdpSocketState.rx_queued_bytes(rx).value() == 0, "drained socket reads 0")
    _ = tx.local_addr_v4()


def test_closed_socket_is_none() raises:
    var rx = Socket.udp_v4()
    rx.close()
    assert_true(not UdpSocketState.rx_queued_bytes(rx), "closed socket gives None")


def main() raises:
    var failed = 0
    try:
        test_queue_grows_and_drains()
    except e:
        print("FAIL test_queue_grows_and_drains:", e)
        failed += 1
    try:
        test_closed_socket_is_none()
    except e:
        print("FAIL test_closed_socket_is_none:", e)
        failed += 1
    if failed:
        raise Error(String(failed) + " failed")
    print("PASS: test_udp_socket_rx_queued")
