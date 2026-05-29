# tests/test_interop_udp.mojo
#
# Unit tests for interop/udp.mojo
# Run with: uv run mojo run -I . tests/test_interop_udp.mojo

from interop.udp import (
    udp_bind,
    udp_recvfrom,
    udp_sendto,
    udp_poll,
    udp_connect,
    monotonic_us,
    udp_close,
)
from tests._test_util import assert_true, assert_equal_int


# ── test_bind_close ──────────────────────────────────────────────────────────


def test_bind_close() raises:
    var fd = udp_bind(19876)
    assert_true(Int(fd) > 0, "udp_bind returned valid fd")
    udp_close(fd)
    print("PASS test_bind_close")


# ── test_poll_timeout ────────────────────────────────────────────────────────


def test_poll_timeout() raises:
    var fd = udp_bind(19877)
    var ready = udp_poll(fd, 10)
    assert_true(not ready, "poll should return False with no data pending")
    udp_close(fd)
    print("PASS test_poll_timeout")


# ── test_monotonic_us ────────────────────────────────────────────────────────


def test_monotonic_us() raises:
    var t1 = monotonic_us()
    var t2 = monotonic_us()
    assert_true(t2 >= t1, "monotonic_us should be non-decreasing")
    assert_true(t1 > 0, "monotonic_us should be positive")
    print("PASS test_monotonic_us")


# ── test_bind_and_sendto_recvfrom ────────────────────────────────────────────


def test_bind_and_sendto_recvfrom() raises:
    # Bind a server socket
    var srv_fd = udp_bind(19878)

    # Connect a client socket to the server
    var cli_fd = udp_connect("127.0.0.1", 19878)

    # Send "hello" from client via send (connected socket)
    var msg = List[UInt8]()
    # h=104, e=101, l=108, l=108, o=111
    msg.append(104)
    msg.append(101)
    msg.append(108)
    msg.append(108)
    msg.append(111)
    var msg_buf = alloc[UInt8](5).as_any_origin()
    for i in range(5):
        msg_buf[i] = msg[i]
    var n = external_call["send", Int](cli_fd, msg_buf, Int(5), Int32(0))
    msg_buf.free()
    assert_true(n == 5, "send returned 5 bytes")

    # Poll the server socket to ensure data arrived
    var ready = udp_poll(srv_fd, 1000)
    assert_true(ready, "poll should indicate data ready")

    # Receive on server
    var result = udp_recvfrom(srv_fd)
    var data = result[0].copy()
    var addr_bytes = result[1].copy()
    assert_equal_int(len(data), 5, "received 5 bytes")
    assert_equal_int(Int(data[0]), 104, "byte 0 = 'h'")
    assert_equal_int(Int(data[1]), 101, "byte 1 = 'e'")
    assert_equal_int(Int(data[2]), 108, "byte 2 = 'l'")
    assert_equal_int(Int(data[3]), 108, "byte 3 = 'l'")
    assert_equal_int(Int(data[4]), 111, "byte 4 = 'o'")

    # addr_bytes should be 28 bytes (sockaddr_in6). interop/udp.mojo went
    # dual-stack — see _ADDR_SIZE in interop/udp.mojo — so every recvfrom
    # address buffer is sized for IPv6 even when the underlying transport
    # is IPv4-mapped.
    assert_equal_int(len(addr_bytes), 28, "addr is 28 bytes (sockaddr_in6)")

    udp_close(cli_fd)
    udp_close(srv_fd)
    print("PASS test_bind_and_sendto_recvfrom")


# ── main ─────────────────────────────────────────────────────────────────────

from std.ffi import external_call
from std.memory.unsafe_pointer import alloc
from std.memory import UnsafePointer


def main() raises:
    test_bind_close()
    test_poll_timeout()
    test_monotonic_us()
    test_bind_and_sendto_recvfrom()
    print("All tests passed.")
