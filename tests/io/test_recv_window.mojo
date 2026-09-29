"""Receive-window arithmetic: the payload window is ≥ 1,472 B in both GRO modes and bounds the advertised size."""

from navette.runtime.udp_socket_state import (
    MIN_RECV_WINDOW,
    MAX_COALESCED_PAYLOAD,
    recv_payload_window,
    recv_buffer_size_for,
    advertised_max_udp_payload,
)
from bouclette.net.socket import Socket

from navette.runtime.udp_socket_state import UdpSocketState
from tests._test_util import assert_true, assert_equal_int

# The H3 server's delivery layout: sockaddr_in6 name, ECN + GRO control records.
comptime NAME = 28
comptime CONTROL = 48


def test_window_at_least_1472_both_modes() raises:
    for coalesced in [False, True]:
        var size = recv_buffer_size_for(coalesced, NAME, CONTROL)
        var w = recv_payload_window(size, NAME, CONTROL)
        assert_true(w >= MIN_RECV_WINDOW, "window >= 1472, coalesced=" + String(coalesced))
    assert_equal_int(
        recv_payload_window(recv_buffer_size_for(False, NAME, CONTROL), NAME, CONTROL),
        1472,
        "non-GRO buffers are sized exactly for 1472",
    )
    print("PASS: test_window_at_least_1472_both_modes")


def test_gro_window_holds_any_coalesced_delivery() raises:
    """GRO stops merging at a 65,536-byte IP packet, so a delivery carries at most 65,507 B (v4) / 65,487 B (v6).

    The old 65,535-byte buffer left a 65,443-byte window: 50 x 1,309-byte
    segments (65,450 B) came back MSG_TRUNC and were dropped whole.
    """
    var w = recv_payload_window(recv_buffer_size_for(True, NAME, CONTROL), NAME, CONTROL)
    assert_equal_int(w, MAX_COALESCED_PAYLOAD, "coalesced window is the full 16-bit payload")
    assert_true(w >= 65535, "window >= 65,535")
    assert_true(w >= 65507, "the largest IPv4 coalesced payload fits")
    assert_true(w >= 50 * 1309, "50 x 1,309-byte segments fit")
    assert_true(w >= 64 * 1023, "64 x 1,023-byte segments fit")
    print("PASS: test_gro_window_holds_any_coalesced_delivery")


def test_old_sizing_was_short() raises:
    """The pre-fix non-GRO buffer (MTU 1200 + 100 headroom) only held 1,208 B."""
    assert_equal_int(recv_payload_window(1300, NAME, CONTROL), 1208, "1300 - 16 - 28 - 48")
    print("PASS: test_old_sizing_was_short")


def test_advertised_is_min() raises:
    assert_true(advertised_max_udp_payload(UInt64(65527), 1472) == UInt64(1472), "clamped to the window")
    assert_true(advertised_max_udp_payload(UInt64(1350), 1472) == UInt64(1350), "a smaller configured value wins")
    print("PASS: test_advertised_is_min")


def test_disable_coalesced_recv_propagates_failure() raises:
    """A refused `set_gro(False)` raises and leaves the snapshot coalesced.

    Swallowing it would size single-datagram buffers on a socket that
    still merges. A TCP socket makes the kernel refuse (ENOPROTOOPT).
    """
    var udp = Socket.udp_v4()
    var state = UdpSocketState(udp)
    if not state.supports_coalesced_recv():
        print("SKIP: test_disable_coalesced_recv_propagates_failure (kernel lacks UDP_GRO)")
        return
    var tcp = Socket.tcp_v4()
    var raised = False
    try:
        state.disable_coalesced_recv(tcp)
    except:
        raised = True
    assert_true(raised, "set_gro(False) failure propagates")
    assert_true(state.supports_coalesced_recv(), "snapshot still reports GRO on")
    state.disable_coalesced_recv(udp)
    assert_true(not state.supports_coalesced_recv(), "a successful disable clears it")
    _ = udp^
    _ = tcp^
    print("PASS: test_disable_coalesced_recv_propagates_failure")


def main() raises:
    test_window_at_least_1472_both_modes()
    test_gro_window_holds_any_coalesced_delivery()
    test_old_sizing_was_short()
    test_advertised_is_min()
    test_disable_coalesced_recv_propagates_failure()
