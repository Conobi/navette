"""UDP socket transport-capability state.

Probes kernel support for datagram coalescing (UDP_GRO) and segmentation
offload (UDP_SEGMENT) at socket creation time, and records the results
so the QUIC transport can size its send/recv buffers and decide whether
to batch datagrams without re-probing on every I/O cycle.

Capabilities degrade gracefully: unsupported features are silently
disabled rather than raising.
"""

from bouclette.net.message import DELIVERY_HEADER_LEN
from bouclette.net.socket import Socket


# Linux UDP_MAX_SEGMENTS (include/uapi/linux/udp.h).
comptime _MAX_SEGMENTS: Int = 64

# QUIC minimum MTU (RFC 9000 Section 14).
comptime _QUIC_MIN_MTU: Int = 1200

# Large recv buffer for coalesced datagrams (64 segments * 1500 bytes,
# rounded to a 256 KiB boundary that the kernel will clamp to rmem_max).
comptime _COALESCED_RECV_BUF: Int = 65535 * 4

# Smallest UDP payload every receive buffer must hold: a full 1500-byte
# Ethernet MTU minus the IPv4 (20) and UDP (8) headers.
comptime MIN_RECV_WINDOW: Int = 1472

# Payload window every coalesced receive buffer must hold. GRO stops
# merging once the IP packet would reach 65,536 bytes (`skb_gro_receive`
# against `gro_max_size`), so a delivery carries at most 65,507 B of UDP
# payload over IPv4 and 65,487 B over IPv6; 65,535 covers both.
comptime MAX_COALESCED_PAYLOAD: Int = 65535


def recv_payload_window(buffer_size: Int, name_capacity: Int, control_capacity: Int) -> Int:
    """Largest datagram payload one multishot recvmsg buffer can carry untruncated.

    Each delivery is laid out as the 16-byte `io_uring_recvmsg_out`
    header, then the peer name, then the control region, then the
    payload; only what remains after the first three is payload.
    """
    return buffer_size - DELIVERY_HEADER_LEN - name_capacity - control_capacity


def recv_buffer_size_for(coalesced: Bool, name_capacity: Int, control_capacity: Int) -> Int:
    """BufferPool entry size whose payload window is `MAX_COALESCED_PAYLOAD` with GRO, `MIN_RECV_WINDOW` without.

    A delivery that overflows the window comes back MSG_TRUNC and is
    dropped whole, so with GRO the window must hold the largest merge.
    """
    var window = MAX_COALESCED_PAYLOAD if coalesced else MIN_RECV_WINDOW
    return window + DELIVERY_HEADER_LEN + name_capacity + control_capacity


def advertised_max_udp_payload(configured: UInt64, window: Int) -> UInt64:
    """`max_udp_payload_size` to advertise: never more than the receive window (RFC 9000 Section 18.2)."""
    return min(configured, UInt64(window))


struct UdpSocketState(Movable):
    """Transport capability snapshot taken once at socket creation.

    Probes UDP_GRO and UDP_SEGMENT on the given socket, then exposes
    the results through a vocabulary that hides the kernel option names
    ("coalesce" / "segments") so the public API carries no platform
    constants.
    """

    var _coalesced_recv: Bool
    var _max_segments: Int
    var _mtu: Int

    def __init__(out self, ref socket: Socket):
        """Probe transport capabilities on `socket`.

        Enables ECN mark delivery unconditionally. Coalesced receive
        and segmentation offload are best-effort: failure to set either
        option simply disables that path rather than raising.
        """
        self._coalesced_recv = False
        self._max_segments = 0
        self._mtu = _QUIC_MIN_MTU

        # ECN: enable TOS/traffic-class delivery in cmsgs.
        try:
            socket.set_recv_tos(True)
        except:
            pass

        # UDP_GRO: let the kernel coalesce consecutive datagrams.
        try:
            socket.set_gro(True)
            self._coalesced_recv = True
        except:
            pass

        # UDP_SEGMENT: enable segmentation offload.
        try:
            socket.set_gso_segment_size(UInt16(_QUIC_MIN_MTU))
            self._max_segments = _MAX_SEGMENTS
        except:
            pass

        # Enlarge the recv buffer for coalesced datagrams.
        if self._coalesced_recv:
            try:
                socket.set_recv_buffer_size(_COALESCED_RECV_BUF)
            except:
                pass

    def max_send_segments(self) -> Int:
        """Maximum datagrams the kernel can segment from a single send.

        Returns 1 when segmentation offload is unavailable or has been
        downgraded after a send failure.
        """
        return self._max_segments if self._max_segments > 0 else 1

    def supports_coalesced_recv(self) -> Bool:
        """True when the kernel will coalesce consecutive datagrams."""
        return self._coalesced_recv

    def send_buffer_size(self) -> Int:
        """Largest payload a single segmented send can carry."""
        return self.max_send_segments() * self._mtu

    def recv_buffer_size(self, name_capacity: Int, control_capacity: Int) -> Int:
        """BufferPool entry size for the probed GRO mode; see `recv_buffer_size_for`."""
        return recv_buffer_size_for(self._coalesced_recv, name_capacity, control_capacity)

    def disable_coalesced_recv(mut self, ref socket: Socket) raises:
        """Turn GRO off on `socket` and in this snapshot; tests use it to pin the non-coalesced path.

        Raises if the kernel refuses, leaving the snapshot coalesced: a
        snapshot claiming GRO is off while the socket still merges would
        size single-datagram buffers and drop every coalesced delivery.
        """
        socket.set_gro(False)
        self._coalesced_recv = False

    def downgrade_send_segments(mut self):
        """Permanently disable segmentation offload.

        Called when a segmented send fails at runtime, so subsequent
        sends fall back to one-datagram-per-syscall.
        """
        self._max_segments = 1
