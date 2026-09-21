"""UDP socket transport-capability state.

Probes kernel support for datagram coalescing (UDP_GRO) and segmentation
offload (UDP_SEGMENT) at socket creation time, and records the results
so the QUIC transport can size its send/recv buffers and decide whether
to batch datagrams without re-probing on every I/O cycle.

Capabilities degrade gracefully: unsupported features are silently
disabled rather than raising.
"""

from bouclette.net.socket import Socket


# Linux UDP_MAX_SEGMENTS (include/uapi/linux/udp.h).
comptime _MAX_SEGMENTS: Int = 64

# QUIC minimum MTU (RFC 9000 Section 14).
comptime _QUIC_MIN_MTU: Int = 1200

# Large recv buffer for coalesced datagrams (64 segments * 1500 bytes,
# rounded to a 256 KiB boundary that the kernel will clamp to rmem_max).
comptime _COALESCED_RECV_BUF: Int = 65535 * 4


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

    def __init__(out self, *, deinit move: Self):
        self._coalesced_recv = move._coalesced_recv
        self._max_segments = move._max_segments
        self._mtu = move._mtu

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

    def recv_buffer_size(self) -> Int:
        """Minimum recv buffer to avoid truncation.

        65535 when coalesced receive is active (one coalesced delivery
        can span up to 64 segments); MTU + headroom otherwise.
        """
        if self._coalesced_recv:
            return 65535
        return self._mtu + 100

    def downgrade_send_segments(mut self):
        """Permanently disable segmentation offload.

        Called when a segmented send fails at runtime, so subsequent
        sends fall back to one-datagram-per-syscall.
        """
        self._max_segments = 1
