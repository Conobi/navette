# src/quic/cc/dummy.mojo
# No-op CC. Used by tests that don't want CC dynamics to interfere.
# All ops are no-ops; cwnd reports unlimited; pacing_rate reports 0 (pacer disabled).

from src.quic.cc.cc_trait import AckedPacket, LostPacket, UINT64_UNLIMITED


struct DummyCc(ImplicitlyCopyable, Movable):
    """No-op congestion controller. cwnd always returns UINT64_UNLIMITED."""
    var max_datagram_size: UInt64

    def __init__(out self, max_datagram_size: UInt64):
        self.max_datagram_size = max_datagram_size

    def cwnd(self) -> UInt64:
        return UINT64_UNLIMITED

    def pacing_rate(self, smoothed_rtt_us: UInt64) -> UInt64:
        return UInt64(0)

    def on_packet_sent(mut self, size: UInt64, pn: UInt64, now: UInt64):
        pass

    def on_packet_acked(mut self, packet: AckedPacket, smoothed_rtt_us: UInt64, now: UInt64):
        pass

    def on_packets_lost(mut self, lost: List[LostPacket], smoothed_rtt_us: UInt64,
                        now: UInt64, persistent: Bool):
        pass

    def name(self) -> String:
        return String("dummy")
