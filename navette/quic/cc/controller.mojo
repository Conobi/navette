# src/quic/cc/controller.mojo
# Tag-discriminated CC variant dispatcher.
# Uses nested-Copyable struct fields plus a kind tag for variant dispatch.

from navette.quic.cc.cc_trait import (
    AckedPacket, LostPacket,
    CC_KIND_DUMMY, CC_KIND_CUBIC, UINT64_UNLIMITED,
)
from navette.quic.cc.dummy import DummyCc
from navette.quic.cc.cubic import Cubic


struct CcController(ImplicitlyCopyable, Movable):
    """Tag-discriminated dispatcher holding both Cubic and DummyCc variants."""
    var kind: UInt8
    var dummy: DummyCc
    var cubic: Cubic

    def __init__(out self, kind: UInt8, dummy: DummyCc, cubic: Cubic):
        self.kind = kind
        self.dummy = dummy
        self.cubic = cubic

    @staticmethod
    def new_cubic(max_datagram_size: UInt64) -> CcController:
        return CcController(
            kind=CC_KIND_CUBIC,
            dummy=DummyCc(max_datagram_size=max_datagram_size),
            cubic=Cubic(max_datagram_size=max_datagram_size),
        )

    @staticmethod
    def new_dummy(max_datagram_size: UInt64) -> CcController:
        return CcController(
            kind=CC_KIND_DUMMY,
            dummy=DummyCc(max_datagram_size=max_datagram_size),
            cubic=Cubic(max_datagram_size=max_datagram_size),
        )

    def cwnd(self) -> UInt64:
        if self.kind == CC_KIND_CUBIC:
            return self.cubic.cwnd()
        return UINT64_UNLIMITED

    def pacing_rate(self, smoothed_rtt_us: UInt64) -> UInt64:
        if self.kind == CC_KIND_CUBIC:
            return self.cubic.pacing_rate(smoothed_rtt_us)
        return UInt64(0)

    def on_packet_sent(mut self, size: UInt64, pn: UInt64, now: UInt64):
        if self.kind == CC_KIND_CUBIC:
            self.cubic.on_packet_sent(size, pn, now)

    def on_packet_acked(mut self, packet: AckedPacket, smoothed_rtt_us: UInt64, now: UInt64):
        if self.kind == CC_KIND_CUBIC:
            self.cubic.on_packet_acked(packet, smoothed_rtt_us, now)

    def on_packets_lost(mut self, lost: List[LostPacket], smoothed_rtt_us: UInt64,
                        now: UInt64, persistent: Bool):
        if self.kind == CC_KIND_CUBIC:
            self.cubic.on_packets_lost(lost, smoothed_rtt_us, now, persistent)

    def on_congestion_event(mut self, smoothed_rtt: UInt64, now: UInt64):
        """ECN CE congestion signal. Reduces cwnd without persistent-congestion logic."""
        if self.kind == CC_KIND_CUBIC:
            self.cubic._on_congestion_event(smoothed_rtt, now)
        # DummyCc: no-op.

    def name(self) -> String:
        if self.kind == CC_KIND_CUBIC:
            return String("cubic")
        return String("dummy")
