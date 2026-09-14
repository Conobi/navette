# src/quic/cc/controller.mojo
# Tag-discriminated CC variant dispatcher using Variant.

from std.utils import Variant

from navette.quic.cc.cc_trait import (
    AckedPacket, LostPacket,
    UINT64_UNLIMITED,
)
from navette.quic.cc.dummy import DummyCc
from navette.quic.cc.cubic import Cubic


struct CcController(ImplicitlyCopyable, Movable):
    """Tag-discriminated CC variant dispatcher using Variant."""
    var cc: Variant[DummyCc, Cubic]

    def __init__(out self, var cc: Variant[DummyCc, Cubic]):
        self.cc = cc^

    @staticmethod
    def new_cubic(max_datagram_size: UInt64) -> CcController:
        return CcController(
            Variant[DummyCc, Cubic](Cubic(max_datagram_size=max_datagram_size))
        )

    @staticmethod
    def new_dummy(max_datagram_size: UInt64) -> CcController:
        return CcController(
            Variant[DummyCc, Cubic](DummyCc(max_datagram_size=max_datagram_size))
        )

    def cwnd(self) -> UInt64:
        if self.cc.isa[Cubic]():
            return self.cc.unsafe_get[Cubic]().cwnd()
        return UINT64_UNLIMITED

    def pacing_rate(self, smoothed_rtt_us: UInt64) -> UInt64:
        if self.cc.isa[Cubic]():
            return self.cc.unsafe_get[Cubic]().pacing_rate(smoothed_rtt_us)
        return UInt64(0)

    def on_packet_sent(mut self, size: UInt64, pn: UInt64, now: UInt64):
        if self.cc.isa[Cubic]():
            self.cc.unsafe_get[Cubic]().on_packet_sent(size, pn, now)

    def on_packet_acked(mut self, packet: AckedPacket, smoothed_rtt_us: UInt64, now: UInt64):
        if self.cc.isa[Cubic]():
            self.cc.unsafe_get[Cubic]().on_packet_acked(packet, smoothed_rtt_us, now)

    def on_packets_lost(mut self, lost: List[LostPacket], smoothed_rtt_us: UInt64,
                        now: UInt64, persistent: Bool):
        if self.cc.isa[Cubic]():
            self.cc.unsafe_get[Cubic]().on_packets_lost(lost, smoothed_rtt_us, now, persistent)

    def on_congestion_event(mut self, smoothed_rtt: UInt64, now: UInt64):
        """ECN CE congestion signal. Reduces cwnd without persistent-congestion logic."""
        if self.cc.isa[Cubic]():
            self.cc.unsafe_get[Cubic]()._on_congestion_event(smoothed_rtt, now)

    def name(self) -> String:
        if self.cc.isa[Cubic]():
            return String("cubic")
        return String("dummy")
