# tests/test_cc_controller.mojo
# CcController tag-discriminated dispatcher tests per spec §9.3.

from mojo_net.quic.cc.controller import CcController
from mojo_net.quic.cc.cubic import Cubic
from mojo_net.quic.cc.dummy import DummyCc
from mojo_net.quic.cc.cc_trait import (
    AckedPacket, LostPacket,
    CC_KIND_DUMMY, CC_KIND_CUBIC, UINT64_UNLIMITED,
)
from std.testing import assert_true

comptime MDS: UInt64 = 1200


def test_dummy_cc_basic() raises:
    var d = DummyCc(max_datagram_size=MDS)
    assert_true(d.cwnd() == UINT64_UNLIMITED, "dummy cwnd unlimited")
    assert_true(d.pacing_rate(UInt64(100_000)) == UInt64(0), "dummy pacing 0")
    assert_true(d.name() == String("dummy"), "dummy name")
    print("PASS: test_dummy_cc_basic")


def test_controller_cubic_dispatch() raises:
    var ctrl = CcController.new_cubic(max_datagram_size=MDS)
    assert_true(ctrl.kind == CC_KIND_CUBIC, "kind is CUBIC")
    assert_true(ctrl.name() == String("cubic"), "name dispatch")
    var start = ctrl.cwnd()
    ctrl.on_packet_sent(size=MDS, pn=UInt64(1), now=UInt64(1000))
    assert_true(ctrl.cwnd() == start, "on_packet_sent doesn't change cwnd")
    print("PASS: test_controller_cubic_dispatch")


def test_controller_dummy_unlimited_cwnd() raises:
    var ctrl = CcController.new_dummy(max_datagram_size=MDS)
    assert_true(ctrl.kind == CC_KIND_DUMMY, "kind is DUMMY")
    assert_true(ctrl.cwnd() == UINT64_UNLIMITED, "dummy cwnd unlimited")
    print("PASS: test_controller_dummy_unlimited_cwnd")


def test_controller_dummy_no_op_acked() raises:
    var ctrl = CcController.new_dummy(max_datagram_size=MDS)
    var before_name = ctrl.name()
    var pkt = AckedPacket(pkt_num=1, size=MDS, time_sent=0, time_acked=1000, rtt_sample=1000)
    ctrl.on_packet_acked(pkt, smoothed_rtt_us=UInt64(1000), now=UInt64(1000))
    assert_true(ctrl.cwnd() == UINT64_UNLIMITED, "dummy cwnd still unlimited after ACK")
    assert_true(ctrl.name() == before_name, "name unchanged")
    print("PASS: test_controller_dummy_no_op_acked")


def test_controller_copy_preserves_variant() raises:
    var ctrl = CcController.new_cubic(max_datagram_size=MDS)
    # Mutate: trigger a congestion event so cwnd reduces.
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=1, size=MDS, time_sent=0))
    ctrl.on_packets_lost(lost, smoothed_rtt_us=UInt64(50_000), now=UInt64(100_000), persistent=False)
    var reduced = ctrl.cwnd()
    var ctrl2 = ctrl
    assert_true(ctrl2.kind == CC_KIND_CUBIC, "copy kind preserved")
    assert_true(ctrl2.cwnd() == reduced, "copy cwnd preserved")
    print("PASS: test_controller_copy_preserves_variant")


def test_controller_persistent_loss_resets_cubic() raises:
    var ctrl = CcController.new_cubic(max_datagram_size=MDS)
    # Grow cwnd via simulated ACKs.
    for i in range(50):
        var pkt = AckedPacket(pkt_num=UInt64(i), size=MDS,
                              time_sent=UInt64(i * 1000), time_acked=UInt64(i * 1000 + 500),
                              rtt_sample=UInt64(500))
        ctrl.on_packet_acked(pkt, smoothed_rtt_us=UInt64(500), now=UInt64(i * 1000 + 500))
    assert_true(ctrl.cwnd() > UInt64(2) * MDS, "cwnd grew past min before test")
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=1, size=MDS, time_sent=0))
    ctrl.on_packets_lost(lost, smoothed_rtt_us=UInt64(500), now=UInt64(100_000), persistent=True)
    assert_true(ctrl.cwnd() == UInt64(2) * MDS, "persistent loss through controller resets")
    print("PASS: test_controller_persistent_loss_resets_cubic")


def main() raises:
    test_dummy_cc_basic()
    test_controller_cubic_dispatch()
    test_controller_dummy_unlimited_cwnd()
    test_controller_dummy_no_op_acked()
    test_controller_copy_preserves_variant()
    test_controller_persistent_loss_resets_cubic()
    print("All controller tests passed.")
