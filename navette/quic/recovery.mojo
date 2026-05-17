# src/quic/recovery.mojo
# QUIC loss detection and congestion control — RFC 9002.
# RTT estimation, loss detection, and PTO computation.

from navette.quic.cc.controller import CcController
from navette.quic.cc.pacing import Pacer
from navette.quic.cc.cc_trait import AckedPacket, LostPacket

# ── Constants (RFC 9002 §6) ─────────────────────────────────────────────

comptime K_PACKET_THRESHOLD: Int = 3
comptime K_GRANULARITY: UInt64 = 1000  # 1ms in microseconds
comptime K_TIME_THRESHOLD_NUM: UInt64 = 9
comptime K_TIME_THRESHOLD_DEN: UInt64 = 8
comptime INITIAL_RTT: UInt64 = 333_000  # 333ms in microseconds
comptime INITIAL_RTTVAR: UInt64 = 166_500  # 333ms / 2


# ── Recovery struct ─────────────────────────────────────────────────────


struct Recovery(Movable):
    """QUIC recovery state: RTT estimation, loss detection, PTO, CC, and pacing."""

    var smoothed_rtt: UInt64  # Microseconds, init = INITIAL_RTT
    var rttvar: UInt64  # Microseconds, init = INITIAL_RTTVAR
    var min_rtt: UInt64  # Microseconds, init = 0 (no sample yet)
    var latest_rtt: UInt64  # Most recent RTT sample
    var bytes_in_flight: UInt64  # Total in-flight bytes
    var pto_count: Int  # Exponential backoff counter
    var has_rtt_sample: Bool  # False until first ACK
    var cc: CcController  # Congestion controller (Cubic or Dummy)
    var pacer: Pacer  # Token-bucket pacer

    def __init__(out self, max_datagram_size: UInt64 = UInt64(1200), use_cubic: Bool = True):
        """Create a Recovery instance.

        Args:
            max_datagram_size: Max datagram size in bytes (default 1200).
                               Callers that used Recovery() continue to work unchanged.
            use_cubic: If True (default), use CUBIC CC. If False, use Dummy CC.
                       Task 8/9 callers will thread max_datagram_size and now properly.
        """
        self.smoothed_rtt = INITIAL_RTT
        self.rttvar = INITIAL_RTTVAR
        self.min_rtt = UInt64(0)
        self.latest_rtt = UInt64(0)
        self.bytes_in_flight = UInt64(0)
        self.pto_count = 0
        self.has_rtt_sample = False
        if use_cubic:
            self.cc = CcController.new_cubic(max_datagram_size)
        else:
            self.cc = CcController.new_dummy(max_datagram_size)
        self.pacer = Pacer.new(max_datagram_size)

    def __init__(out self, *, deinit take: Self):
        self.smoothed_rtt = take.smoothed_rtt
        self.rttvar = take.rttvar
        self.min_rtt = take.min_rtt
        self.latest_rtt = take.latest_rtt
        self.bytes_in_flight = take.bytes_in_flight
        self.pto_count = take.pto_count
        self.has_rtt_sample = take.has_rtt_sample
        self.cc = take.cc
        self.pacer = take.pacer

    # ── RTT estimation (RFC 9002 §5) ────────────────────────────────────

    def update_rtt(
        mut self,
        rtt_sample: UInt64,
        ack_delay: UInt64,
        max_ack_delay: UInt64,
        handshake_confirmed: Bool,
    ):
        """Update RTT estimates from a new ACK-derived sample.

        Implements RFC 9002 §5.3 with erratum #7539: rttvar is computed
        using the OLD smoothed_rtt before smoothed_rtt is updated.
        """
        self.latest_rtt = rtt_sample

        # First sample — use directly as baseline.
        if not self.has_rtt_sample:
            self.smoothed_rtt = rtt_sample
            self.rttvar = rtt_sample // 2
            self.min_rtt = rtt_sample
            self.has_rtt_sample = True
            return

        # Update min_rtt (never increases once set).
        if rtt_sample < self.min_rtt:
            self.min_rtt = rtt_sample

        # Determine adjusted ack_delay.
        var adj_ack_delay: UInt64
        if handshake_confirmed:
            adj_ack_delay = ack_delay
            if adj_ack_delay > max_ack_delay:
                adj_ack_delay = max_ack_delay
        else:
            adj_ack_delay = UInt64(0)  # Ignore ack_delay before handshake

        # Compute adjusted RTT.
        var adjusted_rtt = rtt_sample
        if rtt_sample >= self.min_rtt + adj_ack_delay:
            adjusted_rtt = rtt_sample - adj_ack_delay

        # CRITICAL: rttvar BEFORE smoothed_rtt (erratum #7539).
        var rttvar_sample: UInt64
        if adjusted_rtt > self.smoothed_rtt:
            rttvar_sample = adjusted_rtt - self.smoothed_rtt
        else:
            rttvar_sample = self.smoothed_rtt - adjusted_rtt
        self.rttvar = (3 * self.rttvar + rttvar_sample) // 4
        self.smoothed_rtt = (7 * self.smoothed_rtt + adjusted_rtt) // 8

    # ── Packet bookkeeping ──────────────────────────────────────────────

    def on_packet_sent(mut self, size: Int, in_flight: Bool,
                       pn: UInt64 = UInt64(0), now: UInt64 = UInt64(0)):
        """Track bytes when a packet is sent and notify CC.

        `pn` defaults to 0 for backward compatibility with existing call sites.
        `connection.mojo` (Task 6) will pass the real PN.
        Note: pacer.on_sent is called at the actual send site by connection.mojo,
        not here, since the connection controls the send path.
        """
        if in_flight:
            self.bytes_in_flight += UInt64(size)
            self.cc.on_packet_sent(UInt64(size), pn, now)

    def on_packet_acked(mut self, size: Int, in_flight: Bool):
        """Release bytes when a packet is acknowledged."""
        if in_flight:
            var s = UInt64(size)
            if s > self.bytes_in_flight:
                self.bytes_in_flight = 0
            else:
                self.bytes_in_flight -= s

    def on_packet_lost(mut self, size: Int, in_flight: Bool):
        """Release bytes when a packet is declared lost."""
        if in_flight:
            var s = UInt64(size)
            if s > self.bytes_in_flight:
                self.bytes_in_flight = 0
            else:
                self.bytes_in_flight -= s

    def on_ack_received(mut self):
        """Reset PTO backoff on ACK receipt and refresh pacer capacity.

        CC.on_packet_acked fan-out is called by connection.mojo (Task 9),
        which iterates sent_packets to build AckedPacket records.
        Here we just reset PTO and sync the pacer with current CC state.
        """
        self.pto_count = 0
        # Refresh pacer capacity to reflect any cwnd change from CC ACK processing.
        self.pacer.update_capacity(self.cc.cwnd(), self.smoothed_rtt)

    # ── Loss delay and PTO (RFC 9002 §6) ────────────────────────────────

    def loss_delay(self) -> UInt64:
        """Compute time threshold for declaring a packet lost."""
        var base = self.smoothed_rtt
        if self.latest_rtt > base:
            base = self.latest_rtt
        var delay = (K_TIME_THRESHOLD_NUM * base) // K_TIME_THRESHOLD_DEN
        if delay < K_GRANULARITY:
            delay = K_GRANULARITY
        return delay

    def pto_timeout(self, max_ack_delay: UInt64) -> UInt64:
        """Compute probe timeout including exponential backoff."""
        var pto = self.smoothed_rtt
        var four_rttvar = 4 * self.rttvar
        if four_rttvar < K_GRANULARITY:
            four_rttvar = K_GRANULARITY
        pto += four_rttvar + max_ack_delay
        # Exponential backoff: pto * 2^pto_count.
        pto = pto << UInt64(self.pto_count)
        return pto

    # ── Loss detection (RFC 9002 §6.1) ──────────────────────────────────

    def detect_lost_packets(
        self,
        sent_pns: List[Int],
        sent_times: List[UInt64],
        sent_in_flight: List[Bool],
        largest_acked_pn: Int,
        now: UInt64,
    ) -> List[Int]:
        """Return packet numbers that should be declared lost.

        Uses both packet-threshold and time-threshold criteria.
        """
        var lost = List[Int]()
        var ld = self.loss_delay()
        for i in range(len(sent_pns)):
            var pn = sent_pns[i]
            if pn > largest_acked_pn:
                continue  # Not yet ackable
            # Packet threshold: gap >= K_PACKET_THRESHOLD.
            if largest_acked_pn - pn >= K_PACKET_THRESHOLD:
                lost.append(pn)
                continue
            # Time threshold.
            if now >= sent_times[i] + ld:
                lost.append(pn)
        return lost^
