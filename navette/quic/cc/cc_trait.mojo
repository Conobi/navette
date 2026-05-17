# src/quic/cc/trait.mojo
# Shared types + method-contract documentation for CC implementations.
# See specs/2026-04-15-m4a-quic-cc-core.md §3 for the full contract.

# --- Module-scope constants (RFC 9002 + spec §3.1) ---

comptime CC_KIND_CUBIC: UInt8 = 0
comptime CC_KIND_DUMMY: UInt8 = 1
# Reserved for M4b / later: CC_KIND_BBR = 2, CC_KIND_BBR3 = 3.

comptime MIN_WINDOW_PACKETS: UInt64 = 2            # RFC 9002 §7.2
comptime INITIAL_WINDOW_PACKETS: UInt64 = 10       # RFC 9002 §7.2
comptime INITIAL_WINDOW_BYTES_CAP: UInt64 = 14720  # RFC 9002 §7.2 (clamp on 10*MDS)
comptime LOSS_REDUCTION_NUM: UInt64 = 1            # 0.5 expressed as num/den for UInt64 math
comptime LOSS_REDUCTION_DEN: UInt64 = 2
comptime PERSISTENT_CONG_THRESHOLD: UInt64 = 3     # RFC 9002 §7.6.2

# Sentinel for Dummy CC's unlimited cwnd. Per Task 0 spike, UInt64.MAX works as a comptime initializer.
comptime UINT64_UNLIMITED: UInt64 = UInt64.MAX


# --- Shared value types ---

struct AckedPacket(ImplicitlyCopyable, Movable):
    """One newly-ACKed packet's information, passed from Connection to CC."""
    var pkt_num: UInt64
    var size: UInt64
    var time_sent: UInt64      # us
    var time_acked: UInt64     # us
    var rtt_sample: UInt64     # us, the RTT sample derived from this ACK

    def __init__(out self, pkt_num: UInt64, size: UInt64,
                 time_sent: UInt64, time_acked: UInt64, rtt_sample: UInt64):
        self.pkt_num = pkt_num
        self.size = size
        self.time_sent = time_sent
        self.time_acked = time_acked
        self.rtt_sample = rtt_sample


struct LostPacket(ImplicitlyCopyable, Movable):
    """One lost packet's information, passed from Connection to CC."""
    var pkt_num: UInt64
    var size: UInt64
    var time_sent: UInt64  # us

    def __init__(out self, pkt_num: UInt64, size: UInt64, time_sent: UInt64):
        self.pkt_num = pkt_num
        self.size = size
        self.time_sent = time_sent


# --- Method contract (every CC implementation provides) ---
# Documented here for reference; Mojo 0.26.2 does not have an interface keyword.
#
# cwnd(self) -> UInt64
#     Current congestion window, in bytes.
#
# pacing_rate(self, smoothed_rtt_us: UInt64) -> UInt64
#     Target pacing rate in bytes/sec. Returning 0 means unpaced.
#
# on_packet_sent(mut self, size: UInt64, pn: UInt64, now: UInt64)
#     Called when an in-flight packet leaves the host.
#     `pn` is the packet number; used by HyStart++ round tracking.
#
# on_packet_acked(mut self, packet: AckedPacket, smoothed_rtt_us: UInt64, now: UInt64)
#     Called once per newly-ACKed packet.
#
# on_packets_lost(mut self, lost: List[LostPacket], smoothed_rtt_us: UInt64,
#                 now: UInt64, persistent: Bool)
#     Called on loss detection. persistent=True means RFC 9002 §7.6 condition met;
#     CC MUST reset cwnd to min_cwnd.
#
# name(self) -> String
#     Used in logging / qlog.
