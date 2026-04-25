# src/quic/profile.mojo
#
# QUIC accept-loop profile module (Plan A).
#
# Provides AcceptProfile (counter struct + report formatters), monotonic_us
# (sans-I/O CLOCK_MONOTONIC wrapper), and PROFILE_ACCEPT (comptime opt-in).
#
# Hand-edit PROFILE_ACCEPT to True to produce a profile build (see Plan B
# for how this gates instrumentation in connection.mojo + bench/h3_server.mojo).

from std.ffi import external_call
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc


comptime PROFILE_ACCEPT: Bool = False
comptime _CLOCK_MONOTONIC: Int32 = 1


def monotonic_us() -> UInt64:
    """clock_gettime(CLOCK_MONOTONIC) → microseconds. Sans-I/O."""
    # struct timespec: tv_sec(i64) + tv_nsec(i64) = 16 bytes
    var ts = alloc[UInt8](16).as_any_origin()
    for i in range(16):
        ts[i] = 0
    _ = external_call["clock_gettime", Int32](_CLOCK_MONOTONIC, ts)
    var tv_sec = UInt64(0)
    for i in range(8):
        tv_sec = tv_sec | (UInt64(ts[i]) << UInt64(i * 8))
    var tv_nsec = UInt64(0)
    for i in range(8):
        tv_nsec = tv_nsec | (UInt64(ts[8 + i]) << UInt64(i * 8))
    ts.free()
    return tv_sec * 1_000_000 + tv_nsec / 1_000


struct AcceptProfile(Copyable, Movable):
    var run_start_us: UInt64

    var idle_us_total: UInt64
    var busy_us_total: UInt64
    var on_flush_count: UInt64

    var pkts_per_flush_buckets: List[UInt64]   # len = 8

    var ffi_shim_us_total: UInt64
    var hp_us_total: UInt64
    var aead_us_total: UInt64
    var header_parse_us_total: UInt64
    var frame_parse_us_total: UInt64
    var sm_us_total: UInt64
    var drain_us_total: UInt64
    var residual_us_total: UInt64
    var pkt_count: UInt64

    var per_pkt_total_buckets: List[UInt64]    # len = 24
    var per_pkt_total_overflow: UInt64

    var hs_arrivals: UInt64
    var hs_completed: UInt64
    var hs_timed_out: UInt64
    var hs_latency_us: List[UInt64]

    def __init__(out self):
        self.run_start_us = monotonic_us()
        self.idle_us_total = UInt64(0)
        self.busy_us_total = UInt64(0)
        self.on_flush_count = UInt64(0)
        self.pkts_per_flush_buckets = List[UInt64]()
        for _ in range(8):
            self.pkts_per_flush_buckets.append(UInt64(0))
        self.ffi_shim_us_total = UInt64(0)
        self.hp_us_total = UInt64(0)
        self.aead_us_total = UInt64(0)
        self.header_parse_us_total = UInt64(0)
        self.frame_parse_us_total = UInt64(0)
        self.sm_us_total = UInt64(0)
        self.drain_us_total = UInt64(0)
        self.residual_us_total = UInt64(0)
        self.pkt_count = UInt64(0)
        self.per_pkt_total_buckets = List[UInt64]()
        for _ in range(24):
            self.per_pkt_total_buckets.append(UInt64(0))
        self.per_pkt_total_overflow = UInt64(0)
        self.hs_arrivals = UInt64(0)
        self.hs_completed = UInt64(0)
        self.hs_timed_out = UInt64(0)
        self.hs_latency_us = List[UInt64]()

    def record_idle(mut self, idle_us: UInt64):
        self.idle_us_total += idle_us

    def record_flush(mut self, pkts: Int, busy_us: UInt64):
        self.on_flush_count += UInt64(1)
        self.busy_us_total += busy_us
        var b = _pkts_per_flush_bucket(pkts)
        self.pkts_per_flush_buckets[b] += UInt64(1)

    def record_pkt(
        mut self,
        *,
        total_us: UInt64,
        ffi_us: UInt64,
        hp_us: UInt64,
        aead_us: UInt64,
        header_parse_us: UInt64,
        frame_parse_us: UInt64,
        sm_us: UInt64,
    ):
        self.pkt_count += UInt64(1)
        self.ffi_shim_us_total += ffi_us
        self.hp_us_total += hp_us
        self.aead_us_total += aead_us
        self.header_parse_us_total += header_parse_us
        self.frame_parse_us_total += frame_parse_us
        self.sm_us_total += sm_us

        # residual = total - (hp + aead + header_parse + frame_parse + sm)
        # ffi NOT subtracted (overlaps sm). Clamp to 0 on underflow.
        var legs_sum = hp_us + aead_us + header_parse_us + frame_parse_us + sm_us
        if total_us >= legs_sum:
            self.residual_us_total += (total_us - legs_sum)

        var b = _per_pkt_bucket(total_us)
        if b >= 24:
            self.per_pkt_total_overflow += UInt64(1)
        else:
            self.per_pkt_total_buckets[b] += UInt64(1)


fn _pkts_per_flush_bucket(pkts: Int) -> Int:
    """Map fan-out count to bucket index 0..7. Buckets [1,2-3,4-7,...,128+]."""
    if pkts <= 1: return 0
    if pkts <= 3: return 1
    if pkts <= 7: return 2
    if pkts <= 15: return 3
    if pkts <= 31: return 4
    if pkts <= 63: return 5
    if pkts <= 127: return 6
    return 7


fn _per_pkt_bucket(us: UInt64) -> Int:
    """Map us to bucket 0..23 or 24 (overflow). bucket[0]={0}; bucket[i]=[2^(i-1), 2^i) for 1<=i<=23; overflow=24 for us>=2^23."""
    if us == UInt64(0):
        return 0
    if us >= UInt64(8_388_608):  # 2^23
        return 24
    var v = us
    var i = 0
    while v >= UInt64(1):
        v = v >> UInt64(1)
        i += 1
    return i  # floor(log2(us)) + 1 for us > 0
