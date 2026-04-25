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


comptime PROFILE_ACCEPT: Bool = False
comptime _CLOCK_MONOTONIC: Int32 = 1


fn monotonic_us() -> UInt64:
    """clock_gettime(CLOCK_MONOTONIC) → microseconds. Sans-I/O.

    Uses a stack-allocated InlineArray[Int64, 2] for the timespec to avoid
    the heap-alloc + free that previously fired on every call. Plan B fires
    monotonic_us() many times per packet on the QUIC handshake hot path, so
    the per-call fixed cost matters for the ≤10% on-build overhead budget.
    """
    var ts = InlineArray[Int64, 2](fill=0)
    var ts_ptr = UnsafePointer(to=ts).bitcast[UInt8]()
    _ = external_call["clock_gettime", Int32](_CLOCK_MONOTONIC, ts_ptr)
    var tv_sec = UInt64(ts[0])
    var tv_nsec = UInt64(ts[1])
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

    def record_drain(mut self, drain_us: UInt64):
        self.drain_us_total += drain_us

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

    def record_handshake_arrival(mut self):
        self.hs_arrivals += UInt64(1)

    def record_handshake_complete(mut self, latency_us: UInt64):
        self.hs_completed += UInt64(1)
        self.hs_latency_us.append(latency_us)

    def record_handshake_timeout(mut self, count: UInt64 = UInt64(1)):
        self.hs_timed_out += count

    def report_text(self) -> String:
        var now = monotonic_us()
        var run_us = now - self.run_start_us
        var n_closed = self.pkt_count - self.per_pkt_total_overflow

        var s = String("=== mojo-net QUIC accept-loop profile ===\n")
        s += "Run wall-clock:           " + _fmt_duration_us(run_us) + "\n"
        s += "On_flush events:          " + _fmt_count(self.on_flush_count) + "\n"
        s += "  Idle (boucle wait):     " + _fmt_duration_us(self.idle_us_total)
        s += "  " + _fmt_pct(self.idle_us_total, self.idle_us_total + self.busy_us_total) + "\n"
        s += "  Busy (in loop):         " + _fmt_duration_us(self.busy_us_total)
        s += "  " + _fmt_pct(self.busy_us_total, self.idle_us_total + self.busy_us_total) + "\n\n"

        s += "Datagrams batched per flush (approx. CQE multishot batching):\n"
        var labels = List[String]()
        labels.append(String("size=1     "))
        labels.append(String("size=2-3   "))
        labels.append(String("size=4-7   "))
        labels.append(String("size=8-15  "))
        labels.append(String("size=16-31 "))
        labels.append(String("size=32-63 "))
        labels.append(String("size=64-127"))
        labels.append(String("size=128+  "))
        for i in range(8):
            var c = self.pkts_per_flush_buckets[i]
            s += "  " + labels[i] + " " + _fmt_count(c)
            if c > UInt64(0):
                s += "  " + _fmt_pct(c, self.on_flush_count)
            s += "\n"
        s += "\n"

        s += "Per-packet wall-clock (bucket-estimated p_n, us):\n"
        var p50 = _bucket_percentile(self.per_pkt_total_buckets, n_closed, 50.0)
        var p90 = _bucket_percentile(self.per_pkt_total_buckets, n_closed, 90.0)
        var p99 = _bucket_percentile(self.per_pkt_total_buckets, n_closed, 99.0)
        s += "  total:           p50=" + String(p50) + "  p90=" + String(p90) + "  p99=" + String(p99)
        s += "  (n=" + String(n_closed) + ", overflow=" + String(self.per_pkt_total_overflow) + ")\n"
        s += "  " + _fmt_leg("header parse",  self.header_parse_us_total, self.pkt_count) + "\n"
        s += "  " + _fmt_leg("HP unprotect",  self.hp_us_total,            self.pkt_count) + "\n"
        s += "  " + _fmt_leg("AEAD decrypt",  self.aead_us_total,          self.pkt_count) + "\n"
        s += "  " + _fmt_leg("frame parse",   self.frame_parse_us_total,   self.pkt_count) + "\n"
        s += "  " + _fmt_leg("state machine", self.sm_us_total,            self.pkt_count) + "\n"
        s += "  " + _fmt_leg("residual",      self.residual_us_total,      self.pkt_count) + "\n"
        s += "  " + _fmt_leg("shim FFI",      self.ffi_shim_us_total,      self.pkt_count) + "\n"
        s += "  " + _fmt_leg("drain (bench)", self.drain_us_total,         self.pkt_count) + "\n\n"

        s += "Handshake accounting:\n"
        s += "  Arrivals:                  " + _fmt_count(self.hs_arrivals) + "\n"
        s += "  Successful:                " + _fmt_count(self.hs_completed)
        s += "  " + _fmt_pct(self.hs_completed, self.hs_arrivals) + "\n"
        s += "  Timed out:                 " + _fmt_count(self.hs_timed_out)
        s += "  " + _fmt_pct(self.hs_timed_out, self.hs_arrivals) + "\n\n"

        s += "Successful handshake latency (exact percentiles, us):\n"
        var lp50 = _exact_percentile(self.hs_latency_us, 50.0)
        var lp90 = _exact_percentile(self.hs_latency_us, 90.0)
        var lp99 = _exact_percentile(self.hs_latency_us, 99.0)
        var lmax = _exact_percentile(self.hs_latency_us, 100.0)
        s += "  p50=" + String(lp50) + "   p90=" + String(lp90)
        s += "   p99=" + String(lp99) + "   max=" + String(lmax)
        s += "   (n=" + String(len(self.hs_latency_us)) + ")\n"
        s += "=== end ===\n"
        return s^

    def report_json(self) -> String:
        var now = monotonic_us()
        var run_us = now - self.run_start_us
        var n_closed = self.pkt_count - self.per_pkt_total_overflow
        var p50 = _bucket_percentile(self.per_pkt_total_buckets, n_closed, 50.0)
        var p90 = _bucket_percentile(self.per_pkt_total_buckets, n_closed, 90.0)
        var p99 = _bucket_percentile(self.per_pkt_total_buckets, n_closed, 99.0)
        var bucket_max: UInt64 = UInt64(0)
        var b = 23
        while b >= 0:
            if self.per_pkt_total_buckets[b] > UInt64(0):
                bucket_max = UInt64(1) << UInt64(b)
                break
            b -= 1
        if self.per_pkt_total_overflow > UInt64(0):
            bucket_max = UInt64(8_388_608)

        var lp50 = _exact_percentile(self.hs_latency_us, 50.0)
        var lp90 = _exact_percentile(self.hs_latency_us, 90.0)
        var lp99 = _exact_percentile(self.hs_latency_us, 99.0)
        var lmax = _exact_percentile(self.hs_latency_us, 100.0)

        var s = String("{\n")
        s += '  "schema_version": 1,\n'
        s += '  "run_wall_clock_us": ' + String(run_us) + ',\n'
        s += '  "on_flush_events": ' + String(self.on_flush_count) + ',\n'
        s += '  "idle_us_total": ' + String(self.idle_us_total) + ',\n'
        s += '  "busy_us_total": ' + String(self.busy_us_total) + ',\n'

        s += '  "pkts_per_flush_histogram": {\n'
        var keys = List[String]()
        keys.append(String("1"))
        keys.append(String("2-3"))
        keys.append(String("4-7"))
        keys.append(String("8-15"))
        keys.append(String("16-31"))
        keys.append(String("32-63"))
        keys.append(String("64-127"))
        keys.append(String("128+"))
        for i in range(8):
            s += '    "' + keys[i] + '": ' + String(self.pkts_per_flush_buckets[i])
            if i < 7:
                s += ","
            s += "\n"
        s += "  },\n"

        s += '  "per_pkt_us": {\n'
        s += '    "total":         {"p50": ' + String(p50) + ', "p90": ' + String(p90)
        s += ', "p99": ' + String(p99) + ', "max": ' + String(bucket_max)
        s += ', "n": ' + String(n_closed) + ', "overflow": ' + String(self.per_pkt_total_overflow) + "},\n"
        s += _json_leg("header_parse", self.header_parse_us_total, self.pkt_count) + ",\n"
        s += _json_leg("hp",           self.hp_us_total,           self.pkt_count) + ",\n"
        s += _json_leg("aead",         self.aead_us_total,         self.pkt_count) + ",\n"
        s += _json_leg("frame_parse",  self.frame_parse_us_total,  self.pkt_count) + ",\n"
        s += _json_leg("sm",           self.sm_us_total,           self.pkt_count) + ",\n"
        s += _json_leg("residual",     self.residual_us_total,     self.pkt_count) + ",\n"
        s += _json_leg("shim_ffi",     self.ffi_shim_us_total,     self.pkt_count) + ",\n"
        s += _json_leg("drain",        self.drain_us_total,        self.pkt_count) + "\n"
        s += "  },\n"

        s += '  "handshake": {\n'
        s += '    "arrivals": ' + String(self.hs_arrivals) + ', '
        s += '"successful": ' + String(self.hs_completed) + ', '
        s += '"timed_out": ' + String(self.hs_timed_out) + ',\n'
        s += '    "latency_us": {"p50": ' + String(lp50) + ', "p90": ' + String(lp90)
        s += ', "p99": ' + String(lp99) + ', "max": ' + String(lmax)
        s += ', "count": ' + String(len(self.hs_latency_us)) + "}\n"
        s += "  }\n"
        s += "}\n"
        return s^


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


fn _exact_percentile(values: List[UInt64], p: Float64) -> UInt64:
    """Nearest-rank percentile of values. Sorts a copy. Returns 0 for empty."""
    var n = len(values)
    if n == 0:
        return UInt64(0)
    var sorted_v = List[UInt64](capacity=n)
    for i in range(n):
        sorted_v.append(values[i])
    # Insertion sort (n is bounded — handshakes per run, low thousands).
    for i in range(1, n):
        var key = sorted_v[i]
        var j = i - 1
        while j >= 0 and sorted_v[j] > key:
            sorted_v[j + 1] = sorted_v[j]
            j -= 1
        sorted_v[j + 1] = key
    # Nearest-rank: idx = ceil(p/100 * n) - 1, clamped to [0, n-1].
    var raw = (p / 100.0) * Float64(n)
    var idx = Int(raw)
    if Float64(idx) < raw:
        idx += 1  # ceil
    idx -= 1
    if idx < 0:
        idx = 0
    if idx >= n:
        idx = n - 1
    return sorted_v[idx]


fn _bucket_percentile(buckets: List[UInt64], total: UInt64, p: Float64) -> UInt64:
    """Linear-interp percentile inside the containing 24-bucket histogram.

    `total` = sum of closed-bucket counts (overflow excluded). Returns 0 if total==0.
    """
    if total == UInt64(0):
        return UInt64(0)
    var target = (p / 100.0) * Float64(total)
    var target_count = UInt64(target)
    if Float64(target_count) < target:
        target_count += UInt64(1)
    if target_count == UInt64(0):
        target_count = UInt64(1)
    var cum: UInt64 = UInt64(0)
    for b in range(24):
        var c = buckets[b]
        if c == UInt64(0):
            continue
        var new_cum = cum + c
        if new_cum >= target_count:
            # Bucket b contains the target. Linear-interp inside [lower, upper).
            var lower: UInt64
            var upper: UInt64
            if b == 0:
                lower = UInt64(0)
                upper = UInt64(1)
            else:
                lower = UInt64(1) << UInt64(b - 1)
                upper = UInt64(1) << UInt64(b)
            var into = target_count - cum
            var frac = Float64(into) / Float64(c)
            var span = Float64(upper - lower)
            return lower + UInt64(frac * span)
        cum = new_cum
    # Should not reach here when total > 0; clamp to top bucket upper bound.
    return UInt64(1) << UInt64(23)


fn _fmt_count(n: UInt64) -> String:
    """Decimal with comma thousands separators. Uses byte-scan because Mojo 0.26.2 does not support String[i]."""
    var raw = String(n)
    var raw_b = raw.as_bytes()
    var out = String()
    var k = 0
    for i in range(len(raw_b) - 1, -1, -1):
        if k > 0 and k % 3 == 0:
            out = String(",") + out
        out = chr(Int(raw_b[i])) + out
        k += 1
    return out^


fn _fmt_pct(part: UInt64, whole: UInt64) -> String:
    if whole == UInt64(0):
        return String("(0.0%)")
    var pct = (Float64(part) * 100.0) / Float64(whole)
    var pct_x10 = Int(pct * 10.0 + 0.5)  # round to 1 decimal
    var whole_part = pct_x10 // 10
    var frac_part = pct_x10 % 10
    return String("(") + String(whole_part) + "." + String(frac_part) + "%)"


fn _fmt_duration_us(us: UInt64) -> String:
    """Format us as 'N.NNs' (>=1s) or 'N.NNNms' (<1s)."""
    if us >= UInt64(1_000_000):
        var secs_x100 = Int((Float64(us) / 10000.0) + 0.5)
        var whole = secs_x100 // 100
        var frac = secs_x100 % 100
        var frac_str = String(frac)
        if frac < 10:
            frac_str = String("0") + frac_str
        return String(whole) + "." + frac_str + "s"
    var ms_x1000 = Int(Float64(us) + 0.5)  # us → us, displayed as ms.uuu
    var ms_whole = ms_x1000 // 1000
    var ms_frac = ms_x1000 % 1000
    var frac_str = String(ms_frac)
    while len(frac_str) < 3:
        frac_str = String("0") + frac_str
    return String(ms_whole) + "." + frac_str + "ms"


fn _fmt_leg(label: String, total: UInt64, count: UInt64) -> String:
    if count == UInt64(0):
        return label + ":  avg=  0   total=        0us"
    var avg = total / count
    var avg_s = String(avg)
    while len(avg_s) < 3:
        avg_s = String(" ") + avg_s
    var total_s = String(total)
    return label + ":  avg=" + avg_s + "   total=" + total_s + "us"


fn _json_leg(name: String, total: UInt64, count: UInt64) -> String:
    var avg: UInt64 = UInt64(0)
    if count > UInt64(0):
        avg = total / count
    var pad = String()
    while len(pad) + len(name) < 14:
        pad += " "
    return '    "' + name + '":' + pad + '{"avg": ' + String(avg) + ', "total": ' + String(total) + "}"
