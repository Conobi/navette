# QUIC accept-loop profile module.
#
# AcceptProfile (counter struct + report formatters), monotonic_us
# (sans-I/O CLOCK_MONOTONIC), and PROFILE_ACCEPT (comptime opt-in).

from std.collections import Optional
from std.ffi import external_call
from std.memory import Pointer
from std.sys.intrinsics import llvm_intrinsic

comptime PROFILE_ACCEPT: Bool = False
comptime _CLOCK_MONOTONIC: Int32 = 1
comptime N_COUNTERS: Int = 67


def monotonic_us() -> UInt64:
    """`clock_gettime(CLOCK_MONOTONIC)` in microseconds, sans-I/O."""
    var ts = InlineArray[Int64, 2](fill=0)
    var ts_ptr = Pointer(to=ts).unsafe_bitcast[UInt8]()
    _ = external_call["clock_gettime", Int32](_CLOCK_MONOTONIC, ts_ptr)
    return UInt64(ts[0]) * 1_000_000 + UInt64(ts[1]) / 1_000


@always_inline
def rdtsc() -> UInt64:
    """CPU timestamp counter via LLVM readcyclecounter intrinsic."""
    return llvm_intrinsic["llvm.readcyclecounter", UInt64, has_side_effect=True]()


comptime N_CALL_IDS: Int = 6


@fieldwise_init
struct CallId(ImplicitlyCopyable):
    """Identifies a tracked function in the CallTracker."""
    var value: UInt8
    comptime RECV_FROM_BUFFER = CallId(0)
    comptime SEND = CallId(1)
    comptime POLL_QUIC_EVENTS = CallId(2)
    comptime PARSE_FRAMES = CallId(3)
    comptime ON_REQUEST = CallId(4)
    comptime DRAIN_RESPONSES = CallId(5)


def _call_id_name(v: UInt8) -> String:
    """Human-readable name for a CallId value."""
    if v == 0: return "recv_from_buffer"
    if v == 1: return "send"
    if v == 2: return "poll_quic_events"
    if v == 3: return "parse_frames_from_buf"
    if v == 4: return "on_request"
    if v == 5: return "drain_responses"
    return "unknown"


@fieldwise_init
struct CounterId(ImplicitlyCopyable):
    """Identifies a scalar counter in the AcceptProfile counter table."""
    var value: UInt8
    # timing
    comptime IDLE_US_TOTAL = CounterId(0)
    comptime BUSY_US_TOTAL = CounterId(1)
    comptime ON_FLUSH_COUNT = CounterId(2)
    # per-packet
    comptime FFI_SHIM_US_TOTAL = CounterId(3)
    comptime HP_US_TOTAL = CounterId(4)
    comptime AEAD_US_TOTAL = CounterId(5)
    comptime HEADER_PARSE_US_TOTAL = CounterId(6)
    comptime FRAME_PARSE_US_TOTAL = CounterId(7)
    comptime SM_US_TOTAL = CounterId(8)
    comptime DRAIN_US_TOTAL = CounterId(9)
    comptime RESIDUAL_US_TOTAL = CounterId(10)
    comptime PKT_COUNT = CounterId(11)
    comptime PER_PKT_TOTAL_OVERFLOW = CounterId(12)
    # handshake
    comptime HS_ARRIVALS = CounterId(13)
    comptime HS_COMPLETED = CounterId(14)
    comptime HS_TIMED_OUT = CounterId(15)
    # arrival latency
    comptime ARRIVAL_LAT_US_OVERFLOW = CounterId(16)
    comptime ARRIVAL_LAT_US_TOTAL = CounterId(17)
    # dcid
    comptime DCID_MISMATCH_PKTS = CounterId(18)
    # ffi sub-legs
    comptime FFI_READ_HS_US_TOTAL = CounterId(19)
    comptime FFI_WRITE_HS_US_TOTAL = CounterId(20)
    comptime FFI_TAKE_KEYS_US_TOTAL = CounterId(21)
    # loop phases
    comptime LOOP_POP_DISPATCH_US_TOTAL = CounterId(22)
    comptime LOOP_POST_PKT_US_TOTAL = CounterId(23)
    comptime LOOP_TEARDOWN_US_TOTAL = CounterId(24)
    comptime LOOP_ITER_COUNT = CounterId(25)
    # h3 phases
    comptime H3_DRAIN_RESP_US_TOTAL = CounterId(26)
    comptime QUIC_POST_RECV_US_TOTAL = CounterId(27)
    comptime H3_DISPATCH_US_TOTAL = CounterId(28)
    # drain stream sub-legs
    comptime DRAIN_STREAM_US_TOTAL = CounterId(29)
    comptime DRAIN_RECV_FFI_US_TOTAL = CounterId(30)
    comptime DRAIN_BUF_ACCUMULATE_US_TOTAL = CounterId(31)
    comptime DRAIN_FRAME_PARSE_US_TOTAL = CounterId(32)
    comptime DRAIN_QPACK_DECODE_US_TOTAL = CounterId(33)
    # handshake kinds
    comptime HANDSHAKES_FULL_TOTAL = CounterId(34)
    comptime HANDSHAKES_RESUMED_TOTAL = CounterId(35)
    # overflow counters
    comptime FRESH_CONN_FFI_US_OVERFLOW = CounterId(36)
    comptime READ_HS_US_PER_CALL_OVERFLOW = CounterId(37)
    comptime READ_HS_INPUT_MARSHALLING_US_OVERFLOW = CounterId(38)
    comptime READ_HS_STATE_MACHINE_US_OVERFLOW = CounterId(39)
    comptime READ_HS_OUTPUT_ALLOC_US_OVERFLOW = CounterId(40)
    comptime READ_HS_OUTPUT_MARSHALLING_US_OVERFLOW = CounterId(41)
    comptime ALLOC_TLS_HANDLE_US_OVERFLOW = CounterId(42)
    comptime IOURING_PARK_US_TOTAL = CounterId(43)
    comptime IOURING_PARK_US_OVERFLOW = CounterId(44)
    comptime CQES_PER_WAKE_COUNT = CounterId(45)
    comptime CQES_TOTAL = CounterId(46)
    comptime FLUSH_IMPL_US_TOTAL = CounterId(47)
    comptime FLUSH_IMPL_US_OVERFLOW = CounterId(48)
    comptime DRAIN_SUBMITS_US_TOTAL = CounterId(49)
    comptime FLUSH_FEED_DATAGRAM_US_TOTAL = CounterId(50)
    comptime FLUSH_FEED_DATAGRAM_US_OVERFLOW = CounterId(51)
    comptime HS_CPU_US_PER_HANDSHAKE_OVERFLOW = CounterId(52)
    comptime HS_WAIT_US_PER_HANDSHAKE_OVERFLOW = CounterId(53)
    # zero-rtt (stored as UInt64; semantically signed for future delta arithmetic)
    comptime ZERO_RTT_INSTALL_ATTEMPTS = CounterId(54)
    comptime ZERO_RTT_INSTALL_SUCCESSES = CounterId(55)
    comptime ZERO_RTT_DRAIN_DROPPED = CounterId(56)
    comptime ZERO_RTT_REPLAY_ACCEPT = CounterId(57)
    comptime ZERO_RTT_REPLAY_REJECT_DUPLICATE = CounterId(58)
    comptime ZERO_RTT_REPLAY_REJECT_PER_KEY_QUOTA = CounterId(59)
    comptime ZERO_RTT_REPLAY_REJECT_GLOBAL_CEILING = CounterId(60)
    comptime ZERO_RTT_REPLAY_REJECT_NO_AUTHENTICATOR = CounterId(61)
    comptime ZERO_RTT_HTTP_FILTER_ACCEPT = CounterId(62)
    comptime ZERO_RTT_HTTP_FILTER_REJECT_425 = CounterId(63)
    comptime ZERO_RTT_HTTP_FILTER_MISCONFIG_FAIL_CLOSED = CounterId(64)
    comptime ZERO_RTT_HTTP_FILTER_1RTT_BYPASSED = CounterId(65)
    comptime ZERO_RTT_HTTP_FILTER_USER_RAISED = CounterId(66)


def counter_name(id: CounterId) -> String:
    """Map counter ID to its JSON leaf key."""
    var names: List[String] = [
        "idle_us_total", "busy_us_total", "on_flush_events",
        "shim_ffi", "hp", "aead", "header_parse", "frame_parse",
        "sm", "drain", "residual", "pkt_count", "per_pkt_total_overflow",
        "arrivals", "successful", "timed_out",
        "arrival_lat_us_overflow", "arrival_lat_us_total", "dcid_mismatch_pkts",
        "read_hs", "write_hs", "take_keys",
        "pop_dispatch", "post_pkt", "teardown", "loop_iter_count",
        "drain_resp", "post_recv", "dispatch",
        "drain_stream_us_total", "recv_ffi_us", "buf_accumulate_us",
        "frame_parse_us", "qpack_decode_us",
        "full", "resumed",
        "fresh_conn_ffi_us_overflow", "read_hs_us_per_call_overflow",
        "read_hs_input_marshalling_us_overflow", "read_hs_state_machine_us_overflow",
        "read_hs_output_alloc_us_overflow", "read_hs_output_marshalling_us_overflow",
        "alloc_tls_handle_us_overflow",
        "iouring_park_us_total", "iouring_park_us_overflow",
        "cqes_per_wake_count", "cqes_total",
        "flush_impl_us_total", "flush_impl_us_overflow",
        "drain_submits_us_total",
        "flush_feed_datagram_us_total", "flush_feed_datagram_us_overflow",
        "hs_cpu_us_per_handshake_overflow", "hs_wait_us_per_handshake_overflow",
        "attempts", "successes", "dropped",
        "accept", "reject_duplicate", "reject_per_key_quota",
        "reject_global_ceiling", "reject_no_authenticator",
        "accept", "reject_425", "misconfig_fail_closed",
        "1rtt_bypassed", "user_raised",
    ]
    var idx = Int(id.value)
    if idx < len(names):
        return names[idx]
    return "unknown"


comptime _CT_HIST_BUCKETS: Int = 16
comptime _CT_STATS_PER_ID: Int = 4  # count, total, min, max
comptime _CT_STATS_SIZE: Int = N_CALL_IDS * _CT_STATS_PER_ID
comptime _CT_HIST_SIZE: Int = N_CALL_IDS * _CT_HIST_BUCKETS


struct CallTracker(Copyable, Movable):
    """Per-call cycle-cost tracker with log2 histograms, zero heap allocation."""

    var stats: InlineArray[UInt64, _CT_STATS_SIZE]
    var hist: InlineArray[UInt64, _CT_HIST_SIZE]

    def __init__(out self):
        self.stats = InlineArray[UInt64, _CT_STATS_SIZE](fill=UInt64(0))
        self.hist = InlineArray[UInt64, _CT_HIST_SIZE](fill=UInt64(0))
        for i in range(N_CALL_IDS):
            self.stats[i * _CT_STATS_PER_ID + 2] = ~UInt64(0)

    @always_inline
    def record(mut self, id: CallId, cycles: UInt64):
        """Record one call's cycle cost into stats and histogram."""
        var base = Int(id.value) * _CT_STATS_PER_ID
        self.stats[base] += UInt64(1)
        self.stats[base + 1] += cycles
        if cycles < self.stats[base + 2]:
            self.stats[base + 2] = cycles
        if cycles > self.stats[base + 3]:
            self.stats[base + 3] = cycles
        var bucket = 0
        if cycles > 0:
            var v = cycles
            while v > 1 and bucket < _CT_HIST_BUCKETS - 1:
                v >>= 1
                bucket += 1
        var hbase = Int(id.value) * _CT_HIST_BUCKETS
        self.hist[hbase + bucket] += UInt64(1)

    def count(self, id: CallId) -> UInt64:
        """Total number of recorded calls for this function."""
        return self.stats[Int(id.value) * _CT_STATS_PER_ID]

    def total(self, id: CallId) -> UInt64:
        """Cumulative cycle count across all calls."""
        return self.stats[Int(id.value) * _CT_STATS_PER_ID + 1]

    def min_cycles(self, id: CallId) -> UInt64:
        """Minimum observed cycles for a single call."""
        return self.stats[Int(id.value) * _CT_STATS_PER_ID + 2]

    def max_cycles(self, id: CallId) -> UInt64:
        """Maximum observed cycles for a single call."""
        return self.stats[Int(id.value) * _CT_STATS_PER_ID + 3]

    def mean_cycles(self, id: CallId) -> UInt64:
        """Average cycles per call (integer division)."""
        var c = self.count(id)
        if c == 0:
            return UInt64(0)
        return self.total(id) // c

    def report_text(self) -> String:
        """Human-readable per-function summary table."""
        var s = String("=== CallTracker (rdtsc cycles/call) ===\n")
        s += "  function                    calls      mean       min       p50       p99       max\n"
        for i in range(N_CALL_IDS):
            var id = CallId(UInt8(i))
            var c = self.count(id)
            if c == 0:
                continue
            var hbase = i * _CT_HIST_BUCKETS
            var p50 = _ct_percentile(self.hist, hbase, c, 50)
            var p99 = _ct_percentile(self.hist, hbase, c, 99)
            s += "  " + _call_id_name(UInt8(i))
            # Pad name to 24 chars.
            var name_len = _call_id_name(UInt8(i)).byte_length()
            for _ in range(max(0, 24 - name_len)):
                s += " "
            s += String(c) + "  " + String(self.mean_cycles(id))
            s += "  " + String(self.min_cycles(id))
            s += "  " + p50 + "  " + p99
            s += "  " + String(self.max_cycles(id)) + "\n"
        return s^

    def report_json_fragment(self) -> String:
        """JSON object fragment for embedding in the profile sidecar."""
        var s = String('"call_tracker": {\n')
        var first = True
        for i in range(N_CALL_IDS):
            var id = CallId(UInt8(i))
            var c = self.count(id)
            if c == 0:
                continue
            if not first:
                s += ",\n"
            first = False
            var hbase = i * _CT_HIST_BUCKETS
            var p50 = _ct_percentile(self.hist, hbase, c, 50)
            var p99 = _ct_percentile(self.hist, hbase, c, 99)
            s += '  "' + _call_id_name(UInt8(i)) + '": {'
            s += '"count": ' + String(c)
            s += ', "mean": ' + String(self.mean_cycles(id))
            s += ', "min": ' + String(self.min_cycles(id))
            s += ', "p50": "' + p50 + '"'
            s += ', "p99": "' + p99 + '"'
            s += ', "max": ' + String(self.max_cycles(id))
            s += "}"
        s += "\n}"
        return s^


def _ct_percentile(
    hist: InlineArray[UInt64, _CT_HIST_SIZE],
    base: Int,
    total: UInt64,
    pct: Int,
) -> String:
    """Estimate a percentile from a log2 histogram as '2^bucket' string."""
    var target = (total * UInt64(pct)) // UInt64(100)
    var cumulative = UInt64(0)
    for b in range(_CT_HIST_BUCKETS):
        cumulative += hist[base + b]
        if cumulative >= target:
            return "2^" + String(b)
    return "2^" + String(_CT_HIST_BUCKETS - 1)


struct AcceptProfile(Copyable, Movable):
    """QUIC accept-loop profile counters with data-driven counter table.

    WARNING: holds List[UInt64] histogram fields — each copy triggers deep
    copies. Production code threads via UnsafePointer, never copy.
    """
    var run_start_us: UInt64
    var counters: InlineArray[UInt64, N_COUNTERS]
    # Gauge / sampling fields.
    var last_gauge_sample_us: UInt64
    var active_drive_count: UInt32
    var active_bouclette_count_samples: List[UInt32]
    var in_flight_handshake_count_samples: List[UInt32]
    # Histogram buckets (List[UInt64]).
    var pkts_per_flush_buckets: List[UInt64]
    var per_pkt_total_buckets: List[UInt64]
    var hs_latency_us: List[UInt64]
    var arrival_lat_us_buckets: List[UInt64]
    var fresh_conn_ffi_us_buckets: List[UInt64]
    var recv_batch_size_buckets: List[UInt64]
    var read_hs_per_handshake_count_buckets: List[UInt64]
    var read_hs_us_per_call_buckets: List[UInt64]
    var read_hs_input_marshalling_us_buckets: List[UInt64]
    var read_hs_state_machine_us_buckets: List[UInt64]
    var read_hs_output_alloc_us_buckets: List[UInt64]
    var read_hs_output_marshalling_us_buckets: List[UInt64]
    var alloc_tls_handle_us_buckets: List[UInt64]
    var sendmsg_batch_size_buckets: List[UInt64]
    var recvmsg_batch_size_buckets: List[UInt64]
    var hs_cpu_us_per_handshake_buckets: List[UInt64]
    var hs_wait_us_per_handshake_buckets: List[UInt64]
    var iouring_park_us_buckets: List[UInt64]
    var cqes_per_wake_buckets: List[UInt64]
    var flush_impl_us_buckets: List[UInt64]
    var flush_feed_datagram_us_buckets: List[UInt64]
    var call_tracker: CallTracker

    def __init__(out self):
        self.run_start_us = monotonic_us()
        self.counters = InlineArray[UInt64, N_COUNTERS](fill=UInt64(0))
        self.last_gauge_sample_us = UInt64(0)
        self.active_drive_count = UInt32(0)
        self.active_bouclette_count_samples = List[UInt32]()
        self.in_flight_handshake_count_samples = List[UInt32]()
        self.hs_latency_us = List[UInt64]()
        self.pkts_per_flush_buckets = _init_hist(8)
        self.per_pkt_total_buckets = _init_hist(24)
        self.arrival_lat_us_buckets = _init_hist(24)
        self.fresh_conn_ffi_us_buckets = _init_hist(24)
        self.recv_batch_size_buckets = _init_hist(8)
        self.read_hs_per_handshake_count_buckets = _init_hist(8)
        self.read_hs_us_per_call_buckets = _init_hist(24)
        self.read_hs_input_marshalling_us_buckets = _init_hist(24)
        self.read_hs_state_machine_us_buckets = _init_hist(24)
        self.read_hs_output_alloc_us_buckets = _init_hist(24)
        self.read_hs_output_marshalling_us_buckets = _init_hist(24)
        self.alloc_tls_handle_us_buckets = _init_hist(24)
        self.sendmsg_batch_size_buckets = _init_hist(8)
        self.recvmsg_batch_size_buckets = _init_hist(8)
        self.hs_cpu_us_per_handshake_buckets = _init_hist(24)
        self.hs_wait_us_per_handshake_buckets = _init_hist(24)
        self.iouring_park_us_buckets = _init_hist(24)
        self.cqes_per_wake_buckets = _init_hist(8)
        self.flush_impl_us_buckets = _init_hist(24)
        self.flush_feed_datagram_us_buckets = _init_hist(24)
        self.call_tracker = CallTracker()

    def get(self, id: CounterId) -> UInt64:
        """Read counter value by ID."""
        return self.counters[Int(id.value)]

    def set(mut self, id: CounterId, val: UInt64):
        """Write counter value by ID."""
        self.counters[Int(id.value)] = val

    def record(mut self, id: CounterId, delta: UInt64 = UInt64(1)):
        """Increment counter by delta."""
        self.counters[Int(id.value)] = self.counters[Int(id.value)] + delta

    # ── Trivial wrappers (delegate to record; signatures kept for callers) ──
    def record_idle(mut self, idle_us: UInt64):
        self.record(CounterId.IDLE_US_TOTAL, idle_us)
    def record_drain(mut self, drain_us: UInt64):
        self.record(CounterId.DRAIN_US_TOTAL, drain_us)
    def record_handshake_arrival(mut self):
        self.record(CounterId.HS_ARRIVALS)
    def record_handshake_timeout(mut self, count: UInt64 = UInt64(1)):
        self.record(CounterId.HS_TIMED_OUT, count)
    def record_dcid_mismatch(mut self):
        self.record(CounterId.DCID_MISMATCH_PKTS)
    def record_ffi_read_hs(mut self, us: UInt64):
        self.record(CounterId.FFI_READ_HS_US_TOTAL, us)
    def record_ffi_write_hs(mut self, us: UInt64):
        self.record(CounterId.FFI_WRITE_HS_US_TOTAL, us)
    def record_ffi_take_keys(mut self, us: UInt64):
        self.record(CounterId.FFI_TAKE_KEYS_US_TOTAL, us)
    def record_loop_pop_dispatch(mut self, us: UInt64):
        self.record(CounterId.LOOP_POP_DISPATCH_US_TOTAL, us)
    def record_loop_post_pkt(mut self, us: UInt64):
        self.record(CounterId.LOOP_POST_PKT_US_TOTAL, us)
    def record_loop_teardown(mut self, us: UInt64):
        self.record(CounterId.LOOP_TEARDOWN_US_TOTAL, us)
    def record_loop_iter(mut self):
        self.record(CounterId.LOOP_ITER_COUNT)
    def record_h3_drain_resp(mut self, us: UInt64):
        self.record(CounterId.H3_DRAIN_RESP_US_TOTAL, us)
    def record_quic_post_recv(mut self, us: UInt64):
        self.record(CounterId.QUIC_POST_RECV_US_TOTAL, us)
    def record_h3_dispatch(mut self, us: UInt64):
        self.record(CounterId.H3_DISPATCH_US_TOTAL, us)
    def record_drain_stream(mut self, us: UInt64):
        self.record(CounterId.DRAIN_STREAM_US_TOTAL, us)
    def record_drain_recv_ffi(mut self, us: UInt64):
        self.record(CounterId.DRAIN_RECV_FFI_US_TOTAL, us)
    def record_drain_buf_accumulate(mut self, us: UInt64):
        self.record(CounterId.DRAIN_BUF_ACCUMULATE_US_TOTAL, us)
    def record_drain_frame_parse(mut self, us: UInt64):
        self.record(CounterId.DRAIN_FRAME_PARSE_US_TOTAL, us)
    def record_drain_qpack_decode(mut self, us: UInt64):
        self.record(CounterId.DRAIN_QPACK_DECODE_US_TOTAL, us)
    def record_handshake_full(mut self):
        self.record(CounterId.HANDSHAKES_FULL_TOTAL)
    def record_handshake_resumed(mut self):
        self.record(CounterId.HANDSHAKES_RESUMED_TOTAL)
    def record_drain_submits_us(mut self, us: UInt64):
        self.record(CounterId.DRAIN_SUBMITS_US_TOTAL, us)
    def record_zero_rtt_drain_dropped(mut self):
        self.record(CounterId.ZERO_RTT_DRAIN_DROPPED)
    def record_zero_rtt_replay_accept(mut self):
        self.record(CounterId.ZERO_RTT_REPLAY_ACCEPT)
    def record_zero_rtt_replay_reject_duplicate(mut self):
        self.record(CounterId.ZERO_RTT_REPLAY_REJECT_DUPLICATE)
    def record_zero_rtt_replay_reject_per_key_quota(mut self):
        self.record(CounterId.ZERO_RTT_REPLAY_REJECT_PER_KEY_QUOTA)
    def record_zero_rtt_replay_reject_global_ceiling(mut self):
        self.record(CounterId.ZERO_RTT_REPLAY_REJECT_GLOBAL_CEILING)
    def record_zero_rtt_replay_reject_no_authenticator(mut self):
        self.record(CounterId.ZERO_RTT_REPLAY_REJECT_NO_AUTHENTICATOR)
    def record_zero_rtt_http_filter_accept(mut self):
        self.record(CounterId.ZERO_RTT_HTTP_FILTER_ACCEPT)
    def record_zero_rtt_http_filter_reject_425(mut self):
        self.record(CounterId.ZERO_RTT_HTTP_FILTER_REJECT_425)
    def record_zero_rtt_http_filter_misconfig_fail_closed(mut self):
        self.record(CounterId.ZERO_RTT_HTTP_FILTER_MISCONFIG_FAIL_CLOSED)
    def record_zero_rtt_http_filter_1rtt_bypassed(mut self):
        self.record(CounterId.ZERO_RTT_HTTP_FILTER_1RTT_BYPASSED)
    def record_zero_rtt_http_filter_user_raised(mut self):
        self.record(CounterId.ZERO_RTT_HTTP_FILTER_USER_RAISED)

    # ── Compound record methods ──
    def record_flush(mut self, pkts: Int, busy_us: UInt64):
        """Record one flush event: bump count, accumulate busy time, histogram."""
        self.record(CounterId.ON_FLUSH_COUNT)
        self.record(CounterId.BUSY_US_TOTAL, busy_us)
        self.pkts_per_flush_buckets[_pkts_per_flush_bucket(pkts)] += UInt64(1)

    def record_pkt(mut self, *, total_us: UInt64, ffi_us: UInt64, hp_us: UInt64,
                   aead_us: UInt64, header_parse_us: UInt64, frame_parse_us: UInt64,
                   sm_us: UInt64):
        """Record per-packet timing decomposition."""
        self.record(CounterId.PKT_COUNT)
        self.record(CounterId.FFI_SHIM_US_TOTAL, ffi_us)
        self.record(CounterId.HP_US_TOTAL, hp_us)
        self.record(CounterId.AEAD_US_TOTAL, aead_us)
        self.record(CounterId.HEADER_PARSE_US_TOTAL, header_parse_us)
        self.record(CounterId.FRAME_PARSE_US_TOTAL, frame_parse_us)
        self.record(CounterId.SM_US_TOTAL, sm_us)
        var legs_sum = hp_us + aead_us + header_parse_us + frame_parse_us + sm_us
        if total_us >= legs_sum:
            self.record(CounterId.RESIDUAL_US_TOTAL, total_us - legs_sum)
        var b = _per_pkt_bucket(total_us)
        if b >= 24:
            self.record(CounterId.PER_PKT_TOTAL_OVERFLOW)
        else:
            self.per_pkt_total_buckets[b] += UInt64(1)

    def record_handshake_complete(mut self, latency_us: UInt64):
        """Record successful handshake with raw latency."""
        self.record(CounterId.HS_COMPLETED)
        self.hs_latency_us.append(latency_us)

    def record_arrival_lat(mut self, us: UInt64):
        """Record per-packet queueing latency into 24-bucket histogram."""
        self.record(CounterId.ARRIVAL_LAT_US_TOTAL, us)
        if _dispatch_pow2(self.arrival_lat_us_buckets, us):
            self.record(CounterId.ARRIVAL_LAT_US_OVERFLOW)

    def record_fresh_conn_ffi_us(mut self, us: UInt64):
        """Per-fresh-conn FFI total histogram (24-bucket pow2)."""
        if _dispatch_pow2(self.fresh_conn_ffi_us_buckets, us):
            self.record(CounterId.FRESH_CONN_FFI_US_OVERFLOW)
    def record_recv_batch(mut self, n: Int):
        """Recvmsg batch-size histogram (8-bucket)."""
        self.recv_batch_size_buckets[_pkts_per_flush_bucket(n)] += UInt64(1)
    def record_read_hs_per_handshake_count(mut self, n: Int):
        """Per-server-conn read_hs call count histogram (8-bucket)."""
        self.read_hs_per_handshake_count_buckets[_pkts_per_flush_bucket(n)] += UInt64(1)
    def record_read_hs_us_per_call(mut self, us: UInt64):
        """Per-call read_hs duration histogram (24-bucket pow2)."""
        if _dispatch_pow2(self.read_hs_us_per_call_buckets, us):
            self.record(CounterId.READ_HS_US_PER_CALL_OVERFLOW)
    def record_read_hs_input_marshalling_us(mut self, us: UInt64):
        """Input marshalling sub-leg (24-bucket pow2)."""
        if _dispatch_pow2(self.read_hs_input_marshalling_us_buckets, us):
            self.record(CounterId.READ_HS_INPUT_MARSHALLING_US_OVERFLOW)
    def record_read_hs_state_machine_us(mut self, us: UInt64):
        """TLS state machine sub-leg (24-bucket pow2)."""
        if _dispatch_pow2(self.read_hs_state_machine_us_buckets, us):
            self.record(CounterId.READ_HS_STATE_MACHINE_US_OVERFLOW)
    def record_read_hs_output_alloc_us(mut self, us: UInt64):
        """Handle-table lookup sub-leg (24-bucket pow2)."""
        if _dispatch_pow2(self.read_hs_output_alloc_us_buckets, us):
            self.record(CounterId.READ_HS_OUTPUT_ALLOC_US_OVERFLOW)
    def record_read_hs_output_marshalling_us(mut self, us: UInt64):
        """Output copy sub-leg (24-bucket pow2)."""
        if _dispatch_pow2(self.read_hs_output_marshalling_us_buckets, us):
            self.record(CounterId.READ_HS_OUTPUT_MARSHALLING_US_OVERFLOW)
    def record_alloc_tls_handle_us(mut self, us: UInt64):
        """Per-fresh-conn rustls handle creation (24-bucket pow2)."""
        if _dispatch_pow2(self.alloc_tls_handle_us_buckets, us):
            self.record(CounterId.ALLOC_TLS_HANDLE_US_OVERFLOW)
    def record_sendmsg_batch_size(mut self, n: Int):
        """Sendmsg batch-size histogram (8-bucket)."""
        self.sendmsg_batch_size_buckets[_pkts_per_flush_bucket(n)] += UInt64(1)
    def record_recvmsg_batch_size(mut self, n: Int):
        """Recvmsg batch-size histogram (8-bucket)."""
        self.recvmsg_batch_size_buckets[_pkts_per_flush_bucket(n)] += UInt64(1)
    def record_hs_cpu_us_per_handshake(mut self, us: UInt64):
        """Per-FD per-handshake CPU duration (24-bucket pow2)."""
        if _dispatch_pow2(self.hs_cpu_us_per_handshake_buckets, us):
            self.record(CounterId.HS_CPU_US_PER_HANDSHAKE_OVERFLOW)
    def record_hs_wait_us_per_handshake(mut self, us: UInt64):
        """Per-FD per-handshake wait duration (24-bucket pow2)."""
        if _dispatch_pow2(self.hs_wait_us_per_handshake_buckets, us):
            self.record(CounterId.HS_WAIT_US_PER_HANDSHAKE_OVERFLOW)
    def record_iouring_park_us(mut self, us: UInt64):
        """Park-bound total + 24-bucket pow2 histogram."""
        self.record(CounterId.IOURING_PARK_US_TOTAL, us)
        if _dispatch_pow2(self.iouring_park_us_buckets, us):
            self.record(CounterId.IOURING_PARK_US_OVERFLOW)
    def record_cqes_per_wake(mut self, n: UInt64):
        """CQE count per wake: 8-bucket + running totals."""
        self.cqes_per_wake_buckets[_pkts_per_flush_bucket(Int(n))] += UInt64(1)
        self.record(CounterId.CQES_PER_WAKE_COUNT)
        self.record(CounterId.CQES_TOTAL, n)
    def record_flush_impl_us(mut self, us: UInt64):
        """Per-wake flush_impl wall-clock (total + 24-bucket pow2)."""
        self.record(CounterId.FLUSH_IMPL_US_TOTAL, us)
        if _dispatch_pow2(self.flush_impl_us_buckets, us):
            self.record(CounterId.FLUSH_IMPL_US_OVERFLOW)
    def record_flush_feed_datagram_us(mut self, us: UInt64):
        """Per-pkt feed_datagram_from_buffer (total + 24-bucket pow2)."""
        self.record(CounterId.FLUSH_FEED_DATAGRAM_US_TOTAL, us)
        if _dispatch_pow2(self.flush_feed_datagram_us_buckets, us):
            self.record(CounterId.FLUSH_FEED_DATAGRAM_US_OVERFLOW)
    def record_zero_rtt_install(mut self, success: Bool):
        """Bump install-lifecycle counter: success vs attempt."""
        if success:
            self.record(CounterId.ZERO_RTT_INSTALL_SUCCESSES)
        else:
            self.record(CounterId.ZERO_RTT_INSTALL_ATTEMPTS)

    def tick_profile_gauges(mut self, now_us: UInt64):
        """100ms-cadence sampler for gauge timeseries.

        First call always captures; cap at 600 entries (60s @ 10/s).
        """
        if self.last_gauge_sample_us != UInt64(0) and now_us - self.last_gauge_sample_us < UInt64(100_000):
            return
        if now_us == UInt64(0):
            self.last_gauge_sample_us = UInt64(1)
        else:
            self.last_gauge_sample_us = now_us
        if len(self.active_bouclette_count_samples) < 600:
            self.active_bouclette_count_samples.append(self.active_drive_count)
        if len(self.in_flight_handshake_count_samples) < 600:
            self.in_flight_handshake_count_samples.append(self.active_drive_count)

    def _compute_drain_event_dispatch_us(self) -> UInt64:
        """Residual = drain_stream - sum(measured legs), clamped >= 0."""
        var sum_legs = (self.get(CounterId.DRAIN_RECV_FFI_US_TOTAL)
            + self.get(CounterId.DRAIN_BUF_ACCUMULATE_US_TOTAL)
            + self.get(CounterId.DRAIN_FRAME_PARSE_US_TOTAL)
            + self.get(CounterId.DRAIN_QPACK_DECODE_US_TOTAL))
        var parent = self.get(CounterId.DRAIN_STREAM_US_TOTAL)
        if sum_legs >= parent:
            return UInt64(0)
        return parent - sum_legs

    # ── Report methods ──
    def report_text(self) raises -> String:
        """Human-readable text report."""
        var now = monotonic_us()
        var run_us = now - self.run_start_us
        var pkt_n = self.get(CounterId.PKT_COUNT)
        var n_closed = pkt_n - self.get(CounterId.PER_PKT_TOTAL_OVERFLOW)
        var idle = self.get(CounterId.IDLE_US_TOTAL)
        var busy = self.get(CounterId.BUSY_US_TOTAL)
        var flush_n = self.get(CounterId.ON_FLUSH_COUNT)
        var iter_n = self.get(CounterId.LOOP_ITER_COUNT)
        var s = String("=== navette QUIC accept-loop profile ===\n")
        s += "Run wall-clock:           " + _fmt_duration_us(run_us) + "\n"
        s += "On_flush events:          " + _fmt_count(flush_n) + "\n"
        s += "  Idle (bouclette wait):     " + _fmt_duration_us(idle) + "  " + _fmt_pct(idle, idle + busy) + "\n"
        s += "  Busy (in loop):         " + _fmt_duration_us(busy) + "  " + _fmt_pct(busy, idle + busy) + "\n\n"
        s += "Datagrams batched per flush (approx. CQE multishot batching):\n"
        s += _text_8bucket_fmt(self.pkts_per_flush_buckets, "size=", "  ", total_for_pct=flush_n)
        s += "Per-packet wall-clock (bucket-estimated p_n, us):\n"
        var p50 = _bucket_percentile(self.per_pkt_total_buckets, n_closed, 50.0)
        var p90 = _bucket_percentile(self.per_pkt_total_buckets, n_closed, 90.0)
        var p99 = _bucket_percentile(self.per_pkt_total_buckets, n_closed, 99.0)
        s += "  total:           p50=" + String(p50) + "  p90=" + String(p90) + "  p99=" + String(p99)
        s += "  (n=" + String(n_closed) + ", overflow=" + String(self.get(CounterId.PER_PKT_TOTAL_OVERFLOW)) + ")\n"
        s += "  " + _fmt_leg("header parse",  self.get(CounterId.HEADER_PARSE_US_TOTAL), pkt_n) + "\n"
        s += "  " + _fmt_leg("HP unprotect",  self.get(CounterId.HP_US_TOTAL), pkt_n) + "\n"
        s += "  " + _fmt_leg("AEAD decrypt",  self.get(CounterId.AEAD_US_TOTAL), pkt_n) + "\n"
        s += "  " + _fmt_leg("frame parse",   self.get(CounterId.FRAME_PARSE_US_TOTAL), pkt_n) + "\n"
        s += "  " + _fmt_leg("state machine", self.get(CounterId.SM_US_TOTAL), pkt_n) + "\n"
        s += "  " + _fmt_leg("residual",      self.get(CounterId.RESIDUAL_US_TOTAL), pkt_n) + "\n"
        s += "  " + _fmt_leg("shim FFI",      self.get(CounterId.FFI_SHIM_US_TOTAL), pkt_n) + "\n"
        s += "  " + _fmt_leg("drain (bench)", self.get(CounterId.DRAIN_US_TOTAL), pkt_n) + "\n\n"
        s += "Handshake accounting:\n"
        s += "  Arrivals:                  " + _fmt_count(self.get(CounterId.HS_ARRIVALS)) + "\n"
        s += "  Successful:                " + _fmt_count(self.get(CounterId.HS_COMPLETED))
        s += "  " + _fmt_pct(self.get(CounterId.HS_COMPLETED), self.get(CounterId.HS_ARRIVALS)) + "\n"
        s += "  Timed out:                 " + _fmt_count(self.get(CounterId.HS_TIMED_OUT))
        s += "  " + _fmt_pct(self.get(CounterId.HS_TIMED_OUT), self.get(CounterId.HS_ARRIVALS)) + "\n\n"
        s += "Successful handshake latency (exact percentiles, us):\n"
        var lp50 = _exact_percentile(self.hs_latency_us, 50.0)
        var lp90 = _exact_percentile(self.hs_latency_us, 90.0)
        var lp99 = _exact_percentile(self.hs_latency_us, 99.0)
        var lmax = _exact_percentile(self.hs_latency_us, 100.0)
        s += "  p50=" + String(lp50) + "   p90=" + String(lp90)
        s += "   p99=" + String(lp99) + "   max=" + String(lmax)
        s += "   (n=" + String(len(self.hs_latency_us)) + ")\n"
        # Arrival latency.
        s += "Arrival-to-processing latency (bucket-estimated p_n, us):\n"
        var arr_total_obs = _sum_buckets(self.arrival_lat_us_buckets, 24)
        var arr_p50 = _bucket_percentile(self.arrival_lat_us_buckets, arr_total_obs, 50.0)
        var arr_p90 = _bucket_percentile(self.arrival_lat_us_buckets, arr_total_obs, 90.0)
        var arr_p99 = _bucket_percentile(self.arrival_lat_us_buckets, arr_total_obs, 99.0)
        s += "  total:           p50=" + String(arr_p50) + "  p90=" + String(arr_p90) + "  p99=" + String(arr_p99)
        s += "  (n=" + String(arr_total_obs) + ", overflow=" + String(self.get(CounterId.ARRIVAL_LAT_US_OVERFLOW)) + ")\n"
        s += "  total_us:        " + String(self.get(CounterId.ARRIVAL_LAT_US_TOTAL)) + "\n\n"
        s += "dcid_mismatch_pkts: " + String(self.get(CounterId.DCID_MISMATCH_PKTS)) + "\n\n"
        s += "Handshake kinds:\n"
        s += "  full:    " + _fmt_count(self.get(CounterId.HANDSHAKES_FULL_TOTAL)) + "\n"
        s += "  resumed: " + _fmt_count(self.get(CounterId.HANDSHAKES_RESUMED_TOTAL)) + "\n\n"
        s += "zero_rtt_install:\n"
        s += "  attempts:  " + _fmt_count(self.get(CounterId.ZERO_RTT_INSTALL_ATTEMPTS)) + "\n"
        s += "  successes: " + _fmt_count(self.get(CounterId.ZERO_RTT_INSTALL_SUCCESSES)) + "\n\n"
        s += "zero_rtt_drain:\n"
        s += "  dropped: " + _fmt_count(self.get(CounterId.ZERO_RTT_DRAIN_DROPPED)) + "\n\n"
        s += "zero_rtt_replay:\n"
        s += "  accept:                 " + _fmt_count(self.get(CounterId.ZERO_RTT_REPLAY_ACCEPT)) + "\n"
        s += "  reject_duplicate:       " + _fmt_count(self.get(CounterId.ZERO_RTT_REPLAY_REJECT_DUPLICATE)) + "\n"
        s += "  reject_per_key_quota:   " + _fmt_count(self.get(CounterId.ZERO_RTT_REPLAY_REJECT_PER_KEY_QUOTA)) + "\n"
        s += "  reject_global_ceiling:  " + _fmt_count(self.get(CounterId.ZERO_RTT_REPLAY_REJECT_GLOBAL_CEILING)) + "\n"
        s += "  reject_no_authenticator:" + _fmt_count(self.get(CounterId.ZERO_RTT_REPLAY_REJECT_NO_AUTHENTICATOR)) + "\n\n"
        s += "zero_rtt_http_filter:\n"
        s += "  accept:                " + _fmt_count(self.get(CounterId.ZERO_RTT_HTTP_FILTER_ACCEPT)) + "\n"
        s += "  reject_425:            " + _fmt_count(self.get(CounterId.ZERO_RTT_HTTP_FILTER_REJECT_425)) + "\n"
        s += "  misconfig_fail_closed: " + _fmt_count(self.get(CounterId.ZERO_RTT_HTTP_FILTER_MISCONFIG_FAIL_CLOSED)) + "\n"
        s += "  1rtt_bypassed:         " + _fmt_count(self.get(CounterId.ZERO_RTT_HTTP_FILTER_1RTT_BYPASSED)) + "\n"
        s += "  user_raised:           " + _fmt_count(self.get(CounterId.ZERO_RTT_HTTP_FILTER_USER_RAISED)) + "\n\n"
        # Per-fresh-conn measurements.
        s += "Per-fresh-conn FFI us (24-bucket pow2):\n"
        s += "  total samples:    " + _fmt_count(_sum_buckets(self.fresh_conn_ffi_us_buckets, 24)) + "\n"
        s += "  overflow (>=2^23):" + _fmt_count(self.get(CounterId.FRESH_CONN_FFI_US_OVERFLOW)) + "\n"
        s += "Recv-batch size (8-bucket):\n" + _text_8bucket_fmt(self.recv_batch_size_buckets, "size=", "  ")
        s += "read_hs per-handshake count (8-bucket):\n" + _text_8bucket_fmt(self.read_hs_per_handshake_count_buckets, "count=", "  ", trailing_newline=False)
        s += "read_hs per-call duration (24-bucket pow2 us):\n"
        s += "  total samples:    " + _fmt_count(_sum_buckets(self.read_hs_us_per_call_buckets, 24)) + "\n"
        s += "  overflow (>=2^23):" + _fmt_count(self.get(CounterId.READ_HS_US_PER_CALL_OVERFLOW)) + "\n\n"
        s += _text_hist24_summary("read_hs_input_marshalling_us", self.read_hs_input_marshalling_us_buckets, self.get(CounterId.READ_HS_INPUT_MARSHALLING_US_OVERFLOW))
        s += _text_hist24_summary("read_hs_state_machine_us", self.read_hs_state_machine_us_buckets, self.get(CounterId.READ_HS_STATE_MACHINE_US_OVERFLOW))
        s += _text_hist24_summary("read_hs_output_alloc_us", self.read_hs_output_alloc_us_buckets, self.get(CounterId.READ_HS_OUTPUT_ALLOC_US_OVERFLOW))
        s += _text_hist24_summary("read_hs_output_marshalling_us", self.read_hs_output_marshalling_us_buckets, self.get(CounterId.READ_HS_OUTPUT_MARSHALLING_US_OVERFLOW))
        s += _text_hist24_summary("alloc_tls_handle_us", self.alloc_tls_handle_us_buckets, self.get(CounterId.ALLOC_TLS_HANDLE_US_OVERFLOW))
        # FFI sub-legs.
        s += "FFI sub-legs:\n"
        s += "  " + _fmt_leg("read_hs",   self.get(CounterId.FFI_READ_HS_US_TOTAL),   pkt_n) + "\n"
        s += "  " + _fmt_leg("write_hs",  self.get(CounterId.FFI_WRITE_HS_US_TOTAL),  pkt_n) + "\n"
        s += "  " + _fmt_leg("take_keys", self.get(CounterId.FFI_TAKE_KEYS_US_TOTAL), pkt_n) + "\n\n"
        # Loop phases.
        s += "Loop phases:\n"
        s += "  " + _fmt_leg("pop_dispatch", self.get(CounterId.LOOP_POP_DISPATCH_US_TOTAL), iter_n) + "\n"
        s += "  " + _fmt_leg("post_pkt",     self.get(CounterId.LOOP_POST_PKT_US_TOTAL),     iter_n) + "\n"
        s += "  " + _fmt_leg("teardown",     self.get(CounterId.LOOP_TEARDOWN_US_TOTAL),     flush_n) + "\n"
        s += "  loop_iter_count:                  " + _fmt_count(iter_n) + "\n"
        s += "H3 phases:\n"
        s += "  drain_resp.total: " + _fmt_count(self.get(CounterId.H3_DRAIN_RESP_US_TOTAL)) + "\n"
        s += "  post_recv.total:  " + _fmt_count(self.get(CounterId.QUIC_POST_RECV_US_TOTAL)) + "\n"
        s += "  dispatch.total:   " + _fmt_count(self.get(CounterId.H3_DISPATCH_US_TOTAL)) + "\n\n"
        var de_t_us = self._compute_drain_event_dispatch_us()
        s += "Drain-stream sub-legs:\n"
        s += "  drain_stream.total:     " + _fmt_count(self.get(CounterId.DRAIN_STREAM_US_TOTAL)) + "\n"
        s += "  recv_ffi.total:         " + _fmt_count(self.get(CounterId.DRAIN_RECV_FFI_US_TOTAL)) + "\n"
        s += "  buf_accumulate.total:   " + _fmt_count(self.get(CounterId.DRAIN_BUF_ACCUMULATE_US_TOTAL)) + "\n"
        s += "  frame_parse.total:      " + _fmt_count(self.get(CounterId.DRAIN_FRAME_PARSE_US_TOTAL)) + "\n"
        s += "  qpack_decode.total:     " + _fmt_count(self.get(CounterId.DRAIN_QPACK_DECODE_US_TOTAL)) + "\n"
        s += "  event_dispatch.derived: " + _fmt_count(de_t_us) + "\n\n"
        # Gauge sampling.
        s += "Q7 gauge sampling (100ms cadence, capped 600 entries):\n"
        s += "  active_drive_count.live:                " + _fmt_count(UInt64(self.active_drive_count)) + "\n"
        s += "  active_bouclette_count_samples.len:        " + _fmt_count(UInt64(len(self.active_bouclette_count_samples))) + "\n"
        s += "  in_flight_handshake_count_samples.len:  " + _fmt_count(UInt64(len(self.in_flight_handshake_count_samples))) + "\n\n"
        s += "Q7 batch-size histograms (8-bucket _pkts_per_flush_bucket dispatch):\n"
        s += "  sendmsg:\n" + _text_8bucket_fmt(self.sendmsg_batch_size_buckets, "size=", "    ", trailing_newline=False)
        s += "  recvmsg:\n" + _text_8bucket_fmt(self.recvmsg_batch_size_buckets, "size=", "    ", trailing_newline=False)
        s += "Q7 per-FD per-handshake (24-bucket pow2 us):\n"
        var q7_cpu = _sum_buckets(self.hs_cpu_us_per_handshake_buckets, 24)
        var q7_wait = _sum_buckets(self.hs_wait_us_per_handshake_buckets, 24)
        s += "  hs_cpu.samples:    " + _fmt_count(q7_cpu) + "  overflow=" + _fmt_count(self.get(CounterId.HS_CPU_US_PER_HANDSHAKE_OVERFLOW)) + "\n"
        s += "  hs_wait.samples:   " + _fmt_count(q7_wait) + "  overflow=" + _fmt_count(self.get(CounterId.HS_WAIT_US_PER_HANDSHAKE_OVERFLOW)) + "\n\n"
        s += "Q7 io_uring park (H_F PARK-BOUND, total + 24-bucket pow2):\n"
        s += "  iouring_park_us.total:    " + _fmt_count(self.get(CounterId.IOURING_PARK_US_TOTAL)) + "\n"
        s += "  iouring_park_us.overflow: " + _fmt_count(self.get(CounterId.IOURING_PARK_US_OVERFLOW)) + "\n"
        s += "Q-IO-1 cqes_per_wake (8-bucket via _pkts_per_flush_bucket):\n"
        s += "  cqes_per_wake.wakes:    " + _fmt_count(self.get(CounterId.CQES_PER_WAKE_COUNT)) + "\n"
        s += "  cqes_per_wake.cqes_sum: " + _fmt_count(self.get(CounterId.CQES_TOTAL)) + "\n"
        s += _text_8bucket_fmt(self.cqes_per_wake_buckets, "size=", "    ", trailing_newline=False)
        s += "Q-IO-1 flush_impl_us (24-bucket pow2):\n"
        s += "  flush_impl_us.total:    " + _fmt_count(self.get(CounterId.FLUSH_IMPL_US_TOTAL)) + "\n"
        s += "  flush_impl_us.overflow: " + _fmt_count(self.get(CounterId.FLUSH_IMPL_US_OVERFLOW)) + "\n"
        s += "Q-IO-1 drain_submits_us (total-only, AC3 budget closure):\n"
        s += "  drain_submits_us.total: " + _fmt_count(self.get(CounterId.DRAIN_SUBMITS_US_TOTAL)) + "\n\n"
        # Budget closure.
        var pp_legs = (self.get(CounterId.HEADER_PARSE_US_TOTAL) + self.get(CounterId.HP_US_TOTAL)
            + self.get(CounterId.AEAD_US_TOTAL) + self.get(CounterId.FRAME_PARSE_US_TOTAL)
            + self.get(CounterId.SM_US_TOTAL) + self.get(CounterId.RESIDUAL_US_TOTAL))
        var acct = (pp_legs + self.get(CounterId.DRAIN_US_TOTAL)
            + self.get(CounterId.LOOP_POP_DISPATCH_US_TOTAL) + self.get(CounterId.LOOP_POST_PKT_US_TOTAL)
            + self.get(CounterId.LOOP_TEARDOWN_US_TOTAL) + self.get(CounterId.H3_DRAIN_RESP_US_TOTAL)
            + self.get(CounterId.QUIC_POST_RECV_US_TOTAL) + self.get(CounterId.H3_DISPATCH_US_TOTAL))
        var unacct: UInt64 = UInt64(0)
        if busy > acct:
            unacct = busy - acct
        var unacct_pct: UInt64 = UInt64(0)
        if busy > UInt64(0):
            unacct_pct = (unacct * UInt64(100)) / busy
        s += "  unaccounted_us_total:             " + _fmt_count(unacct) + "  (" + String(unacct_pct) + "% of busy)\n\n"
        s += self.call_tracker.report_text()
        s += "=== end ===\n"
        return s^

    def report_json(self) raises -> String:
        """Machine-readable JSON report (schema_version=7)."""
        var now = monotonic_us()
        var run_us = now - self.run_start_us
        var pkt_n = self.get(CounterId.PKT_COUNT)
        var flush_n = self.get(CounterId.ON_FLUSH_COUNT)
        var iter_n = self.get(CounterId.LOOP_ITER_COUNT)
        var n_closed = pkt_n - self.get(CounterId.PER_PKT_TOTAL_OVERFLOW)
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
        if self.get(CounterId.PER_PKT_TOTAL_OVERFLOW) > UInt64(0):
            bucket_max = UInt64(8_388_608)
        var lp50 = _exact_percentile(self.hs_latency_us, 50.0)
        var lp90 = _exact_percentile(self.hs_latency_us, 90.0)
        var lp99 = _exact_percentile(self.hs_latency_us, 99.0)
        var lmax = _exact_percentile(self.hs_latency_us, 100.0)
        var s = String("{\n")
        s += '  "schema_version": 7,\n'
        s += '  "run_wall_clock_us": ' + String(run_us) + ',\n'
        s += '  "on_flush_events": ' + String(flush_n) + ',\n'
        s += '  "idle_us_total": ' + String(self.get(CounterId.IDLE_US_TOTAL)) + ',\n'
        s += '  "busy_us_total": ' + String(self.get(CounterId.BUSY_US_TOTAL)) + ',\n'
        s += _json_dict8("pkts_per_flush_histogram", self.pkts_per_flush_buckets) + ",\n"
        s += '  "per_pkt_us": {\n'
        s += '    "total":         {"p50": ' + String(p50) + ', "p90": ' + String(p90)
        s += ', "p99": ' + String(p99) + ', "max": ' + String(bucket_max)
        s += ', "n": ' + String(n_closed) + ', "overflow": ' + String(self.get(CounterId.PER_PKT_TOTAL_OVERFLOW)) + "},\n"
        s += _json_leg("header_parse", self.get(CounterId.HEADER_PARSE_US_TOTAL), pkt_n) + ",\n"
        s += _json_leg("hp",           self.get(CounterId.HP_US_TOTAL), pkt_n) + ",\n"
        s += _json_leg("aead",         self.get(CounterId.AEAD_US_TOTAL), pkt_n) + ",\n"
        s += _json_leg("frame_parse",  self.get(CounterId.FRAME_PARSE_US_TOTAL), pkt_n) + ",\n"
        s += _json_leg("sm",           self.get(CounterId.SM_US_TOTAL), pkt_n) + ",\n"
        s += _json_leg("residual",     self.get(CounterId.RESIDUAL_US_TOTAL), pkt_n) + ",\n"
        s += _json_leg("shim_ffi",     self.get(CounterId.FFI_SHIM_US_TOTAL), pkt_n) + ",\n"
        s += _json_leg("drain",        self.get(CounterId.DRAIN_US_TOTAL), pkt_n) + "\n"
        s += "  },\n"
        s += '  "arrival_lat_us_total": ' + String(self.get(CounterId.ARRIVAL_LAT_US_TOTAL)) + ',\n'
        s += '  "arrival_lat_us_overflow": ' + String(self.get(CounterId.ARRIVAL_LAT_US_OVERFLOW)) + ',\n'
        s += '  "arrival_lat_us_buckets": ' + _json_arr(self.arrival_lat_us_buckets, 24) + ",\n"
        s += '  "dcid_mismatch_pkts": ' + String(self.get(CounterId.DCID_MISMATCH_PKTS)) + ',\n'
        s += '  "handshakes": {\n    "full": ' + String(self.get(CounterId.HANDSHAKES_FULL_TOTAL))
        s += ',\n    "resumed": ' + String(self.get(CounterId.HANDSHAKES_RESUMED_TOTAL)) + '\n  },\n'
        s += '  "zero_rtt_install": {\n    "attempts": ' + String(self.get(CounterId.ZERO_RTT_INSTALL_ATTEMPTS))
        s += ',\n    "successes": ' + String(self.get(CounterId.ZERO_RTT_INSTALL_SUCCESSES)) + '\n  },\n'
        s += '  "zero_rtt_drain": {\n    "dropped": ' + String(self.get(CounterId.ZERO_RTT_DRAIN_DROPPED)) + '\n  },\n'
        s += '  "zero_rtt_replay": {\n'
        s += '    "accept": ' + String(self.get(CounterId.ZERO_RTT_REPLAY_ACCEPT)) + ',\n'
        s += '    "reject_duplicate": ' + String(self.get(CounterId.ZERO_RTT_REPLAY_REJECT_DUPLICATE)) + ',\n'
        s += '    "reject_per_key_quota": ' + String(self.get(CounterId.ZERO_RTT_REPLAY_REJECT_PER_KEY_QUOTA)) + ',\n'
        s += '    "reject_global_ceiling": ' + String(self.get(CounterId.ZERO_RTT_REPLAY_REJECT_GLOBAL_CEILING)) + ',\n'
        s += '    "reject_no_authenticator": ' + String(self.get(CounterId.ZERO_RTT_REPLAY_REJECT_NO_AUTHENTICATOR)) + '\n  },\n'
        s += '  "zero_rtt_http_filter": {\n'
        s += '    "accept": ' + String(self.get(CounterId.ZERO_RTT_HTTP_FILTER_ACCEPT)) + ',\n'
        s += '    "reject_425": ' + String(self.get(CounterId.ZERO_RTT_HTTP_FILTER_REJECT_425)) + ',\n'
        s += '    "misconfig_fail_closed": ' + String(self.get(CounterId.ZERO_RTT_HTTP_FILTER_MISCONFIG_FAIL_CLOSED)) + ',\n'
        s += '    "1rtt_bypassed": ' + String(self.get(CounterId.ZERO_RTT_HTTP_FILTER_1RTT_BYPASSED)) + ',\n'
        s += '    "user_raised": ' + String(self.get(CounterId.ZERO_RTT_HTTP_FILTER_USER_RAISED)) + '\n  },\n'
        s += _json_hist24("fresh_conn_ffi_us", self.fresh_conn_ffi_us_buckets, self.get(CounterId.FRESH_CONN_FFI_US_OVERFLOW)) + ",\n"
        s += _json_dict8("recv_batch_size_buckets", self.recv_batch_size_buckets) + ",\n"
        s += _json_dict8("read_hs_per_handshake_count_buckets", self.read_hs_per_handshake_count_buckets) + ",\n"
        s += _json_hist24("read_hs_us_per_call", self.read_hs_us_per_call_buckets, self.get(CounterId.READ_HS_US_PER_CALL_OVERFLOW)) + ",\n"
        s += _json_hist24("read_hs_input_marshalling_us", self.read_hs_input_marshalling_us_buckets, self.get(CounterId.READ_HS_INPUT_MARSHALLING_US_OVERFLOW)) + ",\n"
        s += _json_hist24("read_hs_state_machine_us", self.read_hs_state_machine_us_buckets, self.get(CounterId.READ_HS_STATE_MACHINE_US_OVERFLOW)) + ",\n"
        s += _json_hist24("read_hs_output_alloc_us", self.read_hs_output_alloc_us_buckets, self.get(CounterId.READ_HS_OUTPUT_ALLOC_US_OVERFLOW)) + ",\n"
        s += _json_hist24("read_hs_output_marshalling_us", self.read_hs_output_marshalling_us_buckets, self.get(CounterId.READ_HS_OUTPUT_MARSHALLING_US_OVERFLOW)) + ",\n"
        s += _json_hist24("alloc_tls_handle_us", self.alloc_tls_handle_us_buckets, self.get(CounterId.ALLOC_TLS_HANDLE_US_OVERFLOW)) + ",\n"
        # FFI sub-legs.
        var read_hs_avg: UInt64 = UInt64(0)
        var write_hs_avg: UInt64 = UInt64(0)
        var take_keys_avg: UInt64 = UInt64(0)
        if pkt_n > UInt64(0):
            read_hs_avg = self.get(CounterId.FFI_READ_HS_US_TOTAL) / pkt_n
            write_hs_avg = self.get(CounterId.FFI_WRITE_HS_US_TOTAL) / pkt_n
            take_keys_avg = self.get(CounterId.FFI_TAKE_KEYS_US_TOTAL) / pkt_n
        s += '  "ffi_subleg_us": {\n'
        s += '    "read_hs":   {"avg": ' + String(read_hs_avg) + ', "total": ' + String(self.get(CounterId.FFI_READ_HS_US_TOTAL)) + '},\n'
        s += '    "write_hs":  {"avg": ' + String(write_hs_avg) + ', "total": ' + String(self.get(CounterId.FFI_WRITE_HS_US_TOTAL)) + '},\n'
        s += '    "take_keys": {"avg": ' + String(take_keys_avg) + ', "total": ' + String(self.get(CounterId.FFI_TAKE_KEYS_US_TOTAL)) + '}\n  },\n'
        # Loop phases + budget closure.
        var pop_dispatch_avg: UInt64 = UInt64(0)
        var post_pkt_avg: UInt64 = UInt64(0)
        if iter_n > UInt64(0):
            pop_dispatch_avg = self.get(CounterId.LOOP_POP_DISPATCH_US_TOTAL) / iter_n
            post_pkt_avg = self.get(CounterId.LOOP_POST_PKT_US_TOTAL) / iter_n
        var teardown_avg: UInt64 = UInt64(0)
        if flush_n > UInt64(0):
            teardown_avg = self.get(CounterId.LOOP_TEARDOWN_US_TOTAL) / flush_n
        var per_pkt_legs_sum = (self.get(CounterId.HEADER_PARSE_US_TOTAL) + self.get(CounterId.HP_US_TOTAL)
            + self.get(CounterId.AEAD_US_TOTAL) + self.get(CounterId.FRAME_PARSE_US_TOTAL)
            + self.get(CounterId.SM_US_TOTAL) + self.get(CounterId.RESIDUAL_US_TOTAL))
        var accounted = (per_pkt_legs_sum + self.get(CounterId.DRAIN_US_TOTAL)
            + self.get(CounterId.LOOP_POP_DISPATCH_US_TOTAL) + self.get(CounterId.LOOP_POST_PKT_US_TOTAL)
            + self.get(CounterId.LOOP_TEARDOWN_US_TOTAL) + self.get(CounterId.H3_DRAIN_RESP_US_TOTAL)
            + self.get(CounterId.QUIC_POST_RECV_US_TOTAL) + self.get(CounterId.H3_DISPATCH_US_TOTAL))
        var busy = self.get(CounterId.BUSY_US_TOTAL)
        var unaccounted: UInt64 = UInt64(0)
        if busy > accounted:
            unaccounted = busy - accounted
        var unaccounted_pct: UInt64 = UInt64(0)
        if busy > UInt64(0):
            unaccounted_pct = (unaccounted * UInt64(100)) / busy
        s += '  "loop_phases_us": {\n'
        s += '    "pop_dispatch": {"avg": ' + String(pop_dispatch_avg) + ', "total": ' + String(self.get(CounterId.LOOP_POP_DISPATCH_US_TOTAL)) + '},\n'
        s += '    "post_pkt":     {"avg": ' + String(post_pkt_avg) + ', "total": ' + String(self.get(CounterId.LOOP_POST_PKT_US_TOTAL)) + '},\n'
        s += '    "teardown":     {"avg": ' + String(teardown_avg) + ', "total": ' + String(self.get(CounterId.LOOP_TEARDOWN_US_TOTAL)) + '},\n'
        s += '    "loop_iter_count": ' + String(iter_n) + ',\n'
        s += '    "unaccounted_us_total": ' + String(unaccounted) + ',\n'
        s += '    "unaccounted_pct": ' + String(unaccounted_pct) + '\n  },\n'
        # H3 phases.
        s += '  "h3_phases_us": {\n'
        s += '    "drain_resp": {"total": ' + String(self.get(CounterId.H3_DRAIN_RESP_US_TOTAL)) + '},\n'
        s += '    "post_recv":  {"total": ' + String(self.get(CounterId.QUIC_POST_RECV_US_TOTAL)) + '},\n'
        s += '    "dispatch":   {"total": ' + String(self.get(CounterId.H3_DISPATCH_US_TOTAL)) + '}\n  },\n'
        # Drain stream sub-legs.
        var de_us = self._compute_drain_event_dispatch_us()
        var sum_legs_us = (self.get(CounterId.DRAIN_RECV_FFI_US_TOTAL)
            + self.get(CounterId.DRAIN_BUF_ACCUMULATE_US_TOTAL)
            + self.get(CounterId.DRAIN_FRAME_PARSE_US_TOTAL)
            + self.get(CounterId.DRAIN_QPACK_DECODE_US_TOTAL) + de_us)
        var drain_total = self.get(CounterId.DRAIN_STREAM_US_TOTAL)
        var unacct_drain_pct: UInt64 = UInt64(0)
        if drain_total > UInt64(0) and sum_legs_us < drain_total:
            unacct_drain_pct = ((drain_total - sum_legs_us) * UInt64(100)) / drain_total
        s += '  "drain_stream_subleg": {\n'
        s += '    "drain_stream_us_total": ' + String(drain_total) + ',\n'
        s += '    "recv_ffi_us": ' + String(self.get(CounterId.DRAIN_RECV_FFI_US_TOTAL)) + ',\n'
        s += '    "buf_accumulate_us": ' + String(self.get(CounterId.DRAIN_BUF_ACCUMULATE_US_TOTAL)) + ',\n'
        s += '    "frame_parse_us": ' + String(self.get(CounterId.DRAIN_FRAME_PARSE_US_TOTAL)) + ',\n'
        s += '    "qpack_decode_us": ' + String(self.get(CounterId.DRAIN_QPACK_DECODE_US_TOTAL)) + ',\n'
        s += '    "event_dispatch_us": ' + String(de_us) + ',\n'
        s += '    "sum_legs_us": ' + String(sum_legs_us) + ',\n'
        s += '    "unaccounted_pct": ' + String(unacct_drain_pct) + '\n  },\n'
        # Gauge samples.
        s += '  "active_bouclette_count_samples": ' + _json_arr32(self.active_bouclette_count_samples) + ",\n"
        s += '  "in_flight_handshake_count_samples": ' + _json_arr32(self.in_flight_handshake_count_samples) + ",\n"
        s += _json_dict8("sendmsg_batch_size_buckets", self.sendmsg_batch_size_buckets) + ",\n"
        s += _json_dict8("recvmsg_batch_size_buckets", self.recvmsg_batch_size_buckets) + ",\n"
        s += _json_hist24("hs_cpu_us_per_handshake", self.hs_cpu_us_per_handshake_buckets, self.get(CounterId.HS_CPU_US_PER_HANDSHAKE_OVERFLOW)) + ",\n"
        s += _json_hist24("hs_wait_us_per_handshake", self.hs_wait_us_per_handshake_buckets, self.get(CounterId.HS_WAIT_US_PER_HANDSHAKE_OVERFLOW)) + ",\n"
        s += _json_total_hist24("iouring_park_us", self.get(CounterId.IOURING_PARK_US_TOTAL), self.iouring_park_us_buckets, self.get(CounterId.IOURING_PARK_US_OVERFLOW)) + ",\n"
        # CQEs per wake — has inner dict, not flat array.
        s += '  "cqes_per_wake": {\n'
        s += '    "wakes": ' + String(self.get(CounterId.CQES_PER_WAKE_COUNT)) + ',\n'
        s += '    "cqes_total": ' + String(self.get(CounterId.CQES_TOTAL)) + ',\n'
        s += '    "buckets": ' + _json_dict8_inner(self.cqes_per_wake_buckets) + '\n  },\n'
        s += _json_total_hist24("flush_impl_us", self.get(CounterId.FLUSH_IMPL_US_TOTAL), self.flush_impl_us_buckets, self.get(CounterId.FLUSH_IMPL_US_OVERFLOW)) + ",\n"
        s += _json_total_hist24("flush_feed_datagram_us", self.get(CounterId.FLUSH_FEED_DATAGRAM_US_TOTAL), self.flush_feed_datagram_us_buckets, self.get(CounterId.FLUSH_FEED_DATAGRAM_US_OVERFLOW)) + ",\n"
        s += '  "drain_submits_us": {\n    "total": ' + String(self.get(CounterId.DRAIN_SUBMITS_US_TOTAL)) + '\n  },\n'
        s += '  "handshake": {\n'
        s += '    "arrivals": ' + String(self.get(CounterId.HS_ARRIVALS)) + ', '
        s += '"successful": ' + String(self.get(CounterId.HS_COMPLETED)) + ', '
        s += '"timed_out": ' + String(self.get(CounterId.HS_TIMED_OUT)) + ',\n'
        s += '    "latency_us": {"p50": ' + String(lp50) + ', "p90": ' + String(lp90)
        s += ', "p99": ' + String(lp99) + ', "max": ' + String(lmax)
        s += ', "count": ' + String(len(self.hs_latency_us)) + "}\n  },\n"
        s += "  " + self.call_tracker.report_json_fragment() + "\n}\n"
        return s^


# ── ProfileState ─────────────────────────────────────────────────────


@fieldwise_init
struct ProfileState(Movable):
    """Per-connection profiling accumulators and handshake timing."""

    var ptr: Optional[Pointer[AcceptProfile, MutUntrackedOrigin]]
    var first_initial_us: UInt64
    var rustls_us_accum: UInt64
    var first_iter_done: Bool
    var fresh_conn_ffi_us_total: UInt64
    var read_hs_call_count: UInt64
    var read_hs_input_marshalling_us_total: UInt64
    var read_hs_state_machine_us_total: UInt64
    var read_hs_output_alloc_us_total: UInt64
    var read_hs_output_marshalling_us_total: UInt64
    var accept_us: UInt64
    var hs_cpu_us_total: UInt64
    var hs_wait_us_total: UInt64

    # ── Profiling helpers ────────────────────────────────────────────

    def stamp(self) -> UInt64:
        """Return monotonic_us() if profiling is compiled-in and active."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None:
                return monotonic_us()
        return UInt64(0)

    def elapsed(self, start: UInt64) -> UInt64:
        """Return monotonic_us() - start if profiling is active."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None:
                return monotonic_us() - start
        return UInt64(0)

    def is_active(self) -> Bool:
        """True when profiling is compiled-in and the pointer is set."""
        comptime if PROFILE_ACCEPT:
            return self.ptr is not None
        return False

    def begin_iter(mut self) -> UInt64:
        """Start a recv_from_buffer per-packet iteration bracket."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None:
                if self.first_iter_done:
                    self.rustls_us_accum = UInt64(0)
                return monotonic_us()
        return UInt64(0)

    def end_iter(
        mut self,
        t_start: UInt64,
        hp_us: UInt64,
        aead_us: UInt64,
        header_parse_us: UInt64,
        frame_parse_us: UInt64,
        sm_us: UInt64,
    ):
        """Close the per-packet iteration bracket and record metrics."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None:
                var total_us = monotonic_us() - t_start
                self.ptr.value()[].record_pkt(
                    total_us=total_us,
                    ffi_us=self.rustls_us_accum,
                    hp_us=hp_us,
                    aead_us=aead_us,
                    header_parse_us=header_parse_us,
                    frame_parse_us=frame_parse_us,
                    sm_us=sm_us,
                )
                self.first_iter_done = True

    def record_zero_rtt_install(mut self, ok: Bool):
        """Delegate 0-RTT key install outcome to AcceptProfile."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None:
                if ok:
                    self.ptr.value()[].record(CounterId.ZERO_RTT_INSTALL_SUCCESSES)
                else:
                    self.ptr.value()[].record(CounterId.ZERO_RTT_INSTALL_ATTEMPTS)

    def record_handshake_arrival(mut self):
        """Delegate handshake arrival to AcceptProfile."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None:
                self.ptr.value()[].record(CounterId.HS_ARRIVALS)

    def begin_drive(mut self) -> UInt64:
        """Start the _drive_handshake body bracket."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None:
                self.ptr.value()[].active_drive_count = self.ptr.value()[].active_drive_count + UInt32(1)
                return monotonic_us()
        return UInt64(0)

    def end_drive(mut self, t_start: UInt64):
        """Close the _drive_handshake body bracket."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None and t_start > UInt64(0):
                self.hs_cpu_us_total = self.hs_cpu_us_total + (monotonic_us() - t_start)
                if self.ptr.value()[].active_drive_count > UInt32(0):
                    self.ptr.value()[].active_drive_count = self.ptr.value()[].active_drive_count - UInt32(1)

    def stamp_ffi(mut self) -> UInt64:
        """Stamp and pre-subtract from rustls_us_accum for FFI brackets."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None:
                var t = monotonic_us()
                self.rustls_us_accum -= t
                return t
        return UInt64(0)

    def record_ffi_read_hs_end(
        mut self,
        t_start: UInt64,
        input_marshalling_us: UInt64,
        out_sm_us: UInt64,
        out_lookup_us: UInt64,
    ):
        """Close the read_hs FFI bracket with sub-leg accumulation."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None:
                var t_end = monotonic_us()
                self.rustls_us_accum += t_end
                var delta = t_end - t_start
                self.ptr.value()[].record_ffi_read_hs(delta)
                self.fresh_conn_ffi_us_total = self.fresh_conn_ffi_us_total + delta
                self.read_hs_call_count = self.read_hs_call_count + UInt64(1)
                self.ptr.value()[].record_read_hs_us_per_call(delta)
                self.read_hs_input_marshalling_us_total = self.read_hs_input_marshalling_us_total + input_marshalling_us
                self.read_hs_state_machine_us_total = self.read_hs_state_machine_us_total + out_sm_us
                self.read_hs_output_alloc_us_total = self.read_hs_output_alloc_us_total + out_lookup_us
                self.read_hs_output_marshalling_us_total = self.read_hs_output_marshalling_us_total + UInt64(0)
                self.ptr.value()[].record_read_hs_input_marshalling_us(input_marshalling_us)
                self.ptr.value()[].record_read_hs_state_machine_us(out_sm_us)
                self.ptr.value()[].record_read_hs_output_alloc_us(out_lookup_us)
                self.ptr.value()[].record_read_hs_output_marshalling_us(UInt64(0))

    def record_ffi_write_hs_end(mut self, t_start: UInt64):
        """Close the write_hs FFI bracket."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None:
                var t_end = monotonic_us()
                self.rustls_us_accum += t_end
                var delta = t_end - t_start
                self.ptr.value()[].record_ffi_write_hs(delta)
                self.fresh_conn_ffi_us_total = self.fresh_conn_ffi_us_total + delta

    def record_ffi_take_keys_end(mut self, t_start: UInt64):
        """Close the take_keys FFI bracket."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None:
                var t_end = monotonic_us()
                self.rustls_us_accum += t_end
                var delta = t_end - t_start
                self.ptr.value()[].record_ffi_take_keys(delta)
                self.fresh_conn_ffi_us_total = self.fresh_conn_ffi_us_total + delta

    def record_hs_complete(mut self, now: UInt64):
        """Record handshake-completion latency."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None and self.first_initial_us > UInt64(0):
                self.ptr.value()[].record_handshake_complete(now - self.first_initial_us)

    def record_counter(mut self, id: CounterId):
        """Bump any counter by ID (comptime-gated)."""
        comptime if PROFILE_ACCEPT:
            if self.ptr is not None:
                self.ptr.value()[].record(id)


# ── Free functions ──

def _init_hist(n: Int) -> List[UInt64]:
    """Create a zero-filled histogram of n buckets."""
    var h = List[UInt64]()
    for _ in range(n):
        h.append(UInt64(0))
    return h^


def _dispatch_pow2(mut buckets: List[UInt64], us: UInt64) -> Bool:
    """Dispatch into 24-bucket pow2 histogram. Returns True if overflow."""
    var b = _per_pkt_bucket(us)
    if b >= 24:
        return True
    buckets[b] = buckets[b] + UInt64(1)
    return False


def _sum_buckets(buckets: List[UInt64], n: Int) -> UInt64:
    """Sum the first n elements of a bucket list."""
    var t: UInt64 = UInt64(0)
    for i in range(n):
        t += buckets[i]
    return t


def _pkts_per_flush_bucket(pkts: Int) -> Int:
    """Map fan-out count to bucket index 0..7. Buckets [1,2-3,4-7,...,128+]."""
    if pkts <= 1: return 0
    if pkts <= 3: return 1
    if pkts <= 7: return 2
    if pkts <= 15: return 3
    if pkts <= 31: return 4
    if pkts <= 63: return 5
    if pkts <= 127: return 6
    return 7


def _per_pkt_bucket(us: UInt64) -> Int:
    """Map us to bucket 0..23 or 24 (overflow)."""
    if us == UInt64(0):
        return 0
    if us >= UInt64(8_388_608):
        return 24
    var v = us
    var i = 0
    while v >= UInt64(1):
        v = v >> UInt64(1)
        i += 1
    return i


def _exact_percentile(values: List[UInt64], p: Float64) -> UInt64:
    """Nearest-rank percentile. Sorts a copy. Returns 0 for empty."""
    var n = len(values)
    if n == 0:
        return UInt64(0)
    var sorted_v = List[UInt64](capacity=n)
    for i in range(n):
        sorted_v.append(values[i])
    for i in range(1, n):
        var key = sorted_v[i]
        var j = i - 1
        while j >= 0 and sorted_v[j] > key:
            sorted_v[j + 1] = sorted_v[j]
            j -= 1
        sorted_v[j + 1] = key
    var raw = (p / 100.0) * Float64(n)
    var idx = Int(raw)
    if Float64(idx) < raw:
        idx += 1
    idx -= 1
    if idx < 0:
        idx = 0
    if idx >= n:
        idx = n - 1
    return sorted_v[idx]


def _bucket_percentile(buckets: List[UInt64], total: UInt64, p: Float64) -> UInt64:
    """Linear-interp percentile inside a 24-bucket histogram."""
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
    return UInt64(1) << UInt64(23)


# ── Formatting helpers ──

def _fmt_count(n: UInt64) -> String:
    """Decimal with comma thousands separators."""
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


def _fmt_pct(part: UInt64, whole: UInt64) -> String:
    """Format as percentage string like (N.N%)."""
    if whole == UInt64(0):
        return String("(0.0%)")
    var pct_x10 = Int((Float64(part) * 100.0) / Float64(whole) * 10.0 + 0.5)
    return String("(") + String(pct_x10 // 10) + "." + String(pct_x10 % 10) + "%)"


def _fmt_duration_us(us: UInt64) -> String:
    """Format us as 'N.NNs' (>=1s) or 'N.NNNms' (<1s)."""
    if us >= UInt64(1_000_000):
        var secs_x100 = Int((Float64(us) / 10000.0) + 0.5)
        var frac = secs_x100 % 100
        var frac_str = String(frac)
        if frac < 10:
            frac_str = String("0") + frac_str
        return String(secs_x100 // 100) + "." + frac_str + "s"
    var ms_x1000 = Int(Float64(us) + 0.5)
    var ms_frac = ms_x1000 % 1000
    var frac_str = String(ms_frac)
    while frac_str.byte_length() < 3:
        frac_str = String("0") + frac_str
    return String(ms_x1000 // 1000) + "." + frac_str + "ms"


def _fmt_leg(label: String, total: UInt64, count: UInt64) -> String:
    """Format a timing leg as 'label:  avg=N   total=Nus'."""
    if count == UInt64(0):
        return label + ":  avg=  0   total=        0us"
    var avg = total / count
    var avg_s = String(avg)
    while avg_s.byte_length() < 3:
        avg_s = String(" ") + avg_s
    return label + ":  avg=" + avg_s + "   total=" + String(total) + "us"


def _json_leg(name: String, total: UInt64, count: UInt64) -> String:
    """Format a JSON timing leg as '    "name": {"avg": N, "total": N}'."""
    var avg: UInt64 = UInt64(0)
    if count > UInt64(0):
        avg = total / count
    var pad = String()
    while pad.byte_length() + name.byte_length() < 14:
        pad += " "
    return '    "' + name + '":' + pad + '{"avg": ' + String(avg) + ', "total": ' + String(total) + "}"


# ── JSON report helpers ──

def _json_arr(buckets: List[UInt64], n: Int) -> String:
    """Format n UInt64 values as a JSON array."""
    var s = String("[")
    for i in range(n):
        s += String(buckets[i])
        if i < n - 1:
            s += ", "
    s += "]"
    return s^


def _json_arr32(samples: List[UInt32]) -> String:
    """Format List[UInt32] as a JSON array."""
    var s = String("[")
    for i in range(len(samples)):
        s += String(samples[i])
        if i < len(samples) - 1:
            s += ", "
    s += "]"
    return s^


def _json_dict8(name: String, buckets: List[UInt64]) -> String:
    """Format 8-bucket histogram as JSON '  "name": {"1": N, ...}'."""
    var keys = _8bucket_keys()
    var s = String('  "') + name + '": {\n'
    for i in range(8):
        s += '    "' + keys[i] + '": ' + String(buckets[i])
        if i < 7:
            s += ","
        s += "\n"
    s += "  }"
    return s^


def _json_dict8_inner(buckets: List[UInt64]) -> String:
    """Format 8-bucket histogram as a JSON dict (no outer name)."""
    var keys = _8bucket_keys()
    var s = String("{\n")
    for i in range(8):
        s += '      "' + keys[i] + '": ' + String(buckets[i])
        if i < 7:
            s += ","
        s += "\n"
    s += "    }"
    return s^


def _json_hist24(name: String, buckets: List[UInt64], overflow: UInt64) -> String:
    """Format 24-bucket histogram as '  "name": {"buckets": [...], "overflow": N}'."""
    return '  "' + name + '": {\n    "buckets": ' + _json_arr(buckets, 24) + ',\n    "overflow": ' + String(overflow) + "\n  }"


def _json_total_hist24(name: String, total: UInt64, buckets: List[UInt64], overflow: UInt64) -> String:
    """Format 24-bucket histogram with total as JSON object."""
    return '  "' + name + '": {\n    "total": ' + String(total) + ',\n    "buckets": ' + _json_arr(buckets, 24) + ',\n    "overflow": ' + String(overflow) + "\n  }"


# ── Text report helpers ──

def _8bucket_keys() -> List[String]:
    """Return the 8 standard bucket key labels."""
    var k: List[String] = [
        "1", "2-3", "4-7", "8-15", "16-31", "32-63", "64-127", "128+",
    ]
    return k^


def _text_8bucket_fmt(
    buckets: List[UInt64],
    prefix: String,
    indent: String,
    total_for_pct: UInt64 = UInt64(0),
    pad_label: Bool = True,
    trailing_newline: Bool = True,
) -> String:
    """Unified 8-bucket text formatter.

    Args:
        prefix: label prefix before each range (e.g. "size=", "count=", "").
        indent: whitespace prefix per line.
        total_for_pct: when > 0, append percentage after each count.
        pad_label: when True, pad range label to 7 chars.
        trailing_newline: when True, append a blank line after the block.
    """
    var s = String()
    var ranges = _8bucket_keys()
    for i in range(8):
        var label = ranges[i]
        if pad_label:
            while label.byte_length() < 7:
                label += " "
        s += indent + prefix + label + " " + _fmt_count(buckets[i])
        if total_for_pct > UInt64(0) and buckets[i] > UInt64(0):
            s += "  " + _fmt_pct(buckets[i], total_for_pct)
        s += "\n"
    if trailing_newline:
        s += "\n"
    return s^


def _text_hist24_summary(name: String, buckets: List[UInt64], overflow: UInt64) -> String:
    """Format a 24-bucket histogram summary block (name, total, overflow)."""
    var total = _sum_buckets(buckets, 24)
    var s = name + ":\n"
    s += "  total samples:    " + _fmt_count(total) + "\n"
    s += "  overflow (>=2^23):" + _fmt_count(overflow) + "\n\n"
    return s^
