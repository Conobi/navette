# src/quic/profile.mojo
#
# QUIC accept-loop profile module (Plan A).
#
# Provides AcceptProfile (counter struct + report formatters), monotonic_us
# (sans-I/O CLOCK_MONOTONIC wrapper), and PROFILE_ACCEPT (comptime opt-in).
#
# Hand-edit PROFILE_ACCEPT to True to produce a profile build (see Plan B
# for how this gates instrumentation in connection.mojo + bench/h3_server.mojo).

from collections import Dict
from std.ffi import external_call
from std.memory import UnsafePointer


comptime PROFILE_ACCEPT: Bool = False
comptime DRAIN_TO_EAGAIN: Bool = False
comptime EGRESS_POOL: Bool = False
comptime EGRESS_POOL_SIZE: Int = 256
comptime EGRESS_POOL_V2: Bool = False
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
    """QUIC accept-loop profile counters.

    WARNING: This struct is `Copyable, Movable` for ergonomic test setup,
    but it holds 3 `List[UInt64]` fields (pkts_per_flush_buckets,
    per_pkt_total_buckets, hs_latency_us). Each `=` or pass-by-value
    triggers a deep copy of those lists — silently expensive on hot
    paths. Plan B threads `AcceptProfile` exclusively via
    `UnsafePointer[AcceptProfile, MutAnyOrigin]` (see QuicConnection
    .profile_ptr and H3UdpHandler.profile). Do NOT copy.
    """

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

    # Arrival-to-processing queueing latency (Plan: queueing-tail spec).
    # Wall-clock interval between packet ingress (_handle_recvmsg) and
    # flush-time processing (_flush_impl). Distinct from per_pkt_total
    # which times the *processing*, not the wait. PROFILE_ACCEPT-gated
    # at every measurement site in bench/h3_server.mojo.
    var arrival_lat_us_buckets: List[UInt64]   # len = 24, same layout as per_pkt_total_buckets
    var arrival_lat_us_overflow: UInt64
    var arrival_lat_us_total: UInt64

    # Per-connection packet counts and handshake-complete tracking.
    # `conn_pkt_counts` maps addr_key (src_ip:src_port String) → packet count.
    # `conn_hs_complete` is used as a Set: presence == hs_complete observed.
    # Aggregated histogram + scalar derived at report time.
    var conn_pkt_counts: Dict[String, UInt64]
    var conn_hs_complete: Dict[String, Bool]

    # Plan: 2026-04-27-quic-addr-key-dcid-collision-counter
    # Total packets where _find_conn(pd.addr_key) returned a hit but
    # pd.dcid was not in the conn's expected-DCID set.  Direct measure
    # of demux failure under PROFILE_ACCEPT.
    var dcid_mismatch_pkts: UInt64

    # 3 FFI sub-leg totals — decompose ffi_shim_us_total per rustls call-site.
    # Lifetime-accumulated (NEVER reset per-pkt). Cross-validation:
    # ffi_read_hs + ffi_write_hs + ffi_take_keys must equal ffi_shim_us_total
    # within ±1% across a 30s capture.
    var ffi_read_hs_us_total: UInt64
    var ffi_write_hs_us_total: UInt64
    var ffi_take_keys_us_total: UInt64

    # 3 loop phase totals — decompose un-attributed bench-loop overhead.
    # pop_dispatch + post_pkt are per-pkt accumulators; teardown is
    # per-flush. Divisor for pop_dispatch.avg / post_pkt.avg is
    # loop_iter_count (NOT pkt_count, which excludes continue'd iters);
    # divisor for teardown.avg is on_flush_count.
    var loop_pop_dispatch_us_total: UInt64
    var loop_post_pkt_us_total: UInt64
    var loop_teardown_us_total: UInt64
    var loop_iter_count: UInt64

    # 3 H3 phase totals — decompose long-conn unaccounted ε (Plan: 2026-04-29).
    # All three live in the post-recv tail of feed_datagram_from_buffer.
    var h3_drain_resp_us_total: UInt64
    var quic_post_recv_us_total: UInt64
    var h3_dispatch_us_total: UInt64

    # 5 sub-legs of quic_post_recv_us → _drain_stream (Plan: 2026-05-01-quic-h3-drain-stream-subleg).
    # event_dispatch is computed via residual at emit time, no field.
    var drain_stream_us_total: UInt64
    var drain_recv_ffi_us_total: UInt64
    var drain_buf_accumulate_us_total: UInt64
    var drain_frame_parse_us_total: UInt64
    var drain_qpack_decode_us_total: UInt64

    # 2 handshake-kind totals (Plan: 2026-05-03-short-conn-resumption).
    # Server-side increments exactly once per QuicConnection at handshake completion.
    # Sum invariant: handshakes_full_total + handshakes_resumed_total ==
    # number of server connections that completed the handshake.
    var handshakes_full_total: UInt64
    var handshakes_resumed_total: UInt64

    # 4 per-fresh-conn measurements (Plan: 2026-05-03-q4-fresh-conn-cpu-decomposition).
    # fresh_conn_ffi_us_buckets[24] dispatches via _per_pkt_bucket (pow2, [0, 2^23) us).
    # recv_batch_size_buckets[8] mirrors pkts_per_flush_buckets shape.
    var fresh_conn_ffi_us_buckets: List[UInt64]
    var fresh_conn_ffi_us_overflow: UInt64
    var recv_batch_size_buckets: List[UInt64]

    # 3 read_hs decomposition fields (Plan: 2026-05-03-q5-read-hs-per-call-decomposition).
    # Per-handshake call count: 8-bucket via _pkts_per_flush_bucket.
    # Per-call duration: 24-bucket pow2 via _per_pkt_bucket.
    var read_hs_per_handshake_count_buckets: List[UInt64]
    var read_hs_us_per_call_buckets: List[UInt64]
    var read_hs_us_per_call_overflow: UInt64

    # Q6 read_hs internal sub-leg histograms (Plan: 2026-05-04-q6-read-hs-internal-decomposition).
    # Four 24-bucket pow2-µs histograms decomposing per-call read_hs wall-clock into:
    #   input_marshalling  (Mojo→Rust CRYPTO copy)
    #   state_machine      (rustls conn.read_hs body)
    #   output_alloc       (Rust handle-table lookup overhead)
    #   output_marshalling (zero-by-design for read_hs; reserved for symmetric reuse)
    # All dispatch via _per_pkt_bucket (overflow on >= 2^23 us).
    var read_hs_input_marshalling_us_buckets: List[UInt64]
    var read_hs_input_marshalling_us_overflow: UInt64
    var read_hs_state_machine_us_buckets: List[UInt64]
    var read_hs_state_machine_us_overflow: UInt64
    var read_hs_output_alloc_us_buckets: List[UInt64]
    var read_hs_output_alloc_us_overflow: UInt64
    var read_hs_output_marshalling_us_buckets: List[UInt64]
    var read_hs_output_marshalling_us_overflow: UInt64

    # Q9 per-fresh-conn alloc decomposition (Plan: 2026-05-05-q9).
    # Sub-legs of fresh_conn_ffi_us_total. Each sample = one fresh-conn create.
    #   alloc_quic_state_us  (QuicConnection.server outer wall-clock; INCLUDES inner FFI)
    #   alloc_tls_handle_us  (inner quic_server_conn_new FFI call)
    #   alloc_h3_state_us    (H3HandlerServer ctor wall-clock)
    #   bench_dict_insert_us (dual-DCID Dict insert + 3 parallel-list appends)
    # Inner-outer overlap: alloc_quic_state >= alloc_tls_handle by construction.
    # Verdict §3.1 handles via threshold-priority (TLS-BOUND checked first).
    var alloc_quic_state_us_buckets: List[UInt64]
    var alloc_quic_state_us_overflow: UInt64
    var alloc_tls_handle_us_buckets: List[UInt64]
    var alloc_tls_handle_us_overflow: UInt64
    var alloc_h3_state_us_buckets: List[UInt64]
    var alloc_h3_state_us_overflow: UInt64
    var bench_dict_insert_us_buckets: List[UInt64]
    var bench_dict_insert_us_overflow: UInt64

    # Q7 cold-handshake CPU-utilization decomposition (Plan: 2026-05-04-q7).
    # Cadence gate for tick_profile_gauges (100ms cadence).
    var last_gauge_sample_us: UInt64

    # Group A — gauge sampling (capped at 600 entries each = 60s @ 10/s).
    var active_drive_count: UInt32                       # live counter (inc on _drive_handshake entry, dec on exit)
    var active_boucle_count_samples: List[UInt32]
    var in_flight_handshake_count_samples: List[UInt32]

    # Group B — batch-size histograms (8-bucket via _pkts_per_flush_bucket).
    var sendmsg_batch_size_buckets: List[UInt64]
    var recvmsg_batch_size_buckets: List[UInt64]

    # Group C — 3 lock-wait surfaces (24-bucket pow2 via _per_pkt_bucket).
    var demux_map_lock_wait_us_total: UInt64
    var demux_map_lock_wait_us_buckets: List[UInt64]
    var demux_map_lock_wait_us_overflow: UInt64
    var rustls_config_clone_lock_wait_us_total: UInt64
    var rustls_config_clone_lock_wait_us_buckets: List[UInt64]
    var rustls_config_clone_lock_wait_us_overflow: UInt64
    var ticket_store_lock_wait_us_total: UInt64
    var ticket_store_lock_wait_us_buckets: List[UInt64]
    var ticket_store_lock_wait_us_overflow: UInt64

    # Group D — per-FD per-handshake CPU vs wait histograms (24-bucket pow2 via _per_pkt_bucket).
    var hs_cpu_us_per_handshake_buckets: List[UInt64]
    var hs_cpu_us_per_handshake_overflow: UInt64
    var hs_wait_us_per_handshake_buckets: List[UInt64]
    var hs_wait_us_per_handshake_overflow: UInt64

    # Group F — H_F instrumentation (PARK-BOUND verdict). Total-only per spec §4.6.1.
    var iouring_park_us_total: UInt64

    # Per-addr_key mismatch counts.  Same Dict shape as conn_pkt_counts.
    var addr_key_mismatch_counts: Dict[String, UInt64]

    # Drain-extension counters (Plan: 2026-05-05-quic-bench-drain-extension).
    # `drain_extension_pkts_total` accumulates datagrams pulled by the userspace
    # recvfrom-until-EAGAIN loop wired in bench/h3_server.mojo (T2/T3).
    # `drain_extension_overflow_count` ticks once per `_flush_impl` invocation
    # that exhausted the scratch_pool before EAGAIN — a sizing-pressure signal
    # for the scratch_pool ceiling.
    var drain_extension_pkts_total: UInt64
    var drain_extension_overflow_count: UInt64

    # Egress-pool counters (Plan: 2026-05-05-q8-egress-hot-path-batching).
    # `egress_pool_hits_total` ticks each time `_drain_and_send` reuses a slot
    # popped from the `H3UdpHandler.egress_pool_freelist`; `egress_pool_misses_total`
    # ticks when the freelist was empty and the slot fell back to `_heap_alloc`.
    # Hit/(hit+miss) ratio reports pool reuse rate (target ≥0.95 per AC7).
    var egress_pool_hits_total: UInt64
    var egress_pool_misses_total: UInt64

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
        self.arrival_lat_us_buckets = List[UInt64]()
        for _ in range(24):
            self.arrival_lat_us_buckets.append(UInt64(0))
        self.arrival_lat_us_overflow = UInt64(0)
        self.arrival_lat_us_total = UInt64(0)
        self.conn_pkt_counts = Dict[String, UInt64]()
        self.conn_hs_complete = Dict[String, Bool]()
        self.dcid_mismatch_pkts = UInt64(0)
        self.ffi_read_hs_us_total = UInt64(0)
        self.ffi_write_hs_us_total = UInt64(0)
        self.ffi_take_keys_us_total = UInt64(0)
        self.loop_pop_dispatch_us_total = UInt64(0)
        self.loop_post_pkt_us_total = UInt64(0)
        self.loop_teardown_us_total = UInt64(0)
        self.loop_iter_count = UInt64(0)
        self.h3_drain_resp_us_total = UInt64(0)
        self.quic_post_recv_us_total = UInt64(0)
        self.h3_dispatch_us_total = UInt64(0)
        self.drain_stream_us_total = UInt64(0)
        self.drain_recv_ffi_us_total = UInt64(0)
        self.drain_buf_accumulate_us_total = UInt64(0)
        self.drain_frame_parse_us_total = UInt64(0)
        self.drain_qpack_decode_us_total = UInt64(0)
        self.handshakes_full_total = UInt64(0)
        self.handshakes_resumed_total = UInt64(0)
        self.fresh_conn_ffi_us_buckets = List[UInt64]()
        for _ in range(24):
            self.fresh_conn_ffi_us_buckets.append(UInt64(0))
        self.fresh_conn_ffi_us_overflow = UInt64(0)
        self.recv_batch_size_buckets = List[UInt64]()
        for _ in range(8):
            self.recv_batch_size_buckets.append(UInt64(0))
        self.read_hs_per_handshake_count_buckets = List[UInt64]()
        for _ in range(8):
            self.read_hs_per_handshake_count_buckets.append(UInt64(0))
        self.read_hs_us_per_call_buckets = List[UInt64]()
        for _ in range(24):
            self.read_hs_us_per_call_buckets.append(UInt64(0))
        self.read_hs_us_per_call_overflow = UInt64(0)
        # Q6 init (Plan: 2026-05-04-q6-read-hs-internal-decomposition).
        self.read_hs_input_marshalling_us_buckets = List[UInt64]()
        self.read_hs_state_machine_us_buckets = List[UInt64]()
        self.read_hs_output_alloc_us_buckets = List[UInt64]()
        self.read_hs_output_marshalling_us_buckets = List[UInt64]()
        for _ in range(24):
            self.read_hs_input_marshalling_us_buckets.append(UInt64(0))
            self.read_hs_state_machine_us_buckets.append(UInt64(0))
            self.read_hs_output_alloc_us_buckets.append(UInt64(0))
            self.read_hs_output_marshalling_us_buckets.append(UInt64(0))
        self.read_hs_input_marshalling_us_overflow = UInt64(0)
        self.read_hs_state_machine_us_overflow = UInt64(0)
        self.read_hs_output_alloc_us_overflow = UInt64(0)
        self.read_hs_output_marshalling_us_overflow = UInt64(0)
        # Q9 init (Plan: 2026-05-05-q9).
        self.alloc_quic_state_us_buckets = List[UInt64]()
        self.alloc_tls_handle_us_buckets = List[UInt64]()
        self.alloc_h3_state_us_buckets = List[UInt64]()
        self.bench_dict_insert_us_buckets = List[UInt64]()
        for _ in range(24):
            self.alloc_quic_state_us_buckets.append(UInt64(0))
            self.alloc_tls_handle_us_buckets.append(UInt64(0))
            self.alloc_h3_state_us_buckets.append(UInt64(0))
            self.bench_dict_insert_us_buckets.append(UInt64(0))
        self.alloc_quic_state_us_overflow = UInt64(0)
        self.alloc_tls_handle_us_overflow = UInt64(0)
        self.alloc_h3_state_us_overflow = UInt64(0)
        self.bench_dict_insert_us_overflow = UInt64(0)
        # Q7 init (Plan: 2026-05-04-q7).
        self.last_gauge_sample_us = UInt64(0)
        self.active_drive_count = UInt32(0)
        self.active_boucle_count_samples = List[UInt32]()
        self.in_flight_handshake_count_samples = List[UInt32]()
        self.sendmsg_batch_size_buckets = List[UInt64]()
        self.recvmsg_batch_size_buckets = List[UInt64]()
        for _ in range(8):
            self.sendmsg_batch_size_buckets.append(UInt64(0))
            self.recvmsg_batch_size_buckets.append(UInt64(0))
        self.demux_map_lock_wait_us_total = UInt64(0)
        self.demux_map_lock_wait_us_overflow = UInt64(0)
        self.demux_map_lock_wait_us_buckets = List[UInt64]()
        self.rustls_config_clone_lock_wait_us_total = UInt64(0)
        self.rustls_config_clone_lock_wait_us_overflow = UInt64(0)
        self.rustls_config_clone_lock_wait_us_buckets = List[UInt64]()
        self.ticket_store_lock_wait_us_total = UInt64(0)
        self.ticket_store_lock_wait_us_overflow = UInt64(0)
        self.ticket_store_lock_wait_us_buckets = List[UInt64]()
        self.hs_cpu_us_per_handshake_buckets = List[UInt64]()
        self.hs_cpu_us_per_handshake_overflow = UInt64(0)
        self.hs_wait_us_per_handshake_buckets = List[UInt64]()
        self.hs_wait_us_per_handshake_overflow = UInt64(0)
        for _ in range(24):
            self.demux_map_lock_wait_us_buckets.append(UInt64(0))
            self.rustls_config_clone_lock_wait_us_buckets.append(UInt64(0))
            self.ticket_store_lock_wait_us_buckets.append(UInt64(0))
            self.hs_cpu_us_per_handshake_buckets.append(UInt64(0))
            self.hs_wait_us_per_handshake_buckets.append(UInt64(0))
        self.iouring_park_us_total = UInt64(0)
        self.addr_key_mismatch_counts = Dict[String, UInt64]()
        self.drain_extension_pkts_total = UInt64(0)
        self.drain_extension_overflow_count = UInt64(0)
        self.egress_pool_hits_total = UInt64(0)
        self.egress_pool_misses_total = UInt64(0)

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

    def record_arrival_lat(mut self, us: UInt64):
        """Record per-packet queueing latency (arrival → processing dispatch).

        Dispatches into 24-bucket power-of-2 histogram via _per_pkt_bucket.
        Values >= 2^23 us go to arrival_lat_us_overflow; total sum always
        accumulated regardless of bucket vs overflow.
        """
        self.arrival_lat_us_total += us
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.arrival_lat_us_overflow += UInt64(1)
        else:
            self.arrival_lat_us_buckets[b] += UInt64(1)

    def record_conn_pkt(mut self, addr_key: String) raises:
        """Increment per-connection packet counter for `addr_key`."""
        if addr_key in self.conn_pkt_counts:
            self.conn_pkt_counts[addr_key] = self.conn_pkt_counts[addr_key] + UInt64(1)
        else:
            self.conn_pkt_counts[addr_key] = UInt64(1)

    def record_conn_hs_complete(mut self, addr_key: String):
        """Mark addr_key as having completed the QUIC handshake.

        Idempotent: redundant calls (per-packet polling of is_established())
        result in only one entry in conn_hs_complete.
        """
        self.conn_hs_complete[addr_key] = True

    def record_dcid_mismatch(mut self, addr_key: String) raises:
        """Record a packet whose dcid did not match the conn for its addr_key.

        Caller has already done the membership test against
        QuicConnection.is_expected_dcid; this method only counts.
        """
        self.dcid_mismatch_pkts = self.dcid_mismatch_pkts + UInt64(1)
        if addr_key in self.addr_key_mismatch_counts:
            self.addr_key_mismatch_counts[addr_key] = (
                self.addr_key_mismatch_counts[addr_key] + UInt64(1))
        else:
            self.addr_key_mismatch_counts[addr_key] = UInt64(1)

    def record_ffi_read_hs(mut self, us: UInt64):
        self.ffi_read_hs_us_total = self.ffi_read_hs_us_total + us

    def record_ffi_write_hs(mut self, us: UInt64):
        self.ffi_write_hs_us_total = self.ffi_write_hs_us_total + us

    def record_ffi_take_keys(mut self, us: UInt64):
        self.ffi_take_keys_us_total = self.ffi_take_keys_us_total + us

    def record_loop_pop_dispatch(mut self, us: UInt64):
        self.loop_pop_dispatch_us_total = self.loop_pop_dispatch_us_total + us

    def record_loop_post_pkt(mut self, us: UInt64):
        self.loop_post_pkt_us_total = self.loop_post_pkt_us_total + us

    def record_loop_teardown(mut self, us: UInt64):
        self.loop_teardown_us_total = self.loop_teardown_us_total + us

    def record_loop_iter(mut self):
        self.loop_iter_count = self.loop_iter_count + UInt64(1)

    def record_h3_drain_resp(mut self, us: UInt64):
        self.h3_drain_resp_us_total = self.h3_drain_resp_us_total + us

    def record_quic_post_recv(mut self, us: UInt64):
        self.quic_post_recv_us_total = self.quic_post_recv_us_total + us

    def record_h3_dispatch(mut self, us: UInt64):
        self.h3_dispatch_us_total = self.h3_dispatch_us_total + us

    def record_drain_stream(mut self, us: UInt64):
        self.drain_stream_us_total = self.drain_stream_us_total + us

    def record_drain_recv_ffi(mut self, us: UInt64):
        self.drain_recv_ffi_us_total = self.drain_recv_ffi_us_total + us

    def record_drain_buf_accumulate(mut self, us: UInt64):
        self.drain_buf_accumulate_us_total = self.drain_buf_accumulate_us_total + us

    def record_drain_frame_parse(mut self, us: UInt64):
        self.drain_frame_parse_us_total = self.drain_frame_parse_us_total + us

    def record_drain_qpack_decode(mut self, us: UInt64):
        self.drain_qpack_decode_us_total = self.drain_qpack_decode_us_total + us

    def record_handshake_full(mut self):
        """Increment full-handshake counter. Called once per server-side
        connection whose handshake completed without resumption."""
        self.handshakes_full_total = self.handshakes_full_total + UInt64(1)

    def record_handshake_resumed(mut self):
        """Increment resumed-handshake counter. Called once per server-side
        connection whose handshake completed via TLS 1.3 PSK/ticket resumption."""
        self.handshakes_resumed_total = self.handshakes_resumed_total + UInt64(1)

    def record_fresh_conn_ffi_us(mut self, us: UInt64):
        """Increment the histogram bucket for a per-fresh-conn FFI total.
        Called once per server-side connection at handshake-completion edge."""
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.fresh_conn_ffi_us_overflow = self.fresh_conn_ffi_us_overflow + UInt64(1)
        else:
            self.fresh_conn_ffi_us_buckets[b] = self.fresh_conn_ffi_us_buckets[b] + UInt64(1)

    def record_recv_batch(mut self, n: Int):
        """Increment the histogram bucket for a recvmsg-completion event size.
        Called once per recvmsg CQE; with multishot recvmsg, n=1 every call."""
        var b = _pkts_per_flush_bucket(n)
        self.recv_batch_size_buckets[b] = self.recv_batch_size_buckets[b] + UInt64(1)

    def record_read_hs_per_handshake_count(mut self, n: Int):
        """Increment 8-bucket histogram for per-server-conn read_hs call count.
        Called once at _on_handshake_complete server-side."""
        var b = _pkts_per_flush_bucket(n)
        self.read_hs_per_handshake_count_buckets[b] = self.read_hs_per_handshake_count_buckets[b] + UInt64(1)

    def record_read_hs_us_per_call(mut self, us: UInt64):
        """Increment 24-bucket pow2 histogram for per-call read_hs duration.
        Called per read_hs FFI bracket completion."""
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.read_hs_us_per_call_overflow = self.read_hs_us_per_call_overflow + UInt64(1)
        else:
            self.read_hs_us_per_call_buckets[b] = self.read_hs_us_per_call_buckets[b] + UInt64(1)

    # Q6 read_hs internal sub-leg record methods (Plan: 2026-05-04-q6).
    # Each dispatches via _per_pkt_bucket; overflow on >= 2^23 us.

    def record_read_hs_input_marshalling_us(mut self, us: UInt64):
        """Q6 — Mojo-side input marshalling (CRYPTO bytes alloc + per-byte copy)."""
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.read_hs_input_marshalling_us_overflow = self.read_hs_input_marshalling_us_overflow + UInt64(1)
        else:
            self.read_hs_input_marshalling_us_buckets[b] = self.read_hs_input_marshalling_us_buckets[b] + UInt64(1)

    def record_read_hs_state_machine_us(mut self, us: UInt64):
        """Q6 — Rust-side rustls conn.read_hs body (TLS state machine + crypto)."""
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.read_hs_state_machine_us_overflow = self.read_hs_state_machine_us_overflow + UInt64(1)
        else:
            self.read_hs_state_machine_us_buckets[b] = self.read_hs_state_machine_us_buckets[b] + UInt64(1)

    def record_read_hs_output_alloc_us(mut self, us: UInt64):
        """Q6 — Rust-side handle-table lookup overhead (with_mut path)."""
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.read_hs_output_alloc_us_overflow = self.read_hs_output_alloc_us_overflow + UInt64(1)
        else:
            self.read_hs_output_alloc_us_buckets[b] = self.read_hs_output_alloc_us_buckets[b] + UInt64(1)

    def record_read_hs_output_marshalling_us(mut self, us: UInt64):
        """Q6 — Rust→Mojo output copy on read_hs return.
        Zero-by-design for read_hs (returns status only); slot reserved for
        future symmetric write_hs/take_keys decomposition reuse."""
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.read_hs_output_marshalling_us_overflow = self.read_hs_output_marshalling_us_overflow + UInt64(1)
        else:
            self.read_hs_output_marshalling_us_buckets[b] = self.read_hs_output_marshalling_us_buckets[b] + UInt64(1)

    # Q9 per-fresh-conn alloc decomposition record methods (Plan: 2026-05-05-q9).
    # Each fired ONCE per fresh-conn-create event in bench/h3_server.mojo's
    # cold-create branch (alloc_tls_handle fires inside QuicConnection.server).

    def record_alloc_quic_state_us(mut self, us: UInt64):
        """Q9 — QuicConnection.server outer wall-clock (INCLUDES inner FFI)."""
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.alloc_quic_state_us_overflow = self.alloc_quic_state_us_overflow + UInt64(1)
        else:
            self.alloc_quic_state_us_buckets[b] = self.alloc_quic_state_us_buckets[b] + UInt64(1)

    def record_alloc_tls_handle_us(mut self, us: UInt64):
        """Q9 — inner quic_server_conn_new FFI call (rustls TLS session alloc)."""
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.alloc_tls_handle_us_overflow = self.alloc_tls_handle_us_overflow + UInt64(1)
        else:
            self.alloc_tls_handle_us_buckets[b] = self.alloc_tls_handle_us_buckets[b] + UInt64(1)

    def record_alloc_h3_state_us(mut self, us: UInt64):
        """Q9 — H3HandlerServer ctor wall-clock (QPACK init, stream maps)."""
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.alloc_h3_state_us_overflow = self.alloc_h3_state_us_overflow + UInt64(1)
        else:
            self.alloc_h3_state_us_buckets[b] = self.alloc_h3_state_us_buckets[b] + UInt64(1)

    def record_bench_dict_insert_us(mut self, us: UInt64):
        """Q9 — conn_dcid_map dual insert + 3 parallel-list appends (bench-side)."""
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.bench_dict_insert_us_overflow = self.bench_dict_insert_us_overflow + UInt64(1)
        else:
            self.bench_dict_insert_us_buckets[b] = self.bench_dict_insert_us_buckets[b] + UInt64(1)

    # Q7 cold-handshake CPU-utilization decomposition (Plan: 2026-05-04-q7).
    fn tick_profile_gauges(mut self, now_us: UInt64):
        """100ms-cadence sampler. No-ops if last sample < 100_000us ago.
        Cadence gate stored as field (not caller-owned) per spec §3.2 / AC2.
        Caller writes to active_drive_count via inc/dec at _drive_handshake;
        in-flight HS = handshakes_started - (full + resumed) running totals.

        First call (when last_gauge_sample_us == 0) always captures, so the
        cadence gate doesn't swallow the bench window's leading sample.
        """
        if self.last_gauge_sample_us != UInt64(0) and now_us - self.last_gauge_sample_us < UInt64(100_000):
            return
        # last_gauge_sample_us == 0 sentinel for "never sampled". After the
        # first sample, store max(1, now_us) so the sentinel can never re-fire
        # if the caller passes now_us == 0 (e.g. test fixtures or clock skew).
        if now_us == UInt64(0):
            self.last_gauge_sample_us = UInt64(1)
        else:
            self.last_gauge_sample_us = now_us
        if len(self.active_boucle_count_samples) < 600:
            self.active_boucle_count_samples.append(self.active_drive_count)
        # In-flight = handshakes_started_total - completed_total. If P2 has no
        # handshakes_started_total counter, T2 adds it (additive scope per §7.4 risk).
        # For now, use active_drive_count as proxy gauge until handshakes_started lands.
        var inflight: UInt32 = self.active_drive_count
        if len(self.in_flight_handshake_count_samples) < 600:
            self.in_flight_handshake_count_samples.append(inflight)

    def record_sendmsg_batch_size(mut self, n: Int):
        """Q7 Group B — sendmsg batch-size histogram (8-bucket via _pkts_per_flush_bucket)."""
        var b = _pkts_per_flush_bucket(n)
        self.sendmsg_batch_size_buckets[b] = self.sendmsg_batch_size_buckets[b] + UInt64(1)

    def record_recvmsg_batch_size(mut self, n: Int):
        """Q7 Group B — recvmsg batch-size histogram (8-bucket via _pkts_per_flush_bucket)."""
        var b = _pkts_per_flush_bucket(n)
        self.recvmsg_batch_size_buckets[b] = self.recvmsg_batch_size_buckets[b] + UInt64(1)

    def record_demux_map_lock_wait_us(mut self, us: UInt64):
        """Q7 Group C — Mojo-side addr_key→conn Dict lookup duration."""
        self.demux_map_lock_wait_us_total = self.demux_map_lock_wait_us_total + us
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.demux_map_lock_wait_us_overflow = self.demux_map_lock_wait_us_overflow + UInt64(1)
        else:
            self.demux_map_lock_wait_us_buckets[b] = self.demux_map_lock_wait_us_buckets[b] + UInt64(1)

    def record_rustls_config_clone_lock_wait_us(mut self, us: UInt64):
        """Q7 Group C — Rust-side Arc<rustls::ServerConfig> clone path duration."""
        self.rustls_config_clone_lock_wait_us_total = self.rustls_config_clone_lock_wait_us_total + us
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.rustls_config_clone_lock_wait_us_overflow = self.rustls_config_clone_lock_wait_us_overflow + UInt64(1)
        else:
            self.rustls_config_clone_lock_wait_us_buckets[b] = self.rustls_config_clone_lock_wait_us_buckets[b] + UInt64(1)

    def record_ticket_store_lock_wait_us(mut self, us: UInt64):
        """Q7 Group C — Rust-side TLS 1.3 session-ticket store mutex duration."""
        self.ticket_store_lock_wait_us_total = self.ticket_store_lock_wait_us_total + us
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.ticket_store_lock_wait_us_overflow = self.ticket_store_lock_wait_us_overflow + UInt64(1)
        else:
            self.ticket_store_lock_wait_us_buckets[b] = self.ticket_store_lock_wait_us_buckets[b] + UInt64(1)

    def record_hs_cpu_us_per_handshake(mut self, us: UInt64):
        """Q7 Group D — per-FD per-handshake CPU duration (24-bucket pow2)."""
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.hs_cpu_us_per_handshake_overflow = self.hs_cpu_us_per_handshake_overflow + UInt64(1)
        else:
            self.hs_cpu_us_per_handshake_buckets[b] = self.hs_cpu_us_per_handshake_buckets[b] + UInt64(1)

    def record_hs_wait_us_per_handshake(mut self, us: UInt64):
        """Q7 Group D — per-FD per-handshake wait duration (24-bucket pow2)."""
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.hs_wait_us_per_handshake_overflow = self.hs_wait_us_per_handshake_overflow + UInt64(1)
        else:
            self.hs_wait_us_per_handshake_buckets[b] = self.hs_wait_us_per_handshake_buckets[b] + UInt64(1)

    fn record_iouring_park_us(mut self, us: UInt64):
        """Q7 Group F — H_F PARK-BOUND instrumentation. Total-only — bracket
        every io_uring_enter call site (or equivalent submit-and-wait entry)."""
        self.iouring_park_us_total = self.iouring_park_us_total + us

    def record_drain_extension(mut self, n: UInt64, overflowed: Bool):
        """Drain-extension instrumentation (Plan: 2026-05-05-quic-bench-drain-extension).

        Records a single `_drain_extension` invocation pulling `n` datagrams.
        `overflowed=True` indicates the scratch_pool was exhausted before
        EAGAIN — caller still pulled `n` datagrams (`n` may be the pool cap).
        Only the overflow event count ticks; `n` is added to the running total
        regardless.
        """
        self.drain_extension_pkts_total += n
        if overflowed:
            self.drain_extension_overflow_count += UInt64(1)

    def record_egress_pool_hit(mut self):
        """Egress-pool hit (Plan: 2026-05-05-q8-egress-hot-path-batching).

        Records a single `_drain_and_send` slot acquisition that reused an
        `UdpTxSlot` popped from `H3UdpHandler.egress_pool_freelist`.
        """
        self.egress_pool_hits_total += UInt64(1)

    def record_egress_pool_miss(mut self):
        """Egress-pool miss (Plan: 2026-05-05-q8-egress-hot-path-batching).

        Records a single `_drain_and_send` slot acquisition that fell back to
        `_heap_alloc` because `H3UdpHandler.egress_pool_freelist` was empty
        (peak burst exceeded `EGRESS_POOL_SIZE`).
        """
        self.egress_pool_misses_total += UInt64(1)

    def report_text(self) raises -> String:
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

        # Arrival-to-processing latency.
        s += "Arrival-to-processing latency (bucket-estimated p_n, us):\n"
        var arr_total_obs: UInt64 = UInt64(0)
        for i in range(24):
            arr_total_obs += self.arrival_lat_us_buckets[i]
        var arr_p50 = _bucket_percentile(self.arrival_lat_us_buckets, arr_total_obs, 50.0)
        var arr_p90 = _bucket_percentile(self.arrival_lat_us_buckets, arr_total_obs, 90.0)
        var arr_p99 = _bucket_percentile(self.arrival_lat_us_buckets, arr_total_obs, 99.0)
        s += "  total:           p50=" + String(arr_p50) + "  p90=" + String(arr_p90) + "  p99=" + String(arr_p99)
        s += "  (n=" + String(arr_total_obs) + ", overflow=" + String(self.arrival_lat_us_overflow) + ")\n"
        s += "  total_us:        " + String(self.arrival_lat_us_total) + "\n\n"

        # Per-connection packet counts (aggregated histogram).
        s += "Per-connection packet counts (aggregated 8-bucket histogram):\n"
        var pc_buckets = List[UInt64]()
        for _ in range(8):
            pc_buckets.append(UInt64(0))
        var pc_total: UInt64 = UInt64(0)
        var pc_no_hs: UInt64 = UInt64(0)
        for entry in self.conn_pkt_counts.items():
            pc_total += UInt64(1)
            var b = _pkts_per_flush_bucket(Int(entry.value))
            pc_buckets[b] += UInt64(1)
            if entry.key not in self.conn_hs_complete:
                pc_no_hs += UInt64(1)
        var pc_labels = List[String]()
        pc_labels.append(String("size=1     "))
        pc_labels.append(String("size=2-3   "))
        pc_labels.append(String("size=4-7   "))
        pc_labels.append(String("size=8-15  "))
        pc_labels.append(String("size=16-31 "))
        pc_labels.append(String("size=32-63 "))
        pc_labels.append(String("size=64-127"))
        pc_labels.append(String("size=128+  "))
        for i in range(8):
            s += "  " + pc_labels[i] + " " + _fmt_count(pc_buckets[i]) + "\n"
        s += "  conns_total:                  " + _fmt_count(pc_total) + "\n"
        s += "  conns_with_pkts_no_hs_complete:" + _fmt_count(pc_no_hs) + "\n\n"

        # addr_key DCID-mismatch section (Plan: 2026-04-27 collision counter).
        s += "-- addr_key DCID mismatch --\n"
        s += "  total mismatch pkts:    " + String(self.dcid_mismatch_pkts) + "\n"
        s += "  addr_keys total:        " + String(len(self.addr_key_mismatch_counts)) + "\n"
        var addr_keys_with_mismatch_t: UInt64 = UInt64(0)
        for entry in self.addr_key_mismatch_counts.items():
            if entry.value > UInt64(0):
                addr_keys_with_mismatch_t = addr_keys_with_mismatch_t + UInt64(1)
        s += "  addr_keys w/ mismatch:  " + String(addr_keys_with_mismatch_t) + "\n"
        for entry in self.addr_key_mismatch_counts.items():
            s += "    " + entry.key + ": " + String(entry.value) + "\n"
        s += "\n"

        # Handshake kinds (Plan: 2026-05-03-short-conn-resumption).
        s += "Handshake kinds:\n"
        s += "  full:    " + _fmt_count(self.handshakes_full_total) + "\n"
        s += "  resumed: " + _fmt_count(self.handshakes_resumed_total) + "\n\n"

        # Drain-extension (Plan: 2026-05-05-quic-bench-drain-extension).
        s += "drain_extension:\n"
        s += "  pkts_total:     " + _fmt_count(self.drain_extension_pkts_total) + "\n"
        s += "  overflow_count: " + _fmt_count(self.drain_extension_overflow_count) + "\n\n"

        # Egress-pool (Plan: 2026-05-05-q8-egress-hot-path-batching).
        s += "egress_pool:\n"
        s += "  hits_total:   " + _fmt_count(self.egress_pool_hits_total) + "\n"
        s += "  misses_total: " + _fmt_count(self.egress_pool_misses_total) + "\n\n"

        # Per-fresh-conn measurements (Plan: 2026-05-03-q4-fresh-conn-cpu-decomposition).
        s += "Per-fresh-conn FFI us (24-bucket pow2):\n"
        var fci_total: UInt64 = UInt64(0)
        for i in range(24):
            fci_total = fci_total + self.fresh_conn_ffi_us_buckets[i]
        s += "  total samples:    " + _fmt_count(fci_total) + "\n"
        s += "  overflow (>=2^23):" + _fmt_count(self.fresh_conn_ffi_us_overflow) + "\n"

        s += "Recv-batch size (8-bucket):\n"
        var rb_labels = List[String]()
        rb_labels.append(String("1     "))
        rb_labels.append(String("2-3   "))
        rb_labels.append(String("4-7   "))
        rb_labels.append(String("8-15  "))
        rb_labels.append(String("16-31 "))
        rb_labels.append(String("32-63 "))
        rb_labels.append(String("64-127"))
        rb_labels.append(String("128+  "))
        for i in range(8):
            s += "  size=" + rb_labels[i] + " " + _fmt_count(self.recv_batch_size_buckets[i]) + "\n"
        s += "\n"

        # Q5 read_hs decomposition (Plan: 2026-05-03-q5-read-hs-per-call-decomposition).
        s += "read_hs per-handshake count (8-bucket):\n"
        var rh_labels = List[String]()
        rh_labels.append(String("1     "))
        rh_labels.append(String("2-3   "))
        rh_labels.append(String("4-7   "))
        rh_labels.append(String("8-15  "))
        rh_labels.append(String("16-31 "))
        rh_labels.append(String("32-63 "))
        rh_labels.append(String("64-127"))
        rh_labels.append(String("128+  "))
        for i in range(8):
            s += "  count=" + rh_labels[i] + " " + _fmt_count(self.read_hs_per_handshake_count_buckets[i]) + "\n"

        s += "read_hs per-call duration (24-bucket pow2 us):\n"
        var rd_total: UInt64 = UInt64(0)
        for i in range(24):
            rd_total = rd_total + self.read_hs_us_per_call_buckets[i]
        s += "  total samples:    " + _fmt_count(rd_total) + "\n"
        s += "  overflow (>=2^23):" + _fmt_count(self.read_hs_us_per_call_overflow) + "\n\n"

        # Q6 read_hs sub-leg histograms (Plan: 2026-05-04-q6).
        s += "read_hs_input_marshalling_us:\n"
        var rh_im_total: UInt64 = UInt64(0)
        for i in range(24):
            rh_im_total = rh_im_total + self.read_hs_input_marshalling_us_buckets[i]
        s += "  total samples:    " + _fmt_count(rh_im_total) + "\n"
        s += "  overflow (>=2^23):" + _fmt_count(self.read_hs_input_marshalling_us_overflow) + "\n\n"

        s += "read_hs_state_machine_us:\n"
        var rh_sm_total: UInt64 = UInt64(0)
        for i in range(24):
            rh_sm_total = rh_sm_total + self.read_hs_state_machine_us_buckets[i]
        s += "  total samples:    " + _fmt_count(rh_sm_total) + "\n"
        s += "  overflow (>=2^23):" + _fmt_count(self.read_hs_state_machine_us_overflow) + "\n\n"

        s += "read_hs_output_alloc_us:\n"
        var rh_oa_total: UInt64 = UInt64(0)
        for i in range(24):
            rh_oa_total = rh_oa_total + self.read_hs_output_alloc_us_buckets[i]
        s += "  total samples:    " + _fmt_count(rh_oa_total) + "\n"
        s += "  overflow (>=2^23):" + _fmt_count(self.read_hs_output_alloc_us_overflow) + "\n\n"

        s += "read_hs_output_marshalling_us:\n"
        var rh_om_total: UInt64 = UInt64(0)
        for i in range(24):
            rh_om_total = rh_om_total + self.read_hs_output_marshalling_us_buckets[i]
        s += "  total samples:    " + _fmt_count(rh_om_total) + "\n"
        s += "  overflow (>=2^23):" + _fmt_count(self.read_hs_output_marshalling_us_overflow) + "\n\n"

        # Q9 per-fresh-conn alloc sub-leg histograms (Plan: 2026-05-05-q9).
        s += "alloc_quic_state_us:\n"
        var aqs_total: UInt64 = UInt64(0)
        for i in range(24):
            aqs_total = aqs_total + self.alloc_quic_state_us_buckets[i]
        s += "  total samples:    " + _fmt_count(aqs_total) + "\n"
        s += "  overflow (>=2^23):" + _fmt_count(self.alloc_quic_state_us_overflow) + "\n\n"

        s += "alloc_tls_handle_us:\n"
        var ath_total: UInt64 = UInt64(0)
        for i in range(24):
            ath_total = ath_total + self.alloc_tls_handle_us_buckets[i]
        s += "  total samples:    " + _fmt_count(ath_total) + "\n"
        s += "  overflow (>=2^23):" + _fmt_count(self.alloc_tls_handle_us_overflow) + "\n\n"

        s += "alloc_h3_state_us:\n"
        var ahs_total: UInt64 = UInt64(0)
        for i in range(24):
            ahs_total = ahs_total + self.alloc_h3_state_us_buckets[i]
        s += "  total samples:    " + _fmt_count(ahs_total) + "\n"
        s += "  overflow (>=2^23):" + _fmt_count(self.alloc_h3_state_us_overflow) + "\n\n"

        s += "bench_dict_insert_us:\n"
        var bdi_total: UInt64 = UInt64(0)
        for i in range(24):
            bdi_total = bdi_total + self.bench_dict_insert_us_buckets[i]
        s += "  total samples:    " + _fmt_count(bdi_total) + "\n"
        s += "  overflow (>=2^23):" + _fmt_count(self.bench_dict_insert_us_overflow) + "\n\n"

        # FFI sub-legs (Plan: 2026-04-28).
        s += "FFI sub-legs:\n"
        s += "  " + _fmt_leg("read_hs",   self.ffi_read_hs_us_total,   self.pkt_count) + "\n"
        s += "  " + _fmt_leg("write_hs",  self.ffi_write_hs_us_total,  self.pkt_count) + "\n"
        s += "  " + _fmt_leg("take_keys", self.ffi_take_keys_us_total, self.pkt_count) + "\n\n"

        # Loop phases (Plan: 2026-04-28).
        s += "Loop phases:\n"
        s += "  " + _fmt_leg("pop_dispatch", self.loop_pop_dispatch_us_total, self.loop_iter_count) + "\n"
        s += "  " + _fmt_leg("post_pkt",     self.loop_post_pkt_us_total,     self.loop_iter_count) + "\n"
        s += "  " + _fmt_leg("teardown",     self.loop_teardown_us_total,     self.on_flush_count) + "\n"
        s += "  loop_iter_count:                  " + _fmt_count(self.loop_iter_count) + "\n"
        # H3 phases (Plan: 2026-04-29-quic-h3-phase-leg-instrumentation).
        s += "H3 phases:\n"
        s += "  drain_resp.total: " + _fmt_count(self.h3_drain_resp_us_total) + "\n"
        s += "  post_recv.total:  " + _fmt_count(self.quic_post_recv_us_total) + "\n"
        s += "  dispatch.total:   " + _fmt_count(self.h3_dispatch_us_total) + "\n\n"
        # Drain-stream sub-leg decomposition (Plan: 2026-05-01-quic-h3-drain-stream-subleg).
        var de_t_us = self._compute_drain_event_dispatch_us()
        s += "Drain-stream sub-legs:\n"
        s += "  drain_stream.total:     " + _fmt_count(self.drain_stream_us_total) + "\n"
        s += "  recv_ffi.total:         " + _fmt_count(self.drain_recv_ffi_us_total) + "\n"
        s += "  buf_accumulate.total:   " + _fmt_count(self.drain_buf_accumulate_us_total) + "\n"
        s += "  frame_parse.total:      " + _fmt_count(self.drain_frame_parse_us_total) + "\n"
        s += "  qpack_decode.total:     " + _fmt_count(self.drain_qpack_decode_us_total) + "\n"
        s += "  event_dispatch.derived: " + _fmt_count(de_t_us) + "\n\n"
        # Q7 cold-handshake CPU-utilization decomposition (Plan: 2026-05-04-q7).
        s += "Q7 gauge sampling (100ms cadence, capped 600 entries):\n"
        s += "  active_drive_count.live:                " + _fmt_count(UInt64(self.active_drive_count)) + "\n"
        s += "  active_boucle_count_samples.len:        " + _fmt_count(UInt64(len(self.active_boucle_count_samples))) + "\n"
        s += "  in_flight_handshake_count_samples.len:  " + _fmt_count(UInt64(len(self.in_flight_handshake_count_samples))) + "\n\n"
        s += "Q7 batch-size histograms (8-bucket _pkts_per_flush_bucket dispatch):\n"
        var q7_bs_labels = List[String]()
        q7_bs_labels.append(String("1     "))
        q7_bs_labels.append(String("2-3   "))
        q7_bs_labels.append(String("4-7   "))
        q7_bs_labels.append(String("8-15  "))
        q7_bs_labels.append(String("16-31 "))
        q7_bs_labels.append(String("32-63 "))
        q7_bs_labels.append(String("64-127"))
        q7_bs_labels.append(String("128+  "))
        s += "  sendmsg:\n"
        for i in range(8):
            s += "    size=" + q7_bs_labels[i] + " " + _fmt_count(self.sendmsg_batch_size_buckets[i]) + "\n"
        s += "  recvmsg:\n"
        for i in range(8):
            s += "    size=" + q7_bs_labels[i] + " " + _fmt_count(self.recvmsg_batch_size_buckets[i]) + "\n"
        s += "Q7 lock-wait surfaces (24-bucket pow2 us):\n"
        s += "  demux_map_lock_wait.total:           " + _fmt_count(self.demux_map_lock_wait_us_total) + "\n"
        s += "  demux_map_lock_wait.overflow:        " + _fmt_count(self.demux_map_lock_wait_us_overflow) + "\n"
        s += "  rustls_config_clone_lock_wait.total: " + _fmt_count(self.rustls_config_clone_lock_wait_us_total) + "\n"
        s += "  rustls_config_clone_lock_wait.overflow: " + _fmt_count(self.rustls_config_clone_lock_wait_us_overflow) + "\n"
        s += "  ticket_store_lock_wait.total:        " + _fmt_count(self.ticket_store_lock_wait_us_total) + "\n"
        s += "  ticket_store_lock_wait.overflow:     " + _fmt_count(self.ticket_store_lock_wait_us_overflow) + "\n\n"
        s += "Q7 per-FD per-handshake (24-bucket pow2 us):\n"
        var q7_cpu_total: UInt64 = UInt64(0)
        var q7_wait_total: UInt64 = UInt64(0)
        for i in range(24):
            q7_cpu_total = q7_cpu_total + self.hs_cpu_us_per_handshake_buckets[i]
            q7_wait_total = q7_wait_total + self.hs_wait_us_per_handshake_buckets[i]
        s += "  hs_cpu.samples:    " + _fmt_count(q7_cpu_total) + "  overflow=" + _fmt_count(self.hs_cpu_us_per_handshake_overflow) + "\n"
        s += "  hs_wait.samples:   " + _fmt_count(q7_wait_total) + "  overflow=" + _fmt_count(self.hs_wait_us_per_handshake_overflow) + "\n\n"
        s += "Q7 io_uring park (H_F PARK-BOUND, total-only):\n"
        s += "  iouring_park_us.total: " + _fmt_count(self.iouring_park_us_total) + "\n\n"
        # Budget closure (mirrors report_json computation).
        var pp_legs = (self.header_parse_us_total + self.hp_us_total + self.aead_us_total
            + self.frame_parse_us_total + self.sm_us_total + self.residual_us_total)
        var acct = (pp_legs + self.drain_us_total + self.loop_pop_dispatch_us_total
            + self.loop_post_pkt_us_total + self.loop_teardown_us_total
            + self.h3_drain_resp_us_total
            + self.quic_post_recv_us_total
            + self.h3_dispatch_us_total)
        var unacct: UInt64 = UInt64(0)
        if self.busy_us_total > acct:
            unacct = self.busy_us_total - acct
        var unacct_pct: UInt64 = UInt64(0)
        if self.busy_us_total > UInt64(0):
            unacct_pct = (unacct * UInt64(100)) / self.busy_us_total
        s += "  unaccounted_us_total:             " + _fmt_count(unacct) + "  (" + String(unacct_pct) + "% of busy)\n\n"

        # Top-50 worst offenders (parallel insertion sort).
        s += "Worst offenders (top 50 addr_keys by pkt_count, no hs_complete):\n"
        var wo_keys = List[String]()
        var wo_vals = List[UInt64]()
        for entry in self.conn_pkt_counts.items():
            if entry.key in self.conn_hs_complete:
                continue
            wo_keys.append(entry.key)
            wo_vals.append(entry.value)
        var wo_n = len(wo_vals)
        for i in range(1, wo_n):
            var v = wo_vals[i]
            var k = wo_keys[i]
            var j = i - 1
            while j >= 0 and wo_vals[j] < v:
                wo_vals[j + 1] = wo_vals[j]
                wo_keys[j + 1] = wo_keys[j]
                j -= 1
            wo_vals[j + 1] = v
            wo_keys[j + 1] = k
        var wo_cap = wo_n
        if wo_cap > 50:
            wo_cap = 50
        for i in range(wo_cap):
            s += "  " + wo_keys[i] + "  pkt_count=" + String(wo_vals[i]) + "\n"
        if wo_n == 0:
            s += "  (none)\n"
        s += "\n"
        s += "=== end ===\n"
        return s^

    def _compute_drain_event_dispatch_us(self) -> UInt64:
        """Residual = drain_stream_us_total - sum(measured legs), clamped >= 0.
        Clamp absorbs (a) clock-read jitter where measured legs slightly
        exceed parent and (b) any accumulation bug — large overshoot still
        surfaces as Hard Gate 5 violation against the RAW unclamped fields."""
        var sum_legs = (self.drain_recv_ffi_us_total
            + self.drain_buf_accumulate_us_total
            + self.drain_frame_parse_us_total
            + self.drain_qpack_decode_us_total)
        if sum_legs >= self.drain_stream_us_total:
            return UInt64(0)
        return self.drain_stream_us_total - sum_legs

    def report_json(self) raises -> String:
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
        s += '  "schema_version": 7,\n'
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

        s += '  "arrival_lat_us_total": ' + String(self.arrival_lat_us_total) + ',\n'
        s += '  "arrival_lat_us_overflow": ' + String(self.arrival_lat_us_overflow) + ',\n'
        s += '  "arrival_lat_us_buckets": ['
        for i in range(24):
            s += String(self.arrival_lat_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"

        # Per-conn aggregated histogram + scalar.
        # Walk conn_pkt_counts.items(); dispatch each conn's packet count via _pkts_per_flush_bucket.
        var per_conn_buckets = List[UInt64]()
        for _ in range(8):
            per_conn_buckets.append(UInt64(0))
        var conns_total: UInt64 = UInt64(0)
        var conns_no_hs: UInt64 = UInt64(0)
        for entry in self.conn_pkt_counts.items():
            conns_total += UInt64(1)
            var bkt = _pkts_per_flush_bucket(Int(entry.value))
            per_conn_buckets[bkt] += UInt64(1)
            if entry.key not in self.conn_hs_complete:
                conns_no_hs += UInt64(1)

        s += '  "per_conn_pkts_buckets": ['
        for i in range(8):
            s += String(per_conn_buckets[i])
            if i < 7:
                s += ", "
        s += "],\n"
        s += '  "conns_total": ' + String(conns_total) + ',\n'
        s += '  "conns_with_pkts_no_hs_complete": ' + String(conns_no_hs) + ',\n'

        # addr_key DCID-mismatch block (Plan: 2026-04-27 collision counter).
        var addr_keys_with_mismatch: UInt64 = UInt64(0)
        for entry in self.addr_key_mismatch_counts.items():
            if entry.value > UInt64(0):
                addr_keys_with_mismatch = addr_keys_with_mismatch + UInt64(1)
        s += '  "addr_key_dcid_mismatch": {\n'
        s += '    "dcid_mismatch_pkts": ' + String(self.dcid_mismatch_pkts) + ',\n'
        s += '    "addr_keys_total": ' + String(len(self.addr_key_mismatch_counts)) + ',\n'
        s += '    "addr_keys_with_mismatch": ' + String(addr_keys_with_mismatch) + ',\n'
        s += '    "per_addr_key": {'
        var first_mm = True
        for entry in self.addr_key_mismatch_counts.items():
            if not first_mm:
                s += ","
            first_mm = False
            s += '\n      "' + entry.key + '": ' + String(entry.value)
        s += "\n    }\n  },\n"

        # Handshake kind block (Plan: 2026-05-03-short-conn-resumption).
        s += '  "handshakes": {\n'
        s += '    "full": ' + String(self.handshakes_full_total) + ',\n'
        s += '    "resumed": ' + String(self.handshakes_resumed_total) + '\n'
        s += "  },\n"

        # Drain-extension block (Plan: 2026-05-05-quic-bench-drain-extension).
        s += '  "drain_extension": {\n'
        s += '    "pkts_total": ' + String(self.drain_extension_pkts_total) + ',\n'
        s += '    "overflow_count": ' + String(self.drain_extension_overflow_count) + '\n'
        s += "  },\n"

        # Egress-pool block (Plan: 2026-05-05-q8-egress-hot-path-batching).
        s += '  "egress_pool": {\n'
        s += '    "hits_total": ' + String(self.egress_pool_hits_total) + ',\n'
        s += '    "misses_total": ' + String(self.egress_pool_misses_total) + '\n'
        s += "  },\n"

        # Per-fresh-conn FFI histogram (Plan: 2026-05-03-q4-fresh-conn-cpu-decomposition).
        s += '  "fresh_conn_ffi_us": {\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.fresh_conn_ffi_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.fresh_conn_ffi_us_overflow) + "\n"
        s += "  },\n"

        # Recv-batch-size histogram (Plan: 2026-05-03-q4-fresh-conn-cpu-decomposition).
        var rb_keys = List[String]()
        rb_keys.append(String("1"))
        rb_keys.append(String("2-3"))
        rb_keys.append(String("4-7"))
        rb_keys.append(String("8-15"))
        rb_keys.append(String("16-31"))
        rb_keys.append(String("32-63"))
        rb_keys.append(String("64-127"))
        rb_keys.append(String("128+"))
        s += '  "recv_batch_size_buckets": {\n'
        for i in range(8):
            s += '    "' + rb_keys[i] + '": ' + String(self.recv_batch_size_buckets[i])
            if i < 7:
                s += ","
            s += "\n"
        s += "  },\n"

        # Q5 read_hs decomposition (Plan: 2026-05-03-q5-read-hs-per-call-decomposition).
        var rh_keys = List[String]()
        rh_keys.append(String("1"))
        rh_keys.append(String("2-3"))
        rh_keys.append(String("4-7"))
        rh_keys.append(String("8-15"))
        rh_keys.append(String("16-31"))
        rh_keys.append(String("32-63"))
        rh_keys.append(String("64-127"))
        rh_keys.append(String("128+"))
        s += '  "read_hs_per_handshake_count_buckets": {\n'
        for i in range(8):
            s += '    "' + rh_keys[i] + '": ' + String(self.read_hs_per_handshake_count_buckets[i])
            if i < 7:
                s += ","
            s += "\n"
        s += "  },\n"

        s += '  "read_hs_us_per_call": {\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.read_hs_us_per_call_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.read_hs_us_per_call_overflow) + "\n"
        s += "  },\n"

        # Q6 read_hs sub-leg histograms (Plan: 2026-05-04-q6-read-hs-internal-decomposition).
        s += '  "read_hs_input_marshalling_us": {\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.read_hs_input_marshalling_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.read_hs_input_marshalling_us_overflow) + "\n"
        s += "  },\n"

        s += '  "read_hs_state_machine_us": {\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.read_hs_state_machine_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.read_hs_state_machine_us_overflow) + "\n"
        s += "  },\n"

        s += '  "read_hs_output_alloc_us": {\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.read_hs_output_alloc_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.read_hs_output_alloc_us_overflow) + "\n"
        s += "  },\n"

        s += '  "read_hs_output_marshalling_us": {\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.read_hs_output_marshalling_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.read_hs_output_marshalling_us_overflow) + "\n"
        s += "  },\n"

        # Q9 per-fresh-conn alloc sub-leg histograms (Plan: 2026-05-05-q9).
        s += '  "alloc_quic_state_us": {\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.alloc_quic_state_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.alloc_quic_state_us_overflow) + "\n"
        s += "  },\n"

        s += '  "alloc_tls_handle_us": {\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.alloc_tls_handle_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.alloc_tls_handle_us_overflow) + "\n"
        s += "  },\n"

        s += '  "alloc_h3_state_us": {\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.alloc_h3_state_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.alloc_h3_state_us_overflow) + "\n"
        s += "  },\n"

        s += '  "bench_dict_insert_us": {\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.bench_dict_insert_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.bench_dict_insert_us_overflow) + "\n"
        s += "  },\n"

        # FFI sub-legs (Plan: 2026-04-28-quic-accept-loop-subleg-instrumentation).
        var read_hs_avg: UInt64 = UInt64(0)
        var write_hs_avg: UInt64 = UInt64(0)
        var take_keys_avg: UInt64 = UInt64(0)
        if self.pkt_count > UInt64(0):
            read_hs_avg = self.ffi_read_hs_us_total / self.pkt_count
            write_hs_avg = self.ffi_write_hs_us_total / self.pkt_count
            take_keys_avg = self.ffi_take_keys_us_total / self.pkt_count
        s += '  "ffi_subleg_us": {\n'
        s += '    "read_hs":   {"avg": ' + String(read_hs_avg) + ', "total": ' + String(self.ffi_read_hs_us_total) + '},\n'
        s += '    "write_hs":  {"avg": ' + String(write_hs_avg) + ', "total": ' + String(self.ffi_write_hs_us_total) + '},\n'
        s += '    "take_keys": {"avg": ' + String(take_keys_avg) + ', "total": ' + String(self.ffi_take_keys_us_total) + '}\n'
        s += "  },\n"

        # Loop phases (Plan: 2026-04-28-quic-accept-loop-subleg-instrumentation).
        var pop_dispatch_avg: UInt64 = UInt64(0)
        var post_pkt_avg: UInt64 = UInt64(0)
        if self.loop_iter_count > UInt64(0):
            pop_dispatch_avg = self.loop_pop_dispatch_us_total / self.loop_iter_count
            post_pkt_avg = self.loop_post_pkt_us_total / self.loop_iter_count
        var teardown_avg: UInt64 = UInt64(0)
        if self.on_flush_count > UInt64(0):
            teardown_avg = self.loop_teardown_us_total / self.on_flush_count
        # Budget closure ε:
        # busy = per_pkt_total_sum + drain + pop_dispatch + post_pkt + teardown + ε
        # per_pkt_total_sum is reconstructed from leg sums (ffi excluded — overlaps sm).
        var per_pkt_legs_sum = (self.header_parse_us_total
            + self.hp_us_total
            + self.aead_us_total
            + self.frame_parse_us_total
            + self.sm_us_total
            + self.residual_us_total)
        var accounted = (per_pkt_legs_sum
            + self.drain_us_total
            + self.loop_pop_dispatch_us_total
            + self.loop_post_pkt_us_total
            + self.loop_teardown_us_total
            + self.h3_drain_resp_us_total
            + self.quic_post_recv_us_total
            + self.h3_dispatch_us_total)
        var unaccounted: UInt64 = UInt64(0)
        if self.busy_us_total > accounted:
            unaccounted = self.busy_us_total - accounted
        var unaccounted_pct: UInt64 = UInt64(0)
        if self.busy_us_total > UInt64(0):
            unaccounted_pct = (unaccounted * UInt64(100)) / self.busy_us_total
        s += '  "loop_phases_us": {\n'
        s += '    "pop_dispatch": {"avg": ' + String(pop_dispatch_avg) + ', "total": ' + String(self.loop_pop_dispatch_us_total) + '},\n'
        s += '    "post_pkt":     {"avg": ' + String(post_pkt_avg) + ', "total": ' + String(self.loop_post_pkt_us_total) + '},\n'
        s += '    "teardown":     {"avg": ' + String(teardown_avg) + ', "total": ' + String(self.loop_teardown_us_total) + '},\n'
        s += '    "loop_iter_count": ' + String(self.loop_iter_count) + ',\n'
        s += '    "unaccounted_us_total": ' + String(unaccounted) + ',\n'
        s += '    "unaccounted_pct": ' + String(unaccounted_pct) + '\n'
        s += "  },\n"
        s += '  "h3_phases_us": {\n'
        s += '    "drain_resp": {"total": ' + String(self.h3_drain_resp_us_total) + '},\n'
        s += '    "post_recv":  {"total": ' + String(self.quic_post_recv_us_total) + '},\n'
        s += '    "dispatch":   {"total": ' + String(self.h3_dispatch_us_total) + '}\n'
        s += "  },\n"
        var de_us = self._compute_drain_event_dispatch_us()
        var sum_legs_us = (self.drain_recv_ffi_us_total
            + self.drain_buf_accumulate_us_total
            + self.drain_frame_parse_us_total
            + self.drain_qpack_decode_us_total
            + de_us)
        var unacct_drain_pct: UInt64 = UInt64(0)
        if self.drain_stream_us_total > UInt64(0) and sum_legs_us < self.drain_stream_us_total:
            unacct_drain_pct = ((self.drain_stream_us_total - sum_legs_us) * UInt64(100)) / self.drain_stream_us_total
        s += '  "drain_stream_subleg": {\n'
        s += '    "drain_stream_us_total": ' + String(self.drain_stream_us_total) + ',\n'
        s += '    "recv_ffi_us": ' + String(self.drain_recv_ffi_us_total) + ',\n'
        s += '    "buf_accumulate_us": ' + String(self.drain_buf_accumulate_us_total) + ',\n'
        s += '    "frame_parse_us": ' + String(self.drain_frame_parse_us_total) + ',\n'
        s += '    "qpack_decode_us": ' + String(self.drain_qpack_decode_us_total) + ',\n'
        s += '    "event_dispatch_us": ' + String(de_us) + ',\n'
        s += '    "sum_legs_us": ' + String(sum_legs_us) + ',\n'
        s += '    "unaccounted_pct": ' + String(unacct_drain_pct) + '\n'
        s += "  },\n"

        # Q7 cold-handshake CPU-utilization decomposition (Plan: 2026-05-04-q7).
        # 10 new top-level keys per spec §4.7.
        s += '  "active_boucle_count_samples": ['
        for i in range(len(self.active_boucle_count_samples)):
            s += String(self.active_boucle_count_samples[i])
            if i < len(self.active_boucle_count_samples) - 1:
                s += ", "
        s += "],\n"
        s += '  "in_flight_handshake_count_samples": ['
        for i in range(len(self.in_flight_handshake_count_samples)):
            s += String(self.in_flight_handshake_count_samples[i])
            if i < len(self.in_flight_handshake_count_samples) - 1:
                s += ", "
        s += "],\n"

        var bs_keys = List[String]()
        bs_keys.append(String("1"))
        bs_keys.append(String("2-3"))
        bs_keys.append(String("4-7"))
        bs_keys.append(String("8-15"))
        bs_keys.append(String("16-31"))
        bs_keys.append(String("32-63"))
        bs_keys.append(String("64-127"))
        bs_keys.append(String("128+"))
        s += '  "sendmsg_batch_size_buckets": {\n'
        for i in range(8):
            s += '    "' + bs_keys[i] + '": ' + String(self.sendmsg_batch_size_buckets[i])
            if i < 7:
                s += ","
            s += "\n"
        s += "  },\n"
        s += '  "recvmsg_batch_size_buckets": {\n'
        for i in range(8):
            s += '    "' + bs_keys[i] + '": ' + String(self.recvmsg_batch_size_buckets[i])
            if i < 7:
                s += ","
            s += "\n"
        s += "  },\n"

        s += '  "demux_map_lock_wait_us": {\n'
        s += '    "total": ' + String(self.demux_map_lock_wait_us_total) + ',\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.demux_map_lock_wait_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.demux_map_lock_wait_us_overflow) + "\n"
        s += "  },\n"

        s += '  "rustls_config_clone_lock_wait_us": {\n'
        s += '    "total": ' + String(self.rustls_config_clone_lock_wait_us_total) + ',\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.rustls_config_clone_lock_wait_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.rustls_config_clone_lock_wait_us_overflow) + "\n"
        s += "  },\n"

        s += '  "ticket_store_lock_wait_us": {\n'
        s += '    "total": ' + String(self.ticket_store_lock_wait_us_total) + ',\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.ticket_store_lock_wait_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.ticket_store_lock_wait_us_overflow) + "\n"
        s += "  },\n"

        s += '  "hs_cpu_us_per_handshake": {\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.hs_cpu_us_per_handshake_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.hs_cpu_us_per_handshake_overflow) + "\n"
        s += "  },\n"

        s += '  "hs_wait_us_per_handshake": {\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.hs_wait_us_per_handshake_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
        s += '    "overflow": ' + String(self.hs_wait_us_per_handshake_overflow) + "\n"
        s += "  },\n"

        s += '  "iouring_park_us": {\n'
        s += '    "total": ' + String(self.iouring_park_us_total) + "\n"
        s += "  },\n"

        # Top-50 worst offenders: addr_keys with most packets but no hs_complete.
        # Materialize parallel List[String] + List[UInt64], insertion-sort descending.
        # Report time is non-hot; clarity > heap-select.
        var off_keys = List[String]()
        var off_vals = List[UInt64]()
        for entry in self.conn_pkt_counts.items():
            if entry.key in self.conn_hs_complete:
                continue
            off_keys.append(entry.key)
            off_vals.append(entry.value)
        # Insertion sort by val descending.
        var n_off = len(off_vals)
        for i in range(1, n_off):
            var v = off_vals[i]
            var k = off_keys[i]
            var j = i - 1
            while j >= 0 and off_vals[j] < v:
                off_vals[j + 1] = off_vals[j]
                off_keys[j + 1] = off_keys[j]
                j -= 1
            off_vals[j + 1] = v
            off_keys[j + 1] = k

        var cap = n_off
        if cap > 50:
            cap = 50
        s += '  "worst_conns": [\n'
        for i in range(cap):
            s += '    {"addr_key": "' + off_keys[i] + '", "pkt_count": ' + String(off_vals[i]) + ', "hs_complete": false}'
            if i < cap - 1:
                s += ","
            s += "\n"
        s += "  ],\n"

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
