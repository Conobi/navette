## Host

- Kernel: `Linux 6.19.12-lqx1-1-lqx`
- CPU: `11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz`
- Cores: `8`
- Docker: `29.3.0`
- Date: `2026-04-25`

## Reference numbers

`make bench-mvp` on the host above. Each cell is the median of 3 iterations of
a 30 s measurement window after a 5 s warmup, with `--cpuset-cpus=0` for the
server and `--cpuset-cpus=2-5` for the client. CPU% is sampled at the cgroup
level via `docker stats --no-stream` once per second.

### tquic_client (4 threads, 25 conns/thread, saturating)

| Payload | Scenario   | mojo-net req/s (n) | TQUIC req/s (n) | mojo-net CPU% | mojo-net / TQUIC |
|---------|------------|--------------------|-----------------|---------------|------------------|
| 1k      | long-conn  | 412 (3)            | 87,113 (3)      | 5.6           | 0.0047× |
| 1k      | short-conn | 1 (3)              | 2,535 (3)       | 0.2           | 0.0004× |

### h2load-h3 (single-threaded, regression-tracking)

| Payload | Scenario   | mojo-net req/s (n) | TQUIC req/s (n) | mojo-net CPU% | mojo-net / TQUIC |
|---------|------------|--------------------|-----------------|---------------|------------------|
| 1k      | long-conn  | 125 (3)            | 32,625 (3)      | 2.9           | 0.0038× |
| 1k      | short-conn | 11 (3)             | 66,023 (3)      | 0.6           | 0.0002× |

## How to read this

- **TQUIC's tquic_server hits 87K req/s with `tquic_client` and saturates core 0
  at 88% CPU** — server-side bottleneck reached, the hardware envelope on this
  laptop. This is the calibration anchor.
- **mojo-net hits 412 req/s long-conn / 1 req/s short-conn while using <6% of
  one CPU core.** Mojo-net is *not* CPU-bound on core 0 — there is huge headroom
  the server isn't using. The bottleneck is **per-connection cost**: under
  saturating load (400 attempted connections in 30 s) only ~3–10 complete the
  QUIC handshake, the rest time out. The successful handshakes then drive
  thousands of requests, but the throughput is gated by the trickle of
  conns the server can actually accept.
- **h2load → mojo-net is single-threaded at the client** — those numbers are
  for regression tracking against prior runs, not absolute comparisons.

## Known limitations of these numbers

- **2 MB / 5K / 15K payloads not in the MVP matrix.** The 1 KB cells are the
  ones run by `make bench-mvp`. Run `make bench-full` for all 32 cells.
- **`tquic_client` knob ceiling** — 4 threads × 25 conns × 10 streams = 1,000
  in-flight requests. On a 48-core EPYC the ceiling would be higher; here we
  are likely under-saturating `tquic_server` slightly. The 87K rps is a lower
  bound on TQUIC's achievable throughput.
- **No CI integration / no commit-to-commit tracking yet** — REFERENCE.md is
  a manual snapshot. Numbers will drift with kernel updates, thermals, and
  parallel host load.
- **Single-worker mojo-net** (`--workers 1`). Multi-process via SO_REUSEPORT
  is out of scope for this harness.

## Where the work goes from here

The honest read: mojo-net is ~210× slower than TQUIC long-conn, ~2,500× slower
short-conn, while using essentially zero CPU. The next optimisation pass should
target **connection-establishment throughput** — handshake latency, accept
loop, packet decryption pipelining — rather than steady-state stream throughput.

## Hypothesis-pass log

### 2026-04-25 — pacer-bypass-during-handshake — FALSIFIED

**Spec:** `specs/2026-04-25-quic-pacer-bypass-handshake.md`. Hypothesis: the
M4a universal `_can_send` gate paces Initial+Handshake-space packets;
cold-start pacing rate (`2 × cwnd × 1e6 / smoothed_rtt ≈ 60 KiB/s`) blocks
each subsequent datagram for ~20 ms in a multishot recvmsg burst, pushing
~100 concurrent client handshakes past their handshake timeout. Fix: gate
the pacer (and post-send token commit + timer-deadline branch) on
`is_established()`; preserve anti-amp and CC cwnd unchanged.

**Single-cell gate** (`bench.sh mojo-net 1k long-conn tquic_client --iters 3`):

| iter | rps | CPU% | success | fail |
|---|---|---|---|---|
| 1 | 415.08 | 5.5% | 12,870 | 40 |
| 2 | 432.81 | 4.4% | 13,420 | 40 |
| 3 | 411.20 | 4.5% | 12,750 | 40 |

**Median: 415 rps.** Threshold for confirmation was ≥ 4,000 rps (≥ 10× the
412 pre-fix baseline). Result: 1.01× — within noise. **Hypothesis
falsified: the pacer was not the cold-start handshake-throughput floor.**
CPU% remains ~5%, same idle-waiting symptom. Something else gates accept /
handshake throughput under concurrency.

**Code shipped anyway as a code-quality improvement.** The fix is
RFC-compatible (RFC 9002 §7's only normative MUST is "pace OR limit bursts
to the initial congestion window"; retained anti-amp + cwnd checks satisfy
the burst-limit clause). picoquic ships this exact design; quinn / TQUIC /
ngtcp2 / quiche pace every encryption level. mojo-net is now in the
picoquic camp on this point. Commits: `911601e..ba3c254` on
`fix/quic-pacer-bypass-handshake`.

**Next hypothesis (open question, severity: required-later, trigger:
before any further QUIC perf work):** the multi-fiber accept fan-out / the
serial single-fiber `on_flush` loop in `bench/h3_server.mojo:523-600`. The
recvmsg burst delivers N Initial packets into one CQ wakeup; today they
are processed strictly serially in one fiber. Even with the pacer out of
the way, the serial nature plus per-packet FFI roundtrips through the
rustls global lock would explain the symptom (low CPU + high handshake
timeout rate under concurrency).

### 2026-04-26 — accept-loop-instrumentation-data-collection — DATA (steady-state only)

**Spec:** `specs/2026-04-25-quic-accept-loop-instrumentation.md`. Goal:
distinguish three suspects (fan-out / per-packet cost / FFI-AEAD-SM
decomposition) for the 412 req/s cold-start floor on
`bench.sh mojo-net 1k long-conn tquic_client`.

**On-build single-cell capture (1k long-conn, 30s window, SIGINT-driven sidecar):**

| Metric | Value |
|---|---|
| pkts_per_flush weighted-mean | 2.47 |
| pkts_per_flush bucket dist | size=1: 59.3% / size=2-3: 30.0% / size=4-7: 7.0% / size=8-15: 2.1% / size=16-31: 1.4% / size=32-63: 0.3% / size=64-127: 0.1% / size=128+: 0% |
| per_pkt_us.total p50 / p90 / p99 | 15 / 29 / 57 |
| shim_ffi avg | 7 us |
| aead avg | 0 us (sub-us — bucket=0) |
| header_parse avg | 0 us (sub-us) |
| hp avg | 0 us (sub-us) |
| frame_parse avg | 11 us |
| sm avg | 8 us (overlaps shim_ffi as inner sub-budget) |
| residual avg | 0 us (sub-us) |
| drain avg (bench TX path) | 31 us |
| arrivals / successful / timed_out | 5 / 5 / 0 (100% success) |
| handshake latency p50 / p90 / p99 / max | 1,348 / 29,477 / 29,477 / 29,477 us |
| Run wall-clock / on_flush events | 38.37 s / 3,504 |
| Idle vs busy | 97.5% idle / 2.5% busy |

**Spec ≥2× signal table — applied:**
- `shim_ffi.avg=7 ≥ 2 × frame_parse.avg=11`? **NO** (0.6×). FFI dominance NOT confirmed.
- `aead.avg=0 ≥ 2 × frame_parse.avg=11`? **NO**. AEAD dominance NOT confirmed.
- `sm.avg=8 ≥ 2 × frame_parse.avg=11` (excluding shim_ffi as overlap)? **NO** (0.7×). SM dominance NOT confirmed.
- `pkts_per_flush weighted-mean=2.47 ≥ 8`? **NO** (0.31×). Fan-out dominance NOT confirmed.

**No single in-recv leg dominates.** The bench-side `drain` leg (31 us avg, 2.8× frame_parse) is the largest per-packet wall-clock contributor, but `drain` covers the full TX path (response generation + outgoing AEAD + io_uring sendmsg queue) and is expected to dominate steady-state.

**Critical caveat — this run did NOT reproduce the cold-start floor.**
Only **5** handshakes arrived in 30 s (vs the calibrated baseline's "~400 attempts → 3-10 successes" pattern with 99% timeouts). With `tquic_client --max-concurrent-conns=25 --duration=30` in long-conn mode, the client opened 5 long-lived connections and pumped streams through them rather than constantly reconnecting. Steady-state stream serving dominates; the saturating-handshake load that produced the 412 req/s + 99% timeout floor in `2026-04-25 — pacer-bypass-during-handshake — FALSIFIED` did not manifest here.

The handshake-latency tail IS suggestive: `p50=1.3ms` vs `p99/max=29ms` (n=5) — the first arriving connection paid the Initial-key-derivation bleed-in cost (Plan B's `profile_first_iter_done` semantic harvesting it on iter 1). But n=5 is too small to draw conclusions.

**Sidecar JSON:** `bench/quic_perf/results/profile/INSTRUMENTATION-20260426-183256.json` (committed).

**On-build overhead drift (B13 single-cell smoke gate, separate run):** −0.40% (on-build 413.46 rps median vs off-build 411.83 rps median; within run-to-run noise — the spec's ≤10% budget is satisfied with ~25× headroom).

**Methodology note:** Full bench-mvp matrix (~50 min, 24 cells) skipped per Plan B option B. B13 already validated the overhead budget on the load-bearing cell at −0.40%; the 7 other matrix cells re-confirm the same drift property without new diagnostic value. The dominant-cost identification was meant to come from the sidecar's per-packet decomposition, but **the single 30 s long-conn capture does not exercise the cold-start path** that motivated the spec.

**Next hypothesis (revised — required-later, severity: high):**
1. **Re-capture under cold-start saturation.** Run `tquic_client` with `short-conn` scenario (forces frequent reconnect) AND/OR raise `--max-concurrent-conns` from 25 to 100+ to force the saturating-handshake regime. The resulting sidecar should show much higher `arrivals` (closer to 100/s) and lower `successful` rate — that's the regime the spec was designed to characterise. Trigger: anyone returning to the QUIC perf push.
2. **In the meantime,** the steady-state data above stands as a baseline: per-packet RX is fast (~15 us p50 total), fan-out is low (~2.5 mean), no in-recv leg dominates. If saturating-handshake re-runs ALSO show no in-recv dominance, the bottleneck is elsewhere — most plausibly in `_drain_and_send` or downstream of it (response generation, outgoing AEAD throughput, or sendmsg queue depth).
