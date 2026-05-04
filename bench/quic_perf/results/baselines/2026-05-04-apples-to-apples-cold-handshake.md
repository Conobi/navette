# Apples-to-Apples Cold-Handshake Baseline (2026-05-04)

**Date:** 2026-05-04
**Scenario:** short-conn, 1k payload, cold handshakes (TLS 1.3 ticket reuse disabled both sides)
**Method:** n=10 per server, side-by-side, same host, same client, same network path.
**Patch:** `bench/quic_perf/configs/short-conn.env` (commented out `SESSION_FILE` line at L12). Server-side ticketer remains on (TQUIC's tquic_server also issues tickets unconditionally — symmetric).
**Branch:** `feat/quic-queueing-tail-instrumentation` (no source code changes; bench-config-only landed).

## Headline

Apples-to-apples cold-handshake bench (no client-side ticket cache; both servers issue tickets symmetrically) places mojo-net at **0.489× TQUIC short-conn rps** (1391 vs 2846 median). The headline gap is **2.04×**, but **the gap is primarily a CPU-utilization gap, NOT a compute-cost gap**. Server CPU% medians are 52% (mojo-net) vs 92% (TQUIC). Per-CPU-% efficiency is only 1.16× in TQUIC's favor (26.6 vs 31.0 rps/%CPU). The dominant question for the next perf-roadmap spec is "why does mojo-net leave 48% of one core on the table while client load is offered?" — not "rustls vs boringssl per-handshake compute cost."

## Bench config

| Parameter | Value |
|---|---|
| Servers | mojo-net (rustls, librustls-mojo); tquic-server (boringssl) |
| Payload | 1k |
| Scenario | `short-conn` |
| Client driver | tquic_client |
| Duration | 30s |
| Warmup | 5s |
| Client threads | 4 |
| Max-concurrent-conns (client) | 25 |
| Max-requests-per-conn | 1 (forces fresh handshake per req) |
| `--send-udp-payload-size` | 1350 |
| `--session-file` | **disabled** (apples-to-apples cold handshake) |
| `--enable-early-data` | **disabled** |
| Server-side ticketer | enabled both sides (symmetric; client just doesn't read them) |
| Iterations per server | n=10 |

## Data table (n=10 each)

| Metric | mojo-net | tquic | ratio mojo/tquic |
|---|---|---|---|
| rps median | 1391.3 | 2846.3 | 0.489 |
| rps min | 1174.1 | 2559.5 | — |
| rps max | 1499.7 | 2919.3 | — |
| rps IQR | 173.1 | 286.8 | — |
| rps IQR % of median | 12.44% | 10.07% | — |
| rps stdev | 113.4 | 143.5 | — |
| Server CPU % median | 52.3 | 91.8 | 0.570 |
| p50 latency ms median | 2.238 | 3.700 | mojo lower |
| p99 latency ms median | 11.316 | 57.160 | mojo lower |
| Failures total | 220 | 454 | — |
| Successes total | 426,578 | 860,343 | — |
| Failure rate % | 0.052 | 0.053 | parity |
| Per-CPU-% efficiency (rps/%) | 26.6 | 31.0 | 0.860 |

### Variance note

The rps IQR% values (12.44% mojo-net, 10.07% tquic) sit above the ±5% drift gate calibrated in `feedback_bench_gate_width_calibration.md`. **These are inter-iter variance, NOT inter-window drift.** The drift gate measures same-window pre/post smoke deltas; the IQR here measures n=10 iter-to-iter spread within a contiguous 12-minute capture. Both servers' inter-iter variance is comparable in absolute % terms — no asymmetric noise floor.

## Source JSON files

n=10 each, 2026-05-04, in `bench/quic_perf/results/`:

**mojo-net (08:27:10Z – 08:33:25Z):**
- `2026-05-04T08-27-10Z-mojo-net-1k-short-conn-tquic_client-iter1.json`
- `2026-05-04T08-27-48Z-mojo-net-1k-short-conn-tquic_client-iter2.json`
- `2026-05-04T08-28-56Z-mojo-net-1k-short-conn-tquic_client-iter3.json`
- `2026-05-04T08-29-35Z-mojo-net-1k-short-conn-tquic_client-iter4.json`
- `2026-05-04T08-30-13Z-mojo-net-1k-short-conn-tquic_client-iter5.json`
- `2026-05-04T08-30-52Z-mojo-net-1k-short-conn-tquic_client-iter6.json`
- `2026-05-04T08-31-30Z-mojo-net-1k-short-conn-tquic_client-iter7.json`
- `2026-05-04T08-32-08Z-mojo-net-1k-short-conn-tquic_client-iter8.json`
- `2026-05-04T08-32-47Z-mojo-net-1k-short-conn-tquic_client-iter9.json`
- `2026-05-04T08-33-25Z-mojo-net-1k-short-conn-tquic_client-iter10.json`

**tquic (08:34:33Z – 08:42:42Z):**
- `2026-05-04T08-34-33Z-tquic-1k-short-conn-tquic_client-iter1.json`
- `2026-05-04T08-35-10Z-tquic-1k-short-conn-tquic_client-iter2.json`
- `2026-05-04T08-36-18Z-tquic-1k-short-conn-tquic_client-iter3.json`
- `2026-05-04T08-36-56Z-tquic-1k-short-conn-tquic_client-iter4.json`
- `2026-05-04T08-37-33Z-tquic-1k-short-conn-tquic_client-iter5.json`
- `2026-05-04T08-39-11Z-tquic-1k-short-conn-tquic_client-iter6.json`
- `2026-05-04T08-39-48Z-tquic-1k-short-conn-tquic_client-iter7.json`
- `2026-05-04T08-40-27Z-tquic-1k-short-conn-tquic_client-iter8.json`
- `2026-05-04T08-41-34Z-tquic-1k-short-conn-tquic_client-iter9.json`
- `2026-05-04T08-42-42Z-tquic-1k-short-conn-tquic_client-iter10.json`

## Reframe — the 73/16 decomposition

The 2.04× short-conn rps gap decomposes multiplicatively:

```
rps_ratio (TQUIC / mojo-net)  = 2.045
  = (CPU_util_ratio) × (per-CPU-% efficiency ratio)
  = (91.8 / 52.3)   × (31.0 / 26.6)
  = 1.755           × 1.165
  = 2.04
```

Wall-clock-share-of-gap (impact-floor framing per `feedback_perf_impact_floor_filter.md`):

| Frame | Multiplicative share | Wall-clock share of the 2.04× |
|---|---|---|
| **CPU-utilization gap (mojo under-saturated)** | 1.755× | **~73%** |
| **Per-CPU-% efficiency gap (compute cost)** | 1.165× | **~16%** |
| (interaction term) | — | balance |

**Implications:**

1. **The 16% slice is what every prior optimization spec (Q4, Q5) has been targeting.** It is real but bounded: even a perfect 1.0× per-CPU-% efficiency match (which would require beating boringssl with rustls + Mojo FFI) only buys ~16% of the rps gap. The remaining 73% of the gap is structural — the box has the headroom; mojo-net isn't claiming it.
2. **Better p50/p99 for mojo-net is diagnostic, not a feature.** Lower-latency-at-lower-rps is the canonical signature of an under-saturated server: queues are short because the server is processing requests as they arrive, not because anything is faster per-op. Once mojo-net saturates the core, latencies will rise to TQUIC-like levels at TQUIC-like rps.
3. **Disabling resumption did NOT widen the gap vs the resumed-era ratio (~0.48).** This confirms TLS 1.3 resumption was not load-bearing for either side's published numbers — both servers do the work either way; the client just skips an RTT. Resumption gives the client a wall-clock latency win, not a server-CPU win.

## Hypotheses for the 73% CPU-utilization gap

Hypotheses for the 73% utilization slice are enumerated in `specs/2026-05-04-q7-cold-handshake-cpu-utilization-decomposition.md` §1; this baseline records the gap, not the candidates. (Q4 sidecar evidence — 100% of multishot recvmsg CQEs deliver n=1 datagram — is the standing input that motivates Q7's H_F scheduler-underfill / io_uring-park-time hypothesis.)

## Next-spec sequencing

**Q7 first (utilization-gap decomposition; ~73% of the gap).**
**Q6 second (per-call decomposition for the 16% efficiency gap).**

Rationale:

- The 73% slice is the larger lever, and the efficiency gap (16%) is bounded above by the rustls-vs-boringssl + FFI-overhead structural delta. No amount of Q6-style decomposition can buy more than the 16%; Q7's hypothesis space contains slices that can buy multiples of that.
- Q7 must come *before* Q6 because the right Q6 brackets depend on which busy phase Q7 identifies. Decomposing busy time before knowing whether the bench is even busy-bound risks instrumenting the wrong phase.
- Q6 is not cancelled — only re-sequenced. Per `feedback_perf_impact_floor_filter.md`, the 16% slice is above the 5% impact floor; a per-call decomposition spec is justified once Q7's results land.

The Q7 spec enumerates and instruments its own hypothesis set (see `specs/2026-05-04-q7-cold-handshake-cpu-utilization-decomposition.md` §1). The Q6 spec will be authored after Q7 completes.

## Cross-cutting context

- **No source code changes.** Only `bench/quic_perf/configs/short-conn.env` was edited (commented out `SESSION_FILE`). Servers, harness, image SHAs all unchanged from Q5.
- **Failure-rate parity (0.052% vs 0.053%) confirms harness symmetry.** Both servers are doing the same work on the same path; the gap is a property of the server-side hot path, not a harness or client artifact.
- **Long-conn parity remains valid.** Per `project_long_conn_parity_short_conn_ceiling.md`, mojo-net achieves 1.15× TQUIC long-conn (steady state). The 0.489× short-conn ratio is a fresh-conn-path-specific result, not an indication of steady-state regression.
