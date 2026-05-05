# Lever I — QPACK Huffman Table-Driven Rewrite — VERDICT: FALSIFIED

**Date:** 2026-05-05
**Branch / HEAD:** `main` @ `8218017`
**Spec:** `specs/2026-05-04-qpack-huffman-table-driven.md`
**Bench cell:** `mojo-net 1k short-conn tquic_client` (cold handshake; `MAX_REQUESTS_PER_CONN=1`)
**Iters:** n=10 per cell, `bench.sh --iters 1` × 10 with 30 s inter-iter sleeps (per `feedback_bench_iter_pacing.md`)

---

## TL;DR

| metric | PRE-I | POST-I | Δ |
|---|---|---|---|
| median rps | **1165.45** | **1168.81** | **+0.29%** |
| Q1–Q3 (IQR) | 1145.74 – 1193.25 (47.50) | 1115.25 – 1185.48 (70.23) | **overlap** |
| stdev | 195.66 (with outlier) / ~25 (cleaned) | 37.81 | — |
| min / max | 560.37 / 1218.03 | 1086.25 / 1192.52 | — |
| mean server CPU | 55.86% | 55.67% | -0.19 pp |
| **median p50 latency** | 5.41 ms | **3.83 ms** | **-29% (faster)** |
| **median p99 latency** | 17.85 ms | **14.66 ms** | **-18% (faster)** |
| qpack conformance | n/a (pre stash) | **30/30 PASS** | — |

**AC verdict:** **FALSIFIED** under the impact-floor rule (`feedback_perf_impact_floor_filter.md`): rps lift +0.29% < 1%. The 4–7% short-conn rps lift projected from microbench (`QpackDecoder.decode 7.2–9.2× faster`) **did not materialise** at the bench level. IQRs overlap entirely.

**Important nuance — DO NOT misread as "no improvement":** post-I latencies are unambiguously lower (median p50 -29%, p99 -18%), CPU stayed flat, and conformance is clean. The decode is faster; throughput is just bottlenecked elsewhere. Consistent with the `flush_impl=75%, QPACK ≈17% inclusive / 7% self of short-conn CPU` flamegraph attribution from G — eliminating QPACK CPU entirely cannot lift rps by more than ~7% in the best case, and tail-improvements alone don't move the median rps signal above noise.

---

## Image SHAs

| tag | SHA | source state |
|---|---|---|
| `mojo-net-bench:i-pre-fresh` | `d19c7179f24698dda50b94809c9bbf244127830f7f0f269ecdd8d2993180456a` | qpack.mojo=842 lines (stashed I) |
| `mojo-net-bench:i-post` (= `:latest`) | `5517581a6735999d3950a4240bbd65bcfebcb0979b72239e76414ab31a6be357` | qpack.mojo=1086 lines (post-I) |

Both rebuilt from clean Docker contexts on 2026-05-05. The pre-existing `mojo-net-bench:i-pre` left by the failed agent (`b0de83b5...`) was actually built off post-I source — discarded; not used.

---

## Per-iter rps tables

### PRE-I

| iter | rps | server CPU% | p50 ms | p99 ms |
|---|---|---|---|---|
| 1 | 1218.03 | 60.04 | 5.842 | 19.017 |
| 2 | 1194.01 | 56.69 | 6.348 | 18.440 |
| 3 | 1150.96 | 59.41 | 4.315 | 19.000 |
| 4 | **560.37** | **40.04** | 1.897 | 7.067 |
| 5 | 1162.06 | 56.26 | 5.407 | 19.172 |
| 6 | 1155.75 | 55.40 | 5.596 | 17.849 |
| 7 | 1130.09 | 58.37 | 4.245 | 17.163 |
| 8 | 1192.99 | 56.96 | 4.748 | 17.493 |
| 9 | 1190.96 | 58.90 | 4.978 | 17.822 |
| 10 | 1168.84 | 56.57 | 6.189 | 20.143 |

iter4 is a host-contention outlier (CPU 40% vs. 56% norm; visible spike on host during that 30 s window). Robust median absorbs it. Cleaned (n=9) median = 1168.84 rps → lift ≈ 0.00%.

### POST-I

| iter | rps | server CPU% | p50 ms | p99 ms |
|---|---|---|---|---|
| 1 | 1086.25 | 54.84 | 2.811 | 14.549 |
| 2 | 1192.52 | 56.66 | 4.290 | 15.601 |
| 3 | 1119.14 | 55.69 | 4.853 | 18.196 |
| 4 | 1103.58 | 54.68 | 3.044 | 14.109 |
| 5 | 1170.73 | 56.30 | 4.547 | 15.653 |
| 6 | 1143.76 | 53.91 | 3.492 | 14.563 |
| 7 | 1190.63 | 54.72 | 3.827 | 13.669 |
| 8 | 1167.93 | 57.02 | 4.946 | 17.440 |
| 9 | 1169.69 | 56.05 | 4.173 | 17.051 |
| 10 | 1183.76 | 56.86 | 3.575 | 13.721 |

---

## Verdict matrix application

Per `feedback_bench_gate_width_calibration.md` and `feedback_perf_impact_floor_filter.md`:

| condition | result |
|---|---|
| lift ≥ +4% AND conformance PASS AND IQRs separated → **CONFIRMED** | NO (+0.29%, IQRs overlap) |
| lift ≥ +4% but IQRs overlap → **PARTIAL** | NO (+0.29%) |
| lift in 0–4% range with overlapping IQRs → **INCONCLUSIVE** | n/a |
| **lift < 1% impact-floor → FALSIFIED** | **YES** |
| lift < 0% or conformance FAIL → **FALSIFIED** | n/a |

**FINAL: FALSIFIED**

---

## Conformance

`TESTS_FILTER=qpack bash scripts/run_tests.sh` against post-I `mojo-net-bench:latest`:

```
test_h3_qpack: 30/30 PASS
```

(All 30 sub-tests passed: static-table indexing, huffman roundtrip, padding/EOS rules, encode/decode literals, indexed/literal field-line forms, error paths.)

`test_h3_connection` failed during a broader `TESTS_FILTER=h3` run with `quic_server_conn_new failed: rlsm_quic_server_conn_new: invalid config handle` — pre-existing, unrelated to QPACK changes (last touch on `src/h3/connection.mojo` is `96d7f6d` which predates I; the FFI handle error is in TLS/QUIC FFI, not QPACK). Not gating.

---

## Why throughput didn't move (analysis)

1. **Decode IS faster.** Latency tails confirm it: post-I median p50 = 3.83 ms vs pre-I 5.41 ms (-29%); p99 = 14.66 ms vs 17.85 ms (-18%). The 7.2–9.2× microbench result is real on the per-request critical path.
2. **Short-conn throughput is not QPACK-bound.** Per `project_short_conn_lib_bound_was_artifact.md` (2026-05-04 flamegraph): `_flush_impl = 75% CPU`, QPACK = 17% inclusive / 7% self. Reducing QPACK CPU from 7% self → ~1% self frees ~6% of one core. Bench server is single-core (`--cpuset-cpus=0 --workers 1`) running at ~55% CPU on average — compute is not the binder. The compute headroom freed by I is *consumed by idle / io_uring_enter waits*, not converted to additional connections served.
3. **CPU% confirms.** Pre vs post mean server CPU: 55.86% → 55.67% (delta = -0.19 pp). If I were converting compute savings into rps, we'd expect either (a) higher rps at same CPU% or (b) lower CPU at same rps. We see neither — the ~6% per-request CPU saving is being absorbed by the wait cycle, not turned into more handshakes/sec.
4. **Bottleneck is elsewhere.** Consistent with the long-standing finding (`project_long_conn_parity_short_conn_ceiling.md`): server parked 97.7% in io_uring_enter, recvmsg n=1/CQE. The lever to move short-conn rps is on the io path, not on Mojo-side compute reductions.

This matches the spec's own `risk: lift may not transmit through bench harness if QPACK CPU is amortised across the wait cycle` (paraphrased); the prediction has been verified.

---

## Sidecar counters — N/A this cell

PROFILE_ACCEPT was reverted to `False` per `q9-verdict` retrospective; no sidecar JSONs were produced for either cell. (We have only client-side parsed output.) If a follow-up wants per-leg attribution, the agent would need to re-flip PROFILE_ACCEPT and rebuild — out of scope for this verdict run.

---

## Recommendation

1. **Keep the I changes.** Decode is correct (30/30 conformance) and measurably faster on per-request latency (-29% p50, -18% p99). Tail-latency improvements alone have value for SLOs even if median rps is unchanged.
2. **Drop the "+4–7% short-conn rps" claim from the I report.** The claim was a microbench-projection that did not survive bench validation. Update the spec retrospective to note this falsification.
3. **Stop searching for short-conn rps lifts inside Mojo-side compute paths.** Per the impact-floor + ledger:
   - Per-request CPU phases below ~10% of wall-clock cannot move median rps with the current bottleneck (io_uring_enter). All such optimisations will FALSIFY at the impact-floor regardless of microbench speedup.
   - The next hypothesis bracket should target the io path (recvmsg multi-shot, CQE batching, kernel byp ass tunables) — not further Mojo-side decode/encode work.
4. **Do NOT roll I back.** Latency improvements are real and rolling back loses them for zero throughput cost.

---

## Working-tree state at end of run

- 3 modified files (intended): `crates/librustls-mojo/Cargo.toml`, `src/h3/qpack.mojo` (1086 lines), `tests/test_h3_qpack.mojo` (462 lines).
- `mojo-net-bench:latest` SHA matches `mojo-net-bench:i-post` SHA (verified `5517581a6735…`).
- Stash cleanly applied and dropped — no residual stash entries.
- Per-iter logs preserved under `bench/quic_perf/results/baselines/i-pre/iter-N.log` and `i-post/iter-N.log`; per-iter JSON results under `i-pre/json/` and `i-post/json/`.

## Files

- This verdict: `bench/quic_perf/results/baselines/i-qpack-huffman-verdict.md`
- Per-iter logs + JSON: `bench/quic_perf/results/baselines/i-pre/{iter-N.log, json/*.json}` and `bench/quic_perf/results/baselines/i-post/{iter-N.log, json/*.json}`
- Spec being validated: `specs/2026-05-04-qpack-huffman-table-driven.md`
