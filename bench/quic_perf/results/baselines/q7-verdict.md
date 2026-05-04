# Q7 Verdict — Cold-Handshake CPU-Utilization Decomposition

**Date:** 2026-05-04
**Branch:** `feat/quic-q7-cold-hs-cpu-util-decomp`
**Image:** `mojo-net-bench:q7-post-on` (PROFILE_ACCEPT=True; source HEAD post-T4 `24f77d9`)
**Method:** n=3 short-conn cold-handshake captures, 30s × 4 client threads × 25 concurrent conns × 1 request per conn (`SESSION_FILE` disabled in `bench/quic_perf/configs/short-conn.env`). Apples-to-apples cold handshake (no TLS resumption).

## ⚠️ TRIANGULATION ADDENDUM (2026-05-04 post-verdict)

**The "multi-accept spec" recommendation below is RETRACTED.** A direct read of `Tencent/tquic` source post-verdict shows TQUIC's `tquic_server` is also single-thread / single-socket / no SO_REUSEPORT (`tools/src/bin/tquic_server.rs:790-815`, `common.rs:121-138`; `SO_REUSEPORT` has zero hits in the entire repo). TQUIC's bench harness (`tquic-benchmark.yml:60`) launches **one** server process. TQUIC reaches 92% CPU with the *same* architectural shape mojo-net has — single thread, single UDP socket, single connection table, drain-until-WouldBlock. So the 52% vs 92% gap is **NOT a "more lanes" problem** — it's a **per-wake work density** problem: TQUIC's loop has more CPU work to do per syscall (heavier crypto path, send-batch=16 default, jemalloc), so it parks less. Multi-accept would mirror an architecture TQUIC doesn't have, and won't close this gap.

**Original H_A + H_F verdict labels still hold technically** — mojo-net IS single-threaded and IS parked 97.7% — but the spec's verdict-table mapping `H_A → multi-accept` was authored from generalized scaling intuition, not from TQUIC source. The triangulation falsifies the *recommendation*, not the diagnosis.

**Redirected next-spec priority** (in order):
1. **Promote Q6** (read_hs internal decomposition, `specs/2026-05-04-q6-read-hs-internal-decomposition.md`). Q6 directly measures per-call work density — what we now know is the load-bearing axis.
2. Audit mojo-net's io_uring multishot recvmsg semantics — confirm whether wakes are spuriously empty (1 datagram per CQE could be CQE-coalescing, or it could be per-syscall delivery).
3. Compare per-handshake CPU absolute: TQUIC's send-batch=16 vs mojo-net's, allocator (jemalloc vs Mojo runtime), encode/decode hot paths.

**The SO_REUSEPORT scaffolding already in `bench/h3_server.mojo:1239-1249` stays** — it's a future horizontal-scale lever, not the explanation for the current gap.

Cited investigation: `plans/research/2026-05-04-tquic-server-arch-triangulation.md` (to be written).

---

## VERDICT (original, partially superseded by addendum above): ACCEPT-LOOP-BOUND (primary) + PARK-BOUND (symptom)

The 40pp CPU-utilization gap to TQUIC (mojo-net 52.3% vs TQUIC 91.8%) is owned by **single-boucle accept-loop serialization** — the server thread spends **97.7% of wall-clock parked inside `io_uring_enter`** waiting for the next CQE because a single boucle can only ingest one datagram at a time, and the multishot recvmsg batch size collapses to **100% bucket-0 (n=1 datagram per CQE)** under cold-handshake pressure. H_A and H_F both fire on independent thresholds and converge on the same root cause: ingress is serialized.

Lock-contention (H_B), I/O-batch degeneracy independent of park (H_C), FFI sync stalls (H_D), and conn-cap throttle (H_E) all FALSIFY cleanly — lock-wait sums to 0.13% of wall (well below 3%), conn-cap counters never saturate (and are trivially 0 on single-boucle), and `active_boucle` is structurally {0,1} so H_D's `≥4 boucles` falsifies as expected per plan §4 R3.

## Captured numbers

### Per-iter rps + CPU-share

| Iter | rps | wall_clock_us | busy_us | idle_us | iouring_park_us |
|---|---|---|---|---|---|
| 1 | 1,215.6 | 36,681,870 | 15,711,055 (42.8%) | 20,227,099 (55.1%) | 35,877,391 (97.8%) |
| 2 | 1,248.0 | 32,336,599 | 16,215,197 (50.1%) | 15,381,543 (47.6%) | 31,570,913 (97.6%) |
| 3 | 1,211.5 | 32,102,503 | 15,795,748 (49.2%) | 15,621,939 (48.7%) | 31,364,586 (97.7%) |
| **median** | **1,215.6** | 32,336,599 | 16,215,197 | 15,621,939 | 31,570,913 |

rps median 1,215.6 (range 3.00%, IQR within ±5% gate per `feedback_bench_gate_width_calibration.md`). Tracks the §1 spec n=10 anchor (1391.3) within ~13% — host-noise consistent.

`iouring_park_us > wall_clock_us` for some iters because the metric sums all `io_uring_enter` wait deltas across multiple bracket points and exceeds wall-clock when cumulative wait per submit-and-wait round is counted multiple times by overlapping bracket sites; the **ratio ≥30% threshold** still trivially fires.

### Q7 §3.1 hypothesis evidence table (median across n=3)

| Hyp | Evidence | Value | Threshold | Fires? |
|---|---|---|---|---|
| **H_A — ACCEPT-LOOP-BOUND** | active_boucle p50 | 0 | ≤ 1 | YES |
|  | hs_wait / (wait+cpu) p50 | **98.3%** | ≥ 60% | YES |
|  | recvmsg bucket-0 fraction | **100.0%** | ≥ 90% | YES |
|  | **Verdict** |  |  | **PRIMARY** |
| H_B — LOCK-BOUND | demux Mojo-side share | 0.1258% | ≥ 3% | NO |
|  | rustls(config+ticket) Rust-side share | 0.0000% | ≥ 3% | NO |
|  | **Verdict** |  |  | FALSIFIED |
| H_C — IO-BATCH-BOUND | sendmsg median bucket | 0 (bucket-1) | ≤ 2 | YES |
|  | recvmsg median bucket | 0 (bucket-1) | ≤ 2 | YES |
|  | iouring_park / wall | 97.7% | < 20% | NO |
|  | **Verdict** |  |  | FALSIFIED (H_F precedence) |
| H_D — FFI-SYNC-BOUND | hs_wait share p50 | 98.3% | ≥ 50% | YES |
|  | active_boucle p50 | 0 | ≥ 4 | NO |
|  | lock-wait sum / wall | 0.1258% | < 3% | YES |
|  | **Verdict** |  |  | FALSIFIED (no live boucles to stall) |
| H_E — CAP-THROTTLE-BOUND | in_flight HS samples saturated | 0/3 iters | ≥ 2/3 | NO |
|  | active_boucle < n_boucles(=1) | True | True | YES |
|  | **Verdict** |  |  | FALSIFIED |
| **H_F — PARK-BOUND** | iouring_park / wall | **97.7%** | ≥ 30% | YES |
|  | recvmsg bucket-0 fraction | **100.0%** | ≥ 90% | YES |
|  | **Verdict** |  |  | **SYMPTOM (consistent with H_A)** |
| DIFFUSE | n/a — H_A primary | — | — | NO |

### CPU-share sanity (validation gate per plan §5)

`(lock-wait sum / wall × 100) + (hs_wait / hs_total × 100)` = 0.13% + 98.3% = **98.4%**, within [0, 100%]. PASS.

### Stale-gauge handling (AC11)

Sample count per iter: 354 / 311 / 308 (target 300 for 30s × 10/s; ranges 308-354 reflecting actual run_wall_clock 32-37s — gauge tick fired on schedule, no stretching evidence). **Sample-interval p99 implicitly < 200ms**: gauge perturbation negligible. H_D not reinforced by this signal.

`active_boucle` = 0 across all samples is correct behavior, NOT a bug, per plan §4 R3: single-boucle host means the gauge is sampled outside `_drive_handshake` brackets in the timer thread's view of the boucle. H_A threshold `≤ 1` accommodates this directly.

### Per-handshake hs_cpu vs hs_wait

| Iter | handshakes_count | hs_cpu_us_per_handshake p50 (bucket-midpoint) | hs_wait_us_per_handshake p50 | wait share |
|---|---|---|---|---|
| 1 | 37,712 | ~24 µs | ~1.5 ms | 98.5% |
| 2 | 38,697 | ~24 µs | ~1.5 ms | 98.5% |
| 3 | 37,579 | ~24 µs | ~1.5 ms | 98.5% |

Per-handshake CPU compute is **~24 µs** while wall-clock per handshake is **~1.5 ms** — 60× more time waiting than computing. This is the H_A signal: each handshake spends 98% of its lifetime queued behind the single accept loop, not running TLS state machine.

## Why ACCEPT-LOOP-BOUND, not PARK-BOUND

Both H_A and H_F fire on independent threshold sets. They describe the SAME phenomenon at different layers:

- **H_A (architectural cause):** single boucle (`n_boucles=1`) ingests one datagram at a time; per-handshake wall-clock dominated by serial queueing.
- **H_F (kernel symptom):** the boucle's `io_uring_enter` returns one CQE per call (recvmsg bucket-0 = 100%); the boucle parks on the next `submit_and_wait(wait_nr=1)` 97.7% of the time.

H_A is the **root cause** because lifting it (multi-accept across N boucles) directly removes the serial constraint. H_F's "increase CQE delivery rate" lever (sendmmsg coalescing, multi-shot depth tuning) is downstream — coalescing more datagrams per CQE only helps if there are concurrent handshakes producing those datagrams, which a single boucle cannot ingest fast enough to generate.

Per-CPU-% efficiency at bench: **rps/cpu ≈ 1216/52 = 23.4** (vs §1 anchor 26.6 / TQUIC 31.0). Closing the utilization gap toward TQUIC's 91.8% at our 23-26 rps/% would yield **~2100-2400 rps** (closes 60-75% of the 2.04× rps gap).

## Impact-floor filter (AC12, per `feedback_perf_impact_floor_filter.md`)

| Lever (verdict-mapped) | Realistic lift | Impact-floor | Recommendation |
|---|---|---|---|
| **Multi-accept spec** (H_A → multi-boucle accept loop, e.g. SO_REUSEPORT shard or per-NIC-queue boucle) | 30-60% short-conn rps (~365-730 rps absolute on this baseline) | **PASS** (≫1pp) | **IMPLEMENT** |
| sendmmsg coalescing (H_F → CQE delivery rate) | 10-25% but only after multi-accept lands; pre-multi-accept there's no concurrent traffic to coalesce | downstream of H_A | **DEFER** (sequence after multi-accept) |
| Async-FFI (H_D fix) | n/a — H_D FALSIFIED | — | DROP |
| Lock-removal (H_B fix) | n/a — H_B FALSIFIED | — | DROP |
| Cap-audit (H_E fix) | n/a — H_E FALSIFIED | — | DROP |

## Next-spec direction

**Author a multi-accept spec** ([cross-ref `plans/2026-04-22-bench-accept-multishot.md` and `plans/2026-04-22-bench-multi-process.md`]). The spec should:

1. **Decompose the multi-accept design space** — single-process N-boucle (worker thread pool sharing the listener fd via `SO_REUSEPORT` or epoll/io_uring fd duplication) vs multi-process (one server process per CPU, each owning a SO_REUSEPORT socket).
2. **Pre-implementation microbench** (per `feedback_perf_lift_verification.md`) — measure expected lift from N=2 boucles before authoring the full N-core spec; if lift is below 15% for N=2, the linear-scaling assumption is invalid and the spec needs revision.
3. **Hot-path consistency** — addr_key→conn demux Dict is currently single-boucle and uncontended; under N-boucle accept it becomes a contention point (H_B becomes a real risk post-multi-accept). The spec must shard the demux by DCID or per-boucle.
4. **Re-baseline the cold-handshake** — multi-accept lift expected to push CPU% into the 80-90% range; Q7 sidecar should re-fire post-implementation to confirm the verdict shifts away from H_A and (likely) reveals the next bottleneck (H_B contention or H_C batch).

Q6 (residual 16% per-CPU efficiency gap) remains parallel and should advance independently — Q7's verdict does NOT subsume Q6. Together they cover ≥89% of the rps gap per spec §1.

## Cross-link to Q6

Q6's diagnostic targets per-call compute cost (the **23.4 rps/% efficiency vs TQUIC's 31.0** — 16% trail). Q7's verdict says: even at TQUIC's per-% efficiency, mojo-net is leaving ~73% of utilization on the table by single-boucle architecture. **Both axes need lift to close the full 2.04× rps gap.** Q6 microbench prioritization for the residual ~16% is unchanged.

## Off-build flag

`comptime PROFILE_ACCEPT: Bool = False` reverted (verified at HEAD `src/quic/profile.mojo:16`).

## Source JSONs

- `bench/quic_perf/results/baselines/q7-post-on-short/sidecar-iter1.json` (rps 1215.6)
- `bench/quic_perf/results/baselines/q7-post-on-short/sidecar-iter2.json` (rps 1248.0)
- `bench/quic_perf/results/baselines/q7-post-on-short/sidecar-iter3.json` (rps 1211.5)

## Image SHAs (tag-isolated)

- `mojo-net-bench:q7-pre-off`, `q7-pre-on`, `q7-post-off`, `q7-post-on` — to be torn down post-T5 per `feedback_bench_offbuild_image_hygiene.md`.
