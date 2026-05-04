# Q6 Verdict — `read_hs` Internal Decomposition: **LIB-BOUND**

**Date:** 2026-05-04
**Branch:** `feat/quic-q6-read-hs-internal-decomp`
**Spec:** `specs/2026-05-04-q6-read-hs-internal-decomposition.md`
**Image:** `mojo-net-bench:q6-post-on` (PROFILE_ACCEPT=True, DRAIN_TO_EAGAIN=False)

## TL;DR

**LIB-BOUND, unambiguous.** 99.5% of `read_hs` per-call wall-clock is the rustls state machine itself; the 4-sub-leg decomposition closes 100.9% of Q5's existing `read_hs_us_per_call` total (within ±5% sanity gate).

| sub-leg | median share | threshold | hit? |
|---|---|---|---|
| `state_machine_us` (rustls body) | **99.5%** | LIB-BOUND ≥80% | **YES** |
| `input_marshalling_us` (Mojo→Rust copy) | 0.6% | CALLPATTERN-BOUND ≥10% | NO |
| `output_alloc_us` (handle-table lookup) | 0.4% | — | NO |
| `output_marshalling_us` (zero-by-design for read_hs) | 0.4% | informational | — |
| `output_alloc + output_marshalling` | 0.9% | ALLOC-BOUND ≥30% | NO |
| sub-leg sum vs Q5 total | 100.9% | sanity ±5% | PASS |

Verdict per spec §3.1: **LIB-BOUND**. Next-spec direction per spec: Lever A (rustls → boringssl/aws-lc) closes ~16pp of the per-CPU-% efficiency gap; **realistic lift: <1pp of total rps until Q7 utilization gap closes** — not the load-bearing lever post-reframe.

## Captured numbers

n=3 short-conn SIGINT sidecars at `bench/quic_perf/results/baselines/q6-post-on-short/sidecar-iter{1,2,3}.json`:

| iter | calls | state_machine µs total | sm µs/call | input_marshal µs/call | output_alloc µs/call |
|---|---|---|---|---|---|
| 1 | 52,153 | 5,964,960 | ~114 | ~0.65 | ~0.51 |
| 2 | 52,153 | 5,964,960 | ~114 | ~0.65 | ~0.51 |
| 3 | 52,105 | 5,955,456 | ~114 | ~0.65 | ~0.51 |

Median per-call cost: **~114 µs in rustls state machine, ~1.6 µs combined Mojo-side overhead** (input copy + output alloc + output marshalling). The 47 ns FFI thunk microbench from Q5 is a tiny subset of the 1.6 µs Mojo-side total.

iter1 and iter2 numbers are bit-identical because bucket midpoints + matching counts produce deterministic estimated totals. This is an artifact of the bucket-midpoint estimator, not a real measurement-stability claim — the underlying bucket histograms are very wide-tailed and a few-count bucket shift would change the estimate. Treat the per-leg shares as the load-bearing signal, not the absolute µs.

## Long-conn post-on sanity (1 iter)

| rps | cpu% |
|---|---|
| 14,312 | 97.7% |

Within the long-conn pre-off baseline range (13,941 rps, IQR 4.6%). No on-build regression from Q6's instrumentation.

## What's left of the short-conn gap

Apples-to-apples cold-handshake baseline (n=10): mojo-net 1,391 rps / TQUIC 2,846 rps = 0.489× (gap 2.04×).

Decomposition (per Q7 + this Q6):

| Slice | Share of gap | Mechanism | Status |
|---|---|---|---|
| CPU-utilization gap (1.755×) | **73%** | unknown — drain-extension FALSIFIED 2026-05-05 (audit interpretation invalidated). Q7's H_A label "ACCEPT-LOOP-BOUND" stands; multi-accept fix retracted (TQUIC has identical arch). Actual mechanism: still open. | OPEN — **highest-priority unknown** |
| Per-CPU-% efficiency gap (1.165×) | 16% | **LIB-BOUND** — 99.5% of `read_hs` is rustls compute. Lever A (boringssl swap) closes ~16pp efficiency. | NAMED, **deferred** behind Q7 |
| Residual | ~11% | unaccounted | small, defer |

## Implications

1. **Library swap is now a real, named lever** but blocks on Q7's CPU-utilization mechanism. If we close 73% via Q7 (somehow), Lever A unlocks the remaining 16%.

2. **No cheaper Q6 win exists.** All non-`state_machine` sub-legs are <1% individually. Buffer pool / combined-FFI-return / stream-reassemble — all defer or stay falsified per impact-floor filter (`feedback_perf_impact_floor_filter.md`).

3. **The 73% slice is now the ONLY structurally tractable lever this side of a multi-day FFI rewrite.** Drain-extension didn't fit; multi-accept doesn't fit (TQUIC has none); per-call work density (Q6) is `read_hs` itself. We need a new diagnostic to find what TQUIC's loop does between epoll_wait calls that mojo-net's loop doesn't.

## Acceptance criteria checkpoint

| AC | Status | Evidence |
|---|---|---|
| AC1 | PASS | `QuicConnection`: 4× UInt64 fields init to 0 in BOTH ctors (commit `fbffd4d`) |
| AC2 | PASS | `AcceptProfile`: 4× histograms + 4× overflow + 4× record (commit `86e4b3a`) |
| AC3 | PASS | FFI signature 4-out-param block, NULL-safe (commits `2f8743e` Q6 + Q7 prior) |
| AC4 | PASS | `RustlsLibrary` wrapper: legacy 3-arg + profiled 7-arg, default-NULL |
| AC5 | PASS | Bracket site at `connection.mojo:1608+` wires Mojo timer + Rust out-params |
| AC6 | PASS | JSON: 4 new top-level keys; text: 4 summary blocks |
| AC7 | PASS | +1 unit test in test_quic_profile + 1 in test_tls_quic; total 354 → 356 (T2c added 1 less than spec's 357 — single FFI null-safety test covers both bucket-dispatch (T1) and end-to-end null-safety) |
| AC8 | PASS | sub-leg sum sanity 100.9% (spec ±5% gate) |
| AC9 | **PASS** | LIB-BOUND verdict; next-spec direction = Lever A (deferred) |
| AC10 | DEFERRED | smoke gate ±5% n=3 — replaced with 1-iter sanity (97.7% CPU, 14,312 rps; in pre-baseline range). Lean trade-off documented in user/conv. |
| AC11 | (next) | REFERENCE.md row |
| AC12 | PASS | `comptime PROFILE_ACCEPT: Bool = False` confirmed at `src/quic/profile.mojo:16` |

## Image SHAs

- `mojo-net-bench:q6-post-on` (built 2026-05-04T15:18Z)

Sidecars: `bench/quic_perf/results/baselines/q6-post-on-short/sidecar-iter{1,2,3}.json`.

## Lessons (for `feedback_perf_lift_verification.md` corpus)

1. **Q6 succeeded as a measurement-driven projection** (Q4 was the prior survivor; Q6 is the second). The decomposition was clean, the dominant frame is unambiguously rustls-compute, and the verdict aligns with all prior Q5 measurements (97% of read_hs in the 64-128 µs bucket; 99.5% of that bucket is rustls itself, not surrounding code).
2. **The verdict didn't change the search space** — just the cost-arithmetic. We knew before Q6 that "rustls is expensive"; Q6 nailed it to 99.5% so future "tweak the marshalling layer" specs are dead-on-arrival.
3. **Inspection-projection track record now 1/7** when measurement is the projection (Q4 + Q6); 0/6 for inspection-only. Tracking distinct from raw inspection now; measurement-driven projections that survive get their own column.
