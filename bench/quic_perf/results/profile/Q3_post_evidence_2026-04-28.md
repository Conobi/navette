# Q3 Post-migration Evidence — 2026-04-28

**Plan:** `plans/2026-04-28-quic-bench-dcid-u64-demux.md`
**Branch:** `feat/quic-bench-dcid-u64-demux` (T2 commit `31f9b4c`)

## Image SHAs

| Image | SHA256 | PROFILE_ACCEPT |
|---|---|---|
| `mojo-net-bench:q3-post-off` | `84acc58486717cda...` | False |
| `mojo-net-bench:q3-post-on` | `4c475002d91ce3eb...` | True |

## AC#2 — Hard Gate 1: on-build long-conn RPS non-regression

**Verdict: ✅ PASS**

| | Pre (q3-pre-on) | Post (q3-post-on) | Drift |
|---|---|---|---|
| Median | 14,121.25 rps | **14,232.28 rps** | **+0.79%** |
| Mean | 13,977.22 | 14,090.02 | — |
| Stdev | 295.93 (2.12%) | 605.35 (4.30%) | — |
| IQR p25/p75 | 13,748.67 / 14,179.31 | — | — |

Gate threshold: median drift ≥ −2.0%. Observed +0.79% (well within budget).

Per-iter post values: 13719.03, 13985.03, 14315.99, 14553.58, 14448.75, 14525.66, 14528.42, 14148.58, 12551.13, 14124.06.

## AC#3 — Hard Gate 2: short-conn `loop_pop_dispatch.total` observed drop

**Verdict: ✅ PASS — direct decision on n=5+5 (no escalation needed)**

| | Pre (n=5) | Post (n=5) |
|---|---|---|
| Median (μs / 30s) | 905,094 | **763,277** |
| Mean | 909,884 | 760,531 |
| Stdev | 24,337 (2.69%) | 11,818 (1.55%) |

Per-iter pre: 902643, 920857, 877454, 905094, 943374
Per-iter post: 769615, 763277, 768226, 761229, 740309

**Drop = 15.67%** (predicted bracket 8–22%; lands at upper-middle of prediction).

Decision rule outcome:
- treatment stdev 1.55% (gate: ≤5%) → no escalation triggered
- median drop 15.67% > 10% (outside marginal zone [6%, 10%]) → no escalation triggered
- median drop 15.67% ≥ 8% threshold → **PASS direct on n=5+5**

Notable: treatment stdev (1.55%) is _lower_ than baseline (2.69%) — the migration also tightened variance, plausibly because UInt64 packing has constant cost while hex-encoding has variable allocator cost.

## AC#4 — Hard Gate 3: `dcid_mismatch_pkts == 0` correctness check

**Verdict: ✅ PASS**

All 10 sidecars (5 pre + 5 post) report `dcid_mismatch_pkts == 0`. Demux invariant preserved through the type migration.

## AC#5 — off-build long-conn non-regression

**Verdict: ✅ PASS**

| | Pre (q3-pre-off) | Post (q3-post-off) | Drift |
|---|---|---|---|
| Median | 13,311.51 rps | **14,122.02 rps** | **+6.09%** |
| Mean | 13,298.68 | 14,103.68 | — |
| Stdev | 742.90 (5.59%) | 364.84 (2.59%) | — |

Gate threshold: median drift ≥ −2.0%. Observed +6.09%.

Per-iter post: 14304.88, 14381.83, 13901.36, 14602.75, 14489.71, 13772.94, 13937.94, 13401.39, 14049.99, 14194.06.

Off-build CV improved from 5.59% pre → 2.59% post (similar tightening to AC#3's sidecar variance — consistent with the constant-cost u64-packing replacing variable-cost hex-encoding).

## Soft Gate — short-conn RPS (informational)

| | Pre (off-build) | Post (off-build) | Drift |
|---|---|---|---|
| Median | 1,143.22 rps | **1,194.50 rps** | **+4.49%** |
| CV | 1.59% | 3.58% | — |

Per-iter post: 1204.38, 1091.41, 1179.92, 1141.05, 1168.48, 1222.45, 1237.04, 1208.02, 1194.94, 1194.06.

Conservative prediction was 0.5–1.4% RPS lift; observed +4.49% is at the optimistic end of the 2–3% upper estimate. Drift sits above the n=10 short-conn noise floor (σ ≈ 1.59% pre, ≈ 3.58% post). Not gated, but a credible directional signal.

## Open question — AHash distribution sanity

Skipped per spec §10 risk note: DCIDs are random by construction (rustls CSPRNG). No clustering observed — `loop_pop_dispatch.total` consistency at n=5 (CV 1.55%) implies stable Dict probe behaviour across iters.

## All ACs summary

| # | Description | Verdict |
|---|---|---|
| AC#1 | Unit test count delta = +2 | ✅ PASS (T1 closed) |
| AC#2 | Hard Gate 1 long-conn on-build drift ≥ −2.0% | ✅ PASS (+0.79%) |
| AC#3 | Hard Gate 2 sub-leg drop ≥ 8% | ✅ PASS (15.67%) |
| AC#4 | Hard Gate 3 `dcid_mismatch_pkts == 0` | ✅ PASS (all 10 sidecars) |
| AC#5 | Off-build long-conn drift ≥ −2.0% | ✅ PASS (+6.09%) |
| AC#6 | REFERENCE.md entry | (T5) |
| AC#7 | Flag revert | ✅ PASS (verified) |

**All measurement gates GREEN. Q3 migration ready for T5 close-out.**
