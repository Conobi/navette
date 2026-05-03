# Q5 T0 — Pre-Spec Anchors

**Branch:** `feat/quic-q5-read-hs-decomp` (off main `2a5defb`)
**Source HEAD at T0:** `2a5defb` (post-Q4 merge)
**Docker images:**
- `mojo-net-bench:q5-pre-off`: `dc7717c49121` (re-tag of `mojo-net-bench:gate-cal-off`; built from main `2a5defb`, PROFILE_ACCEPT=False)
- `mojo-net-bench:q5-pre-on`: `fb9d2dfc8b78` (rebuilt from `2a5defb` source with PROFILE_ACCEPT=True; flag reverted to False post-build)

## Test count anchor

`grep -c '^def test_'` across `tests/test_quic_*.mojo` + `tests/test_h3_*.mojo`:

**Total: 352 test functions.** (Matches expected: 348 pre-Q4 + 4 Q4 = 352.)

The +2 logical / +3 functional invariant for Q5: post-T1 count must equal **355** (T1 adds 3 test functions for 2 logical assertions: count-bucket dispatch + duration-bucket dispatch + JSON shape). T2 adds 0 new test functions (its invariant is exercised at T4 via real bench).

## Pre-Q5 baselines (n=3, long-conn 1k payload, 30s × 4 threads × 25 conns)

| Build | Median rps | Stdev | Notes |
|---|---|---|---|
| `q5-pre-off` (PROFILE_ACCEPT=False) | 14,833.2 | ~0.2% IQR | Tight; matches gate-calibration baseline |
| `q5-pre-on` (PROFILE_ACCEPT=True) | 14,867.0 | <0.1% IQR | Tight; +0.2% above off-build (within noise) |

Off/on parity at <0.5% gap is in line with the host-calibrated noise floor (`feedback_bench_gate_width_calibration.md`: IQR 1.25%, gate ±5%).

## Drift gate

Per `feedback_bench_gate_width_calibration.md`, smoke-gate drift threshold for Q5 is **±5% on both off-build and on-build**. T3 will compute same-window pre/post pairs (re-running pre-Q5 in the same wall-clock window as post-Q5).

## n=3 deviation justification

Per memory `feedback_bench_iter_count.md` the default is n≥10. Q5 uses n=3 because:
- Diagnostic-only spec (no perf lift expected); the smoke gate is about variance-not-changing post-Q5.
- Same n=3 precedent in Q1, Q3, Q-drain-subleg, Q4.
- Q4-T5 short-conn n=3 capture is also retained for verdict (4-row table only needs distribution shape).
