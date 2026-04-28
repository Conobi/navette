# Q1 Pre-migration Baselines — 2026-04-29

**Plan:** `plans/2026-04-29-quic-h3-phase-leg-instrumentation.md`
**Branch:** `feat/quic-h3-phase-leg-instrumentation` off main `978389b`
**Pre-spec test count anchor (TESTS_FILTER=test_quic_profile, ^PASS: prefix):** 42

## Image SHAs

| Image | SHA256 | PROFILE_ACCEPT |
|---|---|---|
| `mojo-net-bench:q1-pre-off` | `84acc58486717cda...` | False |
| `mojo-net-bench:q1-pre-on`  | `db320611e265c966...` | True  |

## Off-build long-conn (n=10, 1k payload, tquic_client)

| Stat | Value |
|---|---|
| Median | **13,857.79 rps** |
| Mean | 13,737.67 rps |
| Stdev | 537.46 (CV 3.91%) |

Per-iter: 14378.47, 14128.37, 14248.39, 14195.03, 13710.81, 13251.75, 13543.30, 13005.22, 14004.77, 12910.59

## Off-build short-conn (n=10, 1k payload, tquic_client)

| Stat | Value |
|---|---|
| Median | **1,180.38 rps** |
| Mean | 1,143.74 rps |
| Stdev | 92.08 (CV 8.05%) |

Per-iter: 1141.60, 948.28, 1002.39, 1179.06, 1208.70, 1164.85, 1181.71, 1201.83, 1205.67, 1203.35

(High CV from iter 2-3 outliers; acceptable as anchor since AC#5 threshold is non-regression ≥-2.0%.)

## On-build long-conn (n=10)

| Stat | Value |
|---|---|
| Median | **14,172.62 rps** |
| Mean | 14,014.07 rps |
| Stdev | 516.19 (CV 3.68%) |

Per-iter: 12589.33, 14396.85, 13886.08, 14177.42, 14186.74, 14149.44, 14265.85, 14143.79, 14170.43, 14174.81

## On-build short-conn (n=10)

| Stat | Value |
|---|---|
| Median | **1,173.53 rps** |
| Mean | 1,166.24 rps |
| Stdev | 37.19 (CV 3.19%) |

Per-iter: 1203.70, 1076.98, 1145.56, 1173.58, 1209.21, 1173.34, 1182.57, 1173.47, 1175.15, 1148.85

## On-build n=3 long-conn SIGINT sidecars (Hard Gate 1 baseline)

| Iter | `unaccounted_pct` | `dcid_mismatch_pkts` |
|---|---|---|
| 1 | 93.3% | 0 |
| 2 | 93.5% | 0 |
| 3 | 93.4% | 0 |
| **Median** | **93.4%** | **0** |

**Note:** Higher than the sub-leg pass's 82% reading. Possible contributors: (a) post-Q3 hot-path tightening shifted the busy-time mix toward H3-application work; (b) host noise in the small n=3 sample. Either way, the 93.4% baseline gives Q1 even more headroom to close (target <15% post; the 3 new H3 legs should absorb the bulk).

Sidecar files:
- `INSTRUMENTATION-20260428-234733-q1-pre-long-conn-iter1.json`
- `INSTRUMENTATION-20260428-234808-q1-pre-long-conn-iter2.json`
- `INSTRUMENTATION-20260428-234842-q1-pre-long-conn-iter3.json`

## On-build n=3 short-conn SIGINT sidecars (informational)

| Iter | `unaccounted_pct` | `dcid_mismatch_pkts` |
|---|---|---|
| 1 | 31.4% | 0 |
| 2 | 30.9% | 0 |
| 3 | 31.1% | 0 |
| **Median** | **31.1%** | **0** |

**Note:** Higher than sub-leg pass's 18% short-conn reading; same possible contributors. Short-conn ε is not gated by Hard Gate 1 (that's long-conn-only), but the Q1 H3 legs are expected to reduce short-conn ε below 5% as a side benefit.

Sidecar files:
- `INSTRUMENTATION-20260428-234925-q1-pre-short-conn-iter1.json`
- `INSTRUMENTATION-20260428-234959-q1-pre-short-conn-iter2.json`
- `INSTRUMENTATION-20260428-235033-q1-pre-short-conn-iter3.json`

## Notes / lessons

- `bench/build.sh` worktree-relative `BOUCLE_DIR` path failure recurs as expected — fixed by passing explicit env vars (`BOUCLE_DIR=../boucle SIMDJSON_DIR=../json-simd-mojo`) per `feedback_bench_offbuild_image_hygiene.md`.
- PROFILE_ACCEPT was flipped True → captured → reverted False; working tree clean post-T0.
- Image cache: `mojo-net-bench:q1-pre-off` shares SHA `84acc5848671` with Q3's `q3-post-off` (same source content; only docs/spec/plan changed since Q3 merge). Cache hit kept the off-build rebuild fast.
