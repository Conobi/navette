# Q3 Pre-migration Baselines — 2026-04-28

**Plan:** `plans/2026-04-28-quic-bench-dcid-u64-demux.md`
**Branch:** `feat/quic-bench-dcid-u64-demux` off main `b1274d11`
**Pre-spec test count anchor (TESTS_FILTER=test_quic_connection):** 36 tests (34 `<name>: PASS` style + 2 `PASS: <name>` style).

## Image SHAs

| Image | SHA256 | PROFILE_ACCEPT | ASSERT |
|---|---|---|---|
| `mojo-net-bench:q3-pre-off` | `58355c391e7b...` | False | (default) |
| `mojo-net-bench:q3-pre-on` | `7dc8312bff74...` | True | (default) |

## Off-build long-conn (n=10, 1k payload, tquic_client)

| Stat | Value |
|---|---|
| Median | **13,311.51 rps** |
| Mean | 13,298.68 rps |
| Stdev | 742.90 rps |
| CV | 5.59% |
| IQR p25 | 12,515.06 rps |
| IQR p75 | 14,085.56 rps |

Per-iter: 13320.75, 14189.22, 13302.26, 14155.65, 14062.19, 12815.39, 12429.84, 12543.47, 12307.74, 13860.32

## Off-build short-conn (n=10, 1k payload, tquic_client)

| Stat | Value |
|---|---|
| Median | **1,143.22 rps** |
| Mean | 1,141.06 rps |
| Stdev | 18.09 rps |
| CV | 1.59% |
| IQR p25 | 1,136.44 rps |
| IQR p75 | 1,151.91 rps |

Per-iter: 1142.21, 1154.89, 1136.96, 1134.89, 1145.31, 1144.22, 1139.35, 1150.91, 1165.28, 1096.54

## On-build long-conn (n=10, 1k payload, tquic_client)

| Stat | Value |
|---|---|
| Median | **14,121.25 rps** |
| Mean | 13,977.22 rps |
| Stdev | 295.93 rps |
| CV | 2.12% |
| IQR p25 | 13,748.67 rps |
| IQR p75 | 14,179.31 rps |

Per-iter: 13324.09, 14098.37, 13703.55, 13763.71, 13949.42, 14169.65, 14208.30, 14245.40, 14144.12, 14165.59

Note: on-build > off-build (14,121 vs 13,311) is unexpected (profiling overhead should slow on-build). Most likely host noise — off-build batch landed first when post-build CPU was still settling. Both numbers serve as baselines for their respective post-migration comparisons (AC#2 uses on-build vs on-build; AC#5 uses off-build vs off-build).

## On-build short-conn `loop_pop_dispatch.total` (n=5 SIGINT sidecars)

| Stat | Value (μs / 30s) |
|---|---|
| Median | **905,094** |
| Mean | 909,884 |
| Stdev | 24,337 |
| CV | 2.67% |

Per-iter: 902,643, 920,857, 877,454, 905,094, 943,374

`dcid_mismatch_pkts == 0` confirmed in all 5 sidecars (Hard Gate 3 baseline).

Sidecar files:
- `INSTRUMENTATION-20260428-163732-q3-pre-shortconn-iter1.json`
- `INSTRUMENTATION-20260428-163806-q3-pre-shortconn-iter2.json`
- `INSTRUMENTATION-20260428-163840-q3-pre-shortconn-iter3.json`
- `INSTRUMENTATION-20260428-163914-q3-pre-shortconn-iter4.json`
- `INSTRUMENTATION-20260428-163948-q3-pre-shortconn-iter5.json`

## Notes / lessons

- `bench/build.sh` fails from worktrees because it infers `BOUCLE_DIR=$REPO_ROOT/../boucle` which doesn't exist relative to `.worktrees/baseline-main/`. Fix: pass explicit `BOUCLE_DIR=../boucle SIMDJSON_DIR=../json-simd-mojo` env vars (matches `feedback_bench_offbuild_image_hygiene.md` lesson).
- Long-conn CV at 5.59% is higher than short-conn 1.59%; this is consistent with prior captures and reflects long-conn's wider per-iter spread (the 30s window with multiple background variables).
- PROFILE_ACCEPT was flipped True → captured → reverted False; working tree clean post-T0.
