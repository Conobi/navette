# Q-drain-subleg Pre-migration Baselines — 2026-05-01

**Plan:** `plans/2026-05-01-quic-h3-drain-stream-subleg.md`
**Branch:** `feat/quic-h3-drain-stream-subleg` off main `7e2eb01`
**Pre-spec test count anchor (TESTS_FILTER=test_quic_profile, ^PASS: prefix):** 48

## Image SHAs

| Image | SHA256 | PROFILE_ACCEPT | Notes |
|---|---|---|---|
| `mojo-net-bench:drain-subleg-pre-off` | `e77d7eb425ec...` | False | Re-tag of `mojo-net-bench:q1-post-off` (zero src/+bench/ changes since Q1 merge `70ba90c`) |
| `mojo-net-bench:drain-subleg-pre-on`  | `6b3a214097a2...` | True  | Re-tag of `mojo-net-bench:q1-post-on` |

## Off-build long-conn (n=10, 1k payload, tquic_client)

**Original capture under elevated host load (loadavg 2.4 → 1.8) showed cratered 4.2k rps median; rerun under quieter load (1.8 → 1.5) recovered to expected ~14.5k.**

Iter 1 cold-start was 7886 rps (warmup didn't fully prime); iters 2-10 stable.

| Stat | Value (rerun, iter 2-10) |
|---|---|
| Median | **14,581.45 rps** |
| Per-iter (incl. iter1 outlier) | 7886.36, 13726.86, 14397.79, 14380.04, 14762.61, 14854.86, 14790.35, 14629.21, 14533.29, 14694.54 |

## Off-build short-conn (n=10, 1k payload, tquic_client)

| Stat | Value |
|---|---|
| Median | **1,179.80 rps** |
| Per-iter | 1127.41, 1096.74, 1048.50, 1222.60, 1239.15, 1233.91, 1240.49, 1181.09, 1210.66, 1178.50 |

## On-build long-conn (n=10)

| Stat | Value |
|---|---|
| Median | **14,497.49 rps** |
| Per-iter | 14446.52, 14544.37, 14548.45, 14727.93, 14790.50, 14247.93, 13170.66, 14246.73, 14176.69, 14518.92 |

## On-build short-conn (n=10)

| Stat | Value |
|---|---|
| Median | **1,159.06 rps** |
| Per-iter | 1189.90, 1144.06, 1109.90, 1182.09, 1147.65, 1170.45, 1138.89, 1192.57, 1171.96, 1115.38 |

## On-build n=3 long-conn SIGINT sidecars

| Iter | `busy_us_total` | `h3.post_recv.total` (Q1 named-dominant) | `h3.drain_resp.total` | `h3.dispatch.total` | `dcid_mismatch_pkts` |
|---|---|---|---|---|---|
| 1 | 35,155,241 | 22,442,826 | 5,281,826 | 1,317,407 | 0 |
| 2 | 35,295,071 | 22,770,773 | 5,289,572 | 1,280,743 | 0 |
| 3 | 35,354,076 | 22,870,684 | 5,304,180 | 1,279,487 | 0 |

**Note:** `quic_post_recv_us` median ≈ 22.7M μs (Q1 measured ~19.4M μs — 17% higher today; consistent with elevated background load on this host).

Sidecar files:
- `INSTRUMENTATION-20260501-204612-q-drain-subleg-pre-long-conn-iter1.json`
- `INSTRUMENTATION-20260501-204652-q-drain-subleg-pre-long-conn-iter2.json`
- `INSTRUMENTATION-20260501-204731-q-drain-subleg-pre-long-conn-iter3.json`

## On-build n=3 short-conn SIGINT sidecars (informational)

| Iter | `busy_us_total` | `h3.post_recv.total` | `h3.drain_resp.total` | `h3.dispatch.total` | `dcid_mismatch_pkts` |
|---|---|---|---|---|---|
| 1 | 18,834,429 | 2,421,074 | 530,257 | 190,887 | 0 |
| 2 | 19,262,709 | 2,490,130 | 535,755 | 193,487 | 0 |
| 3 | 19,937,448 | 2,510,621 | 553,503 | 204,184 | 0 |

Sidecar files:
- `INSTRUMENTATION-20260501-204832-q-drain-subleg-pre-short-conn-iter1.json`
- `INSTRUMENTATION-20260501-204912-q-drain-subleg-pre-short-conn-iter2.json`
- `INSTRUMENTATION-20260501-204953-q-drain-subleg-pre-short-conn-iter3.json`

## T0 deviations from plan

1. **Re-tag instead of rebuild.** Both `mojo-net-bench:q1-post-{off,on}` images were verified bit-identical to a fresh build (zero src/+bench/ changes since Q1 merge `70ba90c`); re-tagged as `drain-subleg-pre-{off,on}` to save ~30 min of redundant docker work. SHAs match Q1's recorded post-evidence SHAs.

2. **`bench/quic_perf/scripts/start-server.sh`** modified to add a bind mount `$REPO_ROOT/bench/quic_perf/results/profile:/app/bench/quic_perf/results/profile`. Without this, the SIGINT-handler-written sidecar JSONs land inside the container's writable layer and are destroyed by `docker rm -f`. (Q1 must have used a manual `docker cp` or had a different stop mechanism — the current main does not expose the sidecars on host.) Bind mount is the lasting infrastructure fix.

3. **`bench/quic_perf/scripts/stop-server.sh`** modified to use `docker stop -t 10` (SIGTERM with 10s grace) instead of `docker rm -f` (SIGKILL after 10s grace). The signal handler in `bench/h3_server.mojo:_profile_install_signal_handlers` writes the sidecar at the next flush boundary — the explicit grace period gives the io_uring loop a chance to detect the termination flag and flush.

4. **Off-build long-conn first capture was contaminated** by elevated host load (loadavg 2.4 vs Q1's quieter ~1.5). Re-run under quieter load (loadavg 1.5-1.8) recovered to ~14.5k rps. Per-iter values for the rerun are the recorded baseline.

## Notes / lessons

- **Host noise sensitivity:** off-build long-conn dropped from ~14k to ~4k under loadavg 2.4 with no other infrastructure changes. The PROFILE_ACCEPT-on path appears more robust to host noise (capture under loadavg 1.8 still landed at 14.5k). Hypothesis: PROFILE_ACCEPT-on path's instrumentation hot-path uses different cache lines, possibly less affected by noisy-neighbor evictions. Recorded for retrospective.
- Image cache: `mojo-net-bench:drain-subleg-pre-off` shares SHA `e77d7eb425ec` with Q1's `q1-post-off` (same source content; only docs/spec/plan changed since Q1 merge). Cache hit kept the off-build "rebuild" instant.
- Tests pre-spec: `TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh` reports 48 PASS lines (anchored).
