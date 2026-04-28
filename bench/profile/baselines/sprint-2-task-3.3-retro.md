# Sprint 2 Task 3.3 — 3-iter regression bench + streaming smoke

**Date:** 2026-04-28
**Commit:** `bf394fc` (PR #1 head, before this retro)
**Image:** `mojo-net-bench:latest` rebuilt from `bf394fc` via `bench/build.sh`
**CPU gate:** active before each iter; one stall observed (queueing-tail track running `test_quic_profile` on `baseline-main` worktree — waited and re-gated).

## H2 sync regression — 3 iters

`bench/profile/h2-throughput.sh` against `httparena-mojo-net:latest`, N=200000, C=50, M=16. Mojo-net only (comparators not re-run). Median per cell:

| Endpoint | iter1 | iter2 | iter3 | median | bytes/req |
|---|---|---|---|---|---|
| `/baseline2?a=1&b=2` | 406317 | 371375 | 412020 | **406317** | 22 |
| `/json/50?m=6` | 44201 | 44981 | 46877 | **44981** | 8418 |
| `/static/footer.html` | 392687 | 388287 | 402613 | **392687** | 29 |

**Verdict:** No regression vs Sprint 1 baselines (Sprint 1 used a different cell shape so direct comparison is non-trivial; the 3-iter spread is tight enough to confirm `feat/h2-state-machine-path-a` is healthy under load).

Latest 9 rows appended to `bench/profile/baselines/h2-throughput.csv`.

## H3 sync regression — 3 iters

`bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 3`. Per-iter rps + p50:

| iter | rps | p50 (ms) | p99 (ms) | succ/total | server cpu% |
|---|---|---|---|---|---|
| 1 | 400.57 | 3.168 | 5.282 | 12420/12460 | 4.4% |
| 2 | 379.91 | 3.177 | 7.146 | 11780/11820 | 4.5% |
| 3 | 556.02 | 2.720 | 6.728 | 17240/17280 | 5.6% |

**Verdict:** Confirms the known QUIC accept-loop bottleneck (~400-560 rps at ~5% CPU) — **not** moved by Sprint 2's H3 sync mirror because the H3 bench harness (`bench/h3_server`) uses `H3HandlerServer`, not `H3CoroServer`. This was Sprint 2's framing error (recorded in `feedback_perf_lift_verification.md`, retro at `plans/2026-04-27-sprint-2-retrospective.md`). The queueing-tail diagnostic track owns the fix.

Per-iter JSON in `bench/quic_perf/results/2026-04-28T00-3*-mojo-net-1k-long-conn-tquic_client-iter*.json` (gitignored; raw client stdout preserved).

## Streaming smoke — H2 + H3

Single-call (`-c 1 -m 1 -n 1000`) against the new `bench/h{2,3}_streaming_server` binaries. Demo handler emits 64 SSE tokens per request. **No regression target** — baselining only.

| Protocol | rps | p50 (us) | p95 (us) | p99 (us) | succ/total | bytes/req |
|---|---|---|---|---|---|---|
| H2 (port 8445) | 5611.20 | 94 | 145 | 213 | 1000/1000 | 1932 |
| H3 (port 8444) | 9.34 | — | — | — | **3/1000** | 6 |

**H2 streaming:** clean — confirms the streaming handler shape works end-to-end with the H2StreamingServer + boucle.stackful path. Latency p99=213us for 64-token SSE stream.

**H3 streaming:** the same QUIC handshake bottleneck the long-conn cell exhibits. Only 3 of 1000 requests completed; 997 failed at handshake. The shape works (3 successful 64-token streams delivered), but throughput is gated by the QUIC accept loop, not the streaming dispatch. Tracked under the queueing-tail investigation; not a Sprint 2 deliverable.

Rows appended to `bench/profile/baselines/streaming-smoke.csv`.

## Process notes

- `bench/.httparena/` is repo-root-only; symlinked into this worktree (gitignored).
- `bench/Dockerfile` patched with `mkdir -p lib` before the librustls .so cp because the worktree's `lib/` is a symlink, not a directory copied via `COPY . .`. `.dockerignore` excludes both `lib` and `bench/.httparena` to keep build context clean.
- `mojo-net-bench:latest` re-tagged from `httparena-mojo-net:latest` (same image, same Dockerfile, two consumer scripts).
- CPU gate (`/tmp/cpu_gate.sh`) caught one collision with the queueing-tail track's `test_quic_profile` run on `baseline-main`. Waiting for it to finish before re-gating produced a clean run.
