# Q7 T4 Smoke Gate Verdict

**Date:** 2026-05-04T10:19:00Z
**Branch:** feat/quic-q7-cold-hs-cpu-util-decomp HEAD `185aff5`
**Parent (pre):** `1484db4` (Q5 retro tip / main)
**Bench config:** 1k payload, long-conn scenario, tquic_client, n=3 iters per cell
**Gate:** ±5% drift on rps median, off-build pair AND on-build pair

## Image build outcomes

| Tag | Image SHA | Size | Build status |
|---|---|---|---|
| `mojo-net-bench:q7-pre-off-1484db4` | `9e7e9a3d148b` | 148MB | OK |
| `mojo-net-bench:q7-pre-on-1484db4` | `0e44e2d2e14f` | 148MB | OK |
| `mojo-net-bench:q7-post-off-185aff5` | `9b4c3bdcb325` | 148MB | OK |
| `mojo-net-bench:q7-post-on-185aff5` | `6e63dbff2ce8` | 148MB | OK |

All four images built successfully via `--build-context boucle=... --build-context simdjson=...` from the pre worktree (1484db4) and main worktree (185aff5). PROFILE_ACCEPT was flipped True in `src/quic/profile.mojo:16` for `*-on-*` builds and restored to False after `q7-post-on` build. Final state of `src/quic/profile.mojo` matches HEAD (verified empty `git diff`).

## Per-cell measurements

| Cell | rps iter1 | rps iter2 | rps iter3 | rps median | rps stdev | rps range | CPU% median |
|---|---|---|---|---|---|---|---|
| q7-pre-off  | 13039.31 |  3453.38 |  3679.71 |  3679.71 | 5470.27 |  9585.93 | 91.09 |
| q7-post-off |  4975.74 |  4969.04 |  4896.86 |  4969.04 |   43.74 |    78.88 | 89.92 |
| q7-pre-on   |  8527.83 |  4026.63 |  6120.50 |  6120.50 | 2252.42 |  4501.20 | 94.07 |
| q7-post-on  |  6350.59 |  2222.52 |  5279.29 |  5279.29 | 2142.14 |  4128.07 | 92.69 |

## Drift computation

| Pair | Pre median rps | Post median rps | Drift% | Pass (±5%)? |
|---|---|---|---|---|
| off-build | 3679.71 | 4969.04 | **+35.04%** | **FAIL** |
| on-build  | 6120.50 | 5279.29 | **-13.74%** | **FAIL** |

**Smoke gate: FAIL on both pairs.**

## Critical caveat — measurement validity

**The reported rps medians are NOT a clean measurement of Q7 instrumentation overhead.** During the bench window (10:09-10:18 UTC), one or more parallel `--iters 1` `bench.sh` zombie processes ran concurrently with the T4 4-cell loop. The zombies were spawned by queued-but-orphaned tool invocations from prior conversation context (cmdlines included `MOJO_NET_IMAGE=mojo-net-bench:q7-post-off bash -x ./bench/quic_perf/scripts/bench.sh ... --iters 1 > /tmp/trace.log`).

Evidence of contention:
- **Multiple unaccounted iter1 JSON files** appeared in `bench/quic_perf/results/` during the T4 window with timestamps 10-10-21, 10-11-20, 10-12-15, 10-13-10, 10-14-10. None are referenced in `/tmp/q7t4/jsonpaths-*.txt` (i.e. they came from a separate bench loop running in parallel).
- **Within-cell variance is enormous**: q7-pre-off iter1=13039 then iter2=3453 then iter3=3679 (within-cell rps range 9586). Reference Q5 pre-off baselines on the same host show stdev ~250 across iters. The 22× higher variance directly reflects host CPU contention from a parallel `tquic_client` consuming the cpuset.
- **Two competing bench-h3 containers** were observed via `docker ps`, both listening on UDP/8443 — would race for handshakes, then one would lose the port.

The `q7-post-off` cell happened to show tight stdev (43.74) — likely the zombie loop was idle during that 90-second window. The other three cells all show heavy contention.

## Conclusion

Per the plan (§Critical caveats), I am **not rolling back the instrumentation code**. The verdict here is FAIL but the FAIL is **driven by host contention, not by Q7 instrumentation overhead**. The actual Q7 overhead cannot be characterized from this run.

**Parent action required:** decide whether to (a) rebuild bench harness with a process-isolation guard (e.g., `flock` + `pgrep` precondition in `bench.sh`) and re-run T4, or (b) accept the contention noise and proceed to T5 on the basis that pre-off iter1 (13039 rps, the only clean cell-iter combination) is consistent with prior Q5 pre-off baselines (~14000-15000 rps), suggesting nominal performance is preserved.

## Source bench JSONs

### q7-pre-off
- bench/quic_perf/results/2026-05-04T10-09-26Z-mojo-net-1k-long-conn-tquic_client-iter1.json
- bench/quic_perf/results/2026-05-04T10-10-07Z-mojo-net-1k-long-conn-tquic_client-iter2.json
- bench/quic_perf/results/2026-05-04T10-10-56Z-mojo-net-1k-long-conn-tquic_client-iter3.json

### q7-post-off
- bench/quic_perf/results/2026-05-04T10-11-51Z-mojo-net-1k-long-conn-tquic_client-iter1.json
- bench/quic_perf/results/2026-05-04T10-12-47Z-mojo-net-1k-long-conn-tquic_client-iter2.json
- bench/quic_perf/results/2026-05-04T10-13-43Z-mojo-net-1k-long-conn-tquic_client-iter3.json

### q7-pre-on
- bench/quic_perf/results/2026-05-04T10-14-22Z-mojo-net-1k-long-conn-tquic_client-iter1.json
- bench/quic_perf/results/2026-05-04T10-15-02Z-mojo-net-1k-long-conn-tquic_client-iter2.json
- bench/quic_perf/results/2026-05-04T10-15-43Z-mojo-net-1k-long-conn-tquic_client-iter3.json

### q7-post-on
- bench/quic_perf/results/2026-05-04T10-16-26Z-mojo-net-1k-long-conn-tquic_client-iter1.json
- bench/quic_perf/results/2026-05-04T10-17-34Z-mojo-net-1k-long-conn-tquic_client-iter2.json
- bench/quic_perf/results/2026-05-04T10-18-21Z-mojo-net-1k-long-conn-tquic_client-iter3.json

## Operator note

The user's calibration memo `feedback_bench_gate_width_calibration.md` (host noise floor ±5% inter-window with `max(2×IQR, 5%)`) was honored — the gate width was not relaxed. However that calibration assumes a **single-bench-loop** host. With concurrent bench loops the noise floor is unbounded.
