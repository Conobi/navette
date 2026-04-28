# T6/T7 Smoke Gate — sub-leg instrumentation

Plan: `plans/2026-04-28-quic-accept-loop-subleg-instrumentation.md`
Branch: `feat/quic-accept-loop-subleg-instrumentation`
Date: 2026-04-28

## T6 — Off-build (`comptime PROFILE_ACCEPT: Bool = False`)

Image: `mojo-net-bench:subleg-T6` (sha `e40a46bdc896`, built 2026-04-28 02:43:35 from post-T5 source state).

**Tag isolation rationale:** the default `mojo-net-bench:latest` tag was overwritten mid-bench by a parallel HttpArena workflow in another worktree (`feat-h2-state-machine-path-a`) producing pre-migration code. We retagged as `:subleg-T6` and added `MOJO_NET_IMAGE` env-var override in `bench/quic_perf/scripts/start-server.sh` (backwards-compatible default).

### Long-conn cell (10 iters)

| iter | rps |
|---|---|
| 1 | 14631.46 |
| 2 | 14951.29 |
| 3 | 14928.39 |
| 4 | 15051.45 |
| 5 | 14930.32 |
| 6 | 14942.74 |
| 7 | 14721.46 |
| 8 | 15041.12 |
| 9 | 14993.07 |
| 10 | 15061.12 |

**Median: 14,947.01 rps** | mean=14,925 | stdev=141.92 | IQR=167.05

**Drift vs post-migration off-build baseline (14,436 rps): +3.54%**  (gate: ±10%)

Verdict: **PASS**.

### Short-conn cell (10 iters)

| iter | rps |
|---|---|
| 1 | 1205.49 |
| 2 | 1249.47 |
| 3 | 1228.30 |
| 4 | 1238.48 |
| 5 | 1202.51 |
| 6 | 1263.06 |
| 7 | 1218.64 |
| 8 | 1245.64 |
| 9 | 1210.32 |
| 10 | 1225.01 |

**Median: 1,226.65 rps** | mean=1,228.69 | stdev=20.20 | IQR=37.49

**Drift vs post-migration off-build baseline (1,208 rps): +1.54%**  (gate: ±10%)

Verdict: **PASS**.

### T6 verdict: **PASS** (both cells)

The tag-isolated image (`mojo-net-bench:subleg-T6`, sha `e40a46bdc896`) reflects the post-T5 source state and reproduces the post-migration off-build baselines within ±5%. The previous T6 attempt with `mojo-net-bench:latest` was contaminated by a parallel workflow's image overwrite.

## T7 — On-build (`comptime PROFILE_ACCEPT: Bool = True`)

Pending.
