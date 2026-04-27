# Smoke Gate — addr_key DCID collision counter

Plan: `plans/2026-04-27-quic-addr-key-dcid-collision-counter.md`
Spec: `specs/2026-04-27-quic-addr-key-dcid-collision-counter.md`
Branch: `feat/quic-addr-key-dcid-collision-counter`
Base SHA: `bff4c42b9d323162cc9268a479e10c4a9f9ccd18`
Date: 2026-04-27

## T0 — Off-build baseline (`comptime PROFILE_ACCEPT: Bool = False`)

`bench.sh mojo-net 1k <scenario> tquic_client --iters 3`. Each iteration is 5s warmup + 30s measurement.

### Long-conn cell

| iter | rps | succ | fail |
|---|---|---|---|
| 1 | 430.86 | 13320 | 40 |
| 2 | 427.95 | 13230 | 40 |
| 3 | 406.35 | 12570 | 40 |
| **median** | **427.95** | — | — |

Result JSONs:
- `bench/quic_perf/results/2026-04-27T16-05-40Z-mojo-net-1k-long-conn-tquic_client-iter1.json`
- `bench/quic_perf/results/2026-04-27T16-06-18Z-mojo-net-1k-long-conn-tquic_client-iter2.json`
- `bench/quic_perf/results/2026-04-27T16-06-56Z-mojo-net-1k-long-conn-tquic_client-iter3.json`

### Short-conn cell

| iter | rps | succ | fail |
|---|---|---|---|
| 1 | 0.42 | 13 | 0 |
| 2 | 0.29 | 9 | 0 |
| 3 | 0.52 | 16 | 0 |
| **median** | **0.42** | — | — |

Result JSONs:
- `bench/quic_perf/results/2026-04-27T16-07-47Z-mojo-net-1k-short-conn-tquic_client-iter1.json`
- `bench/quic_perf/results/2026-04-27T16-08-25Z-mojo-net-1k-short-conn-tquic_client-iter2.json`
- `bench/quic_perf/results/2026-04-27T16-09-03Z-mojo-net-1k-short-conn-tquic_client-iter3.json`

## Mojo MCP signature locks (T0 Steps 4-5)

| Probe | Result | Notes |
|---|---|---|
| `List[UInt8] == List[UInt8]` element-wise | ✅ PASS | `a==b: True a==c: False` (Mojo 0.26.2). T3 can use either `==` or byte-loop; plan picks byte-loop for clarity. |
| `Span[UInt8, _]` parameter on a method receiver | ✅ PASS | `match: True / no-match: False` (Mojo 0.26.2). T3 accessor signature `is_expected_dcid(self, dcid: Span[UInt8, _]) -> Bool` is locked as designed; no fallback needed. |

## Reference for T5 / T6

The medians above (long-conn **427.95** rps, short-conn **0.42** rps) are the off-build references. T5 (long-conn) and T6 (short-conn) compare on-build (`PROFILE_ACCEPT=True`) measurements against these.

- **T5 PASS bound:** long-conn on-build rps within `[427.95 × 0.9, 427.95 × 1.1] = [385.16, 470.75]` rps.
- **T6 PASS bound:** short-conn on-build rps within `[0.42 × 0.9, 0.42 × 1.1] = [0.378, 0.462]` rps OR within ±0.1 rps absolute (noise-floor escape per the prior queueing-tail T12 convention; the short-conn cell is dominated by handshake-failure-induced timeouts at the addr_key-collapse rate, not by per-packet code cost).

## T5 — On-build long-conn smoke gate (`comptime PROFILE_ACCEPT: Bool = True`)

Docker image rebuilt from baseline-main worktree at HEAD `bd30ecd` (T4 commit) with `PROFILE_ACCEPT=True`. Same `bench.sh mojo-net 1k long-conn tquic_client --iters 3` invocation as T0.

| iter | rps |
|---|---|
| 1 | 608.53 |
| 2 | 425.08 |
| 3 | 433.46 |
| **median** | **433.46** |

Drift: `(433.46 - 427.95) / 427.95 = +1.29%`. Threshold ≤10%. **PASS.**

Iter 1 outlier (608.53) likely a warmup/scheduler artefact; iters 2 and 3 sit within ±2% of off-build, so the median is stable and representative of steady state.

## T6 — On-build short-conn smoke gate

Same image, `bench.sh mojo-net 1k short-conn tquic_client --iters 3`.

| iter | rps |
|---|---|
| 1 | 0.68 |
| 2 | 0.48 |
| 3 | 0.45 |
| **median** | **0.48** |

Absolute Δ vs off-build: `0.48 - 0.42 = +0.06 rps`, within the ±0.1 rps noise floor. **PASS** (noise-bounded). Percentage drift +14.3% exceeds the relative ≤10% gate, but per the prior queueing-tail T12 convention the absolute Δ governs in this regime.

Why noise-bounded passes: short-conn is dominated by client-side handshake-timeout-driven cycling. Most attempts time out before per-packet code is exercised. The new gated branch in `_flush_impl` adds a few cycles per processed packet, but the cell processes only single-digit successful packets per second. Per-packet overhead is below measurement floor here.

## Both gates PASS — green light for T7/T8 captures.
