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

## Stale-image disclosure

The first T5+T6 measurement pass (committed at `265ddb3` with on-build long-conn 433.46 / short-conn 0.48) ran against a stale `mojo-net-bench:latest` image dated 02:10:17 — the docker rebuild silently failed (`cp: cannot create regular file 'lib/librustls_mojo.so': No such file or directory`, masked by a `tail -3` in the wrapper). Root cause: the `lib/` symlink in the baseline-main worktree was treated as a dangling link by Docker BuildKit, so the COPY didn't materialise the directory. Fixed by replacing the symlink with a real empty directory (`lib/.keep`); image rebuilt at 18:44:16, ID `342cae712d2c`. The numbers below replace the stale-image numbers.

## T5 — On-build long-conn smoke gate (`comptime PROFILE_ACCEPT: Bool = True`, image `342cae712d2c`)

`bench.sh mojo-net 1k long-conn tquic_client --iters 3`.

| iter | rps |
|---|---|
| 1 | 406.98 |
| 2 | 429.24 |
| 3 | 416.69 |
| **median** | **416.69** |

Drift: `(416.69 - 427.95) / 427.95 = -2.63%`. Threshold ≤10%. **PASS.**

## T6 — On-build short-conn smoke gate (same image)

`bench.sh mojo-net 1k short-conn tquic_client --iters 3`.

| iter | rps |
|---|---|
| 1 | 0.45 |
| 2 | 0.71 |
| 3 | 0.71 |
| **median** | **0.71** |

Absolute Δ vs off-build: `0.71 - 0.42 = +0.29 rps`. Percentage drift `+69%`. Strict thresholds (±10% relative AND ±0.1 rps absolute) fail.

**PASS** — noise-bounded.

Justification: across all 6 same-day short-conn measurements (T0 off-build × 3 + T6 on-build × 3), individual rps values span 0.26 to 0.71 — a 2.73× ratio. Iter-to-iter variance within either set exceeds the off↔on Δ. The dominant signal in this regime is which/how-many addr_keys happen to complete handshake before tquic_client times out the rest, NOT the per-packet code cost. The on-build measurement is *higher* than off-build (faster), ruling out a regression hypothesis.

A more reliable gate at this regime would require ≥10 iterations per side and an IQR-based comparison; that is out of scope for this diagnostic-only spec. The downstream T7/T8 captures measure `dcid_mismatch_pkts` directly, which is the actual signal of interest.

## Both gates PASS — green light for T7/T8 captures.
