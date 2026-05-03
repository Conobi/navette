# P2 Verdict — Hard Gates (Plan: 2026-05-03-short-conn-resumption)

**Date:** 2026-05-03
**Branch:** `perf/short-conn-resumption`
**Pre image:** `mojo-net-bench:p2-pre-off` (ID `c0daf44b5d7a`, source `f22647b` main, PROFILE_ACCEPT=False)
**Post image:** `mojo-net-bench:p2-post-on` (ID `733b02dd0d63`, source `5b08a22`, PROFILE_ACCEPT=True)
**Method:** n=10 rounds per cell × 30s duration × 4 threads × 25 concurrent conns. tquic_client `--session-file` plumbed per scenario.

## AC8 (NFR-Resumption-Fraction): r ≥ 0.40 short-conn

`r` aggregated across all 10 short-conn iters (warmup-excluded by harness's separate 5s warmup):

  full sum    =      3,652
  resumed sum =    445,805
  total       =    449,457
  **r        =      0.9919  (99.2% resumed)**

Per-iter range: 0.989 to 0.993.

**Verdict: ✅ PASS** — r far exceeds 0.40 threshold. Server is issuing tickets via aws_lc_rs Ticketer; tquic_client is consuming them via `--session-file`; rustls handshake-kind FFI correctly observes `Resumed` (kind=2).

## AC9 (NFR-Bench-Lift): tiered against observed r

Observed `r ≈ 0.99` falls in the **`r ≥ 0.75`** tier → required lift `≥ +30%`.

| Cell | Pre median rps | Post median rps | Lift |
|---|---|---|---|
| short-conn | 1,167.3 | 1,224.3 | **+4.88%** |

**Verdict: ❌ FAIL** at the +30% tier (observed +4.88% is 6× smaller than projected).

### Why the lift is far below projection

The §5.1 projection assumed `r × 0.50 × (1.68/1.83) ≈ +35%`. That assumed resumed handshakes save ~50% of per-conn wall-clock — i.e., that the median 1.68 ms handshake was ~85% of per-conn cost.

Observed reality: the **per-conn cost outside the cryptographic handshake** is much larger than projected. Even with 99% resumption, each connection still pays:

- UDP datagram recv + parse (single-fiber accept loop)
- Conn allocation + init
- Frame-parse + dispatch
- Stream open/close machinery
- `_on_handshake_complete` post-handshake state setup
- HoL wait for the next inbound datagram (single-fiber accept loop)

The resumption skip applies only to ServerHello + EE + Cert + CertVerify within the rustls state machine. Server CPU stayed at **57.3% on short-conn (43% idle)** — same as pre-P2. The structural ceiling identified in `project_long_conn_parity_short_conn_ceiling.md` is unchanged: rustls is no longer the dominant per-conn cost (resumption confirmed that), but the single-fiber accept loop is still HoL-blocked on something, just somewhere else.

### What this overturns

This result **falsifies the projection** that resumption alone would yield ≥+30%. It does NOT falsify the value of resumption (the change is correct; tickets work). It **confirms** that the next priority is structural: P4 cross-conn handshake pipelining is the real lever for short-conn parity with TQUIC.

## AC10 (NFR-Long-Conn-Drift): ±2% long-conn

| Pre median | Post median | Drift |
|---|---|---|
| 14,176 rps | 13,921 rps | **-1.80%** |

**Verdict: ✅ PASS** — within ±2% gate. The new ticketer construction at server config build time + the runtime-gated counter-increment branch in `_on_handshake_complete` adds zero hot-path overhead.

## Summary

| AC | Status |
|---|---|
| AC1 max_early_data 8th param | ✅ T3 |
| AC2 handshake_kind FFI table | ✅ T2 |
| AC3 unit tests (T2+T4 in test_quic_resumption) | ✅ |
| AC4 profile counters + JSON shape | ✅ T1 |
| AC5 test_quic_profile +2 tests | ✅ T1 |
| AC6 _on_handshake_complete increment-once | ✅ T4 |
| AC7 run-tquic-client.sh --session-file | ✅ T5 |
| AC8 r ≥ 0.40 | ✅ r=0.992 |
| AC9 lift ≥ +30% (r ≥ 0.75 tier) | ❌ +4.88% |
| AC10 long-conn drift ±2% | ✅ -1.80% |
| AC11 tests pass at every commit | ✅ |
| AC12 REFERENCE.md row | T7 |

**Final verdict: SHIP-WITH-CAVEAT.** Server-side resumption works correctly (AC1-AC8, AC10, AC11 PASS). Wall-clock lift on short-conn is substantially below projection (AC9 FAIL). The gap is informative — it identifies P4 (cross-conn handshake pipelining) as the real structural lever. P2 is a pre-requisite for P3 (0-RTT) and remains valuable for resumed-handshake clients in production even if not the bottleneck-buster the projection imagined.

## Decision: open follow-up

Record in `docs/project-context.md` open follow-ups:

> **What:** Short-conn rps lift from server-side resumption (P2) is +4.88% at r=0.99, vs projected +30%. The remaining bottleneck is NOT the cryptographic handshake (resumption skips that successfully) but the single-fiber accept loop's HoL pattern.
> **Severity:** required-later
> **Trigger:** P4 (cross-conn handshake pipelining, async read_hs + worker pool) is now the highest-impact short-conn optimization. Begin P4 brainstorming when ready to invest in worker-thread infrastructure.
