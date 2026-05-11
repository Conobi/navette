# P2 Resumption Verdict — Production-Realism vs Lib-Bound Decomposition

> **Source spec:** `specs/2026-05-03-short-conn-resumption.md` (tail-task: §AC7/AC8/AC9 cold-vs-resumption side-by-side).
> **Goal:** Quantify how much of the 0.489× short-conn gap vs TQUIC is *production-realism artifact* (no client ticket cache) vs *real lib-bound CPU work* (rustls + FFI + Mojo per-conn cost).
> **Date:** 2026-05-04 (verdict authoring); data sourced from 2026-05-03 P2 capture and 2026-05-04 apples-to-apples capture.

---

## Methodological note (data provenance)

This verdict folds two paired-cell captures into one decomposition. **No fresh side-by-side run was added** because the host was continuously contended by another `h3_server`/`tquic_client` benchmark workflow during the 22:39-23:00+ window — per `feedback_concurrent_mojo_sessions_perturb_bench.md` the policy is *pause and wait, never contend*. The existing captures already provide the two anchors the spec needs:

| Capture | Date | Image | Cell | Provides |
|---|---|---|---|---|
| `p2-pre-off` / `p2-post-on` | 2026-05-03 16:43 | `mojo-net-bench:p2-{pre-off,post-on}` (built `f22647b` / `5b08a22`) | cold (pre, no server ticketer) → resumption (post, server ticketer + `SESSION_FILE`) | **In-image lift** of resumption vs no-resumption on identical hardware/host. Sidecar `r` = 0.9919. |
| `2026-05-04-apples-to-apples-cold-handshake` | 2026-05-04 08:27-08:42 | `mojo-net-bench:latest` (built post-q5, pre-q9) + `tquic-bench:latest` | cold (apples-to-apples, `SESSION_FILE` commented out) | **Published-comparison anchor**: mojo-net 1391.3 rps vs TQUIC 2846.3 rps = 0.489×. |

The new `bench/quic_perf/configs/short-conn-resumption.env` config is shipped (sets `SESSION_FILE=/tmp/tquic-session-shortconn-resume.bin`) so future runs on a quiet host can reproduce side-by-side **on a single image** in a single contiguous capture window. AC7 (config plumbing) is satisfied.

---

## Cell results

### Cold cell (apples-to-apples, `SESSION_FILE` unset → 100% Full handshakes)

Per `bench/quic_perf/results/baselines/2026-05-04-apples-to-apples-cold-handshake.md` (08:27Z-08:33Z, n=10, image post-q5).

| Metric | mojo-net cold | TQUIC cold | ratio mojo/tquic |
|---|---|---|---|
| **rps median** | **1391.3** | **2846.3** | **0.489×** |
| rps IQR | [1339.7, 1440.5] (12.4% of median) | [2608.8, 2880.7] (10.1% of median) | — |
| rps stdev | 113.4 | 143.5 | — |
| Server CPU% median | 52.3 | 91.8 | 0.570 |

This is the **published-comparison anchor**: TQUIC's bench defaults (`--session-file=None`, `--enable-early-data=false`) match this configuration, so the 0.489× ratio is the apples-to-apples gap.

### Resumption cell (`SESSION_FILE` set → ~99% Resumed handshakes)

Per `bench/quic_perf/results/baselines/p2-post-rps.csv` + `p2-post-on/short/INSTRUMENTATION-*.json` (2026-05-03 16:43Z, n=10, image `p2-post-on`).

| Metric | mojo-net resumption |
|---|---|
| **rps median** | **1224.3** |
| rps IQR | [1191.2, 1262.5] (5.8% of median) |
| rps stdev | 93.7 |
| Server CPU% median | 57.4 |
| **Sidecar r = resumed/(full+resumed)** | **0.9919** (full=3,652; resumed=445,805 across 10 iters) |
| Sidecar r per-iter range | 0.989 – 0.993 |

Tickets are issued (server-side aws_lc_rs `Ticketer::new()` at `crates/librustls-mojo/src/quic_hs.rs:146`), `tquic_client --session-file` consumes them, and the rustls `handshake_kind == 2` (`Resumed`) is observed at the server post-handshake edge.

### Same-image lift (in-image cold→resumption, P2 capture)

Per the original P2 verdict (`p2-verdict.md`), captured side-by-side on `mojo-net-bench:p2-{pre-off,post-on}` (image differs *only* by the server-side ticketer commit; harness, host, and source path are identical):

| Capture | Median rps |
|---|---|
| p2-pre-off (no server ticketer; cold) | 1167.3 |
| p2-post-on (server ticketer + client `SESSION_FILE`; r=0.99) | 1224.3 |
| **Lift = (1224.3 / 1167.3) − 1** | **+4.88%** |

This is the load-bearing same-image number. It is **not** affected by image-generation drift between the apples-to-apples cold (1391.3 on post-q5 image) and the resumption capture (1224.3 on pre-q5 image).

---

## AC8 — `r ≥ 0.40` warmup-excluded

| AC8 | Observed | Threshold | Verdict |
|---|---|---|---|
| `r = resumed/(full+resumed)` aggregated across 10 iters, warmup-excluded by harness's separate 5-s warmup phase | **0.9919** | ≥ 0.40 | **PASS** (2.5× threshold) |

Harness is *not* the limiter. Server is issuing tickets; client is consuming them. Per-iter `r` range 0.989-0.993 is tight.

## AC9 — Tiered rps lift gate (NFR-Bench-Lift §5.1)

Observed `r ≈ 0.99` falls in the **`r ≥ 0.75`** tier → required lift `≥ +30%`.

| AC9 | Observed | Threshold | Verdict |
|---|---|---|---|
| Same-image lift (cold→resumption) | **+4.88%** | ≥ +30% (r ≥ 0.75 tier) | **FAIL** (6× short of projection) |

The §5.1 projection assumed `r × 0.50 × (1.68/1.83) ≈ +35%`. This required the per-conn cost outside the cryptographic handshake to be small (≤ 15% of wall-clock). It is not.

---

## Production-realism vs lib-bound decomposition

The two cells together let us decompose the 2.04× rps gap into three slices:

```
TQUIC_cold_rps / mojo_cold_rps           = 2846.3 / 1391.3 = 2.045×
TQUIC_cold_rps / mojo_resumption_rps     = 2846.3 / 1224.3 = 2.325×    (using p2-era resumption)
mojo_cold_rps / mojo_resumption_rps      = 1391.3 / 1224.3 = 1.136×    (image-drift; NOT same-image)
mojo_post / mojo_pre (same image, P2)    = 1224.3 / 1167.3 = 1.049×    (same-image resumption lift)
```

**The +4.88% same-image resumption lift is the upper bound on the "production-realism artifact" share of the gap.**

| Frame | Gap share |
|---|---|
| Production-realism (cold→resumption) | **~5%** of gap (on the post-q5 image, projects to ~+68 rps out of the ~1455 rps shortfall) |
| CPU-utilization gap (mojo at 52% vs TQUIC at 92%) | **~73%** of gap (per `2026-05-04-apples-to-apples-cold-handshake.md` decomposition) |
| Per-CPU-% efficiency gap (rustls+FFI+Mojo vs boringssl+TQUIC) | **~16%** of gap |
| (interaction term) | balance |

**Interpretation:** the 0.489× short-conn ratio is **NOT** primarily a production-realism artifact. Even if all real-world clients carried hot ticket caches and exercised `r=0.99` server-side resumption, mojo-net would close at most ~5% of the 2.04× gap — landing somewhere around **0.51× TQUIC short-conn rps**, not 0.85× or higher.

The dominant slice (73%) is CPU-utilization: mojo-net leaves ~48% of one core on the table while client load is offered. This is the structural lever — the single-fiber accept loop's HoL pattern (`project_long_conn_parity_short_conn_ceiling.md`), not the rustls handshake state machine. Q4-Q9 already established that the rustls per-call cost is `lib-bound` (Q6 verdict: 99.5% rustls state machine; Q9 verdict: `DIFFUSE-CONFIRMS-LIB-BOUND`).

## What this means for closing the production short-conn gap

Resumption is correct, ships, and provides modest wall-clock latency benefit to clients (skipping ServerHello+EE+Cert+CertVerify means fewer round trips). It is **prerequisite work** for P3 (0-RTT) and matches reference servers (TQUIC, quiche, h2o, nginx-quic). However, **production-realism (resumption-on-by-default) does NOT close the short-conn gap to TQUIC**. The +4.88% same-image lift caps the achievable closure from this lever alone.

The real production short-conn gap closure requires structural work on the accept loop: cross-conn handshake pipelining (P4 — `async read_hs` + worker pool), or multi-socket / multi-thread accept (currently retracted per `project_long_conn_parity_short_conn_ceiling.md` because TQUIC is also single-thread/single-socket — but the *scheduler-underfill* hypothesis from Q7 remains). Both are higher-impact than any further crypto-handshake-cost optimization (capped at 16% of the gap by the apples-to-apples decomposition).

## Acceptance summary

| AC | Status | Note |
|---|---|---|
| AC7 plumbed `--session-file` | PASS | `run-tquic-client.sh:25-32` already plumbs; `short-conn-resumption.env` shipped this verdict cell. |
| AC8 r ≥ 0.40 | PASS | r = 0.9919 on p2-post-on capture. |
| AC9 lift ≥ +30% (r ≥ 0.75 tier) | FAIL | +4.88% same-image (P2 capture). Falsifies the §5.1 projection assumption that handshake cost dominates wall-clock. Confirms lib-bound rustls cost is small fraction of per-conn cost. |

## Follow-ups

- A fresh side-by-side n=10 run on a single image (current main rebuild + PROFILE_ACCEPT=True for sidecar emission) using `short-conn-resumption.env` is recommended once the host is quiet, to refresh the same-image lift number on the post-q9 codebase. The new config makes this a one-line invocation: `bench.sh mojo-net 1k short-conn-resumption tquic_client --iters 10`.
- The image used for the resumption capture (`p2-post-on`, source `5b08a22`) predates Q6/Q7/Q8/Q9 measurement work. The Q8 Phase 2 +22.8% short-conn rps lift (per `q8p2-post-on-short` retrospective) raises the post-q8 resumption rps absolute level, but the **lift ratio** (cold→resumption on the same image) is the load-bearing comparison and should remain in the same +5% range pending re-capture.

## Cross-references

- Spec: `specs/2026-05-03-short-conn-resumption.md`
- Predecessor verdict: `bench/quic_perf/results/baselines/p2-verdict.md`
- Apples-to-apples baseline: `bench/quic_perf/results/baselines/2026-05-04-apples-to-apples-cold-handshake.md`
- Long-conn parity context: `project_long_conn_parity_short_conn_ceiling.md`
- Lib-bound confirmation chain: Q6 verdict (`docs/q6-verdict.md` equivalent), Q9 verdict (commit `8218017`)
- New cell config: `bench/quic_perf/configs/short-conn-resumption.env`
