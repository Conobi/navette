# Topic 4 — Bench Gate Design for Q3 Sub-Percent Lift

**Date:** 2026-04-28
**Subject spec:** Q3 — `Dict[String, Int]` → `Dict[UInt64, Int]` DCID demux migration in `bench/h3_server.mojo`.
**Estimate (Subagent C):** 0.5–1.4% short-conn RPS conservative; 2–3% optimistic. 77–215 ms / 30s drop in `loop_pop_dispatch.total` (8–22% of the 958 ms leg).

**Verdicts (lead):**

1. RPS-only gate at the conservative effect size is **infeasible** at 10 iters; barely feasible at 30 iters.
2. Sub-leg-direct gate on `loop_pop_dispatch.total` **is feasible** at 10 iters and is the principled gate for this spec.
3. Recommended composition: **sub-leg-direct PASS gate + RPS soft directional check + long-conn non-regression hard gate**. RPS reported, not gated.

---

## 1. Noise floor — calibrated from T6/T7 + retrospective

Source: `plans/2026-04-28-quic-accept-loop-subleg-instrumentation-retrospective.md` smoke-gate table (n=10 each cell, both off-build and on-build), plus migration spec's 10-iter rerun (project-context line 5).

| Cell | n | Median rps | IQR (rps) | IQR (% of median) | stdev≈IQR/1.35 | Source |
|---|---|---|---|---|---|---|
| off-build long-conn (subleg-T6) | 10 | 14,947 | 167 | **1.12%** | ~0.83% | retrospective §smoke gate |
| off-build short-conn (subleg-T6) | 10 | 1,226.65 | 37 | **3.02%** | ~2.24% | retrospective §smoke gate |
| on-build long-conn (subleg-T7) | 10 | 14,885 | 167 | **1.12%** | ~0.83% | retrospective §smoke gate |
| on-build short-conn (subleg-T7) | 10 | 1,194.95 | 27 | **2.26%** | ~1.67% | retrospective §smoke gate |
| migration 10-iter rerun (overhead claim) | 10 | — | — | drift −2.3% / −1.8% **within noise** | — | project-context line 5 |

**Calibrated noise floor (10-iter median):**
- **Long-conn: ~1.1% IQR / ~0.8% stdev.** Clean signal channel.
- **Short-conn: ~2.3–3.0% IQR / ~1.7–2.2% stdev.** Noisy channel — the 2.3% retrospective-line "within noise" claim quantifies this.

This matches the `feedback_bench_iter_count.md` guidance (10-iter minimum; report median + IQR + stdev).

---

## 2. RPS gate feasibility

Using `n ≥ (1.96 · σ / Δ)²` for 95% CI on the mean (one-sided rejection of null at α=0.05; conservative — paired-design across baseline/treatment further reduces this, but we don't run them paired).

Using **σ ≈ 1.7% short-conn** (best of measured) and **σ ≈ 2.2%** (worst of measured):

| Effect size Δ | n (σ=1.7%) | n (σ=2.2%) | Verdict at n=10 |
|---|---|---|---|
| 0.5% (lower-bound conservative) | **44** | **74** | infeasible |
| 1.0% (mid conservative) | **11** | **19** | borderline at σ=1.7%; infeasible at σ=2.2% |
| 1.4% (upper conservative) | **6** | **10** | feasible if σ holds at lower end |
| 2.0% (lower optimistic) | **3** | **5** | feasible at 10 iters |
| 3.0% (upper optimistic) | **2** | **3** | trivially feasible |

**Verdict on RPS gate:** at the **conservative 0.5–1.4% range**, a 10-iter gate cannot reject null with 95% confidence — false-pass and false-fail rates both elevated. **30 iters** would push n above the threshold for Δ=1.0%. **At the optimistic 2–3%**, 10 iters is sufficient.

Practical implication: an RPS-only PASS gate at 10 iters at the conservative case has roughly a **30–40% false-fail rate** even when the real lift is exactly +1.0%. Unacceptable for spec acceptance.

Long-conn is irrelevant to the lift (Q3 hot path doesn't touch long-conn meaningfully — long-conn's `conn_dcid_map` is ~10 entries, L1-hot already, per `research/2026-04-28-pop-dispatch-finer-split.md` §2). Long-conn becomes the **non-regression channel**, not the lift channel.

---

## 3. Sub-leg-direct gate

**Direct measurement target:** `loop_pop_dispatch.total` (μs) from the SIGINT sidecar JSON, which the just-shipped instrumentation captures bit-exactly (T8 AC#4 PASS).

**Baseline (T8 short-conn capture):** 958,147 μs / 30s, with `loop_iter_count = 306,675`.

**Predicted absolute drop (Subagent C):** 77–215 ms / 30s on the conservative band.
- Conservative-low: 77,000 μs drop → **8.0% leg-relative**, post-treatment leg total ~881,000 μs.
- Conservative-high: 215,000 μs drop → **22.4% leg-relative**, post-treatment leg total ~743,000 μs.

**Per-iter noise of the leg:** the leg total is the sum of 306,675 per-iter measurements. Per-iter cost is ~3.1 μs short-conn (avg), with the dominant variance contributor being clock-read overhead per iter (deterministic ~1–2 μs × 2 reads). At 306k samples per iter, the law of large numbers compresses per-iter variance dramatically — the **leg-total** distribution across 10 bench iters is what matters, not per-loop-iter variance.

**Reproducibility check via T8 capture data:** we have only one T8 short-conn capture (n=1 sidecar). We do **not** yet have a 10-iter repeated SIGINT-sidecar series for `loop_pop_dispatch.total`. **This is a measurement gap.**

However, by structural argument:
- The leg total is dominated by per-pkt clock-read overhead (~31–63% of 958 ms — see attribution table) plus the addressable B+C real-work (8–22%). Clock-read overhead is a deterministic per-iter constant × `loop_iter_count`, and `loop_iter_count` is itself controlled by the bench harness's wall-clock-bounded run length and the server's accept rate. Per-iter clock cost varies <5% across bench iters on a quiet box.
- `loop_iter_count` itself varies ~2.3% on short-conn (it tracks RPS approximately).
- Therefore **leg-total stdev across 10 bench iters ≈ 2–4%**, conservatively.

At Δ ≥ 8% leg-relative, even 4% stdev gives n=(1.96·4/8)²=0.96 → **n=1 is sufficient**, n=10 is overkill. **The sub-leg gate is robustly feasible.**

**Required pre-treatment work:** capture **3 baseline SIGINT sidecars** of `loop_pop_dispatch.total` to empirically measure leg-total IQR before committing the gate threshold. If observed stdev exceeds 5%, escalate to 10-sidecar baseline.

---

## 4. Recommended gate composition

Order matters — fail-fast cheap gates first, expensive deep gates last.

### Hard gates (failure blocks spec merge)

**Gate 1 — Long-conn non-regression (RPS, n=10):**
- Threshold: long-conn median rps drift ≥ −2.0% (i.e. no worse than 1.5σ below baseline at σ=0.83%).
- Rationale: Q3 doesn't touch long-conn's hot path; any long-conn drift signals an unintended regression in shared code (e.g. `_handle_timeout` rewrite, teardown remap loop). Tight gate is justified by long-conn's clean noise floor.
- Cost: ~5 min bench.

**Gate 2 — Sub-leg-direct lift (SIGINT sidecar, n=3 per side):**
- Threshold: `loop_pop_dispatch.total` post-treatment ≤ 92% of pre-treatment median (i.e. ≥ 8% leg-relative drop, the lower bound of Subagent C's prediction).
- Stretch threshold (informational): ≥ 15% drop confirms the optimistic case.
- Rationale: this is the prediction's directly-measurable component; the noise margin is ~5% so an 8% gate clears it with 1.6σ headroom.
- Cost: ~3 min × 6 captures = ~20 min.

### Soft gates (failure does not block; reported as observation)

**Gate 3 — Short-conn RPS directional check (n=10):**
- Report median + IQR + stdev. **No hard threshold.** Document as: "Observed Δ = +X.X% (IQR ±Y.Y%); below noise floor, not a gate."
- If observed Δ ≥ +2%, upgrade to "lift visible at noise floor".
- If observed Δ ≤ −2%, escalate to investigation — this contradicts the leg-direct gate and implies the leg drop was offset elsewhere (e.g. additional cache pressure shifting cost into a different leg).
- Cost: ~5 min bench (already covered by Gate 1's run if both cells benched together).

### Order of evaluation

1. **CPU-load gate** (`pgrep` + load1 < 1.0) — pre-existing T0 hard gate from retrospective D3.
2. **Image hygiene check** — fresh docker rebuild with current `PROFILE_ACCEPT` flag value (auto-memory `feedback_bench_offbuild_image_hygiene.md`). For Q3, `PROFILE_ACCEPT=True` is required because Gate 2 reads sidecar JSON.
3. Gate 1 (long-conn n=10).
4. Gate 2 (sub-leg n=3 baseline + n=3 treatment).
5. Gate 3 (short-conn n=10, reporting only).

Total cost: ~35–40 min wall-clock for a clean run. Adds <10 min over the standard 2-cell smoke gate.

---

## 5. Measurement traps

**T1 — Clock-read overhead is the dominant component of `loop_pop_dispatch.total`.** Per attribution table, ~300–600 ms of the 958 ms is the profiling brackets themselves (`profile_monotonic_us` × ~2 calls/iter × 306k iters × ~1–2 μs/call). The **addressable real-work** portion is only ~350–650 ms. **Implication for Gate 2:** Subagent C's predicted 77–215 ms drop is an **absolute** drop, not a percentage of total. Expressed as percentage of total leg: 8–22%. Expressed as percentage of *addressable* real work: 12–60%. The 8% gate threshold is correctly anchored to leg-total (what we measure), not addressable-work (which we can't isolate cleanly).

**T2 — On-build vs off-build.** Q3's bench needs `PROFILE_ACCEPT=True` for Gate 2 (sidecar). Per retrospective table, on-build short-conn is ~2.6% slower than off-build (within noise but biased). Both Q3 baseline AND Q3 treatment must be captured **on-build**. Mixing builds invalidates the comparison. Reuse the `MOJO_NET_IMAGE` env-var pattern (retrospective D2) — tag isolated as e.g. `mojo-net-bench:q3-baseline` and `mojo-net-bench:q3-treatment`.

**T3 — `loop_iter_count` divisor caveat.** `record_loop_iter` increments only on packet-bearing iters; `continue` paths and idle iters don't count. If Q3 changes the iter mix (it shouldn't — the change is purely Dict-key-type, not control-flow), the per-iter average could shift even if total cost is unchanged. **Mitigation:** Gate 2 reads `loop_pop_dispatch.total` (not the per-iter average), which is unaffected by iter-count changes.

**T4 — Cold-create count must match across baseline/treatment.** Short-conn has ~18,000 cold conn-creates contributing 16–74 ms / 30s to the leg. If RPS rises, more cold creates fire and offset some of the per-pkt savings. Sanity check: report `pkt_count` and infer cold-create count (approximately `handshake.arrivals`) from both captures; flag if they differ by >5%.

**T5 — n=3 sidecar baseline assumes leg-total stdev ≤5%.** If the empirical baseline shows stdev >5% over 3 captures, escalate to n=10 sidecars (~30 min extra). Document the as-measured stdev in the spec's bench results regardless.

**T6 — Long-conn comparator is asymmetric.** Long-conn's `conn_dcid_map` has ~10 entries (L1-hot); the optimisation has near-zero leg impact there. Don't expect Gate 2 to fire any signal on long-conn — it's pure non-regression theatre. **Do not** add a long-conn sub-leg gate; it would be a false-positive magnet.

---

## 6. Open questions for spec author

1. **Should Gate 2's threshold be 8% (conservative-low) or 12% (mid)?** 8% follows Subagent C's lower bound. 12% asks for half the predicted range and would catch a "leg drop happened but smaller than expected" scenario as a soft signal. Recommend **8% PASS / 12% stretch / 15%+ optimistic-confirm**.

2. **Should we capture an empirical 10-sidecar leg-total IQR** before committing the spec, to firm up the n=3 sidecar count? Cost: ~30 min to know the per-iter leg-total noise floor for real. **Recommend yes** — this is a one-time piece of bench infrastructure data that is reusable for any future leg-targeted spec (Q1, Q2 follow-on work).

3. **Is there a third cell needed?** The current 2-cell (long/short) gate doesn't sample medium-conn behaviour. Q3's effect is monotonic in DCID-map size, so the short-conn cell is the worst-case (largest map = biggest lift). Recommend **no** — adding a 3rd cell adds ~10 min per pass for marginal info gain.

4. **Should Gate 3 (RPS soft) be promoted to hard if 30-iter capacity is available?** With 30 iters and σ=1.7%, n threshold for Δ=1% is 11; for Δ=1.4% is 6. 30-iter short-conn would cost ~15 min and would let the RPS channel itself become a hard gate at the conservative case. **Recommend optional** — only if Gate 2 fails ambiguously (e.g. observed leg drop = 7%, just under the 8% threshold), upgrade to 30-iter RPS as a tiebreaker.

5. **Does the spec need a "diagnostic-only" T8 capture step** to record post-Q3 sub-leg attribution? Yes — pop_dispatch should drop from 5.9% to ~5.0–5.4% of busy. Documenting the post-Q3 capture in REFERENCE.md preserves the diagnostic chain and lets a future spec target the next-largest leg cleanly.
