# Q1 H3 phase-leg instrumentation — Retrospective

**Spec:** `specs/2026-04-29-quic-h3-phase-leg-instrumentation.md`
**Plan:** `plans/2026-04-29-quic-h3-phase-leg-instrumentation.md`
**Branch:** `feat/quic-h3-phase-leg-instrumentation` off main `978389b`
**Date completed:** 2026-04-29
**Total commits:** 9 (T0 `b5866f0` → T1 `6d31f73` → T2 `6df600d` → T2-fix `11daf11` → T3 `064605a` → T4 `85024ba` → T5+T6 `45be7e2` → T7 `f8b5fb1` → retrospective)
**Status:** ✅ Closed; all 9 ACs PASS without escalation; tests 72/72 src + 48 filtered.

---

## Built vs. planned

| Plan task | Status | Commit | Time | Notes |
|---|---|---|---|---|
| T0 — Branch + pre-spec test count anchor + pre-migration baselines | ✅ done | `b5866f0` | ~50 min | All 12 sub-steps; pre-on long-conn `unaccounted_pct` baseline 93.4% (higher than sub-leg pass's 82% — suggests Q3 hot-path tightening shifted busy-time mix). |
| T1 — profile.mojo: 3 fields + 3 record methods + JSON/text emit + budget closure refresh (TDD, 4 tests) | ✅ done | `6d31f73` | ~9 min subagent | Per-task review ✅ CLEAN. Implementer added missing `assert_equal_int` import (matches `tests/test_request_response.mojo:6` precedent). |
| T2 — h3_handler_server: profile_ptr field + ctor threading + 2 brackets | ⚠️ done with fix-up | `6df600d` + `11daf11` | ~9 min subagent + ~2 min fix | **Plan template bug:** I baked `profile_monotonic_us` into the spec/plan, but the actual stdlib symbol is `monotonic_us` (the alias `as profile_monotonic_us` only exists in `bench/h3_server.mojo:27`, NOT in `src/`). Per-task review caught it; fix-up commit renamed to `monotonic_us`. |
| T3 — h3/connection bracket + Shape B post-construction setter (also enables T2's deferred line) | ✅ done | `064605a` | ~8 min subagent | Per-task review ✅ CLEAN. Shape B threading verified at 18 H3Connection.server/.client call sites — none required edits. |
| T4 — bench/h3_server cold-create + 2 invariant tests (TDD) | ✅ done | `85024ba` | ~9 min subagent | Per-task review ✅ CLEAN. T1's budget-closure refresh was already correct, so `test_budget_closure_subtracts_h3_legs` passed on first attempt. |
| T5 — Smoke gate (Hard Gate 2 + 3 + 4) | ✅ done | (folded into `45be7e2`) | ~30 min | All 4 RPS gates PASS: on-build +2.54%/+2.64%; off-build +5.50%/+3.77%. Variance tightened across the board (CVs 3-8% → 0.5-2%). |
| T6 — SIGINT sidecars + Hard Gates 1/5/6 + dominant-phase identification | ✅ done | `45be7e2` | ~10 min | **Diagnostic deliverable MET.** Long-conn `unaccounted_pct` 93.4%→9.82% (target <15%; far below). Subagent B's prediction OVERTURNED — see "Surprises". |
| T7 — REFERENCE.md + flag revert + project-context advance + final review | ✅ done | `f8b5fb1` | ~12 min | Final cross-cutting review ✅ CLEAN. |

**Total wall-clock:** ~150 min (vs plan estimate ~3 hours; bench captures faster than budgeted, no escalation needed).

## Key results

### Diagnostic deliverable — long-conn `unaccounted_pct` reduction

| | Pre (T0 baseline) | Post (T6 sidecars) | Delta |
|---|---|---|---|
| Median `unaccounted_pct` | 93.4% | **9.82%** | **−83.6pp** |

Spec threshold: <15%. Soft-floor zone: 15-25% (would have been SHIPPED-with-caveat). **Observed 9.82% — well below threshold and outside the soft floor entirely.** No escalation needed.

The 3 H3 legs collectively absorb ~89% of the previous-pass unaccounted bucket on long-conn. Residual 9.82% ε is the un-instrumented leftovers (likely `_quic.timeout` early-returns, `consumed_bufs.append`, etc. — Subagent B's honourable-mentions list).

### Dominant phase named — PREDICTION OVERTURNED 🎯

| Leg | Subagent B prediction | Observed median (μs / 30s long-conn) | vs prediction |
|---|---|---|---|
| **`quic_post_recv_us`** | 5–8s (Rank 2) | **19,355,006 ≈ 19.4s** | **+11s above prediction; LARGEST** |
| `h3_drain_resp_us` | 12–16s (Rank 1) | 4,458,769 ≈ 4.5s | **−8s below prediction; SECOND** |
| `h3_dispatch_us` | 1–3s (Rank 3) | 1,064,250 ≈ 1.1s | within prediction |

**Interpretation:** Subagent B's per-call cost analysis was probably right but the call-frequency was severely underestimated for `_drain_stream` (which lives inside `quic_post_recv_us` along with `_quic.timeout` and the poll-loop event-pump). At long-conn 14k rps × multiple STREAM_READABLE events per request × per-event H3 frame parse + QPACK decode, this dominates over the response-build path by ~4×.

**This is the kind of finding the spec's diagnostic-only design was meant to surface.** The earlier sub-leg pass had a similar overturn (`ffi_read_hs` 93.3% vs predicted `write_hs` ≥60%) — both passes show that intuition-based per-call cost analysis is unreliable at this scale; only direct measurement names the dominant phase correctly.

### RPS gates — all PASS, all positive

| Gate | Pre median | Post median | Drift | CV pre→post |
|---|---|---|---|---|
| On-build long-conn | 14,173 rps | 14,532 rps | **+2.54%** | 3.68% → 0.47% |
| On-build short-conn | 1,174 rps | 1,205 rps | **+2.64%** | 3.19% → 1.98% |
| Off-build long-conn | 13,858 rps | 14,620 rps | **+5.50%** | 3.91% → 0.93% |
| Off-build short-conn | 1,180 rps | 1,225 rps | **+3.77%** | 8.05% → 1.18% |

All 4 drifts are positive even though Q1 is diagnostic-only (no perf change predicted). The positive numbers are host noise, not signal — but the consistency + the variance tightening is striking. Recorded as a recurring observation (3rd pass: Q3 had it, Q1 has it stronger).

## Deviations from plan

### D1 — Plan template bug: `profile_monotonic_us` typo in spec + plan

**What happened:** I wrote `profile_monotonic_us` in both the spec (§5.2 + §5.3) and plan (T2 + T3 code snippets). The actual symbol in `src/quic/profile.mojo:20` is `monotonic_us`. Only `bench/h3_server.mojo:27` aliases it (`as profile_monotonic_us`) because it imports a different `monotonic_us` from `interop.udp` first — that aliasing is bench-local and doesn't apply to `src/h3/`.

**Detection:** T2's combined reviewer (a fresh subagent reading the diff) caught it via `grep`-confirming the symbol doesn't exist in `src/quic/profile.mojo`. Marked Critical.

**Fix:** Single sed-rename + 4 call sites in T2's fix-up commit `11daf11`.

**Lesson:** Spec/plan code snippets that name external symbols MUST be grep-validated against the actual codebase before locking. **Specifically:** if a plan says "import X from src.Y", run `grep -n "fn X\|def X\|var X" src/Y/*.mojo` to confirm the symbol exists. The plan's "T3 implementer must use `monotonic_us` NOT `profile_monotonic_us`" warning sentence I added to T3 (because I had noticed by then) was a band-aid; the underlying spec/plan should have been correct from the start. Worth adding to the writing-plans skill template: "Before saving the plan: grep every external-symbol citation against the source-of-truth file."

### D2 — Pre-baseline `unaccounted_pct` higher than expected (93.4% vs predicted 82%)

**What happened:** Subagent B's report (from sub-leg pass) cited `unaccounted_pct` of 82% for long-conn. T0 baseline came in at 93.4% — 11.4pp higher.

**Likely cause:** Q3 (Dict[UInt64,Int] DCID demux) tightened the per-pkt + loop-phases bucket (`loop_pop_dispatch.total` dropped 15.67% in Q3). With those buckets smaller, the unaccounted ε's *share of busy* grew correspondingly, even though the absolute work in the H3 path didn't change. Algebraically: smaller denominator-shrinking buckets → larger ε / busy ratio.

**Implication:** Hard Gate 1's <15% target was set against the 82% figure. Post-Q3 the equivalent target should arguably have been <12% or so to maintain the same "fraction of pre absorbed by named legs". Observed 9.82% would still pass either threshold.

**No corrective action needed.** Recording the algebraic interaction: future passes that close ε will see ε grow temporarily before the new pass closes it, because each bucket-shrinking pass increases ε's relative share.

### D3 — Subagent B's prediction inversion (Rank 1 ↔ Rank 2)

**What happened:** Subagent B predicted `h3_drain_resp` as the largest leg (12-16s); reality is `quic_post_recv` largest by ~4× (19.4s vs 4.5s).

**Why it happened:** Subagent B's analysis was per-call cost. `_drain_responses` is invoked per inbound datagram (per H3 response cycle); `_drain_stream` is invoked per STREAM_READABLE event (per inbound stream chunk × multiple chunks per request). At 14k rps × multi-chunk-per-req on long-conn, `_drain_stream`'s call frequency overshoots the response-build path despite each call being smaller.

**Lesson echoes sub-leg pass:** intuition-based per-call cost analysis is unreliable at this scale. Always direct-measure. This is the SECOND time a subagent's prediction has been inverted by data (sub-leg pass: `read_hs` 93% vs predicted `write_hs` ≥60%; Q1: `post_recv` ~19s vs predicted Rank 2). The pattern is recurring; treat it as a stable lesson.

**Memory entry candidate:** "Profile-prediction inversions: per-call cost analysis without call-frequency data is unreliable. Always direct-measure dominant phases via instrumentation BEFORE specing optimizations targeted at predicted hot spots."

## Pain points

### P1 — Spec/plan template hygiene (covered in D1)

Spec/plan code snippets must grep-validate every external-symbol citation. Cost of skipping the check: 1 fix-up commit + 1 round of reviewer cycle. Not catastrophic, but consistent enough to systematise.

### P2 — Long-running bench captures (~80 min of T0 + T5 + T6 combined)

Same pattern as Q3. Pure shell work that benefits from `run_in_background=True` + completion notifications. The capture-script reuse from Q3 (`/tmp/q3_capture_pre_sidecars.sh`-clone-and-modify pattern) saved ~10 min vs writing fresh script. **Lesson:** capture scripts should live in-tree at `bench/quic_perf/scripts/capture-sidecars.sh` so each pass doesn't have to re-derive the loop. Worth adding to a future bench-tooling spec.

### P3 — Pre-baseline contamination risk (avoided this pass)

Q3 had image-tag contamination from parallel HttpArena workflows; Q1 didn't. Tag isolation (`mojo-net-bench:q1-{pre,post}-{off,on}`) per `feedback_bench_offbuild_image_hygiene.md` continues to work. No issues.

## Open questions / required-later items (from spec §9)

| What | Severity | Trigger | Status post-Q1 |
|---|---|---|---|
| Next opt-spec target = `_drain_stream` (inside `quic_post_recv_us`) | required-later (high) | This spec ships → next long-conn-targeted optimisation | **OPEN — top recommendation for next spec.** Likely: QPACK decode batching, varint length-prefix parsing, stream-buffer chunk handling. |
| Sub-bracket of `quic_post_recv_us` (split timeout vs `_drain_stream` vs poll-loop) | optional | If next opt-spec needs to disambiguate inside the dominant phase | OPEN; defer until needed. The 19.4M μs is concentrated enough that we can probably skip sub-bracketing and go straight to `_drain_stream` deep-dive. |
| Short-conn `unaccounted_pct` residual (14.43% post-Q1, was 31.1% pre) | optional | If a future short-conn spec targets sub-1% RPS lift detection | CLOSED-as-acceptable — short-conn ε reduced by ~17pp as a side benefit; remaining 14.43% is small enough to not block. |
| Q2 — TLS 1.3 session resumption (`ffi_read_hs` deep-dive) | required-later (high) | Next short-conn-targeted spec | OPEN — sub-leg pass identified this as the short-conn bottleneck. Now Q1 is closed, Q2 is naturally next-in-line for short-conn. |
| Cold-create FFI accounting (sub-leg pass Subagent C Rank 3) | required-later (medium) | Post-Q1 budget-gap-closure | RESOLVED — Q1 closed the budget gap; this open question is implicitly addressed (cold-create FFI work runs inside `quic_post_recv_us`'s `_quic.timeout`/poll path, captured by Q1's instrumentation). |

## Surprises / design concerns

### Surprise 1 — Prediction inverted (covered in D3)

Already discussed. The pattern is recurring (sub-leg pass had it too). Memory entry candidate logged.

### Surprise 2 — Pre-baseline `unaccounted_pct` ballooned to 93.4% post-Q3 (covered in D2)

Algebraic interaction between the two diagnostic passes. Now understood; no corrective action.

### Surprise 3 — Variance tightening recurs (3rd pass)

| Cell | Pre CV | Post CV |
|---|---|---|
| On-build long-conn | 3.68% | 0.47% |
| On-build short-conn | 3.19% | 1.98% |
| Off-build long-conn | 3.91% | 0.93% |
| Off-build short-conn | 8.05% | 1.18% |

Stronger than Q3's tightening. Mechanism unclear — maybe constant-cost path additions (the brackets themselves run constant-cost code), maybe better cache behaviour from rebuild. **Bench harness sensitivity floor continues to drop pass-over-pass**, which is good for future sub-1% RPS lift detection (Q3's lesson stands).

### Design concern — None

No design choices need revisiting. All 5 design decisions held up:
- D1 Option A wiring (decomposed) — gave us the inversion finding; bench-only outer wrap (Option B) would have missed it.
- D2 3 phase legs — the spread between #1 and #2 (4×) and between #2 and #3 (4×) is wide enough that the 3-leg split is informative; collapsing would have lost the post_recv vs drain_resp signal.
- D3 Shape B post-construction setter — none of the 18 H3Connection.server/.client call sites needed edits. Lower blast radius confirmed.
- D4 5-gate validation — sum invariant catches bracket overlap (didn't fire here; useful guard); RPS gates caught nothing (no regression); `dcid_mismatch_pkts == 0` always passed.
- D5 Single-pair clock-read with hoisted t_start — worked; no Mojo lexical-scope issues.

## Next-spec recommendations

In priority order:

1. **`_drain_stream` deep-dive (highest priority).** This is the dominant long-conn phase per Q1's data (19.4M μs / 30s). Optimisation candidates: QPACK decode batching (`H3Connection._dec.decode(...)`), varint length-prefix parsing in H3 frame headers, stream-buffer chunk handling (`_H3StreamBuf` operations). Likely 100-200 LoC across `src/h3/connection.mojo` + `src/h3/qpack/decoder.mojo`.

2. **Q2 — TLS 1.3 session resumption (high priority for short-conn).** Sub-leg pass identified `ffi_read_hs` at 93.3% of short-conn `shim_ffi`; rustls already supports server-side resumption. Plumb the session-cache key + ticket lifecycle through `librustls-mojo/quic_hs.rs`. Likely 200-300 LoC.

3. **Tooling: in-tree sidecar capture script** (housekeeping). `bench/quic_perf/scripts/capture-sidecars.sh` accepting `LABEL`, `IMAGE`, `CELL`, `START_ITER`, `END_ITER` — same shape as `/tmp/q1_capture_sidecars.sh`. Saves ~10 min on every future diagnostic pass.

4. **writing-plans skill template hardening** (housekeeping). Add a pre-save-scan rule: "Every external-symbol citation in plan code snippets must be grep-validated against the source-of-truth file." Would have caught D1's `profile_monotonic_us` typo at planning time, not at T2 review time.

## Acceptance summary

| AC | Verdict | Detail |
|---|---|---|
| AC#1 (+6 unit tests) | ✅ PASS | Filtered count 42 → 48; full src suite 72/72 unchanged. |
| AC#2 (Hard Gate 1 long-conn `unaccounted_pct` <15%) | ✅ PASS | 9.82% (target <15%; soft floor 15-25%). |
| AC#3 (Hard Gate 2 on-build long-conn drift ≥−2.0%) | ✅ PASS | +2.54%. |
| AC#4 (Hard Gate 3 on-build short-conn drift ≥−2.0%) | ✅ PASS | +2.64%. |
| AC#5 (Hard Gate 4 off-build drift ≥−2.0% both cells) | ✅ PASS | +5.50% / +3.77%. |
| AC#6 (Hard Gate 5 sum invariant) | ✅ PASS | All 6 post sidecars satisfy `h3_legs ≤ pre-h3 unacct`. |
| AC#7 (Hard Gate 6 dcid_mismatch_pkts == 0) | ✅ PASS | All 12 sidecars (6 pre + 6 post). |
| AC#8 (REFERENCE.md entry) | ✅ PASS | Appended; verdict + image SHAs + per-AC table + dominant-phase-named verdict. |
| AC#9 (flag revert) | ✅ PASS | `comptime PROFILE_ACCEPT: Bool = False` verified. |

**All 9 ACs PASS without escalation. Subagent B's prediction OVERTURNED but the spec's diagnostic deliverable (name the dominant phase) is met with high confidence — that's the spec's whole point.**

## Reusable lessons

1. **Profile-prediction inversion is recurring.** Two diagnostic passes (sub-leg + Q1) both had per-call-cost predictions inverted by direct measurement. Lesson: per-call cost analysis without call-frequency data is unreliable; always direct-measure before specing optimisations. **Worth saving as a memory entry.**

2. **ε-share grows when other buckets shrink.** Each bucket-shrinking pass (Q3 reduced loop_pop_dispatch by 15.67%) increases the unaccounted ε's *share* of busy, even though absolute ε work is unchanged. Future "close the gap" specs should set thresholds against the FRESH baseline, not the predecessor pass's number.

3. **Spec/plan code snippets must grep-validate external symbols.** D1's `profile_monotonic_us` typo cost 1 fix-up cycle; a 5-second grep at planning time would have prevented it. Consider hardening the writing-plans skill.

4. **Variance tightening continues pass-over-pass.** Bench harness sensitivity floor is dropping (CV 8% → 1% in the noisiest cell). Future perf specs targeting sub-1% RPS lifts have lower noise floor to exploit.

5. **Capture script reuse is high-ROI.** Cloning Q3's sidecar-capture script + 1-line edit saved ~10 min for Q1. In-tree `capture-sidecars.sh` would generalise it.

---

**Final phase:** spec-quic-h3-phase-leg-instrumentation-reviewing → done.
**Tests:** 72/72 src PASS on HEAD `f8b5fb1`.
**Working tree:** clean (only pre-existing untracked: `certs/`, `h3_server`, unrelated old plan).
**Image cleanup:** all 4 q1-* tagged images can stay or be cleaned via `docker image rm mojo-net-bench:q1-{pre,post}-{off,on}` post-merge; not blocking.
