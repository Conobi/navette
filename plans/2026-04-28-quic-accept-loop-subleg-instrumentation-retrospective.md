# QUIC Accept-Loop Sub-Leg Instrumentation — Retrospective

**Branch:** `feat/quic-accept-loop-subleg-instrumentation` (off main `b345c99`)
**Spec:** `specs/2026-04-28-quic-accept-loop-subleg-instrumentation.md`
**Plan:** `plans/2026-04-28-quic-accept-loop-subleg-instrumentation.md`
**Commits:** T0 `ee8b26b` → final `9a2ab1b` (12 commits)
**Date:** 2026-04-28
**Final cross-cutting review verdict:** ✅ CLEAN

---

## Built vs. planned

### Shipped per spec

- `AcceptProfile` extended with **6 new `UInt64` totals + `loop_iter_count` helper + 7 record_* methods**:
  - FFI sub-legs: `ffi_read_hs_us_total`, `ffi_write_hs_us_total`, `ffi_take_keys_us_total` (T1)
  - Loop phases: `loop_pop_dispatch_us_total`, `loop_post_pkt_us_total`, `loop_teardown_us_total` (T2)
  - Helper: `loop_iter_count` + `record_loop_iter()` (T2)
- `report_json` emits `ffi_subleg_us` + `loop_phases_us` blocks with budget-closure ε (T3).
- `report_text` mirrors the new sections (T3).
- `connection.mojo` 3 FFI call-sites use single-pair clock-read pattern + function-scope `var t_start: UInt64 = 0` hoist (T4).
- `bench/h3_server.mojo` `_flush_impl` brackets PHASE A (4 record sites: 3 continues + main fall-through), PHASE B, PHASE C (T5).
- **+12 unit tests** (verified via `TESTS_FILTER=test_quic_profile`; total 42 tests in `test_quic_profile.mojo`).
- T6/T7 smoke gates: both cells PASS at ±10% on both off-build and on-build.
- T8 SIGINT sidecar captures: long-conn + short-conn JSON sidecars with full new field set.
- T9 REFERENCE.md +76-line entry documenting diagnostic outputs.

### Diagnostic deliverable (AC#7) — **MET**

| Cell | Dominant FFI sub-leg | Dominant loop phase |
|---|---|---|
| Short-conn | **`ffi_read_hs` at 93.3% of `shim_ffi`** | **`loop_pop_dispatch` at 5.9% of `busy_us_total`** |
| Long-conn | (handshake-FFI is 0.4% of busy — irrelevant) | (all phases <1% of busy combined) |

### Smoke gate measurements

| Build | Cell | n | Median rps | IQR | Drift vs baseline | Verdict |
|---|---|---|---|---|---|---|
| OFF-BUILD (`mojo-net-bench:subleg-T6`) | long-conn | 10 | 14,947 | 167 | +3.54% | PASS |
| OFF-BUILD | short-conn | 10 | 1,226.65 | 37 | +1.54% | PASS |
| ON-BUILD (`mojo-net-bench:subleg-T7`) | long-conn | 10 | 14,885 | 167 | +5.50% | PASS |
| ON-BUILD | short-conn | 10 | 1,194.95 | 27 | +0.75% | PASS |

On-build vs off-build overhead: **−0.41% long-conn, −2.59% short-conn — within run-to-run noise**, consistent with the migration spec's 10-iter rerun finding (−2.3% / −1.8%).

---

## Deviations from the plan

### D1 — T2 dropped a planned 4th unit test

**Plan:** T2 had 4 tests (3 record_loop_* + 1 record_loop_iter increment-count test).
**Actual:** T2 shipped 3 tests; the increment-count test was dropped because T3's `test_loop_phase_avg_uses_loop_iter_count_divisor` and `test_report_json_emits_loop_phases_block` exercise `record_loop_iter` indirectly. Total +12 across T1+T2+T3 still satisfies AC#1.

**Why:** discovered during plan-writing's pre-save scan; reconciled at the spec author's discretion to keep test count at exactly 12.

### D2 — Tag isolation override added to `start-server.sh` (not in plan)

**Plan:** assumed `mojo-net-bench:latest` was a stable tag for the bench duration.
**Actual:** added `MOJO_NET_IMAGE` env-var override in `bench/quic_perf/scripts/start-server.sh` (defaults to `mojo-net-bench:latest`). Used `mojo-net-bench:subleg-T6` and `mojo-net-bench:subleg-T7` for T6/T7.

**Why:** parallel HttpArena workflow in `feat-h2-state-machine-path-a` worktree retagged `mojo-net-bench:latest` mid-bench (sha `80fd3f5b0fc0` at 02:58:44, during T6 short-conn) with code from a branch lacking the DCID migration. Initial T6 short-conn cratered to 0.42 rps median (pre-migration symptoms). After tag isolation + retry, both cells PASSED cleanly.

**Lesson preserved in REFERENCE.md:** when running benches alongside parallel workflows, use a unique image tag.

### D3 — T0 sanity check needed a CPU-load gate (not in plan)

**Plan:** T0 step 4 ran a 3-iter long-conn baseline check.
**Actual:** first attempt produced 12,213 rps median (-15.4% drift, outside the gate). Investigation found a parallel `mojo run tests/test_cross_quic_hs_keys.mojo` test in another worktree at 82% CPU. After waiting for it to clear, rerun produced 14,494 rps median (+0.4% drift). User then requested a CPU-load gate before each subsequent bench run.

**Why:** mojo-net's bench is sensitive to L3-cache + scheduler interference from parallel mojo processes (even on different cores). The CPU gate (`pgrep`+ load1 check) was applied before T6, T7, T8 — every subsequent bench produced clean numbers.

**Lesson preserved in REFERENCE.md:** add a CPU-load gate that detects competing processes (especially across worktrees) before kicking off any bench measurement.

### D4 — T0 docker rebuild needed explicit BOUCLE_DIR + SIMDJSON_DIR

**Plan:** T0 just runs `bash bench/build.sh`.
**Actual:** `bench/build.sh` resolves `BOUCLE_DIR=$REPO_ROOT/../boucle` which evaluates to `.worktrees/baseline-main/../boucle` = `.worktrees/boucle` (doesn't exist; boucle lives at `~/Projets/perso/boucle/`). First T6 build attempt failed in 10 seconds with a `cd:` error. Resolved by passing `BOUCLE_DIR=/home/donokami/Projets/perso/boucle SIMDJSON_DIR=/home/donokami/Projets/perso/json-simd-mojo` explicitly.

**Why:** `bench/build.sh`'s relative-path defaults assume the standard mojo-net checkout, not a `.worktrees/` checkout. Pre-existing harness bug.

**Lesson:** when running bench scripts from a worktree, set `BOUCLE_DIR` and `SIMDJSON_DIR` explicitly. Long-term fix is to amend `bench/build.sh` to fall back to `~/Projets/perso/{boucle,json-simd-mojo}` if the relative path doesn't exist — out of scope here, recorded as a minor open question.

### D5 — AC#5 `unaccounted_pct < 2` failed by a wide margin (long-conn 82%, short-conn 18%)

**Plan:** AC#5 was a hard gate.
**Actual:** the gate was unreachable. Investigation showed the prior post-migration captures (2026-04-27 long-conn: 83% unaccounted, short-conn: 28% unaccounted) had **identical pre-existing gaps**. The instrumentation we just added isn't the cause.

**Why:** the existing `record_pkt` only fires inside `recv_from_buffer`'s success path — it does NOT cover `feed_datagram_from_buffer`'s response-build path, the H3 handler invocation, the QPACK encode, or the outgoing-packet build (`_drain_responses` → `send_stream_data`). These are pre-existing untimed paths that consume the bulk of long-conn busy time. The spec author didn't audit the existing profile system's coverage before writing the AC#5 gate; the assumption "all per-pkt work is in `record_pkt`'s legs + drain + the new loop phases" was wrong.

**Resolution:** downgraded AC#5 to "known limitation", recorded as `required-later` open question with explicit follow-on spec scope (Subagent B's report identifies the 3 untimed sinks).

**Lesson:** before writing budget-closure ACs, audit the existing instrumentation's coverage by running a pre-spec capture and computing the residual. The 28% / 83% gap was visible in 2026-04-27 captures we already had.

### D6 — Spec's predicted FFI sub-leg shares were badly wrong

**Plan:** `ffi_write_hs ≥60% of shim_ffi` (reasoning: server output bytes are larger than input).
**Actual:** `ffi_read_hs = 93.3%`, `ffi_write_hs = 6.4%`, `ffi_take_keys = 0.3%`.

**Why:** the spec's prediction confused **bytes flowing** with **CPU spent**. Server-side TLS handshake is parse-heavy on ingress (ECDHE shared-secret derivation, ClientHello extension parse, Client-Finished HMAC verify, optionally cert verify) and copy-heavy on egress (memcpy pre-built Cert chain + one CertificateVerify signing op). Plus call-frequency asymmetry: `read_hs` fires per-crypto-level-per-arrival (3-6× per handshake) while `write_hs` drains in a single `while True:` loop pass. Subagent A's deep-dive into rustls source confirms: `ConnectionCommon::read_hs` → `process_new_packets` → `tls13::CompleteClientHelloHandling::handle_client_hello` is where ECDHE + signature emission + HKDF×12 + transcript SHA all happen. `write_hs` is `while pop_front + extend_from_slice + Option<KeyChange>` — pure memcpy.

**Lesson recorded in memory:** `feedback_byte_size_cpu_share_fallacy.md` — don't predict crypto-protocol CPU shares from byte volumes. Cite library source or microbench.

This was the **single most surprising finding of the pass** and explicitly the kind of overturn this diagnostic spec was designed to produce. The data did its job.

---

## Pain points

### P1 — `bench/build.sh` BOUCLE_DIR default doesn't work from worktrees

See D4. Pre-existing. Costs ~10 seconds per fresh attempt + a few minutes of investigation the first time someone hits it.

### P2 — Image-tag collision with parallel workflows is invisible until results crater

See D2. Hard to debug because the SYMPTOM (pre-migration rps numbers) only appears DURING bench iters, and the image tag is opaque (no version stamp inside the image to compare against source HEAD). Cost: ~30 min including the second build + retry. The `MOJO_NET_IMAGE` env-var override mitigates this for future passes.

### P3 — `run_tests.sh` halts at pre-existing `test_tls_connection` failure (set -e)

`bash scripts/run_tests.sh 2>&1 | grep -cE '^PASS:'` returns 33, NOT 33+12=45 after T3, because `test_quic_profile` runs AFTER `test_tls_connection`'s halt. Verifying AC#1 required `TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh` instead (returns 42 = 30 pre-existing + 12 new).

The plan's AC#1 framing assumed un-halted run_tests.sh. Future plans should either:
- run with TESTS_FILTER, or
- Audit run_tests.sh order and check whether new tests fall before or after the halt point.

Pre-existing infrastructure issue (rustls FFI symbol missing in shipped `.so`).

### P4 — Stale wakeup-prompt reuse during long bench runs

Multiple `ScheduleWakeup` prompts fired with stale instructions (e.g. "check long-conn bench" after the bench had already finished and short-conn was running). The orchestrator handled them by checking current state instead of re-executing the stale instruction, but it's a small UX cost and easy to mishandle.

### P5 — AC#5 was unreachable by design

See D5. The author wrote a budget-closure invariant without auditing the existing profile system's coverage. The 18-82% pre-existing gap was discoverable by recomputing on the existing 2026-04-27 captures — a 5-min check the spec didn't include. Pattern is similar to D6 (predict-without-verify); both fall under the byte-size fallacy lesson's umbrella.

---

## Surprises and design concerns

1. **`ffi_read_hs` at 93.3% (vs predicted ~25%)** — see D6. Memory entry written. The single most valuable finding of the pass.

2. **`loop_pop_dispatch` per-iter cost is 4× higher on short-conn vs long-conn** (3.1 μs vs 0.84 μs avg). Subagent C's analysis traces this to `Dict[String, Int]` lookup on a 36k-entry map (~exceeds L1 cache) on short-conn vs ~10-entry map on long-conn (always L1-hot). Replacing the Dict key type with `UInt64` (packed 8-byte DCID, no String alloc) is the leading microoptimisation candidate.

3. **The 24.4s long-conn unaccounted gap is concentrated in 3 untimed paths.** Subagent B's read identifies `H3HandlerServer._drain_responses` (12-16s, QPACK encode + frame build + send_stream_data), `H3Connection._drain_stream` (5-8s, frame parse + QPACK decode), and `BenchHandler.on_request` dispatch (1-3s) — all running inside `feed_datagram_from_buffer` between `record_pkt` (line 890 of connection.mojo) and `record_drain` (line 889 of bench/h3_server.mojo). None of the H3 application path is currently instrumented.

4. **Subagent A's irreducibility floor.** Of the 7s of `ffi_read_hs`, ~70% is irreducible cryptographic work (ECDHE scalar mult + signing + HKDF + HMAC verify). The remaining 30% (~2s) is potentially addressable via TLS 1.3 session resumption, ECDSA/Ed25519 cert (vs RSA-2048 default), or sigscheme tightening.

5. **Single-pair clock-read pattern works exactly as designed.** AC#4 sub-leg sum is bit-exact (diff = 0) in both cells. The function-scope `var t_start: UInt64 = 0` hoist (added in spec review round 2 after the in-scope `var t_start` failed Mojo's lexical-scope rules) is correct.

---

## Open questions (severity + trigger)

### Q1 — AC#5 budget-closure pre-existing gap

**Severity:** required-later.
**Trigger:** any future bench-budget-dependent spec (e.g. an optimisation spec that wants to verify "X% reduction in busy time" — the residual ε must be smaller than X% to make the comparison meaningful).
**Resolution path:** Subagent B's report (`research/2026-04-28-long-conn-unaccounted-gap.md`) recommends a ~80-100 LoC follow-on spec adding 3 new legs (`h3_dispatch_us`, `h3_drain_resp_us`, `quic_post_recv_us`), wired via `profile_ptr` threaded through `H3HandlerServer` / `H3Connection` ctors, mirroring the existing FFI sub-leg pattern.

### Q2 — `ffi_read_hs` optimisation lever

**Severity:** high.
**Trigger:** next short-conn optimisation spec.
**Resolution path:** Subagent A's report (`research/2026-04-28-rustls-read-hs-cost-decomposition.md`) recommends TLS 1.3 session resumption (40-60% shave; rustls server already supports via `send_tls13_tickets` + `attempt_tls13_ticket_decryption`). Cheap warm-up: audit the test cert under `certs/` — if RSA-2048 (rcgen default), 5-15% recoverable for free by switching to ECDSA-P-256 or Ed25519.

### Q3 — `loop_pop_dispatch` Dict[UInt64,Int] microoptimisation

**Severity:** medium.
**Trigger:** any bench-local optimisation spec.
**Resolution path:** Subagent C's report (`research/2026-04-28-pop-dispatch-finer-split.md`) recommends `Dict[String, Int] → Dict[UInt64, Int]` keyed on packed 8-byte DCID via a new `_dcid_to_u64(Span[UInt8, _]) → UInt64` helper. ~50 LoC bench-local; ~6% rps uplift on short-conn. The DCID 8-byte invariant is already hard-gated by the existing `debug_assert` + dedicated unit test, so the precondition holds.

### Q4 — `bench/build.sh` BOUCLE_DIR default doesn't work from worktrees

**Severity:** optional.
**Trigger:** another contributor hits D4 OR someone has a free 10 minutes.
**Resolution path:** amend `bench/build.sh` to fall back to `~/Projets/perso/{boucle,json-simd-mojo}` if the relative path resolution fails.

### Q5 — `alias` deprecation warnings in profile.mojo

**Severity:** optional.
**Trigger:** clean-up sweep across `comptime`/`alias` migration.
**Resolution path:** rename `alias _HEX_DIGITS = "..."` to `comptime _HEX_DIGITS: ... = "..."` in `bench/h3_server.mojo`; same for any other alias in `src/quic/profile.mojo`. Functional; warnings are noise.

---

## Next-spec recommendations

The 3 parallel research subagents produced evidence-grounded scope notes. Three follow-on specs are ranked-orderable:

1. **Highest-confidence + smallest scope: Q3 (`Dict[UInt64, Int]` microoptimisation).** ~50 LoC, ~6% short-conn uplift, no `src/` surface, no FFI changes, no new bench cells. Bench-local mechanical optimisation. Spec it as a 1-3 task plan; can ship in <1 day.

2. **Highest-impact + medium scope: Q2 (TLS 1.3 session resumption).** ~150-300 LoC across `src/quic/connection.mojo` (server config: enable ticket cache, tune ticket lifetime), test the resumption path, and verify the rustls API is wired correctly. 40-60% short-conn uplift on the FFI cost (which is 93% of the optimisation surface). However, behavioural change requires careful conformance (RFC 8446 §4.2.11 ticket handling) — needs spec brainstorming.

3. **Medium-confidence + medium scope: Q1 (close the budget closure gap).** ~80-100 LoC instrumentation-only. Unblocks rigorous benchmarking of any future optimisation. Worth doing before Q2 ships, so Q2's "X% improvement" claim has a verifiable ε bound.

Suggested order: **Q3 → Q1 → Q2.** Q3 ships fast and produces a non-controversial uplift. Q1 closes the bench infrastructure gap. Q2 then ships against a clean budget.

---

## Process observations

- **Plan-then-research-via-parallel-subagents was effective.** While T8 + T9 finalisation ran on the main thread, 3 subagents produced 3 independent reports (`research/2026-04-28-{rustls-read-hs-cost-decomposition,long-conn-unaccounted-gap,pop-dispatch-finer-split}.md`) totalling 26 KB of evidence-grounded scope notes for follow-on specs. Better than waiting until the next brainstorm session — the user's frustration with the byte-size fallacy was specifically about "we should have grounded predictions in evidence", and the parallel investigation pattern delivers that for the next spec round.

- **Two diagnostic-only spec patterns now in the playbook** (with this pass + the queueing-tail + the collision-counter passes): instrumentation-only specs that ship the same shape (PROFILE_ACCEPT-gated extension to AcceptProfile + SIGINT sidecar capture + REFERENCE.md verdict entry). Future diagnostic specs can be ~1/3 shorter by referencing this template.

- **Methodology gate satisfied.** Re-read all 553 prior REFERENCE.md lines before drafting T9 entry. No contradictions found; sub-leg shares refine (do not contradict) prior `shim_ffi` aggregate. Pattern is working.
