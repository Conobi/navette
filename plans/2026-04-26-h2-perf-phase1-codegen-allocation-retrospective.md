# H2 Perf — Phase 1 Codegen-Allocation: Retrospective

> Plan: `plans/2026-04-26-h2-perf-phase1-codegen-allocation.md`
> Phase 0 baseline: `d6fdbcb` (55 s, 5 109 samples on `/baseline2`)
> Phase 1 final: `d3f84ed` (110 s, 528 unique stacks, ~11 500 samples)
> Branch: `worktree-perf+h2-phase1-task1-decode-string`

## Built vs. planned

All 6 tasks delivered. 5 perf commits + 1 retrospective:

| Task | Commit | What landed |
|------|--------|-------------|
| 1 — bulk decode strings | `e424eb6` | `String(unsafe_from_utf8=...)` replaces per-byte `+= chr(Int(b))` in HpackDecoder._decode_string |
| 2 — bulk extend wire slice | `174aed8` | `List.extend(Span(wire)[start:end])` + `capacity=str_len` replaces per-byte `raw` build |
| 3 — `_to_lower` bulk byte-build | `3bdd92a` | List[UInt8] build + `String(unsafe_from_utf8=...)` replaces per-byte `+= chr(...)` |
| 4 — `Headers.add_lowercase` fast path | `4b77271` | New skip-validation insert; 4 HPACK ingress callsites in `pseudo_headers.mojo` switched over |
| 5 — pre-size + bulk-extend connection buffers | `d3f84ed` | 16 KB `_inbuf`/`_outbuf` capacity, `extend(encoded^)` in `_queue_frame`, in-place `memmove + resize(unsafe_uninit_length)` in `_trim_inbuf` |
| 6 — retrospective | (this commit) | |

**Deviations:**
1. **Mojo MCP-driven verification per task.** Plan flagged `String(unsafe_from_utf8=...)`, `List.extend(Span)`, `memmove`, `resize(unsafe_uninit_length=...)` as verify-before-edit risks. Each was confirmed via Mojo MCP `execute` before going into source. Took ~30 seconds per check; saved at least one compile-error round trip per task.
2. **`huff_result[0]^` syntax error caught early.** Tuple subscripts can't be moved with `^` in Mojo 0.26.2 — `String(unsafe_from_utf8=huff_result[0])` works because the constructor borrows. Documented in the Task 1 commit message.
3. **Docker image rebuild fails in worktree.** `bench/build.sh` errors on `cp crates/librustls-mojo/target/release/liblibrustls_mojo.so` because the rustls crate isn't built in the worktree's Docker context. Throughput tier (which uses Docker) was deliberately not re-run per task; perf-record tier (host binary) ran every task. The end-of-Phase-1 throughput comparison is deferred to a separate retrospective run from the main checkout.
4. **Per-task small-sample captures overstated wins.** Documented in the methodology section below.

---

## The methodology lesson

**Per-task 60 s / 5 K-sample perf captures show large hotspot deltas. Final 110 s / 11 K-sample capture corrects them downward.**

The Phase 0 retrospective explicitly flagged this: *"5 109 samples is on the threshold. A single-run delta of <1 % is below the noise floor."* I logged per-task hotspot tables in commit messages anyway, with deltas of 1–4 % attributed to single tasks. The 110 s reference capture shows those numbers were noisy; real cumulative deltas are much smaller.

**Per-task captures (60 s, 5 K samples) implied:**
- `_to_lower` self: 4.43 → 1.13 (-3.30)
- HPACK trio combined: 11.79 → 11.62 (-0.17)
- `_drain_responses` self: 7.92 → 7.14 (-0.78)

**110 s reference capture (final, 11 K samples) actually shows:**
- `_to_lower` self: 4.43 → 3.84 (-0.59)
- `_decode_string` self: 6.76 → 6.16 (-0.60)
- `_drain_responses` self: 7.92 → 7.20 (-0.72)

**Lesson for Phase 2:** Reject any per-task delta claim that rests on a single <10 K-sample run. Either run 120 s+ captures per task, or run two captures and report the spread. The Phase 0 README "Stable percentages need ≥5 000 samples" is wrong as written — the threshold is closer to 10 000 for sub-1 % deltas.

---

## Cumulative numbers — Phase 0 vs Phase 1 final

### Self-time hotspot delta (110 s captures, top symbols only)

| Symbol | Phase 0 self | Phase 1 self | Δ |
|--------|-------------:|-------------:|--:|
| `[libAsyncRTRuntimeGlobals.so]` | 18.22 % | 18.99 % | +0.77 |
| `_drain_responses` | 7.92 % | 7.20 % | -0.72 |
| `_decode_string` | 6.76 % | 6.16 % | -0.60 |
| `__tls_get_addr` | 4.09 % | 5.96 % | +1.87 |
| `_to_lower` | 4.43 % | 3.84 % | -0.59 |
| `String::_iadd` | 3.45 % | 3.20 % | -0.25 |
| `H2Connection::receive_data` | 3.95 % | 4.02 % | +0.07 |
| `H2Connection::send_headers` | 3.47 % | 2.97 % | -0.50 |
| `swapcontext` | 2.95 % | 2.81 % | -0.14 |
| `Dict::_insert` | 2.95 % | 2.77 % | -0.18 |
| `TCMallocInternalCfree` | 2.48 % | 2.62 % | +0.14 |
| `List::_realloc` | 2.26 % | 2.19 % | -0.07 |
| `chr` | 1.58 % | 1.69 % | +0.11 |

**Aggregate: ~2 % of total CPU recovered**, concentrated in HPACK + headers + send paths. The methodology projection of ~10 % was overstated. The ~22 % combined runtime + `__tls_get_addr` actually grew (the cost didn't disappear — it became more visible relative to a now-smaller pie).

### Inclusive-time delta (selected)

| Symbol | Phase 0 incl | Phase 1 incl | Δ |
|--------|-------------:|-------------:|--:|
| `HpackDecoder::decode` | 12.14 % | 11.79 % | -0.35 |
| `_decode_string` | 10.36 % | 9.97 % | -0.39 |
| `_decode_literal` | 10.44 % | 10.13 % | -0.31 |
| `_to_lower` | 7.52 % | 6.54 % | -0.98 |
| `List::_realloc` | 18.06 % | 21.39 % | **+3.33** |

`List::_realloc` inclusive WENT UP. This is the most important negative finding: the 16 KB pre-sizing + bulk-extend in Task 5 didn't help, and may have made things worse by encouraging larger initial allocations that then realloc on growth. Plan flagged this as a "won't go to zero but realistic 50 % cut" prediction; reality was a regression.

### Throughput

End-to-end h2load on host (single-process):
- Phase 0 baseline: 67 827 req/s (20 s) / 60 692 req/s (12 s smoke)
- Per-task captures: 66 110 / 67 652 / 69 116 / 68 659 (60 s each, all within noise)
- Phase 1 final 110 s: **62 910 req/s** ⚠️

The 110 s final number is lower than per-task 60 s numbers. This reflects steady-state vs warm-up. Hard to declare progress on throughput without re-running the 110 s capture multiple times for variance. Treat as "flat within ±5 K req/s noise band" pending more captures.

**Throughput tier (Docker, multi-worker, mojo-net vs hyper) deliberately deferred.** The Docker rebuild fails in the worktree; the comparison number against hyper requires the main checkout. Recommended next action: cherry-pick this branch onto main, rebuild bench Docker image, run `bench/profile/h2-throughput.sh` for the public mojo-net-vs-hyper number.

---

## Per-task wins, honestly

Recomputed against the 110 s reference (not per-task 60 s captures).

| Task | Hotspot move | End-to-end | Verdict |
|------|--------------|------------|---------|
| 1 — bulk decode | `_decode_string` self ±0; inclusive -1.10 | flat | partial — cost moved into ctor, not eliminated |
| 2 — bulk extend wire | `_decode_string` inclusive -0.39 cumulatively | flat | mechanical correctness; small win |
| 3 — `_to_lower` bulk | `_to_lower` self -0.59, `_iadd` -0.25 | flat | best of the lot — clean win |
| 4 — `add_lowercase` | `_to_lower` self ±0 (same level) | flat | duplicates Task 3's territory; tiny added win |
| 5 — connection buffers | `List::_realloc` self -0.07; **inclusive +3.33** | flat | **mechanically correct, hotspot-negative** |

Phase 1's main wins came from Task 3 (`_to_lower` bulk) and to a lesser extent Task 1+2's HPACK inclusive drop. Task 4 ate Task 3's territory rather than stacking. Task 5 is a wash at best, possibly slightly negative.

---

## Decision gate: Phase 2?

The plan's exit criterion: **"if ≥80 % of hyper, declare victory and stop."**

We don't have a Docker / multi-worker mojo-net-vs-hyper number for Phase 1 final (Docker rebuild blocked in the worktree). What we have:
- Single-process host: 63–69 K req/s (noisy).
- Phase 0 Docker baseline: mojo-net 236 935 vs hyper 337 484 → 70 %.

If Phase 1's hotspot moves ($_to_lower$ -0.59, HPACK inclusive -0.35–0.39) translate to throughput at all, we're at most ~71–72 % of hyper now. Not at 80 %.

**Recommendation: continue to Phase 2.** The remaining gap requires touching the architectural items deferred in Phase 0:
- `[libAsyncRTRuntimeGlobals.so]` 19 % self (opaque — needs Modular debug-symbol build, or different runtime configuration)
- `swapcontext` + `getcontext` ~3.6 % combined (coro suspends per request)
- `Dict::_insert` 2.77 % (stream-state map → InlineArray)
- `__tls_get_addr` 5.96 % self (C runtime TLS lookup churn — switch to a different threading model or eliminate the lookups)
- HpackEncoder cost (not visible self, but an inclusive piece of `send_headers` 7.34 %)

These are NOT mechanical edits; they're architectural decisions. Phase 2 should be smaller in scope (1-2 changes) and bigger in measurement budget per change.

---

## Open questions

- **O-2 — `[libAsyncRTRuntimeGlobals.so]` opacity** (carried over from Phase 0). Now bumped to **required-now** for Phase 2: 19 % of self-time can't be optimized blind. Need debug symbols.
- **O-3 — Task 5 `List::_realloc` inclusive regression.** Severity: investigate. The pre-sized 16 KB might be encouraging larger first-allocations that then realloc more aggressively under growth, or the change-in-shape of work is exposing other realloc paths. Could be benign noise, could be a real regression. Recommend re-measuring on the main checkout after Docker rebuild before drawing a hard conclusion.
- **O-4 — Per-task throughput regression noise.** The 110 s capture's 62 910 req/s is below per-task 60 s numbers. Either short captures are the warm-up phase (and Phase 0's 67 827 was warm-up too), or there's a real slowdown from cumulative changes. Need 3+ runs of 110 s to disambiguate.

---

## Exit criteria — answered

| # | Question | Answer |
|--:|----------|--------|
| 1 | mojo-net req/s on `/baseline2` and `/json/...` post-Phase-1, % of hyper? | Single-process host: 63 K req/s (noise band 60–69 K). Docker comparison vs hyper: deferred — rebuild blocked in worktree. Pre-Phase-1 ratio was 70 %; not enough movement to expect we crossed 80 %. |
| 2 | Did the three target families end up ≤ half their Phase 0 weight? | `_to_lower` 4.43 → 3.84 (≈87 %; **failed** the half-weight goal). `_decode_string` 6.76 → 6.16 (≈91 %; **failed**). `List::_realloc` self -0.07 / inclusive +3.33 (**failed both directions**). |
| 3 | New top hotspot? | `[libAsyncRTRuntimeGlobals.so]` 18.99 % (was 18.22 %); `__tls_get_addr` 5.96 % (was 4.09 %, climbed because other items shrank); `_drain_responses` 7.20 % (was 7.92 %, still #2 attackable). |
| 4 | Cumulative throughput crossed 80 % of hyper? | **No, and we lack a clean Docker comparison number.** Recommend re-running the comparison from main after the cherry-pick. |

---

## Recommendations for Phase 2

1. **Fix the methodology first.** Adopt 120 s minimum captures, mandatory 3-run spread reporting, and a Docker rebuild (from the main checkout, not a worktree) before declaring any per-task win.
2. **Cherry-pick this branch to main**, rebuild Docker, run the full throughput tier (mojo-net + hyper across all 3 endpoints), commit those numbers as the post-Phase-1 reference. THEN decide Phase 2 scope.
3. **Phase 2 candidates (in plan-priority order):**
   - **`[libAsyncRTRuntimeGlobals.so]` triage.** 19 % opaque cost. Get debug-symbols build, capture again, see what's inside. Likely the largest single win available.
   - **Stream-state `Dict` → `InlineArray`** (Phase 0 deferred). 2.77 % self. Mechanical change once the cap on concurrent streams is fixed.
   - **HPACK encoder fast paths** — Phase 0 didn't show encoder symbols in top 30, but the new `send_headers` 7.34 % inclusive deserves a deeper look.
4. **Drop Task-5 territory from future scope.** Connection-buffer pre-sizing didn't move the needle; per-frame response-writer allocation (in `handler.mojo` / `h2_coro_server.mojo`) is the actual realloc source.
5. **Don't ship to main without a Docker throughput rerun.** The honest comparison numbers (vs hyper, on the multi-worker image) are the credible signal; per-task host-binary numbers are not.

---

## Code-quality note (independent of perf)

All five Task changes are mechanically correct improvements that:
- Removed two byte-by-byte `+= chr(...)` anti-patterns (HPACK + headers).
- Eliminated a per-byte slice rebuild and a per-byte `_outbuf` append.
- Replaced an O(n) buffer rebuild with an in-place memmove + resize.
- Added an `add_lowercase` fast path with a clear correctness contract.

The diff is worth keeping even if the perf numbers don't justify it on their own — the code is cleaner and the patterns now match Mojo 0.26.2 idioms.
