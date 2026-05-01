# Q-drain-subleg — Retrospective

**Spec:** `specs/2026-05-01-quic-h3-drain-stream-subleg.md`
**Plan:** `plans/2026-05-01-quic-h3-drain-stream-subleg.md`
**Branch:** `feat/quic-h3-drain-stream-subleg` off main `7e2eb01`
**Closed:** 2026-05-02
**Type:** Diagnostic-only sub-leg pass (Q1 follow-on)

## Headline

**🎯 BOTH research predictions OVERTURNED.** Topic 1 predicted `buf_accumulate_us` would dominate (architectural-gap argument: mojo-net's accumulator + per-frame O(residual) shift has no reference analogue). Topic 1 also predicted QPACK would be sub-µs/req → unlikely dominant. Reality:

- `qpack_decode_us` (the wall-clock wrapping `self._dec.decode(frame.payload)` end-to-end) = **95.4%** of `drain_stream_us_total` (~21.2M μs / 30s on long-conn)
- `buf_accumulate_us` (B3a + B3b combined — the `_H3StreamBuf.buf` accumulator: copy + per-byte append + Dict copy/reassign + residual rebuild) = **1.1%**
- `recv_ffi_us` = 2.2%, `frame_parse_us` = 0.5%, `event_dispatch_us` = 0.6%

At long-conn 14k rps × ~14k HEADERS frames/sec, the bracket measures ~50 μs/HEADERS-frame inside `_dec.decode(...)`. For comparison, TQUIC + quiche static-only QPACK is sub-µs/req per Topic 1 §4 — but those are reference *algorithm* costs, not direct apples-to-apples wall-clock measurements of the same call.

**What the 95% proves:** The wall-clock cost of invoking `self._dec.decode(frame.payload)` end-to-end is the dominant `_drain_stream` cost. Sum invariant closes exactly (sum of 5 legs = `drain_stream_us_total` to the byte across all 6 post sidecars), so there is no hidden bucket — the 95% is genuinely inside that call.

**What the 95% does NOT prove:**

1. **Where inside `_dec.decode` the time goes.** Could be varint length-prefix parsing, the 99-entry static-table lookup loop, per-call `List[QpackHeaderField]` allocation, header-name/value String construction, or some combination. The B5 bracket wraps the call, not the call's internals.
2. **Whether some of the 50 μs is Mojo function-call / parameter-passing / result-allocation overhead** rather than algorithmic QPACK work. `frame.payload: List[UInt8]` may incur an implicit copy on parameter binding; `List[QpackHeaderField]` result requires allocation. Both count toward the measured 50 μs but aren't "QPACK algorithm" cost.
3. **Whether 50 μs/call reproduces in a microbench.** We measured only under live bench load; no isolated cross-check.

**Inspection-driven dominant-phase predictions now have a 0/3 track record on this codebase**:
1. Subagent B's Q1 prediction (`drain_resp` rank 1 at 12-16s) → overturned by `quic_post_recv` (~19.4M μs)
2. Sub-leg pass's prediction (`write_hs ≥60%`) → overturned by `read_hs` 93%
3. Topic 1's `buf_accumulate` prediction → overturned by `qpack_decode_us` (call-site) at 95%

**Implication for next spec:** target the `_dec.decode` call-path — but **diagnose before optimising**. Sub-sub-leg the decoder body (varint / table-lookup / result-alloc / String construction) AND consider an isolated microbench to separate "Mojo call/copy/alloc overhead" from "algorithmic QPACK". Otherwise we'll be predicting again. Topic 2's `_drain_stream` optimisations (`extend(Span)`, `ref slot = d[k]`, head-cursor) account for ~1% combined and are below bench harness sensitivity floor — not the right primary target.

## Built vs. planned

| Plan task | Built | Notes |
|---|---|---|
| T0 — branch + pre-baselines + 6 sidecars + image isolation + flag revert | ✓ + extras | Added bind-mount + SIGTERM grace fixes (see D1 below) |
| T1 — profile.mojo 5 fields + 5 record methods + helper + JSON/text emit + 5 tests | ✓ | All TDD steps green; ✅ CLEAN review |
| T2 — connection.mojo 7 brackets | ✓ | All exit sites covered; ✅ CLEAN review |
| T3 — sum-invariant + overshoot-clamp tests | ✓ | +2 tests; ✅ CLEAN review |
| T4 — smoke gate ±2.0% on/off-build both cells | ✓ + diagnostic detour | All 4 cells PASS same-window; original off-window measurements showed spurious -8% / -9.8% (see D2) |
| T5 — SIGINT sidecar capture + Hard Gates 1/5/6 verdict | ✓ | All gates PASS |
| T6 — REFERENCE.md row + flag revert + project-context advance + final review | ✓ | Final review CLEAN |

**Test count:** 48 → 55 PASS (anchor matched).
**Source LoC:** ~150 across `src/quic/profile.mojo` (+62), `src/h3/connection.mojo` (+87), `tests/test_quic_profile.mojo` (+~120). Bench infra: +8 `bench/quic_perf/scripts/*`.
**Commits:** 7 (T0 + T1 + T2 + T3 + T5 + T6 + initial spec/plan/research commit at branch creation).
**Walltime:** ~6 hours (4-5h docker builds + bench captures + diagnostic detour for host-noise; ~30 min implementation in subagents).

## Deviations and why

### D1. Bench sidecar bind-mount infrastructure was missing — added in T0

**What:** Q1's `bench/quic_perf/scripts/start-server.sh` did NOT bind-mount `bench/quic_perf/results/profile/` from the host. PROFILE_ACCEPT-on bench server writes its SIGINT-handler sidecar to `/app/bench/quic_perf/results/profile/INSTRUMENTATION-<ts>.json` inside the container, which gets destroyed by `docker rm -f`. Q1 must have used a manual `docker cp` step that wasn't captured in any committed code or plan documentation. T0 had to:
1. Add the bind mount: `-v "$REPO_ROOT/bench/quic_perf/results/profile:/app/bench/quic_perf/results/profile"` (mojo-net case only — TQUIC unaffected).
2. Switch `stop-server.sh` from `docker rm -f` (sends SIGKILL after 10s grace) to `docker stop -t 10` followed by `docker rm -f`. The explicit grace lets the SIGINT/SIGTERM signal handler in `bench/h3_server.mojo:_profile_install_signal_handlers` flush the sidecar before the container is force-killed.

**Why this matters:** Without these fixes, no PROFILE_ACCEPT-on diagnostic spec could capture sidecars going forward. T0 was the first time this was discovered — Q1's pass must have worked through some local convenience that wasn't committed.

**Cost:** ~30 min to discover + verify + fix. Bind-mount + stop-with-grace are now permanent infrastructure improvements.

### D2. Host noise across measurement windows — spurious 8-10% drift

**What:** T4's first round of post-baseline captures (loadavg 2.0+) showed -8.0% on-build long-conn drift and -9.8% off-build long-conn drift versus T0's pre-baselines (loadavg 1.5). Both gates initially FAILED. Stability check (re-running the SAME pre-image under T4's load window) confirmed the same image showed 14,581 → 13,712 rps drift purely from loadavg shift. After re-measuring pre-baselines under the same load window:
- on-build long-conn: pre 13,452 → post 13,641 = **+1.4%** ✅ PASS
- off-build long-conn: pre 13,712 → post 13,790 = **+0.6%** ✅ PASS (proves comptime elision; PROFILE_ACCEPT=False off-build path is functionally identical to pre-T2 binary)

**Why this matters:** The plan's measurement protocol assumed pre and post baselines could be captured hours apart. The long-conn cell is host-noise-sensitive at ~7% intrinsic floor (loadavg-dependent). Future diagnostic plans should require pre+post captured back-to-back under the same load window.

**Cost:** ~30 min of stability sanity-check rerun + analysis + 2 extra bench cells. Same-window pre-rerun was the right call (the spec said "halt; re-run pre-baselines once for stability sanity (3 iters); if persistent, escalate" — this is the codified protocol).

### D3. Both research predictions overturned — diagnostic deliverable inverted

See "Headline" above. Recorded as **D3** here for retrospective bookkeeping. The retrospective records this overturn openly because that's the entire point of recording predictions.

The user's decision at brainstorming time to **NOT record a predicted dominant phase** (overriding my recommendation in §4 of decisions) turned out to be wise — the spec/REFERENCE.md/evidence files don't carry confirm/overturn framing for the dominant phase, only the actual finding. Topic 1's structural-difference argument is recorded as a research finding with its predicted dominance overturned, not as a spec-level prediction.

### D4. Build script tags wrong image name

**What:** `bench/build.sh` produces `httparena-mojo-net:latest`, NOT `mojo-net-bench:latest`. The plan's T4 step assumed `bench/build.sh` would emit `mojo-net-bench:latest` directly. Manual re-tag step required after each build:
```bash
docker tag httparena-mojo-net:latest mojo-net-bench:drain-subleg-post-off
docker tag httparena-mojo-net:latest mojo-net-bench:latest
```

**Cost:** ~5 min × 2 builds. Recorded for next spec's plan. Q1 must have hit this and worked around it manually.

## Pain points

1. **Auto mode + bench captures don't compose well.** Each bench cell is ~6 minutes wall-time, and the docker build is ~5 minutes. Auto mode doesn't allow polling/sleeping during these waits — I have to issue a `run_in_background` and wait for completion notification. Six bench cells × stability rerun = significant elapsed time.
2. **Host noise dominates the bench harness.** A 7% intrinsic noise floor on long-conn means any drift gate <10% is fragile. Q1 was lucky to capture in a quiet window.
3. **Topic 1's prediction was so confident** that it nearly drove a wrong follow-on plan (target the `_H3StreamBuf.buf` accumulator). User's decision to skip prediction recording was load-bearing — without it the retro would frame this as "prediction wrong, what should we do next" instead of "let the data speak; here's what dominates."
4. **No PROFILE_DUMP_PATH override path.** The bench server writes sidecars with hardcoded path + auto-generated timestamp filename. Captured sidecars must be RENAMED post-hoc to add the per-iter context. Plan should have called this out.

## Open questions for follow-on specs

1. **What:** Where inside `self._dec.decode(frame.payload)` does the ~50 μs/HEADERS-frame wall-clock go? Our B5 bracket measures the call-site end-to-end but cannot distinguish: (a) algorithmic QPACK work — varint length-prefix + 99-entry static-table lookup + Huffman; (b) per-call allocation — `List[QpackHeaderField]` result + per-header String name/value construction; (c) Mojo parameter-passing overhead — implicit copy of `frame.payload: List[UInt8]` if `decode` doesn't borrow; (d) Some other Mojo runtime cost not visible in the source.
   **Severity:** **required-later** (this IS the long-conn bottleneck — next opt-spec target).
   **Trigger:** Next QPACK-decoder diagnostic spec (NOT optimisation spec — predict-then-optimise has a 0/3 record on this codebase). Methodology: (i) read `src/h3/qpack.mojo` end-to-end (single file containing both `QpackEncoder` and `QpackDecoder` structs; the static-only decoder is at `src/h3/qpack.mojo:750`) with no prior assumption about which sub-step dominates; (ii) add 4-5 sub-sub-leg timers inside the decoder body matching the candidate angles above; (iii) write an isolated microbench that calls `decode()` in a tight loop with synthetic inputs to separate "amortised algorithmic cost" from "per-invocation overhead"; (iv) capture under same-window bench protocol per D2; (v) only THEN write the optimisation spec.

2. **What:** Topic 2's optimisations (`extend(Span)`, `ref slot = d[k]`, head-cursor pattern in `_H3StreamBuf`) are valid micro-improvements but account for only ~1% of `drain_stream_us_total`.
   **Severity:** optional.
   **Trigger:** Either (a) after the QPACK refactor lands, if remaining `_drain_stream` cost is still bottlenecking; or (b) part of a Sprint-3 H3 hot-path streamlining pass that bundles many <2% wins together.

3. **What:** Bench harness host-noise sensitivity (~7% intrinsic floor on long-conn under varying load). Same-window pre+post protocol works around it; doesn't fix it.
   **Severity:** optional.
   **Trigger:** Any future diagnostic spec where the predicted RPS gate threshold is <5%. Investigate CPU pinning (`taskset` more aggressively?), realtime priority on bench server, or run benches inside a `cgcreate -g cpu:bench-isolated` cgroup.

4. **What:** Q1 left-over from this pass: `quic_post_recv_us` includes `_quic.timeout(now)` + the poll-loop dispatch ALONGSIDE `_drain_stream`. Our new `drain_stream_us_total` covers only `_drain_stream`. The gap (`quic_post_recv_us` ~22.7M μs minus `drain_stream_us_total` ~22.2M μs = ~500k μs ≈ 2.2%) is the timeout + poll-loop work.
   **Severity:** optional.
   **Trigger:** If next-pass QPACK refactor lands and `_drain_stream` drops to <50% of `quic_post_recv_us`, consider sub-bracketing the remaining post_recv work.

## Next spec recommendation

**Q-qpack-decode-subleg** — DIAGNOSTIC-first sub-leg pass on `self._dec.decode(...)`. Goal: name what fraction of the 50 μs/HEADERS-frame is algorithmic QPACK work vs allocation vs Mojo call overhead. ~4-5 sub-sub-leg timers inside `src/h3/qpack.mojo` + an isolated microbench cross-check. Only AFTER this lands should an optimisation spec be written. Methodology refinements (codify into the spec template): (a) drop dominant-phase prediction entirely — record candidate angles, not rankings; (b) require same-window pre+post bench captures back-to-back per D2; (c) require an isolated microbench cross-check whenever a single function call is the named target (so we can tell amortised algorithmic cost apart from per-invocation overhead).

**Followup options to bundle if QPACK refactor doesn't fully close the gap:**
- Topic 2's `_drain_stream` micro-optimisations (small wins; bundle for a Sprint-3 H3 streamlining pass)
- Q2 — TLS 1.3 session resumption for short-conn (still the named ffi_read_hs target from sub-leg pass)
- Sprint 3 — InlineArray streams + SIMD primitives + extended zero-copy on `H3HandlerServer`

## Reusable lessons

1. **Inspection-driven dominant-phase prediction has a 0/3 track record. Stop predicting.** Future diagnostic specs should either (a) skip the prediction entirely, OR (b) frame it explicitly as a falsifiable hypothesis with a "the retrospective will record what's actually true" caveat.
2. **Same-window pre+post bench protocol** for any drift-gated diagnostic pass. Two captures hours apart on this host can show 7%+ spurious drift purely from loadavg shift.
3. **Bench infrastructure changes from a previous pass may not be committed.** Q1's manual `docker cp` workflow wasn't in code. T0 should always smoke-test the sidecar capture path BEFORE running 10-iter pre-baselines.
4. **Build-tag mismatch (`httparena-mojo-net` vs `mojo-net-bench:latest`)** is now a recurring lesson. Either fix `bench/build.sh` to emit the right tag, or add a `--retag` flag, or codify the manual `docker tag` step in the plan.
5. **Architectural critique vs magnitude.** Topic 1 was structurally right that mojo-net's `_H3StreamBuf` accumulator is novel and inefficient by reference-stack standards. But novel-and-inefficient at ~1% of drain time means it's NOT the bottleneck. Magnitude estimation is harder than structural analysis; lean on measurement, not architecture.
