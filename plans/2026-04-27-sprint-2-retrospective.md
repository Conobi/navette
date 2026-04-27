# Sprint 2 Retrospective — Path A across H1/H2/H3 + tiered streaming on H2 + H3

**Sprint:** 2
**Spec:** `specs/2026-04-27-sprint-2-h1h2h3-sync-streaming.md`
**Plans:** `plans/2026-04-27-sprint-2a-h1h3-sync.md` + `plans/2026-04-27-sprint-2b-streaming.md`
**Branch:** `feat/h2-state-machine-path-a`
**Date completed:** 2026-04-27
**Total commits:** ~21 (10 Plan 2A + ~11 Plan 2B including this retro + push)
**Sprint 2 status:** ✅ Closed; one task DESCOPED (2.17 H3 RPS lift), one task DEFERRED (3.3 bench regression — to follow-up commit on this PR).

This retrospective consolidates Plan 2A's working retro note (`plans/2026-04-27-sprint-2a-retro-notes.md`) and adds Plan 2B sections.

---

## Sprint 2 outcomes by plan

### Plan 2A — H1/H3 sync (✅ shipped, 10 commits, range `b0b9ea2..9faa1d2`)

- **Phase 0 — pre-Sprint-2 prerequisites.** 2 doc-update commits. Sprint 1 row added to project-context active-specs table; line 33 `src/io/` exception relaxed to record Sprint 1's deliberate `boucle.completion` import; Mojo pin to "0.26.2 or later (currently 0.26.3 nightly)". Second commit narrowed an over-prescribed line-34 wording introduced by Plan 2A's Task 0.2 (recorded as Plan 2A process lesson).

- **Phase 1 — H1 sync wiring + per-conn allocation audit.** `bench/h1_server.mojo` migrated from raw `CompletionLoop` to `IoUring[H]`. Allocator-pressure audit using `wrk -d 30s -c 256 -t 4 http://localhost:8080/baseline2?a=1&b=2` + `perf record -F 200 -g`. Trigger scorecard: malloc-CPU 2.96% (MISS, vs 7.93% H2 reference), allocs/req N/A (`_heap_alloc[H1Conn]` inlined out of perf samples), `/json/50` regression N/A (no Sprint 1 H1 baseline). **POOL=NO**; Tasks 1.5–1.8 skipped per plan routing. H1 `/baseline2` single-run RPS: 98,722 (contextual data point).

- **Phase 2 — H3 coro→sync mirror (largest single piece).** 605-line rewrite mirroring Sprint 1's H2 sync server over QUIC. R8 ctx=600 B (<1024 B compile-time assert). Plan deviation captured: single `_h3: H3Connection` field instead of separate `_quic: QuicConnection` + `_h3` because `H3Connection` already owns `QuicConnection` internally; double-ownership avoided. Day-3 audit classified the 5 H3 coro tests as 2 REWRITE + 3 MOVE + 0 DELETE; the 3 MOVE tests stashed in `tests/_h3_streaming_pending.mojo` for Plan 2B (later deleted in Plan 2A Task 2.18 because of the broken import; retrieval path: `git show e775866:tests/_h3_streaming_pending.mojo`). Old `src/h3/h3_coro_server.mojo` + `tests/test_h3_coro_server.mojo` deleted; full src + conformance + reverse-proxy suites run; pre-existing TLS-symbol failures confirmed not regressions.

- **Phase 3 — validate + retro + push.** HttpArena `validate.sh` absent from repo (Task 3.1 DEFERRED to Plan 2B). Plan 2A working retro note written. Branch pushed to origin (no PR — Plan 2B continues on same branch).

### Plan 2B — H2 rename + tiered streaming on H2 + H3 (✅ shipped, 8+ commits, range `9faa1d2..adda005`)

- **Phase 0 — audits + rename.** `H2Connection.send_data` audit: shape (d) (silently queues oversized writes in `_pending_data`, drains on inbound `WINDOW_UPDATE`); NO precursor `H2SendResult` enum needed. `h2_coro_server.mojo` → `h2_sync_server.mojo` rename (file-only; struct name `H2CoroServer` preserved). 2-commit rename split (copy+delete vs single `git mv`) — partial `git log --follow` history fragmentation; recorded as Minor.

- **Phase 1 — H3 streaming server (canonical-shape first).** 762-line streaming server using `boucle.stackful.CoroutinePool`. Ctx=640 B (<96 KiB R8'). Streaming-handler API helpers (`next_chunk`, `write_chunk`, `finish`, `cancelled`) as free functions taking `ctx_ptr` + `yld`. **Option A `write_chunk`**: no WouldBlock handling — neither H2 nor H3 surfaces FC backpressure, so the streaming server buffers chunks via `ctx.resp_writer.try_send_body(...)` and trusts the codec/transport layer to absorb. 4 H3 streaming tests (3 ports of pre-Sprint-1 stashed tests + 1 cancellation test). TDD caught two real lifecycle bugs in chunk 2's H3 streaming server (`finish()` premature `response_ended`; `_resume_stream` immediate free on coro DONE) — fixed in same commit as the tests that revealed them. H3 streaming bench harness on UDP 8444; smoke: HTTP 200, multi-chunk SSE.

- **Phase 2 — H2 streaming server (mirror of H3).** 814-line H2 mirror inheriting chunk-3's lifecycle fixups directly. 4 H2 streaming tests. `bench/streaming_handler.mojo` extended with `llm_stream_h2_handler`. H2 streaming bench harness on TCP 8445; smoke: HTTP 200, multi-chunk SSE. Both `llm_stream_h3_handler` and `llm_stream_h2_handler` call `send_status` before `write_chunk` (protocol-correct; HEADERS frame with `:status` is mandatory before DATA in both H2 and H3).

- **Phase 3 — gate + retro + push.** R1' grep gate codified in `scripts/run_tests.sh`:
  ```
  R1_VIOLATIONS=$(grep -rEn 'boucle\.stackful' src/ \
    | grep -vE '^src/(h2/h2_streaming_server|h3/h3_streaming_server)\.mojo:' \
    | grep -vE '^src/tls/lib\.mojo:' \
    || true)
  ```
  Currently passes (zero matches outside allowed files). HttpArena `validate.sh` re-checked, still absent — DEFERRED. This retrospective.

---

## DESCOPED — Plan 2A Task 2.17 (H3 +15-25% RPS lift)

The spec's "+15-25% RPS lift on H3 sync" target had **no execution path**. `bench/h3_server.mojo` has used `H3HandlerServer` (sync-shaped) since commit `5bf1812` introduced the io_uring multishot recvmsg engine. `H3CoroServer` was never wired into the io_uring-era H3 bench. The sync mirror landed in `src/h3/h3_sync_server.mojo` as a 605-line companion module that no production traffic path exercises.

The H3 sync mirror still ships as **API-symmetry + R-rules-conformance** work:
- API surface across H1/H2/H3 sync handlers is uniform (mirrors Sprint 1's H2 pattern).
- R8 budget held at 600 B / <1024 B compile-time assert.
- `boucle.stackful` removed from `src/h3/h3_sync_server.mojo`; passes R1' grep gate.
- Tests pass; build clean; no regressions.

**Lesson saved to auto-memory** (`feedback_perf_lift_verification.md`):

> When a spec or plan claims a measurable performance improvement (RPS lift, latency reduction, memory drop, etc.), two things are non-negotiable:
> 1. The spec MUST name the exact module/function/code path the lift applies to.
> 2. The spec review MUST verify that named code path is actually on the bench/production hot path.
>
> A 5-minute `grep -n '<module-the-spec-names>' bench/<protocol-bench>.mojo` is the bar. Cost of skipping the check: hours of dead-bench code on a misframed perf claim.

---

## DEFERRED — Plan 2B Task 3.3 (3-run regression + streaming smoke baselines)

The 120s × 3-run sync regression bench cells (re-running H2 sync + H3 sync benches to confirm no regression vs Sprint 1 baselines) and low-concurrency streaming smoke captures (latency p50/p95 + tokens-per-sec on H2 + H3 streaming benches) are **deferred to a follow-up commit on this PR**.

The streaming-server single-request smoke tests (chunk 3 H3 + chunk 4 H2) both confirmed end-to-end functionality — sufficient evidence for PR review. The 3-run baselines are forward-tracking data, not a merge gate.

**Trigger:** when reviewer requests baseline numbers, or before the next Sprint 3 perf work begins (whichever comes first).

---

## Spec D4 correction (Plan 2B chunk 2 finding)

**Spec D4 said:** *"Streaming handler signature identical across H2 and H3: `fn(ctx_ptr: UnsafePointer[StreamingCtx], mut yld: CoroYielder) raises -> None`"*.

**Boucle's actual API:** `comptime CoroBody = fn(mut CoroYielder) raises -> None` (no ctx parameter — boucle does not permit a ctx-pointer first argument on the function-pointer type).

**Forced API correction:**
- Handler signature: `fn(mut yld: CoroYielder) raises -> None`
- Ctx access inside handler: `var ctx_ptr = yld.user_data().bitcast[StreamingCtx]().as_any_origin()`

The "identical signature across H2 and H3" promise still holds — both tiers use boucle's `CoroBody`. Just the spec's literal text was wrong about the parameter shape.

**Action item:** user-facing docs (Sprint 4 polish) must reflect this correction.

---

## Other process lessons

- **Spec/plan-vs-code drift** (3 occurrences):
  1. **Plan 2A bench-import claim.** Plan 2A claimed Sprint 1 had migrated `bench/h2_server.mojo` to `IoUring`. Verified during chunk-3a review that it had not — only the H2 protocol-layer `H2CoroServer` was migrated, not the bench harness. Recorded as DEFERRED follow-up.
  2. **Plan 2A `H3HandlerServer` wrap-not-duplicate prediction.** Plan 2A predicted the H3 sync server could wrap helpers from `H3HandlerServer`. Verified during chunk 2 that `H3HandlerServer._H3StreamCtx` is private and structurally incompatible with the new sync server's `CoroStreamCtx`. Sprint 4 polish item: port `_H3StreamCtx` to public so future work can wrap rather than duplicate.
  3. **Spec D4 handler signature.** See "Spec D4 correction" above.

- **Plan-text accuracy.** Plan 2A Task 0.2 over-prescribed line-34 wording, requiring a second narrowing commit. Plan-write should track spec wording exactly, not augment beyond what the spec authorized.

- **Subagent dispatch chunking.** Plan 2A Phase 2's 18 tasks were split into 3 chunks (audit+stash+skeleton, server rewrite, wiring+delete+verify) — each completed in one dispatch. Plan 2B Phase 2's 4 tasks fragmented across 3 dispatches because of token budget hits when one dispatch attempted all of (mirror server + tests + bench + handler extension). **Lesson:** for chunks crossing 600+ LoC of new code AND test creation AND bench harness creation, plan for 2-3 dispatches per chunk rather than expecting one to complete.

- **TDD positive signal.** Chunk 3's H3 streaming tests drove out two real lifecycle bugs in chunk 2's H3 streaming server. The fixes were minimal corrections (not introduce-then-fix). The H2 mirror in chunk 4 was structurally cleaner because it inherited the chunk-3 fixups directly via the canonical reference. Net: writing tests AFTER the streaming server skeleton (rather than test-first within the streaming server build itself) still surfaced all real bugs once the test fixtures actually exercised the code paths.

- **Two-commit rename split.** Plan 2B Task 0.2's H2 rename was implemented as copy+delete across two commits instead of a single `git mv`, partially fragmenting `git log --follow` history. Functionally correct; minor cosmetic loss.

---

## DEFERRED items rolled forward

| What | Severity | Trigger |
|---|---|---|
| `bench/h2_server.mojo` IoUring migration | required-later | Sprint 4 polish — H1 was migrated in Plan 2A; H2 + H3 benches still on raw `CompletionLoop` |
| `bench/h3_server.mojo` IoUring migration | required-later | Sprint 4 polish (same as above) |
| HttpArena `validate.sh` provenance | required-later | Investigate next sprint — script absent from repo despite spec reference; was it removed? renamed? meant to be added by another track? |
| `H3HandlerServer._H3StreamCtx` ↔ `h3_sync_server.CoroStreamCtx` duplication | optional | Sprint 4 — port `_H3StreamCtx` to public so adapters can wrap rather than duplicate |
| `_cleanup_stream` bypasses pool on RST_STREAM (H2 + H3 sync) | optional | Sprint 4 — same asymmetry exists in both sync servers |
| `fn` keyword deprecation warnings (codebase-wide) | optional | Sprint 4 — sweep `fn` → `def` codebase-wide |
| Stash file (`tests/_h3_streaming_pending.mojo`) lifecycle | n/a | Plan 2A created it; Plan 2A deleted it (broken import after `H3CoroServer` removal); retrieval via `git show e775866:tests/_h3_streaming_pending.mojo` if ever needed |
| 3-run regression bench + streaming smoke baselines | this PR | Follow-up commit on this PR |
| User-facing docs for streaming-handler API (Spec D4 correction) | required-later | Sprint 4 polish — docs must reflect `fn(mut yld)` shape with ctx-via-`user_data` |
| H2 unbounded `_pending_data` queueing on slow consumers | optional | Sprint 3+ — Option A streaming `write_chunk` accepts unbounded buffering as known limitation; production-correct watermarking is future work |
| Renaming `H1HandlerServer` → `H1SyncServer`, `H2CoroServer` → `H2SyncServer`, `H3CoroServer` (sync) → `H3SyncServer` | optional | Sprint 4 polish — naming consistency; deferred from Plan 2B Task 0.2 to minimise blast radius |
| Pre-existing test failures (`test_tls_connection`, `test_h2_tls_alpn`, `test_hpack_roundtrip`) | required-later | Operational pass — `lib/librustls_mojo.so` symlink + missing FFI symbol `rlsm_client_config_new_insecure` |

---

## Sprint 3 input

The sync handler shape is now uniform across H1/H2/H3, validated by tests, with R-rules R1' + R8 + R8' all enforced mechanically. Streaming-handler API contract is locked across both protocols (boucle's `CoroBody` shape).

Sprint 3's planned work (InlineArray streams + SIMD primitives + extended zero-copy) targets the **H3 hot path**, which is `H3HandlerServer` — same module as before this sprint, with the new `H3CoroServer` (sync) and `H3StreamingServer` modules now living alongside it. Bench wiring decisions for Sprint 3 must follow the lesson from Plan 2A Task 2.17: name the exact module the lift applies to + verify it's on the bench's hot path before approving the spec.
