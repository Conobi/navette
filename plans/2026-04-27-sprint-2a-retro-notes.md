# Plan 2A — Working Retro Note (input to Sprint 2 retrospective)

**Plan:** `plans/2026-04-27-sprint-2a-h1h3-sync.md`
**Branch:** `feat/h2-state-machine-path-a`
**Commit range:** `b0b9ea2..3a0f963` (9 commits)
**Date completed:** 2026-04-27
**Status:** ✅ Closed for Plan 2A; one task DESCOPED, one DEFERRED.

This is a working note. The consolidated Sprint 2 retrospective (after Plan 2B) integrates this.

---

## Outcomes by phase

### Phase 0 — Pre-Sprint-2 prerequisites (✅)

- Sprint 1 row added to `docs/project-context.md` Active specs and plans table.
- Line 33 (`src/io/` exception) explicitly relaxed to record Sprint 1's deliberate `boucle.completion` import in `src/io/io_uring.mojo`.
- Line 121 Mojo pin updated from "0.26.2" to "0.26.2 or later (currently 0.26.3 nightly)".
- Two commits (`ecacd6f`, `ea5c144`) — second commit narrowed an over-expanded line-34 wording I had over-prescribed in Plan 2A Task 0.2.

### Phase 1 — H1 sync wiring + audit (✅, POOL=NO)

- `bench/h1_server.mojo` migrated from raw `CompletionLoop` to `IoUring[H]` (commit `7232d60`).
- Allocator-pressure audit (commit `bcb322a`) using `wrk -d 30s -c 256 -t 4` against `/baseline2?a=1&b=2`, with `perf record -F 200` sampling for 20s.
- Trigger scorecard:
  - Trigger 1 (malloc-CPU%): MISS — 2.96% (sum of TCMallocInternalCfree 1.46% + AlignedAlloc 0.54% + List::_realloc 0.96%); H2 reference per `bench/profile/baselines/h2-hotspots-174aed8.md` was 7.93%.
  - Trigger 2 (allocs/req): N/A — `_heap_alloc[H1Conn]` inlined; insufficient perf samples.
  - Trigger 3 (json/50 regression): N/A — no Sprint 1 H1 baseline existed.
- POOL=NO. Tasks 1.5–1.8 skipped per Plan 2A's routing logic.
- Single-run RPS: 98,722 req/s (contextual data point only; not a 3-run median).

### Phase 2 — H3 sync mirror (⚠️ shipped but with major plan-level finding)

- Day-3 audit (commit `e775866`): 5 H3 coro tests classified — 2 REWRITE (`test_h3_coro_simple_get`, `test_h3_coro_goaway`) + 3 MOVE (post_with_body, trailers, rst_stream) + 0 DELETE.
- Stash file `tests/_h3_streaming_pending.mojo` created with the 3 MOVE tests, `_coro_` infix replaced with `_streaming_`. Unregistered in `scripts/run_tests.sh`. **Deleted in Plan 2A Task 2.18 chunk** because it imported the now-removed `H3CoroServer`. **Plan 2B Task 1.11 must retrieve verbatim source via `git show e775866:tests/_h3_streaming_pending.mojo`.**
- Skeleton commit (`871672d`): `src/h3/h3_sync_server.mojo` created with imports + module docstring only.
- Server rewrite (`f3d8646`): 605 lines mirroring Sprint 1's `src/h2/h2_coro_server.mojo` over QUIC. `H3CoroServer` struct preserved (file rename without struct rename). `CoroStreamCtx` size = 600 B (R8 budget < 1024 B passed). One plan deviation: single `_h3: H3Connection` field instead of separate `_quic: QuicConnection` + `_h3` — `H3Connection` already owns `QuicConnection` internally; double-ownership avoided. Plan was wrong; implementation right.
- Wiring commit (`b306853`): `src/h3/__init__.mojo` re-exports from new file; `tests/test_h3_sync_server.mojo` ports the 2 REWRITE tests; `bench/handler.mojo::bench_h3_body_fn` rewritten to sync ctx-pointer shape.
- Cleanup commit (`3a0f963`): old `src/h3/h3_coro_server.mojo` + `tests/test_h3_coro_server.mojo` deleted; full src tests + conformance + reverse-proxy run.

### Phase 3 — Validation + retro + push (✅ partial)

- Task 3.1 HttpArena `validate.sh`: **DEFERRED** — script does not exist in the repo. Plan 2B retrospective should investigate (was it removed? was the spec citing a non-existent script? was it always meant to be added by another track?).
- Task 3.2 (this note): ✅ written.
- Task 3.3 push: ✅ branch pushed to origin (no PR opened — Plan 2B continues on the same branch).

---

## DESCOPED — Task 2.17 H3 sync RPS lift measurement

The spec's "+15-25% RPS lift on H3 sync" target had **no execution path** in this codebase. `bench/h3_server.mojo` has used `H3HandlerServer` (sync-shaped already) since commit `5bf1812` introduced the io_uring multishot recvmsg engine. `H3CoroServer` was never wired into the io_uring-era H3 bench. Mirroring the H3 protocol layer to sync (605 lines of new code in `src/h3/h3_sync_server.mojo`) does not affect any traffic path the bench measures.

The H3 sync mirror's actual deliverables:
- API symmetry: H3 surface now matches Sprint 1's H2 pattern.
- R8 budget held at 600 B / < 1024 B (compile-time assert).
- `boucle.stackful` removed from `src/h3/h3_sync_server.mojo` — passes Plan 2B's R1' grep gate.
- Code-quality + R-rules-conformance win, NOT a perf win.

The spec's lift assumption was generalized from H2 (where Sprint 1's bench DID use the coro path) to H3 (where the bench had moved off the coro path long before Sprint 1). Neither the spec-write phase nor the spec-review phase verified the H3 bench's actual import. A 5-minute `grep -n 'H3CoroServer\|H3HandlerServer' bench/h3_server.mojo` at spec time would have surfaced this.

**Lesson recorded to auto-memory** (`feedback_perf_lift_verification.md`): for any spec claiming a perf lift, the spec MUST cite the exact module the lift applies to, AND the spec review MUST verify that module is on the bench/production hot path before approving.

---

## DEFERRED items for Plan 2B / Sprint 2.5 / Sprint 4

| What | Severity | Trigger |
|---|---|---|
| `H3SendResult` precursor commit | optional | Plan 2B Day-9 audit pre-answered: `H3Connection.send_data(stream_id, data, fin) raises` does NOT return WouldBlock; FC is fully QUIC-internal. Plan 2B can call unconditionally. |
| `bench/h2_server.mojo` IoUring migration | required-later | Plan 2B Phase 0 (H2 rename day) is the natural place — h2_server is still on raw `CompletionLoop` despite being a Sprint 1 deliverable claim |
| HttpArena `validate.sh` provenance | required-later | Plan 2B retrospective — investigate whether the script was removed, never added, or referenced under a different name |
| `_cleanup_stream` bypasses `_ctx_pool.release` on RST_STREAM | optional | Sprint 4 polish (same asymmetry exists in Sprint 1's H2 sister file) |
| `H3HandlerServer` private `_H3StreamCtx` duplication with `h3_sync_server.CoroStreamCtx` | optional | Sprint 4 polish — port `_H3StreamCtx` to public `CoroStreamCtx` so wrapping replaces duplication |
| `fn` keyword deprecation warnings (codebase-wide) | optional | Sprint 4 polish — convert all `fn` → `def` in a single sweep |
| Pre-existing test failures: `test_tls_connection`, `test_h2_tls_alpn`, conformance `test_hpack_roundtrip` | required-later | Operational — likely `lib/librustls_mojo.so` symlink + missing FFI symbols (`rlsm_client_config_new_insecure`). Need a separate operational pass to fix the lib link. NOT caused by Plan 2A. |

---

## Plan 2B planning inputs

Three findings from this plan that Plan 2B's planning consumes:

1. **`H3Connection.send_data` shape** — verified during Phase 2: `(stream_id, data, fin) raises`. NO `WouldBlock` return. Plan 2B Task 1.1 (Day-9 prerequisite audit) is pre-answered: do NOT add `H3SendResult`. The streaming server can call `send_data` unconditionally; backpressure surfaces via QUIC's transport-level FC and the handler doesn't observe it directly.

2. **`_h3_streaming_pending.mojo` retrieval path** — Plan 2B Task 1.11 must read the file via `git show e775866:tests/_h3_streaming_pending.mojo` (file deleted in `3a0f963` because it imported the removed `H3CoroServer`).

3. **`H3HandlerServer` already covers the bench's H3 hot path** — any "+lift" target for H3 streaming work in Plan 2B should similarly be measured against `H3HandlerServer`-shape benches, not `H3CoroServer`-shape. The streaming server is a separate sub-API; bench wiring for it must be designed deliberately.

---

## Process lessons (for the consolidated Sprint 2 retrospective)

- **Spec/plan-vs-code drift:** the spec made claims about bench wiring that didn't match reality. The independent spec reviewer caught I3 ("perf-lift target fragility") but accepted "use long-conn cell" as the fix without verifying which module the long-conn cell exercised. A grep-the-bench-import step belongs in every spec-review checklist where a perf lift is claimed.
- **Plan-text accuracy:** Plan 2A Task 0.2 over-prescribed line-34 wording, requiring a second commit to narrow. Plan-write should track spec wording exactly, not augment.
- **Subagent dispatch chunking:** Phase 2's 18-task plan was split into 3 chunks (audit+stash+skeleton, server rewrite, wiring+delete+verify). Chunking by natural file-boundaries worked well; the largest single chunk (the rewrite) ran ~3 hours with one ✅ CLEAN review pass.
