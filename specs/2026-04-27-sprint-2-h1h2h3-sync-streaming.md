# Sprint 2 — Path A across H1/H2/H3 + tiered streaming on H2 + H3

**Spec date:** 2026-04-27
**Sprint duration:** 2 weeks (~10 working days, with ~13 days of estimated work — overrun acceptable for canonical-shape validation)
**Branch:** continues `feat/h2-state-machine-path-a` (Sprint 1 worktree)
**Mojo toolchain:** 0.26.2 or later. Sprint 1 already shipped `comptime assert` (0.26.2 syntax). Active development toolchain at spec time is `Mojo 0.26.3.0.dev2026042005` nightly; spec is forward-compatible with 0.26.3 stable when it lands. **`docs/project-context.md` line 121 (pinning 0.26.2) is stale and needs to be updated to "0.26.2 or later" before Sprint 2 lands** — see Pre-Sprint-2 prerequisites.

**Predecessor:** Sprint 1 — Path A H2 sync handler + Io trait + IoUring + CoroStreamCtxPool. 11 commits on `feat/h2-state-machine-path-a`, last `0ea3720`. Spec at `plans/2026-04-27-h2-perf-roadmap-sprint-sequence.md` and retrospective at `plans/2026-04-27-sprint-1-retrospective.md`. **`docs/project-context.md` does not yet record Sprint 1** — see Pre-Sprint-2 prerequisites.

**Successor:** Sprint 2.5 (H1 streaming companion if not folded in) → Sprint 3 (InlineArray streams + SIMD + extended zero-copy)

## Pre-Sprint-2 prerequisites (must be done before Day 1)

These are NOT Sprint 2 implementation work — they are corrective documentation updates to make Sprint 1's deliverables visible in the project's authoritative state:

1. **Add Sprint 1 row to `docs/project-context.md`** — under "Active specs and plans", recording the spec/plan paths, branch, commit range, and Sprint 1's measured baselines (`/baseline2` GM +47%, `/json/50` GM +7% across three pin configs). Without this, Sprint 2's "no regressions vs Sprint 1 baselines" acceptance criterion is unfalsifiable.
2. **Relax project-context line 33 explicitly** — Sprint 1 introduced `src/io/io_trait.mojo` and `src/io/io_uring.mojo`. Both import `boucle.handle.RawHandle` and `boucle.completion.{CompletionLoop, CompletionHandler, BufRing}`. This is a deliberate relaxation of the "no I/O imports inside `src/`" rule. The project-context line should be updated to: *"Sans-I/O at every protocol layer (`src/h1/`, `src/h2/`, `src/h3/`, `src/quic/`). The `src/io/` capability layer is the explicit exception — it owns the `Io` trait + `IoUring` impl and is the only place inside `src/` that imports `boucle.completion`."*
3. **Update project-context line 121** — change Mojo pin from "0.26.2" to "0.26.2 or later (currently 0.26.3 nightly)".

These three updates can ship as a single commit before Day 1, separate from Sprint 2 implementation.

## Goal

Land Path A's sync handler shape uniformly across H1, H2, and H3, then add an opt-in streaming-handler tier on H2 (most-multiplexed protocol) and H3 (canonical-shape protocol of mojo-net per `docs/project-context.md` line 54). Sprint 1 shipped Path A on H2 only. Sprint 2 makes the Io trait + sync handler the uniform foundation across the public API surface, and proves the streaming-handler API on the canonical-shape protocol before extending it.

H1 streaming companion is **deferred to Sprint 2.5** — H1's request/response shape (no multiplexing, no per-stream FC) has the lowest design risk and is straightforward to add once the API contract is locked on H2 + H3.

## Why now

Sprint 1's user review surfaced that streaming workloads (LLM responses, SSE, gRPC server-streaming, reverse proxies, file upload, chunked DB pagination, WebSocket-over-H2) are **30-60% of real production HTTP/2 traffic**. The Sprint 1 sync handler is correct for TechEmpower-shape REST traffic but inadequate for these workloads. Shipping mojo-net 1.0 without streaming-handler ergonomics would limit the project to micro-benchmark territory.

Additionally, the current state has H2 on Path A (Sprint 1) but H3 still on the pre-Sprint-1 stackful coro shape — an inconsistency that grows harder to clean up the longer it persists, and that blocks Sprint 3's planned InlineArray work on H3.

## Scope

### In scope

1. **H1 sync wiring + per-connection allocation audit** (~1.5 days)
   - Switch `bench/h1_server.mojo` from raw `CompletionLoop` to `IoUring[H]` for symmetry across all three protocols.
   - Profile H1 allocator pressure: count `_heap_alloc` invocations per request under bench load (`wrk -d 30s -c 256 -t 4 http://localhost:8080/baseline2`).
   - **Quantified threshold for "hot":** average ≥ 1 `_heap_alloc` per request, OR malloc-related symbols ≥ 5% of total CPU in `perf record` profile, OR cold-start `/json/50` cache-locality regression ≥ 5% in any pin config (mirrors Sprint 1 H2 audit thresholds).
   - If pressure exceeds any threshold above, add `H1StreamCtxPool(capacity=16)` mirroring Sprint 1's `CoroStreamCtxPool(capacity=16)`. Likely unlocks a Sprint-1-style cache-locality lift on H1's `/baseline2`.
   - `H1HandlerServer` itself does not change shape — it is already sync-shaped and `src/h1/` has no `boucle.stackful` imports.

2. **H3 sync mirror** (~5 days, the largest single piece)
   - **Day 3 audit (before any rewriting):** enumerate `tests/test_h3_coro_server.mojo` cases by name and classify each into one of: (a) DELETE — purely suspension-dependent, no observable behavior worth keeping; (b) MOVE to `tests/test_h3_streaming_server.mojo` — exercises suspend/resume; (c) REWRITE for sync — exercises non-suspension behavior (state transitions, error paths, cleanup, RST_STREAM) that must survive. Write the classification in the Day 3 commit message; do not silently drop tests.
   - Rewrite `src/h3/h3_coro_server.mojo` → `src/h3/h3_sync_server.mojo` mirroring Sprint 1's H2 Path A:
     - Drop `boucle.stackful` imports (`CoroHandle`, `CoroYielder`, `CoroBody`).
     - Drop `coro_addr` field from H3 stream context.
     - Replace `H3BodyFn = fn(...) -> CoroBody` with `H3BodyFn = fn(UnsafePointer[H3StreamCtx, MutAnyOrigin]) raises -> None`.
     - Add `H3StreamCtxPool(capacity=16)` for cache locality.
     - Add `_check_stream_ctx_size()` with `comptime assert size_of[H3StreamCtx]() < 1024` (R8).
   - Rewrite `bench/h3_server.mojo`'s body fn to the sync ctx-pointer signature (mirroring Sprint 1's `bench_h2_body_fn`).
   - Rewrite `tests/test_h3_coro_server.mojo` → `tests/test_h3_sync_server.mojo` per the Day 3 classification.
   - Same `Io` trait used by H2 + H3.

3. **Rename `src/h2/h2_coro_server.mojo` → `src/h2/h2_sync_server.mojo`** (~5 minutes — mechanical)
   - Sprint 1 removed all coroutines from this file. The name is now misleading and would actively confuse readers when `h2_streaming_server.mojo` (with coroutines) lands beside it.
   - Update imports in `bench/h2_server.mojo`, `tests/test_h2_*`, and any other call sites.
   - Rename `tests/test_h2_coro_server.mojo` → `tests/test_h2_sync_server.mojo`.

4. **H3 streaming server** (canonical-shape validation, ~2 days)
   - **Day 9 prerequisite audit (~2 hours, before writing the server):** verify `H3Connection`/`H3Session` exposes a non-blocking send-with-FC-signal. Required interface: `H3Connection.send_data(stream_id, bytes) raises -> SendResult` where `SendResult` is `Sent(n: Int) | WouldBlock | StreamClosed`. If the current M5b API only exposes blocking `send_data`, document the new method signature in this spec's "Open questions" section before proceeding and add it to the H3 codec layer (NOT to the streaming server) as a small precursor commit.
   - Create `src/h3/h3_streaming_server.mojo` — a parallel server type using `boucle.stackful.CoroutinePool`.
   - Restore the suspending body helpers + external-resume API removed in Sprint 1 (recover from git history; the deleted code is on `main`, not on this branch). Treat resurrection as an audited code-review pass: re-walk every signature against current types before re-applying.
   - Streaming connections pay 64 KiB/stream (pinned by `boucle.stackful` stack); sync H3 connections continue to pay <1024 B/stream (R8).
   - Apply R8' compile-time assert: `comptime assert size_of[H3StreamingCtx]() < 96 * 1024`.
   - Add `tests/test_h3_streaming_server.mojo` re-exercising suspending body emit + external resume against QUIC loopback.

5. **H2 streaming server** (~2 days, applies the H3-validated pattern)
   - Same Day-11 prerequisite audit applies for H2: verify `H2Connection.send_data` exposes `WouldBlock` on stream-window-full; if not, add it before writing the streaming server.
   - Create `src/h2/h2_streaming_server.mojo` mirroring `h3_streaming_server.mojo` over the H2 wire format.
   - Restore Sprint-1-deleted `H2BodyYieldFn` / suspending helpers / `resume_stream` API into this new file (NOT into `h2_sync_server.mojo`).
   - Apply R8' compile-time assert: `comptime assert size_of[H2StreamingCtx]() < 96 * 1024`.
   - Add `tests/test_h2_streaming_server.mojo` re-exercising the originally-disabled `test_body_yield` + `test_resume_stream` against the streaming server.

6. **Streaming bench fixtures + servers** (~1 day)
   - Add `bench/streaming_handler.mojo` — LLM-stream pattern (mock upstream emitting tokens on a timer), demonstrates multi-chunk body emission across handler suspends.
   - Add `bench/h3_streaming_server.mojo` — bench server entry-point that wires `streaming_handler.mojo` through `H3StreamingServer`.
   - Add `bench/h2_streaming_server.mojo` — same for H2.
   - Both new bench servers reuse `bench/streaming_handler.mojo` — single handler implementation, two protocol-level bench drivers.

7. **R1' grep gate** (~1 hour)
   - Codify acceptance check (anchored to specific allowed files, NOT a path-prefix regex):
     ```bash
     grep -rEn 'boucle\.stackful' src/ \
       | grep -vE '^src/(h2/h2_streaming_server|h3/h3_streaming_server)\.mojo:' \
       | grep -vE '^src/tls/lib\.mojo:'
     ```
     Must return zero matches. The `src/tls/lib.mojo` exclusion is for FFI-bridge use only (current Wave 1/2 code does not use stackful, but the slot is reserved per R1').
   - Tests live at repo-root `tests/`, NOT under `src/tests/` — they are not matched by the gate at all (the gate scopes to `src/`).
   - Add to `scripts/run_tests.sh` or equivalent so CI enforces the boundary.

### Out of scope (deferred)

- **H1 streaming server** (`h1_streaming_server.mojo`) — deferred to Sprint 2.5. H1's request/response shape (no multiplexing, no FC) is the simplest and easiest to add once H2 + H3 lock the API.
- **Path B comptime spike** — Mojo 0.26.3 nightly's `reflection` module exposes struct-field + function-name introspection only; no function-body access, no AST builders. The walls Sprint 1 hit are unmoved. Skip.
- **Streaming H2/H3 perf lift** — the deliverable is *shape*, not throughput. Benchmark numbers will be measured but no lift target is set; we expect parity with sync on idle paths and slight regression on suspending paths (the cost we accept for the streaming API).
- **Path C (Mojo upstream `co_await`)** — separate parallel track (open feature request). Not a Sprint 2 deliverable.
- **Renaming `H1HandlerServer` to `H1SyncServer`** — no shape change in H1 means the existing name is still accurate. Naming consistency across H1/H2/H3 deferred to Sprint 4 polish.

## Decisions captured

### D1. Path B comptime spike — **skipped**

Verified against active toolchain `Mojo 0.26.3.0.dev2026042005` (April 20, 2026 nightly). The 0.26.3 nightly does not change the metaprogramming surface relevant to Path B:
- The full `reflection` module exposes struct-field reflection (`struct_fields`), trait-conformance checks (`reflection.traits.All*`), and type/function-name introspection (`type_info`).
- **No function-body introspection, no AST builders, no `compile_string`/`eval`, no `@compile_time_function` macro mechanism.**
- T-strings (0.26.2) capture format strings + runtime args as `TString` values but cannot be materialised back into source code.
- `comptime if` / `comptime for` (0.26.2) are syntax replacements for `@parameter if`/`@parameter for`; same expressive power.

Path B's prerequisite — synthesising a `StreamState` struct + phase enum from a linearised handler description — requires capabilities Mojo does not currently expose. The spike's predicted outcome ("burn 2 days confirming Mojo 0.26 metaprogramming can't synthesise state machines") is unchanged by the nightly. The 2 days are better spent on Path A's H1+H3 mirror.

### D2. Sequencing — all three sync first, then streaming on H2 + H3

Locks Path A across H1/H2/H3 (proves Io trait works for all protocols), then adds the streaming tier across H2 + H3. This was the user's explicit sequencing call. Within the streaming week, **H3 streaming ships first** (D3 below).

### D3. H3 streaming before H2 streaming

H3 is the canonical-shape protocol per `docs/project-context.md` line 54. If QUIC's transport-level flow control (`MAX_STREAM_DATA`) fundamentally changes the streaming-handler ergonomics, we discover that before we've committed an H2-shaped API. Risk-reduction over familiarity.

### D4. Streaming handler signature identical across H2 and H3

```mojo
fn(ctx_ptr: UnsafePointer[StreamingCtx], mut yld: CoroYielder) raises -> None
```

User-facing helpers exposed via `StreamingCtx`:
- `body.next_chunk(mut yld) -> Optional[BodyFrame]` — yields next chunk; suspends if none ready, returns `None` on EOF
- `resp.write_chunk(mut yld, bytes)` — emits body chunk; suspends if writer-side window is full (H2 stream window via WINDOW_UPDATE; H3 QUIC FC via MAX_STREAM_DATA)
- `resp.finish(mut yld)` — closes the response body
- `ctx.cancelled() -> Bool` — handler polls between yields; true on RST_STREAM (H2) / STOP_SENDING (H3) / connection drop

The handler signature is **protocol-agnostic at the user level.** Wire-format specifics live in the codec layer beneath. This locks the user-facing "write once, run on H2 or H3" promise that v1.0 needs.

### D5. New file boundary `*_streaming_server.mojo` enforces R1'

The sync server (`h2_sync_server.mojo`, `h3_sync_server.mojo`) stays free of `boucle.stackful` imports. The streaming server (`h2_streaming_server.mojo`, `h3_streaming_server.mojo`) is the only place inside `src/` (besides FFI bridges and tests) where `boucle.stackful` is permitted. The grep gate (R1') verifies this mechanically.

### D6. Rename `h2_coro_server.mojo` → `h2_sync_server.mojo`

Sprint 1 removed all coroutines from this file. The current name is actively misleading. Renaming costs ~5 minutes and prevents months of "wait, why does the *coro* server have no coros?" confusion when `h2_streaming_server.mojo` (with coros) lands beside it. Naming-as-documentation matters at the public-API boundary.

### D7. H1 sync work = bench wiring + per-connection allocation audit (+ pool if hot)

H1's handler shape is already sync. The remaining lift opportunity is the same one Sprint 1 found on H2: per-connection cache locality via a free-list pool. Half a day of profiling work to discover whether H1 is allocator-bound under bench load; if yes, mirror the `CoroStreamCtxPool(16)` pattern as `H1StreamCtxPool(16)`. Unlocking even a 30% lift on H1 `/baseline2` is worth the investment.

### D8. R-rules — unchanged + new R8' for streaming ctx

- **R1':** `boucle.stackful` allowed only in `*_streaming_server.mojo` files inside `src/`, plus `src/tls/lib.mojo` (FFI bridge slot, currently unused). Tests at repo-root `tests/` are out of scope for the gate. Enforced via grep gate (see §7 above).
- **R8 (sync ctx):** `size_of[CoroStreamCtx]() < 1024 B` compile-time assert. Already shipped Sprint 1 for H2 via `comptime assert` in a `_check_stream_ctx_size()` helper (0.26.2+ syntax). Extended to H3 sync ctx in Sprint 2.
- **R8' (streaming ctx — NEW in Sprint 2):** `size_of[StreamingCtx]() < 96 KiB` compile-time assert. The 96 KiB ceiling reflects the 64 KiB `boucle.stackful` stack + ~16 KiB headroom for suspend state, yielder pointer, body-frame buffer, response-write buffer, and CID/origin/peer-address fields. If a streaming ctx exceeds this budget, the design has drifted — file an R8' violation in the retro and audit field choices before raising the bound.
- **R10':** Two handler tiers — sync default `fn(req, resp) raises -> None` + opt-in streaming `fn(ctx_ptr, mut yld: CoroYielder) raises -> None`.

## Target file layout

```
src/
├── io/
│   ├── io_trait.mojo           (Sprint 1 — unchanged; possibly add register_buf_ring extension if H3 streaming needs it)
│   └── io_uring.mojo           (Sprint 1 — unchanged)
├── h1/
│   ├── handler_server.mojo     (already sync-shaped — no shape change)
│   └── stream_ctx_pool.mojo    (NEW conditional on allocator audit; capacity=16)
├── h2/
│   ├── h2_sync_server.mojo         (RENAMED from h2_coro_server.mojo, no functional change)
│   └── h2_streaming_server.mojo    (NEW — uses boucle.stackful)
└── h3/
    ├── h3_sync_server.mojo         (REWRITTEN — replaces current h3_coro_server.mojo's shape)
    └── h3_streaming_server.mojo    (NEW — uses boucle.stackful)

bench/
├── h1_server.mojo                  (switched to IoUring[H])
├── h2_server.mojo                  (uses h2_sync_server)
├── h3_server.mojo                  (switched to new h3_sync_server)
├── h2_streaming_server.mojo        (NEW companion bench)
├── h3_streaming_server.mojo        (NEW companion bench)
├── handler.mojo                    (Sprint 1; bench_h3_body_fn rewritten to sync)
└── streaming_handler.mojo          (NEW — LLM-stream pattern, reused by both H2/H3 streaming benches)

tests/
├── test_h2_sync_server.mojo        (renamed from test_h2_coro_server.mojo)
├── test_h2_streaming_server.mojo   (NEW — restores test_body_yield + test_resume_stream from git)
├── test_h3_sync_server.mojo        (renamed + rewritten from test_h3_coro_server.mojo)
└── test_h3_streaming_server.mojo   (NEW — mirrors H2 streaming tests over QUIC loopback)
```

## Phased plan (10-day target, 13-day estimate)

### Week 1 — sync mirror across all three protocols

| Day | Work | Deliverable |
|---|---|---|
| 1 | H1 bench → `IoUring[H]` wiring; profile H1 allocator pressure | `bench/h1_server.mojo` symmetric with H2/H3; profile data |
| 2 | H1 `StreamCtxPool` if profile shows hot pressure + tests | Optional `src/h1/stream_ctx_pool.mojo` + bench measurement |
| 3-7 | H3 sync mirror: rewrite `h3_coro_server.mojo` → `h3_sync_server.mojo`, body fn, tests | `src/h3/h3_sync_server.mojo`, updated `bench/handler.mojo::bench_h3_body_fn`, rewritten `tests/test_h3_sync_server.mojo`, `comptime assert size_of[H3StreamCtx]() < 1024` |

### Week 2 — streaming tier on H3 (canonical) + H2

| Day | Work | Deliverable |
|---|---|---|
| 8 | Rename `h2_coro_server.mojo` → `h2_sync_server.mojo` (mechanical) | File renamed + import updates + test rename + R1' grep clean |
| 9-10 | **H3 streaming server**: resurrect helpers from git, mirror over QUIC, tests | `src/h3/h3_streaming_server.mojo` + `tests/test_h3_streaming_server.mojo` |
| 11-12 | **H2 streaming server**: apply the H3-validated pattern over H2 + tests | `src/h2/h2_streaming_server.mojo` + `tests/test_h2_streaming_server.mojo` |
| 13 | `bench/streaming_handler.mojo`, `bench/h2_streaming_server.mojo`, `bench/h3_streaming_server.mojo`; R1' grep gate; integration; retrospective | Full bench wiring + R1' enforced + retro doc |

If H3 sync mirror takes >5 days (Days 3-7 budget), defer H3 streaming server to Sprint 2.5 alongside H1 streaming.

## Acceptance criteria

1. All five servers build clean: `h1` (existing), `h2_sync` (renamed), `h2_streaming` (new), `h3_sync` (rewritten), `h3_streaming` (new).
2. HttpArena `validate.sh` passes for H1/H2/H3.
3. 120s × 3-run benchmark captures show:
   - **No regressions** vs Sprint 1 baselines on H2 sync (shouldn't change — only renamed) and H1 (shouldn't change without pool — small lift expected with pool).
   - **+15-25% RPS lift** on H3 sync — measured on a **long-lived-connection cell** that exercises post-handshake stream throughput (e.g. `h2load --h3 -c 1 -m 1000 -n 100000` reusing one connection across many streams), NOT the cold-start short-conn cell which is currently bottlenecked by accept-loop FFI (~412 req/s, project-context line 117) and which a handler-shape change cannot move. The long-conn cell is the cell whose bottleneck is in `H3CoroServer`'s coro-resume path, which is exactly what this rewrite removes.
4. `bench/streaming_handler.mojo` demonstrates end-to-end LLM-shape streaming on **both** H2 and H3 (multiple body chunks emitted across handler suspends, observable via `h2load -m 1` / `h2load --h3 -m 1`).
5. **R1' grep gate** returns zero matches:
   ```bash
   grep -rEn 'boucle\.stackful' src/ \
     | grep -vE '^src/(h2/h2_streaming_server|h3/h3_streaming_server)\.mojo:' \
     | grep -vE '^src/tls/lib\.mojo:'
   ```
6. **R8 + R8' compile-time asserts** all pass:
   - `size_of[H2CoroStreamCtx]() < 1024` (Sprint 1, sync ctx)
   - `size_of[H3StreamCtx]() < 1024` (Sprint 2 new, sync ctx)
   - `size_of[H2StreamingCtx]() < 96 * 1024` (Sprint 2 new, streaming ctx, R8')
   - `size_of[H3StreamingCtx]() < 96 * 1024` (Sprint 2 new, streaming ctx, R8')
7. Test count grows by 8-10:
   - `tests/test_h2_streaming_server.mojo` — at least `test_body_yield` + `test_resume_stream` + `test_cancel_via_rst_stream`.
   - `tests/test_h3_streaming_server.mojo` — same three cases adapted to H3 + STOP_SENDING.
   - `tests/test_h3_sync_server.mojo` — at least 4 cases mirroring `test_h2_sync_server.mojo`.
8. Conformance suite still passes (35/35 H3 + others unchanged).
9. Retrospective written at `plans/2026-04-27-sprint-2-retrospective.md` capturing: actual vs estimated days, any R-rule revisions needed, any spillover to Sprint 2.5.

## Watch for / risks

### R1. QUIC FC double-buffering on H3 streaming

QUIC's `MAX_STREAM_DATA` already provides per-stream backpressure at the transport layer. The streaming-handler's `resp.write_chunk(mut yld, bytes)` must not double-buffer in user-space — if it does, it inverts the FC signal: the QUIC layer thinks the application has data outstanding when it actually has it queued in handler-side memory, leading to head-of-line blocking that looks like a QUIC bug but is actually a handler-API bug.

**Mitigation:** `write_chunk` writes directly to the H3 codec's send buffer; if the codec returns `WouldBlock` (FC window full), the handler suspends via `yld.suspend()`. No intermediate handler-side buffer.

### R2. Sprint 2 budget overrun

13 days of estimated work in a 10-day target window. Sources of variance:
- H3 sync mirror is the biggest unknown — Sprint 1's H2 mirror took 5 days (estimated 4) and we're allocating 5 here.
- Resurrecting deleted `boucle.stackful` helpers from git might surface API changes since they were removed.
- QUIC loopback testing for H3 streaming is more complex than H2 streaming over TLS.

**Mitigation:** if Day 7 review shows H3 sync still has open work, defer H3 streaming server to Sprint 2.5. Sprint 2 ships H1 sync + H3 sync + H2 streaming only. The acceptance criteria above explicitly allow this fallback.

### R3. Pool capacity for streaming ctx

Streaming ctx is much larger than sync ctx (holds yielder + 64 KiB stack + suspend state). Sprint 1's `CoroStreamCtxPool(capacity=16)` would consume ~1 MiB of pinned heap for streaming pool. Streaming connections are far less common per server than sync connections.

**Mitigation:** start streaming pools at `capacity=4` (~256 KiB pool); revisit after benchmark reveals streaming-conn density on representative workloads.

### R4. R8 compile-time assert violation on H3StreamCtx

H3 stream ctx may need to hold more state than H2 (QPACK encoder/decoder pointers, stream-type byte for unidirectional streams, GOAWAY interaction state). Sprint 1 saw H2's CoroStreamCtx hit ~576 B against the 1024-B budget; H3 may exceed it.

**Mitigation:** if `comptime assert size_of[H3StreamCtx]() < 1024` fails, audit field choices — likely move QPACK pointers into per-connection state, not per-stream. If unavoidable, propose R8 budget revision to <2048 B with explicit retro entry.

### R6. R8' streaming-ctx budget overrun

H2/H3 streaming ctx must hold the 64 KiB `boucle.stackful` stack + suspend state + yielder + body-frame ring + response-write buffer + cancellation state + per-protocol fields (CIDs, stream priorities, QPACK refs). The 96 KiB budget is generous but not unbounded.

**Mitigation:** if R8' fails, the heaviest field is usually the response-write buffer; consider making it heap-pointed (extra indirection in exchange for predictable ctx size). If unavoidable, propose R8' budget revision to <128 KiB with explicit retro entry.

### R5. Resurrected helpers conflict with current API surface

The Sprint-1-deleted `H2BodyYieldFn` / `resume_stream` / suspending helpers were designed against the pre-Sprint-1 H2CoroServer. The new `h2_streaming_server.mojo` may need adapter shims to bridge between the resurrected suspending API and the now-different connection-management code.

**Mitigation:** treat resurrection as a code-review pass, not a paste. Re-audit signatures against current types. Expect 1-2 hours of API-shape adjustment beyond the raw git revert.

## Non-goals (explicit)

- **Streaming H2/H3 perf lift target.** The deliverable is *shape*, not throughput. Suspending coros on `boucle.stackful` ARE slower than sync handlers (that's exactly why Sprint 1 dropped them from the default path). Streaming bench numbers are captured for tracking but no lift target is set.
- **H1 streaming server.** Deferred to Sprint 2.5.
- **Mojo upstream `co_await` (Path C).** Parallel track. The Sprint 2 design must not assume Path C lands; if it does, the streaming tier becomes a graceful migration target rather than a permanent fixture, but Sprint 2 ships independently of any Modular roadmap.
- **Renaming `H1HandlerServer` to `H1SyncServer`.** No shape change in H1; the existing name is still accurate. Naming consistency across H1/H2/H3 deferred to Sprint 4 polish.
- **Pooled allocators for streaming ctx beyond the per-server pool.** Cross-connection pooling deferred to Sprint 5.

## Open questions (resolve during planning)

1. **`Io` trait extension for streaming?** Does the streaming-handler tier need new verbs on `Io` (e.g. `submit_send_with_yield_callback`), or can it reuse the Sprint 1 surface (`submit_send` returning a completion handle that the handler polls)? Resolve via a ~2-hour audit at start of Day 9 (this audit is INSIDE the 13-day budget, NOT on top of it). **Default assumption:** reuse Sprint 1's surface; streaming uses application-level polling, not new I/O verbs.

2. **`H3Connection`/`H2Connection` `WouldBlock` send surface.** Required for streaming-handler backpressure to propagate transport-level FC without double-buffering. M5b API was designed pre-streaming; verify by reading `src/h3/connection.mojo::send_data` (and H2 equivalent) at start of Day 9 and Day 11. If absent, add as a small precursor commit BEFORE writing the streaming server.

3. **Streaming pool capacity default.** Start with `capacity=4` for both H2 + H3 streaming pools (~256 KiB pinned heap each). Sprint 1 sync pool was `capacity=16` (~10 KiB pinned heap, since each sync ctx is <1024 B). The 4× difference reflects the 100× cost difference per ctx (608 B sync vs 64 KiB streaming). Validate with bench; revisit in retrospective.

4. **Bench drivers for streaming.** `h2load -m 1` (no concurrency) on a long-running streaming endpoint may not exercise the suspending path correctly. Need either custom bench client or `h2load` wrapper that holds streams open. **Default assumption:** wrap `h2load` for the headline benchmark; write a small custom Mojo client for correctness testing.

5. **Resurrected helper signatures.** Audit needed against current `H2Connection` / `H3Connection` API. Resolve at start of Day 8 (rename day) — the rename pass naturally surfaces the integration boundary. Treat `git show main:src/h2/h2_coro_server.mojo` as a source-of-truth reference, not a paste target.

## Dependencies

- Sprint 1 must be merged or stable on `feat/h2-state-machine-path-a`. (Currently 11 commits on the branch, last `0ea3720`.)
- `boucle.stackful.CoroutinePool` + `CoroYielder` + `CoroHandle` must still build against current Mojo (`v0.26.3.0.dev2026042005`). Verify Day 8 before resurrection.
- HttpArena `validate.sh` must work for all three protocols. Verified working in Sprint 1.

## Success definition

Sprint 2 is successful if:
- The Io trait + sync handler is the uniform foundation across H1/H2/H3.
- A user can write one streaming handler and run it on either H2 or H3 with no signature change.
- The R1' grep gate is enforced mechanically.
- Sprint 1's H2 perf lifts are preserved (no regression).
- The path to Sprint 3 (InlineArray + SIMD on H3 sync) is unblocked.

If Sprint 2 falls back to the partial-acceptance path (R2 mitigation), it is still successful provided:
- H1 sync + H3 sync ship.
- At least one streaming server (preferably H3, the canonical shape) ships.
- The streaming-handler signature is locked even if only one protocol ships against it.
