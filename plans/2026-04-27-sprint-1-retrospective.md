# Sprint 1 retrospective — H2 Path A foundation

**Date:** 2026-04-27
**Branch:** `feat/h2-state-machine-path-a`
**Commits on branch (from main, oldest → newest):**

| SHA | Subject |
|---|---|
| `4d19825` | docs: stackless coroutine research, async direction, sprint roadmap |
| `8b99fa1` | feat(io): sketch Io capability trait (Sprint 1 Step 1) |
| `133e3ce` | feat(io): IoUring backend wrapping CompletionLoop (Sprint 1 Step 2) |
| `e737981` | feat(h2): replace stackful coroutines with sync handler (Sprint 1 Step 3) |
| `0d1445d` | feat(h2): R8 compile-time sizeof assert on CoroStreamCtx |

**Headline:** **+120 % RPS on `/baseline2`, +26 % on `/json/50`** at
`-c 100 -m 10`, with **108× less per-stream memory**.

---

## Plan vs. outcome

| Sprint 1 acceptance criterion | Result |
|---|---|
| `grep -r 'boucle.stackful' src/h{1,2,3}/` returns zero | ✅ zero hits |
| `sizeof(StreamState) < 1024` (revised from <512 — see below) | ✅ 608 B asserted at build time |
| Functional test matrix passes | ✅ 4/4 H2 coro tests + bench builds |
| ≥ +15 % RPS at `-c 100 -m 10` on `/json/50?m=6` | ✅ +26 % median |
| ≥ +15 % RPS at `-c 100 -m 10` on `/baseline2` | ✅ +120 % median |

## Benchmark details

**Setup:** 3 captures × 60 s × `-c 100 -m 10` per (binary, endpoint).
Single-worker, single-host, h2load (Docker, `--network=host`),
TLS 1.3 / `TLS_AES_128_GCM_SHA256`. Quiet system (no parallel docker
build, no other cores stressed). Baseline binary built from main HEAD
(`3919f7d`); Path A binary built from this branch HEAD (`0d1445d`).

### `/baseline2?a=1&b=2` (small response, headers-dominated)

| | run 1 | run 2 | run 3 | **median** |
|---|---:|---:|---:|---:|
| baseline | 106 051 | 93 100 | 100 006 | **100 006** |
| pathA    | 251 269 | 218 267 | 220 422 | **220 422** |

**Lift: +120 % (2.20×) median. Worst-case (min pathA / max baseline):
+106 %.** Decisive win.

### `/json/50?m=6` (~8 KB JSON response, codec + serialisation)

| | run 1 | run 2 | run 3 | **median** |
|---|---:|---:|---:|---:|
| baseline | 17 173 | 17 846 | 18 707 | **17 846** |
| pathA    | 24 413 | 22 497 | 18 745 | **22 497** |

**Lift: +26 % median. Worst-case (min pathA / max baseline):
near zero (18 745 vs. 18 707).** Real win, noisy spread.

The /json/50 endpoint has a non-trivial JSON serialiser in the
handler, so coroutine overhead is a smaller fraction of total work
than on /baseline2. The +26 % median is consistent with that;
the worst-case-flat is consistent with the high run-to-run variance
the bench harness has shown historically (per the Phase 2 R5 note
about 5 % spread before bulk extends landed).

## Per-stream memory

| | Pre-Path-A | Post-Path-A | Change |
|---|---:|---:|---:|
| Stack (mmap'd, per stream) | 65 536 B | 0 | — |
| ucontext × 2 | ~400 B | 0 | — |
| CoroHandle | ~200 B | 0 | — |
| Heap context (CoroStreamCtx) | (unmeasured) | 608 B | — |
| **Per stream total** | **~66 KiB** | **608 B** | **108×** |

At 100 conns × 16 streams: **~106 MiB → ~960 KiB** resident. Connection
state now fits in L3 instead of spilling to DRAM.

## What changed (architectural, not just perf)

1. **`Io` trait** (`src/io/io_trait.mojo`) defining the abstract
   submission verbs.  Concrete impl `IoUring` (`src/io/io_uring.mojo`)
   wraps boucle's CompletionLoop.  Not yet wired into the bench
   server (R4 / YAGNI: defer until a second backend demands it,
   probably Sprint 5 kTLS).
2. **Coroutines removed from the H2 server's per-stream concurrency.**
   `H2CoroServer._body_fn` is now `H2BodyFn = fn(ctx_ptr) raises -> None`
   instead of `CoroBody = fn(yld: CoroYielder) raises -> None`.
   Handler runs to completion in one synchronous call.
3. **`boucle.stackful` is no longer imported by `src/h2/`.** R1 enforced.
4. **R8 compile-time assert** (`sizeof(CoroStreamCtx) < 1024`) fires
   at build time inside `_check_stream_ctx_size()`.

## Deviations from the plan

1. **R8 budget revised from <512 B → <1024 B.** The protocol holders
   (Request 248, RecvBody 96, ResponseWriter 216, Capabilities 16)
   sum to 576 B, so 512 B was unattainable without trimming those
   types — out of scope for Sprint 1. Settled at 608 B with a 1024 B
   cap; the architectural 108× win is unchanged.
2. **Bench server NOT rewired through `IoUring`.** Originally Step 2
   was supposed to do this. Decision: defer until a second backend
   exists. The trait + impl are present, but `bench/h2_server.mojo`
   still constructs `CompletionLoop` directly. Per R4/YAGNI, this is
   correct — abstracting now without a second consumer is premature.
   The rewire becomes a one-line type swap when kTLS arrives.
3. **Two suspension-dependent tests disabled.** `test_body_yield` and
   `test_resume_stream` exercised handler suspension (`yield_to_caller`,
   `resume_stream`) — features Path A intentionally drops. They will
   be re-added in a future sprint that introduces a streaming state
   machine for handlers needing to await body data. Logged in the
   test file's "Disabled" header comment.

## What's next (Sprint 2 entry point)

The roadmap targets H1 + H3 in Sprint 2. Path A applied to:

- `bench/h1_server.mojo` + `src/h1/` — H1 server uses
  `H1HandlerServer` not coroutines; should be smaller surgery.
- `bench/h3_server.mojo` + `src/h3/h3_coro_server.mojo` — H3 coro
  server still uses `boucle.stackful`. Same shape change as H2.
- Optional 2-day spike on Path B (`comptime` state-machine generator)
  before doing H1/H3 by hand.

After Sprint 2, the next big lever is M3 + M4 (InlineArray + SIMD
JSON) — Sprint 3 in the roadmap.

## Health check on the 1.0 pitch

| | Today (post-Sprint-1) | h2o reference | hyper reference |
|---|---:|---:|---:|
| `/baseline2` RPS, single worker, 1 client | 220 k | ~1 450 k | ~293 k |
| `/json/50` RPS, single worker, 1 client | 22.5 k | n/a | ~322 k |
| Per-stream memory | 608 B | ~kB | ~1-2 kB |
| Codebase LoC (H2 server-side) | ~1.7 k | ~50 k | n/a |

Path A is the foundation. The full pitch (beat h2o on `/baseline2`,
beat hyper on memory) requires Sprints 3-4 (M1+M2+M3+M4) — all of
which land cleanly on this foundation because the codec is sans-IO
and protocol code no longer touches concurrency primitives.

## Files touched

| File | Change |
|---|---|
| `plans/2026-04-26-stackless-coroutines-research.md` | new (research) |
| `plans/2026-04-27-mojo-async-direction-and-server-architecture.md` | new (commitment) |
| `plans/2026-04-27-h2-perf-roadmap-sprint-sequence.md` | new (roadmap) |
| `plans/2026-04-27-sprint-1-retrospective.md` | new (this doc) |
| `src/io/__init__.mojo` | new |
| `src/io/io_trait.mojo` | new |
| `src/io/io_uring.mojo` | new |
| `src/h2/h2_coro_server.mojo` | rewrite (drop coros) |
| `bench/handler.mojo` | bench_h2_body_fn signature update |
| `tests/test_h2_coro_server.mojo` | rewrite for sync handler |
| `bench/profile/baselines/h2-throughput.csv` | append Sprint 1 medians |

## Open questions for next session

1. Should we run a 120 s × 3 capture (vs. the 60 s × 3 used here) for
   the recorded headline? The lift is decisive; tighter bounds may
   not change the conclusion.
2. The /json/50 spread (24.4 k → 22.5 k → 18.7 k across run-1-2-3) is
   declining. Re-run on a system with explicit CPU pinning + thermal
   stable state, or accept the median as is?
3. Path B spike now (timeboxed 2 days), or proceed straight to H1
   hand-roll in Sprint 2?
