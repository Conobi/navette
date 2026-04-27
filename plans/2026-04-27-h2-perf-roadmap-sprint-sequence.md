# mojo-net H2 perf roadmap — sprint sequence

**Date:** 2026-04-27
**Status:** committed sequence (post-Phase-2)
**Companion to:**
- `plans/2026-04-26-stackless-coroutines-research.md` (SOTA survey)
- `plans/2026-04-27-mojo-async-direction-and-server-architecture.md` (architectural commitment)

This doc is the **execution plan** that follows from those two. The
prior docs argue *why*; this one says *what and when*.

---

## North-star goal

By end of Sprint 4 on a quiet single-socket box with a single h2load
client, mojo-net **exceeds h2o on small-response RPS** (/json/50 and
/baseline2-shape) while using **10-100× less per-stream memory than
hyper**. By end of Sprint 6, the result holds on TLS-terminated traffic
across multiple cores.

Reference points (current numbers, see `bench/profile/baselines/h2-throughput.csv`):
- mojo-net: ~196k-237k RPS on `/baseline2`, ~29-36k on `/json/50`
- hyper:    ~293k-337k RPS on `/baseline2`, ~322-363k on `/json/50`
- h2o:      ~1.45M RPS reference (separate measurement)
- Per-stream memory today: 64 KiB stack + ucontext = ~64 KiB
- Per-stream memory target post-Sprint-1: ~256 B

---

## Sprint 1 — Path A foundation on H2 server (2 weeks)

**Goal:** confirm the architectural shape before extending it.

Scope:
1. Replace per-stream `CoroHandle` in `src/h2/h2_coro_server.mojo`
   with `StreamState` struct (phase enum + ~256 B live-set).
2. Define `Io` trait — small surface:
   `recv(fd, buf) -> ReadyToken`,
   `send(fd, buf) -> ReadyToken`,
   `accept(fd) -> ReadyToken`,
   `spawn(state)`,
   `now_us()`,
   `sleep(us)`.
3. First concrete impl: `IoUringIo` wrapping the existing boucle ring.
4. Route `bench/h2_server.mojo` through `Io`.
5. Audit codec for zero `loop.submit_*` calls (sans-IO confirmation).
6. Sync user-handler signature: `fn handle(req: Request, mut io: Io) -> Response`.
7. Keep `boucle.stackful` available, gated by R1-R10 (see § "Coexistence requirements").

Acceptance:
- 120s × 3-run capture vs. current baseline shows ≥+15% median RPS
  at -c 100 -m 10 on `/json/50?m=6`.
- `sizeof(StreamState) < 512` asserted at compile time.
- `grep -r 'boucle.stackful' src/h{1,2,3}/` returns zero hits.
- Functional test matrix (existing) passes.

Lift: **+15-25% RPS**. Memory: **64 KiB → ~256 B per stream**.

---

## Sprint 2 — Path A on H1/H3 + tiered streaming server on H2 (2 weeks)

**Goal:** (a) uniform sync-handler shape across all three protocols,
(b) usable streaming-handler API for LLM/SSE/proxy/gRPC workloads.

**Why streaming is in this sprint**: Sprint 1's user review surfaced
that streaming workloads are 30-60 % of real production HTTP/2 traffic
(LLM responses, SSE, gRPC server-streaming, reverse proxies, file
upload, chunked DB pagination, WebSocket-over-H2). The Path A sync
handler is correct for TechEmpower-shape REST traffic but inadequate
for these. Shipping mojo-net 1.0 without streaming-handler ergonomics
would limit it to micro-benchmark territory. See
`plans/2026-04-27-tiered-handler-design.md` for the full design.

Optional 2-day spike first: **Path B feasibility** — can Mojo
`comptime` synthesise a `StreamState` struct + phase enum from a
linearised description? If yes, Path B subsumes manual H1/H3 work.
If no, hand-roll H1 and H3 mirroring the H2 sprint.

Scope:
1. **Sync-handler mirror for H1 + H3.** Apply Path A to
   `bench/h1_server.mojo` + `src/h1/` and `bench/h3_server.mojo` +
   `src/h3/`. Same `Io` trait used by all three. Effort: 1 week.
2. **Tiered streaming server for H2.** Effort: 1 week.
   - Rename `src/h2/h2_coro_server.mojo` → `src/h2/h2_sync_server.mojo`
     (Path A as it stands).
   - Create `src/h2/h2_streaming_server.mojo` — a parallel server
     type using `boucle.stackful.CoroutinePool`. Restores the
     previously-removed suspending body helpers and the
     `resume_stream` external-resume API. Streaming connections pay
     64 KiB per stream; sync connections continue to pay 608 B.
   - Add `bench/streaming_handler.mojo` demonstrating an
     LLM-stream pattern (mock upstream emitting tokens on a timer).
   - Add `tests/test_h2_streaming_server.mojo` re-exercising the
     originally-disabled `test_body_yield` / `test_resume_stream`
     cases against the streaming server.
3. **Apply the tiered split to H1 + H3** (or defer one protocol if
   Sprint 2 runs long).

Acceptance:
- All three benchmarks build clean.
- HttpArena validate.sh passes for all three protocols.
- 120s × 3-run captures show no regressions vs. Sprint 1 baselines.
- `bench/streaming_handler.mojo` demonstrates an end-to-end
  streaming response (LLM-shape, multiple body chunks emitted as the
  handler suspends/resumes).
- `grep -r 'boucle.stackful' src/ | grep -vE '(_streaming_server|_ffi_bridge|/tests/)'`
  returns zero (revised R1' enforced).

Lift on H1/H3 sync: same +15-25 % pattern as H2.
Lift on streaming H2: not a perf goal — the deliverable is *shape*.

---

## Sprint 3 — InlineArray + SIMD primitives + extended zero-copy (2 weeks)

**Goal:** match h2o on `/baseline2`-shape RPS.

Scope (priority order from post-Sprint-1 profile):
1. **M3 InlineArray streams** — replace per-connection
   `Dict[stream_id, Stream]` with
   `InlineArray[Stream, MAX_CONCURRENT_STREAMS]` indexed by
   `stream_id % MAX`. Eliminates Dict hashing + heap chains.
2. **M4 SIMD primitives** (highest-yield first):
   - SIMD JSON serialisation for `/json/N` endpoints (could double
     `/json/50` RPS on its own).
   - SIMD HPACK Huffman decode (4-byte parallel lookups).
   - SIMD HTTP/2 frame-header parse (9-byte aligned read).
3. **M5 extended zero-copy `Span`** — push origin-checked spans
   through HPACK and JSON serialisation paths.

Acceptance:
- `/baseline2?a=1&b=2` RPS within ±5% of h2o reference on the same
  hardware.
- `/json/50?m=6` RPS doubles vs. Sprint 2.
- No Dict allocations on hot paths (verified via heap profile).

Lift: **+5-15%** aggregate, with `/json/50` jumping disproportionately.

---

## Sprint 4 — Comptime codec dispatch + HPACK static emitters (2 weeks)

**Goal:** **exceed h2o** on small-response RPS.

Scope:
1. **M1 comptime codec dispatch** — `comptime`-specialise codec entry
   per known frame type. Inline-able fast paths for HEADERS, DATA,
   WINDOW_UPDATE; runtime fallback for the rest. Replaces the giant
   switch in `_handle_recv`.
2. **M2 comptime HPACK static-table emitters** — generate per-entry
   encoders for the 61 static-table entries. Eliminates dynamic-table
   dispatch on hot pseudo-headers.

Acceptance:
- `encode_frame` falls below 5% self in profile (currently 19.3%).
- mojo-net `/baseline2` RPS exceeds h2o reference on same hardware
  by ≥5%.
- HPACK encoding ranks below top 20 in profile.

Lift: **+5-15%** + symbolic milestone (we beat h2o).

---

## Sprint 5 — kTLS (parallelisable with Sprint 6, 2 weeks)

**Goal:** beat h2o on TLS-terminated RPS.

Scope:
1. Add `KTlsIo` impl of the `Io` trait — `setsockopt(TCP_ULP, "tls")`
   + `TLS_TX/TLS_RX` setup at accept.
2. `Io.send(buf)` writes plaintext; kernel encrypts.
3. Pair with sendfile-style zerocopy for DATA frames.
4. Fallback path: `RustlsIo` for hosts without kTLS.

Acceptance:
- BoringSSL `EVP_AEAD_CTX_seal` falls out of top-50 hotspots.
- `/baseline2` over TLS within 10% of plaintext RPS (today: ~50%).
- mojo-net TLS RPS exceeds h2o TLS reference.

Lift: **+15-30%** on TLS hot paths.

---

## Sprint 6 — Multi-process / SO_REUSEPORT (parallelisable, 1-2 weeks)

**Goal:** scale linearly in cores.

Scope:
1. Bench launcher forks N workers, each with its own `Io` impl.
2. `SO_REUSEPORT` load-balances accept queue across workers.
3. No cross-worker state — each worker is independent (matches h2o).

Acceptance:
- N=8 workers deliver ≥6× single-worker RPS on `/baseline2`.
- No shared mutable state between workers (verified via static check
  or convention).

Lift: **near-linear in cores** (independent of all other levers).

---

## Backlog (post-Sprint-6, profile-driven)

| Item | Status |
|---|---|
| M6 comptime route table | unscheduled — wait for routing-bound profile |
| M7 NUMA-aware specialisation | unscheduled — single-socket box only |
| M8 GPU-resident response cache | speculative — long-term differentiator |
| Registered SQ + SQPOLL | low-priority — small lift, layerable when needed |
| Path C (Mojo upstream `co_await` request) | filed in parallel; no ETA |

---

## Coexistence requirements — `boucle.stackful` ↔ hand-written state machine

These are the YAGNI/SOLID rules that keep the two implementations
from drifting into a tangled coexistence. Enforced by CI and review.

**Revision history.** R1 and R3 were tightened in Sprint 1 (no
`boucle.stackful` outside FFI bridges) but loosened in the
post-Sprint-1 design review (see
`plans/2026-04-27-tiered-handler-design.md`) once we acknowledged
streaming workloads as a real, common second use case.  The current
versions are R1' and R3' — narrower than "free-for-all" but broader
than the original "FFI only".

**R1' (revised).** `boucle.stackful` is allowed in:
- Modules clearly named `*_streaming_server.mojo` (the streaming
  HTTP servers added in Sprint 2)
- Modules clearly named `*_ffi_bridge.mojo` (FFI integrations)
- Tests for either of the above

CI grep enforcement:
```
grep -r 'boucle.stackful' src/ | \
  grep -vE '(_streaming_server|_ffi_bridge|/tests/)'
```
must return zero. The original "no `boucle.stackful` in
`src/h{1,2,3}/`" check is replaced by this stricter file-naming
enforcement.

**R2.** The sync-handler state machine never imports anything
coroutine-shaped. No `CoroBody`, `Yielder`, or `yield_to_caller` in
the sync-server file, codec, or protocol-data types — only inside
`*_streaming_server.mojo`.

**R3' (revised).** Reasons to use `boucle.stackful`:
- Non-invertible FFI requiring a separate stack (e.g. C library
  callbacks where the C code holds the stack).
- **Streaming HTTP handlers that need to suspend on body data,
  upstream I/O, or wire backpressure** — the streaming server
  subsystem's per-stream concurrency primitive.

No other reason. "More ergonomic for sync code" still doesn't
qualify; sync handlers stay sync.

**R4.** The `Io` trait is the only allowed injection point. Extensions
go via "extend `Io` by addition," never "add a coroutine."

**R5.** `boucle.stackful` evolves only when an FFI bridge or the
streaming server needs it.
Unused parameters and methods get deleted, not preserved.

**R6.** State machine phase enums are local to their module
(`src/h2/h2_state.mojo`, `src/h3/h3_state.mojo`, etc.). No
cross-protocol "common phase" abstraction. DRY is wrong here.

**R7.** Tests for `boucle.stackful` use either an FFI bridge use case
or a streaming-handler use case as their fixture. If neither fits,
the use case isn't real and shouldn't be added.

**R8.** `sizeof(CoroStreamCtx) < 1024 bytes` asserted at compile
time (revised from <512 in Sprint 1 once protocol-holder sizes were
audited — Request 248 + RecvBody 96 + ResponseWriter 216 + bookkeeping
≈ 608 B today). Build fails on drift.

**R9.** No `Future`, `Promise`, `Awaiter`, or `Continuation` types
until Mojo's async lands. The `Io` trait + sync handlers + (Sprint 2)
streaming-handler coroutines cover every case the server actually has.

**R10' (revised).** Two handler tiers, each with a fixed signature:
- **Sync handler** (default): `fn(ctx_ptr) raises -> None` —
  used by 80 % of endpoints (REST, static, JSON CRUD). 608 B / stream,
  zero coroutine overhead.
- **Streaming handler** (opt-in, Sprint 2): `fn(ctx_ptr, mut yld: CoroYielder) raises -> None`
  — used by LLM / SSE / gRPC / proxy / file-upload endpoints.
  64 KiB / stream, but only connections that opted in pay it.

When Mojo async stabilises:
- Sync handler signature stays unchanged.
- Streaming handler signature flips to `async fn(ctx, body, resp) raises`;
  `CoroYielder.yield_to_caller()` calls become `await something()`.
- Codec, `Io` trait, connection mgmt, sync server: unchanged.

Until then, no async sugar leaks downward into either tier.

---

## Checkpoints

After each sprint, capture:
- 120s × 3-run RPS at -c 100 -m 10 on `/baseline2` and `/json/50`
- Per-stream memory (`sizeof(StreamState)` printed at startup)
- Top 20 perf-record hotspots
- HttpArena validate.sh PASS/FAIL

Update `bench/profile/baselines/h2-throughput.csv` and write a sprint
retrospective in `plans/YYYY-MM-DD-sprint-N-retrospective.md`.

---

## Success criteria for the 1.0 pitch

By end of Sprint 6, mojo-net should credibly claim:

1. **As fast as h2o on CPU** — `/baseline2` and `/json/50` RPS within
   5 % of h2o on equivalent hardware.
2. **Smaller than hyper in memory** — sync-handler streams hold
   ~608 B each (vs. hyper's tens of KB); streaming-handler streams
   hold ~64 KiB each but only when explicitly opted into.
3. **Streaming-handler ergonomics** — LLM/SSE/gRPC/proxy/file-upload
   handlers write top-to-bottom code with `CoroYielder` suspension;
   no callback-state-machine boilerplate. Migrates 1:1 to Mojo
   `async fn` when it lands.
4. **~3K-line core codebase** — vs. h2o's ~50K, via comptime-generated
   dispatch instead of hand-written tables.
5. **Type-safe end-to-end** — origin-checked zero-copy throughout.
6. **First-class GPU story** as long-term differentiator.
7. **None of this depends on Mojo async stabilising** — all sprints
   ship on top of the architectural shape committed in
   `2026-04-27-mojo-async-direction-and-server-architecture.md`.

Updated tagline: *"as fast as h2o on small responses, ergonomic
streaming for LLM/SSE/proxy workloads, smaller than hyper in memory
on the common path, GPU upside nobody else has."*

That's the news-making outcome. Anything less and we revisit the
sprint plan.
