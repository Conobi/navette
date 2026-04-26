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

## Sprint 2 — Path A to H1 and H3 (1 week, possibly preceded by Path B spike)

**Goal:** uniform shape across all three protocols.

Optional 2-day spike first: **Path B feasibility** — can Mojo
`comptime` synthesise a `StreamState` struct + phase enum from a
linearised description? If yes, Path B subsumes manual H1/H3 work.
If no, hand-roll H1 and H3 mirroring the H2 sprint.

Scope:
1. Apply Path A to `bench/h1_server.mojo` and `src/h1/`.
2. Apply Path A to `bench/h3_server.mojo` and `src/h3/`.
3. Same `Io` trait used by all three.

Acceptance:
- All three benchmarks build clean.
- HttpArena validate.sh passes for all three protocols.
- 120s × 3-run captures show no regressions vs. Sprint 0 (per-protocol
  baselines preserved or improved).

Lift on H1/H3: same +15-25% pattern as H2.

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

**R1.** `boucle.stackful` has exactly one allowed entry point per use
case, and zero shared types with the state machine layer. CI grep:
`grep -r 'boucle.stackful' src/h{1,2,3}/` returns zero. Allowed
locations: tests and modules clearly named `*_ffi_bridge.mojo`.

**R2.** The hand-written state machine never imports anything
coroutine-shaped. No `CoroBody`, `Yielder`, or `yield_to_caller` in
protocol or server-loop code.

**R3.** One reason to use `boucle.stackful` — separate stack required
for non-invertible FFI (e.g. C library callbacks where the C code
holds the stack). No other reason. "More ergonomic" doesn't qualify.

**R4.** The `Io` trait is the only allowed injection point. Extensions
go via "extend `Io` by addition," never "add a coroutine."

**R5.** `boucle.stackful` evolves only when an FFI bridge needs it.
Unused parameters and methods get deleted, not preserved.

**R6.** State machine phase enums are local to their module
(`src/h2/h2_state.mojo`, `src/h3/h3_state.mojo`, etc.). No
cross-protocol "common phase" abstraction. DRY is wrong here.

**R7.** Tests for `boucle.stackful` use the FFI bridge use case as
their fixture. If we can't write a real-world fixture, the use case
isn't real and the library should be deleted.

**R8.** `sizeof(StreamState) < 512 bytes` asserted at compile time.
Build fails on drift.

**R9.** No `Future`, `Promise`, `Awaiter`, or `Continuation` types
until Mojo's async lands. The `Io` trait + event handlers cover every
case the server actually has.

**R10.** The user-handler layer is sync today, single function call at
the boundary. Signature: `fn handle(req: Request, mut io: Io) -> Response`.
When Mojo async stabilises, this signature flips in one place; the
server loop adapts. Until then, no async sugar leaks downward.

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
   5% of h2o on equivalent hardware.
2. **Smaller than hyper in memory** — per-stream memory 10-100× less
   than hyper (256 B vs. tens of KB).
3. **~3K-line core codebase** — vs. h2o's ~50K, via comptime-generated
   dispatch instead of hand-written tables.
4. **Type-safe end-to-end** — origin-checked zero-copy throughout.
5. **First-class GPU story** as long-term differentiator.
6. **None of this depends on Mojo async stabilising** — all sprints
   ship on top of the architectural shape committed in
   `2026-04-27-mojo-async-direction-and-server-architecture.md`.

That's the news-making outcome. Anything less and we revisit the
sprint plan.
