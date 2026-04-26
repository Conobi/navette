# Mojo's async direction and what mojo-net should commit to

**Date:** 2026-04-27
**Status:** research / design constraint
**Companion to:** `plans/2026-04-26-stackless-coroutines-research.md`

Three parallel research threads (Mojo official surface, Modular team
+ community signals, transition-survival patterns from Rust/Swift/Zig)
all converge on the same conclusion. This doc records the evidence
and the architectural commitment that follows.

---

## 1. Mojo's async story — current state

### 1.1 What ships in 0.26.2

- `builtin.coroutine.Coroutine[type, origins]` and `RaisingCoroutine`
  — `Movable, RegisterPassable`, **not Copyable**. The non-Copyable
  property breaks the documented `async fn` example
  ([discussion #3274](https://github.com/modular/modular/discussions/3274),
  locked, unanswered since Jul 2024).
- `runtime.asyncrt` — internal docstring says *"low level concurrency
  library"*. Surfaces `Task`, `RaisingTask`, `TaskGroup`,
  `create_task`, `parallelism_level`. No event-loop pump.
- `async fn` / `await` keywords parse but `async def` still
  [crashes the parser (#752)](https://github.com/modular/modular/issues/752).
- No MLIR `async` dialect exposed to user code.

### 1.2 What's planned

- The roadmap parks "first-class async" in **Phase 2 — after 1.0**.
  ([roadmap](https://docs.modular.com/mojo/roadmap/)).
- Modular's path-to-1.0 blog (Dec 2025) confirms 1.0 ships when
  Phase 1 (CPU+GPU perf) completes — async is explicitly out of scope
  for 1.0.
- Direction is **"zero-cost async like Rust"**, **not** Go-style green
  threads. Owen Hilyard (working on the design) on the forum:
  > "Green threads are an abstraction that I don't think Mojo can
  > offer cleanly without unacceptable performance sacrifices… we'll
  > have something more like async/await, which can be made zero-cost."
  > — [forum.modular.com/t/green-threads-and-runtime/576](https://forum.modular.com/t/green-threads-and-runtime/576)
- Two competing language-level proposals are open:
  - PR #3945 — *Structured Async for Mojo* (Hilyard, Jan 2025): Rust-
    style + Send/Sync, linear types, pluggable executors.
  - PR #3986 — *yields effect* (Smith, Feb 2025): colorless via
    abstracting over the `async` effect.
  Both still labelled `needs-discussion`. Chris Lattner is reviewing
  at the syntax level (cf. his `raises Never` trick referenced in
  #3986).
- Steffi (Modular, MLIR coro implementer), Dec 2024:
  > "Mojo Async is under early development and paused to address some
  > higher priorities … sometime early to mid next year we will have
  > a production quality version to release."
  > That window slipped — no production release, design still in
  > proposal stage.

### 1.3 What the community actually ships

- **lightbug_http** (732 stars, the canonical Mojo HTTP server) is
  **fully synchronous**. Its default executor is literally
  `struct SyncExecutor` — *"single-threaded executor: handles each
  connection to completion before accepting the next."* No stdlib
  `Coroutine`, no event loop.
- Hilyard's guidance to the community (Jan 2025):
  > "As you can see from my proposal, async doesn't really exist yet.
  > If you can, a manual state machine with io_uring is probably going
  > to be the best for a while."

### 1.4 Stability signal

**Treat current `Coroutine` / `asyncrt` as unstable.** Concrete
evidence: type is broken in user space, two language-level redesigns
unresolved for a year+, lead engineer calls implementation "early
development … paused", roadmap parks the feature post-1.0, no async
entries in 0.26.1 / 0.26.2 changelogs.

---

## 2. What survives language transitions (Rust/Swift/Zig)

### 2.1 What consistently survived

1. **Plain data types for the protocol** — HTTP messages, frames,
   codec state. No async in the type. Hyper-0.10's `http::Request`
   ships unchanged in hyper 1.x.
2. **Readiness/poll-shaped state machines** — drivable from any
   scheduler. Aaron Turon's 2016 design survived all four Tokio
   rewrites.
3. **Event-handler APIs** — SwiftNIO's `ChannelHandler`,
   hyper's `Service<Request, Response>`, h2o's per-stream callbacks.
   Protocol logic written as `on_data(bytes) -> Action`, not as
   `await` chains.
4. **Caller-injected I/O capability** — Zig's new `Io` interface (an
   `Allocator`-shaped vtable). What survived async being *removed*
   from Zig 0.11.
5. **Value-typed promise / future with `.whenComplete(cb)`** — bridges
   to anything. SwiftNIO `EventLoopFuture` survived async/await by
   adding `.get() async` on top.

### 2.2 What got thrown out every time

- Combinator chains (`and_then`, `flatMap`, `map`) tied to a specific
  Future trait.
- Runtime-specific handles (`tokio-core::Reactor`, `std.event.Loop`).
- "async-fn-everywhere" protocol code.
- Any trait with associated types or `Pin`/`Waker` equivalents that
  are language-version-bound.

### 2.3 The rule

> Code that touches `async`/`await` keywords gets rewritten.
> Code shaped as sans-IO + event handlers + injected I/O capability
> doesn't.

---

## 3. The architectural commitment for mojo-net

The Mojo direction (Rust-style stackless, post-1.0) and the survival
patterns (sans-IO + event handlers + injected I/O) point to the same
shape. We commit to it.

### 3.1 Layer model

```
┌────────────────────────────────────────────────────────────┐
│  USER HANDLER (today: sync `fn`. Future: `async fn` if/when│
│  Mojo's async/await stabilises. Single layer that flips.)  │
├────────────────────────────────────────────────────────────┤
│  SERVER LOOP — explicit state machine.                     │
│  Calls `io.recv(fd, buf)`, `io.send(fd, buf)`, `io.spawn`. │
│  No `async`/`await` keyword in this layer.                 │
├────────────────────────────────────────────────────────────┤
│  IO CAPABILITY (`Io` trait, Allocator-shaped).             │
│  Concrete impl: io_uring today. epoll fallback later.      │
│  Future: Mojo `async`-driven impl. ONE thing changes.      │
├────────────────────────────────────────────────────────────┤
│  CODEC — sans-IO. `feed_bytes(buf) -> events`,             │
│  `next_outgoing() -> bytes`. No I/O, no async, pure data.  │
│  Mirrors TQUIC, h11, h2 (Python), nghttp2.                 │
└────────────────────────────────────────────────────────────┘
```

### 3.2 Concrete mappings to current code

| Layer | Today | What changes when Mojo async lands |
|---|---|---|
| Codec (`src/h2/`, `src/h3/`, `src/h1/`) | sans-IO already (TQUIC-style); `H2Connection.feed_bytes`, `data_to_send` | **nothing** |
| Server loop (`bench/h2_server.mojo`, `src/h2/h2_coro_server.mojo`) | manual state machine driven by io_uring CQEs | **nothing** (or thin async-fn wrapper added) |
| Coroutine layer (`boucle.stackful` per-stream) | ucontext stackful coros | **replaced** by either hand-written state machine (Path A) or Mojo `async fn` (when available) |
| `Io` capability | implicit — direct `loop.submit_*` calls | **abstracted** behind a trait so the runtime can be swapped |
| User handlers | sync Mojo `fn` returning a `Response` | flipped to `async fn` if/when language supports it |

### 3.3 The thing we're throwing out

The boucle stackful coroutine usage **inside the per-stream H2
handler** does not survive any of the candidate Mojo async outcomes:

- If Mojo lands Hilyard's structured async → we'd rewrite to use it.
- If Mojo lands Smith's `yields` effect → we'd rewrite.
- If Mojo never lands async → Hilyard's own advice is "manual state
  machine with io_uring."
- If we want to ship now without waiting → same answer.

**All four outcomes lead to the same code.** That's the strongest
possible signal to commit to it.

---

## 4. Practical next steps

1. **Replace `boucle.stackful` use in `h2_coro_server.mojo` with a
   hand-written state machine** (Path A from the prior research).
   This is the perf win (-15-25% RPS) AND the transition-resilient
   shape. Same change does both.
2. **Define `Io` trait** (small — `recv`, `send`, `accept`,
   `spawn`, `now_us`) and route `bench/h2_server.mojo` and
   `bench/h3_server.mojo` through it. Today the impl is io_uring;
   future impls slot in without touching codec or server logic.
3. **Keep `boucle.stackful` available** for code paths where a
   separate stack is genuinely needed (e.g. interleaving with FFI
   that can't be inverted to event handlers). Do not delete it. Just
   stop using it as the per-stream concurrency primitive.
4. **Watch but don't depend on** Mojo `async fn` work. When (if) it
   stabilises, only the user-handler layer needs to change. The flip
   is cheap because we built for it.
5. **File no Mojo async issues from mojo-net** — the design space is
   already crowded with two open proposals. Watch them, don't add
   noise.

---

## 5. Why this isn't a hedge

A hedge would be "design two parallel implementations." This isn't
that. The sans-IO + event-handler + injected-`Io` shape is **the
fastest known shape regardless** (h2o's 1.45M RPS proves it), and it's
also the most transition-resilient shape. The two pressures don't
trade off — they push in the same direction.

The only thing we lose is the visual ergonomics of writing the H2
handler as straight-line code with `yld.yield_to_caller()` reads. That
loss is bounded (it's one file: `h2_coro_server.mojo`) and recoverable
(a `comptime` macro could re-skin a state machine as straight-line
code later).

---

## 6. References

Mojo-direction sources:
- [docs.modular.com/mojo/roadmap](https://docs.modular.com/mojo/roadmap/) — async parked in Phase 2
- [modular.com/blog/the-path-to-mojo-1-0](https://www.modular.com/blog/the-path-to-mojo-1-0) — 1.0 scope excludes async
- [forum.modular.com/t/how-to-write-async-code-in-mojo/473](https://forum.modular.com/t/how-to-write-async-code-in-mojo/473) — Hilyard: "async doesn't really exist yet"
- [forum.modular.com/t/green-threads-and-runtime/576](https://forum.modular.com/t/green-threads-and-runtime/576) — direction confirmed as Rust-style zero-cost
- [forum.modular.com/t/structured-async-for-mojo/487](https://forum.modular.com/t/structured-async-for-mojo/487) — PR #3945
- [forum.modular.com/t/language-proposal-abstracting-over-async-the-yields-effect/529](https://forum.modular.com/t/language-proposal-abstracting-over-async-the-yields-effect/529) — PR #3986
- [github.com/Lightbug-HQ/lightbug_http](https://github.com/Lightbug-HQ/lightbug_http) — canonical Mojo HTTP server, fully sync
- [github.com/modular/modular/discussions/3274](https://github.com/modular/modular/discussions/3274) — Coroutine not Copyable
- [Steffi LLVM Dev Mtg 2024 talk](https://www.youtube.com/watch?v=ILjuvj13EpQ) — MLIR coroutine impl

Survival-pattern sources:
- aturon.github.io — futures design (readiness model)
- Tokio rewrite history (0.1 → 0.3 → std::future)
- SwiftNIO `ChannelHandler` API stability across async/await
- Zig 0.11 release notes — async removed; injected `Io` survived
- TigerBeetle — manual io_uring/kqueue abstraction

Companion plan:
- `plans/2026-04-26-stackless-coroutines-research.md` — the full
  stackless-coroutine SOTA survey and lowering taxonomy.
