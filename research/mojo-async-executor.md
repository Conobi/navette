# research/mojo-async-executor.md

**Spike date:** 2026-04-07
**Mojo version:** 0.26.2
**Author:** M2.5a planning

## Question

Can we drive Mojo coroutines from a custom executor (boucle's
`CompletionLoop` / `ReadinessLoop`) so the M2.5a trait surface can grow
an `AsyncBody` adapter (M2.6 candidate) that lets handlers `await`
inbound body chunks instead of polling `try_read()`?

The decision blocked on this spike (per `docs/project-context.md`): is
M2.6 (AsyncBody adapter) realistic, or should the unified client design
(M6) commit to the callback-only execution model permanently?

## Public surface (Mojo 0.26.2)

The Mojo standard library exposes two coroutine value types:

- `Coroutine[type: ImplicitlyDestructible, origins: OriginSet]`
  in `builtin.coroutine`. Movable, RegisterPassable. Methods: `__init__`,
  `__await__`, `force_destroy`. The `__await__` entry point produces the
  coroutine result; there is no public `resume(handle)` taking a frame
  pointer.
- `RaisingCoroutine[type: AnyType, origins: OriginSet]` — same shape, for
  `async def f() raises -> T`.

`async def` syntax compiles. The validator accepts:

```mojo
async def add(x: Int, y: Int) -> Int:
    return x + y

def main() raises:
    var c = add(2, 3)
    print(c.__await__())
```

`__await__()` is callable from a synchronous context and runs the
coroutine to completion synchronously. There is no documented public API
to (a) construct a custom waker, (b) park a coroutine on an external
event source, or (c) resume a parked coroutine when the event fires.

## MLIR `!co` dialect accessibility

`__mlir_op.\`co.suspend\`` parses cleanly under
`mcp__mojo-mcp__validate` (Mojo 0.26.2). However:

- The `!co` dialect is not documented as a stable interface.
- The shape of the parameters that `co.suspend` / `co.resume` accept is
  not exposed publicly. We could not find a public type for the resumable
  frame pointer or for waker construction in the standard library or in
  upstream Modular issues searched on 2026-04-07.
- Even if we successfully invoke `co.suspend` / `co.resume`, the lack of
  a stable waker API means any executor we build is fragile across Mojo
  releases. Modular has signaled in upstream issues that the coroutine
  runtime is experimental and not pluggable to custom I/O sources today.

## POC outcome

No POC was built. The blocker is not "can we call `co.suspend`" — it is
"can we map an outstanding `boucle::Completion` to a frame pointer that
we are allowed to resume". The standard library does not expose either
half of that mapping.

We did confirm that:

- `Coroutine.__await__()` is the only public completion path.
- Calling `__await__()` blocks the calling thread until the coroutine
  finishes — fine for a single coroutine but useless for an executor that
  needs to interleave many coroutines on a shared completion queue.

## Recommendation

**M2.6 candidate? blocked-on-Modular.**

The M2.5a trait surface should remain callback-only. The γ hybrid model
with `try_read()` / `on_body_available` is the only execution shape we
can realistically implement against the current Mojo runtime. Any
`AsyncBody` adapter would either:

1. Wrap the callback API in a hand-rolled state machine that pretends to
   be a coroutine but is really just a continuation, OR
2. Block the OS thread during `__await__()`, defeating the purpose.

Neither is worth committing trait surface to in M2.5/M2.6.

## Follow-ups

- File a Modular issue (or upvote an existing one) requesting a public
  waker API and a documented mapping from `Coroutine.__await__` resume
  points to user-controlled wakers. Re-open M2.6 if the API lands.
- When designing M6 (HttpClient), do **not** assume an async executor is
  available. The handler-callback model carries through to M6 unchanged.
- Re-run this spike when Mojo 0.27 lands; check the changelog for any
  mention of `Waker`, `Executor`, `co.resume`, or `Future`.

## Sources consulted

- `mcp__mojo-mcp__lookup builtin.coroutine.Coroutine` (2026-04-07)
- `mcp__mojo-mcp__lookup builtin.coroutine.RaisingCoroutine` (2026-04-07)
- `mcp__mojo-mcp__validate` for `async def` shape and `__mlir_op.\`co.suspend\``
- `~/Projets/perso/boucle/` (CompletionLoop / ReadinessLoop public API)
