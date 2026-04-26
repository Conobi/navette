# Stackless coroutines for mojo-net — research & SOTA survey

**Date:** 2026-04-26
**Status:** research / pre-design (no code shipped)
**Scope:** survey what stackless coroutines actually are, how every
serious language has implemented them, and what each approach would
cost / yield if applied to `boucle.stackful → boucle.stackless` and
the H2/H3 servers in mojo-net.

---

## 1. What we have today (baseline)

`boucle/stackful.mojo` — **stackful** coroutines via POSIX `ucontext_t`:

- Each `CoroHandle` owns two `ucontext_t` buffers (caller + coro) and an
  mmap'd stack (`PAGE_SIZE` guard + `DEFAULT_STACK_SIZE` ≈ 64 KiB).
- Suspend/resume = `swapcontext()` system call (saves all callee-saved
  registers + signal mask + stack pointer; ~120-200 cycles).
- Per resume, the kernel reloads TLS — `__tls_get_addr` shows up at
  ~5 % self in our perf profile.
- `CoroutinePool(capacity=16)` + `CoroHandle.reset()` reuse the stack
  and ucontext buffers, so steady-state cost is *just* the swap.

Cost summary today:

| Resource | Per stream | Per resume |
|---|---|---|
| Memory | ~64 KiB stack + 2× ucontext + heap state | — |
| Syscall | — | 0 (purely userspace `swapcontext`) |
| Reg saves | — | ~16 GPRs + xmm + signal mask |
| TLS | reload on switch | 1× `__tls_get_addr` per body fn |

That's the bar to beat.

---

## 2. Stackless coroutines — extensive description

### 2.1 The core idea

> A stackless coroutine is a function whose **activation frame is heap
> (or alloca'd) instead of stack-based**, and whose body has been
> compiled into a **state machine** keyed on a resume point.

There is no separate stack. There is no context switch. Suspending is
*returning to the caller* with a "not done yet" status; resuming is
*calling a function pointer* (the resume thunk) with the frame pointer
as its argument. All locals that span a suspend point are stored in the
frame; locals that don't span a suspend point stay in registers exactly
as in any other function.

The compiler does the work:

1. **Identify suspend points** (`co_await`, `.await`, `yield_to_caller`
   in our case).
2. **Live-range analysis** — for each suspend point, which locals are
   live across it?
3. **Frame layout** — pack live locals into a struct (the "coroutine
   frame") with a tagged discriminant for the resume point.
4. **CFG split** — split the function at each suspend point. Each
   region becomes a basic block in a `switch (resume_point)` dispatch.
5. **Emit resume thunk** — a function `(frame*) -> void` that does the
   switch and runs the next region.
6. **Emit destroy thunk** — a function `(frame*) -> void` that runs
   only the destructors live at the current suspend point.

### 2.2 Compared to stackful (ucontext / fibers)

| Property | Stackful (ucontext, fiber) | Stackless (state machine) |
|---|---|---|
| Frame size | 64 KiB (worst case stack) | exactly sizeof(live vars) |
| Allocation | mmap up front | one heap alloc, often elidable (HALO) |
| Suspend cost | swap registers + TLS reload | return + flag write |
| Resume cost | swap registers + TLS reload | indirect call (often inlined) |
| Suspends from nested call | YES — anywhere on the stack | NO — only at `co_await` in the coroutine body itself ("function coloring") |
| Composable across FFI | YES (own stack) | NO (FFI sees a normal fn return) |
| ABI | platform calling convention | per-coroutine custom ABI |

The pivotal trade-off: stackless gets **per-stream memory down from
~64 KiB to ~hundreds of bytes** and removes the swap/TLS overhead, at
the price of the function-coloring constraint.

### 2.3 Why this matters for an H2 server

A stream coroutine in our H2 server holds:

- a pointer to the parent connection
- the request struct (headers, method, path)
- a few iterator/cursor variables
- the response builder

Live-set across `yield_to_caller` is on the order of **64-256 bytes**.
A stackless lowering would shrink per-stream memory by **256-1000×**
and remove the `__tls_get_addr` hot path entirely (no TLS reload on
resume because no swap).

For 100 conns × 16 streams that's **~100 MiB → ~400 KiB resident**.
That is the difference between "server fits in L3 hot-set" and "server
doesn't."

---

## 3. Implementation styles in the SOTA

There are essentially **four** distinct lowering strategies. Each
language picks one.

### 3.1 Switched-resume (LLVM `coro.id`, C++20, MSVC, GCC)

The resume function is one `switch` over the saved resume index:

```c
void coro_resume(frame* f) {
    switch (f->resume_idx) {
        case 0: goto entry;
        case 1: goto resume_after_recv;
        case 2: goto resume_after_send;
    }
}
```

LLVM materialises this via the `@llvm.coro.id` / `@llvm.coro.begin` /
`@llvm.coro.suspend` intrinsics. Frontend writes "normal" looking IR
with `co_await` lowered to `coro.suspend`; the **CoroSplit** mid-end
pass does the live-range analysis, builds the frame struct, splits the
function into resume + destroy thunks, and (if HALO fires) elides the
heap allocation.

**Pros**

- Pure compiler magic, frontend stays simple.
- HALO (Heap Allocation eLision Optimisation) can promote the frame
  to an alloca in the caller when the coroutine doesn't escape — true
  zero-cost.
- Symmetric transfer (`coro.suspend` returning the next handle to
  resume) avoids unbounded recursion when chaining.

**Cons**

- The single-switch resume is not always tail-call-optimised — each
  resume is one indirect call + one branch. (LLVM's
  `await_suspend` returning a `coroutine_handle` recovers symmetric
  transfer via `musttail`.)
- Lifetime of the frame is delicate: it has to outlive every reference
  taken into it. C++20's `coroutine_handle::destroy` is footgun-prone.

**Used by**: C++20 (Clang, GCC, MSVC), cppcoro, Folly's `folly::coro`.

### 3.2 Returned-continuation / async lowering (LLVM `coro.id.async`)

Each suspend point compiles into a **musttail call** to the next
function (the continuation), with the frame passed as an argument.
There is no `switch`, just a chain of normal functions linked by
guaranteed tail calls.

```c
swiftcc void on_recv_done(async_ctx* ctx, ...) {
    // … work for region 1 …
    musttail return submit_send(ctx, ...);
}

swiftcc void on_send_done(async_ctx* ctx, ...) {
    // … work for region 2 …
    musttail return finalize(ctx, ...);
}
```

**Pros**

- Genuinely zero-overhead resume — it's a tail call. No dispatch
  switch, no indirect call (when the callee is known statically).
- Frame layout under frontend control (Swift packs the frame into the
  async context which is a linked list — caller's frame is a tail of
  callee's).
- Plays well with structured concurrency (the async context naturally
  encodes the parent).

**Cons**

- Frontend has to emit the chained functions; no "write it like a
  stackful function" abstraction.
- Requires `musttail`, which is platform-conditional.

**Used by**: Swift's `async`/`await` (uses `swifttailcc`), parts of
Hylo, experimentally in newer LLVM frontends.

### 3.3 Hand-rolled state-machine struct (Rust, async/await sugar)

The compiler generates an enum-like state machine: each variant is
**one suspend point**, holding the live locals at that point. The
function returns a `Future`-shaped object:

```rust
enum HandleStreamState {
    Start { req: Request },
    AwaitingHeaders { req: Request, fut: SendHeadersFut },
    AwaitingBody    { resp: Response, fut: SendBodyFut },
    Done,
}

impl Future for HandleStream {
    fn poll(&mut self, cx: &mut Context) -> Poll<()> {
        loop { match self {
            Start { req } => { /* … */ *self = AwaitingHeaders { … }; }
            AwaitingHeaders { fut, .. } =>
                match fut.poll(cx) { Pending => return Pending, Ready(()) => /* … */ }
            // …
        } }
    }
}
```

The runtime drives this by polling. Suspension is "return `Pending`";
resumption is "the runtime polls again when the waker fires."

**Pros**

- No special intrinsics needed — pure source-to-source desugaring (in
  Rust this happens before LLVM; LLVM just sees a struct + a poll fn).
- The future type is a normal struct; you can size it (`size_of`),
  store it in a `Box`, embed it in another future, etc.
- Maps cleanly onto a generator/iterator transform — same machinery
  Rust already had for iterators.
- The runtime is decoupled — Tokio, smol, glommio, embassy, embedded
  bare-metal all share the same `Future` trait.

**Cons**

- Frame size is **the size of the enum's largest variant**. Naive
  codegen can produce huge futures (the `tmandry` blog post is the
  classic war story — 1700-byte futures from a few await points).
  Rust now has `generator-layout` optimisations and
  `niche-fill` to compress these but it's still a real concern.
- "Pinning": once a future is being polled, it cannot be moved (its
  internal references would break). This is the source of all the
  `Pin<&mut Self>` complexity in Rust.

**Used by**: Rust (since 2019), Kotlin (continuation-passing variant),
older Python `asyncio` (manually as classes).

### 3.4 Returned-CPS / typestate (Kotlin, JS regenerator)

The compiler rewrites the function in **continuation-passing style**:
each suspend point yields control via a callback (the continuation),
which is itself an object holding the captured locals. The compiler
generates one continuation class per suspend point.

```kotlin
suspend fun handle(req: Request): Response { … }
// becomes (sketch):
fun handle(req: Request, k: Continuation<Response>): Any {
    // dispatch on k.label
    // each label corresponds to a suspend point
}
```

**Pros**

- No platform intrinsics — pure source rewrite.
- Each continuation is a real heap object — you can serialize it,
  inspect it, schedule it on any executor.
- Natural fit for languages with a managed runtime.

**Cons**

- Heap allocation per suspend in the naive case; sophisticated
  compilers (Kotlin's K2) coalesce these but it's per-suspend, not
  per-coroutine.
- Slower than raw state-machine — there's an indirect call per resume.

**Used by**: Kotlin (`suspend fun`), JavaScript (Babel `regenerator`),
older C# `IEnumerator` lowering, Scala 3 `async`.

### 3.5 Hybrid: Zig "colorblind" async (historical)

Zig's pre-0.11 design treated `async fn` as **the same function** as a
sync one — the compiler inferred whether it needed to be a state
machine based on call-graph reachability of `suspend`. The frame was a
fixed-size struct (`@Frame(fn)`), sized at comptime to hold the
live-set.

It was an elegant idea but Zig **removed async/await in 0.11** because
the implementation was incomplete and the cost model was harder to
reason about than expected. **Cited as a cautionary tale**: even in a
small language with comptime, doing this well is genuinely hard.

---

## 4. SOTA implementations — concrete data points

| Project | Style | Frame source | Per-coroutine size | Resume cost | Notes |
|---|---|---|---|---|---|
| **C++20 (Clang)** | switched-resume | LLVM CoroSplit | sizeof(live set) + ~32 B header | indirect call + switch | HALO can elide heap |
| **Folly `folly::coro`** | switched-resume | C++20 + custom executors | same as C++20 | same | adds `Task<T>` + symmetric transfer awaiters |
| **Rust async/await** | state-machine struct | rustc MIR transform | sizeof(largest enum variant) | indirect call (poll) | no heap unless boxed; pinning required |
| **Tokio** | Rust state-machine + multi-thread runtime | — | — | — | work-stealing scheduler over Rust futures |
| **Glommio / Monoio** | Rust state-machine + thread-per-core | — | — | — | one runtime per core, no cross-core sync |
| **Pingora** | Rust state-machine (Tokio) | — | — | — | Cloudflare's prod proxy; multi-threaded async, ~1 quadrillion req in prod |
| **Hyper / h2** | Rust state-machine | — | — | — | the H2 lib; runs over Tokio |
| **h2o (C)** | hand-written state-machine | — | ~kB per stream | — | the gold-standard H2 server; 1.45M RPS in our bench |
| **Swift async** | returned-continuation (musttail) | LLVM `coro.id.async` | sizeof(live set) | musttail call (≈0) | structured concurrency; fastest known lowering |
| **Kotlin** | CPS | rewriter | one continuation obj per suspend | indirect call | JVM heap, but escape-analysis can stack-alloc |
| **Python `asyncio`** | generator-based | bytecode | PyFrameObject (~1 KB) | bytecode dispatch | slow but ubiquitous |
| **Lua coroutines** | stackful (separate stack per) | C runtime | ~few KB stack | C function call | not stackless — included for comparison |
| **Boost.Asio composed ops** | hand-written CPS | — | per-op struct | callback dispatch | what Asio used pre-coroutines |

### 4.1 The "right" reference for our problem

For a per-stream coroutine in an H2 server, the **most directly
comparable** SOTA designs are:

- **h2o** (C, hand-written state machine): 1.45M RPS, single-threaded
  per worker, SO_REUSEPORT for sharding. The state machine *is* the
  HTTP/2 stream.
- **hyper + Tokio** (Rust, compiler-generated state machine, runtime
  drives polling): 609k RPS in our bench. Heavier-weight scheduler,
  but generic and composable.
- **nginx** (C, hand-written state machine): 200-400k RPS H2, but the
  state machine is interleaved with the HTTP parser — not directly
  comparable to "user code with await."

The two "knobs" that distinguish them are:

1. **Compiler-generated vs hand-rolled state machine.** h2o pays in
   developer time; hyper pays in larger frame sizes (Rust's enum
   variants are bounded by the largest one).
2. **Scheduling locus.** h2o's loop dispatches directly to the
   per-stream state function; Tokio adds a generic task wakeup
   indirection that costs ~50-150 ns per resume.

The **fastest currently-shipping** L7 stack at the level of granularity
we care about (per-stream user code with `await`) is **Swift-style
returned-continuation lowering**, but no major HTTP server uses it
because Swift's ecosystem doesn't have one. The closest real-world
data point is **Glommio + thread-per-core Rust async**, which has
demonstrated >1M RPS on 1 core for tiny responses.

---

## 5. What this means for mojo-net

### 5.1 Mojo's compiler doesn't have native coroutine intrinsics today

Mojo (0.26.2) does not expose `co_await` or LLVM `coro.id` to user
code. We have:

- `comptime` / metaprogramming.
- A reflection-ish facility via parameter functions.
- `__moveinit__` / `__copyinit__` lifecycle hooks.
- Async/coroutine support exists in stdlib (`AsyncRTRuntimeGlobals`)
  but **only for the in-house Mojo compiler async** — not exposed as
  user-extensible state-machine lowering.

So a "compiler-generated state machine" path (3.1, 3.2, 3.3) is **not
available without compiler work**. We have three realistic paths:

### 5.2 Path A — Hand-written state machine (à la h2o)

Replace `CoroHandle` with a per-stream `StreamState` struct:

```mojo
@value
struct StreamState:
    var phase: UInt8       # 0=start, 1=awaiting_body, 2=sending, 3=done
    var stream_id: UInt32
    var conn_idx: UInt32
    var req: H2Request     # the live set
    var resp_cursor: UInt
```

Each H2 event handler becomes a `match` on `phase`. No coroutines, no
swap, no stack. The H2 codec already encodes most of this state in
`H2Connection`; we'd be making the per-stream user-code piece explicit
too.

- **Lift**: removes ucontext entirely (the stated 15-25 % gain).
- **Cost**: ~1-2 weeks. Refactors `h2_coro_server.mojo` substantially.
  No changes to boucle (we just stop using `stackful`).
- **Risk**: writing state machines by hand is error-prone (the curl
  CVE referenced in `without.boats` was exactly this category of bug).
  Mitigation: keep the test harness comprehensive and mirror h2o's
  state-table layout.
- **Optionality**: doesn't preclude later compiler lowering — the
  state machine just becomes the target.

This is the **lowest-risk, highest-immediate-yield** option.

### 5.3 Path B — `comptime`-driven state-machine generator

Use Mojo metaprogramming to generate the state machine from a "linear"
description. The user writes:

```mojo
@coroutine
fn handle(req: Request, mut yld: Yielder) -> Response:
    var headers = parse(req)
    yld.suspend()                    # ← suspend point 1
    var body = read_body(req)
    yld.suspend()                    # ← suspend point 2
    return build_response(body)
```

…and a `comptime` macro produces the `StreamState` struct, the
phase enum, and the resume function. This is **roughly** the
Rust/Kotlin source-to-source approach, executed in user space rather
than in the compiler.

- **Lift**: same as Path A (we generate the same state machine).
- **Cost**: 3-5 weeks. Need to figure out which Mojo metaprogramming
  facilities are powerful enough — comptime expressions, parameter
  functions, custom decorators. Real risk this is **not feasible**
  with current Mojo, in which case we revert to A.
- **Reward if it works**: applies to H1, H2, H3, future protocols
  with no per-protocol rewrite.

### 5.4 Path C — Push for compiler support (real `co_await`)

File an upstream Mojo feature request for `co_await` / `co_yield`
backed by LLVM `coro.id.async` (the Swift-style lowering). This is
the **technically best** answer — Mojo is built on MLIR/LLVM and the
intrinsics exist — but it's a **months-long** dependency.

- **Lift**: matches Swift / C++20 best-in-class.
- **Cost**: blocking on Modular roadmap; effectively unbounded for us.
- **Action**: file the issue regardless. In the meantime, Path A
  unblocks the perf gain.

---

## 6. Recommendation

**Path A first**, in two stages:

1. **Stage A1** — Replace `CoroHandle` in the H2 server's per-stream
   handler with a hand-written `StreamState` machine. Keep the
   `boucle.stackful` library intact (other code may still use it),
   just stop using it in `h2_coro_server.mojo`. Estimated lift:
   **+15-25 % RPS** at -c 100 -m 10. Effort: 1-2 weeks.

2. **Stage A2** — If Stage A1 confirms the model, do the same for the
   H1 and H3 servers. Effort: 1 week each.

In parallel:

3. **File a Mojo issue** asking for compiler-level `co_await` (Path C).
   Cost: 1 hour. No ETA but starts the clock.

4. **Spike Path B** as a 2-day timeboxed experiment after Stage A1
   lands — see if comptime can derive the state machine from a
   linearised description. If yes, Path B subsumes A2.

**Do not touch `boucle.stackful` for this work.** It remains the right
primitive for code paths where we genuinely want a separate stack
(e.g. interleaving with FFI callbacks that can't be rewritten as state
machines). The H2 stream handler isn't one of those.

---

## 7. Open questions / things to verify before committing

1. Does `__tls_get_addr` *actually* go to ~0 % when we drop ucontext?
   Verify with a tiny prototype that just runs a state machine and
   profile it. (High confidence yes, but needs proof.)
2. What's the live-set size of a real H2 stream handler in mojo-net
   today? Do we have headers + method + path + body cursor + response
   builder = ~256 bytes, or is it larger due to copies we haven't
   audited? Audit before sizing the `StreamState` struct.
3. How many coroutines does H3 hold concurrently? If the answer is
   "thousands per QUIC connection," the memory pressure argument for
   stackless gets stronger.
4. Does Mojo's comptime allow generating a struct *type* whose field
   layout is derived from inspecting a function's body? If yes,
   Path B is real. If no, Path B is dead until compiler support.

---

## 8. References indexed in this session

- LLVM Coroutines docs (intrinsics, switched-resume, async lowering, HALO)
- Lewis Baker — Coroutine Theory
- Lewis Baker — Understanding `operator co_await`
- cppreference — C++20 coroutines
- without.boats — Why async Rust (history of stackful → stackless)
- Tyler Mandry — Optimising async/await Part 1 (state-machine sizes)
- Loris Cro — Zig colorblind async/await
- Cloudflare — Pingora open source

(All fully indexed in context-mode; searchable for follow-up.)
