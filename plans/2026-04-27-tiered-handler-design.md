# Tiered handler design — sync default + opt-in streaming via stackful coros

**Date:** 2026-04-27
**Status:** design / pending implementation in Sprint 2
**Companion to:** `2026-04-27-h2-perf-roadmap-sprint-sequence.md`,
`2026-04-27-mojo-async-direction-and-server-architecture.md`,
`2026-04-26-stackless-coroutines-research.md`

## Context

Sprint 1's Path A replaced stackful coroutines with synchronous
handlers in `H2CoroServer`. This is correct for TechEmpower-style
workloads (small, sync request-response) and gives us the architectural
shape, the 108× per-stream memory reduction, and the transition-resilient
foundation.

But Sprint 1's Path A **does not support streaming-handler workloads**.
The original Path A docs underestimated how common streaming is.
Modern HTTP/2 traffic includes:

- LLM responses (Anthropic, OpenAI, etc. — streaming is the default
  response shape, not an edge case)
- Server-Sent Events (live dashboards, agent UIs, notifications)
- gRPC server-streaming + bidi RPCs
- Reverse proxies and API gateways (forward chunks upstream as they
  arrive — the *core* gateway pattern)
- File uploads with progress / virus-scanning / quota enforcement
- Chunked database pagination (write JSON array as cursor advances)
- WebSocket-over-HTTP/2 (RFC 8441)

Estimated 30-60 % of real production HTTP/2 traffic is streaming-shaped.
"mojo-net is a real H2 server" requires a usable streaming-handler API.

## The shape problem

A streaming handler written in callback-event form (the natural Path A
style for async-over-events) is significantly less ergonomic than the
same handler written as straight-line code:

| | sync handler (Path A) | callback-streaming | coroutine-streaming |
|---|---|---|---|
| Functions | 1 | 6+ (per-event callbacks) | 1 |
| Local vars | locals | promoted to struct fields | locals |
| Loops over chunks | n/a | accumulator + counter + phase | `while chunk in body:` |
| Mid-handler abort | `return` | `phase = DONE; check phase` | `return` |
| Cleanup on RST | RAII | explicit `on_reset` callback | RAII |

The callback form is what every language that lacks compiler-level
async/await (or has chosen not to use it) ends up with. It's
correct but consistently 3-5× longer and has more places to be wrong.

## The proposal

Adopt a **tiered handler API**:

- **Sync handler** (default): `H2BodyFn = fn(ctx_ptr) raises -> None`
  - Used by 80 % of endpoints (REST, static, JSON CRUD).
  - 608 B per stream. Zero coroutine overhead. Path A as it stands.
- **Streaming handler** (opt-in): `H2StreamingBodyFn = fn(ctx_ptr, mut yld: CoroYielder) raises -> None`
  - Used by streaming endpoints (LLM, SSE, gRPC, proxy).
  - 64 KiB per stream — but only connections that opted in pay it.
  - Uses `boucle.stackful` internally, lives in `*_streaming_server.mojo`.

Server-side:

- `src/h2/h2_coro_server.mojo` (current): the sync server. Path A.
  Renamed in this sprint to `h2_sync_server.mojo` for clarity.
- `src/h2/h2_streaming_server.mojo` (new in Sprint 2): the streaming
  server. Wraps the same `H2Connection` codec, but per-stream
  dispatch acquires a `CoroHandle` from a per-connection
  `CoroutinePool` and resumes it on body events.

Both servers share:

- `H2Connection` codec (sans-IO, identical for both)
- `Io` trait (`src/io/`)
- `CoroStreamCtx` shape (with the streaming server using a richer
  variant that carries `coro_addr` again)
- All HPACK / framing / flow-control logic

Users (or the bench launcher / gateway) pick the server type per
listener:

```mojo
# Sync — bench/h2_server.mojo (current)
var h2 = H2SyncServer(body_fn=bench_h2_body_fn, extra_data=...)

# Streaming — bench/llm_server.mojo (new)
var h2 = H2StreamingServer(body_fn=llm_stream_body_fn, extra_data=...)
```

## Updated R-rules

Path A's R1/R3 said "no `boucle.stackful` references in
`src/h{1,2,3}/`; only in FFI bridges". Update to:

**R1' (revised).** `boucle.stackful` is allowed in:
- `src/h2/h2_streaming_server.mojo` (and its H1/H3 siblings)
- Modules clearly named `*_ffi_bridge.mojo`
- Tests for both
- *Nowhere else* in `src/`. CI grep:
  `grep -r 'boucle.stackful' src/ | grep -vE '(_streaming_server|_ffi_bridge|/tests/)'`
  must return zero.

**R3' (revised).** Reasons to use `boucle.stackful`:
- Non-invertible FFI requiring a separate stack
- **Streaming HTTP handlers that need to suspend on body data,
  upstream I/O, or wire backpressure**
- *Nowhere else.*

The R-rules stay tight; we're just acknowledging streaming as a
second legitimate use case, narrowly bounded by file naming.

## Sample streaming handler

```mojo
fn llm_stream_body_fn(
    ctx: UnsafePointer[CoroStreamCtx, MutAnyOrigin],
    mut yld: CoroYielder,
) raises:
    # Read prompt from body. May suspend if body hasn't arrived.
    var prompt = read_full_body(ctx, yld)

    # Call OpenAI. May suspend waiting for upstream connect / first byte.
    var token_stream = openai_call(prompt, yld)

    # Send response headers (synchronous — just queue them).
    var hdrs = Headers()
    hdrs.add("content-type", "text/event-stream")
    ctx[].resp_writer.send_status(StatusCode.ok(), hdrs^)

    # Stream tokens as they arrive. Each iteration may suspend.
    while True:
        var event = token_stream.next(yld)  # suspend until next token
        if event.is_done():
            break
        var line = String("data: ") + event.token + String("\n\n")
        ctx[].resp_writer.send_data(line.as_bytes(), end_stream=False)
        # send_data buffers; if H2 flow window full, the wire-drain
        # event will resume us.

    ctx[].resp_writer.end()
```

Compare to the callback version (~6 functions + state struct). This
reads top-to-bottom, like a whiteboard sketch.

## Migration when Mojo async lands

Per the public direction (PR #3945 structured-async / PR #3986
yields-effect), Mojo will land Rust-style stackless `async fn`
some time post-1.0. When that happens:

| | Sync handler | Streaming (coro) handler |
|---|---|---|
| Code change | none — sync stays sync | `CoroYielder` → `await`, `yld.yield_to_caller()` → `await something()` |
| API churn | none | rewrite handler bodies, drop CoroYielder |
| Server-side | none | swap CoroutinePool for Mojo runtime |

Sync handlers, the codec, the `Io` trait, the connection management:
**all unchanged.** Only the streaming-server subsystem flips. That's
the same migration cost a callback-streaming approach would incur,
but with vastly better ergonomics in the meantime.

## Comparison to alternatives I considered

| Option | Elegance | Implementable today | Migration cost |
|---|---|---|---|
| **A. Tiered (sync + coro streaming)** ← chosen | high | yes | low (only streaming flips) |
| B. Comptime-driven state machine | highest | NO (Mojo 0.26 can't do it) | depends on Mojo proposal |
| C. Iterator-shaped re-entry | low (still callback-shaped) | yes | low |
| D. Promise/Future combinators | low (combinator hell) | yes | high (rewrite to async fn) |

Option B is the holy grail; we should track the Mojo proposals so we
can adopt it when it ships. In the meantime A delivers ergonomics
where it matters with no compiler dependency.

## Sprint 2 implementation plan

1. Rename `src/h2/h2_coro_server.mojo` → `src/h2/h2_sync_server.mojo`.
   Update imports across `bench/handler.mojo`,
   `tests/test_h2_coro_server.mojo`, `bench/h2_server.mojo`.
2. Create `src/h2/h2_streaming_server.mojo` — a parallel server type
   that uses `boucle.stackful.CoroutinePool`. Restore the previously
   deleted `_resume_and_handle_error`, `resume_stream`, and
   suspending body-reading helpers.
3. Add `bench/streaming_handler.mojo` demonstrating LLM-stream pattern
   (mock upstream that emits tokens on a timer).
4. Add `tests/test_h2_streaming_server.mojo` re-exercising the
   originally-disabled `test_body_yield` / `test_resume_stream` cases.
5. Apply the same split to H1 (`h1_sync_server` + `h1_streaming_server`)
   and H3 in Sprint 2's protocol-mirror work.

Effort: 1 week beyond the H1/H3 mirror work.

## What this means for the 1.0 pitch

Updated tagline: *"as fast as h2o on small responses, ergonomic
streaming for LLM/SSE/proxy workloads, smaller than hyper in memory,
GPU upside nobody else has."* The streaming story becomes a feature,
not a footnote.

Without it, mojo-net 1.0 is a TechEmpower benchmark stack. With it,
it's a real production server.
