# H2 Perf — Phase 2: Coroutine Runtime + Allocation

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Phase 1 retro:** `plans/2026-04-26-h2-perf-phase1-codegen-allocation-retrospective.md`. Mechanical Phase 1 cleanups recovered ~2 % CPU; not at 80 % of hyper. Phase 2 targets the architectural cost categories that Phase 1 deliberately deferred.

**Phase 2 spike (2026-04-26):** Counted `swapcontext` and `getcontext` calls via LD_PRELOAD shim across 6 load profiles. **Result: exactly 1 `getcontext` + 2 `swapcontext` per request, regardless of `c=1…50` or `m=1…16`.** Concrete implications:
- A fresh coroutine is allocated AND initialized for every single request (no pooling).
- Suspends/req is at the floor (2: yield + resume) for the current per-request-coro model.
- Path C's primary angle is therefore **coroutine pooling**, not "suspend less."
- Path B's primary angle stays **`__tls_get_addr` (6 % CPU) per-coro lookup elimination**.

**Phase 2 amendment (2026-04-26 evening):** boucle just landed `IORING_OP_PROVIDE_BUFFERS` + `IORING_REGISTER_PBUF_RING` + `submit_recvmsg_multishot(buf_group=...)` (commits `1a7a81e`, `2b39325`, `ad9754e`, `7846233`). The H2 server's recv path today does per-connection `recv_buf` alloc, single in-flight RECV gated by `recv_in_flight`, and a per-recv byte-by-byte copy out of `recv_buf` — all of which collapse into a registered buffer ring + multishot recv. **Task 0 inserted before Task 1.** It is non-blocking for Tasks 1-4 but lands a measurable win on its own and may shrink the marginal gain of the coro pool (less recv-path frequency = less per-request coro alloc weight).

**Goal:** Recover ~12-18 % throughput across five mechanical changes, no architectural rewrite, no bet against Mojo's eventual `async`/`await`.

**Architecture:** Two-target spread:
- **mojo-net changes (Tasks 0, 3, 4):** provided-buffer recv ring; stream-state `Dict` → `InlineArray`; HPACK encoder fast paths.
- **boucle changes (Tasks 1, 2):** coroutine pool + per-coro TLS-lookup elimination. Owned upstream — needs PR.

**Methodology rule (from Phase 1 retro):** Every per-task perf claim requires a **120 s minimum capture** with **3-run spread reporting** (median + min + max). Per-task 60 s captures are noisy enough to over-state wins by 3-5×.

**Tech Stack:** Mojo 0.26.2, boucle stackful coroutines (ucontext-based), Mojo MCP `validate` + `execute`.

---

## File structure

| File | Changes | Requirements |
|------|---------|--------------|
| `bench/h2_server.mojo` | Replace per-conn `recv_buf` + `recv_in_flight`-gated `submit_recv` with: per-worker buffer ring (`provide_buffers` at boot), `submit_recvmsg_multishot(buf_group=...)` per connection, decode `IORING_CQE_F_BUFFER`/`buf_id` from CQE flags, `reprovide_buffer` after copy-out | R0 |
| `boucle/boucle/stackful.mojo` (upstream) | Coroutine pool: reuse stacks across coro spawn/destroy cycles; new `CoroutinePool` struct + `acquire`/`release` | R1 |
| `boucle/boucle/_sys/linux/ucontext.mojo` (upstream) | If `__tls_get_addr` is reachable: switch current-coro pointer from TLS to per-CPU/`thread_local` register pattern (or `__thread` storage class) | R2 |
| `src/h2/h2_coro_server.mojo` | Use `CoroutinePool` from boucle for per-request coro spawn | R1 |
| `src/h2/connection.mojo` (Phase 0 line 507 area) | `_streams: Dict[Int, StreamState]` → `_streams: InlineArray[Optional[StreamState], MAX_CONCURRENT_STREAMS]` (sparse-but-bounded) | R3 |
| `src/h2/hpack.mojo` (HpackEncoder section, ~lines 50-160) | Hot-path fast lookups: static-table reverse map + inline single-byte `:status` codes for common values (200, 204, 404, 500) | R4 |
| `bench/profile/baselines/h2-throughput.csv` | One row per task, post-task 120s × 3 runs (median appended) | R5 |
| `bench/profile/baselines/h2-hotspots-<sha>.md` | One per task | R5 |
| `plans/2026-04-26-h2-perf-phase2-coro-runtime-retrospective.md` | New | R5 |

---

## Requirements

- **R0 — Provided-buffer recv ring.** Per worker, register a buffer pool via `provide_buffers(buf_base, buf_size=8192, count=512, group_id=1, base_buf_id=0)` at boot. Replace per-connection 8 KB `recv_buf` field + `recv_in_flight` gate + per-recv `submit_recv` with `submit_recvmsg_multishot(fd, msghdr_ptr, buf_group=1, token=...)` once per connection. CQE flags carry `IORING_CQE_F_BUFFER` + `buf_id = flags >> 16`. `IORING_CQE_F_MORE` cleared = multishot ended (re-submit). Copy out the kernel-selected buffer's payload, then `reprovide_buffer(buf_ptr, buf_size, group_id=1, buf_id)` to return it to the pool. Per-connection state shrinks; the recv-buffer 8 KB allocation moves from per-connection to per-worker (512×8K = 4 MiB total per worker, fixed).
- **R1 — Coroutine pool.** Per spike: every request currently allocates+initializes a coro. Add a fixed-size pool (default 256) of pre-initialized coroutine slots. On request: `pool.acquire()` returns an idle slot or allocates a new one (capped). On request done: `pool.release(slot)` returns it to the freelist. Must be safe under multi-worker (per-worker pool, not global).
- **R2 — `__tls_get_addr` elimination.** Phase 0 measured 5.96 % self. Investigate where in boucle the per-coro thread-local lookup happens. Switch to a faster mechanism: `__thread`-declared storage (linker-resolved offset, no `__tls_get_addr` call), or a per-CPU pointer accessed via `rseq` / `getcpu`. The first is much simpler and may suffice.
- **R3 — Stream-state `InlineArray`.** Replace `Dict[Int, StreamState]` with `InlineArray[Optional[StreamState], 256]` (or whatever the negotiated `MAX_CONCURRENT_STREAMS` cap is). Stream IDs are sparse (1, 3, 5, …) but bounded — index by `(stream_id - 1) >> 1` modulo the cap. Pattern lifted from json-simd-mojo Plan 6 container-stack work.
- **R4 — HPACK encoder fast paths.** `send_headers` 7.34 % inclusive in Phase 0. The encoder isn't broken out as a self hotspot but it IS reachable from this 7 %. Two fast paths:
  - **Static-table reverse map** (header-name → static-table index): a comptime-built `Dict[String, Int]` so the encoder doesn't linear-scan the static table per header.
  - **Inline `:status` for common codes** (200, 204, 301, 304, 404, 500): emit the static-table index as a 1-byte fixed sequence without going through the integer encoder.
- **R5 — Per-task 120 s × 3-run measurement.** No per-task win is claimed without 3 captures. Report median rps and the spread (min/max). Reject any task whose median doesn't beat the prior median by more than the spread.

---

## Task 0: io_uring provided buffers in H2 recv path

**Files:**
- Modify: `bench/h2_server.mojo` (recv path: drop per-conn `recv_buf`, use multishot recvmsg + buffer ring)
- Reference: `/home/donokami/Projets/perso/boucle/boucle/completion.mojo:209-285` for API
- Reference: `/home/donokami/Projets/perso/boucle/tests/test_provide_buffers.mojo` for usage pattern
- Reference: `/home/donokami/Projets/perso/boucle/tests/test_multishot_recvmsg.mojo` for CQE handling

**Step plan:**

- [ ] **Step 1: Read the boucle API + tests.** Confirm: `provide_buffers` registers contiguous buffers identified by `group_id` + `base_buf_id..base_buf_id+count`; `submit_recvmsg_multishot(fd, msghdr_ptr, buf_group, token)` requires a per-connection `msghdr` with zero `msg_iov`/`msg_iovlen` (kernel uses provided buffer); CQE.flags carries `IORING_CQE_F_BUFFER` + `buf_id` in upper 16 bits, `IORING_CQE_F_MORE` clear means multishot ended.
- [ ] **Step 2: Test scaffolding.** Write `tests/test_h2_server_recv_ring.mojo` (or a minimal harness inside `bench/`) asserting one connection through the H2 server consumes provided buffers, returns them via `reprovide_buffer`, and survives the buffer ring being smaller than concurrent connections (back-pressure path).
- [ ] **Step 3: Boot-time buffer-ring registration.** In `bench/h2_server.mojo:main`, after the `CompletionLoop` is built, allocate `BUF_RING_SIZE × 8 KB` once via `_heap_alloc[UInt8]`, call `loop.provide_buffers(buf_base, 8192, BUF_RING_SIZE, group_id=1, base_buf_id=0)`. Track `buf_base` for `reprovide_buffer` arithmetic: `buf_ptr_for(buf_id) = buf_base + buf_id * 8192`.
- [ ] **Step 4: Per-connection msghdr.** Each `H2Conn` gets a heap-allocated `msghdr` (zero `iov`, zero `iovlen`, zero `msg_name`, etc). Drop the `recv_buf` field. On accept, replace `_queue_recv` with a single `submit_recvmsg_multishot(fd, msghdr_ptr, buf_group=1, token)`.
- [ ] **Step 5: Recv CQE handling.** In `_handle_recv`, decode `IORING_CQE_F_BUFFER` + extract `buf_id = flags >> 16`. Compute `buf_ptr = buf_base + buf_id * 8192`. Copy `result` bytes (or pass `Span` if downstream allows) into the existing TLS receive path. Then `reprovide_buffer(buf_ptr, 8192, group_id=1, buf_id)`. If `IORING_CQE_F_MORE` is clear, re-submit `submit_recvmsg_multishot`.
- [ ] **Step 6: Back-pressure / `-ENOBUFS`.** If recv completes with `result == -ENOBUFS`, reprovide a buffer if any are free or fall back to one-shot `submit_recv` for that connection until the ring has capacity. Document the chosen policy.
- [ ] **Step 7: Run all H2 tests** (`scripts/run_tests.sh test_h2_*`). No regressions.
- [ ] **Step 8: 3-run measurement.** `bench/profile/h2-perf-record.sh` × 3 at DURATION=120, capture median rps + spread. Also: confirm via `perf record` that the per-recv buffer-copy hotspot is gone or shrunken.
- [ ] **Step 9: Commit.** `commit-smart` body must include: median rps + spread, before/after recv-path self-time %, and the `recv_buf` field removal.

**Expected gain:** ~3-6 % rps. The per-recv `chunk = List[UInt8](capacity=n) + recv_buf[i] copy` loop in `_handle_recv` is removed; per-connection memory drops by 8 KB; outstanding-recv parallelism increases (multishot keeps draining without per-CQE re-submit).

**Risk:** if mojo-net's connection count regularly exceeds `BUF_RING_SIZE` under high `-c`, we hit `-ENOBUFS` and need either a larger ring or the fallback path. h2load `-c 1000` is the stress case.

---

## Task 1: Coroutine pool in boucle

**Files:**
- Modify: `boucle/boucle/stackful.mojo` (add `CoroutinePool` struct + `acquire`/`release`)
- Modify: `src/h2/h2_coro_server.mojo` (use the pool)

**Step plan:**

- [ ] **Step 1: Spike on boucle's existing coro lifecycle.** Read `boucle/boucle/stackful.mojo:1-280`. Identify where the coro stack is allocated, where `getcontext` is called, where the trampoline is set up. Confirm that "fresh coro per request" is happening at the H2 server layer (not boucle's CompletionLoop), so the pool can live in mojo-net only.
- [ ] **Step 2: Decision.** If the per-request coro allocation is mojo-net's choice (in `H2CoroServer`), implement the pool in mojo-net only — simpler. If it's structurally bound up in boucle, add the pool to boucle.
- [ ] **Step 3: Implement `CoroutinePool`** with fixed-size freelist + soft cap. API:
  ```mojo
  struct CoroutinePool[T: AnyType]:
      def __init__(out self, capacity: Int): ...
      def acquire(mut self) -> CoroutineSlot: ...
      def release(mut self, slot: CoroutineSlot): ...
  ```
- [ ] **Step 4: Wire into `H2CoroServer._dispatch_events` (or wherever the per-request coro is spawned).** Replace the alloc-then-getcontext path with `pool.acquire()`.
- [ ] **Step 5: Run all H2 tests** (`scripts/run_tests.sh test_h2_*`). Conformance suite must not regress.
- [ ] **Step 6: 3-run measurement.** Run `bench/profile/h2-perf-record.sh` 3 times at DURATION=120, capture median. Re-run swapcount LD_PRELOAD (recompile if needed) and verify `getcontext`/req has dropped (toward 0 in steady state, since pooled coros aren't re-initialized).
- [ ] **Step 7: Commit.** `commit-smart`. Body must include the 3-run rps median + spread + the new `getcontext`/req number.

**Expected gain:** ~3 % rps, getcontext/req ~0 in steady state.

---

## Task 2: `__tls_get_addr` elimination

**Files:**
- Investigate: `boucle/boucle/_sys/linux/ucontext.mojo`
- Investigate: `boucle/boucle/stackful.mojo` for current-coro lookup patterns
- Possibly modify: a small C shim or Mojo `external_call` to a `__thread`-declared symbol

**Step plan:**

- [ ] **Step 1: Locate the `__tls_get_addr` callsite.** Phase 0 flamegraph showed it's reachable from many parents (drain_responses, dispatch_events, _trampoline). It's almost certainly the boucle runtime's "get current coroutine" lookup. Read the relevant boucle source to find the TLS variable.
- [ ] **Step 2: Determine if the variable uses `thread_local` (Mojo) or `__thread` (C ABI).** The `__tls_get_addr` calls suggest TLS via the dynamic-linker GD model. Linker-resolved IE/LE TLS models are 5-10× faster but require the variable to be in the main binary, not a shared library.
- [ ] **Step 3: Decision.** Either:
  - **(a) Move the TLS variable into the binary** (link as IE model — fast `mov`-based access, no `__tls_get_addr`). Requires reorganizing boucle's binary layout.
  - **(b) Cache the per-coro pointer in a register** for the duration of a coroutine's execution. Saves the lookup but adds compiler complexity.
  - **(c) Switch to a single-thread-per-worker model** where the "current coro" is a process-global atomic. Eliminates TLS entirely if mojo-net's worker model already has 1 worker = 1 thread (verify).
- [ ] **Step 4: Implement** the chosen approach.
- [ ] **Step 5: H2 tests + 120 s × 3-run measurement.**
- [ ] **Step 6: Commit** with median rps + spread + new `__tls_get_addr` self %.

**Expected gain:** ~5 % rps. The 5.96 % `__tls_get_addr` self should drop by at least half.

**Risk note:** if (a) requires PIE/non-PIE build flag changes, this may collide with rustls's loader requirements. Verify before committing to this path.

---

## Task 3: Stream-state `Dict` → `InlineArray`

**Files:**
- Modify: `src/h2/connection.mojo` (around line 507, `_streams` field)
- Modify: `src/h2/connection.mojo` (all `_streams` callsites — `[stream_id]`, `__contains__`, iteration)

**Step plan:**

- [ ] **Step 1: Inventory `_streams` callsites.** `grep -n _streams src/h2/connection.mojo`. Likely: insert on stream open, lookup on every frame, remove on stream close, iteration on connection close.
- [ ] **Step 2: Decide on the index function.** H2 stream IDs are 1, 3, 5 (client) or 2, 4, 6 (server). Index = `(stream_id - 1) >> 1` modulo `MAX_CONCURRENT_STREAMS`. Verify this stays bounded by the negotiated `SETTINGS_MAX_CONCURRENT_STREAMS`.
- [ ] **Step 3: Replace `Dict[Int, StreamState]` with `InlineArray[Optional[StreamState], MAX_CONCURRENT_STREAMS]`** (or `List[Optional[StreamState]]` pre-sized to the cap if `InlineArray` doesn't compose with `Optional`).
- [ ] **Step 4: Run H2 tests + integration tests.** Particularly stream-state edge cases: refused streams (`MAX_CONCURRENT_STREAMS+1` arrives), stream reset cleanup, GOAWAY behavior.
- [ ] **Step 5: 120 s × 3-run measurement.** Verify `Dict::_insert` self drops from 2.77 % to <0.5 %.
- [ ] **Step 6: Commit.**

**Expected gain:** ~2 % rps. Pattern proven in json-simd-mojo Plan 6.

---

## Task 4: HPACK encoder fast paths

**Files:**
- Modify: `src/h2/hpack.mojo` (HpackEncoder section)

**Step plan:**

- [ ] **Step 1: Profile the encoder specifically.** Run perf-record on a workload that's response-heavy (h2load -n 10000 against `/json/...`). Capture the encoder hotspot (it didn't show in Phase 0 self because each call is small; should show as inclusive under `send_headers`).
- [ ] **Step 2: Build a comptime static-table reverse map.** The HPACK static table (RFC 7541 Appendix A) has 61 entries. Build `Dict[String, Int]` at struct construction time so encoder lookups are O(1).
- [ ] **Step 3: Inline the common `:status` byte sequences.** For `:status: 200`, the wire sequence is a single byte `0x88` (static table index 8 with the indexed-header bit set). Same for 204 (`0x89`), 301 (`0x8A`), etc. Special-case these instead of running the encoder.
- [ ] **Step 4: Run H2 tests + conformance.** HPACK encoding tests must pass.
- [ ] **Step 5: 120 s × 3-run measurement** on `/json/...` workload (where header encoding matters more than `/baseline2`).
- [ ] **Step 6: Commit.**

**Expected gain:** ~2-4 % rps on encoder-heavy workloads (`/json/...`). Smaller on `/baseline2`.

---

## Task 5: Final retrospective + Phase 3 decision gate

**Files:**
- Create: `plans/2026-04-26-h2-perf-phase2-coro-runtime-retrospective.md`

- [ ] **Step 1: Final 120 s × 3-run measurement** (mojo-net + hyper, `/baseline2` and `/json/...`). Use the median rps as the headline.
- [ ] **Step 2: Cumulative table** (Phase 0 → Phase 1 → Phase 2). Include median + min/max spread per row, and mojo/hyper ratio.
- [ ] **Step 3: Per-task win attribution** with honest 120 s numbers (not 60 s noise).
- [ ] **Step 4: Phase 3 decision.** If mojo/hyper ≥ 80 % on `/baseline2`, **declare victory and stop perf**. Otherwise: **draft Phase 3** scoped to either:
  - Path A (full stackless rewrite — only if Mojo ships `async`/`await` first or the gap is unacceptable).
  - `Bytes`-style refcounted byte slice abstraction (replaces `String` for headers; closes the per-request String allocation cost).
  - `[libAsyncRT]` 19 % opacity triage (needs Modular debug build).
- [ ] **Step 5: Commit.**

---

## Exit criteria

Phase 3 is not drafted until Phase 2's retrospective answers:

1. What is mojo-net's median rps on `/baseline2` post-Phase-2, % of hyper?
2. Did `__tls_get_addr` self drop ≥ 50 %?
3. Did `getcontext`/req drop to ≤ 0.1 (steady-state pool reuse)?
4. Did `Dict::_insert` self drop ≥ 50 %?
5. Did the cumulative throughput cross the 80 % decision gate?

---

## Out of scope

- **Path A (full stackless rewrite).** Deferred to Phase 3 if and only if Phase 2 doesn't close the gap.
- **`Bytes`-style refcounted slice abstraction.** Deferred — large new abstraction, Phase 3 territory.
- **`[libAsyncRTRuntimeGlobals.so]` triage.** Blocked on Modular debug-symbol build. Phase 3 candidate.
- **Per-frame response-writer alloc reuse.** Phase 1 Task 5 falsified the connection-buffer angle; the actual realloc source needs separate investigation. Phase 3.
- **rustls swap, kTLS, OpenSSL/BoringSSL.** Phase 0 falsified.
- **H1 plain and H3.** This plan is H2 TLS only.

---

## Risk notes

- **R1 coroutine pool**: the pool needs to handle coro-died-mid-request gracefully (panic in handler must release the slot, not leak). Test path: synthetic handler that raises.
- **R2 `__tls_get_addr` elimination**: linker model changes can interact with rustls and Docker's PIE policies. Test by running the full conformance suite + the bench Docker image build before declaring success.
- **R3 stream-state InlineArray**: H2 streams can be reset and re-opened with the same ID? Verify against RFC 7540 §5.1.1 (stream-id reuse rules) before assuming the index function is collision-free.
- **R4 HPACK encoder**: the comptime reverse map must match exactly the static table ordering used by the decoder, or HPACK becomes inconsistent across peers. Single source of truth for the static table.
- **Methodology**: 120 s × 3 runs takes ~6.5 minutes per task measurement, ~30 min for Phase 2 cumulative. Plan time accordingly.
