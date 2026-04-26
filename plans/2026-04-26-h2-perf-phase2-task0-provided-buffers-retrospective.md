# Phase 2 Task 0 + Task 1 — provided buffers + coroutine pool: retrospective

## Status

**Phase 2 Task 0 (registered buffer ring) and Task 1 (coroutine pool)
landed together.** The 3-run × 120 s methodology in R5 surfaced
genuine wins at every step and confirmed earlier single-capture
measurements were noisy.

### Step-by-step measurement (3 × 120 s captures, `-c 100 -m 10`)

| Step | What changed | Median RPS | Spread |
|---|---|---:|---:|
| Pre-Task 0 baseline (single) | per-conn 8 KB recv_buf + per-recv submit_recv | 10 380 | n/a |
| Task 0 v1 (provide_buffers SQE) | SQE-per-reprovide + buffer-pool tree | 2 589 | n/a (regression) |
| Task 0 Step A (register_buf_ring) | userspace BufRing.add_buffer; copy in recv | **10 094** | 9 608 – 10 108 |
| Task 0 Step B (no-copy Span) | drop recv copy, Span over ring slot | **9 960** | 9 496 – 9 990 |
| Phase 2 Task 1 (coroutine pool) | per-conn `CoroutinePool(capacity=16)` | **10 620** | 10 617 – 10 645 |
| **Phase 2 Task 1.5 (bulk extends)** | `_stage_send` / `_flush_outbound` / send-buf swap → `List.extend` | **17 893** | 17 733 – 17 895 |

Task 1 win **+5.3 % vs Step B median, +2.3 % vs single-capture
pre-Task 0 baseline.** Run-to-run spread collapsed from ~5 % to
**0.3 %** — the pool eliminated a major source of timing variance.
Per Phase 2 R5 (gain 660 RPS > spread 28 RPS), the win is real.

All configurations: 100 % success rate, 0 errored, 0 failed.

## Boucle change shipped

`origin/main` commit `9319574 feat: add submit_recv_multishot for TCP
buffer-ring recv` is in tree:
- `Recv` builder gains `ioprio()` (mirrors `RecvMsg`)
- `CompletionLoop.submit_recv_multishot(fd, buf_group, token)` — TCP
  variant of `submit_recvmsg_multishot`, payload at offset 0 (no
  `io_uring_recvmsg_out` header)
- `tests/test_multishot_recv.mojo` — TCP loopback: registers a
  4 × 1024 ring, sends "hello" via SOCK_STREAM, asserts
  `IORING_CQE_F_BUFFER | IORING_CQE_F_MORE` and payload at offset 0
  of `buf_id=0`. **Test passes.**

This is reusable across mojo-net and any other TCP server.

## mojo-net changes (working tree, uncommitted)

`bench/h2_server.mojo` — 156 insertions / 27 deletions:
- Boot: 1024 × 8 KB buffer ring registered via `loop.provide_buffers`
  with `group_id=1`, `base_buf_id=0..1023`. 8 MiB resident per worker.
- `H2Conn` drops the per-connection 8 KB `recv_buf` (8 KB × N conns →
  8 MiB shared ring).
- Accept queues `submit_recv_multishot(fd, buf_group=1, token)` once
  per connection instead of per-recv `submit_recv`.
- `_handle_recv(idx, result, flags)`: decodes `buf_id` from
  `flags >> IORING_CQE_BUFFER_SHIFT`, computes `buf_ptr = buf_base +
  buf_id * 8192`, copies the kernel-selected slice into a fresh
  `List[UInt8]`, queues a `reprovide_buffer` SQE, calls
  `tls.receive_data`. On `-ENOBUFS`, re-arms the multishot. On
  `IORING_CQE_F_MORE` clear, re-arms.
- New `OP_PROVIDE_BUFFERS = 3` op kind so provide / reprovide
  completions don't collide with `OP_ACCEPT = 0` (default token = 0
  was previously routed into `_handle_accept` as `result == 0` →
  treated as `accept(fd=0)` zombie connection — caught and fixed).
- `_drain_pending_submits` learns `_SUBMIT_RECV_MULTISHOT` and
  `_SUBMIT_REPROVIDE_BUFFER`.

Build clean. Functional tests pass.

## Why the perf regressed at `-c 100`

**The reprovide SQE costs the same as the saved recv submit.**

Pre-Task 0:
- 1 `submit_recv` SQE per recv CQE = 1 SQE per recv
- Per-conn 8 KB stack alloc, no kernel buffer-pool tree

Task 0:
- 0 `submit_recv` (multishot is one-shot at accept)
- 1 `reprovide_buffer` SQE per recv CQE = **1 SQE per recv** (same)
- Plus: `IORING_OP_PROVIDE_BUFFERS` kernel-side maintains a
  buffer-ID tree per `buf_group`, with insert/lookup work per
  reprovide and per recv

Net: same SQE volume, more kernel-side bookkeeping per recv. At
low conn count, the saved per-conn 8 KB allocation + the avoided
per-recv submit_recv path-length wins. At `-c 100`, the buffer-pool
tree becomes a contention/cache hotspot and the win flips negative.

Connect time on the regressing config (`170 ms` mean, vs `66 ms`
baseline) is the smoking gun: accept-time cost rose, not recv-time
cost. The kernel does the buffer-pool lookup on every CQE; under
100 simultaneous multishots the tree gets pounded.

## Path forward — pick one

### Option A: Wait on `IORING_REGISTER_PBUF_RING` (recommended)

The kernel has a **second** provided-buffer API (since 5.19): the
ring-mapped buffer pool. The user space writes `buf_id` directly into
a kernel-shared mmap'd ring; the kernel reads it without an SQE.
Per-recv work becomes one cache-line write (no `IORING_OP_PROVIDE_BUFFERS`
SQE, no buffer-pool tree). This is the right primitive for the H2
server — 100+ multishot recvs with full ring throughput.

Boucle currently exposes `IORING_OP_PROVIDE_BUFFERS` only. Adding
`register_buf_ring` + `reprovide_via_ring` would be a
~150-300-line PR (kernel struct mapping + a small Mojo wrapper).
After it lands, this Task 0 implementation flips: drop the
`reprovide_buffer` SQE, write `buf_id` into the shared ring,
expect `-c 100` perf to recover and exceed baseline.

**Estimated boucle PR effort:** 1 day.
**Estimated mojo-net cutover:** 2 hours (replace 4 callsites in
`bench/h2_server.mojo`).

### Option B: Revert Task 0 and skip to Task 1

The Phase 2 plan's original tasks (CoroutinePool, `__tls_get_addr`,
`InlineArray` streams, HPACK encoder) are independent of provided
buffers. Reverting `bench/h2_server.mojo` to `dc70099` and starting
Task 1 keeps the +12-15 % goal on track. The boucle
`submit_recv_multishot` commit (`9319574`) stays — it's correct and
useful even unused, and unblocks Option A whenever we revisit.

### Option C: Profile the regression and patch in tree

Bring up `bench/profile/h2-perf-record.sh` against the new binary,
diff the flamegraph against the pre-Task 0 capture. If the dominant
delta is in
`io_uring_submit_buf_provide_to_pool` / `io_uring_alloc_pbuf` (or
similar kernel symbols), Option A is confirmed. If something else
shows up (e.g. user-space `_drain_pending_submits` overhead), there
may be a workaround within the existing boucle API.

## Recommendation

**Option A.** The boucle PR is small, the registered-ring API is the
"right" primitive for this server's recv path, and shipping Task 0
behind a half-API just to get a partial win delays the real one.

In the meantime: **do not commit the `bench/h2_server.mojo`
diff to a perf-claiming branch.** Either revert and pursue
Option A's boucle PR first, or commit as a `wip:` snapshot on a
side branch for reference.

## Files touched

| File | State |
|---|---|
| `/home/donokami/Projets/perso/boucle/boucle/_sys/linux/io_uring/op.mojo` | committed `9319574`, pushed |
| `/home/donokami/Projets/perso/boucle/boucle/completion.mojo` | committed `9319574`, pushed |
| `/home/donokami/Projets/perso/boucle/tests/test_multishot_recv.mojo` | committed `9319574`, pushed |
| `bench/h2_server.mojo` | uncommitted (works, but 4× slower at `-c 100`) |
| `plans/2026-04-26-h2-perf-phase2-coro-runtime.md` | committed `dc70099` (added Task 0 section) |

## Open data

- Functional test matrix above is empirical; perf comparison ran
  once each, single-process, single h2load client, host-built binary.
- The 5 000-req `-c 10 -m 10` smoke at `2 532 RPS` is genuinely faster
  than the pre-Task 0 baseline of `1 132 RPS`. The contention model
  (kernel pool tree) predicts this — 10 conns don't stress the tree.
- 120 s × 3 measurement (per Phase 2 R5) was not run because the
  cliff at `-c 100` made it moot.
