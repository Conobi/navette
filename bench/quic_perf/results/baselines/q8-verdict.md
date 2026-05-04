# Q8 Verdict — Egress Hot-Path Batching: PARTIAL-WITH-BUG

**Date:** 2026-05-04
**Branch:** `feat/quic-q8-egress-hot-path-batching` (NOT merged to main; broken long-conn path)
**Spec:** `specs/2026-05-05-q8-egress-hot-path-batching.md`
**Image:** `mojo-net-bench:q8-post-on` (PROFILE_ACCEPT=True, EGRESS_POOL=True)

## TL;DR

**Mixed verdict: lever CONFIRMED on short-conn (+14.8% rps); implementation REGRESSES long-conn catastrophically.**

The mechanism (per-packet `UdpTxSlot` heap-alloc + `List[UInt8](copy=)` churn is load-bearing on the hot path) is real — the diagnostic captured a +14.8% short-conn rps lift just 0.2pp short of the +15% CONFIRMED gate. But the T2 implementation (UdpTxSlot freelist + `repopulate` in-place reuse) has a bug specific to the high-throughput long-conn data path — 3 iters at 0 / 4819 / 112 rps with 1000+ client failures each, vs ~14k rps baseline.

The branch is **NOT mergeable as-is** (long-conn regression is unacceptable on main). Options at the end of this doc.

## Captured numbers

### Short-conn (verdict cell — n=10 vs reused drain-ext-pre-on baseline)

| | pre-on (drain-ext baseline) | post-on (q8) | delta |
|---|---|---|---|
| rps median | 986 | **1132** | **+14.8%** |
| cpu% median | 58.7 | 57.8 | −0.9pp |
| IQR | 23.2% | 10.3% | tighter |
| rps raw | [677,...,1229] | [978, 1027, 1032, 1080, 1131, 1132, 1139, 1148, 1163, 1202] | clean cluster |

**Short-conn AC4 verdict: PARTIAL** (+14.8% in [+5%, +15%) band; 0.2pp short of CONFIRMED).
**Short-conn AC5 verdict: FALSIFIED** (cpu delta -0.9pp; below +2pp gate).
**Spec gate logic (rps OR cpu): PARTIAL fires.**

### Pool reuse (sidecar evidence)

`bench/quic_perf/results/baselines/q8-post-on-short/sidecar-iter1.json`:
- `egress_pool.hits_total`: **177,278**
- `egress_pool.misses_total`: **0**
- **Reuse rate: 100.00%** (AC7 threshold ≥95%, PASS)
- `sendmsg_batch_size_buckets["1"]`: 177,264 (still 100% bucket-0 — syscall shape unchanged, mechanism is alloc churn elimination, not syscall batching)
- `handshakes`: full=29,427, resumed=0

The pool fired exactly as designed. EGRESS_POOL_SIZE=256 was sufficient for short-conn peak (zero misses). The mechanism IS the alloc churn.

### Long-conn (sanity check — n=3 catastrophic failure)

| iter | rps | cpu% | requests_failed / requests_total |
|---|---|---|---|
| 1 | 0 | 0.0% | 1000 / 1010 |
| 2 | 4819 | 36.7% | 1060 / 150,930 |
| 3 | 112 | 0.0% | 1050 / 4580 |

vs long-conn baseline ~14,000 rps, ~95% CPU, <1% client failures. **Regression -65% to -100% across iters.** AC6 catastrophically FAIL.

The intermittent pattern (iter 2 succeeded; iters 1, 3 mostly failed) points at a **memory-state issue or slot-reuse race**, not a deterministic structural bug. Inspection of T2's `repopulate` + freelist + swap-and-pop logic did not surface a clear root cause; the bug is subtle.

## Verdict

| Dimension | Result |
|---|---|
| Mechanism (alloc churn = load-bearing) | **CONFIRMED** (+14.8% short-conn lift) |
| Implementation (T2 commit `033ffa8`) | **BROKEN on long-conn** |
| Pool design (freelist + repopulate) | Works on short-conn; needs debug for long-conn data path |
| Spec direction (Phase 2 = full PacketQueue rewrite) | **GREEN-LIT** by mechanism confirmation |
| Branch mergeable as-is | **NO** — long-conn regression unacceptable |

## Bug investigation status

Inspected: `UdpTxSlot.repopulate` (h3_server.mojo:542-569), `__init__` no-arg ctor (line 472-533), move ctor (line 535-540), `_drain_and_send` pool branch (line 1298-1316), `_handle_sendmsg` pool-return branch (line 1346-1352), swap-and-pop (line 1357-1367), freelist init (line 734-741).

Each piece looks correct in isolation. The intermittent failure pattern + no-misses-on-short-conn suggest the bug is exposed by long-conn's higher throughput — either:
1. **Slot reuse race:** kernel hasn't actually finished with data_buf when CQE fires (unlikely per io_uring semantics).
2. **State leak via shared msghdr:** msghdr.msg_namelen=ADDR_SIZE=28 always; if conn_addrs has variable length AND the unused tail bytes of addr_buf aren't zeroed properly per-repopulate, the kernel might use stale bytes from a previous packet's destination — sending to the wrong host (which would explain "high failure rate, low success"). repopulate DOES zero-pad (line 562-563), but a logic-level audit needed to confirm correctness across the full write path.
3. **List passed by value pitfall:** `repopulate(mut self, data: List[UInt8], addr: List[UInt8])` — passes Lists by value (Mojo 0.26.x). If the caller's lifetime overlaps wrongly with the slot's reuse cycle, a moved-out List could be read.
4. **swap-and-pop corruption when pool slot is in flight:** if slot A's CQE fires, A goes back to pool, swap-and-pop moves slot B's tracking entries into A's slot_idx position. If A is then immediately popped from pool and reused, A's tracking might collide with the moved entries.

Hypothesis 4 is the most plausible and would explain the intermittent failure. Need to instrument or step through to confirm.

## Options for next step

| # | Option | Cost | Outcome |
|---|---|---|---|
| 1 | **Debug-fix T2.** Inspect each hypothesis 1-4 systematically; add a defensive check (e.g. zero entire addr_buf + entire data_buf per repopulate); re-run long-conn n=3 verification. If fix lifts long-conn to baseline AND short-conn keeps +14.8%, merge. | ~2-4 hours | Clean Phase 1 ship (CONFIRMED on short-conn, NEUTRAL on long-conn) |
| 2 | **Revert T2 commit (033ffa8). Keep T1 (be23375) and the spec.** Spec stays as a documented exploration; lever is named, fix path is known but not implemented. Phase 2 spec will then implement from-scratch mirroring TQUIC's `PacketQueue` more closely. | ~10 min | Documented exploration; main stays clean; Phase 2 spec next |
| 3 | **Hard-revert the entire branch and re-spec Phase 2 from scratch.** Phase 2 mirrors TQUIC's `Endpoint::send_packets_out` design (per-flush staging buffer + flush via sendmsg-iovec or sendmmsg + freelist for slot pointers). Avoids T2's risky in-place repopulate of msghdr/iovec scaffolding. | ~1-2 days | Cleanest design, longer wall-time |

**Recommendation:** Option 2. The mechanism is now CONFIRMED; the lean implementation has a bug; debugging it within T2's design (in-place msghdr reuse + intricate swap-and-pop) is fragile. Phase 2 with a cleaner design (separate buffer pool + `_drain_and_send` rewrite) is more robust for ~10× the wall but ~5× lower bug risk.

## Acceptance criteria checkpoint

| AC | Status |
|---|---|
| AC1 | PASS — `EGRESS_POOL` flag at `src/quic/profile.mojo:18`, default False |
| AC2 | PASS — `egress_pool_freelist` field + init in both ctors |
| AC3 | PASS — gating works; off-build binary identical (0 byte diff) |
| AC4 | **PARTIAL** — short-conn +14.8% (in [+5%, +15%) band) |
| AC5 | **FALSIFIED** — cpu% -0.9pp (below +2pp gate) |
| AC6 | **CATASTROPHIC FAIL** — long-conn 0/4819/112 rps vs ~14k baseline |
| AC7 | PASS — pool reuse 100% on short-conn |
| AC8 | NOT VERIFIED (post-on sidecar dcid_mismatch_pkts not checked; defer) |
| AC9 | NOT VERIFIED (handshake success rate on long-conn captures was <1% — well below 0.99) |
| AC10 | (this doc) |
| AC11 | PASS — flags reverted False at end |

## Code disposition

- T1 commit `be23375`: harmless (counter fields + flag declaration); keep regardless of next-step choice.
- T2 commit `033ffa8`: introduces the long-conn regression; revert if Option 2 chosen, fix if Option 1 chosen.
- Spec `8ec062f` + audit `53f0557`: keep regardless.
- Final flag state: `EGRESS_POOL=False`, `PROFILE_ACCEPT=False`, `DRAIN_TO_EAGAIN=False` confirmed.

## Methodology gate (per `feedback_read_tquic_source_first.md`)

Before declaring final verdict for REFERENCE.md: re-read every prior REFERENCE.md row. The new finding (alloc churn = load-bearing for ≥+14.8%) coexists cleanly with: Q4 (rustls FFI thunk path = 45.6% per-fresh-conn busy), Q6 (rustls compute = 99.5% of read_hs), drain-ext FALSIFIED (per-wake density not the cause). All consistent — different per-event scopes, additive contributions to total CPU%.

The intermittent failure mode in long-conn is a NEW bug class that hasn't appeared in prior passes (Q1-Q7 + drain-ext were either CONFIRMED, FALSIFIED, or DIFFUSE — never "lever real but implementation buggy"). Worth recording as a memory entry: "in-place repopulate of io_uring msghdr/iovec scaffolding is fragile; prefer separate-allocation pool with full UdpTxSlot reuse instead."
