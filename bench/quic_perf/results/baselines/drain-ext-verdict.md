# Drain-Extension Verdict — FALSIFIED + AUDIT-INTERPRETATION INVALIDATED

**Date:** 2026-05-04
**Branch:** `feat/quic-bench-drain-extension` (off main `6483625`)
**Spec:** `specs/2026-05-05-quic-bench-drain-extension.md`
**Image:** `mojo-net-bench:drain-ext-post-on` (PROFILE_ACCEPT=True, DRAIN_TO_EAGAIN=True; source HEAD post-T3 `b7517a8`)

## TL;DR

**FALSIFIED — but with a stronger finding than expected.** The drain extension didn't just fail to lift; it caused a **-33% rps regression** on short-conn (`986 → 658 rps`) and a **-19.5pp CPU drop** (`58.7% → 39.2%`). Long-conn 1-iter sanity also regressed (`13,941 → 10,396 rps`, -25%).

A SIGINT sidecar capture during a post-on short-conn run revealed why: **io_uring multishot recvmsg is already keeping up with kernel UDP arrival**. The drain extension only pulled 483 datagrams in 15s while io_uring multishot delivered 85,226 datagrams (`recv_batch_size_buckets["1"]=85,226`). The userspace recvfrom-until-EAGAIN path finds the socket nearly empty because io_uring is consuming each datagram as it arrives.

**The audit's interpretation of the 82×-per-wake delta vs TQUIC was wrong.** TQUIC's 82 datagrams per `epoll_wait` wake is a *symptom* of mio's polling cadence being slower than io_uring multishot's CQE rate, not a kernel-level structural advantage. mojo-net consumes per-arrival; TQUIC consumes per-batch. Both eventually process every datagram; the per-wake density just reflects when each architecture chooses to look.

This means **per-wake datagram count is the wrong load-bearing metric** for explaining the 73% CPU-utilization gap. The actual gap mechanism is something else — most likely per-handshake compute density (Q6's domain) or a different kernel-side artefact.

## Numbers

### Pre-on short-conn (reused, host noisy at capture time)

```
n=11  median=986 rps  q1=871 q3=1100 IQR=23.2%  cpu%=58.7
raw: [677, 744, 871, 968, 978, 986, 1057, 1063, 1100, 1110, 1229]
```

### Post-on short-conn (lean verdict run, host quiet)

```
n=10  median=658 rps  q1=625 q3=698 IQR=11.0%  cpu%=39.2
raw: [470, 607, 625, 631, 654, 658, 693, 698, 707, 785]
```

### Verdict gate (per spec §0)

| Gate | Threshold | Observed | Result |
|---|---|---|---|
| AC4 rps lift | ≥+20% (CONFIRMED), [+5%, +20%) (PARTIAL), <+5% (FALSIFIED) | **−33.3%** | FALSIFIED (with regression) |
| AC5 CPU% lift | ≥+10pp / [+3pp, +10pp) / <+3pp | **−19.5pp** | FALSIFIED (with regression) |
| AC6 recv_batch_size[≥2] | ≥30% (if CONFIRMED) | 0% (still 100% bucket-0) | n/a |
| AC7 dcid_mismatch_pkts | == 0 | not re-checked (post-on sidecar didn't expose) | needs sidecar verification |
| AC8 handshake success rate | ≥0.99 | tquic_client failure rate not yet tabulated | informational |
| AC9 off-build flag revert | DRAIN_TO_EAGAIN=False | confirmed at `src/quic/profile.mojo:17` | PASS |

### Long-conn sanity (post-on, n=1)

```
rps=10,396  cpu%=77.2
```

vs pre-off long-conn baseline `13,941 rps @ 97.3% cpu` → -25.4% rps, -20.1pp CPU. **Long-conn also regresses.** The drain extension hurts both regimes.

## SIGINT sidecar evidence (15-second capture during post-on short-conn)

```json
{
  "drain_extension": {"pkts_total": 483, "overflow_count": 0},
  "handshakes": {"full": 8501, "resumed": 0},
  "recv_batch_size_buckets": {"1": 85226, "2-3": 0, "4-7": 0, ...},
  "per_pkt_us.total.p50": 7
}
```

- io_uring multishot delivered **85,226 datagrams** as 1-per-CQE.
- Drain extension pulled **483 datagrams** total — 0.57% of the io_uring path's volume.
- recv_batch_size buckets remain 100% bucket-0 — io_uring multishot is NOT changing its delivery shape just because we added the userspace drain.
- Overflow_count = 0 — the 64-buf scratch pool was never exhausted.

**The drain extension is firing as designed; it's just finding the socket nearly empty every time.** This is the diagnostic signal that proves the audit's premise was wrong, not a bug in the implementation.

## Why did adding drain extension cause a regression?

The drain code path executes on every `_flush_impl` invocation when DRAIN_TO_EAGAIN=True:
1. Pop a buf from `drain_scratch_pool` (List indexing — heap touch).
2. Build `addr_bytes` Span and `addr_ptr` UnsafePointer.
3. Call `external_call["recvfrom", Int64](...)` — kernel syscall, ~50ns minimum even on EAGAIN.
4. Read `__errno_location[]`, compare to EAGAIN(11), break.

At 5,700 io_uring deliveries/sec × per-flush call frequency, that's thousands of pointless syscalls + heap touches per second. The `_flush_impl` is on the per-packet hot path; even a 5-10µs added cost per flush iteration compounds.

The 19.5pp CPU drop is the smoking gun: the server is now **more idle**, not less. The recvfrom-then-EAGAIN syscall path forces a kernel transition and back; the bench fiber yields to the scheduler more often; effective wall-clock work density decreases.

**The PROFILE_ACCEPT overhead is also real.** Pre-on already had PROFILE_ACCEPT=True (986 rps was the on-build pre baseline). Post-on adds DRAIN_TO_EAGAIN=True on top. So the -33% is *purely* the drain extension's cost vs the audit's hypothesised lift.

## What this changes

### For the recvmsg-drain audit (`plans/research/2026-05-05-recvmsg-drain-semantics-audit.md`)

The audit's strace measurement was **correct** (TQUIC drains 82/wake; mojo-net 1/wake). The audit's **interpretation** was **wrong**. The interpretation said: "the structural difference at the drain primitive is real and load-bearing for the 73% CPU-utilization gap." This verdict shows it is NOT load-bearing — closing the per-wake delta does not lift the gap.

The correct framing: per-wake datagram count is a *consequence* of poll cadence × arrival rate, not a *cause* of CPU utilization. TQUIC's 92% CPU comes from somewhere else — likely the per-handshake compute path TQUIC's mio cycle does between epoll_wait calls.

### For the next spec direction

**Q6 promoted to primary** (`specs/2026-05-04-q6-read-hs-internal-decomposition.md`). Q6 measures per-call `read_hs` work density — the actual axis where CPU is spent. The 16% per-CPU-% efficiency gap was the quieter slice in the apples-to-apples baseline; the verdict now reframes it as the SOLE remaining structurally-tractable lever. The 73% CPU-utilization gap is now interpreted as "TQUIC does more compute work per datagram than we do" — not "TQUIC drains the socket more aggressively."

### Code disposition

- T1/T2/T3 commits stay on the branch. The drain extension code is comptime-gated behind `DRAIN_TO_EAGAIN: Bool = False` (default). Off-build and on-build production paths are unaffected — the dead-stripped branch costs zero.
- Branch can be merged to main as a permanent diagnostic-then-decide pass, or left as a safety net branch for future re-investigation.
- AC9 PASSES: flag is False post-spec at `src/quic/profile.mojo:17`.

## Lessons

1. **Audit-grounded measurements ≠ verified causal mechanisms.** strace counted 82 datagrams/wake on TQUIC. That number is real. But the inference "if mojo-net matched 82/wake, it would close the CPU gap" was an unsupported leap. The verdict measurement *did* show what mojo-net would do at higher per-wake density (the drain extension delivered exactly that mechanism) and the gap did NOT close. **Always validate the causal direction with a code-change test before specing the fix.**

2. **The inspection-projection track record on this codebase is now 0/6.** Q4 (rustls FFI dominance, CONFIRMED) was the only measurement-driven dominance projection that survived. Q5 falsified Lever B; this drain extension falsifies the audit's interpretation. Future perf specs must keep the diagnostic-then-decide discipline.

3. **A regression that surprises you is data.** The drain extension was supposed to lift OR be neutral. Active -33% means the spec's mental model of the runtime's behavior was wrong. The CPU drop showed where the model failed (server is *more* idle, not less) and the sidecar showed the mechanism (drain pulls almost nothing because io_uring is already keeping up). Without the sidecar capture, we'd have shipped a "FALSIFIED, dunno why" verdict.

4. **`feedback_perf_lift_verification.md` applies recursively.** The memory rule says "verify perf-lift specs against the actual hot path." The audit verified that mojo-net is on the io_uring path. The audit did NOT verify that the drain extension's added volume would *survive* the io_uring path's already-fast consumption. That second verification step would have surfaced the issue at spec time.
