# `/loop` retrospective — short-conn refactor cycle (2026-05-11)

> Closes the short-conn perf cycle. Cycle started after the Q10 verdict landed (`0e213ce`) on the same day. User directive: "long-conn-style refactor pass on short-conn ingress, /loop until we close the gap." Cycle stopped mid-iter-2 after the structural finding below.

## Outcome

- **1 productive iter committed** (`9259549`): two per-pkt `List[UInt8]` copies eliminated in `_quic.recv_from_buffer`. -5.86% p99, -3.90% p50, -1.32% CPU, **rps unchanged** (null at n=5 detection threshold of 1.52%).
- **1 diagnostic iter not committed**: invalidated its own premise (option A — per-iter `io_uring_enter`) via closer reading of Q10 sidecars.
- **Calibrated TQUIC baseline on the VPS** (n=5): 2,085.9 rps, 86% CPU, p50 6.22ms, p99 72.33ms. → mojo-net on this hardware = 0.466× TQUIC.

## Headline finding (banked to `feedback_short_conn_gap_is_structural.md`)

**The long-conn playbook does not translate to short-conn.** Long-conn's 267× lift came from CPU-bound hot-path refactors (Dict ref-binding, dead-list elimination, two-span sends). Short-conn isn't CPU-bound on the Mojo side: the server is parked ~80% of wall-clock per Q7+Q10, and iter-1 confirmed that freed Mojo compute reduces latency tail (-6% p99) but does NOT lift rps.

The 1.82× CPU-efficiency gap vs TQUIC (mojo-net: 0.075% CPU/rps, TQUIC: 0.041% CPU/rps) is **structural**, not addressable by per-packet copy elimination or similar Mojo-side refactors.

## Where the gap actually lives (best localization from this cycle's data)

| Measurement | Value | Interpretation |
|---|---:|---|
| `hs_cpu_us_per_handshake` avg | 217µs | Per-handshake CPU work — cheap |
| `arrival_lat_us` avg (recvmsg→flush) | 87µs | mojo-net internal queueing — fast |
| `hs_wait_us_per_handshake` avg | 10,987µs | Wall-clock wait minus CPU |
| **Per-RTT extra delay** | **~3.56ms** | (hs_wait/3 − ~100µs loopback RTT) |
| Average park-to-park interval | 56µs | Submit batching delay — too small to be culprit |
| Server CPU% | 73% (mojo-net) vs 86% (TQUIC) | mojo-net is parked, not compute-bound |

The 3.56ms per-RTT lives **outside mojo-net's main loop** — likely in:
- Kernel UDP loopback send→recv path
- tquic_client mio/epoll cadence at 25 conns/thread × 4 threads
- Per-conn cycle gap between client conn-close and conn-open

Without sudo on the VPS (no tcpdump/bpftrace access), final attribution to one of these requires either a different bench host or instrumented client.

## Levers considered and rejected this cycle

- **Mojo-side refactor pass (long-conn playbook)** — iter-1 confirmed null rps lift. Validates `feedback_check_cpu_bound_before_rps_projection.md`.
- **Per-iter `io_uring_enter` inside `_flush_impl`** (option A) — invalidated by data: park-to-park is 56µs avg, kernel sees SQEs fast.
- **Egress GSO / `sendmmsg` batching** (option pre-A) — invalidated by source audit: TQUIC's bench tools use plain `send_to(2)` per packet (`tools/src/common.rs:218`). No batching there either.
- **SQPOLL via boucle change** — boucle has the `IORING_SETUP_SQPOLL` primitive but `BatchCompletionLoop` doesn't expose it; the boucle plan doc flags an atomic-fence blocker (Mojo 0.26.2 may still lack release-ordering primitives). Best-case lift ~3% (below detection); doesn't address the 3.56ms/RTT gap.

## What's banked as evidence

- `iter1-baseline/iter-{1..5}.json` — n=5 baseline at HEAD `b5cdfbf` + iter-1 stash, PROFILE_ACCEPT=False.
- `iter1-post/iter-{1..5}.json` — n=5 post-iter-1 at HEAD `9259549`, PROFILE_ACCEPT=False.
- `tquic-baseline-vps/iter-{1..5}.json` — n=5 TQUIC reference on same VPS, same harness, same workload.
- `bench/quic_perf/scripts/loop_bench.sh` — n=5 perf-bench driver with loadavg gate retry. Reusable for any future /loop cycle.
- `bench/quic_perf/results/baselines/io-path-wait-nr/` — earlier wait_nr sweep raw sidecars (already-committed verdict at `48b4bcd`).

## What's NOT banked

- VPS-side `/tmp/strace_bench.sh` — written but never ran (no sudo password). Discarded.
- Docker image tags `mojo-net-bench:iter1-{baseline,post}` on VPS — temporary, will be overwritten on next rebuild.

## Next phase

User decision (2026-05-11): stop the perf cycle. Pivot to **library cleanup → make mojo-net useful and usable**. The short-conn ratio sits at 0.466× TQUIC for v1; long-conn parity at 1.15× TQUIC remains the public headline.

Future short-conn work (deferred):
- Investigate the 3.56ms/RTT on a host with sudo (tcpdump + bpftrace).
- Spec K' (drain_egress_build_us decomposition, 19% leg, never specced).
- SQPOLL pursuit IF a boucle-side atomic-fence primitive lands.
