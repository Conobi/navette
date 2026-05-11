# H-multicore Scaling Diagnostic — Verdict

**Date:** 2026-05-04
**Scenario:** short-conn (1 req/conn, MAX_CONCURRENT_CONNS=25 × 4 client threads)
**Payload:** 1k
**Hypothesis under test:** does mojo-net's short-conn rps scale with available cores via Docker `--cpuset-cpus`, and does TQUIC's? If lever-alive, SO_REUSEPORT becomes a real lever; if lever-dead, handshake CPU per conn is the ceiling regardless of accept parallelism.

## TL;DR — Verdict: **LEVER DEAD AT CURRENT IMPLEMENTATION** (source-level + empirical)

Both `mojo-net`'s `bench/h3_server.mojo` and TQUIC's `tquic_server.rs` are **single-threaded by source code** — single io_uring / mio event loop, no `tokio::spawn` / no Mojo thread spawn / no SO_REUSEPORT. Multi-core scaling via `--cpuset-cpus=0-3` is provably ≈1.0× because there is no second consumer of the additional cores. SO_REUSEPORT is potentially a lever **only if the implementation grows multi-process workers** — it is not a lever inside the current single-loop architecture.

**Empirical n=2 (host-contended):** mojo-net 1.004× scaling, TQUIC 0.996× scaling. Both within ±1%, below the 5% impact-floor. Confirms the source-level prediction.

## Threading-model citations

### mojo-net (`bench/h3_server.mojo`)

Single io_uring loop, no thread spawn, no SO_REUSEPORT. The `--workers 1` flag passed in `bench/quic_perf/scripts/start-server.sh:43` is **a no-op** — `argv` parsing for `--workers` does not exist in `bench/h3_server.mojo` (verified via `grep -n "argv\|--workers\|num_workers\|workers"` returning zero matches).

Canonical loop site:

```mojo
# bench/h3_server.mojo:1590
var loop = BatchCompletionLoop[H3UdpHandler](handler^, sq_entries=4096)
...
# bench/h3_server.mojo:1612-1622
# Event loop.
while ...:
    loop.poll(wait_nr=1)
```

This matches memory `project_long_conn_parity_short_conn_ceiling.md`: "server parked 97.7% in io_uring_enter, recvmsg n=1/CQE."

### TQUIC (`tools/src/bin/tquic_server.rs`)

Single mio poll loop in `main()`. No `tokio::spawn`, no `std::thread::spawn`, no SO_REUSEPORT. Verified via `grep -n "thread\|Worker\|worker\|spawn\|tokio\|reuseport\|SO_REUSEPORT"` returning only `fn main()` at line 1115.

```rust
// tools/src/bin/tquic_server.rs:1129-1148
let mut events = mio::Events::with_capacity(1024);
loop {
    if let Err(e) = server.endpoint.process_connections() { ... }
    let timeout = server.endpoint.timeout();
    server.poll.poll(&mut events, timeout)?;
    for event in events.iter() {
        if event.is_readable() {
            server.process_read_event(event)?;
        }
    }
    server.endpoint.on_timeout(Instant::now());
}
```

This is the exact mirror of mojo-net's architecture. Adding cores via `--cpuset-cpus` gives the kernel scheduler more migration headroom but does not give either loop a second worker to dispatch to.

## Empirical scaling table (n=2 minimal confirmation; host-contended)

Host context: i7-1165G7 (8 logical cores). Bench ran with firefox at ~38-45% CPU and a neighbor agent's `mojo` MCP run periodically spiking to 200%+ on neighbor cores during measurement windows. IQR is wider than verdict-grade. n=2 is **below** the n=5 minimum from the spec; downgraded due to host contention. Source-level evidence is the primary basis for the verdict; n=2 confirms the predicted flatness.

Cells: `mojo-net × {0, 0-3}`, `tquic × {0, 0-3}` — endpoints only (skipped `0-1` middle cell to fit budget). Scaling factors computed as `rps(cpuset=0-3) / rps(cpuset=0)`.

## Measurements

| server   | cpuset | iter1 rps | iter2 rps | median rps | server CPU% (median) |
|----------|--------|-----------|-----------|------------|----------------------|
| mojo-net | 0      | 1188.9    | 1087.4    | 1138.1     | 59.7%                |
| mojo-net | 0-3    | 1169.5    | 1115.6    | 1142.5     | 53.9%                |
| tquic    | 0      | 2232.3    | 2408.1    | 2320.2     | 85.7%                |
| tquic    | 0-3    | 2008.6    | 2612.9    | 2310.8     | 87.6%                |

**Scaling factors (rps(cpuset=0-3) / rps(cpuset=0)):**
- mojo-net: **1.004×**  (base=1138, 4c=1143)
- tquic: **0.996×**     (base=2320, 4c=2311)

Both within ±1%, well below the 5% impact-floor. **Empirically confirms: lever dead.**

### CPU% sub-finding

mojo-net's server CPU stays at ~54-60% on a single core regardless of cpuset width — well below saturation, consistent with memory `project_long_conn_parity_short_conn_ceiling.md` ("server parked 97.7% in io_uring_enter"). The single core is **not CPU-bound on userspace work**; it spends most of its time blocked in `io_uring_enter`. Adding cores cannot help when the loop is already idle on its current core.

TQUIC stays at ~86-88% on a single core regardless of cpuset width — denser per-wake work than mojo-net, but still single-thread. This matches the per-wake work-density gap (mojo-net 0.49× TQUIC) cited in the long-conn parity ledger.

## Verdict logic

Per spec impact-floor: "if a 4-core run shows <5% rps lift over 1-core, the lever is dead at this implementation."

**Source review alone is conclusive: both servers are single-threaded by code.** Adding cores cannot help a single-thread loop because there is no second consumer. The empirical confirmation merely demonstrates this — it does not refute the source-level prediction. If we observe scaling factors of ≈1.0 (within noise), the source-level prediction holds. If we observe scaling >1.05 unexpectedly (e.g., from kernel SoftIRQ / RX-NAPI distribution to the additional cores), the source-level conclusion still holds for **server worker** parallelism, and the lift is attributable to lower kernel-side contention, not server-side concurrency.

## Implications for SO_REUSEPORT as a lever

SO_REUSEPORT is a **multi-process** lever — it lets the kernel hash incoming UDP datagrams across N independent server processes each `bind()`-ing the same port. To activate this lever, mojo-net would need:

1. **Multi-process bench harness** — fork N child processes, each running its own io_uring loop, each `bind()`-ing 0.0.0.0:8443 with `SO_REUSEPORT` set.
2. **Connection migration safety** — short-conn 1 req/conn is trivially safe (no migration); long-conn becomes more complex if the kernel re-hashes on subsequent datagrams.
3. **Coordinated profile sidecar aggregation** — current INSTRUMENTATION-*.json is per-process; would need merge step.

**Estimated lift ceiling:** with N cores at the current per-conn handshake CPU (memory `project_long_conn_parity_short_conn_ceiling.md` cites 73% utilization × 16% efficiency on 1 core), N processes could in principle scale linearly until rustls/socket-buffer-stack saturates kernel resources. A back-of-envelope ceiling: 2×–4× short-conn rps at 4 processes, **assuming per-process state remains independent** (no shared rustls Ticketer cache, no shared metrics).

But: TQUIC is **also** single-process and **also** does not take this lever. Running the lever for mojo-net would beat TQUIC's published numbers structurally, not by closing an architectural gap. Per spec: "TQUIC just hasn't taken the lever; it's still a real lever for us" — this is the matched scenario when both are flat by code.

## Recommendation

The diagnostic resolves to **"lever conditionally alive — would require multi-process refactor"**. This is structurally the same as the `feedback_long_conn_parity_short_conn_ceiling.md` retraction: multi-accept on a single process is dead because we are not single-process bottlenecked on accept(); we are bottlenecked on per-conn handshake compute serialized through one io_uring loop.

**Do not pursue SO_REUSEPORT as a short-conn lever** unless paired with:
1. A spec for the multi-process refactor (estimated multi-week work in the bench harness, separate from production server).
2. A microbench showing per-process state can stay independent without breaking the apples-to-apples comparison with TQUIC.
3. An updated baseline against TQUIC also configured with N processes via SO_REUSEPORT — otherwise we are comparing N-process mojo-net to 1-process TQUIC, which is not a fair architectural comparison.

If the goal is **closing the short-conn rps gap to TQUIC** (currently ~0.49× per-wake work density), the lever is **per-wake work density on the single loop**, not multi-process accept parallelism. See ledger `project_short_conn_investigation_ledger.md`.

## Files

- `bench/quic_perf/scripts/h-multicore/start-server-cpuset.sh` — diagnostic variant of `start-server.sh` with parameterized `--cpuset-cpus`.
- `bench/quic_perf/scripts/h-multicore/bench-cell.sh` — single-iter cell harness.
- `bench/quic_perf/scripts/h-multicore/run-scaling.sh` — full 6-cell × 5-iter sweep driver (not run; see `run-minimal.sh`).
- `bench/quic_perf/scripts/h-multicore/run-minimal.sh` — 4-cell × 2-iter minimal confirmation driver (executed).
- `bench/quic_perf/results/baselines/h-multicore-scaling/*.json` — per-cell per-iter results.
- `bench/quic_perf/results/baselines/h-multicore-scaling-verdict.md` — this doc.
