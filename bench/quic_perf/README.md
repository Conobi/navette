# QUIC Perf Bench Harness

TQUIC-style HTTP/3 benchmark comparing mojo-net's `h3_server` to the TQUIC reference, under matched payloads, matched concurrency, and CPU-saturating load.

> **Status: calibrated.** End-to-end run validated against the TQUIC reference: `tquic_server` saturates core 0 at 87K req/s with `tquic_client` (88% CPU), confirming the harness exposes real saturation. `results/REFERENCE.md` has the current numbers; mojo-net measures ~210× slower long-conn and ~2,500× slower short-conn than TQUIC on the same hardware, while using <6% of one core — the bottleneck is connection-establishment throughput, not steady-state stream work.

## What this measures

The throughput (req/s, MB/s) and server CPU% of mojo-net's H3 stack vs `tquic_server` (pinned to upstream `v1.0.0`, commit `4dcec0f`) over loopback, using both `tquic_client` (multi-threaded, drives to saturation) and `h2load-h3` (single-threaded, kept for regression tracking against our prior numbers). Methodology mirrors https://tquic.net/docs/further_readings/benchmark/.

## What this is NOT

This is **not** the HttpArena leaderboard harness. For "do we beat nginx in HttpArena's profile," see `specs/2026-04-21-quic-benchmark-suite.md` and the existing `bench/` scripts. The two harnesses are independent and produce different numbers (different stress model, different load generators, different comparison set).

## Prerequisites

| Requirement | Why | Verify |
|---|---|---|
| Linux kernel ≥ 5.19 | `IORING_REGISTER_PBUF_RING` for mojo-net's multishot recvmsg | `uname -r` |
| x86_64 architecture | Mojo build targets x86_64 | `uname -m` |
| Docker ≥ 20.10 with `--network host` | All images run on host networking | `docker version` |
| Docker CLI with `stats` access | CPU sampling | `docker stats --no-stream --help` |
| `python3` ≥ 3.10 (stdlib only) | Output parsers + summarizer | `python3 --version` |
| `git` | Repo root resolution + tquic source checkout in Docker | `git --version` |
| ≥ 4 free physical cores | Server pinned to 1, client to 4 | `nproc` |
| ≥ 8 GB RAM | Build TQUIC + run two QUIC stacks under load | `free -h` |

No host-side Mojo or Rust toolchain is required — all builds happen inside Docker.

## Quick start

```bash
make setup        # ~10 min first time, < 1 min on rebuild
make bench-mvp    # ~5 min: 8 single-iter runs
make summary      # prints Markdown table

# Single cell:
./scripts/bench.sh mojo-net 5k long-conn tquic_client

# Full matrix with 3-iter median (~50 min):
make bench-full
```

## Methodology

| Aspect | Value |
|---|---|
| Topology | Single host, loopback `127.0.0.1:8443`, Docker host network |
| Server pinning | Docker `--cpuset-cpus=0` (single physical core) |
| Client pinning | Docker `--cpuset-cpus=2-5` (4 cores, non-sibling of core 0) |
| Duration | 30 s measurement window |
| Warmup | 5 s discarded |
| Iterations | `make bench-mvp` defaults to 3 iters per cell (median); `bench.sh` single-cell defaults to `--iters 1` |
| UDP payload size | `--send-udp-payload-size 1350` |
| Cert | `${REPO_ROOT}/certs/server.{crt,key}` (ECDSA prime256v1) |
| `tquic_client` concurrency | `--threads 4 --max-concurrent-conns 25 --max-concurrent-requests 10` (4×25 = 100 total conns) |
| `h2load` concurrency | `-c 100 -m 10` (long-conn) / `-c 100 -m 1` (short-conn) — single-threaded, regression-tracking only |
| `max_requests_per_conn` | `0` (long-conn) / `1` (short-conn) |
| Server CPU% | `docker stats --no-stream` polled per second over the 30 s window (cgroup-level, catches all container work including child processes) |

## Per-script reference

- `scripts/gen-payloads.sh` — idempotent generator for `1k.bin / 5k.bin / 15k.bin / 2m.bin`. Re-running is a no-op if files exist with correct sizes.
- `scripts/start-server.sh <mojo-net|tquic>` — starts the server in Docker pinned to core 0, mounts payloads + certs read-only, then calls `wait-ready.sh`.
- `scripts/stop-server.sh` — `docker rm -f` for both possible container names. Idempotent.
- `scripts/wait-ready.sh` — probes `127.0.0.1:8443` with a real QUIC handshake (`tquic_client --max-requests-per-conn 1`) every 200 ms for up to 10 s. **Does not use `nc -uz`** — UDP nc is unreliable for QUIC.
- `scripts/resolve-server-pid.sh <container>` — echoes `docker inspect -f '{{.State.Pid}}'`. Unused by `bench.sh` since the switch to cgroup-level CPU sampling, kept for ad-hoc debugging.
- `scripts/run-tquic-client.sh <payload> <scenario> <duration>` — drives the server with `tquic_client`, captures stdout to `/tmp/client-stdout.log`.
- `scripts/run-h2load-client.sh <payload> <scenario> <duration>` — same shape, with `h2load-h3`.
- `scripts/parse-tquic.py` / `scripts/parse-h2load.py` — read stdout from stdin, emit a results-dict JSON to stdout.
- `scripts/measure-cpu.sh <container> <duration>` — `docker stats` sampler that writes `/tmp/cpu.json` with mean and max %CPU at cgroup level.
- `scripts/bench.sh <server> <payload> <scenario> <client> [--iters N]` — orchestrator: warmup → CPU sampler + measurement → JSON write.
- `scripts/summarize.py` — reads `results/*.json`, computes median per cell, writes `results/SUMMARY.md`.

## Output JSON schema

```json
{
  "schema_version": 1,
  "timestamp": "2026-04-25T14:00:00Z",
  "host": {
    "kernel": "Linux 6.19.12-lqx1",
    "cpu_model": "...",
    "cores_total": 8,
    "server_core": 0,
    "client_cores": [2, 3, 4, 5]
  },
  "server": "mojo-net",
  "payload": "5k",
  "scenario": "long-conn",
  "client": "tquic_client",
  "iter": 1,
  "config": { ... },
  "results": {
    "rps": 9543.2,
    "bytes_per_sec": 49144832,
    "requests_total": 286296,
    "requests_succeeded": 286296,
    "requests_failed": 0,
    "server_cpu_percent": 98.2,
    "p50_latency_ms": null,
    "p99_latency_ms": null,
    "raw_client_stdout": "..."
  }
}
```

## How to interpret results

- **Server CPU% near 100**: the server is the bottleneck — the rps number reflects its capacity. This is the desired state.
- **Server CPU% < 80 with `tquic_client`**: the client isn't pushing hard enough — bump `--threads` or `--max-concurrent-conns` and rerun.
- **Server CPU% < 80 with `h2load`**: expected. h2load is single-threaded and saturates client-side first. h2load numbers should be read as "did mojo-net regress between commits," not "is mojo-net within X% of TQUIC."
- **`requests_failed > 0`**: indicates connection errors or timeouts — investigate before trusting throughput numbers.
- **Wide variance across iterations**: core 0 may be hosting kernel softirqs. Edit `start-server.sh` to use `--cpuset-cpus=4` and rerun.
- **mojo-net's `2m` rows look weak vs TQUIC**: expected until M4 flow-control auto-tuning lands. Mojo-net's M3 default stream FC window is 1 MiB, so 2 MiB transfers stall on `MAX_STREAM_DATA` updates.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `EFAULT` / `Operation not permitted` from io_uring | Docker default seccomp blocks `io_uring_setup` | `start-server.sh` already passes `--security-opt seccomp=unconfined`; verify it's there |
| Server container exits immediately, no log | Cert files not mounted | `make setup`; check `${REPO_ROOT}/certs/server.crt` exists |
| `wait-ready.sh` times out | Port 8443 in use | `ss -lunp 'sport = :8443'`; kill the holder |
| `bench.sh` hangs | Stale container from a prior run | `docker rm -f bench-h3 bench-tquic` |
| All requests fail with TLS handshake error | Cert is RSA but server expects ECDSA | Re-run `make setup` (cert regen is idempotent if file exists; delete and retry to force) |
| `rps` is suspiciously low and CPU% < 50 | Client is the bottleneck | Switch to `tquic_client`; if already using it, raise `--threads` |
| `rps` varies wildly run-to-run | Core 0 noisy from softirqs | Set server core to 4 in `start-server.sh`; rerun |
| `tquic-bench` build fails on submodule init | BoringSSL submodule fetch | Re-run; requires network to GitHub |
| `server_cpu_percent: null` in JSON | `docker stats` failed (container down before sampler ran) | check `docker ps`; ensure `start-server.sh` succeeded before sampler started |

## Limitations

- **Loopback only.** Real NIC, GSO, UDP segmentation offload are not exercised. Numbers are upper bounds for an in-host stack.
- **Single-worker.** Both servers run single-thread/single-worker. Multi-process via SO_REUSEPORT is out of scope.
- **`h2load` is single-threaded.** Its throughput is capped client-side regardless of server speed. Use `tquic_client` for absolute comparisons.
- **2 MB payload is FC-bound on mojo-net** until M4 stream-FC auto-tuning ships.
- **Laptop hardware variance.** TQUIC's published numbers came from a 48-core EPYC. Don't compare absolute rps across hardware — only ratios on the same machine.
- **No CI integration.** Manual invocation only.

## Reference baseline

`results/REFERENCE.md` contains numbers from `make bench-mvp` on the implementer's machine, with full host details, so reviewers on different hardware can sanity-check their setup. Treat REFERENCE.md as a snapshot, not as authoritative — re-run on your own hardware for actionable numbers.

## Profile build (Plan B instrumentation)

The QUIC accept-loop profile (`specs/2026-04-25-quic-accept-loop-instrumentation.md`)
is a comptime-gated instrumentation pass. To produce a profile build:

1. **Hand-edit** `src/quic/profile.mojo` line 15:

   ```mojo
   comptime PROFILE_ACCEPT: Bool = False    # ← change to True
   ```

   We do not use `mojo build -D PROFILE_ACCEPT=true` because Mojo 0.26.2's
   `-D`-into-`comptime` semantics are not used elsewhere in this repo.
   Hand-editing one line is the documented recipe.

2. **Rebuild** the bench server:

   ```bash
   bash bench/build.sh
   # or rebuild via Docker:
   docker build -t mojo-net-bench:profile -f bench/Dockerfile .
   ```

3. **Run** any bench cell as usual, e.g.:

   ```bash
   ./scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 3
   ```

4. **Trigger a report dump.** Send `SIGINT` (Ctrl-C) or `SIGTERM` to the
   running `bench/h3_server` process. The report is printed to stderr and
   a JSON sidecar is written to
   `bench/quic_perf/results/profile/INSTRUMENTATION-<UTC-yyyymmdd-hhmmss>.json`.

   **Latency caveat.** The signal handler only flips an atomic flag (held
   in an mmap'd page at the fixed virtual address `0x60000000`). The
   actual flush happens on the next iteration of `_flush_impl`. Because
   `BatchCompletionLoop.poll_completion` may block on `io_uring_enter`
   for arbitrary duration when no CQEs arrive (idle gaps of seconds are
   normal under short-conn 1 req/s load), the report may not appear for
   seconds after the signal. Send a UDP datagram (or wait for the next
   client connection) to wake the loop; a second SIGINT hard-exits without
   a report. Future improvement: register `signalfd` as an io_uring `Read`
   op so the signal generates a CQE — out of scope for this spec.

   **Startup-fail caveat.** On profile builds, the bench server reserves
   the virtual address `0x60000000` for the dump-pending flag using
   `MAP_FIXED_NOREPLACE`. If that address is already in use at process
   start, the server fails fast with `mmap failed (address already in
   use or out of memory)`. This is intentional — the alternative is
   silently clobbering an unrelated mapping. If you see this error,
   inspect `/proc/self/maps` to find the conflict.

## Reading the report

The text report is human-readable; the JSON sidecar is the canonical
artifact. Key sections:

- **Idle vs busy.** `idle_us_total / busy_us_total` ratio reveals whether
  the bench fiber is starved (idle high) or saturated (busy high). Plan A
  retrospective: if idle > 90%, the bottleneck is upstream of the loop.
- **`pkts_per_flush_histogram`.** If the weighted-mean fan-out is ≥ 8,
  multishot recvmsg is delivering large CQE batches that the
  single-fiber `_flush_impl` is serializing. This is the "fan-out" suspect.
- **Per-packet decomposition.** 8 leg averages (`shim_ffi`, `header_parse`,
  `hp`, `aead`, `frame_parse`, `sm`, `residual`, `drain`) plus the
  bucket-estimated `total` percentiles. Decision rules:
  - `shim_ffi.avg ≥ 2 ×` next-largest leg → FFI/rustls dominates.
  - `aead.avg ≥ 2 ×` next-largest → crypto dominates.
  - `sm.avg ≥ 2 ×` next-largest (and not via shim_ffi) → state-machine dispatch dominates.
- **Handshake accounting.** `arrivals = successful + timed_out` should
  hold; if not, the eviction-site or SIGINT-sweep accounting is buggy.
  `successful / arrivals` is the bench's success rate (0.9% on the
  pacer-bypass-falsified run; we want it ≥ 50% post-fix).
- **Successful handshake latency.** Exact percentiles from a sorted vector;
  the right-tail is the load-bearing data for the timeout-rate hypothesis.

