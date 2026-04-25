# QUIC Perf Bench Harness

TQUIC-style HTTP/3 benchmark comparing mojo-net's `h3_server` to the TQUIC reference, under matched payloads, matched concurrency, and CPU-saturating load.

> **Status: machinery shipped, calibration pending.** The harness orchestrates correctly end-to-end (build → run → parse → median → summarize), but the absolute numbers are not yet trustworthy. Three known issues — CPU sampling, cold-start variance, and `tquic_client` undersaturation on laptop hardware — must be resolved before `results/REFERENCE.md` is repopulated. See `results/REFERENCE.md` for details.

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

`results/REFERENCE.md` is currently a **calibration-pending placeholder**: it lists host details and the three issues blocking trustworthy numbers (PID-vs-cgroup CPU sampling, cold-start variance, `tquic_client` undersaturation on laptop hardware). It does not yet contain reference rps/bytes/CPU% rows.

Treat the harness today as a working *machinery* you can run locally to compare *configurations on the same host* (relative signal). Absolute throughput claims should wait on the calibration follow-ups.
