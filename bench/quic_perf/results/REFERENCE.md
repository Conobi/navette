## Host

- Kernel: `Linux 6.19.12-lqx1-1-lqx`
- CPU: `11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz`
- Cores: `8`
- Docker: `29.3.0`
- Date: `2026-04-25`

## Reference numbers

`make bench-mvp` on the host above. Each cell is the median of 3 iterations of
a 30 s measurement window after a 5 s warmup, with `--cpuset-cpus=0` for the
server and `--cpuset-cpus=2-5` for the client. CPU% is sampled at the cgroup
level via `docker stats --no-stream` once per second.

### tquic_client (4 threads, 25 conns/thread, saturating)

| Payload | Scenario   | mojo-net req/s (n) | TQUIC req/s (n) | mojo-net CPU% | mojo-net / TQUIC |
|---------|------------|--------------------|-----------------|---------------|------------------|
| 1k      | long-conn  | 412 (3)            | 87,113 (3)      | 5.6           | 0.0047× |
| 1k      | short-conn | 1 (3)              | 2,535 (3)       | 0.2           | 0.0004× |

### h2load-h3 (single-threaded, regression-tracking)

| Payload | Scenario   | mojo-net req/s (n) | TQUIC req/s (n) | mojo-net CPU% | mojo-net / TQUIC |
|---------|------------|--------------------|-----------------|---------------|------------------|
| 1k      | long-conn  | 125 (3)            | 32,625 (3)      | 2.9           | 0.0038× |
| 1k      | short-conn | 11 (3)             | 66,023 (3)      | 0.6           | 0.0002× |

## How to read this

- **TQUIC's tquic_server hits 87K req/s with `tquic_client` and saturates core 0
  at 88% CPU** — server-side bottleneck reached, the hardware envelope on this
  laptop. This is the calibration anchor.
- **mojo-net hits 412 req/s long-conn / 1 req/s short-conn while using <6% of
  one CPU core.** Mojo-net is *not* CPU-bound on core 0 — there is huge headroom
  the server isn't using. The bottleneck is **per-connection cost**: under
  saturating load (400 attempted connections in 30 s) only ~3–10 complete the
  QUIC handshake, the rest time out. The successful handshakes then drive
  thousands of requests, but the throughput is gated by the trickle of
  conns the server can actually accept.
- **h2load → mojo-net is single-threaded at the client** — those numbers are
  for regression tracking against prior runs, not absolute comparisons.

## Known limitations of these numbers

- **2 MB / 5K / 15K payloads not in the MVP matrix.** The 1 KB cells are the
  ones run by `make bench-mvp`. Run `make bench-full` for all 32 cells.
- **`tquic_client` knob ceiling** — 4 threads × 25 conns × 10 streams = 1,000
  in-flight requests. On a 48-core EPYC the ceiling would be higher; here we
  are likely under-saturating `tquic_server` slightly. The 87K rps is a lower
  bound on TQUIC's achievable throughput.
- **No CI integration / no commit-to-commit tracking yet** — REFERENCE.md is
  a manual snapshot. Numbers will drift with kernel updates, thermals, and
  parallel host load.
- **Single-worker mojo-net** (`--workers 1`). Multi-process via SO_REUSEPORT
  is out of scope for this harness.

## Where the work goes from here

The honest read: mojo-net is ~210× slower than TQUIC long-conn, ~2,500× slower
short-conn, while using essentially zero CPU. The next optimisation pass should
target **connection-establishment throughput** — handshake latency, accept
loop, packet decryption pipelining — rather than steady-state stream throughput.
