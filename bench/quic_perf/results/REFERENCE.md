## Host
- Kernel: `Linux 6.19.12-lqx1-1-lqx`
- CPU: `11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz`
- Cores: `8`
- Docker: `29.3.0`
- pidstat: `sysstat version 12.7.9`
- Date: `2026-04-25T12:11:37Z`

## Reference numbers (from `make bench-mvp` on the host above)

## tquic_client (saturating, 4 threads)

| Payload | Scenario   | mojo-net req/s (n) | TQUIC req/s (n) | mojo-net CPU% | Ratio |
|---------|------------|---------------------|-----------------|---------------|-------|
| 1k      | long-conn  | 4,000 (1)           | 343 (1)         | 0.0           | 11.67x |
| 1k      | short-conn | 444 (1)             | 35 (1)          | 0.1           | 12.58x |

## h2load-h3 (single-threaded, regression-tracking only)

| Payload | Scenario   | mojo-net req/s (n) | TQUIC req/s (n) | mojo-net CPU% | Ratio |
|---------|------------|---------------------|-----------------|---------------|-------|
| 1k      | long-conn  | 101 (1)             | 102,558 (1)     | 1.2           | 0.00x |
| 1k      | short-conn | 10 (1)              | 75,303 (1)      | 0.3           | 0.00x |


## Caveats

- **Server CPU% is suspiciously low (0–1%)** while throughput is multi-thousand req/s. The sampler measures the container init PID via `docker inspect`; for mojo-net the actual worker may be a child process we're not catching. Numbers here are still valid as a *relative* signal across runs of the same configuration on the same host.
- **Run-to-run variance is large** (we've observed 213 → 12,560 → 343 req/s for the same tquic_client→tquic_server long-conn cell across 3 cold-start runs). Treat single-iter numbers as directional, not authoritative; use `--iters 3` for any comparative claim.
- **`tquic_client` knobs undersaturate `tquic_server` on this hardware.** The TQUIC reference's published bench used a 48-core EPYC; on a laptop the multi-thread client coordination overhead may exceed its throughput gain. h2load → tquic_server numbers (~75K-100K req/s) likely better reflect tquic_server's true ceiling here.
