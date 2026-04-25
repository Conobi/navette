## Host

- Kernel: `Linux 6.19.12-lqx1-1-lqx`
- CPU: `11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz`
- Cores: `8`
- Docker: `29.3.0`
- pidstat: `sysstat version 12.7.9`

## Status: **calibration pending**

The harness machinery ships in working order, but the absolute numbers it
currently produces are **not yet a citable benchmark**. Three known issues
must be resolved before populating this file with reference numbers:

1. **CPU% reads ~0–1%** at 4,000 req/s — `pidstat -p <docker-init-pid>` is
   not capturing the actual work. Replaced by `docker stats` cgroup-level
   sampling; needs a clean run to validate.
2. **Single-iter run-to-run variance is enormous** (213 → 12,560 → 343 req/s
   for the same `tquic_client → tquic_server` long-conn cell across three
   cold-start runs). `make bench-mvp` now defaults to `--iters 3` so the
   median absorbs cold-start noise.
3. **`tquic_client` knobs undersaturate `tquic_server`** on this hardware.
   The TQUIC reference's published bench used a 48-core EPYC; on a laptop the
   multi-thread client coordination overhead may exceed its throughput gain.
   A knob sweep (`--threads ∈ {2,4,8,16}` × `--max-concurrent-conns ∈
   {25,50,100}`) is needed to find the saturation knee per server.

Until those land, run `make bench-mvp` locally and treat the output as a
*relative* signal across configurations on the same host, not as authoritative
absolute throughput.
