# bench/compare — quick side-by-side benchmarks

Smoke-test scripts that run mojo-net against established HTTP servers
(hyper, nginx, h2o) on the HttpArena `/baseline2` endpoint.

These are deliberately lightweight: a single endpoint, single profile,
built for a fast pulse-check after invasive HTTP-stack changes. For
full-coverage profiling (json, static, gateway, db, grpc, …) use
`bench/.httparena/scripts/benchmark.sh mojo-net` directly.

## Prerequisites

1. HttpArena cloned into `bench/.httparena/` (gitignored). See
   `bench/.httparena/INSTRUCTIONS.md` (also gitignored, kept locally)
   for clone + setup commands.
2. Docker installed and the user is in the `docker` group.

## One-time setup

```bash
# Build mojo-net image (uses bench/Dockerfile + boucle/json-simd-mojo
# build contexts):
bash bench/build.sh

# Build the comparator framework images + load generators (hyper,
# nginx, h2o, h2load, wrk):
bash bench/compare/build-comparators.sh
```

## Run the benchmarks

```bash
# HTTP/2 over TLS — h2load -n 200000 -c 50 -m 16 against /baseline2
bash bench/compare/h2-vs-others.sh

# HTTP/1.1 plain — wrk -t4 -c200 -d8s against /baseline2
bash bench/compare/h1-vs-others.sh
```

Knobs (env vars):
- `h2-vs-others.sh`: `N`, `C`, `M`, `WARMUP_REQS`
- `h1-vs-others.sh`: `DURATION`, `THREADS`, `CONNS`

## Why mojo-net needs `--security-opt seccomp=unconfined`

mojo-net uses io_uring via boucle. Docker's default seccomp profile
restricts several io_uring syscalls; without `seccomp=unconfined` the
worker processes raise on first I/O setup. The comparator servers
(epoll-based) don't strictly need this flag, but they're given the
same Docker flags here for an apples-to-apples comparison.

## Caveats

- These are smoke tests on a tiny payload (`/baseline2` returns the
  ASCII sum of two query ints, ~1 byte). They do NOT cover JSON,
  static-file, db-driven, or gateway profiles.
- Numbers are sensitive to host load and the SO_REUSEPORT worker
  count baked into each image. Run on an idle box.
- We measured these on a 4-core / 8-thread Tiger Lake laptop — see
  `plans/2026-04-25-h2-bench-comparison.md` for one captured run.
