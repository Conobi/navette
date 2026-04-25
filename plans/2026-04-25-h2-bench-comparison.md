# Bench comparison: mojo-net vs hyper / nginx / h2o

Quick side-by-side after the H2 flow-control + END_STREAM combine + TLS-record
chunking fixes landed (commits `cc813cd` and `9f1665b`). Goal was a sanity check:
is the new mojo-net stack in the same league as established Rust/C servers?

## Setup

- Host: 11th Gen Intel i7-1165G7 (4C/8T) @ 2.80 GHz, Linux 6.19, kernel io_uring
- All servers in Docker `--network host`, `--security-opt seccomp=unconfined`,
  `memlock=-1`, `nofile=1048576` (mojo-net needs the privilege grant for
  io_uring; epoll-based servers don't, but they were given the same flags
  for fairness).
- Endpoint: `/baseline2?a=1&b=2` → text/plain `"3"` body. The HttpArena
  baseline2 profile (sum-of-two-ints).
- mojo-net image: `bench/build.sh` (multi-process launcher, 8 workers per
  protocol, SO_REUSEPORT).
- Comparators built from HttpArena: `frameworks/{hyper,nginx,h2o}/Dockerfile`.

## HTTP/2 over TLS — `h2load -n 200000 -c 50 -m 16`

| Server   | Req/s     | vs mojo-net | Transfer  |
|----------|----------:|------------:|----------:|
| h2o      | 477 716   | 1.96×       | 11.85 MB/s |
| hyper    | 468 908   | 1.92×       | 12.09 MB/s |
| **mojo-net** | **243 971** | **1.00×**   | **5.12 MB/s**  |
| nginx    | 202 649   | 0.83×       | 16.62 MB/s |

mojo-net is **~52 % of hyper / h2o** and **~1.2× nginx** on this profile.
The nginx number is lower than the others on raw rps but its responses
are larger (full Server/Date headers), hence its higher MB/s.

## HTTP/1.1 plain — `wrk -t4 -c200 -d8s`

| Server   | Req/s     | vs mojo-net | Avg Latency | Transfer  |
|----------|----------:|------------:|------------:|----------:|
| hyper    | 493 421   | 1.57×       | 362 µs      | 55.06 MB/s |
| h2o      | 479 210   | 1.52×       | 336 µs      | 46.62 MB/s |
| nginx    | 471 840   | 1.50×       | 388 µs      | 63.45 MB/s |
| **mojo-net** | **314 455** | **1.00×**   | **594 µs**  | **18.89 MB/s** |

mojo-net is **~64 % of hyper** on h1 plain. Latency average is roughly
1.6× hyper's; tail (max) is 5.24 ms vs hyper's 5.95 ms — comparable
under load.

The transfer-per-second gap (18.89 MB/s vs 55+ MB/s) reflects mojo-net's
intentionally minimal response headers (no `Server:`, no `Date:`),
not a throughput ceiling. Per-request, mojo-net writes ~60 bytes while
hyper writes ~117, nginx ~141, h2o ~102. That's a small request-handling
edge for mojo-net, partially offset by lower request volume.

## Takeaways

1. **mojo-net is in the right league.** ~50 % of the fastest h2 server
   (hyper, h2o) on h2 TLS, and beats nginx on raw rps. h1 plain is at
   ~65 % of hyper. Solid for an early-stage Mojo implementation.

2. **Where the gap shows.** Both protocols put us at ~50–65 % of the
   leaders on rps. The most likely sources (in order of suspected
   impact):
   - rustls cost vs OpenSSL/BoringSSL+kTLS that hyper/nginx/h2o use.
   - Per-request allocations in the Mojo response writer (each frame
     is a fresh `List[UInt8]`).
   - TLS-record chunking (the IO-layer fix from `9f1665b`) does an
     extra `tls.send_data` + `drain_ciphertext` per 16 KB; could be
     reduced to one call by batching multiple H2 frame groups.

3. **Where we win.** mojo-net beats nginx on h2 (243K vs 202K rps).
   That's a real bar: nginx is the standard production-grade h2 server
   on Linux. The chunking fix specifically helps multi-stream
   workloads, which is where mojo-net pulls ahead.

4. **What this comparison does NOT measure.** /baseline2 is a tiny
   reply (1 body byte). The HttpArena profile zoo also covers
   `/json/{n}?m=k` (multi-KB JSON), `/static/...` (file fetch),
   gateway/db/grpc — all out of scope here. Running the full
   HttpArena suite (`scripts/benchmark.sh mojo-net`) would give a
   proper picture; this run is a quick smoke test.

## Reproduce

Setup, knobs, and run instructions are in `bench/compare/README.md`.
Two scripts under `bench/compare/`:

- `build-comparators.sh` — one-time build of hyper / nginx / h2o
  framework images plus h2load and wrk load generators.
- `h2-vs-others.sh` — the h2 TLS comparison above.
- `h1-vs-others.sh` — the h1 plain comparison above.

mojo-net's own image is built via `bench/build.sh` as usual.
