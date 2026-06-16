# bench/flare_compare — Flare-methodology comparison

Single-worker `GET /plaintext` benchmark for navette, with the same
calibrated-peak `wrk2` harness Flare publishes in
[`docs/benchmark.md`](https://github.com/ehsanmok/flare/blob/main/docs/benchmark.md).
Apples-to-apples vs flare itself, nginx, Go `net/http`, hyper, axum,
and actix_web — every server runs **single-threaded**, every container
is pinned, every client is the same `wrk2` build.

This is an **iteration harness** — re-run it repeatedly as navette's
HTTP/1.1 hot path tightens. Each run drops `results/<ts>-<host>-<sha>/`
with the full per-target raw data + a self-contained `summary.md`
that inlines the host conditions for that run. No global synthesis
file is checked in — each iteration's summary.md is the canonical
artifact for that point in time.

**Current iteration target: close the gap with `hyper` 1w.** At the
last published run, hyper held the highest 1w throughput of the
field; that's the line to chase. Inspect the latest summary.md
under `results/` to read the current standing; the per-target σ on
p99.9 / p99.99 (the "honesty meter") shows how close to the
saturation cliff each headline number is sitting.

## What the methodology produces

| Field           | Source                                                |
|-----------------|-------------------------------------------------------|
| Req/s (median)  | Median of 3 middle measurement runs (drop min + max). |
| σ%              | Stdev of req/s across all 5 runs, relative to mean.   |
| p50/p99/p99.9/p99.99 | Median of the same percentile across 5 wrk2 runs. |
| ± σ on percentiles | Sample stdev across 5 runs (the "honesty meter"). |
| stable          | σ% < 5 %.                                             |
| Peak (calibrated)| Highest sustainable rate (see §Methodology).         |

Every cell is **coordinated-omission corrected** — wrk2 sends at a
constant rate, so queueing time at the load generator is counted as
client-observed latency.

## Endpoint

`GET /plaintext` returning the 13-byte body `Hello, World!`, with
`Content-Type: text/plain`, HTTP/1.1 keep-alive on, no gzip, no logging.
Every baseline is gated on byte-exact response equality before
measurement starts (`scripts/_integrity_check.sh`).

## Methodology (one paragraph)

1. **Settle** at a low fixed rate (5 s) so caches, branch predictors,
   and TCP slow-start are out of the way.
2. **Ceiling** probe at `-R 10000000` for 20 s — wrk2's overdrive
   peak; we use it as the *upper bound* of the search, not the
   headline number.
3. **Binary-search** (5 steps) between 30 %–100 % of the ceiling for
   the highest rate `R` that holds, all at once:
   - `p99 ≤ 50 ms`,
   - `achieved ≥ 0.9 * R`,
   - `p99.9 ≤ max(p99·3, p99+2)` and `p99.99 ≤ max(p99·10, p99+5)`
     (cliff guard),
   - `p99 ≤ max(p99_floor·2, p99_floor+2)` (growth guard).
   One retry per probe on `CLIFF` or `P99_GREW` — single transient
   blips don't collapse the ceiling.
4. **Validate** at 90 % of the calibrated peak for 20 s; back off
   8 % and re-validate once if the cliff gate trips.
5. **Measure** five 30-s rounds at 90 % of peak, with 30 s of quiet
   between each so kernel state (TIME-WAIT bookkeeping, IRQ
   coalescing) decays. Drop min + max, take the median of the middle
   three.

The methodology mirrors Flare's `bench_vs_baseline.sh` line for line;
the only adaptation is that every server **and** wrk2 runs inside a
pinned Docker container so the harness has no host-toolchain
dependencies. See `scripts/bench_vs_baseline.sh` for the actual
implementation.

## Reproduce

### Prerequisites

- Linux host with Docker (≥ 24.0). Some distros (NixOS in particular)
  need `--network=host` on `docker build` because the default bridge
  has broken DNS; `build-baselines.sh` already passes that flag.
- ≥ 2 quiet physical cores (one for the server, one for `wrk2` —
  CPU 1 is left as a buffer by default). Co-resident workloads
  cap the achievable tail tightness; an idle box is best.
- ~8 GB free disk for the seven Docker images (~5 GB combined; the
  rest is the build-time crate / pixi / cargo caches).
- The sibling Mojo dependencies live in the parent of this repo:

    ```
    <parent>/
        navette/                  ← this repo
        boucle/                   ← required for navette image build
        jsonette/           ← required for navette image build
    ```

    `*-build` mirrors (`boucle-build`, `jsonette-build`) are
    accepted as fallbacks. Override with the env vars `BOUCLE_DIR=`
    and `JSONETTE_DIR=` if your layout differs.

### One-time setup

```bash
cd /path/to/navette

# Build every server image + wrk2 (~45 min cold; ~30 s warm-cache).
# Skip `flare` if you don't want the pixi/Mojo-nightly pull (~1 GB)
# on first build.
bash bench/flare_compare/scripts/build-baselines.sh
```

### Each iteration

```bash
# 1) Make your change inside navette (handler, codec, reactor, …)
#    and rebuild ONLY the navette image — every other image is cached.
bash bench/flare_compare/scripts/build-baselines.sh navette

# 2) Confirm the host is quiet. The harness measures everything via
#    wrk2 calibrated-peak, so anything stealing cycles inflates the
#    σ on the percentile cells.
cat /proc/loadavg
ps --sort=-pcpu -eo pid,pcpu,comm | head

# 3) Run the bench. Server pinned to CPU 0, wrk2 pinned to CPU 2.
#    For a navette-only iteration this is ~8 min; the full matrix is
#    ~55 min.
BENCH_SERVER_CPU=0 BENCH_CLIENT_CPU=2 \
    bash bench/flare_compare/scripts/bench_vs_baseline.sh \
        --only=navette                              # fast loop

BENCH_SERVER_CPU=0 BENCH_CLIENT_CPU=2 \
    bash bench/flare_compare/scripts/bench_vs_baseline.sh \
        --only=navette,flare,nginx,go-nethttp,hyper,axum,actix-web   # full matrix

# 4) Read the headline.
cat bench/flare_compare/results/$(ls -t bench/flare_compare/results/ | head -1)/summary.md

# 5) Compare to the last iteration (or any historical run).
diff -u bench/flare_compare/results/<earlier-ts>-<sha>/summary.md \
        bench/flare_compare/results/<latest-ts>-<sha>/summary.md
```

### Optional knobs

| Env var               | Default       | What it does                                         |
|-----------------------|---------------|------------------------------------------------------|
| `BENCH_SERVER_CPU`    | `0`           | Server container `--cpuset-cpus`                     |
| `BENCH_CLIENT_CPU`    | `2`           | wrk2 container `--cpuset-cpus`                       |
| `BENCH_HOST_LABEL`    | `bench-host`  | Goes into the results-dir name + `env.json`          |
| `BENCH_PORT`          | `8080`        | Loopback port the server binds on                    |
| `BENCH_PROBE_SEC`     | `20`          | Per-probe duration in the binary search             |
| `BUILD_NET`           | `--network=host` | Passed to every `docker build` (NixOS DNS quirk) |
| `BOUCLE_DIR`          | `../boucle`   | Mojo dep for navette image                           |
| `JSONETTE_DIR`        | `../jsonette` | Mojo dep for navette image                     |

### Running on a remote bench host

`scripts/fetch-vps-results.sh` pulls a remote `results/` directory
back into the local checkout for committing. It takes its remote
target entirely from env (no host hardcoded in the script):

```bash
# Either set one combined remote:
BENCH_REMOTE=user@host:/path/to/navette/bench/flare_compare/results \
    bash bench/flare_compare/scripts/fetch-vps-results.sh

# …or set the three parts separately:
BENCH_USER=user \
BENCH_HOST=10.0.0.1 \
BENCH_REMOTE_PATH=/path/to/navette/bench/flare_compare/results \
    bash bench/flare_compare/scripts/fetch-vps-results.sh
```

### Output layout

Every run produces `bench/flare_compare/results/<ts>-<host_label>-<sha>/`
with the following shape. The committed pieces are self-contained —
reading any historical summary in isolation tells you the numbers
plus the broad conditions that produced them.

| File                        | Purpose                                          | Committed? |
|-----------------------------|--------------------------------------------------|------------|
| `summary.md`                | Comparison table + inline "Run conditions" block | yes        |
| `env.json`                  | Overall host shape + per-target image digests    | yes        |
| `integrity.md`              | Response-byte gate result per target             | yes        |
| `<target>-<config>.json`    | Aggregated stats (peak rps, medians, σ, runs)    | yes        |
| `RAW/`                      | Every wrk2 stdout (settle/overdrive/cal/runs)    | no         |
| `*.server.{stdout,stderr}`  | Server boot/error logs                           | no         |

The "Run conditions" inline block keeps the granularity at the
**overall** level: CPU class, logical core count, total RAM, 1-min
loadavg at bench-start, CPU pinning, commit + Docker version,
per-target image digests. No hostname, no co-resident process list,
no distro-specific tunables.

## Targets

| Target      | Build                                            | Threading       |
|-------------|--------------------------------------------------|-----------------|
| navette     | `bench/Dockerfile` (existing multi-stage Mojo)    | `BENCH_WORKERS=1`, H1 only |
| flare       | `baselines/flare/` — pixi-managed Mojo nightly, `ehsanmok/flare@v0.7.0`, `mojo build -D ASSERT=none` | single reactor |
| nginx       | `baselines/nginx/` — official image + minimal conf | `worker_processes 1` |
| go-nethttp  | `baselines/go-nethttp/` — distroless static binary | `runtime.GOMAXPROCS(1)` |
| hyper       | `baselines/hyper/` — Rust 1.88, hyper 1.x         | tokio `current_thread` |
| axum        | `baselines/axum/` — Rust 1.88, axum 0.7           | tokio `current_thread` |
| actix-web   | `baselines/actix-web/` — Rust 1.88, actix-web 4.x | `.workers(1)`   |

Rust baselines use `cargo build --release --locked` with `lto = "fat"`
and `codegen-units = 1` to match Flare's posture. Go uses `-trimpath`
+ stripped symbols. Mojo uses `mojo build -D ASSERT=none -O3` (the
production posture Flare's headline numbers also use).

## Adding a new target

```bash
# 1) Drop a Dockerfile + source under baselines/<name>/
# 2) Write baselines/<name>/run.sh that:
#       - removes any prior "flare-cmp-<name>" container
#       - exec's `docker run --rm --name flare-cmp-<name> \
#             --network host --cpuset-cpus="$BENCH_SERVER_CPU" \
#             flare-cmp-<name>:latest`
# 3) Add the image build to scripts/build-baselines.sh
# 4) Re-run the integrity gate + the bench
```

The harness auto-discovers every `baselines/<name>/run.sh`; there's no
central registry.

## What this *isn't*

- **Not** a multi-worker bench. `--only=navette` plus `BENCH_WORKERS=4`
  in the navette run.sh would give you that, but the matrix here is
  single-worker by design — that's where the cleanest per-core
  comparison lives.
- **Not** the existing QUIC long-conn/short-conn vs TQUIC bench. Those
  live in `bench/quic_perf/` and use `h2load-h3`. This is the HTTP/1.1
  plaintext lane Flare uses.
- **Not** a substitute for the full HttpArena profile sweep. That lives
  under `bench/.httparena/scripts/benchmark.sh` and covers json,
  static, db, grpc, gateway profiles.
