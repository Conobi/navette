# bench/profile — H2 perf measurement harness

Two-tier benchmarking + profiling harness for the mojo-net H2 server.
Built so every perf-optimization PR can post measurable before/after
numbers without hand-rolling commands.

- **Throughput tier** (`h2-throughput.sh`) — req/s + p50/p99/p999 +
  bytes/req across an endpoint set, appended to a CSV. The trend
  metric. Compares mojo-net vs hyper.
- **Perf-record tier** (`h2-perf-record.sh`) — boots the host-built
  H2 server, drives load with h2load, and produces `perf.data` +
  `perf-folded.txt` + `perf.svg` flamegraph for one run.
- **Hotspot extractor** (`h2-hotspots.sh`) — turns a folded perf
  capture into a markdown report with top-N self-time and top-N
  inclusive-time tables.

This harness is **measurement only**. Optimization PRs live in their
own plans; this directory just makes the cost of measurement near-zero
so we don't have to argue about whether something got faster.

---

## Prerequisites

1. **HttpArena cloned** into `bench/.httparena/` (gitignored). See
   `bench/.httparena/INSTRUCTIONS.md` for clone + setup commands.
2. **Docker** with the `httparena-mojo-net`, `httparena-hyper`, and
   `h2load:latest` images already built. If not, build them once:
   ```bash
   bash bench/build.sh                       # mojo-net
   bash bench/compare/build-comparators.sh   # hyper, nginx, h2o, h2load, wrk
   ```
3. **Host build of bench/h2_server** for the perf-record tier:
   ```bash
   # However the project builds — `pixi run build-bench` or your dev cmd.
   # The script checks for bench/h2_server existing as an executable.
   ```
4. **`perf` installed.** Arch: `pacman -S perf`. Debian/Ubuntu:
   `apt install linux-tools-common linux-tools-generic`.
5. **`kernel.perf_event_paranoid <= 2`** so non-root can profile their
   own processes:
   ```bash
   sysctl kernel.perf_event_paranoid          # check current
   sudo sysctl -w kernel.perf_event_paranoid=2
   ```
   Level 2 is enough for user-space stacks (which is what we care
   about). Level 1 unlocks kernel symbols if you ever need them.
6. **FlameGraph cloned once** into `bench/.tools/FlameGraph/`:
   ```bash
   git clone --depth 1 https://github.com/brendangregg/FlameGraph \
       bench/.tools/FlameGraph
   ```
   `bench/.tools/.gitignore` excludes the clone from version control.

---

## Run order

```bash
# 1. Trend metric: req/s + percentiles, appends to baselines/h2-throughput.csv
bash bench/profile/h2-throughput.sh

# 2. Profile capture: 30s perf record, drops to bench/profile/runs/<ts>-<sha>/
bash bench/profile/h2-perf-record.sh

# 3. Convert the latest folded capture into a markdown hotspot table.
bash bench/profile/h2-hotspots.sh
```

`h2-hotspots.sh` defaults to the newest `perf-folded.txt` under
`bench/profile/runs/`. Pass an explicit path to compare older runs.

---

## Knobs (env vars)

### `h2-throughput.sh`
| Var          | Default                                | Meaning |
|--------------|----------------------------------------|---------|
| `N`          | `200000`                               | h2load `-n` |
| `C`          | `50`                                   | h2load `-c` |
| `M`          | `16`                                   | h2load `-m` |
| `WARMUP_REQS`| `5000`                                 | h2load warmup `-n` (discarded) |
| `SERVERS`    | `mojo-net hyper`                       | Space-separated; row per (server, endpoint) |
| `ENDPOINTS`  | `/baseline2?a=1&b=2 /json/50?m=6 /static/footer.html` | Space-separated |
| `OUT_CSV`    | `bench/profile/baselines/h2-throughput.csv` | Append target |

### `h2-perf-record.sh`
| Var         | Default                                | Meaning |
|-------------|----------------------------------------|---------|
| `DURATION`  | `30`                                   | h2load `-D` (total load duration in s) |
| `PERF_DUR`  | `DURATION - 5`                         | perf record window in s; ends before h2load to avoid teardown |
| `C`         | `50`                                   | h2load `-c` |
| `M`         | `16`                                   | h2load `-m` |
| `ENDPOINT`  | `/baseline2?a=1&b=2`                   | Target path |
| `PERF_FREQ` | `99`                                   | perf `-F` Hz |
| `OUT`       | `bench/profile/runs/<ts>-<sha>/`       | Run output dir |

### `h2-hotspots.sh`
| Var         | Default                                | Meaning |
|-------------|----------------------------------------|---------|
| `TOPN`      | `30`                                   | Rows per ranking table |
| Arg 1       | latest `perf-folded.txt`               | Override input |
| Arg 2       | `baselines/h2-hotspots-<sha>.md`       | Override output |

---

## Output schema

### `baselines/h2-throughput.csv`
```
timestamp,git_sha,server,endpoint,n,c,m,reqs_per_s,p50_us,p99_us,p999_us,bytes_per_req
```
- `timestamp` — UTC ISO8601 of the run.
- `git_sha` — short SHA of the working tree at run time.
- `p50_us / p99_us / p999_us` — h2load `--log-file` stream-end
  microseconds, sorted and percentile-picked. **End-of-stream** time
  under high concurrency includes queueing — these are not raw RTTs.
- `bytes_per_req` — total wire bytes / N. Useful for spotting header
  bloat regressions.

### `bench/profile/runs/<ts>-<sha>/`
Per-run dir, gitignored:
```
perf.data         raw perf binary (~100 MB per 15s capture, dwarf unwind)
perf-script.txt   text dump of the trace
perf-folded.txt   stackcollapse-perf.pl output: stack;... weight
perf.svg          interactive flamegraph (open in a browser)
h2_server.log     server stdout/stderr
h2load.log        load-gen stdout: req/s, status codes, percentiles
```

### `baselines/h2-hotspots-<sha>.md`
Two ranked markdown tables:
1. Top-N **self-time** (CPU burning at the leaf of the stack).
2. Top-N **inclusive-time** (any frame in the stack).

The "weight" column is perf's PERIOD field (≈ cycles between samples),
not raw sample count. Use the percentages.

---

## Why host-build for perf-record (not Docker)

mojo-net's host binary at `bench/h2_server` is unstripped ELF, so perf
resolves Mojo symbols (`H2Connection.send_data`, `_drain_responses`,
etc.) cleanly without `--symfs` gymnastics. h2load still runs in Docker
— it's just the load gen and doesn't need symbols.

The perf-record tier runs **single-worker** by construction (no
launcher, no SO_REUSEPORT). Multi-worker scatters samples across
cpus and confuses per-symbol attribution. Multi-worker is what
`h2-throughput.sh` measures — both views are useful.

---

## Caveats

- **Stable percentages need ≥5000 samples.** A 30s capture at -F 99
  produces ~3000 samples. For tight signal:noise, run 60s+ before
  drawing conclusions about a 0.5% delta.
- **`--call-graph=dwarf` makes perf.data huge.** ~100 MB per 15s.
  We keep them in `bench/profile/runs/` (gitignored). Only the SVG +
  hotspot MD get committed to baselines.
- **Single-endpoint perf-record.** The hotspot table reflects whatever
  endpoint you ran. Run separately per workload (`/baseline2`,
  `/json/...`, `/static/...`) — they have different bottlenecks.
- **Multi-worker comparisons.** The throughput CSV uses the default
  multi-worker mojo-net image; hyper/nginx use their own launchers.
  This is the public, fair comparison.
- **No H1 or H3 yet.** This Phase 0 harness is H2 TLS only. H1 plain
  and H3 each get their own when their gaps become a priority.
