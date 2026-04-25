# H2 Perf — Phase 0: Profiling Harness

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a checked-in profiling harness for the H2 server that produces (a) end-to-end throughput numbers and (b) component-level CPU attribution via `perf record` + flamegraph, on both `/baseline2` and the broader HttpArena profile zoo. Establish baselines that subsequent perf phases must beat. **No perf changes in this plan.**

**Why Phase 0:** The comparison writeup (`plans/2026-04-25-h2-bench-comparison.md`) lists three suspects for the ~50 % gap to hyper/h2o (rustls vs OpenSSL+kTLS, per-frame `List[UInt8]` allocations, per-record `drain_ciphertext`) but has zero CPU-level evidence ranking them. Optimizing on hunches risks the same trap json-simd-mojo Plan 8 caught: a "harmless" `List.resize(N, 0)` zero-fill that produced a -53 % Stage 2 regression — found only because every PR re-ran the breakdown harness. We mirror that discipline here.

**Architecture:** Two-tier mirror of json-simd-mojo's `bench_throughput.mojo` + `bench_stage2_breakdown.mojo`:
- `bench/profile/h2-throughput.sh` — wraps `bench/compare/h2-vs-others.sh` with CSV output for trend tracking
- `bench/profile/h2-perf-record.sh` — runs h2load against mojo-net while `perf record -g`-ing the worker; emits `perf.data` + flamegraph SVG
- `bench/profile/h2-hotspots.sh` — post-processes `perf.data` into a hotspot table (% CPU by symbol, top N)
- `bench/profile/baselines/` — committed CSVs anchoring "today's mojo-net" so future phases have a delta target

**Tech Stack:** bash + Docker + `perf` + Brendan Gregg's FlameGraph scripts (vendored or fetched once into `bench/.tools/`).

---

## File structure

| File                                        | Changes  | Requirements |
|---------------------------------------------|----------|--------------|
| `bench/profile/README.md`                   | New      | R1           |
| `bench/profile/h2-throughput.sh`            | New      | R2           |
| `bench/profile/h2-perf-record.sh`           | New      | R3           |
| `bench/profile/h2-hotspots.sh`              | New      | R4           |
| `bench/profile/baselines/.gitkeep`          | New      | R5           |
| `bench/profile/baselines/h2-throughput.csv` | New (empty header) | R5  |
| `bench/profile/baselines/h2-hotspots.md`    | New (empty)        | R5  |
| `bench/.tools/.gitignore`                   | New (`*` to exclude FlameGraph clone) | R3 |
| `plans/2026-04-25-h2-perf-phase0-profiling-retrospective.md` | New | R6 |

---

## Requirements

- **R1 — Documented harness.** A README that explains prerequisites (perf, FlameGraph, HttpArena), one-time setup, run order, and the output schema. Lifted from `bench/compare/README.md`'s shape.
- **R2 — Throughput tier.** A script that runs h2load against mojo-net (and optionally hyper for delta) on `/baseline2` AND `/json/50?m=6` AND `/static/...`, captures req/s + p50/p99/p999 latency + bytes/req, appends a row to `bench/profile/baselines/h2-throughput.csv`. Must include a git-sha column so we can correlate numbers to commits.
- **R3 — Perf-record tier.** A script that boots mojo-net (single-worker, since `perf` on multi-process needs `--all-cpus` and noisier output), runs h2load for a fixed duration with `perf record -F 99 -g -p <worker_pid>`, then unpacks `perf.data` into both `perf.svg` (flamegraph) and `perf-folded.txt` (raw stack samples). Single-worker mode chosen deliberately — multi-worker is for throughput numbers, single-worker for attribution.
- **R4 — Hotspot table.** A script that reads `perf-folded.txt` and emits a markdown table: top 30 functions by % self-time + top 30 by % inclusive-time. Output is committed alongside the flamegraph SVG to `bench/profile/baselines/h2-hotspots.md`.
- **R5 — Baseline.** Run all three scripts once with the current mojo-net main, commit the CSV row + hotspot table + flamegraph SVG. This is the bar Phase 1 must beat.
- **R6 — Retrospective with delta-vs-hyper.** The retrospective documents: (i) measured baseline numbers, (ii) the top 5 hotspots with % CPU, (iii) hypothesized Phase 1 targets ranked by ROI (cost-of-fix vs % CPU recovered), (iv) any methodology issues (perf signal:noise, p99 stability across runs, etc.).

---

## Task 1: Vendor the FlameGraph tooling

**Files:**
- Create: `bench/.tools/.gitignore`
- Verify: `bench/profile/h2-perf-record.sh` will be able to find `flamegraph.pl`

- [ ] **Step 1: Create `bench/.tools/.gitignore`** with content:
  ```
  *
  !.gitignore
  ```
  This keeps `bench/.tools/FlameGraph/` (cloned at runtime) out of the repo.

- [ ] **Step 2: Verify `perf` is available:** `perf --version`. If not, document the install command for the dev OS (Arch: `pacman -S perf`) in the Phase 0 README. Do **not** add as a hard install step — assume the developer has perf.

- [ ] **Step 3: One-time clone (manual, documented in README, not scripted):**
  ```bash
  git clone --depth 1 https://github.com/brendangregg/FlameGraph bench/.tools/FlameGraph
  ```
  Scripts will use `bench/.tools/FlameGraph/{stackcollapse-perf.pl,flamegraph.pl}`.

---

## Task 2: Throughput tier (`h2-throughput.sh`)

**Files:**
- Create: `bench/profile/h2-throughput.sh` (chmod +x)
- Create: `bench/profile/baselines/h2-throughput.csv` (header only)

- [ ] **Step 1: Write `h2-throughput.sh`.**
  - Reuse the Docker setup from `bench/compare/h2-vs-others.sh` (seccomp=unconfined, memlock=-1, nofile=1048576, certs+data mounts).
  - Iterate over a small endpoint set (parameterized via env, default: `/baseline2?a=1&b=2`, `/json/50?m=6`, `/static/...` — pick the smallest static fixture in `bench/.httparena/data/static/`).
  - Per endpoint: warmup (h2load -n 5000 -c 50 -m 16) then measure (h2load -n 200000 -c 50 -m 16, capture p50/p99/p999 from h2load's "time for request" line).
  - Append one CSV row per endpoint per server. Columns: `timestamp,git_sha,server,endpoint,n,c,m,reqs_per_s,p50_us,p99_us,p999_us,bytes_per_req`.
  - Default `SERVERS="mojo-net hyper"`. The hyper row is the *delta target*; we don't need nginx/h2o here — they're for the public comparison writeup.

- [ ] **Step 2: Write the CSV header line into `baselines/h2-throughput.csv`:**
  ```
  timestamp,git_sha,server,endpoint,n,c,m,reqs_per_s,p50_us,p99_us,p999_us,bytes_per_req
  ```

- [ ] **Step 3: Smoke-test by running once.** Verify the CSV row is well-formed and h2load's percentile parsing works for both servers.

- [ ] **Step 4: Commit.** Use the `commit-smart` skill. Message: `feat(bench/profile): add h2 throughput tier with CSV baselines`

---

## Task 3: Perf-record tier (`h2-perf-record.sh`)

**Files:**
- Create: `bench/profile/h2-perf-record.sh` (chmod +x)

- [ ] **Step 1: Write `h2-perf-record.sh`.**
  - Boot mojo-net **single-worker** (override `BENCH_WORKERS=1` env in the launcher) — multi-process samples scatter across cpus and confuse attribution.
  - Capture the worker PID (`pgrep -f bench/h2_server -n` after a 2 s settle).
  - Start `h2load -D 30 -c 50 -m 16 https://127.0.0.1:8443/$ENDPOINT` in the background.
  - In parallel: `perf record -F 99 -g -p $WORKER_PID -o $OUT/perf.data -- sleep 25` (5 s shorter than h2load's duration so we don't sample teardown).
  - On finish: `perf script -i $OUT/perf.data > $OUT/perf-script.txt`, then `bench/.tools/FlameGraph/stackcollapse-perf.pl $OUT/perf-script.txt > $OUT/perf-folded.txt`, then `bench/.tools/FlameGraph/flamegraph.pl $OUT/perf-folded.txt > $OUT/perf.svg`.
  - Parameter: `OUT` defaults to `bench/profile/runs/$(date +%Y%m%d-%H%M%S)-$(git rev-parse --short HEAD)/`.

- [ ] **Step 2: One run for sanity.** Confirm the flamegraph SVG renders, has recognizable mojo-net symbols (`H2Connection.send_data`, `tls.send_data`, etc.), and that h2load reports clean completion (no failed streams).

- [ ] **Step 3: Commit.** Use the `commit-smart` skill. Message: `feat(bench/profile): add h2 perf-record + flamegraph harness`

---

## Task 4: Hotspot extraction (`h2-hotspots.sh`)

**Files:**
- Create: `bench/profile/h2-hotspots.sh` (chmod +x)

- [ ] **Step 1: Write `h2-hotspots.sh`.**
  - Input: a `perf-folded.txt` path (default: latest under `bench/profile/runs/`).
  - Compute, from the folded stacks:
    - **Self time per leaf symbol:** sum of sample-counts for each unique stack's leaf, normalized to %.
    - **Inclusive time per symbol:** sum of sample-counts for any stack containing that symbol.
  - Emit a markdown file with two tables (top 30 each), demangled where possible (Mojo symbols are already demangled; rustls/std symbols need `c++filt` for any C++ frames).
  - Output path: `bench/profile/baselines/h2-hotspots-$(git rev-parse --short HEAD).md` so successive runs accumulate.

- [ ] **Step 2: Run on the Task 3 capture.** Eyeball the table — top hits should be plausible (TLS encrypt, ring/aead, mojo H2 frame encoding, allocator). If it's dominated by `__GI___libc_*` syscall stuff we have a profiling-resolution issue (re-run with `-F 999`).

- [ ] **Step 3: Commit.** Use the `commit-smart` skill. Message: `feat(bench/profile): extract hotspot tables from perf-folded stacks`

---

## Task 5: README + baselines

**Files:**
- Create: `bench/profile/README.md`
- Add: `bench/profile/baselines/h2-throughput.csv` (with the first measurement row)
- Add: `bench/profile/baselines/h2-hotspots-<sha>.md` (from Task 4)
- Add: `bench/profile/baselines/h2-flamegraph-<sha>.svg` (from Task 3)

- [ ] **Step 1: Write `bench/profile/README.md`.** Mirror the structure of `bench/compare/README.md`:
  - Prerequisites (perf, FlameGraph, HttpArena cloned)
  - One-time setup (FlameGraph clone, mojo-net image build)
  - Run order: throughput → perf-record → hotspots
  - How to interpret the outputs (CSV columns, flamegraph reading guide, hotspot-table semantics)
  - Caveats: single-worker for attribution, perf needs `kernel.perf_event_paranoid <= 2`, Docker `--cap-add=SYS_ADMIN` may be needed for kernel symbols.

- [ ] **Step 2: Capture the baseline.** Run all three scripts on the current `main` (or whichever branch is the integration target). Commit the CSV + hotspot MD + flamegraph SVG to `bench/profile/baselines/`.

- [ ] **Step 3: Commit.** Use the `commit-smart` skill. Message: `docs(bench/profile): add README and initial mojo-net baseline capture`

---

## Task 6: Retrospective + Phase 1 target ranking

**Files:**
- Create: `plans/2026-04-25-h2-perf-phase0-profiling-retrospective.md`

- [ ] **Step 1: Write the retrospective.** Sections, in order:
  1. **Built vs. planned** — file checklist, deviations.
  2. **Baseline numbers** — throughput CSV row(s), p50/p99/p999, vs hyper.
  3. **Top hotspots** — extract top 5 by self-time and top 5 by inclusive-time from the hotspot table. Annotate each with a one-line "what is this".
  4. **Phase 1 candidate targets, ranked by ROI.** For each suspect from `plans/2026-04-25-h2-bench-comparison.md` (TLS-record drain batching, per-frame allocs, HPACK fast path, etc.), assign:
     - **Measured % CPU** (or "not visible in profile" if it didn't surface — important negative signal).
     - **Estimated cost** (hours / risk).
     - **Expected gain** (back-of-envelope: if X is 25 % of CPU and we halve it, we recover ~12 % rps).
     - **Decision:** in-scope for Phase 1, deferred to Phase 2, or dropped.
  5. **Methodology issues** — anything noisy, sampling resolution problems, run-to-run variance numbers, missing kernel symbols, etc.
  6. **Open questions** — anything Phase 1 can't proceed without.

- [ ] **Step 2: Commit.** Use the `commit-smart` skill. Message: `docs(plans): Phase 0 profiling retrospective with Phase 1 target ranking`

---

## Exit criteria for Phase 0

Before drafting Phase 1's plan, this Phase 0 retrospective must answer:

1. What is mojo-net's measured req/s for `/baseline2`, `/json/50?m=6`, and `/static/*` against hyper, with p99?
2. What are the top 5 self-time hotspots in the H2 worker?
3. What is the **% CPU spent inside `tls.send_data` + `drain_ciphertext`** specifically? (Tests the chunking-cost hypothesis.)
4. What is the **% CPU spent in allocator paths** (mimalloc/malloc/free)? (Tests the per-frame `List[UInt8]` hypothesis.)
5. What is the **% CPU spent in rustls AEAD encrypt**? (Tests the rustls-vs-OpenSSL hypothesis without committing to swap it yet.)

Phase 1 is **not** drafted until those five questions have numerical answers, not guesses.

---

## Out of scope (deliberately)

- **Any optimization commit.** Phase 0 is measurement only.
- **Multi-worker profiling.** Multi-worker confuses per-symbol attribution; we use single-worker for the flamegraph and multi-worker only for end-to-end throughput.
- **H1 plain and H3 profiling.** This plan is H2 TLS only — that's where the gap is largest and the suspects are most concrete. H1 and H3 each get their own Phase 0 if/when we want to close gaps there.
- **rustls source-level profiling.** We measure rustls's *aggregate* CPU here. Going deeper (which AEAD, which crypto provider) is a Phase 3 concern only if Phase 0 says rustls is dominant.
