# H3 phase-leg instrumentation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decompose the long-conn 24.4s `unaccounted_pct` (82% of busy) into 3 named H3 phase legs (`h3_drain_resp_us`, `quic_post_recv_us`, `h3_dispatch_us`) so the next long-conn-targeted optimisation has a clear, evidence-backed target.

**Architecture:** Mirror sub-leg pass: 3 new `AcceptProfile` UInt64 fields + 3 `record_*` methods + JSON/text emit + budget-closure ε refresh. Brackets wrap `_dispatch_h3_events` + `_drain_responses` in `src/h3/h3_handler_server.mojo` and the post-recv `_quic.timeout`+`poll`-loop tail in `src/h3/connection.mojo`. `profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]` field is unconditional on both H3 structs (precedent: `QuicConnection.profile_ptr` at `src/quic/connection.mojo:334`); threaded via Shape B post-construction setter (`H3HandlerServer.__init__` does `self._h3.profile_ptr = profile_ptr` after `H3Connection.server(...)` returns, leaving the ~15 `H3Connection.server`/`.client` call sites elsewhere in `src/h3/` and `tests/` untouched). Single-pair clock-read pattern with hoisted `var t_start: UInt64 = 0` to function scope (sub-leg pass T4 lesson).

**Tech Stack:** Mojo 0.26.2; bench docker (`bench/Dockerfile`); `bench/quic_perf/scripts/{bench.sh,start-server.sh}` for capture; `src/quic/profile.mojo:16` `comptime PROFILE_ACCEPT` flag.

---

## File structure

| File | Status | Single responsibility |
|---|---|---|
| `src/quic/profile.mojo` | modify | Add 3 UInt64 fields after `loop_iter_count` (`h3_drain_resp_us_total`, `quic_post_recv_us_total`, `h3_dispatch_us_total`); init in `__init__`; add 3 `record_*` methods; emit `h3_phases_us` JSON block; update `report_text` Loop-phases block + budget-closure ε; same for `report_json`. |
| `src/h3/h3_handler_server.mojo` | modify | Add unconditional `profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]` field; update construction `__init__` to accept default-null kwarg + forward to `self._h3.profile_ptr`; update move ctor to copy from `take`; bracket `_dispatch_h3_events` (line 130) + `_drain_responses` (line 132) with single-pair clock-read pattern. |
| `src/h3/connection.mojo` | modify | Add unconditional `profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]` field; update both `__init__`s to init/copy; bracket the post-recv tail (`_quic.timeout` + `while True: poll()` event loop) inside `feed_datagram_from_buffer` (lines 264-296). `H3Connection.server`/`.client` factories untouched. |
| `bench/h3_server.mojo` | modify | At cold-create site (line 843), split `H3HandlerServer[BenchHandler](...)` ctor call via `@parameter if PROFILE_ACCEPT:` / `else:` mirroring `QuicConnection.server` at lines 795-815: on-build branch passes `profile_ptr=UnsafePointer(to=self.profile)`, off-build branch omits the kwarg. |
| `tests/test_quic_profile.mojo` | modify | +6 tests (T1=4, T4=2): 3 record-* increment tests + 1 JSON-emit roundtrip + 1 sum-invariant + 1 budget-closure refresh. |
| `bench/quic_perf/results/REFERENCE.md` | modify | Append shipped-pass row at T7. |
| `bench/quic_perf/results/profile/Q1_pre_baselines_2026-04-29.md` | create | T0 evidence file (RPS medians + pre sidecar `unaccounted_pct`). |
| `bench/quic_perf/results/profile/Q1_post_evidence_2026-04-29.md` | create | T6 evidence file (per-leg medians + dominant-phase verdict + AC table). |
| `bench/quic_perf/results/profile/INSTRUMENTATION-<UTC ts>-q1-{pre,post}-{long,short}conn-iter[1-3].json` | create | 12 SIGINT sidecars (n=3 each cell × 2 cells × pre/post). |
| `docs/project-context.md` | modify | T7: phase advance to `spec-quic-h3-phase-leg-instrumentation-reviewing`; spec status `pending`→`done`; session-history entry. |

---

## Task list

### Task 0: Branch + pre-spec test count anchor + pre-migration baselines

**Tag:** parent
**Estimated time:** ~70 min (2 docker builds + 4 bench cells × 10-iter + 6 sidecars)

**Files:**
- Create: `bench/quic_perf/results/profile/Q1_pre_baselines_2026-04-29.md`
- Create: 6× `INSTRUMENTATION-*-q1-pre-{long,short}conn-iter[1-3].json`

- [ ] **Step 1: Verify prior phase completed**

```bash
cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main
git status -sb  # should be clean on main
git log --oneline | head -3  # HEAD should be 6020c42 or later
```

Expected: clean; HEAD of main at or after `6020c42` (Q3 done).

- [ ] **Step 2: Branch off main**

```bash
MAIN_HEAD=$(git rev-parse main)
echo "Branching off main at: $MAIN_HEAD"
git checkout -b feat/quic-h3-phase-leg-instrumentation main
```

Save `$MAIN_HEAD` for the retrospective.

- [ ] **Step 3: Pre-spec test count anchor**

```bash
TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | tee /tmp/q1_t0_pre_tests.log | tail -3
PRE_PASS=$(grep -c "^PASS:" /tmp/q1_t0_pre_tests.log)
echo "PRE_PASS (^PASS: prefix) = $PRE_PASS"
```

Expected: non-zero PASS count. Record `$PRE_PASS` for AC#1 verification at T1+T4 (target = `$PRE_PASS + 6` after both subagent tasks land).

- [ ] **Step 4: Verify off-build flag is False (sanity)**

```bash
grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo
```

Expected: `comptime PROFILE_ACCEPT: Bool = False`. Abort if True.

- [ ] **Step 5: Build pre-migration off-build image**

```bash
BOUCLE_DIR=/home/donokami/Projets/perso/boucle SIMDJSON_DIR=/home/donokami/Projets/perso/json-simd-mojo \
  bash bench/build.sh 2>&1 | tee /tmp/q1_t0_build_off.log | tail -5
grep -E "Successfully|^ERROR|naming to" /tmp/q1_t0_build_off.log
docker tag httparena-mojo-net mojo-net-bench:q1-pre-off
docker images | grep "mojo-net-bench:q1-pre-off"
```

- [ ] **Step 6: Capture pre-migration off-build baselines (long-conn + short-conn, n=10 each)**

```bash
bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
MOJO_NET_IMAGE=mojo-net-bench:q1-pre-off bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 10 2>&1 | tee /tmp/q1_t0_offbuild_long.log
bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
MOJO_NET_IMAGE=mojo-net-bench:q1-pre-off bash bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 10 2>&1 | tee /tmp/q1_t0_offbuild_short.log
```

Compute medians:
```bash
python3 -c "
import json, statistics, glob
for cell in ['long-conn', 'short-conn']:
    files = sorted(glob.glob(f'bench/quic_perf/results/2026-04-29T*-mojo-net-1k-{cell}-tquic_client-iter*.json'))[-10:]
    rps = [json.load(open(f))['results']['rps'] for f in files]
    m = statistics.median(rps); s = statistics.stdev(rps)
    print(f'{cell}: median={m:.2f}  mean={statistics.mean(rps):.2f}  stdev={s:.2f}  cv={s/statistics.mean(rps)*100:.2f}%')
"
```

Record both medians for AC#5 comparison at T5.

- [ ] **Step 7: Flip PROFILE_ACCEPT to True (uncommitted) + build pre-migration on-build image**

```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = False/comptime PROFILE_ACCEPT: Bool = True/' src/quic/profile.mojo
grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo  # = True
BOUCLE_DIR=/home/donokami/Projets/perso/boucle SIMDJSON_DIR=/home/donokami/Projets/perso/json-simd-mojo \
  bash bench/build.sh 2>&1 | tee /tmp/q1_t0_build_on.log | tail -5
grep -E "Successfully|^ERROR|naming to" /tmp/q1_t0_build_on.log
docker tag httparena-mojo-net mojo-net-bench:q1-pre-on
docker images | grep "q1-pre-on"
```

- [ ] **Step 8: Capture pre-migration on-build long-conn + short-conn 10-iter baselines (AC#3 + AC#4 anchors)**

```bash
bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
MOJO_NET_IMAGE=mojo-net-bench:q1-pre-on bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 10 2>&1 | tee /tmp/q1_t0_onbuild_long.log
bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
MOJO_NET_IMAGE=mojo-net-bench:q1-pre-on bash bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 10 2>&1 | tee /tmp/q1_t0_onbuild_short.log
```

Compute medians (same Python snippet as Step 6, using the latest 10 iters per cell). Record for AC#3 + AC#4.

- [ ] **Step 9: Capture pre-migration n=3 long-conn + n=3 short-conn SIGINT sidecars (Hard Gate 1 baseline)**

Reuse the sidecar capture script from Q3 (already at `/tmp/q3_capture_pre_sidecars.sh`); copy and rename:
```bash
cp /tmp/q3_capture_pre_sidecars.sh /tmp/q1_capture_sidecars.sh
sed -i 's/q3-/q1-/g' /tmp/q1_capture_sidecars.sh
```

Modify the script's hard-coded `1k short-conn` to support both cells:
```bash
cat > /tmp/q1_capture_sidecars.sh <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
LABEL="$1"      # "pre" or "post"
IMAGE="$2"
CELL="$3"       # "long-conn" or "short-conn"
START_ITER="${4:-1}"
END_ITER="${5:-3}"
for i in $(seq "$START_ITER" "$END_ITER"); do
    echo "=== sidecar iter $i (${LABEL}, ${CELL}) ==="
    bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh 2>&1 | tail -2 || true
    MOJO_NET_IMAGE="$IMAGE" bash bench/quic_perf/scripts/start-server.sh mojo-net >/dev/null 2>&1
    bash bench/quic_perf/scripts/run-tquic-client.sh 1k "$CELL" 30 >/dev/null 2>&1
    docker kill --signal=SIGINT bench-h3 >/dev/null 2>&1
    sleep 2
    docker cp bench-h3:/app/bench/quic_perf/results/profile/. bench/quic_perf/results/profile/ 2>/dev/null
    bash bench/quic_perf/scripts/stop-server.sh >/dev/null 2>&1
    LATEST=$(ls -t bench/quic_perf/results/profile/INSTRUMENTATION-*.json 2>/dev/null | grep -v "q[0-9]-" | head -1)
    if [ -n "$LATEST" ]; then
        TARGET="${LATEST%.json}-q1-${LABEL}-${CELL}-iter${i}.json"
        mv "$LATEST" "$TARGET"
        UNACC=$(python3 -c "import json; d=json.load(open('$TARGET')); pp=sum(d['per_pkt_us'][k]['total'] for k in ['header_parse','hp','aead','frame_parse','sm','residual']); ph=d['loop_phases_us']; busy=d.get('busy_us_total',0); a=pp+d.get('drain_us_total',0)+ph['pop_dispatch']['total']+ph['post_pkt']['total']+ph['teardown']['total']; print(round((busy-a)/busy*100,1) if busy else 'N/A')")
        DM=$(python3 -c "import json; d=json.load(open('$TARGET')); print(d.get('addr_key_dcid_mismatch', {}).get('dcid_mismatch_pkts', 'MISSING'))")
        echo "  -> $TARGET  unaccounted_pct=${UNACC}%  dcid_mismatch_pkts=$DM"
    else
        echo "  ERROR: no sidecar produced for iter $i"; exit 1
    fi
done
EOF
chmod +x /tmp/q1_capture_sidecars.sh
bash /tmp/q1_capture_sidecars.sh pre mojo-net-bench:q1-pre-on long-conn 1 3 2>&1 | tee /tmp/q1_t0_pre_long_sidecars.log
bash /tmp/q1_capture_sidecars.sh pre mojo-net-bench:q1-pre-on short-conn 1 3 2>&1 | tee /tmp/q1_t0_pre_short_sidecars.log
```

Expected: 6 files matching `bench/quic_perf/results/profile/INSTRUMENTATION-*-q1-pre-{long,short}conn-iter[1-3].json`. Record per-iter `unaccounted_pct` for Hard Gate 1 baseline (long-conn predicted ≈82%; short-conn predicted ≈18%).

- [ ] **Step 10: Revert PROFILE_ACCEPT (must NOT be committed at T0)**

```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = True/comptime PROFILE_ACCEPT: Bool = False/' src/quic/profile.mojo
grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo  # = False
git status src/quic/profile.mojo  # clean
```

- [ ] **Step 11: Write T0 evidence file**

Write `bench/quic_perf/results/profile/Q1_pre_baselines_2026-04-29.md` with:
- Branch + main `$MAIN_HEAD` + `$PRE_PASS`
- Image SHAs for `q1-pre-off` / `q1-pre-on` (`docker inspect <image> --format '{{.Id}}'`)
- Off-build long-conn + short-conn medians (rps, IQR, stdev, CV) — record raw 10 values each
- On-build long-conn + short-conn medians
- Long-conn n=3 sidecar `unaccounted_pct` per-iter + median
- Short-conn n=3 sidecar `unaccounted_pct` per-iter + median
- All sidecars `dcid_mismatch_pkts` (should be 0)

- [ ] **Step 12: Commit T0 evidence**

```bash
git add bench/quic_perf/results/profile/Q1_pre_baselines_2026-04-29.md \
        bench/quic_perf/results/profile/INSTRUMENTATION-*-q1-pre-*.json
```

Use the `commit-smart` skill. Message: `bench: T0 pre-migration baselines (off+on build, 6x sidecars)`.

---

### Task 1: profile.mojo — 3 fields + 3 record methods + JSON/text emit + budget closure refresh (TDD, 4 tests)

**Tag:** subagent
**Estimated time:** ~20 min

**Files:**
- Modify: `src/quic/profile.mojo` (3 field decls + 3 init lines + 3 record methods + report_json `h3_phases_us` block + report_text `H3 phases:` block + budget closure refresh)
- Modify: `tests/test_quic_profile.mojo` (4 new tests + main() registration)

- [ ] **Step 1: Write 4 failing tests**

In `tests/test_quic_profile.mojo`, after the existing `test_loop_phase_avg_uses_loop_iter_count_divisor` (or similar nearest neighbour from sub-leg pass), add:

```mojo
def test_record_h3_drain_resp_increments_total() raises:
    var p = AcceptProfile()
    p.record_h3_drain_resp(UInt64(123))
    p.record_h3_drain_resp(UInt64(456))
    assert_equal_int(Int(p.h3_drain_resp_us_total), 579, "h3_drain_resp accumulates")
    print("PASS: test_record_h3_drain_resp_increments_total")


def test_record_quic_post_recv_increments_total() raises:
    var p = AcceptProfile()
    p.record_quic_post_recv(UInt64(100))
    p.record_quic_post_recv(UInt64(200))
    assert_equal_int(Int(p.quic_post_recv_us_total), 300, "quic_post_recv accumulates")
    print("PASS: test_record_quic_post_recv_increments_total")


def test_record_h3_dispatch_increments_total() raises:
    var p = AcceptProfile()
    p.record_h3_dispatch(UInt64(50))
    p.record_h3_dispatch(UInt64(75))
    assert_equal_int(Int(p.h3_dispatch_us_total), 125, "h3_dispatch accumulates")
    print("PASS: test_record_h3_dispatch_increments_total")


def test_report_json_emits_h3_phases_block() raises:
    var p = AcceptProfile()
    p.record_h3_drain_resp(UInt64(1000))
    p.record_quic_post_recv(UInt64(2000))
    p.record_h3_dispatch(UInt64(3000))
    var out = p.report_json()
    # Spot-check: the h3_phases_us block must appear with 3 named keys.
    assert_true('"h3_phases_us":' in out, "h3_phases_us block missing")
    assert_true('"drain_resp":' in out, "drain_resp key missing")
    assert_true('"post_recv":' in out, "post_recv key missing")
    assert_true('"dispatch":' in out, "dispatch key missing")
    assert_true('"total": 1000' in out, "drain_resp total missing")
    assert_true('"total": 2000' in out, "post_recv total missing")
    assert_true('"total": 3000' in out, "dispatch total missing")
    print("PASS: test_report_json_emits_h3_phases_block")
```

Register all 4 in `main()` of `tests/test_quic_profile.mojo`:

```mojo
    test_record_h3_drain_resp_increments_total()
    test_record_quic_post_recv_increments_total()
    test_record_h3_dispatch_increments_total()
    test_report_json_emits_h3_phases_block()
```

- [ ] **Step 2: Verify tests fail**

```bash
TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | tail -10
```

Expected: FAIL — `'AcceptProfile' has no method named 'record_h3_drain_resp'` or similar attribute error.

- [ ] **Step 3: Add 3 fields + 3 init lines + 3 record methods**

In `src/quic/profile.mojo`, after line 112 (`var loop_iter_count: UInt64`), insert:

```mojo
    # 3 H3 phase totals — decompose long-conn unaccounted ε (Plan: 2026-04-29).
    # All three live in the post-recv tail of feed_datagram_from_buffer.
    var h3_drain_resp_us_total: UInt64
    var quic_post_recv_us_total: UInt64
    var h3_dispatch_us_total: UInt64
```

In `__init__` after line 156 (`self.loop_iter_count = UInt64(0)`):

```mojo
        self.h3_drain_resp_us_total = UInt64(0)
        self.quic_post_recv_us_total = UInt64(0)
        self.h3_dispatch_us_total = UInt64(0)
```

After the existing `record_loop_iter` method (around line 273), add:

```mojo
    def record_h3_drain_resp(mut self, us: UInt64):
        self.h3_drain_resp_us_total = self.h3_drain_resp_us_total + us

    def record_quic_post_recv(mut self, us: UInt64):
        self.quic_post_recv_us_total = self.quic_post_recv_us_total + us

    def record_h3_dispatch(mut self, us: UInt64):
        self.h3_dispatch_us_total = self.h3_dispatch_us_total + us
```

- [ ] **Step 4: Update `report_json` (around lines 587-605)**

In the `accounted` computation at line 587, add the 3 new legs:

```mojo
        var accounted = (per_pkt_legs_sum
            + self.drain_us_total
            + self.loop_pop_dispatch_us_total
            + self.loop_post_pkt_us_total
            + self.loop_teardown_us_total
            + self.h3_drain_resp_us_total
            + self.quic_post_recv_us_total
            + self.h3_dispatch_us_total)
```

After the closing `s += "  },\n"` of the existing `loop_phases_us` block (around line 605), insert a new `h3_phases_us` block:

```mojo
        s += '  "h3_phases_us": {\n'
        s += '    "drain_resp": {"total": ' + String(self.h3_drain_resp_us_total) + '},\n'
        s += '    "post_recv":  {"total": ' + String(self.quic_post_recv_us_total) + '},\n'
        s += '    "dispatch":   {"total": ' + String(self.h3_dispatch_us_total) + '}\n'
        s += "  },\n"
```

- [ ] **Step 5: Update `report_text` (around lines 397-412)**

After the existing `Loop phases:` block (line 400 `loop_iter_count` line), append a new `H3 phases:` block before the budget-closure block (line 401-412):

```mojo
        # H3 phases (Plan: 2026-04-29-quic-h3-phase-leg-instrumentation).
        s += "H3 phases:\n"
        s += "  drain_resp.total: " + _fmt_count(self.h3_drain_resp_us_total) + "\n"
        s += "  post_recv.total:  " + _fmt_count(self.quic_post_recv_us_total) + "\n"
        s += "  dispatch.total:   " + _fmt_count(self.h3_dispatch_us_total) + "\n\n"
```

In the `acct` computation at line 404, add the 3 new legs (mirroring the report_json change above):

```mojo
        var acct = (pp_legs + self.drain_us_total + self.loop_pop_dispatch_us_total
            + self.loop_post_pkt_us_total + self.loop_teardown_us_total
            + self.h3_drain_resp_us_total
            + self.quic_post_recv_us_total
            + self.h3_dispatch_us_total)
```

- [ ] **Step 6: Verify tests pass**

```bash
TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | tail -10
```

Expected: PASS — 4 new `PASS:` lines printed; total `^PASS:` count = `$PRE_PASS + 4`.

- [ ] **Step 7: Verify full src test suite still green**

```bash
bash scripts/run_tests.sh 2>&1 | tail -3
```

Expected: `All N/N src tests passed` (regression guard).

- [ ] **Step 8: Commit**

Use the `commit-smart` skill. Message: `feat: add 3 H3 phase legs to AcceptProfile (fields + record + emit)`

---

### Task 2: h3_handler_server.mojo — profile_ptr field + ctor threading + 2 brackets

**Tag:** subagent
**Estimated time:** ~15 min

**Files:**
- Modify: `src/h3/h3_handler_server.mojo` (add field + 2 ctor updates + 2 brackets + imports)

This task is a mechanical mirror of the sub-leg pass T4 pattern. No new tests in this task (T1's tests already cover the underlying methods; T4 covers integration semantics).

- [ ] **Step 1: Update imports**

At the top of `src/h3/h3_handler_server.mojo` (after the existing `from src.quic.connection import QuicConnection` line ~11), add:

```mojo
from src.quic.profile import AcceptProfile, profile_monotonic_us, PROFILE_ACCEPT
```

- [ ] **Step 2: Add `profile_ptr` field to `H3HandlerServer` struct**

In the struct field list (around line 90, after `_streams: Dict[Int, _H3StreamPtr]`):

```mojo
    var profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]
```

- [ ] **Step 3: Update construction `__init__` (around line 92)**

Replace the current ctor body:

```mojo
    def __init__(
        out self,
        *,
        var quic: QuicConnection,
        var handler: Self.H,
        profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]
            = UnsafePointer[AcceptProfile, MutAnyOrigin](),
    ) raises:
        self._h3 = H3Connection.server(quic^)
        self.handler = handler^
        self._streams = Dict[Int, _H3StreamPtr]()
        self.profile_ptr = profile_ptr
        # Shape B threading: H3Connection.server/.client have ~15 call sites
        # in src/h3/ and tests/; we set profile_ptr post-construction here
        # rather than threading it through 15 call sites.
        self._h3.profile_ptr = profile_ptr
```

- [ ] **Step 4: Update move ctor (around line 97)**

Replace the move ctor body to copy `profile_ptr` from `take`:

```mojo
    def __init__(out self, *, deinit take: Self):
        self._h3 = take._h3^
        self.handler = take.handler^
        self._streams = take._streams^
        self.profile_ptr = take.profile_ptr
```

- [ ] **Step 5: Bracket `_dispatch_h3_events` and `_drain_responses` (lines 122-132)**

Replace the entire `feed_datagram_from_buffer` method (lines 122-132) with the bracketed form:

```mojo
    def feed_datagram_from_buffer(
        mut self,
        buf: UnsafePointer[UInt8, MutAnyOrigin],
        buf_len: Int,
        now: UInt64,
    ) raises:
        """Feed one inbound QUIC datagram from a mutable buffer (zero-copy)."""
        self._h3.feed_datagram_from_buffer(buf, buf_len, now)

        # Bracket _dispatch_h3_events
        var t_dispatch_start: UInt64 = 0
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                t_dispatch_start = profile_monotonic_us()
        self._dispatch_h3_events(now)
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                self.profile_ptr[].record_h3_dispatch(profile_monotonic_us() - t_dispatch_start)

        # Bracket _drain_responses (only when established)
        if self._h3.is_established():
            var t_drain_resp_start: UInt64 = 0
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    t_drain_resp_start = profile_monotonic_us()
            self._drain_responses(now)
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    self.profile_ptr[].record_h3_drain_resp(profile_monotonic_us() - t_drain_resp_start)
```

The non-buffer `feed_datagram` variant at line 116-120 is left untimed per spec §3 (bench uses `_from_buffer` exclusively).

- [ ] **Step 6: Validate via Mojo MCP**

```
mcp__mojo-mcp__validate src/h3/h3_handler_server.mojo
```

Expected: no syntax errors. (Pre-existing deprecation warnings are fine.)

- [ ] **Step 7: Verify src test suite still green (regression guard)**

```bash
bash scripts/run_tests.sh 2>&1 | tail -3
```

Expected: `All N/N src tests passed`.

(Note: profile_ptr field is null at default; existing tests construct H3HandlerServer with the 2-kwarg form which now picks up the default-null kwarg — should compile + run unchanged.)

- [ ] **Step 8: Commit**

Use the `commit-smart` skill. Message: `feat(h3): bracket _dispatch_h3_events + _drain_responses with profile_ptr`

---

### Task 3: src/h3/connection.mojo — profile_ptr field + post-recv tail bracket

**Tag:** subagent
**Estimated time:** ~12 min

**Files:**
- Modify: `src/h3/connection.mojo` (add field + 2 ctor updates + 1 bracket + imports)

- [ ] **Step 1: Update imports**

At the top of `src/h3/connection.mojo` (with the other `from src.quic` imports), add:

```mojo
from src.quic.profile import AcceptProfile, profile_monotonic_us, PROFILE_ACCEPT
```

- [ ] **Step 2: Add `profile_ptr` field to `H3Connection` struct (around line 140, after `_dec: QpackDecoder`)**

```mojo
    var profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]
```

- [ ] **Step 3: Update construction `__init__` (around line 142)**

In the body after `self._dec = QpackDecoder()`:

```mojo
        self.profile_ptr = UnsafePointer[AcceptProfile, MutAnyOrigin]()
```

(`H3Connection.__init__` keeps its existing 2-arg signature `(var quic, is_server)` unchanged. Profile_ptr is set post-construction by `H3HandlerServer.__init__` per Shape B locked in §5.3 of the spec.)

- [ ] **Step 4: Update move ctor (around line 161)**

In the body after `self._dec = take._dec^`:

```mojo
        self.profile_ptr = take.profile_ptr
```

- [ ] **Step 5: Bracket the post-recv tail of `feed_datagram_from_buffer` (lines 263-296)**

Replace the body of `feed_datagram_from_buffer` (lines 263-296) with the bracketed form. **Critical:** the bracket starts AFTER `self._quic.recv_from_buffer` (which is already timed by `record_pkt`) and ends AFTER the `while True:` poll-loop closes. The `_quic.timeout` call is inside the bracket.

```mojo
    def feed_datagram_from_buffer(
        mut self,
        buf: UnsafePointer[UInt8, MutAnyOrigin],
        buf_len: Int,
        now: UInt64,
    ) raises:
        """Feed one inbound QUIC datagram from a mutable buffer pointer.
        Zero-copy variant — buffer is modified in-place."""
        self._quic.recv_from_buffer(buf, buf_len, now)

        # Bracket the post-recv tail (timeout + poll-loop including _drain_stream).
        # record_pkt at connection.mojo:890 fires INSIDE recv_from_buffer's
        # coalesced-packet for-loop and is bounded by it; this bracket covers
        # the disjoint H3-application-event-drain phase. Single-pair clock-read
        # with hoisted t_start (sub-leg pass T4 lesson — Mojo lexical scope).
        var t_start: UInt64 = 0
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                t_start = profile_monotonic_us()

        _ = self._quic.timeout(now)
        while True:
            var ev_opt = self._quic.poll()
            if not ev_opt:
                break
            var ev = ev_opt.unsafe_take()
            if ev.type_id == QuicEvent.HANDSHAKE_COMPLETE:
                if not self._init_done:
                    self._init_done = True
                    self._bootstrap_local_streams(now)
                var h3ev = H3Event(H3Event.HANDSHAKE_COMPLETE)
                self._h3_events.append(h3ev^)
            elif ev.type_id == QuicEvent.STREAM_OPENED:
                if self._is_peer_initiated(ev.stream_id):
                    var sbuf = _H3StreamBuf()
                    sbuf.is_uni = (ev.stream_id & UInt64(0x02)) != 0
                    self._stream_bufs[Int(ev.stream_id)] = sbuf^
            elif ev.type_id == QuicEvent.STREAM_READABLE:
                try:
                    self._drain_stream(ev.stream_id, now)
                except:
                    pass
            elif ev.type_id == QuicEvent.STREAM_RESET:
                if self._is_request_stream(ev.stream_id):
                    var h3ev = H3Event(H3Event.STREAM_RESET)
                    h3ev.stream_id = ev.stream_id
                    h3ev.error_code = ev.error_code
                    self._h3_events.append(h3ev^)
            elif ev.type_id == QuicEvent.CONNECTION_CLOSED:
                var h3ev = H3Event(H3Event.CONNECTION_CLOSED)
                h3ev.error_code = ev.error_code
                h3ev.reason = ev.reason
                self._h3_events.append(h3ev^)

        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                self.profile_ptr[].record_quic_post_recv(profile_monotonic_us() - t_start)
```

- [ ] **Step 6: Validate via Mojo MCP**

```
mcp__mojo-mcp__validate src/h3/connection.mojo
```

Expected: no syntax errors.

- [ ] **Step 7: Verify src test suite still green**

```bash
bash scripts/run_tests.sh 2>&1 | tail -3
```

Expected: `All N/N src tests passed`. The post-construction `profile_ptr` setter from T2 leaves H3Connection's profile_ptr null in any test that doesn't explicitly set it; the `if Int(self.profile_ptr) != 0` guard skips the bracket cleanly.

- [ ] **Step 8: Commit**

Use the `commit-smart` skill. Message: `feat(h3): bracket post-recv tail of feed_datagram_from_buffer with profile_ptr`

---

### Task 4: bench/h3_server.mojo cold-create + budget-closure refresh tests (TDD, 2 tests)

**Tag:** subagent
**Estimated time:** ~12 min

**Files:**
- Modify: `bench/h3_server.mojo` (cold-create at line 843 — `@parameter if PROFILE_ACCEPT:` / `else:` ctor split)
- Modify: `tests/test_quic_profile.mojo` (+2 tests: sum invariant + budget closure refresh)

- [ ] **Step 1: Write 2 failing tests**

In `tests/test_quic_profile.mojo`, after the 4 tests added in T1, add:

```mojo
def test_h3_phase_legs_sum_within_unaccounted_bucket() raises:
    """Synthetic profile: 3 H3 legs cumulatively are bounded by the
    pre-existing unaccounted bucket. Catches bracket overlap (a future
    bug where two brackets time the same code path)."""
    var p = AcceptProfile()
    # Synthetic busy with known leg shapes:
    #   busy = 1000
    #   per_pkt = 200 (split equally across 6 legs)
    #   drain = 100
    #   loop = 100 (across 3 loop legs)
    #   ε bucket = busy - per_pkt - drain - loop = 600
    p.busy_us_total = UInt64(1000)
    p.header_parse_us_total = UInt64(33)
    p.hp_us_total = UInt64(33)
    p.aead_us_total = UInt64(33)
    p.frame_parse_us_total = UInt64(34)
    p.sm_us_total = UInt64(33)
    p.residual_us_total = UInt64(34)
    p.drain_us_total = UInt64(100)
    p.loop_pop_dispatch_us_total = UInt64(34)
    p.loop_post_pkt_us_total = UInt64(33)
    p.loop_teardown_us_total = UInt64(33)
    # Now introduce 3 H3 legs cumulatively summing to 500 (< 600 unacct bucket).
    p.record_h3_drain_resp(UInt64(300))
    p.record_quic_post_recv(UInt64(150))
    p.record_h3_dispatch(UInt64(50))
    var per_pkt = (p.header_parse_us_total + p.hp_us_total + p.aead_us_total
        + p.frame_parse_us_total + p.sm_us_total + p.residual_us_total)
    var loop_phases = (p.loop_pop_dispatch_us_total + p.loop_post_pkt_us_total + p.loop_teardown_us_total)
    var pre_h3_unacct = p.busy_us_total - per_pkt - p.drain_us_total - loop_phases
    var h3_sum = p.h3_drain_resp_us_total + p.quic_post_recv_us_total + p.h3_dispatch_us_total
    assert_true(h3_sum <= pre_h3_unacct, "h3 legs must fit within pre-h3 unaccounted bucket")
    print("PASS: test_h3_phase_legs_sum_within_unaccounted_bucket")


def test_budget_closure_subtracts_h3_legs() raises:
    """Synthetic profile with all leg types populated. Budget-closure ε must
    subtract h3 legs in addition to per_pkt + drain + loop."""
    var p = AcceptProfile()
    p.busy_us_total = UInt64(1000)
    p.header_parse_us_total = UInt64(50)
    p.hp_us_total = UInt64(50)
    p.aead_us_total = UInt64(50)
    p.frame_parse_us_total = UInt64(50)
    p.sm_us_total = UInt64(50)
    p.residual_us_total = UInt64(50)   # per_pkt sum = 300
    p.drain_us_total = UInt64(100)
    p.loop_pop_dispatch_us_total = UInt64(50)
    p.loop_post_pkt_us_total = UInt64(50)
    p.loop_teardown_us_total = UInt64(50)  # loop sum = 150
    p.record_h3_drain_resp(UInt64(200))
    p.record_quic_post_recv(UInt64(100))
    p.record_h3_dispatch(UInt64(50))   # h3 sum = 350

    var out = p.report_json()
    # Expected unaccounted = 1000 - 300 - 100 - 150 - 350 = 100
    assert_true('"unaccounted_us_total": 100,' in out, "unaccounted_us_total should be 100")
    # Expected unaccounted_pct = 100 / 1000 * 100 = 10
    assert_true('"unaccounted_pct": 10' in out, "unaccounted_pct should be 10")
    print("PASS: test_budget_closure_subtracts_h3_legs")
```

Register both in `main()`:

```mojo
    test_h3_phase_legs_sum_within_unaccounted_bucket()
    test_budget_closure_subtracts_h3_legs()
```

- [ ] **Step 2: Verify tests fail OR pass mismatched values**

```bash
TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | tail -10
```

Expected outcome (depends on whether T1's budget-closure refresh code change is correct): if the formula was correctly updated in T1 to subtract the 3 new legs, both tests pass. If T1's update was incomplete, `test_budget_closure_subtracts_h3_legs` fails with a non-100 unaccounted value — investigate and fix T1's `accounted` formula.

The sum-invariant test should pass regardless (it only checks pre-h3 unacct >= h3_sum).

If `test_budget_closure_subtracts_h3_legs` fails: re-inspect `report_json` and `report_text` `accounted` formulas in `src/quic/profile.mojo`, ensure both subtract `h3_drain_resp_us_total + quic_post_recv_us_total + h3_dispatch_us_total`.

- [ ] **Step 3: Update bench/h3_server.mojo cold-create at line 843**

Find the existing call site (`grep -n "H3HandlerServer\[BenchHandler\](" bench/h3_server.mojo` to confirm current line — likely 843 ± 5 from churn). Replace:

```mojo
# Existing site, pre-spec:
# h3 = H3HandlerServer[BenchHandler](quic=quic^, handler=handler^)
# Post-spec — split via @parameter if PROFILE_ACCEPT, mirroring lines 795-815:
@parameter
if PROFILE_ACCEPT:
    h3 = H3HandlerServer[BenchHandler](
        quic=quic^,
        handler=handler^,
        profile_ptr=UnsafePointer(to=self.profile),
    )
else:
    h3 = H3HandlerServer[BenchHandler](
        quic=quic^,
        handler=handler^,
    )
```

- [ ] **Step 4: Verify all 6 new tests pass**

```bash
TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | tail -10
```

Expected: PASS — 6 new `PASS:` lines (4 from T1 + 2 from this task); total `^PASS:` = `$PRE_PASS + 6`. AC#1 satisfied.

- [ ] **Step 5: Verify full src test suite still green**

```bash
bash scripts/run_tests.sh 2>&1 | tail -3
```

Expected: `All N/N src tests passed`.

- [ ] **Step 6: Commit**

Use the `commit-smart` skill. Message: `feat(bench): thread profile_ptr into H3HandlerServer cold-create + budget-closure tests`

---

### Task 5: Smoke gate — Hard Gate 2 (on-build) + Hard Gate 3 (on-build) + Hard Gate 4 (off-build)

**Tag:** parent
**Estimated time:** ~40 min (2 docker rebuilds + 4 bench cells × 10-iter)

**Files:** none modified; results captured to `bench/quic_perf/results/`.

- [ ] **Step 1: Build post-migration off-build image**

```bash
grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo  # = False
BOUCLE_DIR=/home/donokami/Projets/perso/boucle SIMDJSON_DIR=/home/donokami/Projets/perso/json-simd-mojo \
  bash bench/build.sh 2>&1 | tee /tmp/q1_t5_build_off.log | tail -5
docker tag httparena-mojo-net mojo-net-bench:q1-post-off
```

- [ ] **Step 2: Capture post-migration off-build long-conn + short-conn (Hard Gate 4 — AC#5)**

```bash
bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
MOJO_NET_IMAGE=mojo-net-bench:q1-post-off bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 10
bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
MOJO_NET_IMAGE=mojo-net-bench:q1-post-off bash bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 10
```

Compute medians (use the same Python snippet as T0 Step 6) and compute drift vs T0's off-build medians. Threshold: drift ≥ −2.0% on BOTH cells. AC#5 PASS/FAIL recorded.

If FAIL: stop; investigate. Off-build regression means the unconditional `profile_ptr` field caused struct-layout drift. Per spec §10 rollback plan, remove the field entirely (do not gate per-build).

- [ ] **Step 3: Flip flag + build post-migration on-build image**

```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = False/comptime PROFILE_ACCEPT: Bool = True/' src/quic/profile.mojo
BOUCLE_DIR=/home/donokami/Projets/perso/boucle SIMDJSON_DIR=/home/donokami/Projets/perso/json-simd-mojo \
  bash bench/build.sh 2>&1 | tee /tmp/q1_t5_build_on.log | tail -5
docker tag httparena-mojo-net mojo-net-bench:q1-post-on
```

- [ ] **Step 4: Capture post-migration on-build long-conn + short-conn (Hard Gate 2 + 3 — AC#3 + AC#4)**

```bash
bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
MOJO_NET_IMAGE=mojo-net-bench:q1-post-on bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 10
bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
MOJO_NET_IMAGE=mojo-net-bench:q1-post-on bash bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 10
```

Compute medians + drifts vs T0's on-build medians. Threshold: drift ≥ −2.0% on BOTH cells.

- [ ] **Step 5: Revert flag (uncommitted, will re-flip in T6)**

```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = True/comptime PROFILE_ACCEPT: Bool = False/' src/quic/profile.mojo
git status src/quic/profile.mojo  # clean
```

- [ ] **Step 6: No commit at this step.** T6 captures sub-leg evidence; T7 commits the combined evidence.

---

### Task 6: SIGINT sidecar capture (Hard Gate 1 + 5 + 6)

**Tag:** parent
**Estimated time:** ~15 min (6 sidecars + analysis)

**Files:**
- Create: 6× `INSTRUMENTATION-*-q1-post-{long,short}conn-iter[1-3].json`
- Create: `bench/quic_perf/results/profile/Q1_post_evidence_2026-04-29.md`

- [ ] **Step 1: Capture n=3 post-migration long-conn + n=3 short-conn SIGINT sidecars**

```bash
docker images | grep q1-post-on  # confirm image exists from T5
sed -i 's/comptime PROFILE_ACCEPT: Bool = False/comptime PROFILE_ACCEPT: Bool = True/' src/quic/profile.mojo  # if T5 reverted
# Image was built with True, so no rebuild needed; flag flip is for source consistency only.
bash /tmp/q1_capture_sidecars.sh post mojo-net-bench:q1-post-on long-conn 1 3 2>&1 | tee /tmp/q1_t6_post_long.log
bash /tmp/q1_capture_sidecars.sh post mojo-net-bench:q1-post-on short-conn 1 3 2>&1 | tee /tmp/q1_t6_post_short.log
```

Expected: 6 files at `bench/quic_perf/results/profile/INSTRUMENTATION-*-q1-post-{long,short}conn-iter[1-3].json`. The capture script already prints `unaccounted_pct` and `dcid_mismatch_pkts` per iter.

- [ ] **Step 2: Compute Hard Gate 1 verdict (long-conn `unaccounted_pct` < 15%)**

```bash
python3 -c "
import json, statistics, glob
for cell in ['long-conn', 'short-conn']:
    files = sorted(glob.glob(f'bench/quic_perf/results/profile/INSTRUMENTATION-*-q1-post-{cell}-iter[1-3].json'))
    vals = []
    for f in files:
        d = json.load(open(f))
        per_pkt = sum(d['per_pkt_us'][k]['total'] for k in ['header_parse','hp','aead','frame_parse','sm','residual'])
        ph = d['loop_phases_us']
        h3 = d.get('h3_phases_us', {})
        h3_total = h3.get('drain_resp', {}).get('total', 0) + h3.get('post_recv', {}).get('total', 0) + h3.get('dispatch', {}).get('total', 0)
        busy = d.get('busy_us_total', 0)
        accounted = per_pkt + d.get('drain_us_total', 0) + ph['pop_dispatch']['total'] + ph['post_pkt']['total'] + ph['teardown']['total'] + h3_total
        unacct = max(0, busy - accounted)
        unacct_pct = round(unacct / busy * 100, 2) if busy else 0
        vals.append(unacct_pct)
        print(f'{f}: unaccounted_pct={unacct_pct}%  h3_drain_resp={h3.get(\"drain_resp\",{}).get(\"total\",0)}  quic_post_recv={h3.get(\"post_recv\",{}).get(\"total\",0)}  h3_dispatch={h3.get(\"dispatch\",{}).get(\"total\",0)}')
    if vals:
        m = statistics.median(vals)
        verdict = 'PASS' if m < 15 else ('SHIPPED-with-caveat' if m <= 25 else 'FAIL')
        print(f'  {cell} median unacct={m}%  → {verdict}')
"
```

Expected: long-conn median `unaccounted_pct` < 15% (Hard Gate 1 PASS); soft floor 15-25% = SHIPPED-with-caveat; >25% = FAIL.

- [ ] **Step 3: Compute Hard Gate 5 (sum invariant) verdict**

```bash
python3 -c "
import json, glob
for f in sorted(glob.glob('bench/quic_perf/results/profile/INSTRUMENTATION-*-q1-post-*-iter*.json')):
    d = json.load(open(f))
    per_pkt = sum(d['per_pkt_us'][k]['total'] for k in ['header_parse','hp','aead','frame_parse','sm','residual'])
    ph = d['loop_phases_us']
    h3 = d.get('h3_phases_us', {})
    h3_total = h3.get('drain_resp', {}).get('total', 0) + h3.get('post_recv', {}).get('total', 0) + h3.get('dispatch', {}).get('total', 0)
    pre_h3_unacct = d.get('busy_us_total', 0) - per_pkt - d.get('drain_us_total', 0) - ph['pop_dispatch']['total'] - ph['post_pkt']['total'] - ph['teardown']['total']
    ok = h3_total <= pre_h3_unacct
    print(f'{f}: h3_sum={h3_total}  pre_h3_unacct={pre_h3_unacct}  invariant_OK={ok}')
"
```

Expected: every sidecar reports `invariant_OK=True`. Hard Gate 5 PASS if all 6 pass.

- [ ] **Step 4: Compute Hard Gate 6 (`dcid_mismatch_pkts == 0`) verdict**

```bash
python3 -c "
import json, glob
for f in sorted(glob.glob('bench/quic_perf/results/profile/INSTRUMENTATION-*-q1-{pre,post}-*-iter*.json')):
    d = json.load(open(f))
    dm = d.get('addr_key_dcid_mismatch', {}).get('dcid_mismatch_pkts', 'MISSING')
    print(f'{f}: dcid_mismatch_pkts={dm}')
"
```

Expected: every file `0`. Hard Gate 6 PASS.

- [ ] **Step 5: Identify dominant phase (the diagnostic deliverable)**

```bash
python3 -c "
import json, glob, statistics
files = sorted(glob.glob('bench/quic_perf/results/profile/INSTRUMENTATION-*-q1-post-long-conn-iter*.json'))
legs = {'drain_resp': [], 'post_recv': [], 'dispatch': []}
for f in files:
    d = json.load(open(f))
    h3 = d.get('h3_phases_us', {})
    for k in legs: legs[k].append(h3.get(k, {}).get('total', 0))
medians = {k: statistics.median(v) for k, v in legs.items()}
print('Long-conn H3 phase medians:', medians)
winner = max(medians, key=medians.get)
print(f'Dominant: {winner} ({medians[winner]:,} μs)')
"
```

Record the winner for REFERENCE.md at T7.

- [ ] **Step 6: Write T6 evidence file**

Write `bench/quic_perf/results/profile/Q1_post_evidence_2026-04-29.md` with:
- Image SHAs for `q1-post-{off,on}` (`docker inspect ...`)
- Hard Gate 1: long-conn `unaccounted_pct` per-iter + median, verdict
- Hard Gate 1 (informational): short-conn `unaccounted_pct` per-iter + median
- Hard Gate 2 + 3 (from T5): on-build long-conn + short-conn drift
- Hard Gate 4 (from T5): off-build long-conn + short-conn drift
- Hard Gate 5: sum-invariant pass/fail per sidecar
- Hard Gate 6: `dcid_mismatch_pkts == 0` confirmation
- Dominant H3 phase named with per-leg medians
- All 9 ACs summary table

- [ ] **Step 7: Commit T6 evidence**

```bash
git add bench/quic_perf/results/profile/Q1_post_evidence_2026-04-29.md \
        bench/quic_perf/results/profile/INSTRUMENTATION-*-q1-post-*.json
```

Use the `commit-smart` skill. Message: `bench: T5+T6 post-migration evidence + Hard Gate verdicts`

---

### Task 7: REFERENCE.md + flag revert + project-context advance + final review

**Tag:** parent
**Estimated time:** ~15 min

**Files:**
- Modify: `bench/quic_perf/results/REFERENCE.md`
- Modify: `docs/project-context.md`

- [ ] **Step 1: Verify flag revert (AC#9)**

```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = True/comptime PROFILE_ACCEPT: Bool = False/' src/quic/profile.mojo
grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo  # = False
git status src/quic/profile.mojo  # clean
```

- [ ] **Step 2: Append REFERENCE.md row (AC#8)**

In `bench/quic_perf/results/REFERENCE.md`, append at the bottom (after the Q3 row). Match the layout of the previous shipped-pass row (Q3 at the bottom of REFERENCE.md). Include:
- Spec/plan filenames + branch + main HEAD
- Goal + predicted dominant phase
- Implementation summary (~130 LoC across 5 files + 6 tests)
- Bench gates table (Hard Gates 1-6 with per-cell medians + verdicts)
- AC table (9 rows: AC#1-AC#9, all PASS expected)
- Image SHAs (q1-pre-off / q1-pre-on / q1-post-off / q1-post-on)
- Dominant phase named + per-leg medians
- Predicted vs observed: `unaccounted_pct` 82% → X%; `h3_drain_resp` predicted 12-16s, observed Y; etc.
- Open-question follow-ups (next opt-spec target = the named winner)

- [ ] **Step 3: Update `docs/project-context.md`**

Phase: `spec-quic-h3-phase-leg-instrumentation-planning` → `spec-quic-h3-phase-leg-instrumentation-reviewing`. Active-specs row: status `pending` → `done`. Session-history entry at top of list.

- [ ] **Step 4: Commit T7**

```bash
git add bench/quic_perf/results/REFERENCE.md docs/project-context.md src/quic/profile.mojo
```

Use the `commit-smart` skill. Message: `docs: T7 REFERENCE.md entry + project-context advance`

- [ ] **Step 5: Final cross-cutting review**

Per subagent-driven-development skill: dispatch a final combined reviewer covering all commits since the plan started (full BASE..HEAD range from `$MAIN_HEAD` through T7 commit).

If reviewer returns ✅ CLEAN → invoke `atelier:finishing-a-development-branch`.
If ISSUES → fix per findings, re-dispatch reviewer, repeat until ✅ CLEAN.

---

## Pre-save scan

- [x] **Spec coverage** — every AC#1-#9 maps to a step:
  - AC#1 (+6 tests) → T1 Step 6 (4 tests) + T4 Step 4 (2 tests)
  - AC#2 (Hard Gate 1, long-conn `unaccounted_pct` <15%) → T6 Step 2
  - AC#3 (Hard Gate 2, on-build long-conn drift ≥ −2.0%) → T5 Step 4
  - AC#4 (Hard Gate 3, on-build short-conn drift ≥ −2.0%) → T5 Step 4
  - AC#5 (Hard Gate 4, off-build drift ≥ −2.0% both cells) → T5 Step 2
  - AC#6 (Hard Gate 5, sum invariant) → T6 Step 3
  - AC#7 (Hard Gate 6, `dcid_mismatch_pkts == 0`) → T6 Step 4
  - AC#8 (REFERENCE.md) → T7 Step 2
  - AC#9 (flag revert) → T7 Step 1
- [x] **No forbidden placeholders** — every step has complete code or exact commands.
- [x] **Names + signatures consistent** — `h3_drain_resp_us_total`, `quic_post_recv_us_total`, `h3_dispatch_us_total`, `record_h3_drain_resp`, `record_quic_post_recv`, `record_h3_dispatch`, `profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]` used uniformly.
- [x] **Test count locked at +6** across spec §6, AC#1, T1 Step 1 (4 tests), and T4 Step 1 (2 tests).
- [x] **Image hygiene** — every bench step uses tag-isolated `mojo-net-bench:q1-{pre,post}-{off,on}` images.
- [x] **CPU gate** — every bench step gates on `cpu_gate.sh`.
- [x] **Single-pair clock-read pattern** — all 3 brackets use `var t_start: UInt64 = 0` hoisted to function scope.
- [x] **Shape B threading** — `H3HandlerServer.__init__` does `self._h3.profile_ptr = profile_ptr` post-construction (T2 Step 3); `H3Connection.__init__` keeps unchanged signature (T3 Step 3).
- [x] **Bracket disjointness** — `quic_post_recv_us` brackets `H3Connection.feed_datagram_from_buffer`'s post-recv tail (lines 264-296); `h3_dispatch_us` and `h3_drain_resp_us` bracket H3HandlerServer's outer call site AFTER `self._h3.feed_datagram_from_buffer` returns. All 3 brackets in disjoint code paths.

---

## Branch precondition

- New branch `feat/quic-h3-phase-leg-instrumentation` off `main` (HEAD captured at T0 Step 2; expected to be at or after `6020c42`).
- Pre-spec PASS count anchor captured at T0 Step 3.
- `comptime PROFILE_ACCEPT: Bool = False` in `src/quic/profile.mojo` at T0 Step 4 (verified) and at T7 Step 1 (verified one final time).
