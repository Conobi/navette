# QUIC Accept-Loop Sub-Leg Instrumentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decompose `AcceptProfile`'s `shim_ffi_us_total` into 3 per-rustls-call sub-legs (read_hs / write_hs / take_keys) AND add 3 explicit loop-phase legs (pop_dispatch / post_pkt / teardown) with budget-closure ε so the next short-conn sidecar names the dominant FFI call AND the dominant loop phase.

**Architecture:** Diagnostic-only extension to `AcceptProfile` in `src/quic/profile.mojo`. Six new `UInt64` totals + one helper `loop_iter_count` + 7 new `record_*` methods. Wired at 3 existing rustls FFI sites in `src/quic/connection.mojo` (single-pair clock-read pattern, function-scope `var t_start` hoist) and 3 phase boundaries in `bench/h3_server.mojo`'s `_flush_impl`. PROFILE_ACCEPT-gated; zero off-build cost. Two SIGINT sidecar captures (long-conn + short-conn) gate AC#4 (sub-leg sum invariant) + AC#5 (budget closure invariant).

**Tech Stack:** Mojo 0.26.2; `comptime PROFILE_ACCEPT: Bool` gate; `monotonic_us()` (CLOCK_MONOTONIC sans-I/O wrapper); SIGINT → JSON sidecar capture (existing pattern); `tquic_client --iters 10 --threads 4 --max-concurrent-conns 25` driver.

---

## File structure

| Path | Action | Single responsibility |
|---|---|---|
| `src/quic/profile.mojo` | modify | Add 6 `*_us_total` fields + `loop_iter_count` helper + 7 record_* methods + report_json `ffi_subleg_us` + `loop_phases_us` blocks + report_text mirrors |
| `src/quic/connection.mojo` | modify | Single-pair clock-read pattern at lines 1591-1603 (read_hs), 1620-1634 (write_hs), 1665-1675 (take_keys) — `var t_start: UInt64 = 0` hoisted to function scope |
| `bench/h3_server.mojo` | modify | `_flush_impl` PHASE A bracket (per-pkt, recorded before each of 3 `continue` sites + main fall-through), PHASE B bracket (per-pkt, after feed_datagram), PHASE C bracket (per-flush, around pending_rx.clear) |
| `tests/test_quic_profile.mojo` | modify | Add 12 unit tests + register them in `main()` |
| `bench/quic_perf/results/profile/INSTRUMENTATION-<ts>-postmigration-longconn-subleg.json` | create | Long-conn sidecar capture from on-build run |
| `bench/quic_perf/results/profile/INSTRUMENTATION-<ts>-postmigration-shortconn-subleg.json` | create | Short-conn sidecar capture from on-build run |
| `bench/quic_perf/results/REFERENCE.md` | append | Sub-leg-pass entry naming the dominant FFI sub-leg + dominant loop phase on short-conn |

---

## Branch precondition

All work happens on a fresh branch off `main` at `b345c99` (post-migration tip). T0 creates the branch.

Subagent execution tags:
- **(parent)** — runs in main session via direct Bash; required for any operation > 2 min wall-clock (per the migration retro lesson on Monitor stalls)
- **(subagent)** — dispatched as a fresh subagent per the subagent-driven-development pattern

---

## Task 0: Hard gate (parent)

**Files:**
- Create: branch `feat/quic-accept-loop-subleg-instrumentation` off `main` at `b345c99`
- Verify: `lib/librustls_mojo.so` is a real file (not dangling symlink)
- Verify: pre-spec test count anchor

- [ ] **Step 1: Create branch off main**
Run: `git -C /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main fetch origin && git -C /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main checkout -b feat/quic-accept-loop-subleg-instrumentation b345c99`
Expected: `Switched to a new branch 'feat/quic-accept-loop-subleg-instrumentation'`

- [ ] **Step 2: Verify lib/ is a real directory (per stale-image lesson)**
Run: `ls -la /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main/lib/ 2>&1 | head -5`
Expected: a directory listing with at least `librustls_mojo.so` as a regular file. If empty or symlink, run:
```bash
cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main
rm -f lib  # if symlink
mkdir -p lib && touch lib/.keep
cp crates/librustls-mojo/target/release/liblibrustls_mojo.so lib/librustls_mojo.so
```

- [ ] **Step 3: Capture pre-spec test count anchor**
Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && bash scripts/run_tests.sh 2>&1 | grep -cE '^PASS:'`
Record the number; AC#1 expects this number + 12 after T3 completes.

- [ ] **Step 4: Verify off-build baseline reproducibility (long-conn, 3 iters as quick sanity)**
Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 3 2>&1 | tail -10`
Expected: median rps within 14,436 ± 1,444 (i.e. 12,992 - 15,880). If outside, abort and investigate baseline drift before proceeding.

- [ ] **Step 5: Commit T0 anchor**
Use the `commit-smart` skill. Message format: `chore: branch off main + capture pre-spec test count anchor`.

---

## Task 1: FFI sub-leg fields + record methods (subagent)

**Files:**
- Modify: `src/quic/profile.mojo` — `AcceptProfile` struct (add 3 fields + 3 methods)
- Test: `tests/test_quic_profile.mojo` — add 3 tests + register in `main()`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_quic_profile.mojo` BEFORE the `def main() raises:` line:

```mojo
def test_record_ffi_read_hs_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_ffi_read_hs(UInt64(100))
    p.record_ffi_read_hs(UInt64(150))
    p.record_ffi_read_hs(UInt64(50))
    if p.ffi_read_hs_us_total != UInt64(300):
        raise "expected ffi_read_hs_us_total=300, got " + String(p.ffi_read_hs_us_total)
    print("PASS: test_record_ffi_read_hs_increments_total")


def test_record_ffi_write_hs_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_ffi_write_hs(UInt64(200))
    p.record_ffi_write_hs(UInt64(300))
    if p.ffi_write_hs_us_total != UInt64(500):
        raise "expected ffi_write_hs_us_total=500, got " + String(p.ffi_write_hs_us_total)
    print("PASS: test_record_ffi_write_hs_increments_total")


def test_record_ffi_take_keys_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_ffi_take_keys(UInt64(40))
    p.record_ffi_take_keys(UInt64(60))
    if p.ffi_take_keys_us_total != UInt64(100):
        raise "expected ffi_take_keys_us_total=100, got " + String(p.ffi_take_keys_us_total)
    print("PASS: test_record_ffi_take_keys_increments_total")
```

Add to the `main()` block at end of file (before `print("All Plan A tests passed.")`):
```mojo
    test_record_ffi_read_hs_increments_total()
    test_record_ffi_write_hs_increments_total()
    test_record_ffi_take_keys_increments_total()
```

- [ ] **Step 2: Verify tests fail**
Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && uv run mojo run -I . -D ASSERT=all tests/test_quic_profile.mojo 2>&1 | tail -10`
Expected: FAIL — `error: 'AcceptProfile' has no member 'record_ffi_read_hs'` (or similar).

- [ ] **Step 3: Add fields to AcceptProfile struct**

In `src/quic/profile.mojo`, after the existing `var dcid_mismatch_pkts: UInt64` field declaration (around line 94), add:

```mojo
    # 3 FFI sub-leg totals — decompose ffi_shim_us_total per rustls call-site.
    # Lifetime-accumulated (NEVER reset per-pkt). Cross-validation:
    # ffi_read_hs + ffi_write_hs + ffi_take_keys must equal ffi_shim_us_total
    # within ±1% across a 30s capture.
    var ffi_read_hs_us_total: UInt64
    var ffi_write_hs_us_total: UInt64
    var ffi_take_keys_us_total: UInt64
```

In `__init__`, after `self.dcid_mismatch_pkts = UInt64(0)` (around line 131), add:
```mojo
        self.ffi_read_hs_us_total = UInt64(0)
        self.ffi_write_hs_us_total = UInt64(0)
        self.ffi_take_keys_us_total = UInt64(0)
```

- [ ] **Step 4: Add record methods**

After the existing `record_dcid_mismatch` method (around line 227), append:

```mojo
    def record_ffi_read_hs(mut self, us: UInt64):
        self.ffi_read_hs_us_total = self.ffi_read_hs_us_total + us

    def record_ffi_write_hs(mut self, us: UInt64):
        self.ffi_write_hs_us_total = self.ffi_write_hs_us_total + us

    def record_ffi_take_keys(mut self, us: UInt64):
        self.ffi_take_keys_us_total = self.ffi_take_keys_us_total + us
```

- [ ] **Step 5: Verify tests pass**
Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && uv run mojo run -I . -D ASSERT=all tests/test_quic_profile.mojo 2>&1 | tail -10`
Expected: 3 new `PASS:` lines for the 3 new tests; existing tests still pass.

- [ ] **Step 6: Commit**
Use the `commit-smart` skill. Message format: `feat: add 3 FFI sub-leg counters to AcceptProfile`.

---

## Task 2: Loop phase fields + record methods + loop_iter_count (subagent)

**Files:**
- Modify: `src/quic/profile.mojo` — `AcceptProfile` struct (add 4 fields + 4 methods)
- Test: `tests/test_quic_profile.mojo` — add 3 tests + register in `main()`

(`record_loop_iter` increment behaviour is covered indirectly by T3's `test_report_json_emits_loop_phases_block` and `test_loop_phase_avg_uses_loop_iter_count_divisor` — no standalone test needed, keeps total at 12 per spec AC#1.)

- [ ] **Step 1: Write failing tests**

Append to `tests/test_quic_profile.mojo` BEFORE the `def main()` line:

```mojo
def test_record_loop_pop_dispatch_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_loop_pop_dispatch(UInt64(50))
    p.record_loop_pop_dispatch(UInt64(75))
    if p.loop_pop_dispatch_us_total != UInt64(125):
        raise "expected loop_pop_dispatch_us_total=125, got " + String(p.loop_pop_dispatch_us_total)
    print("PASS: test_record_loop_pop_dispatch_increments_total")


def test_record_loop_post_pkt_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_loop_post_pkt(UInt64(20))
    p.record_loop_post_pkt(UInt64(30))
    if p.loop_post_pkt_us_total != UInt64(50):
        raise "expected loop_post_pkt_us_total=50, got " + String(p.loop_post_pkt_us_total)
    print("PASS: test_record_loop_post_pkt_increments_total")


def test_record_loop_teardown_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_loop_teardown(UInt64(8))
    p.record_loop_teardown(UInt64(12))
    if p.loop_teardown_us_total != UInt64(20):
        raise "expected loop_teardown_us_total=20, got " + String(p.loop_teardown_us_total)
    print("PASS: test_record_loop_teardown_increments_total")
```

Add to `main()`:
```mojo
    test_record_loop_pop_dispatch_increments_total()
    test_record_loop_post_pkt_increments_total()
    test_record_loop_teardown_increments_total()
```

- [ ] **Step 2: Verify tests fail**
Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && uv run mojo run -I . -D ASSERT=all tests/test_quic_profile.mojo 2>&1 | tail -10`
Expected: FAIL — `error: 'AcceptProfile' has no member 'record_loop_pop_dispatch'`.

- [ ] **Step 3: Add fields to AcceptProfile struct**

In `src/quic/profile.mojo`, after the 3 FFI sub-leg fields added in Task 1, add:

```mojo
    # 3 loop phase totals — decompose un-attributed bench-loop overhead.
    # pop_dispatch + post_pkt are per-pkt accumulators; teardown is
    # per-flush. Divisor for pop_dispatch.avg / post_pkt.avg is
    # loop_iter_count (NOT pkt_count, which excludes continue'd iters);
    # divisor for teardown.avg is on_flush_count.
    var loop_pop_dispatch_us_total: UInt64
    var loop_post_pkt_us_total: UInt64
    var loop_teardown_us_total: UInt64
    var loop_iter_count: UInt64
```

In `__init__`, after the 3 FFI sub-leg field initializers from Task 1, add:
```mojo
        self.loop_pop_dispatch_us_total = UInt64(0)
        self.loop_post_pkt_us_total = UInt64(0)
        self.loop_teardown_us_total = UInt64(0)
        self.loop_iter_count = UInt64(0)
```

- [ ] **Step 4: Add record methods**

After the 3 FFI sub-leg methods added in Task 1, append:

```mojo
    def record_loop_pop_dispatch(mut self, us: UInt64):
        self.loop_pop_dispatch_us_total = self.loop_pop_dispatch_us_total + us

    def record_loop_post_pkt(mut self, us: UInt64):
        self.loop_post_pkt_us_total = self.loop_post_pkt_us_total + us

    def record_loop_teardown(mut self, us: UInt64):
        self.loop_teardown_us_total = self.loop_teardown_us_total + us

    def record_loop_iter(mut self):
        self.loop_iter_count = self.loop_iter_count + UInt64(1)
```

- [ ] **Step 5: Verify tests pass**
Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && uv run mojo run -I . -D ASSERT=all tests/test_quic_profile.mojo 2>&1 | tail -10`
Expected: 4 new `PASS:` lines for the 4 new tests.

- [ ] **Step 6: Commit**
Use the `commit-smart` skill. Message format: `feat: add 3 loop-phase counters + loop_iter_count to AcceptProfile`.

---

## Task 3: report_json + report_text new sections + budget closure (subagent)

**Files:**
- Modify: `src/quic/profile.mojo` — `report_json` + `report_text` methods
- Test: `tests/test_quic_profile.mojo` — add 5 tests (1 sum invariant + 2 budget closure + 2 JSON shape, plus the divisor-locking test = 5)

- [ ] **Step 1: Write failing tests**

Append to `tests/test_quic_profile.mojo` BEFORE the `def main()` line:

```mojo
def test_ffi_subleg_sum_matches_shim_ffi_within_tolerance() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Simulate 3 FFI calls within one pkt accumulating into shim_ffi via record_pkt.
    # Then directly populate sub-legs with the same per-call deltas.
    p.record_pkt(
        total_us=UInt64(120),
        ffi_us=UInt64(100),     # 30 + 50 + 20 = 100
        hp_us=UInt64(1),
        aead_us=UInt64(1),
        header_parse_us=UInt64(1),
        frame_parse_us=UInt64(5),
        sm_us=UInt64(60),
    )
    p.record_ffi_read_hs(UInt64(30))
    p.record_ffi_write_hs(UInt64(50))
    p.record_ffi_take_keys(UInt64(20))
    var subleg_sum = p.ffi_read_hs_us_total + p.ffi_write_hs_us_total + p.ffi_take_keys_us_total
    var diff: UInt64
    if subleg_sum >= p.ffi_shim_us_total:
        diff = subleg_sum - p.ffi_shim_us_total
    else:
        diff = p.ffi_shim_us_total - subleg_sum
    var tol = p.ffi_shim_us_total // UInt64(100)
    if tol < UInt64(1):
        tol = UInt64(1)
    if diff > tol:
        raise "ffi_subleg sum (" + String(subleg_sum) + ") differs from shim_ffi (" + String(p.ffi_shim_us_total) + ") by more than 1%"
    print("PASS: test_ffi_subleg_sum_matches_shim_ffi_within_tolerance")


def test_loop_budget_closure_zero_residual() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # busy = 1000us = 200 (per_pkt total) + 100 (drain) + 400 (pop_dispatch) + 200 (post_pkt) + 100 (teardown)
    p.busy_us_total = UInt64(1000)
    p.record_pkt(
        total_us=UInt64(200),
        ffi_us=UInt64(0),
        hp_us=UInt64(0),
        aead_us=UInt64(0),
        header_parse_us=UInt64(0),
        frame_parse_us=UInt64(0),
        sm_us=UInt64(200),
    )
    p.record_drain(UInt64(100))
    p.record_loop_pop_dispatch(UInt64(400))
    p.record_loop_post_pkt(UInt64(200))
    p.record_loop_teardown(UInt64(100))
    var s = p.report_json()
    if "\"unaccounted_us_total\": 0" not in s:
        raise "expected unaccounted_us_total=0; got snippet: " + s
    if "\"unaccounted_pct\": 0" not in s:
        raise "expected unaccounted_pct=0; got snippet: " + s
    print("PASS: test_loop_budget_closure_zero_residual")


def test_loop_budget_closure_nonzero_residual() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # busy = 10000us; sum of legs = 9900us; residual = 100us = 1% (integer-truncated).
    p.busy_us_total = UInt64(10000)
    p.record_pkt(
        total_us=UInt64(2000),
        ffi_us=UInt64(0),
        hp_us=UInt64(0),
        aead_us=UInt64(0),
        header_parse_us=UInt64(0),
        frame_parse_us=UInt64(0),
        sm_us=UInt64(2000),
    )
    p.record_drain(UInt64(1000))
    p.record_loop_pop_dispatch(UInt64(4000))
    p.record_loop_post_pkt(UInt64(2000))
    p.record_loop_teardown(UInt64(900))
    var s = p.report_json()
    if "\"unaccounted_us_total\": 100" not in s:
        raise "expected unaccounted_us_total=100; got snippet: " + s
    if "\"unaccounted_pct\": 1" not in s:
        raise "expected unaccounted_pct=1; got snippet: " + s
    print("PASS: test_loop_budget_closure_nonzero_residual")


def test_report_json_emits_ffi_subleg_block() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_ffi_read_hs(UInt64(100))
    p.record_ffi_write_hs(UInt64(200))
    p.record_ffi_take_keys(UInt64(50))
    var s = p.report_json()
    if "\"ffi_subleg_us\"" not in s:
        raise "missing ffi_subleg_us block"
    if "\"read_hs\"" not in s:
        raise "missing read_hs key"
    if "\"write_hs\"" not in s:
        raise "missing write_hs key"
    if "\"take_keys\"" not in s:
        raise "missing take_keys key"
    if "\"total\": 100" not in s:
        raise "missing read_hs total=100"
    if "\"total\": 200" not in s:
        raise "missing write_hs total=200"
    print("PASS: test_report_json_emits_ffi_subleg_block")


def test_report_json_emits_loop_phases_block() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_loop_pop_dispatch(UInt64(150))
    p.record_loop_post_pkt(UInt64(50))
    p.record_loop_teardown(UInt64(20))
    p.record_loop_iter()
    p.record_loop_iter()
    var s = p.report_json()
    if "\"loop_phases_us\"" not in s:
        raise "missing loop_phases_us block"
    if "\"pop_dispatch\"" not in s:
        raise "missing pop_dispatch key"
    if "\"post_pkt\"" not in s:
        raise "missing post_pkt key"
    if "\"teardown\"" not in s:
        raise "missing teardown key"
    if "\"loop_iter_count\": 2" not in s:
        raise "missing loop_iter_count=2"
    if "\"unaccounted_us_total\"" not in s:
        raise "missing unaccounted_us_total key"
    if "\"unaccounted_pct\"" not in s:
        raise "missing unaccounted_pct key"
    print("PASS: test_report_json_emits_loop_phases_block")


def test_loop_phase_avg_uses_loop_iter_count_divisor() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # 100 iters, 50 pkts (some continue'd). pop_dispatch total = 10000 us.
    # Expected avg = 10000 / 100 = 100 (NOT 10000 / 50 = 200).
    p.record_loop_pop_dispatch(UInt64(10000))
    for _ in range(100):
        p.record_loop_iter()
    # Synthetically populate pkt_count = 50 to ensure divisor is loop_iter_count.
    p.pkt_count = UInt64(50)
    var s = p.report_json()
    # Look for the pop_dispatch.avg = 100 (not 200).
    if "\"pop_dispatch\": {\"avg\": 100" not in s:
        raise "expected pop_dispatch.avg=100 (loop_iter_count divisor); got snippet: " + s
    print("PASS: test_loop_phase_avg_uses_loop_iter_count_divisor")
```

Add to `main()`:
```mojo
    test_ffi_subleg_sum_matches_shim_ffi_within_tolerance()
    test_loop_budget_closure_zero_residual()
    test_loop_budget_closure_nonzero_residual()
    test_report_json_emits_ffi_subleg_block()
    test_report_json_emits_loop_phases_block()
    test_loop_phase_avg_uses_loop_iter_count_divisor()
```

- [ ] **Step 2: Verify tests fail**
Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && uv run mojo run -I . -D ASSERT=all tests/test_quic_profile.mojo 2>&1 | tail -10`
Expected: FAIL — `missing ffi_subleg_us block` (the report_json doesn't yet emit the new sections).

- [ ] **Step 3: Update `report_json` to emit new blocks**

In `src/quic/profile.mojo`, locate the `report_json` method's `addr_key_dcid_mismatch` block emission (around line 466-482). Immediately AFTER the `s += "\n    }\n  },\n"` line that closes the `addr_key_dcid_mismatch` block, insert:

```mojo
        # FFI sub-legs (Plan: 2026-04-28-quic-accept-loop-subleg-instrumentation).
        var read_hs_avg: UInt64 = UInt64(0)
        var write_hs_avg: UInt64 = UInt64(0)
        var take_keys_avg: UInt64 = UInt64(0)
        if self.pkt_count > UInt64(0):
            read_hs_avg = self.ffi_read_hs_us_total / self.pkt_count
            write_hs_avg = self.ffi_write_hs_us_total / self.pkt_count
            take_keys_avg = self.ffi_take_keys_us_total / self.pkt_count
        s += '  "ffi_subleg_us": {\n'
        s += '    "read_hs":   {"avg": ' + String(read_hs_avg) + ', "total": ' + String(self.ffi_read_hs_us_total) + '},\n'
        s += '    "write_hs":  {"avg": ' + String(write_hs_avg) + ', "total": ' + String(self.ffi_write_hs_us_total) + '},\n'
        s += '    "take_keys": {"avg": ' + String(take_keys_avg) + ', "total": ' + String(self.ffi_take_keys_us_total) + '}\n'
        s += "  },\n"

        # Loop phases (Plan: 2026-04-28-quic-accept-loop-subleg-instrumentation).
        var pop_dispatch_avg: UInt64 = UInt64(0)
        var post_pkt_avg: UInt64 = UInt64(0)
        if self.loop_iter_count > UInt64(0):
            pop_dispatch_avg = self.loop_pop_dispatch_us_total / self.loop_iter_count
            post_pkt_avg = self.loop_post_pkt_us_total / self.loop_iter_count
        var teardown_avg: UInt64 = UInt64(0)
        if self.on_flush_count > UInt64(0):
            teardown_avg = self.loop_teardown_us_total / self.on_flush_count
        # Budget closure ε:
        # busy = per_pkt_total_sum + drain + pop_dispatch + post_pkt + teardown + ε
        # per_pkt_total_sum is reconstructed from leg sums (ffi excluded — overlaps sm).
        var per_pkt_legs_sum = (self.header_parse_us_total
            + self.hp_us_total
            + self.aead_us_total
            + self.frame_parse_us_total
            + self.sm_us_total
            + self.residual_us_total)
        var accounted = (per_pkt_legs_sum
            + self.drain_us_total
            + self.loop_pop_dispatch_us_total
            + self.loop_post_pkt_us_total
            + self.loop_teardown_us_total)
        var unaccounted: UInt64 = UInt64(0)
        if self.busy_us_total > accounted:
            unaccounted = self.busy_us_total - accounted
        var unaccounted_pct: UInt64 = UInt64(0)
        if self.busy_us_total > UInt64(0):
            unaccounted_pct = (unaccounted * UInt64(100)) / self.busy_us_total
        s += '  "loop_phases_us": {\n'
        s += '    "pop_dispatch": {"avg": ' + String(pop_dispatch_avg) + ', "total": ' + String(self.loop_pop_dispatch_us_total) + '},\n'
        s += '    "post_pkt":     {"avg": ' + String(post_pkt_avg) + ', "total": ' + String(self.loop_post_pkt_us_total) + '},\n'
        s += '    "teardown":     {"avg": ' + String(teardown_avg) + ', "total": ' + String(self.loop_teardown_us_total) + '},\n'
        s += '    "loop_iter_count": ' + String(self.loop_iter_count) + ',\n'
        s += '    "unaccounted_us_total": ' + String(unaccounted) + ',\n'
        s += '    "unaccounted_pct": ' + String(unaccounted_pct) + '\n'
        s += "  },\n"
```

- [ ] **Step 4: Update `report_text` with mirroring sections**

In `src/quic/profile.mojo`, locate the `report_text` method's `addr_key DCID mismatch` block (around line 331-341). Immediately AFTER the closing `s += "\n"` of that block, insert:

```mojo
        # FFI sub-legs (Plan: 2026-04-28).
        s += "FFI sub-legs:\n"
        s += "  " + _fmt_leg("read_hs",   self.ffi_read_hs_us_total,   self.pkt_count) + "\n"
        s += "  " + _fmt_leg("write_hs",  self.ffi_write_hs_us_total,  self.pkt_count) + "\n"
        s += "  " + _fmt_leg("take_keys", self.ffi_take_keys_us_total, self.pkt_count) + "\n\n"

        # Loop phases (Plan: 2026-04-28).
        s += "Loop phases:\n"
        s += "  " + _fmt_leg("pop_dispatch", self.loop_pop_dispatch_us_total, self.loop_iter_count) + "\n"
        s += "  " + _fmt_leg("post_pkt",     self.loop_post_pkt_us_total,     self.loop_iter_count) + "\n"
        s += "  " + _fmt_leg("teardown",     self.loop_teardown_us_total,     self.on_flush_count) + "\n"
        s += "  loop_iter_count:                  " + _fmt_count(self.loop_iter_count) + "\n"
        # Budget closure (mirrors report_json computation).
        var pp_legs = (self.header_parse_us_total + self.hp_us_total + self.aead_us_total
            + self.frame_parse_us_total + self.sm_us_total + self.residual_us_total)
        var acct = (pp_legs + self.drain_us_total + self.loop_pop_dispatch_us_total
            + self.loop_post_pkt_us_total + self.loop_teardown_us_total)
        var unacct: UInt64 = UInt64(0)
        if self.busy_us_total > acct:
            unacct = self.busy_us_total - acct
        var unacct_pct: UInt64 = UInt64(0)
        if self.busy_us_total > UInt64(0):
            unacct_pct = (unacct * UInt64(100)) / self.busy_us_total
        s += "  unaccounted_us_total:             " + _fmt_count(unacct) + "  (" + String(unacct_pct) + "% of busy)\n\n"
```

- [ ] **Step 5: Verify tests pass**
Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && uv run mojo run -I . -D ASSERT=all tests/test_quic_profile.mojo 2>&1 | tail -15`
Expected: 6 new `PASS:` lines (the 5 from this task + 1 from the divisor-locking test) plus all prior tests passing.

- [ ] **Step 6: Verify total test count == anchor + 12**
Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && bash scripts/run_tests.sh 2>&1 | grep -cE '^PASS:'`
Expected: T0's anchor number + exactly 12 (3 from T1 + 3 from T2 + 6 from T3). AC#1 satisfied.

If count is +13: T2 still includes `test_record_loop_iter_increments_count` — remove it.
If count is +11: a test is missing from T1/T2/T3 — re-check the registrations in `main()`.

- [ ] **Step 7: Commit**
Use the `commit-smart` skill. Message format: `feat: emit ffi_subleg_us + loop_phases_us blocks with budget closure ε`.

---

## Task 4: Wire FFI sub-leg recording in connection.mojo (subagent)

**Files:**
- Modify: `src/quic/connection.mojo` lines 1591-1603 (read_hs), 1620-1634 (write_hs), 1665-1675 (take_keys)

- [ ] **Step 1: Wire read_hs sub-leg (lines 1591-1604)**

In `src/quic/connection.mojo`, replace the existing block at lines 1591-1604:

```mojo
                    @parameter
                    if PROFILE_ACCEPT:
                        if Int(self.profile_ptr) != 0:
                            self.profile_rustls_us_accum -= monotonic_us()
                    var rc = lib[].quic_conn_read_hs(
                        self.conn_handle,
                        data_buf,
                        Int32(len(crypto_data)),
                    )
                    @parameter
                    if PROFILE_ACCEPT:
                        if Int(self.profile_ptr) != 0:
                            self.profile_rustls_us_accum += monotonic_us()
                    data_buf.free()
```

with:

```mojo
                    var t_start: UInt64 = 0
                    @parameter
                    if PROFILE_ACCEPT:
                        if Int(self.profile_ptr) != 0:
                            t_start = monotonic_us()
                            self.profile_rustls_us_accum -= t_start
                    var rc = lib[].quic_conn_read_hs(
                        self.conn_handle,
                        data_buf,
                        Int32(len(crypto_data)),
                    )
                    @parameter
                    if PROFILE_ACCEPT:
                        if Int(self.profile_ptr) != 0:
                            var t_end = monotonic_us()
                            self.profile_rustls_us_accum += t_end
                            self.profile_ptr[].record_ffi_read_hs(t_end - t_start)
                    data_buf.free()
```

- [ ] **Step 2: Wire write_hs sub-leg (lines 1620-1634)**

Replace:

```mojo
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    self.profile_rustls_us_accum -= monotonic_us()
            var rc = lib[].quic_conn_write_hs(
                self.conn_handle,
                out_buf,
                Int32(_WRITE_HS_BUF_SIZE),
                out_written,
                out_kc,
            )
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    self.profile_rustls_us_accum += monotonic_us()
```

with:

```mojo
            var t_start: UInt64 = 0
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    t_start = monotonic_us()
                    self.profile_rustls_us_accum -= t_start
            var rc = lib[].quic_conn_write_hs(
                self.conn_handle,
                out_buf,
                Int32(_WRITE_HS_BUF_SIZE),
                out_written,
                out_kc,
            )
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    var t_end = monotonic_us()
                    self.profile_rustls_us_accum += t_end
                    self.profile_ptr[].record_ffi_write_hs(t_end - t_start)
```

- [ ] **Step 3: Wire take_keys sub-leg (lines 1665-1675)**

Replace:

```mojo
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        self.profile_rustls_us_accum -= monotonic_us()
                var take_rc = lib[].quic_conn_take_keys(
                    self.conn_handle, keys_handle_buf
                )
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        self.profile_rustls_us_accum += monotonic_us()
```

with:

```mojo
                var t_start: UInt64 = 0
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        t_start = monotonic_us()
                        self.profile_rustls_us_accum -= t_start
                var take_rc = lib[].quic_conn_take_keys(
                    self.conn_handle, keys_handle_buf
                )
                @parameter
                if PROFILE_ACCEPT:
                    if Int(self.profile_ptr) != 0:
                        var t_end = monotonic_us()
                        self.profile_rustls_us_accum += t_end
                        self.profile_ptr[].record_ffi_take_keys(t_end - t_start)
```

- [ ] **Step 4: Verify off-build still compiles + tests still pass**
Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && bash scripts/run_tests.sh 2>&1 | tail -5`
Expected: same PASS count as after T3 (no regression). Connection.mojo compiles with `PROFILE_ACCEPT=False` (the new `var t_start` and `var t_end` are gated by `@parameter if PROFILE_ACCEPT:` so off-build they DCE; the function-scope `var t_start: UInt64 = 0` is a single zero-init word).

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message format: `feat: wire FFI sub-leg recording at 3 rustls call-sites`.

---

## Task 5: Wire loop-phase recording in bench/h3_server.mojo (subagent)

**Files:**
- Modify: `bench/h3_server.mojo` `_flush_impl` lines 710-908

- [ ] **Step 1: Add PHASE A pop_dispatch bracket + record_loop_iter**

In `bench/h3_server.mojo`, locate the `for i in range(len(self.pending_rx)):` line (currently line 722). Immediately AFTER the `var pd = self.pending_rx[i].copy()` line (currently line 723), insert:

```mojo
            var t_pop_dispatch_start: UInt64 = 0
            @parameter
            if PROFILE_ACCEPT:
                t_pop_dispatch_start = profile_monotonic_us()
                self.profile.record_loop_iter()
```

This is the start of PHASE A; `record_loop_iter` happens inside the same `@parameter if` block so it's gated.

- [ ] **Step 2: Insert PHASE A end recording at 3 continue sites + main fall-through**

Locate the 3 `continue` statements in the for-loop body. Currently:
- Line 748: `self.consumed_bufs.append(pd.buf_id); continue` (Strict-gate skip)
- Line 793: `self.consumed_bufs.append(pd.buf_id); continue` (QuicConnection.server failure)
- Line 817: `self.consumed_bufs.append(pd.buf_id); continue` (H3HandlerServer ctor failure)

Before each `continue`, insert:

```mojo
                @parameter
                if PROFILE_ACCEPT:
                    self.profile.record_loop_pop_dispatch(profile_monotonic_us() - t_pop_dispatch_start)
```

Then locate the comment `# Feed datagram to the connection.` (currently line 838). Immediately BEFORE that comment, insert:

```mojo
            @parameter
            if PROFILE_ACCEPT:
                self.profile.record_loop_pop_dispatch(profile_monotonic_us() - t_pop_dispatch_start)
```

- [ ] **Step 3: Add PHASE B post_pkt bracket**

Locate the existing `@parameter\nif PROFILE_ACCEPT:` block at line 846 (the is_established poll). Immediately BEFORE that `@parameter` decorator, insert:

```mojo
            var t_post_pkt_start: UInt64 = 0
            @parameter
            if PROFILE_ACCEPT:
                t_post_pkt_start = profile_monotonic_us()
```

Then locate the comment `# Drain and send outgoing datagrams.` (currently line 861). Immediately BEFORE that comment, insert:

```mojo
            @parameter
            if PROFILE_ACCEPT:
                self.profile.record_loop_post_pkt(profile_monotonic_us() - t_post_pkt_start)
```

- [ ] **Step 4: Add PHASE C teardown bracket**

Locate the existing `self.pending_rx.clear()` line (currently line 878). Replace it with:

```mojo
        var t_teardown_start: UInt64 = 0
        @parameter
        if PROFILE_ACCEPT:
            t_teardown_start = profile_monotonic_us()
        self.pending_rx.clear()
        @parameter
        if PROFILE_ACCEPT:
            self.profile.record_loop_teardown(profile_monotonic_us() - t_teardown_start)
```

- [ ] **Step 5: Verify off-build still compiles + bench harness still imports**

Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && uv run mojo build -I . bench/h3_server.mojo 2>&1 | tail -10`
Expected: build succeeds. If unused-variable warnings appear for `t_pop_dispatch_start` / `t_post_pkt_start` / `t_teardown_start` off-build, those are acceptable (they're DCE-eligible).

If build fails with `unused variable`, the `@parameter`-gated assignment may not satisfy Mojo 0.26.2's flow analysis. In that case, replace the `var x: UInt64 = 0` declaration with `var x = UInt64(0)` (which signals an intentional value-init) and verify again.

Run unit tests: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && bash scripts/run_tests.sh 2>&1 | tail -5`
Expected: same PASS count as after T3.

- [ ] **Step 6: Commit**
Use the `commit-smart` skill. Message format: `feat: wire 3 loop-phase brackets in _flush_impl`.

---

## Task 6: Off-build smoke gate (parent — ~15 min)

**Files:**
- Verify: `src/quic/profile.mojo:16` is `comptime PROFILE_ACCEPT: Bool = False`
- Use: existing post-migration off-build docker image OR rebuild with PROFILE_ACCEPT=False

- [ ] **Step 1: Confirm PROFILE_ACCEPT = False in source**
Run: `grep -nE 'comptime PROFILE_ACCEPT' /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main/src/quic/profile.mojo`
Expected: line 16 reads `comptime PROFILE_ACCEPT: Bool = False`. If not, fix it.

- [ ] **Step 2: Rebuild off-build docker image (per docker-image-hygiene memory)**
Run (in background, save output to a log file, watch for "Successfully built" terminator):
```bash
cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main
bash bench/quic_perf/scripts/build.sh 2>&1 | tee /tmp/bench-build-T6.log
```
Expected: log ends with `Successfully built` AND `mojo-net-bench:latest` is the new image (`docker images mojo-net-bench:latest --format '{{.ID}}'` returns a fresh ID). If the log ends with an `ERROR` line, halt and investigate before proceeding.

- [ ] **Step 3: Run 10-iter long-conn smoke gate**
Run (in background via `Bash + run_in_background`):
```bash
cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main
bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 10 2>&1 | tee /tmp/bench-T6-long.log
```
Wait for completion (~6.5 min). Expected: `tail -5 /tmp/bench-T6-long.log` reports `median=<X>` where `X ∈ [12,992, 15,880]` (14,436 ± 10%).

- [ ] **Step 4: Run 10-iter short-conn smoke gate**
Run:
```bash
bash bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 10 2>&1 | tee /tmp/bench-T6-short.log
```
Expected: median rps ∈ [1,087, 1,329] (1,208 ± 10%).

- [ ] **Step 5: Record measurements**

Append a new file `bench/quic_perf/results/profile/T6_T7_smoke_gate_2026-04-28.md` with both medians and the IQR + stdev from each run's bench output. Format:

```markdown
# T6/T7 Smoke Gate — sub-leg instrumentation

Plan: `plans/2026-04-28-quic-accept-loop-subleg-instrumentation.md`
Branch: `feat/quic-accept-loop-subleg-instrumentation`
Date: 2026-04-28

## T6 — Off-build (`comptime PROFILE_ACCEPT: Bool = False`)

| Cell | n | Median rps | IQR | StDev |
|---|---|---|---|---|
| Long-conn | 10 | <X> | <Y> | <Z> |
| Short-conn | 10 | <X> | <Y> | <Z> |

Drift vs post-migration off-build baseline:
- Long-conn: <(median − 14436) / 14436 × 100>% (gate: ±10%)
- Short-conn: <(median − 1208) / 1208 × 100>% (gate: ±10%)

Verdict: **PASS** / FAIL.
```

- [ ] **Step 6: Commit**
Use the `commit-smart` skill. Message format: `bench: T6 off-build smoke gate <PASS|FAIL>`.

If FAIL: halt and investigate before proceeding to T7.

---

## Task 7: On-build smoke gate (parent — ~20 min)

**Files:**
- Modify: `src/quic/profile.mojo:16` → `comptime PROFILE_ACCEPT: Bool = True`
- Rebuild docker image with the flag flipped
- Append T7 section to `bench/quic_perf/results/profile/T6_T7_smoke_gate_2026-04-28.md`

- [ ] **Step 1: Toggle PROFILE_ACCEPT to True in source**
Edit `src/quic/profile.mojo` line 16:
- Old: `comptime PROFILE_ACCEPT: Bool = False`
- New: `comptime PROFILE_ACCEPT: Bool = True`

Verify: `grep -nE 'comptime PROFILE_ACCEPT' /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main/src/quic/profile.mojo` reports `True`.

- [ ] **Step 2: Rebuild on-build docker image fresh**
```bash
cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main
bash bench/quic_perf/scripts/build.sh 2>&1 | tee /tmp/bench-build-T7.log
```
Verify: `grep -E 'Successfully built|^ERROR' /tmp/bench-build-T7.log | tail -3` shows `Successfully built` and no `ERROR`. Record the new image ID: `docker images mojo-net-bench:latest --format '{{.ID}}'`.

- [ ] **Step 3: Run 10-iter long-conn on-build smoke gate**
```bash
bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 10 2>&1 | tee /tmp/bench-T7-long.log
```
Expected: median rps ∈ [12,698, 15,520] (14,109 ± 10%).

- [ ] **Step 4: Run 10-iter short-conn on-build smoke gate**
```bash
bash bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 10 2>&1 | tee /tmp/bench-T7-short.log
```
Expected: median rps ∈ [1,067, 1,305] (1,186 ± 10%).

- [ ] **Step 5: Record measurements + drift analysis**

Append to `bench/quic_perf/results/profile/T6_T7_smoke_gate_2026-04-28.md`:

```markdown
## T7 — On-build (`comptime PROFILE_ACCEPT: Bool = True`)

Image rebuilt at <timestamp>; new image ID `<short-id>`.

| Cell | n | Median rps | IQR | StDev |
|---|---|---|---|---|
| Long-conn | 10 | <X> | <Y> | <Z> |
| Short-conn | 10 | <X> | <Y> | <Z> |

Drift vs post-migration on-build baseline:
- Long-conn: <(median − 14109) / 14109 × 100>% (gate: ±10%)
- Short-conn: <(median − 1186) / 1186 × 100>% (gate: ±10%)

Verdict: **PASS** / FAIL.
```

- [ ] **Step 6: Commit**
Use the `commit-smart` skill. Message format: `bench: T7 on-build smoke gate <PASS|FAIL>`.

If FAIL: halt — likely the new instrumentation has higher overhead than budgeted. Re-check the single-pair clock-read pattern at the 3 FFI sites; consider reducing per-flush teardown timing if loop_teardown is repeatedly called.

---

## Task 8: SIGINT sidecar capture both cells (parent — ~5 min)

**Files:**
- Create: `bench/quic_perf/results/profile/INSTRUMENTATION-<ts>-postmigration-longconn-subleg.json`
- Create: `bench/quic_perf/results/profile/INSTRUMENTATION-<ts>-postmigration-shortconn-subleg.json`

Image is on-build from T7. PROFILE_ACCEPT = True.

- [ ] **Step 1: Long-conn sidecar capture (1 iter, 30s window)**

```bash
cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main

# Start mojo-net server in detached container.
docker run -d --rm --name bench-h3-longconn \
  --network host \
  -e BENCH_PROTOCOL=h3 \
  --security-opt seccomp=unconfined \
  --ulimit memlock=-1:-1 \
  mojo-net-bench:latest

# Wait for ready.
sleep 3

# Drive load via tquic_client (long-conn config).
docker run --rm --network host \
  -v $(pwd)/bench/quic_perf/results:/results \
  --entrypoint /bin/bash \
  tquic-client:latest \
  -c "tquic_client --threads 4 --max-concurrent-conns 25 --max-requests-per-conn 0 https://127.0.0.1:8443/data/static/1k.bin --total-requests-per-thread 0 --tls-versions tls1.3 --tls-ca-certificates /etc/tquic/ca.crt --duration 30s 2>&1" &
TQUIC_PID=$!

# Wait 28s into the 30s run, then SIGINT the server (triggers JSON dump + libc exit).
sleep 28
docker kill --signal=SIGINT bench-h3-longconn 2>&1 || true

wait $TQUIC_PID 2>&1 || true
sleep 1

# Copy sidecar out (the server's _write_profile_json_sidecar writes to /tmp inside container; mount or grep).
docker logs bench-h3-longconn 2>&1 | grep -E "INSTRUMENTATION-" | tail -1

# (If sidecar dir is mounted, copy directly.)
TS=$(date -u +%Y%m%d-%H%M%S)
docker cp bench-h3-longconn:/tmp/INSTRUMENTATION.json bench/quic_perf/results/profile/INSTRUMENTATION-${TS}-postmigration-longconn-subleg.json 2>&1 || true
```

Verify: file `bench/quic_perf/results/profile/INSTRUMENTATION-*-longconn-subleg.json` exists and contains valid JSON with `ffi_subleg_us` + `loop_phases_us` blocks.

If the sidecar path differs in the container (e.g. `/output/` instead of `/tmp/`), inspect the existing sidecar capture protocol used by the prior queueing-tail / counter / migration passes via `git log -p plans/2026-04-27-quic-addr-key-to-dcid-demux-migration.md | grep -E 'docker cp|sidecar' | head -10` and adapt.

- [ ] **Step 2: Short-conn sidecar capture (1 iter, 30s window)**

Same procedure, but launch `tquic_client` with the short-conn config (`--max-requests-per-conn 1` — one request per conn, conn closed after each). Output: `INSTRUMENTATION-<ts>-postmigration-shortconn-subleg.json`.

- [ ] **Step 3: Verify AC#4 — sub-leg sum invariant**

```bash
for f in bench/quic_perf/results/profile/INSTRUMENTATION-*-subleg.json; do
  echo "=== $f ==="
  python3 -c "
import json, sys
d = json.load(open('$f'))
shim = d['per_pkt_us']['shim_ffi']['total']
sl = d['ffi_subleg_us']
sum_sl = sl['read_hs']['total'] + sl['write_hs']['total'] + sl['take_keys']['total']
diff = abs(sum_sl - shim)
tol = max(shim // 100, 1)
print(f'shim_ffi={shim} subleg_sum={sum_sl} diff={diff} tol={tol} {\"PASS\" if diff <= tol else \"FAIL\"}')
"
done
```

Expected: both files print `PASS`. If FAIL, the FFI sub-leg wiring has a gap (a missed FFI site or a double-count); halt and investigate.

- [ ] **Step 4: Verify AC#5 — budget closure invariant**

```bash
for f in bench/quic_perf/results/profile/INSTRUMENTATION-*-subleg.json; do
  echo "=== $f ==="
  python3 -c "
import json
d = json.load(open('$f'))
pct = d['loop_phases_us']['unaccounted_pct']
print(f'unaccounted_pct={pct} {\"PASS\" if pct < 2 else \"FAIL\"}')
"
done
```

Expected: both `PASS` (`unaccounted_pct < 2`). If FAIL, a phase boundary is missed.

- [ ] **Step 5: Verify AC#6 — dcid_mismatch_pkts == 0 (regression check)**

```bash
for f in bench/quic_perf/results/profile/INSTRUMENTATION-*-subleg.json; do
  echo "=== $f ==="
  python3 -c "
import json
d = json.load(open('$f'))
m = d['addr_key_dcid_mismatch']['dcid_mismatch_pkts']
print(f'dcid_mismatch_pkts={m} {\"PASS\" if m == 0 else \"FAIL\"}')
"
done
```

Expected: both `PASS` (count == 0). If FAIL, the new instrumentation broke the demux invariant — halt.

- [ ] **Step 6: Commit captures**
Use the `commit-smart` skill. Message format: `bench: capture sub-leg sidecars for both cells`.

---

## Task 9: REFERENCE.md entry + flag revert + project-context advance (parent)

**Files:**
- Modify: `bench/quic_perf/results/REFERENCE.md` — append sub-leg-pass entry
- Modify: `src/quic/profile.mojo:16` — revert to `comptime PROFILE_ACCEPT: Bool = False`
- Modify: `docs/project-context.md` — advance phase to `done`

- [ ] **Step 1: Read every existing REFERENCE.md row before drafting (methodology gate)**
Run: `wc -l /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main/bench/quic_perf/results/REFERENCE.md`
Then read the file in full. The new entry MUST NOT contradict any prior row's data.

- [ ] **Step 2: Extract dominant FFI sub-leg + dominant loop phase for short-conn**

```bash
python3 -c "
import json, glob
shortconn = [f for f in glob.glob('bench/quic_perf/results/profile/INSTRUMENTATION-*-postmigration-shortconn-subleg.json')][0]
d = json.load(open(shortconn))
sl = d['ffi_subleg_us']
shim = d['per_pkt_us']['shim_ffi']['total']
busy = d['busy_us_total']
print('=== Short-conn sub-legs ===')
for k, v in sl.items():
    pct = 100 * v['total'] / shim if shim else 0
    print(f'  ffi.{k}: {v[\"total\"]} us ({pct:.1f}% of shim_ffi)')
loops = d['loop_phases_us']
for k in ['pop_dispatch', 'post_pkt', 'teardown']:
    pct = 100 * loops[k]['total'] / busy if busy else 0
    print(f'  loop.{k}: {loops[k][\"total\"]} us ({pct:.1f}% of busy)')
"
```

Identify and record:
- (a) The single FFI sub-leg with the highest share of `shim_ffi_us_total` (read_hs / write_hs / take_keys).
- (b) The single loop phase with the highest share of `busy_us_total` (pop_dispatch / post_pkt / teardown).

- [ ] **Step 3: Append sub-leg-pass entry to REFERENCE.md**

Append a new entry following the existing hypothesis-pass entry format. Required sections:
- Pass name: "QUIC accept-loop sub-leg instrumentation pass"
- Spec: `specs/2026-04-28-quic-accept-loop-subleg-instrumentation.md`
- Plan: `plans/2026-04-28-quic-accept-loop-subleg-instrumentation.md`
- Branch: `feat/quic-accept-loop-subleg-instrumentation`
- Verdict: SHIPPED (diagnostic-only)
- Captures: list the two sidecar JSON paths
- Sub-leg breakdown table (long-conn vs short-conn): each FFI sub-leg's % of shim_ffi + each loop phase's % of busy
- Dominant FFI sub-leg on short-conn: <name>
- Dominant loop phase on short-conn: <name>
- AC verification: AC#1 (+12 tests PASS), AC#2 (off-build drift PASS), AC#3 (on-build drift PASS), AC#4 (sub-leg sum invariant PASS in both cells), AC#5 (unaccounted_pct < 2 PASS in both cells), AC#6 (dcid_mismatch_pkts == 0 PASS in both cells), AC#7 (this entry).
- Cross-validation against prior passes: cite the existing post-migration shortconn capture (`INSTRUMENTATION-20260427-200716-postmigration-shortconn.json`) `shim_ffi: total=9720170` and confirm the new capture is within ±20% of that absolute total (run-to-run noise allowance is wider than the ±1% sub-leg sum invariant).
- Next-step recommendation: spec a follow-on pass that targets the dominant FFI sub-leg + dominant loop phase identified here.

- [ ] **Step 4: Revert PROFILE_ACCEPT to False**

Edit `src/quic/profile.mojo` line 16:
- Old: `comptime PROFILE_ACCEPT: Bool = True`
- New: `comptime PROFILE_ACCEPT: Bool = False`

Verify: `grep -nE 'comptime PROFILE_ACCEPT' /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main/src/quic/profile.mojo` shows `False`.

- [ ] **Step 5: Advance docs/project-context.md**

Update the phase line to `spec-quic-accept-loop-subleg-instrumentation-reviewing`. Update the active specs row's status from `pending` to `done`. Add a session history entry summarising the pass (test count delta, AC verification, dominant FFI sub-leg + dominant loop phase identified, next-step recommendation).

- [ ] **Step 6: Commit final state**
Use the `commit-smart` skill. Message format: `bench: REFERENCE.md sub-leg-pass entry + flag revert + context advance`.

- [ ] **Step 7: Verify final test count**
Run: `bash scripts/run_tests.sh 2>&1 | grep -cE '^PASS:'`
Expected: T0 anchor + 12. AC#1 satisfied.

---

## Pre-save scan

- ✅ Every spec requirement maps to a task: AC#1 (T3 Step 6 verification + T9 Step 7), AC#2 (T6), AC#3 (T7), AC#4 (T8 Step 3), AC#5 (T8 Step 4), AC#6 (T8 Step 5), AC#7 (T9 Steps 2-3).
- ✅ No placeholders; every step has complete code, exact command, expected output.
- ✅ Names + signatures consistent: `record_ffi_read_hs / record_ffi_write_hs / record_ffi_take_keys / record_loop_pop_dispatch / record_loop_post_pkt / record_loop_teardown / record_loop_iter` all use `mut self, us: UInt64` (or no-arg for `record_loop_iter`); JSON keys `ffi_subleg_us / loop_phases_us / unaccounted_us_total / unaccounted_pct / loop_iter_count` consistent across spec, tests, impl.
- ✅ Reconciled test count: T1 (3) + T2 (3, after dropping `test_record_loop_iter_increments_count` per T3 Step 6) + T3 (6) = 12. AC#1 = +12.
