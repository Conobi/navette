# QUIC `addr_key` ↔ DCID collision counter — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cross-confirm the `addr_key` demux collapse hypothesis from the server's POV by adding a PROFILE_ACCEPT-gated counter that records packets where `_find_conn(pd.addr_key)` returns an existing conn whose expected DCID set does not contain `pd.dcid`. Capture both long-conn and short-conn cells, cross-check against the existing wire-level pcap, and emit a hard-verdict REFERENCE.md hypothesis-pass entry that authorises (or rejects) the follow-on demux migration spec.

**Architecture:** Single increment site in `bench/h3_server.mojo` `_flush_impl`'s per-packet loop, gated by `comptime PROFILE_ACCEPT`. Two new fields + one method on `AcceptProfile` (in `src/quic/profile.mojo`); one read-only `is_expected_dcid(Span[UInt8, _]) -> Bool` accessor on `QuicConnection` (in `src/quic/connection.mojo`) that matches both `initial_dcid` (line 300) and `local_cid` (line 298). JSON + text rendering mirror the existing queueing-tail block style. Off-build cost = zero; on-build cost ≤10% drift bound by smoke gate.

**Tech Stack:** Mojo 0.26.2; `Dict[String, UInt64]`; `Span[UInt8, _]`; `comptime PROFILE_ACCEPT: Bool`; existing tquic_client harness via `bench/quic_perf/scripts/{start-server,run-tquic-client,stop-server}.sh` + `docker kill --signal=SIGINT bench-h3`.

---

## File structure

| Path | Action | Single responsibility |
|---|---|---|
| `src/quic/profile.mojo` | Modify | Add 2 fields + 1 method (`record_dcid_mismatch`) on `AcceptProfile`; emit a new `addr_key_dcid_mismatch` JSON block + matching text section. |
| `src/quic/connection.mojo` | Modify | Add 1 read-only method `is_expected_dcid` on `QuicConnection` (byte-equality vs `initial_dcid` and `local_cid`). |
| `bench/h3_server.mojo` | Modify | Add 1 PROFILE_ACCEPT-gated branch in `_flush_impl` per-packet loop after `_find_conn`. |
| `tests/test_quic_profile.mojo` | Modify | 4 new unit tests covering increment, accumulation, JSON, text. Register all in `def main()`. |
| `tests/test_quic_connection.mojo` | Modify | 1 new unit test for `is_expected_dcid` (matches both DCIDs, rejects others). |
| `bench/quic_perf/results/profile/INSTRUMENTATION-<date>-collision-shortconn.json` | Create | Sidecar capture artefact (T8). |
| `bench/quic_perf/results/profile/INSTRUMENTATION-<date>-collision-longconn.json` | Create | Sidecar capture artefact (T7). |
| `bench/quic_perf/results/profile/T5_T6_smoke_gate_<date>.md` | Create | Smoke baseline note (T5/T6). |
| `bench/quic_perf/results/REFERENCE.md` | Modify | Hypothesis-pass entry with verdict, cross-check table, off-build flag re-confirmation (T9). |
| `docs/project-context.md` | Modify | Phase advance through implementing → reviewing (T9). |

---

## Task 0: Hard-gate — branch + Mojo MCP signature locks + off-build smoke baseline

**Files:**
- Verify: `src/quic/profile.mojo:16` reads `comptime PROFILE_ACCEPT: Bool = False`.
- Branch: new branch `feat/quic-addr-key-dcid-collision-counter` off `main` at `bff4c42`.

- [ ] **Step 1: Confirm we're on `main` at the right SHA**
Run: `git -C /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main rev-parse HEAD`
Expected: `bff4c42` exactly.

- [ ] **Step 2: Confirm PROFILE_ACCEPT off-build**
Run: `grep -n 'comptime PROFILE_ACCEPT' /home/donokami/Projets/perso/mojo-net/src/quic/profile.mojo`
Expected: `16:comptime PROFILE_ACCEPT: Bool = False`

If True: ABORT. Set to False and re-run baseline before proceeding (this would invalidate any subsequent smoke baseline).

- [ ] **Step 3: Create branch off main**
Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && git checkout -b feat/quic-addr-key-dcid-collision-counter`
Expected: `Switched to a new branch 'feat/quic-addr-key-dcid-collision-counter'`

- [ ] **Step 4: Mojo MCP probe — `List[UInt8]` byte equality**
Use Mojo MCP `execute` with this source:
```mojo
fn main() raises:
    var a = List[UInt8]()
    a.append(UInt8(1)); a.append(UInt8(2)); a.append(UInt8(3))
    var b = List[UInt8]()
    b.append(UInt8(1)); b.append(UInt8(2)); b.append(UInt8(3))
    var c = List[UInt8]()
    c.append(UInt8(1)); c.append(UInt8(2)); c.append(UInt8(4))
    print("a==b:", a == b, " a==c:", a == c)
```
Expected stdout: `a==b: True  a==c: False`
If `a == b` does not compile: change Step 4 of Task 3 to use a `_dcid_equals(a, b) -> Bool` byte-loop helper inside `is_expected_dcid` (~10 LoC). Document the deviation in T9 REFERENCE.md entry.

- [ ] **Step 5: Mojo MCP probe — `Span[UInt8, _]` on a method receiver**
Use Mojo MCP `execute` with this source:
```mojo
struct Foo(Copyable, Movable):
    var data: List[UInt8]
    fn __init__(out self):
        self.data = List[UInt8]()
        self.data.append(UInt8(7))
    fn check(self, s: Span[UInt8, _]) -> Bool:
        if len(s) != len(self.data):
            return False
        for i in range(len(s)):
            if s[i] != self.data[i]:
                return False
        return True

fn main() raises:
    var f = Foo()
    var x = List[UInt8](); x.append(UInt8(7))
    print("match:", f.check(Span(x)))
    var y = List[UInt8](); y.append(UInt8(8))
    print("no-match:", f.check(Span(y)))
```
Expected stdout: `match: True\nno-match: False`
If signature does not compile: change Task 3 to take `dcid: List[UInt8]` instead of `Span[UInt8, _]`; update Task 4's call site to `Span(pd.dcid)` → `pd.dcid` and reduce one allocation. Document the deviation in T9 REFERENCE.md entry.

- [ ] **Step 6: Capture off-build smoke baseline (3-iter median per cell)**
Use the canonical orchestrator (mirrors the prior queueing-tail T11/T12 smoke gate):
```
cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && \
bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 3
```
Then:
```
bash bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 3
```
Expected: each invocation prints 3 iterations of `=== bench: ... ===` headers and writes a JSON result file under `bench/quic_perf/results/`. Read each iteration's parsed rps via `cat bench/quic_perf/results/<latest>.json` (or whatever path the script reports).

Record the 3-iter rps values + median for both cells in `bench/quic_perf/results/profile/T5_T6_smoke_gate_<YYYY-MM-DD>.md` under heading "Off-build baseline (T0)". This is the reference for the T5/T6 ≤10% drift check. Median is the comparison number; individual iterations help diagnose noise.

**Do NOT use the Monitor tool for these bench runs.** Run them as plain Bash commands (foreground or `run_in_background` with `until grep -q ...`). The bench.sh orchestrator exits when its iters complete — it does not need event streaming.

- [ ] **Step 7: Commit T0 gate result**
Use the `commit-smart` skill. Message format: `chore: T0 gate — branch + Mojo MCP signature locks + off-build smoke baseline`.

---

## Task 1: TDD — `AcceptProfile` fields + `record_dcid_mismatch`

**Files:**
- Modify: `src/quic/profile.mojo` (add 2 fields + 1 method).
- Test: `tests/test_quic_profile.mojo` (add 2 tests).

- [ ] **Step 1: Write failing tests**
Append to `tests/test_quic_profile.mojo` (after the last existing `test_*` definition, before `def main()`):
```mojo
def test_record_dcid_mismatch_increments() raises:
    var p = AcceptProfile()
    p.record_dcid_mismatch(String("ip:port:34130"))
    if p.dcid_mismatch_pkts != UInt64(1):
        raise "expected dcid_mismatch_pkts=1, got " + String(p.dcid_mismatch_pkts)
    if p.addr_key_mismatch_counts[String("ip:port:34130")] != UInt64(1):
        raise "expected per-addr_key count=1"
    print("PASS: test_record_dcid_mismatch_increments")


def test_record_dcid_mismatch_accumulates() raises:
    var p = AcceptProfile()
    p.record_dcid_mismatch(String("ip:port:34130"))
    p.record_dcid_mismatch(String("ip:port:34130"))
    p.record_dcid_mismatch(String("ip:port:34131"))
    if p.dcid_mismatch_pkts != UInt64(3):
        raise "expected total=3, got " + String(p.dcid_mismatch_pkts)
    if p.addr_key_mismatch_counts[String("ip:port:34130")] != UInt64(2):
        raise "expected key1=2"
    if p.addr_key_mismatch_counts[String("ip:port:34131")] != UInt64(1):
        raise "expected key2=1"
    print("PASS: test_record_dcid_mismatch_accumulates")
```

Then in `def main() raises:` (after the last existing test call):
```mojo
    test_record_dcid_mismatch_increments()
    test_record_dcid_mismatch_accumulates()
```

- [ ] **Step 2: Verify it fails**
Run: `cd /home/donokami/Projets/perso/mojo-net && mojo run -I . tests/test_quic_profile.mojo 2>&1 | tail -10`
Expected: FAIL with `'AcceptProfile' value has no attribute 'dcid_mismatch_pkts'` or similar.

- [ ] **Step 3: Add fields + method to `AcceptProfile`**
Edit `src/quic/profile.mojo`. Inside the `struct AcceptProfile` block, locate the existing field declarations (the block that starts with the `WARNING:` doc-comment near line 38). Add these two fields immediately after the existing `conn_hs_complete: Dict[String, Bool]` field:
```mojo
    # Plan: 2026-04-27-quic-addr-key-dcid-collision-counter
    # Total packets where _find_conn(pd.addr_key) returned a hit but
    # pd.dcid was not in the conn's expected-DCID set.  Direct measure
    # of demux failure under PROFILE_ACCEPT.
    var dcid_mismatch_pkts: UInt64

    # Per-addr_key mismatch counts.  Same Dict shape as conn_pkt_counts.
    var addr_key_mismatch_counts: Dict[String, UInt64]
```

In the `__init__` body for `AcceptProfile`, immediately after the existing `self.conn_hs_complete = Dict[String, Bool]()` line, add:
```mojo
        self.dcid_mismatch_pkts = UInt64(0)
        self.addr_key_mismatch_counts = Dict[String, UInt64]()
```

In the explicit copy-init constructor (the one taking `other: Self`), immediately after the existing `self.conn_hs_complete = ...` copy line, add:
```mojo
        self.dcid_mismatch_pkts = other.dcid_mismatch_pkts
        self.addr_key_mismatch_counts = Dict[String, UInt64](copy=other.addr_key_mismatch_counts)
```

In the explicit move-init constructor (the one taking `deinit take: Self`), immediately after the existing `self.conn_hs_complete = take.conn_hs_complete^` line, add:
```mojo
        self.dcid_mismatch_pkts = take.dcid_mismatch_pkts
        self.addr_key_mismatch_counts = take.addr_key_mismatch_counts^
```

Add the method (place it near the other `record_*` methods):
```mojo
    def record_dcid_mismatch(mut self, addr_key: String) raises:
        """Record a packet whose dcid did not match the conn for its addr_key.

        Caller has already done the membership test against
        QuicConnection.is_expected_dcid; this method only counts.
        """
        self.dcid_mismatch_pkts = self.dcid_mismatch_pkts + UInt64(1)
        if addr_key in self.addr_key_mismatch_counts:
            self.addr_key_mismatch_counts[addr_key] = (
                self.addr_key_mismatch_counts[addr_key] + UInt64(1))
        else:
            self.addr_key_mismatch_counts[addr_key] = UInt64(1)
```

- [ ] **Step 4: Verify it passes**
Run: `cd /home/donokami/Projets/perso/mojo-net && mojo run -I . tests/test_quic_profile.mojo 2>&1 | tail -6`
Expected: lines ending with
```
PASS: test_record_dcid_mismatch_increments
PASS: test_record_dcid_mismatch_accumulates
All Plan A tests passed.
```

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message format: `feat: add dcid_mismatch fields + record method to AcceptProfile`.

---

## Task 2: TDD — JSON + text rendering for `addr_key_dcid_mismatch` block

**Files:**
- Modify: `src/quic/profile.mojo` (extend `report_json` and `report_text`).
- Test: `tests/test_quic_profile.mojo` (add 2 tests).

- [ ] **Step 1: Write failing tests**
Append to `tests/test_quic_profile.mojo`:
```mojo
def test_report_json_dcid_mismatch_block() raises:
    var p = AcceptProfile()
    p.record_dcid_mismatch(String("ip:port:34130"))
    p.record_dcid_mismatch(String("ip:port:34130"))
    p.record_dcid_mismatch(String("ip:port:34131"))
    var s = p.report_json(UInt64(0))
    if "addr_key_dcid_mismatch" not in s:
        raise "missing addr_key_dcid_mismatch block"
    if "\"dcid_mismatch_pkts\": 3" not in s:
        raise "missing total counter"
    if "\"addr_keys_with_mismatch\": 2" not in s:
        raise "missing addr_keys_with_mismatch"
    if "ip:port:34130" not in s:
        raise "missing per_addr_key entry"
    print("PASS: test_report_json_dcid_mismatch_block")


def test_report_text_dcid_mismatch_block() raises:
    var p = AcceptProfile()
    p.record_dcid_mismatch(String("ip:port:34130"))
    var s = p.report_text(UInt64(0))
    if "addr_key DCID mismatch" not in s:
        raise "missing text section heading"
    if "1" not in s:
        raise "expected count=1 to appear"
    print("PASS: test_report_text_dcid_mismatch_block")
```

Register both in `def main()`.

- [ ] **Step 2: Verify it fails**
Run: `cd /home/donokami/Projets/perso/mojo-net && mojo run -I . tests/test_quic_profile.mojo 2>&1 | tail -8`
Expected: FAIL with `missing addr_key_dcid_mismatch block` (the field exists but the JSON formatter doesn't emit it yet).

- [ ] **Step 3: Extend `report_json`**
In `src/quic/profile.mojo`, locate the `report_json` method (search for `def report_json`). Find the block that emits the existing `per_conn_pkts` aggregated section. Immediately after the closing `,\n` of that block (before whatever block currently follows it), add:
```mojo
        # addr_key DCID-mismatch block (Plan: 2026-04-27 collision counter).
        var addr_keys_with_mismatch: UInt64 = UInt64(0)
        for entry in self.addr_key_mismatch_counts.items():
            if entry.value > UInt64(0):
                addr_keys_with_mismatch = addr_keys_with_mismatch + UInt64(1)
        out = out + ",\n  \"addr_key_dcid_mismatch\": {\n"
        out = out + "    \"dcid_mismatch_pkts\": " + String(self.dcid_mismatch_pkts) + ",\n"
        out = out + "    \"addr_keys_total\": " + String(len(self.addr_key_mismatch_counts)) + ",\n"
        out = out + "    \"addr_keys_with_mismatch\": " + String(addr_keys_with_mismatch) + ",\n"
        out = out + "    \"per_addr_key\": {"
        var first = True
        for entry in self.addr_key_mismatch_counts.items():
            if not first:
                out = out + ","
            first = False
            out = out + "\n      \"" + entry.key + "\": " + String(entry.value)
        out = out + "\n    }\n  }"
```

(If the `report_json` method's existing structure uses a different concatenation idiom, adapt the indentation/comma placement to match — the queueing-tail block at lines emitting `arrival_lat_us` is the closest precedent.)

- [ ] **Step 4: Extend `report_text`**
In the same file, locate `def report_text`. After the existing per-conn aggregated text section, append:
```mojo
        out = out + "\n-- addr_key DCID mismatch --\n"
        out = out + "  total mismatch pkts:    " + String(self.dcid_mismatch_pkts) + "\n"
        out = out + "  addr_keys total:        " + String(len(self.addr_key_mismatch_counts)) + "\n"
        var addr_keys_with_mismatch_t: UInt64 = UInt64(0)
        for entry in self.addr_key_mismatch_counts.items():
            if entry.value > UInt64(0):
                addr_keys_with_mismatch_t = addr_keys_with_mismatch_t + UInt64(1)
        out = out + "  addr_keys w/ mismatch:  " + String(addr_keys_with_mismatch_t) + "\n"
        for entry in self.addr_key_mismatch_counts.items():
            out = out + "    " + entry.key + ": " + String(entry.value) + "\n"
```

- [ ] **Step 5: Verify it passes**
Run: `cd /home/donokami/Projets/perso/mojo-net && mojo run -I . tests/test_quic_profile.mojo 2>&1 | tail -8`
Expected: lines ending with
```
PASS: test_report_json_dcid_mismatch_block
PASS: test_report_text_dcid_mismatch_block
All Plan A tests passed.
```

- [ ] **Step 6: Commit**
Use the `commit-smart` skill. Message format: `feat: emit addr_key_dcid_mismatch block in report_json + report_text`.

---

## Task 3: TDD — `is_expected_dcid` accessor on `QuicConnection`

**Files:**
- Modify: `src/quic/connection.mojo` (add 1 method).
- Test: `tests/test_quic_connection.mojo` (add 1 test).

- [ ] **Step 1: Find anchor for the new method**
Run: `grep -n 'fn .*is_established\|^\s\+fn \|^\s\+def ' /home/donokami/Projets/perso/mojo-net/src/quic/connection.mojo | head -20`
Expected: a list of method declarations within the `QuicConnection` struct. Pick the line immediately after `is_established`'s closing — this is where the new method goes. Record the line number for Step 3.

- [ ] **Step 2: Write failing test**
Append to `tests/test_quic_connection.mojo` a new test function. (If the existing file structure uses a `test_*` function pattern with registration in `def main()`, follow it. Otherwise add to the most analogous existing fixture.)
```mojo
def test_is_expected_dcid_initial_and_local() raises:
    # Build a minimal QuicConnection-like fixture by reaching for an existing
    # construction helper.  If the project's existing test_quic_connection.mojo
    # uses a `_make_server_conn(client_dcid: List[UInt8])` helper, reuse it.
    # Otherwise call QuicConnection.server(...) with a fixed client_dcid.
    var client_dcid = List[UInt8]()
    for b in InlineArray[UInt8, 8](fill=UInt8(0xAB)):
        client_dcid.append(b)
    var conn = _make_server_conn(client_dcid)
    # Expected DCID #1: the conn's own initial_dcid (== client_dcid here)
    if not conn.is_expected_dcid(Span(client_dcid)):
        raise "is_expected_dcid should match initial_dcid"
    # Expected DCID #2: the conn's local_cid (server-chosen SCID)
    var local = List[UInt8](copy=conn.local_cid)
    if not conn.is_expected_dcid(Span(local)):
        raise "is_expected_dcid should match local_cid"
    # NOT expected: an arbitrary third DCID
    var other = List[UInt8]()
    for b in InlineArray[UInt8, 8](fill=UInt8(0xCD)):
        other.append(b)
    if conn.is_expected_dcid(Span(other)):
        raise "is_expected_dcid should reject unrelated DCIDs"
    print("PASS: test_is_expected_dcid_initial_and_local")
```

If `_make_server_conn` does not exist in the test file, replace its call with the same `QuicConnection.server(...)` invocation pattern used by the nearest existing test function in the same file, passing `client_dcid` for both `orig_dcid` and `client_dcid` parameters (as the existing handshake tests do). The exact arguments are determined by reading 5-10 lines around the closest existing `QuicConnection.server` test call.

- [ ] **Step 3: Verify it fails**
Run: `cd /home/donokami/Projets/perso/mojo-net && mojo run -I . tests/test_quic_connection.mojo 2>&1 | tail -10`
Expected: FAIL with `'QuicConnection' has no method 'is_expected_dcid'` or similar.

- [ ] **Step 4: Add the accessor to `QuicConnection`**
In `src/quic/connection.mojo`, immediately after the closing brace of `is_established` (line determined in Step 1), insert:
```mojo
    fn is_expected_dcid(self, dcid: Span[UInt8, _]) -> Bool:
        """True if `dcid` matches either initial_dcid or local_cid.

        - `initial_dcid` is the client's random Initial DCID, used for
          Initial-key derivation. Valid pre-handshake and during the brief
          post-handshake transition before the client switches over.
        - `local_cid` is the server's chosen SCID (or, on a client conn,
          the locally-chosen SCID). The peer uses it as DCID after the
          first server Initial.

        Connection migration is a project non-goal in v1 of M3 (project
        non-goal line 28). Once NEW_CONNECTION_ID emission lands, expand
        this accessor to a set membership over all active local CIDs.
        """
        if len(dcid) == len(self.initial_dcid):
            var match_initial = True
            for i in range(len(dcid)):
                if dcid[i] != self.initial_dcid[i]:
                    match_initial = False
                    break
            if match_initial:
                return True
        if len(dcid) == len(self.local_cid):
            var match_local = True
            for i in range(len(dcid)):
                if dcid[i] != self.local_cid[i]:
                    match_local = False
                    break
            if match_local:
                return True
        return False
```

(Byte-loop comparison rather than `==` on `List[UInt8]` to avoid the T0 Step 4 fallback case if equality didn't compile cleanly. Two short loops, one per candidate DCID. Cost: O(2 × 8) = ~16 byte comparisons per packet, behind PROFILE_ACCEPT.)

- [ ] **Step 5: Verify it passes**
Run: `cd /home/donokami/Projets/perso/mojo-net && mojo run -I . tests/test_quic_connection.mojo 2>&1 | tail -6`
Expected:
```
PASS: test_is_expected_dcid_initial_and_local
... (other existing tests pass)
```

- [ ] **Step 6: Run conformance suite**
Run: `cd /home/donokami/Projets/perso/mojo-net && bash scripts/run_tests.sh 2>&1 | tail -8`
Expected: existing src + conformance counts unchanged (e.g. `36/36 conformance tests passed`).

- [ ] **Step 7: Commit**
Use the `commit-smart` skill. Message format: `feat: add is_expected_dcid accessor to QuicConnection`.

---

## Task 4: Wire the increment site in `bench/h3_server.mojo` `_flush_impl`

**Files:**
- Modify: `bench/h3_server.mojo` (one PROFILE_ACCEPT-gated branch in `_flush_impl`).

- [ ] **Step 1: Locate the insertion line**
Run: `grep -n 'var conn_idx = self._find_conn(pd.addr_key)' /home/donokami/Projets/perso/mojo-net/bench/h3_server.mojo`
Expected: line 689 (approximate; verify the exact line on the working tree).

- [ ] **Step 2: Add the gated branch**
Edit `bench/h3_server.mojo`. Immediately AFTER the line found in Step 1 (so before the `if conn_idx < 0:` check that follows), insert:
```mojo
            @parameter
            if PROFILE_ACCEPT:
                if conn_idx >= 0:
                    if not conn_h3s[conn_idx][]._h3._quic.is_expected_dcid(Span(pd.dcid)):
                        try:
                            self.profile.record_dcid_mismatch(pd.addr_key)
                        except:
                            pass
```

(Indentation matches the surrounding `for i in range(len(self.pending_rx)):` loop body, which uses 12 spaces. The two prior PROFILE_ACCEPT blocks at the top of the same loop are the canonical example.)

- [ ] **Step 3: Verify off-build still compiles cleanly**
Run: `cd /home/donokami/Projets/perso/mojo-net && mojo build bench/h3_server.mojo 2>&1 | tail -10`
Expected: builds without errors. Off-build skips the new branch entirely.

- [ ] **Step 4: Verify on-build compiles cleanly**
Temporarily flip `src/quic/profile.mojo:16` to `comptime PROFILE_ACCEPT: Bool = True`. Then run:
`cd /home/donokami/Projets/perso/mojo-net && mojo build bench/h3_server.mojo 2>&1 | tail -10`
Expected: builds without errors. Revert the flag back to `False` BEFORE committing this task.

- [ ] **Step 5: Run conformance suite**
Run: `cd /home/donokami/Projets/perso/mojo-net && bash scripts/run_tests.sh 2>&1 | tail -8`
Expected: counts unchanged from Task 3 Step 6.

- [ ] **Step 6: Commit**
Use the `commit-smart` skill. Message format: `feat: wire dcid-mismatch counter in _flush_impl`.

---

## Task 5: Smoke gate — long-conn cell

**Files:**
- Modify: `src/quic/profile.mojo:16` flipped to `True` for the duration of T5+T6+T7+T8; reverted before T9.
- Create: `bench/quic_perf/results/profile/T5_T6_smoke_gate_<date>.md` (continuation from T0 baseline).

- [ ] **Step 1: Flip PROFILE_ACCEPT on**
Edit `src/quic/profile.mojo:16` to `comptime PROFILE_ACCEPT: Bool = True`.

- [ ] **Step 2: Build on-build artefact**
Run: `cd /home/donokami/Projets/perso/mojo-net && mojo build bench/h3_server.mojo -o bench/h3_server 2>&1 | tail -5`
Expected: build succeeds; `bench/h3_server` artefact updated.

- [ ] **Step 3: Run long-conn cell on-build (3 iterations, take median)**
Run: `cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 3`
Expected: 3 iterations complete, JSON result written. Read the on-build long-conn median rps from the result file (path printed by bench.sh).

- [ ] **Step 4: Compute drift**
`drift_pct = (on_build_rps - off_build_rps) / off_build_rps * 100`. Use the off-build long-conn rps recorded at T0 Step 6.

- [ ] **Step 5: Verdict gate**
- Drift in `[-10%, +10%]` → PASS. Append the numbers + drift% to `bench/quic_perf/results/profile/T5_T6_smoke_gate_<date>.md` under heading "Long-conn smoke (T5)" and proceed to T6.
- Drift outside that band → FAIL. Stop the plan; investigate the per-packet branch cost (likely candidate: the byte-loop in `is_expected_dcid` running O(64)/packet at PROFILE_ACCEPT=True). Do not commit captures from a failed smoke gate.

- [ ] **Step 6: Commit (only if PASS)**
Use the `commit-smart` skill. Message format: `bench: T5 long-conn smoke gate <DRIFT_PCT>%`.

---

## Task 6: Smoke gate — short-conn cell

**Files:**
- Modify: `bench/quic_perf/results/profile/T5_T6_smoke_gate_<date>.md` (append).

- [ ] **Step 1: Run short-conn cell on-build (3 iterations, take median)**
PROFILE_ACCEPT is still True from T5. Run:
`cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main && bash bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 3`
Expected: 3 iterations complete, JSON result written. Read the on-build short-conn median rps.

- [ ] **Step 2: Compute drift**
Same formula as T5, against T0's off-build short-conn rps.

- [ ] **Step 3: Verdict gate**
- Drift in `[-10%, +10%]` OR within ±0.5 rps absolute (short-conn floor is ~1 rps; relative drift is meaningless near the floor) → PASS. Append numbers + drift% under heading "Short-conn smoke (T6)".
- Drift outside that band AND outside the noise floor → FAIL. Stop the plan, same investigation as T5.

- [ ] **Step 4: Commit (only if PASS)**
Use the `commit-smart` skill. Message format: `bench: T6 short-conn smoke gate <DRIFT_PCT>% (or noise-bounded)`.

---

## Task 7: SIGINT capture — long-conn cell (30s, on-build)

**Files:**
- Create: `bench/quic_perf/results/profile/INSTRUMENTATION-<date>-collision-longconn.json`.

- [ ] **Step 1: Confirm on-build**
PROFILE_ACCEPT is still True from T5. Confirm: `grep 'comptime PROFILE_ACCEPT' /home/donokami/Projets/perso/mojo-net/src/quic/profile.mojo`
Expected: `comptime PROFILE_ACCEPT: Bool = True`.

- [ ] **Step 2: Start server + run client + SIGINT-flush**
Run:
```
cd /home/donokami/Projets/perso/mojo-net && \
bash bench/quic_perf/scripts/start-server.sh && \
sleep 2 && \
bash bench/quic_perf/scripts/run-tquic-client.sh long-conn 30 && \
docker kill --signal=SIGINT bench-h3 && \
sleep 2 && \
docker cp bench-h3:/tmp/profile.json bench/quic_perf/results/profile/INSTRUMENTATION-$(date +%Y%m%d-%H%M%S)-collision-longconn.json && \
bash bench/quic_perf/scripts/stop-server.sh
```
(Adjust the `docker cp` source path to whatever path the bench server's SIGINT handler writes to — confirm via `grep -n 'profile.json\|report_json\|SIGINT' bench/h3_server.mojo` if unsure.)

- [ ] **Step 3: Verify the sidecar JSON contains the new block**
Run: `python3 -c 'import json; d=json.load(open("bench/quic_perf/results/profile/$(ls bench/quic_perf/results/profile/ | grep collision-longconn | tail -1)")); print(json.dumps(d["addr_key_dcid_mismatch"], indent=2))'`
(Use the actual filename from the prior step.)
Expected: `dcid_mismatch_pkts < max(10, 1% of total pkts)` per spec FALSIFIED-band-for-long-conn definition. If not, flag for analysis but DO NOT abort — long-conn high mismatch is itself a signal worth recording.

- [ ] **Step 4: Commit the sidecar**
Use the `commit-smart` skill. Message format: `bench: capture long-conn DCID-mismatch sidecar (T7)`.

---

## Task 8: SIGINT capture — short-conn cell (30s, on-build)

**Files:**
- Create: `bench/quic_perf/results/profile/INSTRUMENTATION-<date>-collision-shortconn.json`.

- [ ] **Step 1: Start server + run client + SIGINT-flush (short-conn shape)**
Run the same sequence as T7 Step 2 but with `run-tquic-client.sh short-conn 30` and the output filename `INSTRUMENTATION-$(date +%Y%m%d-%H%M%S)-collision-shortconn.json`.

- [ ] **Step 2: Verify the sidecar JSON has the new block**
Same `python3 -c` invocation as T7 Step 3 but on the short-conn file. Expected per spec CONFIRMED-band: `dcid_mismatch_pkts ≥ 200` AND `addr_keys_with_mismatch ≥ 2`.

- [ ] **Step 3: Commit the sidecar**
Use the `commit-smart` skill. Message format: `bench: capture short-conn DCID-mismatch sidecar (T8)`.

---

## Task 9: Cross-check + REFERENCE.md hypothesis-pass entry + project-context advance

**Files:**
- Revert: `src/quic/profile.mojo:16` to `comptime PROFILE_ACCEPT: Bool = False`.
- Modify: `bench/quic_perf/results/REFERENCE.md`.
- Modify: `docs/project-context.md`.

- [ ] **Step 1: Re-read every existing REFERENCE.md row**
Run: `wc -l /home/donokami/Projets/perso/mojo-net/bench/quic_perf/results/REFERENCE.md`
Read the entire file (chunked Read calls if needed — this is the methodology gate codified in the queueing-tail Plan-C retrospective). Note any row that contradicts the current capture. Flag contradictions in the new entry; do not silently ignore.

- [ ] **Step 2: Build the cross-check table**
Pcap (already on disk: `bench/quic_perf/results/profile/wire-capture-20260427-shortconn.pcap`) per-port counts: 93, 95, 95, 96. Server-side per-addr-key counts: extract from the short-conn sidecar's `addr_key_dcid_mismatch.per_addr_key` map. Each pair must be within ±25% (the IMPORTANT 5 band documented in spec).

| addr_key | server count | matched pcap port | pcap distinct DCIDs | within ±25%? |
|---|---|---|---|---|

- [ ] **Step 3: Determine verdict**
Apply spec's hard thresholds:
- Short-conn `dcid_mismatch_pkts ≥ 200` AND `addr_keys_with_mismatch ≥ 2` AND long-conn `dcid_mismatch_pkts < max(10, 1%)` → **CONFIRMED**.
- Short-conn `dcid_mismatch_pkts < max(10, 1%)` → **FALSIFIED**.
- Anything else → **INCONCLUSIVE**.

- [ ] **Step 4: Revert PROFILE_ACCEPT to off-build**
Edit `src/quic/profile.mojo:16` back to `comptime PROFILE_ACCEPT: Bool = False`.
Re-confirm: `grep 'comptime PROFILE_ACCEPT' /home/donokami/Projets/perso/mojo-net/src/quic/profile.mojo`
Expected: `16:comptime PROFILE_ACCEPT: Bool = False`.

- [ ] **Step 5: Append REFERENCE.md hypothesis-pass entry**
Append to `bench/quic_perf/results/REFERENCE.md` (under the existing 2026-04-27 queueing-tail entry):
```markdown
### 2026-04-27 — addr-key-dcid-collision-counter — DATA — <VERDICT>

**Spec:** `specs/2026-04-27-quic-addr-key-dcid-collision-counter.md`. Plan: `plans/2026-04-27-quic-addr-key-dcid-collision-counter.md`. Goal: cross-confirm the addr_key demux collapse from the server's POV before specing the migration.

**Methodology gate satisfied:** re-read all <N> lines of REFERENCE.md. Contradictions: <none / list>.

**Capture:** 30s short-conn + 30s long-conn, tquic_client (4 threads × 25 max-concurrent-conns), on-build (PROFILE_ACCEPT=True), SIGINT-driven sidecars. Smoke gate (T5/T6) PASS at <long_drift>% / <short_drift>% drift.

**SHORT-CONN SIDECAR (`INSTRUMENTATION-<date>-collision-shortconn.json`):**
- `dcid_mismatch_pkts`: <N>
- `addr_keys_total`: <N>
- `addr_keys_with_mismatch`: <N>
- `per_addr_key`: <map>

**LONG-CONN SIDECAR (`INSTRUMENTATION-<date>-collision-longconn.json`):**
- `dcid_mismatch_pkts`: <N>
- `addr_keys_total`: <N>
- `addr_keys_with_mismatch`: <N>

**Cross-check vs. wire-capture-20260427-shortconn.pcap:**
| addr_key | server count | pcap port | pcap DCIDs | within ±25%? |
|---|---|---|---|---|
| ... | ... | ... | ... | ... |

**`is_expected_dcid` semantics note:** The accessor matches both `initial_dcid` (client's random Initial DCID) AND `local_cid` (server's chosen SCID). During the brief post-handshake DCID transition window, both are accepted as expected, so transient non-match packets are NOT counted as collisions. Stale-conn-replacement bias documented in spec §Architecture is folded into the cross-check tolerance.

**Verdict: <CONFIRMED | FALSIFIED | INCONCLUSIVE>.**

<For CONFIRMED:> Authorises the follow-on `addr_key→DCID demux migration` spec. Estimated migration scope ~50-100 LoC in `bench/h3_server.mojo` (REFERENCE.md row 386-388).

<For FALSIFIED:> The pcap-implied mechanism does not show up in server-side counters. Investigate wire-vs-server divergence — possibly _find_conn races, swap-and-pop timing, or different mechanism entirely. Brainstorm restart.

<For INCONCLUSIVE:> Run `h2load --h3` capture next; if still INCONCLUSIVE, instrument further (per-packet DCID-vs-conn tag and serial dump).

**Off-build flag confirmed False (post-capture).**

**Test deviations from plan (if any):** <document any T0-Step-4/5 fallback (List equality / Span signature) used during implementation>.
```

- [ ] **Step 6: Update `docs/project-context.md`**
Update phase line to `**Current phase:** spec-quic-addr-key-dcid-collision-counter-reviewing.` Update the spec entry in the "Active specs and plans" table from `pending` to `done` with a one-line summary including the verdict. Append a session-history entry summarising this implementation pass.

- [ ] **Step 7: Run full conformance suite**
Run: `cd /home/donokami/Projets/perso/mojo-net && bash scripts/run_tests.sh 2>&1 | tail -8`
Expected: same counts as T3 Step 6.

- [ ] **Step 8: Commit T9**
Use the `commit-smart` skill. Message format: `docs: REFERENCE.md DCID-mismatch entry — <VERDICT>`.

---

## Pre-save scan (executed by writer, no checkbox)

- ✅ Every spec requirement maps to a task:
  - `record_dcid_mismatch` + 2 fields → T1
  - JSON + text rendering → T2
  - `is_expected_dcid` accessor → T3
  - `_flush_impl` increment site → T4
  - Smoke gate (long + short) → T5/T6
  - Two SIGINT captures → T7/T8
  - REFERENCE.md hypothesis-pass entry + verdict + cross-check + off-build re-confirm → T9
  - Mojo MCP signature locks → T0
- ✅ No forbidden placeholders. Every step has complete code, exact commands, expected output.
- ✅ Names and signatures consistent: `dcid_mismatch_pkts: UInt64`, `addr_key_mismatch_counts: Dict[String, UInt64]`, `record_dcid_mismatch(mut self, addr_key: String) raises`, `is_expected_dcid(self, dcid: Span[UInt8, _]) -> Bool` — same across T1, T2, T3, T4, T9.
