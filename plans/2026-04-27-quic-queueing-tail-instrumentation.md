# QUIC Queueing-Tail Instrumentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Instrument the bench QUIC server to expose per-packet arrival-to-processing queueing latency (24-bucket histogram) and per-connection packet trajectory (aggregated histogram + scalar + top-50 worst-offenders), all `PROFILE_ACCEPT`-gated, so the next short-conn capture can confirm or falsify the queueing-tail hypothesis on the calibrated 412/1 rps cold-start floor.

**Architecture:** Two new instruments live entirely in `bench/`-side code (`AcceptProfile` in `src/quic/profile.mojo` plus `bench/h3_server.mojo` insertion sites). No `src/quic/connection.mojo` changes — handshake-complete is detected at flush time by polling the pre-existing `conn_h3s[i][]._h3.is_established()` accessor. Comptime `PROFILE_ACCEPT: Bool` gates every measurement path; off-build code is byte-for-byte unchanged from pre-spec main.

**Tech Stack:** Mojo 0.26.2 (Docker-pinned bench), `Dict[String, UInt64]` / `Dict[String, Bool]`, existing 24-bucket power-of-2 histogram via `_per_pkt_bucket`, existing 8-bucket fan-out histogram via `_pkts_per_flush_bucket`, `external_call["clock_gettime", ...]` via the already-installed `monotonic_us()`.

---

## Plan A's actual signatures (from `src/quic/profile.mojo` HEAD `fefe435`)

Verbatim — verifying spec pseudocode against integrated code:

```mojo
struct AcceptProfile(Copyable, Movable):
    var run_start_us: UInt64
    var idle_us_total: UInt64
    var busy_us_total: UInt64
    var on_flush_count: UInt64
    var pkts_per_flush_buckets: List[UInt64]   # len = 8
    var ffi_shim_us_total: UInt64
    var hp_us_total: UInt64
    var aead_us_total: UInt64
    var header_parse_us_total: UInt64
    var frame_parse_us_total: UInt64
    var sm_us_total: UInt64
    var drain_us_total: UInt64
    var residual_us_total: UInt64
    var pkt_count: UInt64
    var per_pkt_total_buckets: List[UInt64]    # len = 24
    var per_pkt_total_overflow: UInt64
    var hs_arrivals: UInt64
    var hs_completed: UInt64
    var hs_timed_out: UInt64
    var hs_latency_us: List[UInt64]

    def __init__(out self): ...
    def record_idle(mut self, idle_us: UInt64): ...
    def record_drain(mut self, drain_us: UInt64): ...
    def record_flush(mut self, pkts: Int, busy_us: UInt64): ...
    def record_pkt(mut self, *, total_us, ffi_us, hp_us, aead_us, header_parse_us, frame_parse_us, sm_us): ...
    def record_handshake_arrival(mut self): ...
    def record_handshake_complete(mut self, latency_us: UInt64): ...
    def record_handshake_timeout(mut self, count: UInt64 = UInt64(1)): ...
    def report_text(self) -> String: ...
    def report_json(self) -> String: ...

fn _pkts_per_flush_bucket(pkts: Int) -> Int  # 0..7
fn _per_pkt_bucket(us: UInt64) -> Int        # 0..23 closed; 24 = overflow
fn _exact_percentile(values: List[UInt64], p: Float64) -> UInt64
fn _bucket_percentile(buckets: List[UInt64], total: UInt64, p: Float64) -> UInt64
fn _fmt_count(n: UInt64) -> String
fn _fmt_pct(part: UInt64, whole: UInt64) -> String
fn _fmt_duration_us(us: UInt64) -> String
fn _fmt_leg(label: String, total: UInt64, count: UInt64) -> String
fn _json_leg(name: String, total: UInt64, count: UInt64) -> String
```

## bench/h3_server.mojo line-number map (HEAD `fefe435`)

- `PendingDatagram` struct definition: line **254**
  - 3 init paths to update: positional `__init__` (line 264), copy `__init__(other=...)` (line 276), move `__init__(deinit take=...)` (line 286)
- `_handle_recvmsg` definition: line **560**
  - `pending_rx.append(...)` site: line **625**
- `_flush_impl` definition: line **646**
  - `now = monotonic_us()` at flush start: line **656**
  - Per-packet loop: line **658**
  - `feed_datagram_from_buffer` call: line **726**
  - Drain block: lines **738-750**
  - SIGINT-flush block at bottom: lines **763-784**
- `is_established()` accessor pattern: `conn_h3s[i][]._h3.is_established()` (existing call at line 769 in SIGINT-flush block; line 854 in `_handle_timeout`)

## File structure

| Path | Action | Single responsibility |
|---|---|---|
| `src/quic/profile.mojo` | modify | Add 5 fields (3 arrival-lat scalars/list + 2 dicts), 3 record methods, 3 JSON blocks, 3 text blocks, 1 inline top-50 sort in `report_json`/`report_text` |
| `bench/h3_server.mojo` | modify | Add `arrival_us: UInt64` field to `PendingDatagram` (3 init paths), 1 `@parameter if PROFILE_ACCEPT` arrival-stamp site, 3 `@parameter if PROFILE_ACCEPT` record-method call sites in `_flush_impl` |
| `tests/test_quic_profile.mojo` | modify | Append 7 new test functions; register them in `main()` |
| `bench/quic_perf/results/REFERENCE.md` | append | After capture: 5th hypothesis-pass log entry interpreting the new sidecar fields |

No new files are created.

---

## Task 0: Pre-flight branch verification (HARD GATE)

**Files:** none (verification only)

- [ ] **Step 1: Verify main HEAD includes `feat/quic-accept-loop-instrumentation`**

Run:
```bash
git rev-parse HEAD
git log --oneline -5
git branch --show-current
```

Expected: current branch is `main` (or a fresh feature branch off main); `git log` shows the FF-merged commits from `feat/quic-accept-loop-instrumentation` (Plan B B1-B14 + Plan C C1-C7 + diagnostic counters commit `8c5325e` + correction commit `fefe435`).

If `main` does NOT contain `fefe435`: **ABORT** the plan and ask the user to FF-merge per the spec's "Dependencies / preconditions" section. The planner does not own this step.

- [ ] **Step 2: Confirm tests pass at the integrated baseline**

Run:
```bash
bash scripts/run_tests.sh 2>&1 | tail -20
```

Expected: same baseline as documented in Plan C retro — 33 loopback + `test_quic_profile` (17 tests) + `test_quic_profile_wiring` all PASS; `test_tls_connection` fails with `rlsm_client_config_new_insecure` symbol not found (pre-existing, out-of-scope).

If unexpected failures appear: **ABORT** and surface to the user before proceeding.

- [ ] **Step 3: Create the implementation branch**

Run:
```bash
git checkout -b feat/quic-queueing-tail-instrumentation
git rev-parse HEAD
```

Expected: branched off main HEAD. No commit yet.

---

## Task 1: AcceptProfile arrival-latency fields + `record_arrival_lat`

**Files:**
- Modify: `src/quic/profile.mojo:35-71` (add 3 fields after `hs_latency_us`), `src/quic/profile.mojo:73-97` (extend `__init__`), `src/quic/profile.mojo:149` (insert new method after `record_handshake_timeout`)
- Test: `tests/test_quic_profile.mojo` (append at end before `def main`)

- [ ] **Step 1: Write failing test**

Append to `tests/test_quic_profile.mojo` BEFORE the `def main() raises:` line:

```mojo
def test_record_arrival_lat_buckets() raises:
    """Verify record_arrival_lat dispatches into 24-bucket histogram and accumulates total."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Cover several bucket boundaries (mirrors _per_pkt_bucket: bucket[0]={0}; bucket[i]=[2^(i-1), 2^i)).
    p.record_arrival_lat(UInt64(0))           # bucket 0
    p.record_arrival_lat(UInt64(1))           # bucket 1
    p.record_arrival_lat(UInt64(3))           # bucket 2
    p.record_arrival_lat(UInt64(100))         # bucket 7 ([64, 128))
    p.record_arrival_lat(UInt64(1_000_000))   # bucket 20 ([524288, 1048576))
    assert_true(p.arrival_lat_us_buckets[0] == UInt64(1), "bucket 0 = 1")
    assert_true(p.arrival_lat_us_buckets[1] == UInt64(1), "bucket 1 = 1")
    assert_true(p.arrival_lat_us_buckets[2] == UInt64(1), "bucket 2 = 1")
    assert_true(p.arrival_lat_us_buckets[7] == UInt64(1), "bucket 7 = 1")
    assert_true(p.arrival_lat_us_buckets[20] == UInt64(1), "bucket 20 = 1")
    assert_true(p.arrival_lat_us_total == UInt64(0 + 1 + 3 + 100 + 1_000_000), "total summed")
    assert_true(p.arrival_lat_us_overflow == UInt64(0), "no overflow")
    print("PASS: test_record_arrival_lat_buckets")


def test_record_arrival_lat_overflow() raises:
    """Verify values >= 2^23 us land in arrival_lat_us_overflow."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_arrival_lat(UInt64(8_388_608))   # 2^23 — overflow boundary
    p.record_arrival_lat(UInt64(10_000_000))  # > 2^23 — overflow
    assert_true(p.arrival_lat_us_overflow == UInt64(2), "overflow = 2")
    assert_true(p.arrival_lat_us_total == UInt64(8_388_608 + 10_000_000), "overflow values still summed in total")
    var sum_buckets: UInt64 = UInt64(0)
    for i in range(24):
        sum_buckets += p.arrival_lat_us_buckets[i]
    assert_true(sum_buckets == UInt64(0), "no closed bucket entries")
    print("PASS: test_record_arrival_lat_overflow")
```

In `def main() raises:` register both new tests after the existing list (insert before `print("PASS: test_quic_profile")` or wherever the final `print` is — match existing pattern):

```mojo
    test_record_arrival_lat_buckets()
    test_record_arrival_lat_overflow()
```

- [ ] **Step 2: Verify it fails**

Run:
```bash
mojo run tests/test_quic_profile.mojo 2>&1 | tail -5
```

Expected: FAIL — `error: 'AcceptProfile' has no member 'record_arrival_lat'` (or similar — symbol not yet defined).

- [ ] **Step 3: Add fields and method**

In `src/quic/profile.mojo`, after the `var hs_latency_us: List[UInt64]` line (~line 71), add:

```mojo
    # Arrival-to-processing queueing latency (Plan: queueing-tail spec).
    # Wall-clock interval between packet ingress (_handle_recvmsg) and
    # flush-time processing (_flush_impl). Distinct from per_pkt_total
    # which times the *processing*, not the wait. PROFILE_ACCEPT-gated
    # at every measurement site in bench/h3_server.mojo.
    var arrival_lat_us_buckets: List[UInt64]   # len = 24, same layout as per_pkt_total_buckets
    var arrival_lat_us_overflow: UInt64
    var arrival_lat_us_total: UInt64
```

In `__init__` (~line 97), after `self.hs_latency_us = List[UInt64]()`, add:

```mojo
        self.arrival_lat_us_buckets = List[UInt64]()
        for _ in range(24):
            self.arrival_lat_us_buckets.append(UInt64(0))
        self.arrival_lat_us_overflow = UInt64(0)
        self.arrival_lat_us_total = UInt64(0)
```

After `def record_handshake_timeout(...)` (~line 150), add:

```mojo
    def record_arrival_lat(mut self, us: UInt64):
        """Record per-packet queueing latency (arrival → processing dispatch).

        Dispatches into 24-bucket power-of-2 histogram via _per_pkt_bucket.
        Values >= 2^23 us go to arrival_lat_us_overflow; total sum always
        accumulated regardless of bucket vs overflow.
        """
        self.arrival_lat_us_total += us
        var b = _per_pkt_bucket(us)
        if b >= 24:
            self.arrival_lat_us_overflow += UInt64(1)
        else:
            self.arrival_lat_us_buckets[b] += UInt64(1)
```

- [ ] **Step 4: Verify it passes**

Run:
```bash
mojo run tests/test_quic_profile.mojo 2>&1 | tail -10
```

Expected: PASS — both new tests print `PASS:` lines; all existing 17 tests still pass.

- [ ] **Step 5: Commit**

Use the `commit-smart` skill. Message format: `feat: add arrival-latency histogram to AcceptProfile`.

---

## Task 2: AcceptProfile per-conn fields + `record_conn_pkt` + `record_conn_hs_complete`

**Files:**
- Modify: `src/quic/profile.mojo` (add 2 Dict fields + extend `__init__` + 2 new methods after `record_arrival_lat`)
- Test: `tests/test_quic_profile.mojo` (append before `def main`)

- [ ] **Step 1: Write failing tests**

Append to `tests/test_quic_profile.mojo` before `def main`:

```mojo
def test_record_conn_pkt_increment() raises:
    """Verify record_conn_pkt increments addr_key counter."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_conn_pkt(String("1.2.3.4:5000"))
    p.record_conn_pkt(String("1.2.3.4:5000"))
    p.record_conn_pkt(String("1.2.3.4:5000"))
    p.record_conn_pkt(String("9.9.9.9:6000"))
    assert_true(p.conn_pkt_counts[String("1.2.3.4:5000")] == UInt64(3), "addr1 = 3")
    assert_true(p.conn_pkt_counts[String("9.9.9.9:6000")] == UInt64(1), "addr2 = 1")
    assert_true(len(p.conn_pkt_counts) == 2, "two distinct keys")
    print("PASS: test_record_conn_pkt_increment")


def test_record_conn_hs_complete_idempotent() raises:
    """Verify record_conn_hs_complete dedupes and the no-complete scalar excludes it."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Conn A: 5 packets, completes handshake.
    for _ in range(5):
        p.record_conn_pkt(String("A:1"))
    p.record_conn_hs_complete(String("A:1"))
    p.record_conn_hs_complete(String("A:1"))   # idempotent
    p.record_conn_hs_complete(String("A:1"))
    # Conn B: 3 packets, never completes.
    for _ in range(3):
        p.record_conn_pkt(String("B:2"))
    # Conn C: 1 packet, never completes.
    p.record_conn_pkt(String("C:3"))
    assert_true(len(p.conn_hs_complete) == 1, "only A:1 in hs_complete")
    assert_true(p.conn_hs_complete[String("A:1")] == True, "A:1 marked True")
    # Compute scalar manually for now — formal API in Task 4.
    var no_hs: UInt64 = UInt64(0)
    for entry in p.conn_pkt_counts.items():
        if entry.key not in p.conn_hs_complete:
            no_hs += UInt64(1)
    assert_true(no_hs == UInt64(2), "B and C are no-hs-complete")
    print("PASS: test_record_conn_hs_complete_idempotent")
```

Register in `main`:

```mojo
    test_record_conn_pkt_increment()
    test_record_conn_hs_complete_idempotent()
```

- [ ] **Step 2: Verify it fails**

Run:
```bash
mojo run tests/test_quic_profile.mojo 2>&1 | tail -5
```

Expected: FAIL — `error: 'AcceptProfile' has no member 'record_conn_pkt'`.

- [ ] **Step 3: Add fields and methods**

At the top of `src/quic/profile.mojo`, ensure `Dict` is imported (check; if not, add `from collections import Dict`):

```bash
grep "from collections" src/quic/profile.mojo
```

If `Dict` is not imported, add at the top after the existing imports:

```mojo
from collections import Dict
```

In the struct (after the arrival-latency fields added in Task 1), add:

```mojo
    # Per-connection packet counts and handshake-complete tracking.
    # `conn_pkt_counts` maps addr_key (src_ip:src_port String) → packet count.
    # `conn_hs_complete` is used as a Set: presence == hs_complete observed.
    # Aggregated histogram + scalar derived at report time.
    var conn_pkt_counts: Dict[String, UInt64]
    var conn_hs_complete: Dict[String, Bool]
```

In `__init__`, after the arrival-latency init block:

```mojo
        self.conn_pkt_counts = Dict[String, UInt64]()
        self.conn_hs_complete = Dict[String, Bool]()
```

After `record_arrival_lat`, add:

```mojo
    def record_conn_pkt(mut self, addr_key: String):
        """Increment per-connection packet counter for `addr_key`."""
        if addr_key in self.conn_pkt_counts:
            self.conn_pkt_counts[addr_key] = self.conn_pkt_counts[addr_key] + UInt64(1)
        else:
            self.conn_pkt_counts[addr_key] = UInt64(1)

    def record_conn_hs_complete(mut self, addr_key: String):
        """Mark addr_key as having completed the QUIC handshake.

        Idempotent: redundant calls (per-packet polling of is_established())
        result in only one entry in conn_hs_complete.
        """
        self.conn_hs_complete[addr_key] = True
```

- [ ] **Step 4: Verify it passes**

Run:
```bash
mojo run tests/test_quic_profile.mojo 2>&1 | tail -10
```

Expected: PASS — both new tests print `PASS:`.

- [ ] **Step 5: Commit**

`commit-smart`. Message: `feat: add per-conn packet count + handshake-complete tracking to AcceptProfile`.

---

## Task 3: `report_json` arrival-latency block

**Files:**
- Modify: `src/quic/profile.mojo` `report_json` (~line 216)
- Test: `tests/test_quic_profile.mojo` (extend `test_report_json_canned` or add new test)

- [ ] **Step 1: Write failing test**

Append before `def main`:

```mojo
def test_report_json_arrival_latency_block() raises:
    """Verify report_json emits the arrival-latency block with correct keys + values."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_arrival_lat(UInt64(50))         # bucket 6 ([32, 64))
    p.record_arrival_lat(UInt64(50))         # bucket 6
    p.record_arrival_lat(UInt64(2_000_000))  # bucket 21 ([1048576, 2097152))
    p.record_arrival_lat(UInt64(20_000_000)) # overflow
    var j = p.report_json()
    assert_true('"arrival_lat_us_total":' in j, "arrival_lat_us_total key present")
    assert_true('"arrival_lat_us_buckets":' in j, "arrival_lat_us_buckets key present")
    assert_true('"arrival_lat_us_overflow":' in j, "arrival_lat_us_overflow key present")
    var expected_total = UInt64(50 + 50 + 2_000_000 + 20_000_000)
    assert_true(String('"arrival_lat_us_total": ') + String(expected_total) in j, "total value matches")
    assert_true('"arrival_lat_us_overflow": 1' in j, "overflow = 1")
    print("PASS: test_report_json_arrival_latency_block")
```

Register in `main`:
```mojo
    test_report_json_arrival_latency_block()
```

- [ ] **Step 2: Verify it fails**

Run:
```bash
mojo run tests/test_quic_profile.mojo 2>&1 | tail -5
```

Expected: FAIL — `arrival_lat_us_total key present` assertion fails because the JSON does not yet contain that key.

- [ ] **Step 3: Add JSON block**

In `report_json`, locate the closing `s += "  }\n"` of the `"handshake"` block (just before `s += "}\n"`, ~line 283), and INSERT BEFORE that closing `}` (so the new block is alongside `handshake`):

Concretely change:
```mojo
        s += "  }\n"
        s += "}\n"
        return s^
```

to:
```mojo
        s += "  },\n"

        s += '  "arrival_lat_us": {\n'
        s += '    "total": ' + String(self.arrival_lat_us_total) + ',\n'
        s += '    "overflow": ' + String(self.arrival_lat_us_overflow) + ',\n'
        s += '    "buckets": ['
        for i in range(24):
            s += String(self.arrival_lat_us_buckets[i])
            if i < 23:
                s += ", "
        s += "]\n"
        s += "  }\n"
        s += "}\n"
        return s^
```

Note: also update the `handshake` closing comma — the trailing `}` of `handshake` was previously last; now it's followed by another block. The existing `s += "  }\n"` becomes `s += "  },\n"` (added trailing comma).

Also add top-level total/overflow keys for ergonomic test access. Place them adjacent to the existing `"per_pkt_us"` block. Locate this line in `report_json`:

```mojo
        s += "  },\n"  # close per_pkt_us
```

(just before the `"handshake"` block opens). Immediately AFTER that line, INSERT:

```mojo
        s += '  "arrival_lat_us_total": ' + String(self.arrival_lat_us_total) + ',\n'
        s += '  "arrival_lat_us_overflow": ' + String(self.arrival_lat_us_overflow) + ',\n'
        s += '  "arrival_lat_us_buckets": ['
        for i in range(24):
            s += String(self.arrival_lat_us_buckets[i])
            if i < 23:
                s += ", "
        s += "],\n"
```

This satisfies the spec's flat-key style for the arrival-latency block (matches test assertions that look for `"arrival_lat_us_total":` at top level). Remove the duplicated nested `"arrival_lat_us"` block from the previous instruction in this step — keep only the flat-key version.

**Final corrected change:** `report_json` gains three new top-level keys (`arrival_lat_us_total`, `arrival_lat_us_overflow`, `arrival_lat_us_buckets`) inserted between `per_pkt_us` and `handshake`. The structure is:

```
{
  ...
  "per_pkt_us": { ... },
  "arrival_lat_us_total": <UInt64>,
  "arrival_lat_us_overflow": <UInt64>,
  "arrival_lat_us_buckets": [...24 ints...],
  "handshake": { ... }
}
```

- [ ] **Step 4: Verify it passes**

Run:
```bash
mojo run tests/test_quic_profile.mojo 2>&1 | tail -10
```

Expected: PASS — new test passes; existing `test_report_json_canned` still passes.

- [ ] **Step 5: Commit**

`commit-smart`. Message: `feat: emit arrival-latency block in report_json`.

---

## Task 4: `report_json` per-conn aggregated block

**Files:**
- Modify: `src/quic/profile.mojo` `report_json` (insert another block + computed scalar)
- Test: `tests/test_quic_profile.mojo` (append)

- [ ] **Step 1: Write failing test**

Append before `def main`:

```mojo
def test_report_json_per_conn_aggregated_block() raises:
    """Populate dict with 50 conn-ids of varying counts; verify 8-bucket histogram totals match.

    Buckets layout (matches _pkts_per_flush_bucket): [1, 2-3, 4-7, 8-15, 16-31, 32-63, 64-127, 128+].
    """
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Bucket 0 (size=1): 5 conns
    for i in range(5):
        p.record_conn_pkt(String("b0_") + String(i))
    # Bucket 1 (size=2-3): 4 conns × 2 packets each
    for i in range(4):
        var k = String("b1_") + String(i)
        p.record_conn_pkt(k)
        p.record_conn_pkt(k)
    # Bucket 2 (size=4-7): 3 conns × 5 packets each
    for i in range(3):
        var k = String("b2_") + String(i)
        for _ in range(5):
            p.record_conn_pkt(k)
    # Bucket 3 (size=8-15): 2 conns × 10 packets each
    for i in range(2):
        var k = String("b3_") + String(i)
        for _ in range(10):
            p.record_conn_pkt(k)
    # Mark some hs_complete: 2 from bucket 0, 1 from bucket 2
    p.record_conn_hs_complete(String("b0_0"))
    p.record_conn_hs_complete(String("b0_1"))
    p.record_conn_hs_complete(String("b2_0"))

    var j = p.report_json()
    assert_true('"per_conn_pkts_buckets":' in j, "per_conn_pkts_buckets key present")
    assert_true('"conns_total": 14' in j, "conns_total = 5+4+3+2 = 14")
    # 14 total, 3 hs_complete → 11 without hs_complete
    assert_true('"conns_with_pkts_no_hs_complete": 11' in j, "no-hs scalar = 11")
    # Histogram totals: bucket[0]=5, bucket[1]=4, bucket[2]=3, bucket[3]=2, others=0
    assert_true('"per_conn_pkts_buckets": [5, 4, 3, 2, 0, 0, 0, 0]' in j, "8-bucket histogram matches")
    print("PASS: test_report_json_per_conn_aggregated_block")
```

Register in `main`:
```mojo
    test_report_json_per_conn_aggregated_block()
```

- [ ] **Step 2: Verify it fails**

Run:
```bash
mojo run tests/test_quic_profile.mojo 2>&1 | tail -5
```

Expected: FAIL — `per_conn_pkts_buckets key present` assertion fails.

- [ ] **Step 3: Add per-conn aggregated block**

In `report_json`, AFTER the arrival-latency block (added in Task 3), BEFORE the `"handshake":` line, insert:

```mojo
        # Per-conn aggregated histogram + scalar.
        # Walk conn_pkt_counts.items(); dispatch each conn's packet count via _pkts_per_flush_bucket.
        var per_conn_buckets = List[UInt64]()
        for _ in range(8):
            per_conn_buckets.append(UInt64(0))
        var conns_total: UInt64 = UInt64(0)
        var conns_no_hs: UInt64 = UInt64(0)
        for entry in self.conn_pkt_counts.items():
            conns_total += UInt64(1)
            var b = _pkts_per_flush_bucket(Int(entry.value))
            per_conn_buckets[b] += UInt64(1)
            if entry.key not in self.conn_hs_complete:
                conns_no_hs += UInt64(1)

        s += '  "per_conn_pkts_buckets": ['
        for i in range(8):
            s += String(per_conn_buckets[i])
            if i < 7:
                s += ", "
        s += "],\n"
        s += '  "conns_total": ' + String(conns_total) + ',\n'
        s += '  "conns_with_pkts_no_hs_complete": ' + String(conns_no_hs) + ',\n'
```

- [ ] **Step 4: Verify it passes**

Run:
```bash
mojo run tests/test_quic_profile.mojo 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 5: Commit**

`commit-smart`. Message: `feat: emit per-conn aggregated block in report_json`.

---

## Task 5: `report_json` top-50 worst-offenders block

**Files:**
- Modify: `src/quic/profile.mojo` `report_json` (insert top-50 sort + JSON emission)
- Test: `tests/test_quic_profile.mojo` (append)

- [ ] **Step 1: Write failing test**

Append before `def main`:

```mojo
def test_report_json_worst_conns() raises:
    """Populate 100 non-complete conns + 20 complete; verify top-50 sorted descending and capped."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # 100 non-complete conns: pkt_count = i (1..100)
    for i in range(100):
        var k = String("nc_") + String(i)
        for _ in range(i + 1):
            p.record_conn_pkt(k)
    # 20 complete conns with very high counts (200+) — must be excluded from top-50
    for i in range(20):
        var k = String("c_") + String(i)
        for _ in range(200 + i):
            p.record_conn_pkt(k)
        p.record_conn_hs_complete(k)
    var j = p.report_json()
    assert_true('"worst_conns":' in j, "worst_conns key present")
    # Top entry must be nc_99 (100 packets, not complete)
    assert_true('"addr_key": "nc_99"' in j, "top offender is nc_99")
    assert_true('"pkt_count": 100' in j, "top pkt_count = 100")
    # No complete conn should appear
    assert_true('"addr_key": "c_19"' not in j, "complete conn excluded")
    # Verify cap at 50: count occurrences of '"addr_key":' — exactly 50
    var n_entries = 0
    var idx = 0
    var search = String('"addr_key":')
    var search_b = search.as_bytes()
    var j_b = j.as_bytes()
    while idx < len(j_b) - len(search_b):
        var match = True
        for k in range(len(search_b)):
            if j_b[idx + k] != search_b[k]:
                match = False
                break
        if match:
            n_entries += 1
            idx += len(search_b)
        else:
            idx += 1
    assert_true(n_entries == 50, "exactly 50 worst_conns entries (cap)")
    print("PASS: test_report_json_worst_conns")
```

Register in `main`:
```mojo
    test_report_json_worst_conns()
```

- [ ] **Step 2: Verify it fails**

Run:
```bash
mojo run tests/test_quic_profile.mojo 2>&1 | tail -5
```

Expected: FAIL — `worst_conns key present` assertion fails.

- [ ] **Step 3: Add top-50 sort + JSON block**

In `report_json`, AFTER the per-conn aggregated block (Task 4), BEFORE the `"handshake":` opener, insert:

```mojo
        # Top-50 worst offenders: addr_keys with most packets but no hs_complete.
        # Materialize parallel List[String] + List[UInt64], insertion-sort descending.
        # Report time is non-hot; clarity > heap-select.
        var off_keys = List[String]()
        var off_vals = List[UInt64]()
        for entry in self.conn_pkt_counts.items():
            if entry.key in self.conn_hs_complete:
                continue
            off_keys.append(entry.key)
            off_vals.append(entry.value)
        # Insertion sort by val descending.
        var n_off = len(off_vals)
        for i in range(1, n_off):
            var v = off_vals[i]
            var k = off_keys[i]
            var j = i - 1
            while j >= 0 and off_vals[j] < v:
                off_vals[j + 1] = off_vals[j]
                off_keys[j + 1] = off_keys[j]
                j -= 1
            off_vals[j + 1] = v
            off_keys[j + 1] = k

        var cap = n_off
        if cap > 50:
            cap = 50
        s += '  "worst_conns": [\n'
        for i in range(cap):
            s += '    {"addr_key": "' + off_keys[i] + '", "pkt_count": ' + String(off_vals[i]) + ', "hs_complete": false}'
            if i < cap - 1:
                s += ","
            s += "\n"
        s += "  ],\n"
```

- [ ] **Step 4: Verify it passes**

Run:
```bash
mojo run tests/test_quic_profile.mojo 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 5: Commit**

`commit-smart`. Message: `feat: emit top-50 worst-offenders block in report_json`.

---

## Task 6: `report_text` mirroring of all three new blocks

**Files:**
- Modify: `src/quic/profile.mojo` `report_text` (~line 213, just before `s += "=== end ===\n"`)
- Test: `tests/test_quic_profile.mojo` (presence checks)

- [ ] **Step 1: Write failing test**

Append before `def main`:

```mojo
def test_report_text_new_sections() raises:
    """Verify report_text emits human-readable sections for the three new blocks."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_arrival_lat(UInt64(150))
    p.record_arrival_lat(UInt64(2_000_000))
    p.record_conn_pkt(String("X:1"))
    p.record_conn_pkt(String("Y:2"))
    p.record_conn_pkt(String("Y:2"))
    p.record_conn_pkt(String("Y:2"))
    p.record_conn_hs_complete(String("X:1"))
    var t = p.report_text()
    assert_true("Arrival-to-processing latency" in t, "arrival-lat section header")
    assert_true("Per-connection packet counts" in t, "per-conn section header")
    assert_true("Worst offenders" in t, "worst-offenders section header")
    # Sanity: no-hs scalar reported. Y:2 is not complete and has 3 packets.
    assert_true("Y:2" in t, "non-complete addr_key surfaces in worst offenders")
    print("PASS: test_report_text_new_sections")
```

Register in `main`:
```mojo
    test_report_text_new_sections()
```

- [ ] **Step 2: Verify it fails**

Run:
```bash
mojo run tests/test_quic_profile.mojo 2>&1 | tail -5
```

Expected: FAIL — `arrival-lat section header` assertion fails.

- [ ] **Step 3: Add report_text sections**

In `report_text`, locate the line `s += "=== end ===\n"` (~line 213). Immediately BEFORE that line, insert:

```mojo
        # Arrival-to-processing latency.
        s += "Arrival-to-processing latency (bucket-estimated p_n, us):\n"
        var arr_n = self.pkt_count - self.arrival_lat_us_overflow  # closed-bucket count proxy
        # Note: total observation count is sum of buckets + overflow; use that for accurate %iles.
        var arr_total_obs: UInt64 = UInt64(0)
        for i in range(24):
            arr_total_obs += self.arrival_lat_us_buckets[i]
        var arr_p50 = _bucket_percentile(self.arrival_lat_us_buckets, arr_total_obs, 50.0)
        var arr_p90 = _bucket_percentile(self.arrival_lat_us_buckets, arr_total_obs, 90.0)
        var arr_p99 = _bucket_percentile(self.arrival_lat_us_buckets, arr_total_obs, 99.0)
        s += "  total:           p50=" + String(arr_p50) + "  p90=" + String(arr_p90) + "  p99=" + String(arr_p99)
        s += "  (n=" + String(arr_total_obs) + ", overflow=" + String(self.arrival_lat_us_overflow) + ")\n"
        s += "  total_us:        " + String(self.arrival_lat_us_total) + "\n\n"

        # Per-connection packet counts (aggregated histogram).
        s += "Per-connection packet counts (aggregated 8-bucket histogram):\n"
        var pc_buckets = List[UInt64]()
        for _ in range(8):
            pc_buckets.append(UInt64(0))
        var pc_total: UInt64 = UInt64(0)
        var pc_no_hs: UInt64 = UInt64(0)
        for entry in self.conn_pkt_counts.items():
            pc_total += UInt64(1)
            var b = _pkts_per_flush_bucket(Int(entry.value))
            pc_buckets[b] += UInt64(1)
            if entry.key not in self.conn_hs_complete:
                pc_no_hs += UInt64(1)
        var pc_labels = List[String]()
        pc_labels.append(String("size=1     "))
        pc_labels.append(String("size=2-3   "))
        pc_labels.append(String("size=4-7   "))
        pc_labels.append(String("size=8-15  "))
        pc_labels.append(String("size=16-31 "))
        pc_labels.append(String("size=32-63 "))
        pc_labels.append(String("size=64-127"))
        pc_labels.append(String("size=128+  "))
        for i in range(8):
            s += "  " + pc_labels[i] + " " + _fmt_count(pc_buckets[i]) + "\n"
        s += "  conns_total:                  " + _fmt_count(pc_total) + "\n"
        s += "  conns_with_pkts_no_hs_complete:" + _fmt_count(pc_no_hs) + "\n\n"

        # Top-50 worst offenders (parallel insertion sort).
        s += "Worst offenders (top 50 addr_keys by pkt_count, no hs_complete):\n"
        var wo_keys = List[String]()
        var wo_vals = List[UInt64]()
        for entry in self.conn_pkt_counts.items():
            if entry.key in self.conn_hs_complete:
                continue
            wo_keys.append(entry.key)
            wo_vals.append(entry.value)
        var wo_n = len(wo_vals)
        for i in range(1, wo_n):
            var v = wo_vals[i]
            var k = wo_keys[i]
            var j = i - 1
            while j >= 0 and wo_vals[j] < v:
                wo_vals[j + 1] = wo_vals[j]
                wo_keys[j + 1] = wo_keys[j]
                j -= 1
            wo_vals[j + 1] = v
            wo_keys[j + 1] = k
        var wo_cap = wo_n
        if wo_cap > 50:
            wo_cap = 50
        for i in range(wo_cap):
            s += "  " + wo_keys[i] + "  pkt_count=" + String(wo_vals[i]) + "\n"
        if wo_n == 0:
            s += "  (none)\n"
        s += "\n"
```

- [ ] **Step 4: Verify it passes**

Run:
```bash
mojo run tests/test_quic_profile.mojo 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 5: Commit**

`commit-smart`. Message: `feat: mirror new blocks in report_text`.

---

## Task 7: PendingDatagram.arrival_us field + 3 init paths

**Files:**
- Modify: `bench/h3_server.mojo:254-294` (add field + update 3 init paths)

- [ ] **Step 1: Read current PendingDatagram lines**

Run:
```bash
sed -n '254,295p' bench/h3_server.mojo
```

Confirm 3 init signatures: positional, `other=`, `deinit take=`. (See plan header for exact line numbers; this step is a read-only sanity check.)

- [ ] **Step 2: Add field with doc-comment**

In `bench/h3_server.mojo`, modify the `PendingDatagram` struct to add `arrival_us`:

```mojo
struct PendingDatagram(Copyable, Movable):
    var buf_id: UInt16
    var buf_ptr: UnsafePointer[UInt8, MutAnyOrigin]
    var payload_ptr: UnsafePointer[UInt8, MutAnyOrigin]
    var payload_len: Int
    var addr_offset: Int
    var addr_len: Int
    var addr_key: String
    var dcid: List[UInt8]
    # Arrival-to-processing queueing-tail instrumentation.
    # Read only when PROFILE_ACCEPT is True; off-build the value is always 0
    # and any computed `now - arrival_us` delta is meaningless.
    var arrival_us: UInt64
```

Update positional `__init__` (line 264) — add `arrival_us: UInt64 = UInt64(0)` as a default-valued kwarg-style trailing param so existing callers that don't pass it still work. Mojo 0.26.2 supports defaults; verify by adding:

```mojo
    def __init__(out self, buf_id: UInt16, buf_ptr: UnsafePointer[UInt8, MutAnyOrigin],
                 payload_ptr: UnsafePointer[UInt8, MutAnyOrigin], payload_len: Int,
                 addr_offset: Int, addr_len: Int, var addr_key: String, var dcid: List[UInt8],
                 arrival_us: UInt64 = UInt64(0)):
        self.buf_id = buf_id
        self.buf_ptr = buf_ptr
        self.payload_ptr = payload_ptr
        self.payload_len = payload_len
        self.addr_offset = addr_offset
        self.addr_len = addr_len
        self.addr_key = addr_key^
        self.dcid = dcid^
        self.arrival_us = arrival_us
```

Update copy `__init__(other=...)`:

```mojo
    def __init__(out self, *, other: Self):
        self.buf_id = other.buf_id
        self.buf_ptr = other.buf_ptr
        self.payload_ptr = other.payload_ptr
        self.payload_len = other.payload_len
        self.addr_offset = other.addr_offset
        self.addr_len = other.addr_len
        self.addr_key = String(other.addr_key)
        self.dcid = List[UInt8](copy=other.dcid)
        self.arrival_us = other.arrival_us
```

Update move `__init__(deinit take=...)`:

```mojo
    def __init__(out self, *, deinit take: Self):
        self.buf_id = take.buf_id
        self.buf_ptr = take.buf_ptr
        self.payload_ptr = take.payload_ptr
        self.payload_len = take.payload_len
        self.addr_offset = take.addr_offset
        self.addr_len = take.addr_len
        self.addr_key = take.addr_key^
        self.dcid = take.dcid^
        self.arrival_us = take.arrival_us
```

- [ ] **Step 3: Verify build still passes**

Run:
```bash
bash scripts/run_tests.sh 2>&1 | tail -5
```

Expected: pre-spec baseline still PASS (test_quic_profile + test_quic_profile_wiring + 33 loopback). `test_tls_connection` still fails as out-of-scope.

- [ ] **Step 4: Commit**

`commit-smart`. Message: `refactor: add arrival_us field to PendingDatagram`.

---

## Task 8: `_handle_recvmsg` arrival-stamp insertion

**Files:**
- Modify: `bench/h3_server.mojo:625` (insert PROFILE_ACCEPT-gated stamp before `pending_rx.append`)

- [ ] **Step 1: Locate insertion site**

Run:
```bash
sed -n '620,640p' bench/h3_server.mojo
```

Confirm the lines around `pending_rx.append(...)`.

- [ ] **Step 2: Insert stamp**

In `bench/h3_server.mojo`, just BEFORE the `self.pending_rx.append(` line (currently line 625), insert:

```mojo
        var stamp_us: UInt64 = UInt64(0)
        @parameter
        if PROFILE_ACCEPT:
            stamp_us = profile_monotonic_us()
```

And modify the `pending_rx.append(PendingDatagram(...))` call to pass `arrival_us=stamp_us`:

```mojo
        self.pending_rx.append(
            PendingDatagram(
                buf_id=buf_id,
                buf_ptr=buf_ptr,
                payload_ptr=payload_ptr,
                payload_len=payloadlen,
                addr_offset=addr_offset,
                addr_len=addr_len,
                addr_key=key^,
                dcid=dcid^,
                arrival_us=stamp_us,
            )
        )
```

Note: `profile_monotonic_us` is already imported at the top of the file (`from src.quic.profile import AcceptProfile, PROFILE_ACCEPT, monotonic_us as profile_monotonic_us`).

- [ ] **Step 3: Verify build + tests pass**

Run:
```bash
bash scripts/run_tests.sh 2>&1 | tail -5
```

Expected: pre-spec baseline still PASS.

- [ ] **Step 4: Commit**

`commit-smart`. Message: `feat: stamp arrival_us at recvmsg ingress under PROFILE_ACCEPT`.

---

## Task 9: `_flush_impl` — record_arrival_lat call

**Files:**
- Modify: `bench/h3_server.mojo:646-755` (insert PROFILE_ACCEPT-gated record at top of per-packet loop)

- [ ] **Step 1: Locate insertion site**

In `_flush_impl`, the existing loop at line 658 reads:

```mojo
        for i in range(len(self.pending_rx)):
            var pd = self.pending_rx[i].copy()
            ...
```

The arrival-latency record goes inside the loop, at the very top (before the conn-id lookup).

- [ ] **Step 2: Insert record_arrival_lat call**

Modify the loop body to add the record at top:

```mojo
        for i in range(len(self.pending_rx)):
            var pd = self.pending_rx[i].copy()
            @parameter
            if PROFILE_ACCEPT:
                # Queueing wait: now (flush start) - arrival_us (recvmsg ingress).
                # delta is the wall-clock time the packet sat in pending_rx.
                if pd.arrival_us > UInt64(0) and now >= pd.arrival_us:
                    self.profile.record_arrival_lat(now - pd.arrival_us)
                else:
                    self.profile.record_arrival_lat(UInt64(0))
            # Re-lookup conn_idx by addr_key — the index recorded at
            # _handle_recvmsg time may be stale...
            var conn_idx = self._find_conn(pd.addr_key)
            ...
```

The `pd.arrival_us > UInt64(0)` guard avoids charging a delta when the field is unset (defensive — should be set by Task 8 when PROFILE_ACCEPT=True). The `now >= pd.arrival_us` guard avoids underflow.

- [ ] **Step 3: Verify build + tests pass**

Run:
```bash
bash scripts/run_tests.sh 2>&1 | tail -5
```

Expected: pre-spec baseline PASS.

- [ ] **Step 4: Commit**

`commit-smart`. Message: `feat: record arrival-to-processing latency in _flush_impl`.

---

## Task 10: `_flush_impl` — record_conn_pkt + record_conn_hs_complete calls

**Files:**
- Modify: `bench/h3_server.mojo:646-755` (insert two PROFILE_ACCEPT-gated record calls)

- [ ] **Step 1: Insert record_conn_pkt at top of per-packet loop**

In the per-packet loop body, immediately AFTER the `record_arrival_lat` block from Task 9, ADD:

```mojo
            @parameter
            if PROFILE_ACCEPT:
                self.profile.record_conn_pkt(pd.addr_key)
```

- [ ] **Step 2: Insert record_conn_hs_complete after feed_datagram_from_buffer**

Locate the existing `feed_datagram_from_buffer` call at line 726:

```mojo
            try:
                self.conn_h3s[conn_idx][].feed_datagram_from_buffer(pd.payload_ptr, pd.payload_len, now)
            except e:
                self.feed_datagram_err_count += UInt64(1)
                ...
```

Immediately AFTER the `try/except` block (before the `# Update peer address.` comment at line 732), ADD:

```mojo
            @parameter
            if PROFILE_ACCEPT:
                # Poll handshake-complete state; idempotent record.
                # is_established() is True only after CONN_ESTABLISHED bit
                # set atomically with handshake_complete event (verified at
                # src/quic/connection.mojo:1779-1786).
                if self.conn_h3s[conn_idx][]._h3.is_established():
                    self.profile.record_conn_hs_complete(pd.addr_key)
```

- [ ] **Step 3: Verify build + tests pass**

Run:
```bash
bash scripts/run_tests.sh 2>&1 | tail -5
```

Expected: pre-spec baseline PASS.

- [ ] **Step 4: Commit**

`commit-smart`. Message: `feat: record per-conn packet counts + handshake-complete in _flush_impl`.

---

## Task 11: Smoke gate — long-conn cell

**Files:** none (operational measurement)

- [ ] **Step 1: Off-build baseline (PROFILE_ACCEPT=False)**

Confirm `src/quic/profile.mojo:15` reads `comptime PROFILE_ACCEPT: Bool = False`. If not, restore to False.

Run:
```bash
make -C bench/quic_perf setup 2>&1 | tail -5
bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 3 2>&1 | tail -20
```

Expected: 3 iterations of 1k-long-conn long under tquic_client. Record the median rps. Plan B B13 measured 411.83 rps off-build; expect within ±5%.

- [ ] **Step 2: On-build (PROFILE_ACCEPT=True)**

Edit `src/quic/profile.mojo:15` to `comptime PROFILE_ACCEPT: Bool = True`.

Force-rebuild Docker image:
```bash
docker rmi mojo-net-bench:latest
make -C bench/quic_perf setup 2>&1 | tail -5
```

Run the same bench:
```bash
bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 3 2>&1 | tail -20
```

Record median rps.

- [ ] **Step 3: Compute drift, decide PASS/FAIL**

Compute `drift_pct = 100 * (on_build_median - off_build_median) / off_build_median`.

Threshold: `|drift_pct| ≤ 10%`.

If PASS: proceed.

If FAIL: invoke the fallback documented in spec ("demote `record_conn_pkt` from per-packet to per-flush-aggregate"). Concretely: refactor `_flush_impl` to accumulate a local `Dict[String, UInt64]` over the pending batch, then call a new method `record_conn_pkts_batch(addr_key_counts: Dict[String, UInt64])` once per flush. Add this method to `AcceptProfile` (similar to `record_conn_pkt` but takes a Dict and adds entries in bulk). Re-run smoke gate before continuing.

- [ ] **Step 4: Restore off-build flag**

Edit `src/quic/profile.mojo:15` back to `comptime PROFILE_ACCEPT: Bool = False`.

- [ ] **Step 5: Commit smoke results**

`commit-smart`. Message: `bench: long-conn smoke gate <PASS|FAIL with drift X%>`. Include the off-build vs on-build numbers in the commit body.

---

## Task 12: Smoke gate — short-conn cell

**Files:** none (operational measurement)

- [ ] **Step 1: Off-build baseline**

Confirm `PROFILE_ACCEPT: Bool = False`.

Run:
```bash
bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 3 2>&1 | tail -20
```

Record median rps. Plan C C1 saw 0.42 rps median; expect ~0.4-0.6 rps.

- [ ] **Step 2: On-build**

Set `PROFILE_ACCEPT: Bool = True`, force-rebuild Docker image, re-run bench:

```bash
docker rmi mojo-net-bench:latest
make -C bench/quic_perf setup 2>&1 | tail -5
bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 3 2>&1 | tail -20
```

Record median rps.

- [ ] **Step 3: Compute drift, decide PASS/FAIL**

Same threshold: `|drift_pct| ≤ 10%` of the off-build median.

Caveat: at 0.42 rps a 10% drift is 0.04 rps — within run-to-run noise. If both medians are within `±0.1 rps` of each other, treat as PASS regardless of percentage; the percentage is meaningful only for non-trivial absolute values. Document the choice in the commit message.

If FAIL (and not noise-bounded): invoke the per-flush-aggregate fallback as in Task 11 Step 3 and re-run.

- [ ] **Step 4: Leave on-build flag set for Task 13**

Do NOT restore `PROFILE_ACCEPT` to False yet — Task 13 needs the on-build image for the operational capture.

- [ ] **Step 5: Commit smoke results**

`commit-smart`. Message: `bench: short-conn smoke gate <PASS|FAIL with drift X%>`.

---

## Task 13: Operational SIGINT capture under short-conn

**Files:**
- Create: `bench/quic_perf/results/profile/INSTRUMENTATION-<UTC>-queueing-tail.json`

- [ ] **Step 1: Start the on-build server**

Run:
```bash
bench/quic_perf/scripts/start-server.sh mojo-net
```

Wait for `bench-h3` container to be ready (check `docker ps`).

- [ ] **Step 2: Drive 30s of short-conn load**

Run:
```bash
bench/quic_perf/scripts/run-tquic-client.sh 1k short-conn 30 > /tmp/client-stdout.log 2>&1
cat /tmp/client-stdout.log | tail -20
```

Note the reported "conns: total" + "succeeded" + "timed_out" numbers.

- [ ] **Step 3: SIGINT-flush the server**

Run:
```bash
docker kill --signal=SIGINT bench-h3
sleep 2
docker logs bench-h3 2>&1 | tail -120 > /tmp/server-flush.log
cat /tmp/server-flush.log | tail -120
```

Expected: text report with `Arrival-to-processing latency`, `Per-connection packet counts`, `Worst offenders` sections.

- [ ] **Step 4: Exfiltrate sidecar JSON**

Run:
```bash
mkdir -p bench/quic_perf/results/profile
docker cp bench-h3:/app/bench/quic_perf/results/profile/. bench/quic_perf/results/profile/
ls -la bench/quic_perf/results/profile/INSTRUMENTATION-*-queueing-tail*.json 2>/dev/null || \
    ls -la bench/quic_perf/results/profile/INSTRUMENTATION-*.json | tail -1
```

The latest sidecar should have the new fields. Identify by date suffix; copy to `INSTRUMENTATION-<UTC>-queueing-tail.json` for clarity:

```bash
LATEST=$(ls -t bench/quic_perf/results/profile/INSTRUMENTATION-*.json | head -1)
NEW_NAME=$(echo "$LATEST" | sed 's/\.json/-queueing-tail.json/')
mv "$LATEST" "$NEW_NAME"
echo "Renamed: $NEW_NAME"
```

- [ ] **Step 5: Verify well-formed JSON**

Run:
```bash
python3 -m json.tool < "$NEW_NAME" | head -50
```

Expected: parseable JSON; new keys present (`arrival_lat_us_total`, `per_conn_pkts_buckets`, `worst_conns`).

- [ ] **Step 6: Stop the server, restore off-build flag**

Run:
```bash
bench/quic_perf/scripts/stop-server.sh
```

Edit `src/quic/profile.mojo:15` back to `comptime PROFILE_ACCEPT: Bool = False`.

- [ ] **Step 7: Commit**

`commit-smart`. Message: `bench: capture queueing-tail sidecar under short-conn`. Include the sidecar filename in the commit body.

---

## Task 14: REFERENCE.md hypothesis-pass log entry

**Files:**
- Modify: `bench/quic_perf/results/REFERENCE.md` (append)

- [ ] **Step 1: Re-read every existing row of REFERENCE.md (METHODOLOGY GATE)**

Per the spec acceptance #10 methodology gate codified from the Plan C retro:

```bash
wc -l bench/quic_perf/results/REFERENCE.md
sed -n '1,250p' bench/quic_perf/results/REFERENCE.md
sed -n '250,$p' bench/quic_perf/results/REFERENCE.md
```

Read the entire file. Note line count. The new entry MUST state explicitly: "Methodology gate satisfied: re-read all N lines of REFERENCE.md before drafting this entry; flagged contradictions: <list, or 'none'>."

- [ ] **Step 2: Extract the captured signal**

From the sidecar JSON (Task 13 output), record:

- `arrival_lat_us_total`, `arrival_lat_us_overflow`
- The 24-bucket `arrival_lat_us_buckets` array
- Compute P99 from the buckets — use the formula `_bucket_percentile(arrival_lat_us_buckets, sum(buckets), 99.0)` mentally, OR run a one-liner:

```bash
python3 - << 'EOF'
import json
with open('<sidecar-filename>') as f:
    data = json.load(f)
buckets = data['arrival_lat_us_buckets']
overflow = data['arrival_lat_us_overflow']
total_obs = sum(buckets) + overflow
print(f"total_obs={total_obs}, overflow={overflow}, overflow_pct={100*overflow/total_obs:.2f}%")
target = 0.99 * total_obs
cum = 0
for i, c in enumerate(buckets):
    cum += c
    if cum >= target:
        lower = 0 if i == 0 else (1 << (i - 1))
        upper = 1 << i
        print(f"P99 bucket: {i} [{lower}, {upper}) us")
        break
else:
    print(f"P99 falls in overflow (>= {1<<23} us = 8.39 s)")
EOF
```

Replace `<sidecar-filename>` with the actual path.

- `conns_total`, `conns_with_pkts_no_hs_complete`
- `worst_conns` array (note top 5)

- [ ] **Step 3: Apply 3-verdict signal table**

Determine verdict per the spec:

- **CONFIRMED** if computed P99 ≥ 1,000,000 µs (1s) OR `arrival_lat_us_overflow ≥ 50% of pkt_count` (overflow dominance is itself confirmed-with-coarse-bucketing).
- **FALSIFIED** if P99 ≤ 100,000 µs (100ms).
- **INCONCLUSIVE** if 100,000 < P99 < 1,000,000.

Cross-check `conns_with_pkts_no_hs_complete`:
- ≥ 50: corroborates CONFIRMED.
- ≤ 5: weakens CONFIRMED (re-examine).

If INCONCLUSIVE: capture a second 30s run (re-run Task 13). If both still INCONCLUSIVE, the entry MUST propose a higher-resolution instrument and STOP — do NOT write a fix spec.

- [ ] **Step 4: Append the entry**

Append to `bench/quic_perf/results/REFERENCE.md`:

```markdown
### 2026-04-XX — queueing-tail-instrumentation — DATA — <CONFIRMED|FALSIFIED|INCONCLUSIVE>

**Spec:** `specs/2026-04-27-quic-queueing-tail-instrumentation.md`. Plan: `plans/2026-04-27-quic-queueing-tail-instrumentation.md`. Goal: test the queueing-tail hypothesis (most-plausible mechanism after the 4-diagnosis chain on `feat/quic-accept-loop-instrumentation`).

**Methodology gate satisfied:** re-read all N lines of REFERENCE.md before drafting this entry. Flagged contradictions: <list each, or "none">.

**Capture cell:** 1k short-conn, tquic_client (4 threads × 25 conns), 30s, on-build (PROFILE_ACCEPT=True), manual SIGINT-driven sidecar.

**Sidecar:** `bench/quic_perf/results/profile/INSTRUMENTATION-<UTC>-queueing-tail.json`

**Arrival-to-processing latency:**
- `arrival_lat_us_total`: <value>
- `arrival_lat_us_overflow`: <value> (<X.X>% of total observations)
- Bucket distribution: <fill in non-zero buckets>
- **P99: <value> µs**

**Per-connection trajectory:**
- `conns_total`: <value>
- `conns_with_pkts_no_hs_complete`: <value>
- Top-5 worst offenders: <list>

**3-verdict signal table:**
- CONFIRMED if P99 ≥ 1,000,000 µs OR overflow ≥ 50% of pkt_count: <YES/NO>
- FALSIFIED if P99 ≤ 100,000 µs: <YES/NO>
- INCONCLUSIVE if 100,000 < P99 < 1,000,000: <YES/NO>
- Corroboration: conns_with_pkts_no_hs_complete <comparison vs ≥50 / ≤5 thresholds>

**Verdict: <CONFIRMED | FALSIFIED | INCONCLUSIVE>.**

**Caveat:** captured arrival pattern is `tquic_client`-specific. `h2load --h3` (REFERENCE.md row 28) drives different absolute numbers; conclusions about queueing under tquic_client's load shape do not generalize trivially to other clients without a follow-up capture.

**Next hypothesis (per verdict):**
- If CONFIRMED → spec multi-fiber accept fan-out OR batch FFI (decision deferred to that spec).
- If FALSIFIED → reopen the search with new data: <propose>.
- If INCONCLUSIVE → spec a higher-resolution instrument before any fix spec; do NOT write a fix spec on inconclusive data.

**Off-build flag confirmed:** `PROFILE_ACCEPT: Bool = False` at `src/quic/profile.mojo:15` post-capture.
```

Fill in the `<...>` placeholders with actual measured values.

- [ ] **Step 5: Run baseline tests post-capture**

Run:
```bash
bash scripts/run_tests.sh 2>&1 | tail -10
```

Expected: same baseline as Task 0 Step 2 (33 loopback + test_quic_profile + test_quic_profile_wiring all PASS; `test_tls_connection` fails as out-of-scope).

- [ ] **Step 6: Commit**

`commit-smart`. Message: `docs: REFERENCE.md queueing-tail hypothesis-pass entry — <CONFIRMED|FALSIFIED|INCONCLUSIVE>`.

---

## Acceptance verification (final)

- [ ] All 14 tasks above completed. Each has its own combined-review pass through subagent-driven-development.
- [ ] `src/quic/profile.mojo` has 5 new fields + 3 new methods + 3 JSON blocks + 3 text sections.
- [ ] `bench/h3_server.mojo` has `arrival_us` field on `PendingDatagram` + 1 stamp site + 3 record sites, all `@parameter if PROFILE_ACCEPT`-gated.
- [ ] `tests/test_quic_profile.mojo` has at least 7 new tests; all pass.
- [ ] Off-build: `bash scripts/run_tests.sh` baseline unchanged from Task 0 Step 2.
- [ ] On-build smoke gate: long-conn ≤10% drift (Task 11), short-conn ≤10% drift or noise-bounded (Task 12).
- [ ] Conformance suite still 36/36.
- [ ] Sidecar with new fields committed (Task 13).
- [ ] REFERENCE.md hypothesis-pass log entry committed with explicit verdict (Task 14).
- [ ] `PROFILE_ACCEPT: Bool = False` confirmed at branch HEAD post-capture.

## Out of scope (tracked, not implemented in this plan)

- **`bench/quic_perf/scripts/profile-capture.sh` helper** — Severity: optional. Trigger: if profile re-capture happens more than once after this spec.
- **`conn_pkt_counts` Dict size cap for very long captures (>10 min)** — Severity: optional. Trigger: if any capture exceeds 10 min run length.
- **Cold-start fix (multi-fiber fan-out OR batch FFI)** — Severity: required-later (HIGH). Trigger: this plan's Task 14 verdict is CONFIRMED.
- **Higher-resolution arrival-latency instrument** — Severity: required-later (HIGH if Task 14 INCONCLUSIVE). Trigger: Task 14 INCONCLUSIVE verdict.
