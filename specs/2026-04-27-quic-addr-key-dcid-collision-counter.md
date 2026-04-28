# QUIC `addr_key` ↔ DCID collision counter

**Date:** 2026-04-27
**Status:** brainstorming → review
**Branch precondition:** new branch off `main` (`bff4c42` post FF-merge of queueing-tail).

---

## Goal

Confirm or falsify the **`addr_key` demux collapse** hypothesis from the
**server's point of view**, by counting packets that arrive on an existing
`addr_key` whose DCID does not match the connection currently mapped to that
`addr_key`. The wire-level pcap
(`bench/quic_perf/results/profile/wire-capture-20260427-shortconn.pcap`) already
proves the collapse on the wire (4 src_ports × ~95 distinct Initial DCIDs each
= 378 logical conns colliding on 4 addr_keys). This counter cross-confirms it
inside the server and doubles as a **regression detector** for any future
DCID-demux migration: post-migration the counter must read ≈0.

The counter does **not** fix the bottleneck. It is a one-off diagnostic with a
specific verdict. The fix is a separate spec
(`addr_key→DCID demux migration`, scoped after this confirms).

---

## Background

Prior context lives in:

- `bench/quic_perf/results/REFERENCE.md` rows 280-388 — the queueing-tail
  hypothesis-pass entry, the verified-mechanism block from the wire-level
  pcap, and the explicit "next hypothesis" recommendation.
- `plans/2026-04-27-quic-queueing-tail-instrumentation-retrospective.md` lines
  101-119, 162-171 — open question listing this counter as a quick-diagnostic
  step (10-20 LoC core-counter estimate; revised here to ~180 LoC total
  after accounting for the per-addr_key mismatch dict, JSON + text rendering,
  the `is_expected_dcid` accessor on `QuicConnection`, four unit tests, and
  two capture sidecars + REFERENCE.md entry).
- `research/quic-connection-id-management.md` — RFC 9000 §5 + implementation
  survey. Confirms tquic, quiche, nginx-quic, lsquic all demux by DCID.

**Why this is needed despite the wire-level evidence.** The pcap is decisive
for `tquic_client` but tquic-specific. The retrospective also flags an open
question about whether `h2load --h3` exhibits the same pattern. A server-side
counter is harness-agnostic: any future capture (any client) can attest the
same number, and the counter stays in the build as a regression detector once
the migration ships.

**Why this is *not* the migration spec.** Sequencing decided in brainstorming:
diagnostic counter first → migration spec second. Locks the hypothesis with
server-side data before committing to the bigger refactor.

---

## Hypothesis under test

**H₁ (addr_key demux collapse — to confirm):** A server-side counter of
"packets with `_find_conn(pd.addr_key) ≥ 0` AND `pd.dcid` not matching the
mapped connection's expected DCID(s)" will read **high** under a short-conn
load (matching the pcap's ~95 distinct DCIDs per addr_key) and **≈0** under a
long-conn load (no DCID multiplexing in steady state).

**Hard verdict thresholds** (no ambiguity zone):

| Verdict | Short-conn cell | Long-conn cell |
|---|---|---|
| CONFIRMED | `dcid_mismatch_pkts ≥ 200` AND `addr_keys_with_mismatch ≥ 2` | `dcid_mismatch_pkts < max(10, 1% of total pkts seen on-build)` |
| FALSIFIED | `dcid_mismatch_pkts < max(10, 1% of total pkts seen)` | (any value) |
| INCONCLUSIVE | Short-conn 10-200 mismatch pkts, OR long-conn exceeds the FALSIFIED-threshold defined above | (combined with short-conn) |

CONFIRMED triggers sign-off to spec the migration. FALSIFIED restarts the
brainstorming. INCONCLUSIVE adds the `h2load --h3` cell as a follow-on
capture; if still INCONCLUSIVE, instrument further.

---

## Architecture

### Instrument 1 — DCID-mismatch packet counter

Two fields added to `AcceptProfile` (`src/quic/profile.mojo`):

```mojo
# Total packets where conn for pd.addr_key existed AND pd.dcid was not in
# the mapped conn's expected-DCID set.  Direct measure of demux failure.
var dcid_mismatch_pkts: UInt64

# Per-addr_key mismatch counts.  Same Dict shape as conn_pkt_counts.
# Surfaces which addr_keys had collisions and how many each.
var addr_key_mismatch_counts: Dict[String, UInt64]
```

One method:

```mojo
def record_dcid_mismatch(mut self, addr_key: String) raises:
    """Increment the global mismatch counter and the per-addr_key counter.

    Caller is responsible for the membership test (DCID-not-in-expected-set);
    this method only records.  Same shape as record_conn_pkt."""
    self.dcid_mismatch_pkts += 1
    if addr_key in self.addr_key_mismatch_counts:
        self.addr_key_mismatch_counts[addr_key] = (
            self.addr_key_mismatch_counts[addr_key] + 1)
    else:
        self.addr_key_mismatch_counts[addr_key] = 1
```

### Instrument 2 — `is_expected_dcid` accessor on `QuicConnection`

Single read-only accessor added to `src/quic/connection.mojo`:

```mojo
fn is_expected_dcid(self, dcid: Span[UInt8, _]) -> Bool:
    """Return True if dcid matches either the connection's initial_dcid
    (client's random Initial DCID, valid pre-handshake and during the brief
    post-handshake transition) or local_cid (the server's chosen SCID, which
    the peer uses as DCID after the first server Initial).

    Defensive against DCID rotation: not handled here — connection migration
    is a project non-goal in v1 (docs/project-context.md line 28).  Once a
    NEW_CONNECTION_ID emission lands the accessor expands to a set membership."""
```

Single bool surface lets `bench/h3_server.mojo` ask "is this packet's DCID
the right one for this conn?" without learning anything about the dual-DCID
state machine. Both `initial_dcid` (line 300) and `local_cid` (line 478, 570)
are already stored on `QuicConnection`; the accessor is byte-equality on each.

### Instrument 3 — Increment site in `_flush_impl`

One block added to `bench/h3_server.mojo`'s per-packet loop, alongside the
existing `record_conn_pkt` / `record_conn_hs_complete` calls:

```mojo
@parameter
if PROFILE_ACCEPT:
    if conn_idx >= 0:
        if not conn_h3s[conn_idx][]._h3._quic.is_expected_dcid(Span(pd.dcid)):
            self.profile.record_dcid_mismatch(pd.addr_key)
```

Uses the verified `_h3._quic` access path (same one queueing-tail used for
`is_established()`).  PROFILE_ACCEPT-gated → zero off-build cost. Only runs
when `_find_conn` returned a hit; misses (new addr_key) are never collisions
and skip the check.

**Stale-conn-replacement bias.** When an addr_key is reused after eviction
(swap-and-pop in `_handle_timeout`), a freshly-created replacement
`QuicConnection` has its own fresh `local_cid`. The replacement's first
incoming Initial — which still has `pd.dcid` set to its own random
`initial_dcid` — will NOT register a mismatch (the accessor matches both
`initial_dcid` and `local_cid`). Subsequent Initials of *new* logical conns
collapsing onto that addr_key DO register mismatches. The retrospective
flagged this asymmetry (lines 147-153); the pcap cross-check (~95
distinct DCIDs per port) absorbs the noise: even pessimistic over-counting
of replacement-firsts contributes O(distinct-conns) ≪ the headline mismatch
count.

### Instrument 4 — Sidecar JSON additions

Two new top-level keys added to `report_json`:

```json
"addr_key_dcid_mismatch": {
  "dcid_mismatch_pkts": 376,
  "addr_keys_total": 4,
  "addr_keys_with_mismatch": 4,
  "per_addr_key": {
    "ip:port:34130": 95,
    "ip:port:34131": 93,
    "ip:port:34132": 95,
    "ip:port:34133": 96
  }
}
```

`addr_keys_total` and `addr_keys_with_mismatch` are computed at flush time
from the dict; the `per_addr_key` map is dumped raw (bounded by ~few entries
in practice, matching `conn_pkt_counts`'s existing pattern).

`report_text` mirrors with a one-paragraph block.

---

## File structure

```
src/quic/connection.mojo                         + 8-15 LoC  (one accessor)
src/quic/profile.mojo                            + ~70 LoC   (2 fields, 1 method, JSON, text)
bench/h3_server.mojo                             + ~6 LoC    (one PROFILE_ACCEPT block)
tests/test_quic_profile.mojo                     + ~70 LoC   (4 unit tests)
bench/quic_perf/results/profile/
  INSTRUMENTATION-<date>-collision-shortconn.json (capture, ~1.5 KB)
  INSTRUMENTATION-<date>-collision-longconn.json  (capture, ~1.5 KB)
  T5_T6_smoke_gate_<date>.md                      (smoke baseline, ~2 KB)
bench/quic_perf/results/REFERENCE.md             + ~80 LoC   (hypothesis-pass entry)
docs/project-context.md                          + 1 phase line
```

**Total: ~180 LoC + 2 sidecars.**

---

## Testing

### Unit tests (`tests/test_quic_profile.mojo`)

1. `test_record_dcid_mismatch_increments` — call once, assert
   `dcid_mismatch_pkts == 1` and `addr_key_mismatch_counts[k] == 1`.
2. `test_record_dcid_mismatch_accumulates` — call N times across two addr_keys,
   assert global count and per-addr_key counts both correct.
3. `test_report_json_collision_block_present` — assert the
   `addr_key_dcid_mismatch` block exists with all four keys; per-addr_key
   round-trips correctly.
4. `test_report_text_collision_block_present` — assert the corresponding text
   block renders without crashing.

For the connection-side accessor, one new test in
`tests/test_quic_connection.mojo` (or wherever existing connection tests
live):

5. `test_is_expected_dcid_initial_and_local` — construct a `QuicConnection`
   with a known `initial_dcid` and `local_cid`, assert `is_expected_dcid`
   returns True for both, False for a third arbitrary DCID.

### Smoke gate (acceptance)

Mirror queueing-tail T11/T12. Both cells must show ≤10% drift on-build vs
off-build before any capture is taken.

- **Long-conn cell:** `tquic_client --threads 4 --max-concurrent-conns 25 --max-requests-per-conn 1000`, 30s, `/json/50?m=6`.
- **Short-conn cell:** `--max-requests-per-conn 1` else identical, 30s.

Smoke baseline written to `T5_T6_smoke_gate_<date>.md`. PASS = both within
±10%. FAIL = stop, investigate the per-packet branch cost before capturing.

### Conformance

Existing 36/36 conformance tests must continue to pass. The accessor on
`QuicConnection` is read-only and doesn't touch the state machine.

---

## Acceptance criteria

1. All 4 unit tests in `test_quic_profile.mojo` pass under the project's
   default build (`PROFILE_ACCEPT=False`). Tests construct `AcceptProfile`
   directly and exercise the new fields/methods unconditionally — the
   PROFILE_ACCEPT comptime gate scopes the bench-side *insertion*, not the
   profile module's API. (Same convention as the existing 18 queueing-tail
   tests at `test_record_arrival_lat_*`, etc.) An on-build smoke compile
   (`PROFILE_ACCEPT=True`) is performed separately as part of the smoke
   gate, but does not duplicate the unit-test matrix.
2. `test_is_expected_dcid_initial_and_local` passes.
3. Smoke gate ≤10% drift on both long-conn and short-conn cells.
4. Conformance suite 36/36 passes.
5. Off-build flag confirmed `comptime PROFILE_ACCEPT: Bool = False` after
   capture, before any commit on `main`.
6. Two sidecar JSONs committed (one per cell), labelled with timestamp +
   cell shape.
7. REFERENCE.md hypothesis-pass entry written, with mandatory re-read of
   every prior row first (Plan-C-codified methodology gate). Entry includes:
   - The verdict (CONFIRMED / FALSIFIED / INCONCLUSIVE) with explicit numbers.
   - Cross-check table: server-side `per_addr_key` counts vs. pcap
     per-port DCID counts (93, 95, 95, 96).
   - The `is_expected_dcid` definition note (why we accept both `initial_dcid`
     and `local_cid` as expected).
   - Off-build flag re-confirmation.
8. `docs/project-context.md` phase advanced through brainstorming → planning
   → implementing → reviewing.

---

## Non-goals

- **Demux migration itself.** Counter only. The migration is the *next* spec,
  triggered by a CONFIRMED verdict here.
- **DCID rotation handling.** Connection migration is a project non-goal in
  v1 of M3. Accessor only reads `initial_dcid` and `local_cid`; rotation
  expands the accessor to a set membership when NEW_CONNECTION_ID emission
  lands.
- **Cross-client capture (`h2load --h3`).** Listed as a separate next-step in
  the queueing-tail retrospective. This spec uses `tquic_client` only,
  matching the existing pcap.
- **Always-on counter.** PROFILE_ACCEPT-gated like all other `AcceptProfile`
  state. Diagnostic, not production.
- **Automated regression detection.** This counter is a **manual** regression
  detector — operators capture a sidecar after the future demux migration
  ships and confirm `dcid_mismatch_pkts` reads near-zero. CI does NOT run a
  capture nor fail on non-zero readings. Wiring it into CI is a follow-up
  spec if and when the migration ships.
- **Worst-offenders raw list.** Pcap evidence shows uniform-blowout pattern
  (4 addr_keys all in 80+ DCID territory). Per-addr_key map is sufficient;
  no top-N list needed.

---

## Constraints

- **Mojo 0.26.2 conventions** per `docs/project-context.md` line 62 — `def`
  for trait/ordinary methods, `raises` propagation for `Dict` access.
- **Sans-I/O at every protocol layer.** The accessor on `QuicConnection`
  reads existing state; no I/O imports added.
- **Bench-only change in `bench/h3_server.mojo`.** No new logic in
  `src/h3/` or `src/quic/connection.mojo` beyond the single accessor.
- **Coexistence with prior queueing-tail counters.** New JSON keys live
  beside existing `arrival_lat_us_*`, `conn_pkt_counts`, `conn_hs_complete`
  blocks; no rename, no removal.

---

## Dependencies / preconditions

1. Branch off `main` at `bff4c42` (queueing-tail merged).
2. T0 hard-gate: `PROFILE_ACCEPT == False` confirmed on the new branch's
   first commit; smoke baseline (off-build) re-captured before any source
   change.
3. Mojo MCP verification (executed as part of T0, BEFORE any TDD task):
   - `List[UInt8]` byte-equality semantics in Mojo 0.26.2 match the
     `is_expected_dcid` design (else fall back to a `_dcid_equals` byte-loop
     helper before T1).
   - `Span[UInt8, _]` lifetime parameter on a method-receiver argument
     compiles cleanly in 0.26.2 (else change accessor signature to
     `List[UInt8]` and update T3's tests accordingly).
   Locking these shapes at T0 prevents T1 tests being rewritten after T3.
4. Existing pcap (`wire-capture-20260427-shortconn.pcap`) available for
   cross-check; per-port DCID histogram already known (93, 95, 95, 96).

---

## Open questions

1. **`is_expected_dcid` placement.** Four candidates:
   (a) method on `QuicConnection` (recommendation — reads connection state directly);
   (b) method on `H3HandlerServer` as a delegating wrapper;
   (c) free function in `src/quic/header.mojo` taking a borrowed `QuicConnection` ref (no method-set pollution but extra parameter at the call site);
   (d) free function in `src/quic/connection.mojo` adjacent to `QuicConnection`, same pros/cons as (c) but co-located.
   Decided at planning time after one Mojo MCP probe of method-vs-free-function ergonomics on a borrowed receiver.
2. **Edge case: `initial_dcid` is empty.** Pre-construction or zero-length
   case. The accessor returns False if both reference DCIDs are empty
   (incoming bytes never match empty). Document explicitly in the accessor
   docstring.
3. **Counter granularity in long-conn.** Long-conn cell expected to show
   `dcid_mismatch_pkts ≈ 0`. If it instead reads non-zero (e.g. NEW_CONNECTION_ID
   handshake transitions), is that INCONCLUSIVE or a known-edge-case? Resolution:
   document numeric threshold for "≈0" (e.g. < 1% of total packets seen)
   in the spec acceptance section before capture.
4. **Span vs List[UInt8] argument shape on accessor.** `Span[UInt8, _]`
   is more flexible (doesn't require copy at the call site) but `is_expected_dcid`
   is on the verified read-path so either works. Recommendation: `Span` to
   avoid the copy. Decided at planning time after confirming via Mojo MCP.

---

## Watch for

- **Per-packet branch cost.** The accessor adds two byte-equality checks
  per packet. PROFILE_ACCEPT-gated, so off-build is zero. On-build smoke
  gate must pass; if drift > 10%, consider hoisting the comparison to a
  cached `expected_dcid_hash` on `QuicConnection`.
- **List[UInt8] equality in Mojo 0.26.2.** Element-wise equality should
  work but verify before TDD. If it doesn't compile or behaves
  unexpectedly, fall back to a `_dcid_equals(a, b) -> Bool` byte-loop
  helper in `bench/h3_server.mojo` (~10 LoC).
- **Initial-DCID transition window.** During the brief client-uses-random-DCID
  → client-uses-server-SCID transition, the accessor returns True for both,
  so no false-positive mismatches are recorded. Documented in `is_expected_dcid`
  docstring.
- **Pcap cross-check fidelity.** Pcap counts per-src_port distinct Initial
  DCIDs (long-header packets only). The counter counts per-addr_key DCID
  mismatches across **all** packet types. **Numeric agreement band:** for
  CONFIRMED, each `per_addr_key` mismatch count must fall within
  ±25% of its matching pcap port's distinct-DCID count (i.e. 70-119 for a
  pcap port with 95 distinct DCIDs). Outside that band → INCONCLUSIVE,
  reconcile in REFERENCE.md before declaring a verdict.

---

## Plan shape (preview, ~9 tasks; written by atelier:writing-plans)

- **T0.** Hard-gate: branch off `main` at `bff4c42`; `PROFILE_ACCEPT`
  off-build verified; smoke baseline captured.
- **T1.** TDD: `record_dcid_mismatch` + 2 unit tests on `AcceptProfile`.
- **T2.** TDD: JSON + text rendering + 2 unit tests.
- **T3.** TDD: `is_expected_dcid` accessor on `QuicConnection` + 1 unit test.
- **T4.** Wire the increment in `bench/h3_server.mojo` `_flush_impl`.
- **T5.** Smoke gate (long-conn cell). PASS or stop.
- **T6.** Smoke gate (short-conn cell). PASS or stop.
- **T7.** SIGINT capture (long-conn cell, 30s). Sidecar JSON committed.
- **T8.** SIGINT capture (short-conn cell, 30s). Sidecar JSON committed.
- **T9.** Cross-check vs. pcap; REFERENCE.md hypothesis-pass entry; off-build
  flag re-confirmed; project-context advanced. Verdict pinned.
