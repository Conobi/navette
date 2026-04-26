# QUIC Accept-Loop Queueing-Tail Instrumentation

**Status:** spec
**Date:** 2026-04-27
**Predecessor:** `specs/2026-04-25-quic-accept-loop-instrumentation.md` (Plan A shipped to main; Plans B + C on `feat/quic-accept-loop-instrumentation`)

## Goal

Make the per-packet **arrival-to-processing queueing latency** and **per-connection packet trajectory** visible in the SIGINT-driven sidecar produced by `bench/h3_server.mojo`. Today's 5-phase profiler stamps `record_pkt` only on packets that successfully reached processing; it cannot see packets that sat in `pending_rx` until tquic_client's per-conn handshake timeout fired and the client gave up.

The output of this work is data — a sidecar JSON with two new instruments — and a single hypothesis-pass log entry in `REFERENCE.md` that confirms or falsifies the queueing-tail mechanism. **No fix is in scope.** Choosing between multi-fiber accept fan-out vs batch FFI as the cold-start fix is gated on this data.

## Background

The branch `feat/quic-accept-loop-instrumentation` has produced four superseded diagnoses on the calibrated 412 long-conn rps / 1 short-conn rps floors:

1. **FFI dominance** (Plan C C5). Falsified — FFI cost is real but only times processed packets; can't be the rate-limiter at 0.4-0.7 conn-arrivals/sec.
2. **Buffer-ring exhaustion** (post-Plan-C investigation). Falsified — six diagnostic counters in `bench/h3_server.mojo` (`enobufs_count`, `multishot_term_count`, plus 3 error counters + kernel `UdpRcvbufErrors`) all zero across multiple short-conn runs.
3. **Bench-harness limits** (commit `8c5325e`). Falsified by debate — `REFERENCE.md` rows 16-28 already contained N=2 cross-client validation: same hardware, same harness, both `tquic_client` AND `h2load --h3` drive `tquic_server` to 5-digit rps while bringing mojo-net to <1% of that. The harness can saturate; the bottleneck is in mojo-net.
4. **Server-side queueing under saturating-handshake load** (current working hypothesis). Serial single-fiber `_flush_impl` (~127µs FFI/packet × ~100 simultaneous Initials) creates a queueing tail >> tquic_client's per-conn handshake timeout; tquic_client's conn dies before the server's processing reaches its packets. **This is the hypothesis this spec instruments.**

The existing 6 diagnostic drop counters proved "packets that arrive are processed without error." This spec's instruments prove or disprove "packets arrive in time."

## Architecture

Two new instruments, both `PROFILE_ACCEPT`-gated (zero off-build overhead), both bench-local (no `src/quic/connection.mojo` changes):

### Instrument 1 — Arrival-to-processing latency histogram

The wall-clock interval between packet ingress at `_handle_recvmsg` and processing dispatch at the head of `_flush_impl`. Distinct from `per_pkt_total` (which times the *processing*, not the wait).

- A `UInt64 arrival_us` field is added to `PendingDatagram` in `bench/h3_server.mojo`. The field is always-present in the struct (8 bytes × ~100 pending entries = ~800 bytes — negligible) but only written/read when `PROFILE_ACCEPT` is True. **Default value: 0.** A doc-comment at the field declaration MUST warn: "Read only when `PROFILE_ACCEPT` is True; off-build the value is always 0 and any computed delta is meaningless." This avoids a silent-uninit hazard if a future commit accidentally reads the field on the off-build path (`delta = now - 0` would yield `now` without crashing).
- At the end of `_handle_recvmsg`, immediately before `pending_rx.append(...)`, stamp `arrival_us = monotonic_us()` gated by `if PROFILE_ACCEPT`.
- In `_flush_impl`, after the existing `now = monotonic_us()` at flush start, for each pending datagram: gated by `if PROFILE_ACCEPT`, compute `delta = now - pd.arrival_us` and call `profile_ptr[].record_arrival_lat(delta)`. `now` is the existing flush-start timestamp; the delta represents the wall-clock queueing wait until first processable opportunity.
- In `AcceptProfile` (`src/quic/profile.mojo`), add three fields:
  - `arrival_lat_us_buckets: List[UInt64]` (length 24, same power-of-2 layout as `per_pkt_total_buckets`)
  - `arrival_lat_us_overflow: UInt64`
  - `arrival_lat_us_total: UInt64`
- Add one method `record_arrival_lat(us: UInt64)` that increments the total, dispatches via `_per_pkt_bucket(us)` into `arrival_lat_us_buckets`, with overflow accounting.

### Instrument 2 — Per-connection packet counts + handshake-complete tracking

Per-`addr_key` packet count and a record of which `addr_key`s ever observed `is_established() == True`. The aggregated histogram + scalar reveals the population of "received N packets but never completed handshake."

- In `AcceptProfile`, add two dictionaries:
  - `conn_pkt_counts: Dict[String, UInt64]` — count per addr_key
  - `conn_hs_complete: Dict[String, Bool]` — presence used as Set semantics; value always `True`
- Add two methods:
  - `record_conn_pkt(addr_key: String)` — `conn_pkt_counts[k] = conn_pkt_counts.get(k, 0) + 1`
  - `record_conn_hs_complete(addr_key: String)` — `conn_hs_complete[k] = True` (idempotent)
- In `_flush_impl`, gated by `if PROFILE_ACCEPT`:
  - For each pending datagram, after the existing demux: `profile_ptr[].record_conn_pkt(pd.addr_key)`
  - After `feed_datagram_from_buffer`, poll `conn_h3s[conn_idx][]._h3.is_established()` (matches existing accessor pattern at `bench/h3_server.mojo:769` and `:854`); if True, call `record_conn_hs_complete(pd.addr_key)` (the dict's idempotency tolerates redundant calls on subsequent packets of the same conn)

**`is_established()` semantic — verified at spec time.** `src/quic/connection.mojo:2671-2673` defines `is_established()` as `(self.state & CONN_ESTABLISHED) != 0`. `CONN_ESTABLISHED` is set on the server path at `src/quic/connection.mojo:1779-1786` *atomically* with `events.append(QuicEvent.handshake_complete())`. There is no key-derivation-only intermediate state where `is_established()` flips True before the canonical handshake-complete signal fires. The diagnostic scalar `conns_with_pkts_no_hs_complete` is therefore well-defined: a conn with packets but no `CONN_ESTABLISHED` flip is, by construction, a conn whose handshake never completed.

### Instrument 3 — Sidecar JSON additions

In `report_text` and `report_json`, three new aggregated outputs computed at report time. The aggregated histogram and scalar are bounded; the top-50 raw list is capped.

- **Arrival-latency block:**
  ```json
  "arrival_lat_us_total": <UInt64 sum>,
  "arrival_lat_us_buckets": [b0, b1, ..., b23],
  "arrival_lat_us_overflow": <UInt64 count>
  ```
- **Per-conn aggregated block:**
  ```json
  "per_conn_pkts_buckets": [n_1, n_2_3, n_4_7, n_8_15, n_16_31, n_32_63, n_64_127, n_128_plus],
  "conns_total": <UInt64>,
  "conns_with_pkts_no_hs_complete": <UInt64>
  ```
  Computed by walking `conn_pkt_counts.items()`, dispatching each conn's packet count via the existing `_pkts_per_flush_bucket` helper. The scalar is `sum(1 for k in conn_pkt_counts if k not in conn_hs_complete)`.
- **Top-50 worst offenders:**
  ```json
  "worst_conns": [
    {"addr_key": "1.2.3.4:12345", "pkt_count": 8, "hs_complete": false},
    ...
  ]
  ```
  Reference algorithm: materialize `List[Tuple[String, UInt64]]` of `(addr_key, pkt_count)` for entries where `addr_key not in conn_hs_complete`, call `List.sort` on the materialized list with a key projecting `pkt_count` descending, and slice the first 50. If fewer than 50 candidates exist, output all of them. (Heap-select would be O(n log 50) but report time is non-hot; clarity wins.) Bounded sidecar regardless of run length.

`report_text` mirrors the JSON structure as a human-readable block: histogram bars (reusing `_fmt_leg` / bucket-distribution helpers), scalar lines, and a top-50 table (addr_key | pkt_count | hs_complete).

## File structure

| Path | Action | Single responsibility |
|---|---|---|
| `src/quic/profile.mojo` | modify | Add 5 fields + 3 record methods + 24-bucket arrival-latency dispatch + report_text/report_json sections + top-50 sort helper |
| `bench/h3_server.mojo` | modify | Add `arrival_us` field to `PendingDatagram`; 1 stamp site in `_handle_recvmsg`; 3 record sites in `_flush_impl` (record_arrival_lat, record_conn_pkt, record_conn_hs_complete) |
| `tests/test_quic_profile.mojo` | modify | Add tests for record_arrival_lat (bucket dispatch, overflow boundary), record_conn_pkt (counter increment), record_conn_hs_complete (idempotency, scalar computation), top-50 sort + cap, JSON round-trip parseable by python json.loads |
| `bench/quic_perf/results/REFERENCE.md` | append | After capture: 5th hypothesis-pass log entry interpreting the new sidecar fields |

No new files are created.

## Testing

### Unit tests (`tests/test_quic_profile.mojo`)

- `test_record_arrival_lat_buckets` — insert N values across bucket boundaries; verify dispatch and `arrival_lat_us_total` sum
- `test_record_arrival_lat_overflow` — insert value above 2^23 µs; verify `arrival_lat_us_overflow` increment
- `test_record_conn_pkt_increment` — record same addr_key 3 times; verify count = 3
- `test_record_conn_hs_complete_idempotent` — record same addr_key 5 times; verify only one entry; verify scalar `conns_with_pkts_no_hs_complete` excludes it
- `test_per_conn_aggregated_buckets` — populate dict with 50 conn-ids of varying counts; verify 8-bucket histogram totals match
- `test_worst_conns_sort_and_cap` — populate dict with 100 conn-ids of varying counts (some hs_complete, some not); verify top-50 list contains the 50 highest non-complete entries in descending pkt_count order
- `test_json_roundtrip` — emit full report_json with new fields; parse with `python -c 'import json, sys; json.loads(sys.stdin.read())'` (matches existing test_json_roundtrip pattern)

### Smoke gate (acceptance)

Two-cell on-build vs off-build drift, both with `--iters 3` and median-of-3 comparison. Mirrors Plan B B13 but adds the short-conn cell because that is the regime the new instrumentation will be captured under.

- **Cell 1 — long-conn:** `bench.sh mojo-net 1k long-conn tquic_client --iters 3`. Plan B B13 measured −0.40% on this cell with no Dict ops. Threshold ≤10%.
- **Cell 2 — short-conn:** `bench.sh mojo-net 1k short-conn tquic_client --iters 3`. This cell exercises hundreds-to-thousands of `Dict[String, UInt64]` ops/sec under saturating-handshake load. Threshold ≤10%.

**Fallback if either cell breaches 10%:** demote `record_conn_pkt` from per-packet to per-flush-aggregate. Concretely: in `_flush_impl`, accumulate a local `Dict[String, UInt64]` over the pending batch, then call a new `record_conn_pkts_batch(addr_key_counts: Dict[String, UInt64])` once per flush instead of N times per packet. This trades fidelity-per-packet for amortized Dict overhead. The smoke gate MUST then be re-run on both cells before the spec is accepted.

### Conformance

`bash scripts/run_tests.sh` continues to pass at the same baseline (33 loopback + test_quic_profile + test_quic_profile_wiring); pre-existing `test_tls_connection` failure (missing `rlsm_client_config_new_insecure` rustls FFI symbol) remains out-of-scope as documented.

## Acceptance criteria

1. New `AcceptProfile` fields land: `arrival_lat_us_buckets`, `arrival_lat_us_overflow`, `arrival_lat_us_total`, `conn_pkt_counts`, `conn_hs_complete`.
2. New `AcceptProfile` methods land: `record_arrival_lat`, `record_conn_pkt`, `record_conn_hs_complete`.
3. `report_json` and `report_text` both emit the three new sidecar blocks (arrival-latency, per-conn aggregated, top-50 worst offenders).
4. `bench/h3_server.mojo` stamps `arrival_us` on `PendingDatagram` and calls the three new record methods at the documented sites, all gated by `if PROFILE_ACCEPT`.
5. **Off-build (PROFILE_ACCEPT=False):** zero overhead. The Mojo compiler must elide all new measurement paths; verified by `bash scripts/run_tests.sh` baseline being unchanged from pre-spec baseline.
6. **On-build smoke gate:** ≤10% drift on `bench.sh mojo-net 1k long-conn tquic_client --iters 3` (off-build vs on-build, median of 3 iters each).
7. Conformance suite unchanged: 36/36.
8. `test_quic_profile` adds at least 7 new test cases (one per item in the unit-tests list) and all pass.
9. **Operational capture step.** Re-run short-conn capture using the manual `start-server.sh + run-tquic-client.sh + docker kill --signal=SIGINT bench-h3 + docker cp` pattern documented in Plan C retro. Sidecar JSON contains all three new blocks. Sidecar is committed alongside the spec deliverables.
10. **Hypothesis-pass log entry.** A new entry is appended to `bench/quic_perf/results/REFERENCE.md`. The entry MUST:
    - Cite the captured sidecar by filename
    - Apply a ≥2× signal threshold to the `arrival_lat_us` histogram, with three explicit verdicts (no ambiguity zone):
      - **CONFIRMED** if P99 ≥ 1,000,000 µs (1s, lower bound on tquic_client's per-conn handshake timeout)
      - **FALSIFIED** if P99 ≤ 100,000 µs (100ms)
      - **INCONCLUSIVE** if 100,000 µs < P99 < 1,000,000 µs. In this case, the entry MUST: (a) state inconclusive verdict explicitly; (b) capture a second 30s run and report both P99s; (c) if both still land in the gap, propose a higher-resolution instrument (e.g. tracing arrival timestamps to a separate per-conn-id histogram, or sampling 1-in-N raw arrival times into a circular buffer dumped on SIGINT) and STOP — do not write a fix spec on inconclusive data.
    - Note overflow-counter dominance: if `arrival_lat_us_overflow` ≥ 50% of `pkt_count`, the queueing tail exceeds the 24-bucket ceiling (~8.4s); this is itself CONFIRMED, the histogram bucketing is too coarse for the magnitude of the signal.
    - Report the scalar `conns_with_pkts_no_hs_complete`; values ≥ 50 corroborate; values ≤ 5 weaken the hypothesis
    - Cross-reference the top-50 worst-offenders list to spot pathological cases (e.g. one addr_key receiving 50+ packets without ever completing handshake)
    - Caveat: the captured arrival pattern is `tquic_client`-specific. `h2load --h3` (REFERENCE.md row 28) drives different absolute numbers; conclusions about *queueing under tquic_client's load shape* do not generalize trivially to other clients without a follow-up capture.
    - **Methodology gate (codified per Plan C retro):** before writing the entry, re-read every existing row of `REFERENCE.md` (currently 28+ data rows + 4 hypothesis-pass log entries) and explicitly state in the entry that this was done. The entry MUST flag any contradictions with prior rows and resolve them. Mechanical check: line-count `REFERENCE.md` and confirm the planner read all of it.
11. Outcome of the hypothesis-pass entry feeds the **next** spec decision: CONFIRMED → spec multi-fiber accept fan-out OR batch FFI (depending on whether the queueing comes from dispatch or per-packet processing); FALSIFIED → reopen the search with the new data in hand; INCONCLUSIVE → spec a higher-resolution instrument before any fix spec.

## Non-goals

- **DCID tracking.** Decided: addr_key only (Q1). DCID would help across address-rebinding but mojo-net does not migrate yet.
- **Full Dict dump in sidecar.** Decided: aggregated histogram + scalar + top-50 cap (Q2). Avoids unbounded sidecar growth on long captures.
- **Always-present (off-build) instrumentation.** Decided: PROFILE_ACCEPT comptime gate (Q3). Mirrors existing pattern in profile.mojo; zero off-build overhead.
- **`src/quic/connection.mojo` changes.** Handshake-complete is detected at bench-flush via `is_established()` poll. Connection-side instrumentation deferred (out-of-scope).
- **Any cold-start fix.** Diagnostic only. Multi-fiber fan-out, batch FFI, BufRing port: all deferred until this data lands.
- **Other clients (quiche-client, neqo-client).** N=2 cross-client validation already exists in `REFERENCE.md` rows 16-28 (`tquic_client` + `h2load --h3`). Adding more would be confirmation of an already-confirmed asymmetry, not new signal.
- **Test suite foundation work.** `test_tls_connection` FFI symbol failure and unrun interop matrix are tracked separately; mixing them into this spec would broaden scope past one capture cycle.

## Constraints

- **Mojo 0.26.2 (Docker-pinned).** No `^` move on stored field; no positional `InlineArray` fill; `UnsafePointer(to=...)` not `.address_of`. Established gotchas from Plans A/B carry forward.
- **No host-only Mojo features (0.26.3.dev).** All instrumentation must compile under 0.26.2; the `thin` qualifier issue from Plan B is the precedent.
- **`Dict[String, _]` lookup overhead.** At saturating-handshake load, hundreds of `record_conn_pkt` calls per second. The smoke gate is the safety net; if drift exceeds 10%, reduce frequency (e.g. record per-flush-aggregate rather than per-packet) before considering the spec complete.

## Dependencies / preconditions

- The branch `feat/quic-accept-loop-instrumentation` (HEAD `fefe435` post-correction) must be FF-merged to main BEFORE plan execution begins. The next plan writes against integrated code, not a feature branch. The user's pending h2-perf commits (`88e5812`, `ca19331`) ride along. **Owner of FF-merge: user** (per Plan C retro pattern — branch integration decisions are user-driven, not agent-driven; the planner verifies main HEAD before drafting tasks).
- Plan A's `src/quic/profile.mojo` infrastructure is in place: `monotonic_us`, `_per_pkt_bucket`, `_pkts_per_flush_bucket`, `_fmt_leg`, comma-formatter helpers. No new helper infrastructure required.
- Plan B's `bench/h3_server.mojo` instrumentation is in place: `profile_ptr` field, SIGINT handler with `Atomic[Int32]` flag, JSON sidecar writer using `interop.file_io.write_file`. No new I/O infrastructure required.

## Open questions

- **Out-of-scope, optional severity:** wrap the manual SIGINT-capture pattern (`start-server.sh + run-tquic-client.sh + docker kill -s SIGINT + docker cp + stop-server.sh`) in a `bench/quic_perf/scripts/profile-capture.sh <scenario>` helper. Plan C retro flagged this. Trigger: if profile re-capture happens more than once more after this spec.
- **Out-of-scope, optional:** sidecar size cap on `conn_pkt_counts` Dict for very long captures (>10 min). Currently `Dict[String, UInt64]` grows unbounded; ~10KB per 100 entries × ~12000 entries/hour = ~1.2 MB/hour. Acceptable for typical captures; flag if longer.
