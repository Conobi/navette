# QUIC pacer bypass for handshake-space packets

> **Status:** spec | **Phase:** new hypothesis | **Date:** 2026-04-25

## Goal

Eliminate the cold-start handshake throughput floor that the calibrated bench
(`bench/quic_perf/results/REFERENCE.md`, 2026-04-25) exposes: mojo-net's
`h3_server` measures **412 req/s long-conn / 1 req/s short-conn** vs TQUIC's
**87,113 / 2,535** under saturating concurrency, while consuming **<6% of
one CPU core** on a single worker. The server is **not CPU-bound**; only
3–10 of ~400 attempted handshakes complete per 30 s window — the rest time
out before mojo-net releases the Handshake response.

The hypothesis under test (single hypothesis, smallest-fix-first): the
M4a-introduced pacer (`src/quic/cc/pacing.mojo`) is being applied to
**Initial and Handshake encryption-level packets**. Per `cubic.mojo:141-146`,
slow-start pacing rate is `2 × cwnd × 1e6 / srtt`; with the cold-start
default `cwnd = 10 × MDS` and `smoothed_rtt = INITIAL_RTT = 333 ms`, this is
~60 KiB/s. The first datagram passes the gate (the token bucket refills to
`PACER_MIN_BURST_PACKETS × MDS = 12 KiB` instantly when `last_sched_time = 0`),
but **every subsequent datagram in the same burst** must wait
`MIN_DATAGRAM_SIZE × 1e6 / pacing_rate ≈ 20 ms` for the bucket to refill
enough for one more `MIN_DATAGRAM_SIZE`. Under single-fiber serial
processing of a multishot recvmsg burst (`bench/h3_server.mojo:523-600`),
this back-pressure on the *stream* of Initials/Handshakes the server tries
to emit pushes ~100 concurrent client handshakes past their handshake
timeout (~1 s).

This spec specifies the surgical change to **bypass the pacer for any
connection that has not yet reached the `CONN_ESTABLISHED` state**.
Anti-amplification (`_anti_amp_ok`) and congestion-window checks are
preserved unchanged — they are the actual safety floors for handshake
bandwidth, and they suffice to satisfy RFC 9002 §7's normative
"use pacing OR limit bursts to the initial congestion window" requirement
during the handshake phase.

**Reference-implementation consensus is split** (verified 2026-04-25
against the upstream source repos): **picoquic** ships this exact design
(`picoquic/sender.c`'s pacing gate is applied only on the 1-RTT /
application-data send path, not on the Initial or Handshake send paths).
**quinn**, **TQUIC**, **ngtcp2**, and **quiche** all pace every encryption
level uniformly. mojo-net's bypass is therefore the minority approach but
is RFC-compatible: RFC 9002 §7 contains no normative requirement to pace
Initial/Handshake specifically, only the combined "pace OR limit bursts to
the initial congestion window" clause that the retained anti-amp + cwnd
checks already satisfy.

## Why this is RFC-correct

- **RFC 9002 §7** ("Pacing") is informative, not normative; the document is
  silent on whether handshake packets should be paced.
- **RFC 9000 §8.1** (anti-amplification) provides the actual handshake-phase
  safety floor: a server may send at most 3× the bytes received from an
  unvalidated peer. This check stays in place.
- **picoquic** ships exactly this design — the pacing gate
  (`picoquic_is_sending_authorized_by_pacing`) is wired into the 1-RTT /
  application-data send path only, never on the Initial / Handshake
  prepare paths.
- **TQUIC**, **quinn**, **ngtcp2**, **quiche**: pace every encryption
  level uniformly. mojo-net's bypass diverges from these stacks. Aligning
  with picoquic's design is acceptable for mojo-net because the bypass is
  bounded by the same anti-amp + cwnd checks those stacks also enforce
  during handshake — the practical burst shape is the same; only the
  inter-packet pacing delay during Initial/Handshake differs.
- **mojo-net's M4a CUBIC milestone** (`plans/2026-04-15-m4a-quic-cc-core.md`)
  added a universal `_can_send` gate that did not distinguish encryption
  level. Pacing handshakes was an unintended side-effect of that
  consolidation, not a deliberate design choice.

## Scope

### In scope

1. **Bypass the pacer in `_can_send`** (`src/quic/connection.mojo:2652-2662`)
   when `(self.state & CONN_ESTABLISHED) == 0` — i.e. handshake not yet
   confirmed.

2. **Bypass the pacer in `_next_timeout`'s pacer branch**
   (`src/quic/connection.mojo:2374-2382`) under the same condition. Without
   this, the timer-driven wakeup deadline still defers to the pacer
   deadline, re-introducing throttling when no UDP recv events drive the
   loop.

3. **Preserve `_anti_amp_ok`** (line 2655) and the CC `cwnd` check
   (line 2657) unchanged. These remain on the gate path for all encryption
   levels.

4. **Gate the post-send pacer commit** (`src/quic/connection.mojo:1776-1778`)
   under `if space_idx == 2:`. Today the `pacer.refill_and_check` +
   `pacer.on_sent` calls run inside the `for space_idx in range(3)` loop
   for **every** encryption level. With the gate bypass in place, handshake
   packets pass the gate and reach this site; without this guard they would
   still drain the token bucket on Initial/Handshake sends, partially
   defeating the bypass for the first 1-RTT packets that follow. Symmetric
   with the gate change: the entire pacer interaction (gate + commit) is
   now App-space only.

5. **Unit test** asserting `_can_send` returns `True` on a fresh
   `QuicConnection` (state lacking `CONN_ESTABLISHED`) regardless of pacer
   token state. Specifically: construct a server connection, advance state
   minimally so anti-amp + cwnd allow a send, force the pacer into a
   "next_send_time = now + 50ms" condition, assert `_can_send(1200, now)`
   returns `True`.

6. **Validation gate**: re-run
   `bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 3`
   (single-cell median over 3 iterations, ~2 min wallclock) and assert
   `req/s ≥ 4,000` (≥ 10× the current 412 req/s baseline). Three iterations
   over a single-iter sample because REFERENCE.md does not publish per-iter
   variance; median-of-3 removes single-sample noise. Hypothesis-confirmation
   threshold below.

7. **Full-matrix re-bench on confirmation**: `make bench-mvp` (3 iters per
   cell × 8 cells, ~50 min) and update
   `bench/quic_perf/results/REFERENCE.md` with the new numbers + a one-line
   diff against the prior REFERENCE.md.

### Out of scope (separate hypotheses, do NOT bundle)

- **What:** Multi-fiber accept / fan-out of multishot-recvmsg burst
  (`bench/h3_server.mojo:523-600` `on_flush` serial loop).
  **Severity:** required-later. **Trigger:** if the surgical pacer bypass
  yields < 10× rps improvement, this is the next hypothesis to test.

- **What:** Connection-pool / `QuicConnection` slab pre-allocation.
  **Severity:** optional. **Trigger:** if profiling post-pacer-fix shows
  per-handshake allocation cost dominating CPU.

- **What:** Batch FFI for handshake-space crypto (extend the M4 Phase 2
  Batch FFI design from data-path 1-RTT to Initial + Handshake).
  **Severity:** optional. **Trigger:** if profiling post-pacer-fix shows
  rustls FFI lock contention dominating handshake wallclock.

- **What:** Initial cwnd expansion (10×MDS → 32×MDS, RFC 6928 / quinn
  default).
  **Severity:** optional. **Trigger:** revisit after the surgical fix
  lands; bundle would confound the pacer-bypass signal.

- **What:** CID Dict contention reduction (`bench/h3_server.mojo:537,575`
  lookup-then-insert split).
  **Severity:** optional. **Trigger:** if the next post-fix profile shows
  Dict-mutation cost on the recv hot path.

- **What:** Intra-process worker sharding.
  **Severity:** non-goal per project-context — multi-process via
  SO_REUSEPORT is the chosen scaling axis.

- **What:** Re-running the H2 / non-QUIC benchmarks.
  **Severity:** optional. **Trigger:** none expected; the change is QUIC-only.

## Design

### Code change (single-file, ~15 LoC delta across 3 locations)

**File:** `src/quic/connection.mojo`. Use the existing public predicate
`is_established()` (defined at line 2514) — `(self.state & CONN_ESTABLISHED) == 0`
inline elsewhere is the historical pattern, but the helper exists and reads
better on the gate site.

**Location 1:** `_can_send` (lines 2652-2662). Insert the handshake-bypass
**after** the anti-amp and cwnd checks, **before** the pacer check, so that
anti-amp and CC continue to gate handshake sends correctly:

```mojo
def _can_send(self, size: UInt64, now: UInt64) -> Bool:
    """Composite send gate: anti-amplification + CC window + pacer (non-mutating).
    Token consumption happens via Pacer.refill_and_check at the actual send site.

    The pacer is bypassed for connections that have not yet reached
    CONN_ESTABLISHED. Pacing handshake-space packets caused cold-start
    throughput collapse (see specs/2026-04-25-quic-pacer-bypass-handshake.md).
    Anti-amplification and CC cwnd are the safety floors during handshake.
    """
    if not self._anti_amp_ok(size):
        return False
    if self.recovery.cc.cwnd() < self.recovery.bytes_in_flight + size:
        return False
    if not self.is_established():
        return True
    var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
    if self.recovery.pacer.next_send_time(rate, now):
        return False
    return True
```

**Location 2:** `_next_timeout`'s pacer branch (lines 2374-2382). Skip the
pacer-deadline contribution when handshake is incomplete:

```mojo
# --- Pacer branch ---
# Pacer deadlines do not gate handshake-space sends (see _can_send).
if self.is_established():
    var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
    var pacer_deadline = self.recovery.pacer.next_send_time(rate, now)
    if pacer_deadline:
        if earliest:
            if pacer_deadline.value() < earliest.value():
                earliest = pacer_deadline
        else:
            earliest = pacer_deadline
```

**Location 3:** `process_send` post-send commit (lines 1776-1778). Today
this runs unconditionally inside the `for space_idx in range(3)` loop.
Gate it under `if space_idx == 2:` so handshake sends do not drain the
token bucket. Note: `recovery.on_packet_sent` at line 1774 stays
unconditional — it tracks bytes_in_flight + sent_records for the recovery
path, which is correct for all spaces.

```mojo
self.recovery.on_packet_sent(pkt_size, True, pn, now)
# Pacer commit is App-space only; matches the gate bypass in _can_send.
if space_idx == 2:
    var _pace_rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
    _ = self.recovery.pacer.refill_and_check(_pace_rate, now)
    self.recovery.pacer.on_sent(UInt64(pkt_size))
```

### Why `is_established()` and the `CONN_ESTABLISHED` semantics

`CONN_ESTABLISHED` is the canonical "handshake confirmed, 1-RTT keys
installed" signal. It is written at three sites in `src/quic/connection.mojo`:

- **Line 1041** — client side, on receiving HANDSHAKE_DONE.
- **Line 1628** — server side, immediately after sending HANDSHAKE_DONE in
  `_on_handshake_complete`.
- **Line 1639** — late server path inside `_on_handshake_complete`'s
  follow-up branch.

The existing public predicate `is_established()` at line 2514 reads this
flag. We use that helper rather than inline bitwise checks because (a) the
helper exists, (b) it reads better at the gate, (c) compile-time inlining
makes the method-call cost zero. The earlier "inline state-flag pattern"
mentioned in code review is historic; new code can prefer the helper.

**Edge case (acknowledged):** there is a brief window during the handshake
where the server has installed 1-RTT keys via `take_keys` but
`CONN_ESTABLISHED` has not yet been set (between the TLS write_hs loop
finishing and `_on_handshake_complete` running). `process_send` (line 1696)
iterates all spaces with `has_keys`, so this window is reachable in
principle: an Application-space packet *could* be built and sent unpaced.
Impact analysis: the window is one iteration of `process_send` wide
(microseconds), and any 1-RTT data emitted in that window is bounded by
the same anti-amp and cwnd checks that gate handshake-space sends.
Acceptable; called out so a future profiling pass doesn't rediscover it
as a "surprise."

### Tests

**File:** `tests/test_quic_pacer_bypass.mojo` (new)

Three test functions. The construction explicitly forces the pacer into a
"would-block" state (default-constructed `QuicConnection` does NOT naturally
produce a non-`None` deadline because `last_sched_time = 0` makes
`elapsed = now`, refill saturates to capacity, deadline returns `None`).

1. `test_pacer_bypassed_during_handshake`:
   - Construct a server `QuicConnection` via the existing test helper used
     in `tests/test_quic_connection.mojo` (M3b integration tests).
   - Verify `not conn.is_established()`.
   - Set anti-amp + cwnd into states that would otherwise allow a send:
     ensure `conn.bytes_received >= 1` (anti-amp ok via 3× headroom),
     `conn.recovery.cc.cwnd() >= 1500` (cwnd ok).
   - Force the pacer into a "would-block" state with explicit field
     assignments:
     ```mojo
     conn.recovery.pacer.tokens = UInt64(0)
     conn.recovery.pacer.last_sched_time = now  # zero elapsed since "last sched"
     conn.recovery.smoothed_rtt = UInt64(333_000)  # μs; INITIAL_RTT
     ```
     With `tokens = 0`, `elapsed = 0`, `pacing_rate ≈ 60 KiB/s`, the next
     refill produces `tokens_projected = 0 < MIN_DATAGRAM_SIZE` ⇒
     `next_send_time` returns `Some(deadline)`. Verify by direct call:
     `assert pacer.next_send_time(rate, now) != None` (sanity check the
     setup before checking the bypass).
   - Assert `conn._can_send(1200, now) == True` (the bypass kicks in
     because `is_established() == False`).
   - Assert anti-amp still gates the unestablished case: with
     `bytes_received = 0`, `_can_send(1500, now)` must return `False`.

2. `test_pacer_active_after_handshake`:
   - Drive a connection to `is_established() == True` (use existing
     loopback handshake helper from `tests/test_quic_connection.mojo`).
   - Apply the same pacer "would-block" setup as test 1.
   - Assert `conn._can_send(1200, now) == False` (pacer now gates because
     `is_established() == True`).
   - Advance `now` by `(1200 * 1e6) / pacing_rate` μs + a small fudge;
     assert `_can_send == True`.

3. `test_handshake_padding_still_works`:
   - Drive a fresh client `QuicConnection` to send its first Initial
     flight (existing helper), then call `process_send` to produce a
     datagram.
   - Assert the produced datagram is `>= MIN_DATAGRAM_SIZE` (1200 bytes),
     confirming the handshake-padding logic at lines 1714-1728 still
     emits a padded Initial-only datagram. This catches any subtle
     interaction between the bypass and `_anti_amp_ok` accounting.

**Pre-fix expectations:**

- Test 1 currently passes on `main` because pacer.tokens = 0 + last_sched_time = now means refill produces 0 tokens (capacity not reached) AND `next_send_time` returns a deadline → `_can_send` returns False on `main`. Wait — that's the failing case. Let me re-read: on `main`, `_can_send` calls `pacer.next_send_time` unconditionally → returns Some(deadline) → `_can_send` returns False. So test 1 **fails on main** (asserts True, gets False). After the fix it passes.
- Test 2 passes on `main` (the "after handshake" behavior is unchanged) and continues to pass after the fix.
- Test 3 passes on both `main` and post-fix; it's a regression guard.

These tests reuse helpers already present in `tests/test_quic_connection.mojo`
(M3b integration tests). The pacer field-assignment pattern matches the
unit-test style in `tests/test_cc_pacing.mojo` (9 existing tests of the
`Pacer` struct directly; none assert pacer-active-during-handshake, so no
existing tests need updating).

### Backwards compatibility

- **Existing pacer tests:** `tests/test_cc_pacing.mojo` has 9 tests that
  exercise the `Pacer` struct directly (no `QuicConnection` integration);
  none assert pacer-active-during-handshake. No update required.
- **Existing recovery + connection tests:** `tests/test_quic_recovery.mojo`
  and `tests/test_quic_connection.mojo` reference the pacer in 47 grep
  hits across the three files (mostly construction + ECN + CC integration);
  spot-checked, none assert pacing-during-handshake at the connection
  level. Spec implementer should re-grep at implementation time and quote
  the audit result in the implementation commit message.
- **No public API change.** `_can_send` and `_next_timeout` are private
  helpers; `is_established()` is already public.
- **No FFI change.**

## Validation / acceptance criteria

The hypothesis is **confirmed** if all of the following hold:

| Gate | Source | Threshold |
|---|---|---|
| Conformance | `bash conformance/scripts/run_tests.sh` | 36/36 PASS, no regressions (35 existing + `test_h2_send_window_exhaustion` registered 2026-04-25) |
| Interop | `bash interop/test_local.sh` | All 3 cases pass: TESTCASE=handshake, TESTCASE=transfer, TESTCASE=zerortt-must-exit-127-as-unsupported |
| Bench single-cell | `bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 3` | median `req/s ≥ 4,000` (≥ 10× the 412 baseline) |
| Bench full matrix | `cd bench/quic_perf && make bench-mvp` | All 8 cells complete; long-conn rps strictly greater than current REFERENCE.md baseline; short-conn rps strictly greater than 1 req/s; mojo-net CPU% on the long-conn 1k cell crosses 30% (signal that the pacer was the floor and the server is now doing real work) |

If the single-cell gate is met but the full-matrix gate is not, ship the
change anyway — it's a strict improvement — and capture the next-hypothesis
data in REFERENCE.md.

If the single-cell gate is **not** met (req/s stays ≤ 4,000), the hypothesis
is falsified; **do not ship**. Open an open-question entry in
`docs/project-context.md`:

> **What:** Pacer was not the cold-start handshake floor. Next hypothesis
> needed (probably H2: serial single-fiber on_flush in `bench/h3_server.mojo`).
> **Severity:** required-later. **Trigger:** before any further QUIC perf
> work.

## Risks

1. **Anti-amplification regression.** Removing the pacer gate must NOT
   bypass `_anti_amp_ok`. The change preserves the order
   `anti-amp → cwnd → pacer-bypass-during-hs → pacer`. The existing M3b
   anti-amp test (`tests/test_quic_connection.mojo::test_anti_amplification`)
   is the canary.

2. **State-flag staleness.** Acknowledged in the design section above:
   there is a brief window where 1-RTT keys exist but `CONN_ESTABLISHED`
   is not yet set, and the proposed bypass would let early 1-RTT data
   through unpaced. Window is microseconds wide and bounded by anti-amp +
   cwnd. Acceptable; flagged for future profiling.

3. **Pacing tests asserting handshake-time behavior.** Verified at spec
   time: `tests/test_cc_pacing.mojo` (9 tests) exercises the `Pacer` struct
   directly with no `QuicConnection` integration; none assert
   pacer-active-during-handshake. `tests/test_quic_recovery.mojo` and
   `tests/test_quic_connection.mojo` have 47 grep hits combined for
   `pacer|next_send_time|refill_and_check`, mostly construction and ECN
   integration. Implementer should re-grep at implementation time and
   confirm "no behavior changes for established connections" still holds.

4. **REFERENCE.md churn.** If the hypothesis confirms, REFERENCE.md gets
   rewritten with materially different numbers (412 → ≥ 4,000+). The
   `make bench-mvp` step must run on the implementer's hardware, not in
   CI; document the host details in REFERENCE.md per the existing format.

## Implementation order

1. Write the three unit tests first (TDD). On `main`:
   - Test 1 (`test_pacer_bypassed_during_handshake`) **fails** —
     `_can_send` returns False because the pacer gates regardless of
     handshake state.
   - Test 2 (`test_pacer_active_after_handshake`) **passes** — established
     connections already gate on the pacer.
   - Test 3 (`test_handshake_padding_still_works`) **passes** — regression
     guard for padding logic.
2. Apply the three `connection.mojo` edits (Locations 1, 2, 3 above).
3. Verify all three unit tests pass.
4. Run full conformance + interop suites — both must stay green.
5. Run the bench single-cell gate (`--iters 3`).
6. If single-cell gate confirms, run `make bench-mvp` and update
   REFERENCE.md.
7. Commit-smart per logical step:
   - `test(quic): add pacer-bypass-during-handshake unit tests`
   - `fix(quic): bypass pacer for non-established connections`
   - `docs(bench/quic_perf): refresh REFERENCE.md after pacer-bypass landing`

## Out-of-scope items recap (for future hypothesis passes)

| What | Severity | Trigger |
|---|---|---|
| Multi-fiber accept fan-out | required-later | `< 10×` rps from this fix |
| QuicConnection slab pre-alloc | optional | profiling shows alloc cost dominates |
| Batch handshake FFI | optional | profiling shows rustls lock contention |
| Initial cwnd expansion | optional | always after this lands; never bundled |
| CID Dict contention | optional | profiling shows Dict mutation on hot path |
| Intra-process worker sharding | non-goal | use multi-process SO_REUSEPORT |

## References

- `bench/quic_perf/results/REFERENCE.md` — calibrated baseline (2026-04-25)
- `src/quic/connection.mojo:1041, 1628, 1639` — `CONN_ESTABLISHED` write sites
- `src/quic/connection.mojo:1696-1778` — `process_send` per-space loop (pacer commit at 1776-1778)
- `src/quic/connection.mojo:2374-2382` — `_next_timeout` pacer branch
- `src/quic/connection.mojo:2514-2516` — `is_established()` predicate
- `src/quic/connection.mojo:2652-2662` — `_can_send`
- `src/quic/cc/cubic.mojo:141-146` — `pacing_rate` slow-start formula (`2 × cwnd × 1e6 / srtt`)
- `src/quic/cc/pacing.mojo:65-92` — `next_send_time` token-bucket logic
- `bench/h3_server.mojo:523-600` — `on_flush` serial recvmsg-burst loop
- `tests/test_cc_pacing.mojo` — 9 existing pure-Pacer unit tests (none affected)
- `tests/test_quic_connection.mojo` — M3b loopback handshake helpers (used by new tests)
- `plans/2026-04-15-m4a-quic-cc-core.md` — origin of universal `_can_send`
- `plans/2026-04-15-m4a-quic-cc-core-retrospective.md` — pacer integration
  retrospective (pacing rate calc + token bucket details)
- RFC 9000 §8.1 — anti-amplification
- RFC 9002 §7 — pacing (informative)
