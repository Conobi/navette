# H3 `_drain_stream` sub-leg instrumentation — Spec

**Date:** 2026-05-01
**Status:** pending
**Predecessor:** Q1 (`specs/2026-04-29-quic-h3-phase-leg-instrumentation.md`, FF-merged at main `70ba90c`) named `quic_post_recv_us` at ~19.4M μs / 30s as the long-conn dominant phase. The bracket covers `_quic.timeout` + the H3 event poll-loop including `_drain_stream` inside `feed_datagram_from_buffer` (`src/h3/connection.mojo:259-317`).
**Type:** Diagnostic-only sub-leg pass (no RPS lift expected).
**Branch precondition:** new branch `feat/quic-h3-drain-stream-subleg` off main `7e2eb01`.
**Estimated LoC:** ~150-200 across `src/quic/profile.mojo` + `src/h3/connection.mojo` + `tests/test_quic_profile.mojo`.
**Predecessor research:** `research/2026-05-01-tquic-quiche-stream-read-paths.md` (TQUIC + quiche structural mirror); `research/2026-05-01-mojo-list-dict-batch-apis.md` (Mojo 0.26.2 idiom surface for the follow-on optimization).

---

## 1. Why

Q1 named `quic_post_recv_us` as the long-conn dominant at ~19.4M μs / 30s, but the bracket is broad: it covers `_quic.timeout(now)` + the entire poll-loop dispatching all 5 `QuicEvent` types including `STREAM_READABLE` → `_drain_stream`. The next optimization spec needs a measurement-grounded target inside this bucket — not another inspection-driven prediction. (Track record on this codebase: Subagent B's prediction was overturned by Q1; sub-leg pass's `write_hs ≥60%` prediction was overturned by `read_hs 93%`. Predicting from inspection has a 0/2 record.)

Topic 1 research confirmed that **TQUIC and quiche have zero H3-path timing instrumentation** (`ConnectionStats` is byte counters; `h3::Stats` is QPACK byte volumes). The "mirror their vocabulary" mandate is vacuous because they have no vocabulary. The mirror is **structural** — both reference FSMs size their `state_buf: Vec<u8>` to the next-state demand and `stream_recv` directly into it. mojo-net's `_H3StreamBuf.buf: List[UInt8]` as an unbounded accumulator + per-frame O(residual) shift has **no reference analogue**.

This spec defines net-new vocabulary for mojo-net and times the 5 sub-phases that map onto reference FSM stages where structure aligns + names the single mojo-net-only stage explicitly.

## 2. Scope

### In scope
- Add 6 fields + 6 record methods + JSON/text emit blocks to `AcceptProfile` in `src/quic/profile.mojo`
- Add 7 brackets in `src/h3/connection.mojo` (single-pair clock-read pattern, hoisted `var t_start: UInt64 = 0` per Q1 lessons)
- Add 6 unit tests in `tests/test_quic_profile.mojo`
- Capture pre/post baselines + SIGINT sidecars on both cells
- Update `bench/quic_perf/results/REFERENCE.md` with the new shipped-pass row

### Out of scope
- Any optimization fix to `_drain_stream` or `_parse_frames_from_buf` — that's the FOLLOW-ON spec, with the dominant-phase target chosen by this diagnostic.
- Changes to `src/quic/profile.mojo`'s existing fields/methods/emit shape (additive only).
- Changes to `bench/h3_server.mojo`'s cold-create call-site (Q1 already established the `@parameter if PROFILE_ACCEPT/else` split).
- Changes to QPACK encoder/decoder code paths.

## 3. Sub-leg taxonomy

5 sub-legs + 1 parent. Bracket sites cited at the line numbers in current main HEAD `7e2eb01`.

| Field | Covers | Bracket sites |
|---|---|---|
| `drain_stream_us_total` | Full `_drain_stream` invocation (parent for sum invariant). Suffix `_us_total` matches Q1's `quic_post_recv_us_total` convention. | `connection.mojo:406` entry to `:469` exit |
| `drain_recv_ffi_us` | `_quic.recv_stream_data(stream_id)` FFI + return-tuple alloc. | `:412` |
| `drain_buf_accumulate_us` | Architectural-gap cost: `recv_result[0].copy()` + per-byte append loop (`:413-419`) + Dict `.copy()` + reassign churn (`:417-460`) **+** residual rebuild loop (`:494-498`) per parse-iter. **Two physical brackets that both call `record_drain_buf_accumulate(elapsed)`; the field accumulates.** B3a fires once per `_drain_stream` invocation; B3b fires once per parse-iter inside `_parse_frames_from_buf`. | B3a: `:413` entry → `:460` exit (one contiguous region; the `_parse_frames_from_buf(...)` call at `:461` is OUTSIDE the bracket); B3b: `:494` entry → `:498` exit |
| `drain_frame_parse_us` | `parse_h3_frame(r)` only — varint frame_type + varint payload_len + payload slice (`:486`). Summed across parse-iters. | `:486` per parse-iter |
| `drain_qpack_decode_us` | `self._dec.decode(frame.payload)` only — QPACK static-table decode of the HEADERS field-section. | `:539` |
| `drain_event_dispatch_us` | Residual = `drain_stream_us_total - (recv_ffi + buf_accumulate + frame_parse + qpack_decode)`. Covers `H3Event` construction + `_h3_events.append(...)` paths in `_handle_request_frame` + `_handle_control_frame` + intra-method bookkeeping. | computed at emit time |

### Reference-stack analogues

| Sub-leg | TQUIC analogue | quiche analogue |
|---|---|---|
| `recv_ffi` | `read_and_fill_buffer` around `conn.stream_read` (`tquic/src/h3/stream.rs:435`) | `try_fill_buffer` around `conn.stream_recv` (`quiche/src/h3/stream.rs:452`) |
| `buf_accumulate` | **NONE — measure as 0.** state_buf written into directly. | **NONE — measure as 0.** state_buf[state_off..state_len] is the only buffer. |
| `frame_parse` | `parse_frame_type` + `parse_frame_payload_length` + `parse_frame_payload` (`stream.rs:336/400/524`) | `try_consume_varint`×2 + `try_consume_frame` (`stream.rs:565/585`) |
| `qpack_decode` | `qpack_decoder.decode` (`connection.rs:1122` → `qpack/qpack.rs:220`) | `qpack_decoder.decode` (`mod.rs:2980` → `qpack/decoder.rs:85`) |
| `event_dispatch` | `process_frame` match (`connection.rs:1438-1512`) + handler call in `process_streams` | `process_frame` match (`mod.rs:2922-...`) + caller match in user code |

`buf_accumulate` is the **mojo-net-only leg** — naming it explicitly quantifies the architectural gap.

## 4. Bracket placement (single-pair clock-read pattern)

All brackets follow Q1's pattern: `var t_start: UInt64 = 0` hoisted at function scope; `@parameter if PROFILE_ACCEPT: if Int(self.profile_ptr) != 0: t_start = monotonic_us()` at the entry point; `record_*(monotonic_us() - t_start)` at the exit point. Single pair per bracket (sub-leg pass T4 lesson). For sub-legs that accumulate across iterations, the record call is invoked per iteration with a fresh `t_start`.

### B1 — `drain_stream_us_total` (parent)
- Entry: `_drain_stream` at `:406` AFTER the `def _drain_stream(...)` signature AND AFTER the early `if key not in self._stream_bufs: return` guard at `:409-410`. The early-return at `:410` is OUTSIDE the bracket (we don't time invocations that early-out before any work).
- Exit sites: 4 in-bracket exit paths — explicit `return` at lines `:428`, `:443`, `:452`, plus implicit fall-through at `:469`. Each of the 4 exits MUST record `monotonic_us() - t_start` to the parent total.
- Pattern: `var t_start: UInt64 = 0` hoisted at function scope (right after the `:410` early-return); single guard at function entry sets `t_start = monotonic_us()` if profiling enabled; emit a `record_drain_stream(monotonic_us() - t_start)` block at each of the 4 exits.

### B2 — `drain_recv_ffi_us`
- Entry: just before `:412` `var recv_result = self._quic.recv_stream_data(stream_id)`.
- Exit: just after `:412`.
- One pair per call.

### B3 — `drain_buf_accumulate_us` (two physical brackets, accumulating field)
Two physical brackets, both emitting `record_drain_buf_accumulate(elapsed)`. The field accumulates each call.
- **B3a** — In `_drain_stream`. Fires **once per `_drain_stream` invocation** that reaches `:413`. Entry: just before `:413` `var new_bytes = recv_result[0].copy()`. Exit: just before `:461` `self._parse_frames_from_buf(stream_id, is_ctrl, now)`. Covers: recv-result copy + per-byte append loop + Dict copy/reassign churn + type-byte handling + bidi check.
- **B3b** — In `_parse_frames_from_buf`. Fires **once per parse-iter** inside the while-loop. Entry: just before `:494` `var new_buf = List[UInt8]()`. Exit: just before `:499` `if is_ctrl:`. Covers: residual rebuild + Dict reassign per iter.

Both brackets use the function-scope-hoisted `var t_start: UInt64 = 0` pattern; B3b reassigns `t_start = monotonic_us()` at the start of every iter body.

### B4 — `drain_frame_parse_us` (sum-across-iters)
- Entry: just before `:486` `frame = parse_h3_frame(r)` (after the `try:`).
- Exit: just after `:487` `consumed = r.pos`.
- One record call per parse-iter.

### B5 — `drain_qpack_decode_us`
- Entry: just before `:539` `var fields = self._dec.decode(frame.payload)`.
- Exit: just after `:539`.
- One record call per HEADERS frame.

### B6 — `drain_event_dispatch_us` (residual — no physical bracket)
Computed in BOTH `report_json` and `report_text` via a single private helper `_compute_drain_event_dispatch_us(self) -> UInt64` (so the two emit paths do not diverge):

```
def _compute_drain_event_dispatch_us(self) -> UInt64:
    var sum_legs = (self.drain_recv_ffi_us_total
                    + self.drain_buf_accumulate_us_total
                    + self.drain_frame_parse_us_total
                    + self.drain_qpack_decode_us_total)
    if sum_legs >= self.drain_stream_us_total:
        return UInt64(0)  # clamp-to-zero on overshoot
    return self.drain_stream_us_total - sum_legs
```

Clamp-to-zero handles two cases: (1) clock-read jitter where measured legs slightly exceed parent (small overshoot, expected within ε); (2) any accumulation bug where legs measure work outside the parent bracket (large overshoot, surfaces as Hard Gate 5 violation regardless of the clamp).

**Important:** the clamp does NOT silence Hard Gate 5. Hard Gate 5 (AC#6) checks `sum_legs ≤ drain_stream_us_total + ε` against the RAW unclamped sum read directly from the sidecar fields, not the clamped derived value. Clamp is for human-readable JSON/text only.

## 5. AcceptProfile additions (`src/quic/profile.mojo`)

### 5.1 New fields

After the existing Q1 phase-leg fields (`h3_drain_resp_us_total`, `quic_post_recv_us_total`, `h3_dispatch_us_total`):

```mojo
# Sub-leg decomposition of quic_post_recv_us → _drain_stream (Q1 follow-on, 2026-05-01)
var drain_stream_us_total: UInt64
var drain_recv_ffi_us_total: UInt64
var drain_buf_accumulate_us_total: UInt64
var drain_frame_parse_us_total: UInt64
var drain_qpack_decode_us_total: UInt64
```

(`drain_event_dispatch_us` is residual — not a stored field.)

Initialize all 5 to `UInt64(0)` in `__init__`.

### 5.2 New record methods

Six methods, all PROFILE_ACCEPT-gated trivially via the call-site `@parameter if`:

```mojo
def record_drain_stream(mut self, us: UInt64):
    self.drain_stream_us_total += us

def record_drain_recv_ffi(mut self, us: UInt64):
    self.drain_recv_ffi_us_total += us

def record_drain_buf_accumulate(mut self, us: UInt64):
    self.drain_buf_accumulate_us_total += us

def record_drain_frame_parse(mut self, us: UInt64):
    self.drain_frame_parse_us_total += us

def record_drain_qpack_decode(mut self, us: UInt64):
    self.drain_qpack_decode_us_total += us
```

(Convention matches existing Q1 methods at `src/quic/profile.mojo:284-290`: `def`, parameter `us: UInt64`.)

(No method for `event_dispatch` — derived in emit.)

### 5.3 JSON emit block (in `report_json`)

After the existing `h3_phases` block, add:

```json
"drain_stream_subleg": {
  "drain_stream_us_total": <value>,
  "recv_ffi_us": <value>,
  "buf_accumulate_us": <value>,
  "frame_parse_us": <value>,
  "qpack_decode_us": <value>,
  "event_dispatch_us": <total - recv_ffi - buf_accumulate - frame_parse - qpack_decode, clamp ≥ 0>,
  "sum_legs_us": <recv_ffi + buf_accumulate + frame_parse + qpack_decode + event_dispatch>,
  "unaccounted_pct": <(total - sum_legs) / total * 100, clamp ≥ 0>
}
```

### 5.4 Text emit block (in `report_text`)

Mirror the JSON shape with the existing comma-thousands + duration-us + percentage helpers. Format consistent with Q1's `h3_phases` text block.

### 5.5 Budget closure refresh

The `unaccounted_pct` computed in Q1 (against `quic_post_recv_us` minus H3 phase legs) is unchanged — this spec subtracts INSIDE `quic_post_recv_us` but does not alter Q1's residual. The sub-leg pass's own residual (`event_dispatch_us`) is reported separately and is bounded by `drain_stream_us_total`, not `quic_post_recv_us`.

## 6. Connection.mojo wiring (`src/h3/connection.mojo`)

### 6.1 Profile-pointer access
Already wired by Q1 as `self.profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]` on `H3Connection` (set via Shape B post-construction setter from `H3HandlerServer.__init__`). No new threading needed.

### 6.2 Brackets — implementation pattern

Each bracket uses the pattern verified in Q1 + sub-leg pass:

```mojo
var t_start: UInt64 = 0       # hoisted at function entry after early-return guards
@parameter
if PROFILE_ACCEPT:
    if Int(self.profile_ptr) != 0:
        t_start = monotonic_us()

# ... bracketed code ...

@parameter
if PROFILE_ACCEPT:
    if Int(self.profile_ptr) != 0:
        self.profile_ptr[].record_drain_<leg>(monotonic_us() - t_start)
```

For `_drain_stream` parent (B1), the record call must run on every return path. Mojo 0.26.2 has no `defer` / `try-finally` ergonomics that would simplify this — explicit record at each `return` site is the only correct pattern.

For B3 (`buf_accumulate`) split across two functions, each physical bracket emits an independent `record_drain_buf_accumulate(elapsed)` and the field accumulates.

For B4 + B5, the brackets sit inside per-iter while-loops. Each iteration uses its own `t_start` (re-hoisted at the start of the iteration body or reused at function scope and reassigned).

## 7. Tests (`tests/test_quic_profile.mojo`)

+6 unit tests, locked count. Match Q1's test-ownership style.

| # | Test name | What it validates |
|---|---|---|
| T1 | `test_record_drain_stream_increments_total` | `record_drain_stream(N)` increments the `drain_stream_us_total` field by N. |
| T2 | `test_record_drain_recv_ffi_increments_total` | Same for `recv_ffi`. |
| T3 | `test_record_drain_buf_accumulate_increments_total` | Same for `buf_accumulate`; verify multiple calls accumulate (not last-wins). |
| T4 | `test_record_drain_frame_parse_and_qpack_decode_independent` | Both methods on fresh AcceptProfile; verify they target separate fields. |
| T5 | `test_report_json_emits_drain_stream_subleg_block` | Construct AcceptProfile; record values; call `report_json()`; verify the `drain_stream_subleg` block exists with all 8 keys (5 legs + total + sum_legs + unaccounted_pct). |
| T6 | `test_drain_subleg_sum_invariant_residual` | Construct AcceptProfile; record total=1000; record legs summing to 800; call `report_json`; verify `event_dispatch_us == 200` (residual = total - sum_legs); verify `unaccounted_pct == 0`. |
| T7 | `test_drain_subleg_residual_clamp_overshoot` | Construct AcceptProfile; record total=1000; record legs summing to **1100** (deliberately exceeding total); call `report_json`; verify `event_dispatch_us == 0` (clamped); verify `report_text` produces the same clamped value. Guards against underflow-wrap regression in the residual computation. |

Pre-spec test count anchor: 48 (post-Q1) → post-spec target **55** via `TESTS_FILTER=test_quic_profile`. (T1+T2+T3+T4+T5 in T1 task = 5 tests; T6+T7 in T3 task = 2 tests; total +7.)

## 8. Acceptance criteria

| # | Description | Gate type |
|---|---|---|
| AC#1 | +7 unit tests pass via `bash scripts/run_tests.sh` filtered by `TESTS_FILTER=test_quic_profile` (count 48 → 55 with `^PASS:` prefix). | Hard |
| AC#2 | **Hard Gate 1** — long-conn `unaccounted_pct` (Q1's existing residual budget) ≤ 15% on `quic_post_recv_us`. Soft floor 15-25% = SHIPPED-with-caveat. | Hard |
| AC#3 | **Hard Gate 2** — on-build long-conn RPS drift ≥ −2.0% vs pre-baseline (n=10, median). | Hard |
| AC#4 | **Hard Gate 3** — on-build short-conn RPS drift ≥ −2.0% vs pre-baseline (n=10, median). | Hard |
| AC#5 | **Hard Gate 4** — off-build RPS drift ≥ −2.0% on BOTH cells (n=10, median). | Hard |
| AC#6 | **Hard Gate 5** — sub-leg sum invariant on RAW unclamped fields: `(recv_ffi + buf_accumulate + frame_parse + qpack_decode)_us_total ≤ drain_stream_us_total × (1 + ε)` in ALL 6 post sidecars (3 long + 3 short). **ε ≤ 5%** — chosen to absorb cumulative `monotonic_us()` jitter (Q1 measured per-call ~40-80ns; at 14k rps × ~3 brackets/event × 2 reads/bracket ≈ 84k reads/sec ≈ ~5ms/sec ≈ <0.5% of any leg by itself, but we widen the gate to 5% for compound multi-leg interactions and TLB-cold call paths). Higher than 5% = sum-invariant violation requiring root-cause investigation, not a clamp. The clamp-to-zero in `_compute_drain_event_dispatch_us` is for human-readable display only and does NOT affect this gate. | Hard |
| AC#7 | **Hard Gate 6** — `dcid_mismatch_pkts == 0` in all 12 sidecars (6 pre + 6 post). Q3 invariant preserved. | Hard |
| AC#8 | REFERENCE.md row appended at file tail with full AC table, image SHAs, dominant-phase verdict (no prediction recorded — verdict-only). | Hard |
| AC#9 | PROFILE_ACCEPT=False after T7 verified by grep on the source file. | Hard |

**Note on prediction:** Per user decision, this spec records **no predicted dominant phase**. The retrospective records what dominates as observed, without confirm/overturn framing.

## 9. Image hygiene + CPU gate

Per `feedback_bench_offbuild_image_hygiene.md`:
- Tag-isolate as `mojo-net-bench:drain-subleg-pre-{off,on}` and `mojo-net-bench:drain-subleg-post-{off,on}` (4 distinct images).
- Pass explicit `BOUCLE_DIR=/home/donokami/Projets/perso/boucle SIMDJSON_DIR=/home/donokami/Projets/perso/json-simd-mojo` env vars to `bench/build.sh`.
- CPU-load gate before each bench run (no parallel `mojo run` in other worktrees).

## 10. Plan structure (7 tasks: T0-T6)

- **T0** hard-gate (parent — branch off main `7e2eb01` + pre-spec test count anchor 48 + pre-migration off+on baselines [10-iter each] + n=3 long + n=3 short SIGINT sidecars + image tag isolation + revert PROFILE_ACCEPT)
- **T1** `src/quic/profile.mojo`: 5 fields + 5 record methods (`record_drain_stream`, `record_drain_recv_ffi`, `record_drain_buf_accumulate`, `record_drain_frame_parse`, `record_drain_qpack_decode`) + private `_compute_drain_event_dispatch_us` helper + JSON `drain_stream_subleg` block + text emit (subagent, TDD, **+5 tests**: T1 record_drain_stream, T2 record_drain_recv_ffi, T3 record_drain_buf_accumulate (verifies accumulation), T4 record_drain_frame_parse + record_drain_qpack_decode independent, T5 emit JSON block)
- **T2** `src/h3/connection.mojo` brackets (subagent — 7 physical brackets: B1 ×4 exit sites, B2 ×1, B3a ×1, B3b ×1, B4 ×1, B5 ×1)
- **T3** sum-invariant + clamp tests (subagent, TDD, **+2 tests**: T6 happy-path residual, T7 overshoot clamp)
- **T4** smoke gate ±2.0% on/off-build both cells (parent — 4 bench builds: drain-subleg-pre-{off,on} + drain-subleg-post-{off,on})
- **T5** SIGINT sidecar capture n=3 each cell on `mojo-net-bench:drain-subleg-post-on` + Hard Gates 1/5/6 verdict (parent)
- **T6** REFERENCE.md row + flag revert verified + project-context advance + final cross-cutting review (parent)

Test count: T1 ships 5, T3 ships 2; total **+7**. AC#1 anchor: 48 → 55.

## Appendix A — Pre-save scan

- ✅ Every AC#1-#9 maps to a task in §10
- ✅ No placeholders (TBD / TODO / "implement later")
- ✅ Test count locked at **+7** (T1 task ships 5; T3 task ships 2)
- ✅ Image hygiene + CPU gate enforced
- ✅ Single-pair clock-read pattern with hoisted `t_start`
- ✅ **Bracket nesting (not disjointness)**: B1 ⊇ {B2, B3a, B3b, B4, B5}. Sub-legs are mutually disjoint within B1 by construction (B2 wraps L412; B3a is L413→L460; B3b/B4 are inside `_parse_frames_from_buf`; B5 is inside `_handle_request_frame`). Sum invariant holds because parent contains all sub-legs and sub-legs do not double-count regions.
- ✅ Branch precondition: new branch off main `7e2eb01`
- ✅ All field names start with `drain_` to match the function under instrumentation
- ✅ Field naming convention: `<phase>_us_total` (matches Q1's `quic_post_recv_us_total`); method naming: `record_drain_<phase>` (matches Q1's `record_quic_post_recv`)
- ✅ No prediction recorded (per user decision)
- ✅ Reference-stack analogues cited per sub-leg
- ✅ B1 exit sites enumerated explicitly (`:428`, `:443`, `:452`, `:469`)
- ✅ Hard Gate 5 ε bound (≤5%) is justified, not silenced by the residual clamp
- ✅ Residual computation hoisted to private helper `_compute_drain_event_dispatch_us` to prevent JSON/text divergence

## Appendix B — Open questions for follow-on specs

1. **Optimization spec scope** — The follow-on spec should ship the full 4-fix bundle per Topic 2's "ship together" advice (bulk-extend, drop `.copy()` + reassign, bulk-shift via `extend(Span[n:])`, head-cursor pattern) because piecewise benching will under-attribute wins. Severity: required-later. Trigger: this diagnostic spec's retrospective.
2. **Whether to also remove `recv_stream_data`'s heap allocation** — TQUIC/quiche `stream_read`/`stream_recv` write into caller-provided `&mut [u8]` slices; mojo-net's FFI allocates a fresh `List[UInt8]` per call. Severity: required-later. Trigger: if `drain_recv_ffi_us` is ≥20% of `drain_stream_us_total`.
3. **HEADERS-only vs DATA-frame split for `drain_event_dispatch_us`** — If event_dispatch dominates, splitting by frame type (HEADERS H3Event vs DATA H3Event vs `_h3_events` Vec growth) may be needed. Severity: optional. Trigger: only if `event_dispatch ≥ 30%` of total.
