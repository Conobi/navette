# H3 `_drain_stream` Sub-Leg Instrumentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decompose Q1's `quic_post_recv_us` (~19.4M μs / 30s long-conn dominant) into 5 named sub-legs (`recv_ffi`, `buf_accumulate`, `frame_parse`, `qpack_decode`, `event_dispatch` via residual) plus a parent `drain_stream_us_total`, so the follow-on optimization spec has a measurement-grounded target inside `_drain_stream` / `_parse_frames_from_buf`.

**Architecture:** Diagnostic-only — no semantic changes. PROFILE_ACCEPT-gated single-pair-clock-read brackets in `src/h3/connection.mojo` (already wired with `profile_ptr` from Q1). `AcceptProfile` gains 5 new `_us_total` fields, 5 record methods (Q1 convention `def record_X(mut self, us: UInt64)`), a private `_compute_drain_event_dispatch_us` helper for residual-with-clamp, and a `drain_stream_subleg` JSON block / text emit block. No predicted dominant phase — measure and report.

**Tech Stack:** Mojo 0.26.2 (project pin); `monotonic_us` from `src/quic/profile.mojo`; `@parameter if PROFILE_ACCEPT:` + `if Int(self.profile_ptr) != 0:` runtime guard pattern (verified by Q1).

---

## File structure

| File | Status | Responsibility |
|---|---|---|
| `src/quic/profile.mojo` | Modify | Add 5 fields after Q1's H3 phase totals; add 5 record methods after Q1's; add private `_compute_drain_event_dispatch_us(self) -> UInt64` helper; emit `drain_stream_subleg` JSON block (`report_json`) + matching text block (`report_text`) after the existing `h3_phases_us` blocks. |
| `src/h3/connection.mojo` | Modify | Add 7 physical brackets across `_drain_stream` (B1 parent + B2 + B3a), `_parse_frames_from_buf` (B3b + B4), `_handle_request_frame` (B5). Single-pair clock-read pattern with hoisted `var t_start: UInt64 = 0` per Q1 lessons. |
| `tests/test_quic_profile.mojo` | Modify | +7 unit tests appended at file tail (5 record methods + JSON emit + sum-invariant happy-path + overshoot-clamp). Register all 7 in `main()`. |
| `bench/quic_perf/results/profile/Q-drain-subleg_pre_baselines_2026-05-01.md` | Create (T0) | Pre-migration baselines record. |
| `bench/quic_perf/results/profile/Q-drain-subleg_post_evidence_2026-05-01.md` | Create (T5) | Post-migration evidence + Hard Gate verdicts. |
| `bench/quic_perf/results/REFERENCE.md` | Modify (T6) | Append shipped-pass row at file tail. |
| `docs/project-context.md` | Modify (T6) | Phase advance to `spec-quic-h3-drain-stream-subleg-reviewing`. |

---

## Task 0: Hard Gate — branch + pre-migration baselines + sidecars [PARENT-ONLY]

**Files:**
- Create: `bench/quic_perf/results/profile/Q-drain-subleg_pre_baselines_2026-05-01.md`

- [ ] **Step 1: Verify worktree state and main HEAD**
Run: `git worktree list && git -C /home/donokami/Projets/perso/mojo-net log main -1 --oneline`
Expected: `baseline-main` worktree present; main HEAD at `7e2eb01 docs: project-context advance to done — Q1 FF-merged to main 70ba90c` (or a newer post-Q1 commit if more advance commits landed).

- [ ] **Step 2: Create branch off main**
Run from baseline-main: `git switch main && git pull --ff-only && git switch -c feat/quic-h3-drain-stream-subleg`
Expected: clean switch; new branch tracks main.

- [ ] **Step 3: Anchor pre-spec test count**
Run: `TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | grep -c '^PASS:'`
Expected: `48`. Record exactly: `Pre-spec test count: 48`.

- [ ] **Step 4: Verify PROFILE_ACCEPT is currently False**
Run: `grep -n "alias PROFILE_ACCEPT" src/quic/profile.mojo`
Expected: `alias PROFILE_ACCEPT: Bool = False`. If True, fix to False before continuing.

- [ ] **Step 5: Build off-build pre-baseline image (PROFILE_ACCEPT=False)**
Run: `BOUCLE_DIR=/home/donokami/Projets/perso/boucle SIMDJSON_DIR=/home/donokami/Projets/perso/json-simd-mojo bash bench/build.sh 2>&1 | tee /tmp/drain-subleg-pre-off-build.log | grep -E "Successfully built|^ERROR"`
Then re-tag: `docker tag mojo-net-bench:latest mojo-net-bench:drain-subleg-pre-off`
Expected: `Successfully built <SHA>`; tag set.

- [ ] **Step 6: Capture pre-baseline off-build long-conn (n=10)**
Run: `MOJO_NET_IMAGE=mojo-net-bench:drain-subleg-pre-off bench/quic_perf/run_long_conn.sh 10 2>&1 | tee /tmp/drain-subleg-pre-off-long.log`
Expected: 10 RPS values printed. Compute median. Record in baselines markdown.

- [ ] **Step 7: Capture pre-baseline off-build short-conn (n=10)**
Run: `MOJO_NET_IMAGE=mojo-net-bench:drain-subleg-pre-off bench/quic_perf/run_short_conn.sh 10 2>&1 | tee /tmp/drain-subleg-pre-off-short.log`
Expected: 10 RPS values printed. Compute median. Record.

- [ ] **Step 8: Flip PROFILE_ACCEPT to True; build on-build pre-baseline image**
Run: `sed -i 's/alias PROFILE_ACCEPT: Bool = False/alias PROFILE_ACCEPT: Bool = True/' src/quic/profile.mojo`
Then: `BOUCLE_DIR=/home/donokami/Projets/perso/boucle SIMDJSON_DIR=/home/donokami/Projets/perso/json-simd-mojo bash bench/build.sh 2>&1 | tee /tmp/drain-subleg-pre-on-build.log | grep -E "Successfully built|^ERROR"`
Then: `docker tag mojo-net-bench:latest mojo-net-bench:drain-subleg-pre-on`
Expected: `Successfully built <SHA>`; tag set.

- [ ] **Step 9: Capture pre-baseline on-build long-conn (n=10) + short-conn (n=10)**
Run: `MOJO_NET_IMAGE=mojo-net-bench:drain-subleg-pre-on bench/quic_perf/run_long_conn.sh 10 2>&1 | tee /tmp/drain-subleg-pre-on-long.log`
Then: `MOJO_NET_IMAGE=mojo-net-bench:drain-subleg-pre-on bench/quic_perf/run_short_conn.sh 10 2>&1 | tee /tmp/drain-subleg-pre-on-short.log`
Expected: medians + per-iter values recorded.

- [ ] **Step 10: Capture n=3 pre-baseline SIGINT sidecars on-build (long + short)**
Run for each of 3 long-conn iters: `MOJO_NET_IMAGE=mojo-net-bench:drain-subleg-pre-on PROFILE_DUMP_PATH=bench/quic_perf/results/profile/INSTRUMENTATION-$(date +%Y%m%d-%H%M%S)-q-drain-subleg-pre-long-conn-iter${i}.json bench/quic_perf/run_long_conn.sh 1`
Then 3 short-conn iters with `q-drain-subleg-pre-short-conn-iter${i}` naming.
Expected: 6 JSON sidecar files; record `unaccounted_pct` and `dcid_mismatch_pkts` per iter.

- [ ] **Step 11: Revert PROFILE_ACCEPT to False before commit**
Run: `sed -i 's/alias PROFILE_ACCEPT: Bool = True/alias PROFILE_ACCEPT: Bool = False/' src/quic/profile.mojo`
Then verify: `grep -n "alias PROFILE_ACCEPT" src/quic/profile.mojo`
Expected: `False`.

- [ ] **Step 12: Write Q-drain-subleg_pre_baselines_2026-05-01.md**
Path: `bench/quic_perf/results/profile/Q-drain-subleg_pre_baselines_2026-05-01.md`. Mirror Q1's pre-baselines structure (image SHAs, off+on long+short medians + CV, n=3 SIGINT sidecar `unaccounted_pct` + `dcid_mismatch_pkts` table). Anchor: pre-spec test count 48.

- [ ] **Step 13: Commit T0**
Use the `commit-smart` skill. Message format: `bench: T0 pre-migration baselines (off+on build, 6x sidecars)`.

---

## Task 1: profile.mojo — fields + record methods + emit + helper [SUBAGENT, TDD]

**Files:**
- Modify: `src/quic/profile.mojo:118` (add 5 fields after the 3 H3 phase totals); `src/quic/profile.mojo:165` (init the 5 fields); `src/quic/profile.mojo:291` (add 5 record methods after `record_h3_dispatch`); `src/quic/profile.mojo:423` (text emit after `h3_phases` block); `src/quic/profile.mojo:639` (JSON emit after `h3_phases_us` block); plus a private helper just before `report_json`.
- Test: `tests/test_quic_profile.mojo` (append 5 tests at file tail; register in `main()`).

**Implementation context:** Q1 ships fields `h3_drain_resp_us_total` / `quic_post_recv_us_total` / `h3_dispatch_us_total` at lines 116-118 with init at 163-165; record methods `record_h3_drain_resp` / `record_quic_post_recv` / `record_h3_dispatch` at 284-291; text emit `H3 phases:` block at 419-423; JSON `h3_phases_us` block at 635-639. Mirror that placement.

- [ ] **Step 1: Write test T1 — record_drain_stream accumulates**
Append at the end of `tests/test_quic_profile.mojo` (after `test_budget_closure_subtracts_h3_legs`):
```mojo


def test_record_drain_stream_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain_stream(UInt64(123))
    p.record_drain_stream(UInt64(456))
    assert_equal_int(Int(p.drain_stream_us_total), 579, "drain_stream accumulates")
    print("PASS: test_record_drain_stream_increments_total")
```

- [ ] **Step 2: Verify it fails**
Run: `TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | tail -20`
Expected: FAIL — compilation error referencing missing `record_drain_stream` and/or `drain_stream_us_total`.

- [ ] **Step 3: Add 5 fields to AcceptProfile struct**
Edit `src/quic/profile.mojo`. After line 118 (`var h3_dispatch_us_total: UInt64`), add:
```mojo

    # 5 sub-legs of quic_post_recv_us → _drain_stream (Plan: 2026-05-01-quic-h3-drain-stream-subleg).
    # event_dispatch is computed via residual at emit time, no field.
    var drain_stream_us_total: UInt64
    var drain_recv_ffi_us_total: UInt64
    var drain_buf_accumulate_us_total: UInt64
    var drain_frame_parse_us_total: UInt64
    var drain_qpack_decode_us_total: UInt64
```

- [ ] **Step 4: Init the 5 fields**
After line 165 (`self.h3_dispatch_us_total = UInt64(0)`), add:
```mojo
        self.drain_stream_us_total = UInt64(0)
        self.drain_recv_ffi_us_total = UInt64(0)
        self.drain_buf_accumulate_us_total = UInt64(0)
        self.drain_frame_parse_us_total = UInt64(0)
        self.drain_qpack_decode_us_total = UInt64(0)
```

- [ ] **Step 5: Add 5 record methods after `record_h3_dispatch`**
After line 291 (`self.h3_dispatch_us_total = self.h3_dispatch_us_total + us`) — i.e. after the closing of `record_h3_dispatch` — add:
```mojo

    def record_drain_stream(mut self, us: UInt64):
        self.drain_stream_us_total = self.drain_stream_us_total + us

    def record_drain_recv_ffi(mut self, us: UInt64):
        self.drain_recv_ffi_us_total = self.drain_recv_ffi_us_total + us

    def record_drain_buf_accumulate(mut self, us: UInt64):
        self.drain_buf_accumulate_us_total = self.drain_buf_accumulate_us_total + us

    def record_drain_frame_parse(mut self, us: UInt64):
        self.drain_frame_parse_us_total = self.drain_frame_parse_us_total + us

    def record_drain_qpack_decode(mut self, us: UInt64):
        self.drain_qpack_decode_us_total = self.drain_qpack_decode_us_total + us
```

- [ ] **Step 6: Add private helper `_compute_drain_event_dispatch_us` just before `def report_json`**
Find `def report_json(self) -> String:` (search for it). Insert this method right before it:
```mojo

    def _compute_drain_event_dispatch_us(self) -> UInt64:
        """Residual = drain_stream_us_total - sum(measured legs), clamped ≥ 0.
        Clamp absorbs (a) clock-read jitter where measured legs slightly exceed parent
        and (b) any accumulation bug — large overshoot still surfaces as Hard Gate 5
        violation against the RAW unclamped fields."""
        var sum_legs = (self.drain_recv_ffi_us_total
            + self.drain_buf_accumulate_us_total
            + self.drain_frame_parse_us_total
            + self.drain_qpack_decode_us_total)
        if sum_legs >= self.drain_stream_us_total:
            return UInt64(0)
        return self.drain_stream_us_total - sum_legs
```

- [ ] **Step 7: Run T1 to confirm field+method PASS**
Run: `TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | grep "test_record_drain_stream"`
Expected: `PASS: test_record_drain_stream_increments_total`.

- [ ] **Step 8: Write tests T2-T5**
Append at file tail of `tests/test_quic_profile.mojo`:
```mojo


def test_record_drain_recv_ffi_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain_recv_ffi(UInt64(100))
    p.record_drain_recv_ffi(UInt64(200))
    assert_equal_int(Int(p.drain_recv_ffi_us_total), 300, "drain_recv_ffi accumulates")
    print("PASS: test_record_drain_recv_ffi_increments_total")


def test_record_drain_buf_accumulate_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Verify accumulation across multiple calls (B3a + B3b both call this method).
    p.record_drain_buf_accumulate(UInt64(11))
    p.record_drain_buf_accumulate(UInt64(22))
    p.record_drain_buf_accumulate(UInt64(33))
    assert_equal_int(Int(p.drain_buf_accumulate_us_total), 66,
        "drain_buf_accumulate accumulates across calls (B3a + B3b summed)")
    print("PASS: test_record_drain_buf_accumulate_increments_total")


def test_record_drain_frame_parse_and_qpack_decode_independent() raises:
    """Both methods on a fresh AcceptProfile target separate fields.
    Catches a future bug where frame_parse and qpack_decode aliased the same field."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain_frame_parse(UInt64(50))
    p.record_drain_qpack_decode(UInt64(75))
    assert_equal_int(Int(p.drain_frame_parse_us_total), 50, "frame_parse field independent")
    assert_equal_int(Int(p.drain_qpack_decode_us_total), 75, "qpack_decode field independent")
    # Cross-check: each call did NOT touch the other field.
    p.record_drain_frame_parse(UInt64(10))
    assert_equal_int(Int(p.drain_qpack_decode_us_total), 75,
        "qpack_decode unchanged after second frame_parse call")
    print("PASS: test_record_drain_frame_parse_and_qpack_decode_independent")


def test_report_json_emits_drain_stream_subleg_block() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain_stream(UInt64(10000))
    p.record_drain_recv_ffi(UInt64(1000))
    p.record_drain_buf_accumulate(UInt64(2000))
    p.record_drain_frame_parse(UInt64(500))
    p.record_drain_qpack_decode(UInt64(300))
    var out = p.report_json()
    # Spot-check: drain_stream_subleg block exists with all 8 keys.
    assert_true('"drain_stream_subleg":' in out, "drain_stream_subleg block missing")
    assert_true('"drain_stream_us_total":' in out, "drain_stream_us_total key missing")
    assert_true('"recv_ffi_us":' in out, "recv_ffi_us key missing")
    assert_true('"buf_accumulate_us":' in out, "buf_accumulate_us key missing")
    assert_true('"frame_parse_us":' in out, "frame_parse_us key missing")
    assert_true('"qpack_decode_us":' in out, "qpack_decode_us key missing")
    assert_true('"event_dispatch_us":' in out, "event_dispatch_us key missing")
    assert_true('"sum_legs_us":' in out, "sum_legs_us key missing")
    assert_true('"unaccounted_pct":' in out, "unaccounted_pct key missing")
    # Numeric spot-checks for raw fields.
    assert_true('"drain_stream_us_total": 10000' in out, "drain_stream value")
    assert_true('"recv_ffi_us": 1000' in out, "recv_ffi value")
    # Residual = 10000 - (1000+2000+500+300) = 6200.
    assert_true('"event_dispatch_us": 6200' in out, "event_dispatch residual=6200")
    # sum_legs = 1000+2000+500+300+6200 = 10000.
    assert_true('"sum_legs_us": 10000' in out, "sum_legs=10000")
    print("PASS: test_report_json_emits_drain_stream_subleg_block")
```

- [ ] **Step 9: Verify T2-T4 fail (no JSON block, no helper-aware emit)**
Run: `TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | grep -E "PASS|FAIL|test_record_drain_recv_ffi|test_record_drain_buf_accumulate|test_record_drain_frame_parse|test_report_json_emits_drain_stream_subleg" | tail -20`
Expected: T2/T3/T4 PASS (record methods exist after Step 5); T5 FAIL (JSON block not emitted yet).

- [ ] **Step 10: Add JSON `drain_stream_subleg` block in `report_json`**
Find the existing `h3_phases_us` JSON block (line 635-639). Right after `s += "  },\n"` that closes h3_phases_us, add:
```mojo
        var de_us = self._compute_drain_event_dispatch_us()
        var sum_legs_us = (self.drain_recv_ffi_us_total
            + self.drain_buf_accumulate_us_total
            + self.drain_frame_parse_us_total
            + self.drain_qpack_decode_us_total
            + de_us)
        var unacct_drain_pct: UInt64 = UInt64(0)
        if self.drain_stream_us_total > UInt64(0) and sum_legs_us < self.drain_stream_us_total:
            unacct_drain_pct = ((self.drain_stream_us_total - sum_legs_us) * UInt64(100)) / self.drain_stream_us_total
        s += '  "drain_stream_subleg": {\n'
        s += '    "drain_stream_us_total": ' + String(self.drain_stream_us_total) + ',\n'
        s += '    "recv_ffi_us":           ' + String(self.drain_recv_ffi_us_total) + ',\n'
        s += '    "buf_accumulate_us":     ' + String(self.drain_buf_accumulate_us_total) + ',\n'
        s += '    "frame_parse_us":        ' + String(self.drain_frame_parse_us_total) + ',\n'
        s += '    "qpack_decode_us":       ' + String(self.drain_qpack_decode_us_total) + ',\n'
        s += '    "event_dispatch_us":     ' + String(de_us) + ',\n'
        s += '    "sum_legs_us":           ' + String(sum_legs_us) + ',\n'
        s += '    "unaccounted_pct":       ' + String(unacct_drain_pct) + '\n'
        s += "  },\n"
```

- [ ] **Step 11: Add text `drain_stream_subleg` block in `report_text`**
Find the existing `H3 phases:` text block (lines 419-423). After line 423 (`s += "  dispatch.total:   " + _fmt_count(self.h3_dispatch_us_total) + "\n\n"`), add:
```mojo
        # Drain-stream sub-leg decomposition (Plan: 2026-05-01-quic-h3-drain-stream-subleg).
        var de_t_us = self._compute_drain_event_dispatch_us()
        s += "Drain-stream sub-legs:\n"
        s += "  drain_stream.total:     " + _fmt_count(self.drain_stream_us_total) + "\n"
        s += "  recv_ffi.total:         " + _fmt_count(self.drain_recv_ffi_us_total) + "\n"
        s += "  buf_accumulate.total:   " + _fmt_count(self.drain_buf_accumulate_us_total) + "\n"
        s += "  frame_parse.total:      " + _fmt_count(self.drain_frame_parse_us_total) + "\n"
        s += "  qpack_decode.total:     " + _fmt_count(self.drain_qpack_decode_us_total) + "\n"
        s += "  event_dispatch.derived: " + _fmt_count(de_t_us) + "\n\n"
```

- [ ] **Step 12: Register the 5 new tests in `main()`**
Find `def main() raises:` near line 992 of `tests/test_quic_profile.mojo`. Find `test_budget_closure_subtracts_h3_legs()` call (line 1040). After it, add:
```mojo
    test_record_drain_stream_increments_total()
    test_record_drain_recv_ffi_increments_total()
    test_record_drain_buf_accumulate_increments_total()
    test_record_drain_frame_parse_and_qpack_decode_independent()
    test_report_json_emits_drain_stream_subleg_block()
```

- [ ] **Step 13: Run all profile tests; verify count 48 → 53**
Run: `TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | grep -c '^PASS:'`
Expected: `53` (48 + 5).

- [ ] **Step 14: Run full test suite to verify nothing else broke**
Run: `bash scripts/run_tests.sh 2>&1 | tail -5`
Expected: `All 77/77 src tests passed.` (72 prior + 5 new). If any unrelated test fails, do not proceed; investigate.

- [ ] **Step 15: Commit T1**
Use the `commit-smart` skill. Message format: `feat: add 5 drain-stream sub-leg fields + record methods + emit`.

---

## Task 2: connection.mojo — 7 brackets [SUBAGENT]

**Files:**
- Modify: `src/h3/connection.mojo:406-469` (`_drain_stream` — B1 parent + B2 + B3a); `src/h3/connection.mojo:471-502` (`_parse_frames_from_buf` — B3b + B4); `src/h3/connection.mojo:536-554` (`_handle_request_frame` — B5).

**Implementation context:** Q1 already wired `self.profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]` on `H3Connection` (set via Shape B post-construction setter from `H3HandlerServer.__init__`). The `monotonic_us` and `PROFILE_ACCEPT` are already imported (Q1's import lines). All 7 brackets use the verified Q1 pattern: `var t_start: UInt64 = 0` hoisted at function scope; entry-side `@parameter if PROFILE_ACCEPT: if Int(self.profile_ptr) != 0: t_start = monotonic_us()`; exit-side `@parameter if PROFILE_ACCEPT: if Int(self.profile_ptr) != 0: self.profile_ptr[].record_drain_<phase>(monotonic_us() - t_start)`.

The current source as of main `7e2eb01`: `_drain_stream` is at `src/h3/connection.mojo:406`. Returns are at `:410` (early, OUT of bracket), `:428`, `:443`, `:452`, fall-through at `:469`. `_parse_frames_from_buf` is at `:471`; the residual rebuild is at `:494-498`; `parse_h3_frame` call is at `:486`. `_handle_request_frame` is at `:536`; `_dec.decode` is at `:539`.

- [ ] **Step 1: Read current state of `_drain_stream`**
Run: `awk 'NR>=405 && NR<=470' src/h3/connection.mojo` and verify the line numbers in the spec match what you'll edit. Note all 4 in-bracket return sites (`:428`, `:443`, `:452`) plus fall-through (`:469`).

- [ ] **Step 2: Add B1 (parent `drain_stream_us_total`) + B2 (`recv_ffi`) + B3a (`buf_accumulate`) in `_drain_stream`**
Replace `_drain_stream` body. Original (lines 406-469):
```mojo
    def _drain_stream(mut self, stream_id: UInt64, now: UInt64) raises:
        """Read bytes from QUIC, accumulate in _stream_bufs, parse frames."""
        var key = Int(stream_id)
        if key not in self._stream_bufs:
            return  # locally-initiated stream or unknown — ignore

        var recv_result = self._quic.recv_stream_data(stream_id)
        var new_bytes = recv_result[0].copy()
        var fin = recv_result[1]

        # Append new bytes to accumulator
        var sbuf = self._stream_bufs[key].copy()
        for i in range(len(new_bytes)):
            sbuf.buf.append(new_bytes[i])
        self._stream_bufs[key] = sbuf^

        # Handle unidirectional stream type byte (first byte = stream type)
        var sbuf2 = self._stream_bufs[key].copy()
        if sbuf2.is_uni:
            if not sbuf2.type_byte:
                if len(sbuf2.buf) == 0:
                    self._stream_bufs[key] = sbuf2^
                    return
                # ... (rest of UNI handling)
                ...
                else:
                    return
            else:
                self._stream_bufs[key] = sbuf2^

        # Reject server-initiated bidi from peer (RFC 9114 §6.1)
        var sbuf3 = self._stream_bufs[key].copy()
        if not sbuf3.is_uni and self._is_peer_initiated(stream_id) and not self._is_server:
            self._stream_bufs[key] = sbuf3^
            self._quic.close(H3_STREAM_CREATION_ERROR, "server-initiated bidi not supported", now)
            return
        self._stream_bufs[key] = sbuf3^

        # Determine if this is the peer control stream
        var is_ctrl = False
        if self._peer_ctrl_sid:
            if self._peer_ctrl_sid.value() == stream_id:
                is_ctrl = True

        self._parse_frames_from_buf(stream_id, is_ctrl, now)

        # FIN on bidi request stream → STREAM_ENDED event
        var sbuf4 = self._stream_bufs[key].copy()
        if not sbuf4.is_uni and fin:
            var h3ev = H3Event(H3Event.STREAM_ENDED)
            h3ev.stream_id = stream_id
            self._h3_events.append(h3ev^)
        self._stream_bufs[key] = sbuf4^
```

Wrap it as follows. Hoist `var t_start_drain: UInt64 = 0` and `var t_start_buf: UInt64 = 0` and `var t_start_ffi: UInt64 = 0` at function scope (after the early-return guard). Bracket B1 starts after the early-return; record at each of the 4 exit sites. Bracket B2 wraps the `_quic.recv_stream_data` call. Bracket B3a wraps L413-460 (everything from `var new_bytes = recv_result[0].copy()` through the end of the bidi check, before `_parse_frames_from_buf`). The full transformed body:

```mojo
    def _drain_stream(mut self, stream_id: UInt64, now: UInt64) raises:
        """Read bytes from QUIC, accumulate in _stream_bufs, parse frames."""
        var key = Int(stream_id)
        if key not in self._stream_bufs:
            return  # locally-initiated stream or unknown — ignore

        # Hoisted clock-read state for B1 (parent), B2 (recv_ffi), B3a (buf_accumulate).
        # Single-pair pattern per Q1 lessons (sub-leg pass T4 — Mojo lexical scope).
        var t_start_drain: UInt64 = 0
        var t_start_ffi: UInt64 = 0
        var t_start_buf: UInt64 = 0
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                t_start_drain = monotonic_us()

        # B2 entry — wrap the FFI recv_stream_data call.
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                t_start_ffi = monotonic_us()
        var recv_result = self._quic.recv_stream_data(stream_id)
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                self.profile_ptr[].record_drain_recv_ffi(monotonic_us() - t_start_ffi)

        # B3a entry — wrap from recv_result.copy() through the bidi-check exit.
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                t_start_buf = monotonic_us()

        var new_bytes = recv_result[0].copy()
        var fin = recv_result[1]

        # Append new bytes to accumulator
        var sbuf = self._stream_bufs[key].copy()
        for i in range(len(new_bytes)):
            sbuf.buf.append(new_bytes[i])
        self._stream_bufs[key] = sbuf^

        # Handle unidirectional stream type byte (first byte = stream type)
        var sbuf2 = self._stream_bufs[key].copy()
        if sbuf2.is_uni:
            if not sbuf2.type_byte:
                if len(sbuf2.buf) == 0:
                    self._stream_bufs[key] = sbuf2^
                    # B3a + B1 exit (return path 1).
                    @parameter
                    if PROFILE_ACCEPT:
                        if Int(self.profile_ptr) != 0:
                            self.profile_ptr[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                            self.profile_ptr[].record_drain_stream(monotonic_us() - t_start_drain)
                    return
                var type_byte = sbuf2.buf[0]
                var new_buf = List[UInt8]()
                for i in range(1, len(sbuf2.buf)):
                    new_buf.append(sbuf2.buf[i])
                sbuf2.buf = new_buf^
                sbuf2.type_byte = Optional[UInt8](type_byte)
                self._stream_bufs[key] = sbuf2^
                if type_byte == UInt8(0x00):
                    self._peer_ctrl_sid = Optional[UInt64](stream_id)
                elif type_byte == UInt8(0x02):
                    self._peer_qenc_sid = Optional[UInt64](stream_id)
                elif type_byte == UInt8(0x03):
                    self._peer_qdec_sid = Optional[UInt64](stream_id)
                else:
                    # B3a + B1 exit (return path 2 — unknown UNI type).
                    @parameter
                    if PROFILE_ACCEPT:
                        if Int(self.profile_ptr) != 0:
                            self.profile_ptr[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                            self.profile_ptr[].record_drain_stream(monotonic_us() - t_start_drain)
                    return
            else:
                self._stream_bufs[key] = sbuf2^

        # Reject server-initiated bidi from peer (RFC 9114 §6.1)
        var sbuf3 = self._stream_bufs[key].copy()
        if not sbuf3.is_uni and self._is_peer_initiated(stream_id) and not self._is_server:
            self._stream_bufs[key] = sbuf3^
            self._quic.close(H3_STREAM_CREATION_ERROR, "server-initiated bidi not supported", now)
            # B3a + B1 exit (return path 3 — bidi rejection).
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    self.profile_ptr[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
                    self.profile_ptr[].record_drain_stream(monotonic_us() - t_start_drain)
            return
        self._stream_bufs[key] = sbuf3^

        # Determine if this is the peer control stream
        var is_ctrl = False
        if self._peer_ctrl_sid:
            if self._peer_ctrl_sid.value() == stream_id:
                is_ctrl = True

        # B3a exit — buf_accumulate phase ends BEFORE parse-loop entry.
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                self.profile_ptr[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)

        self._parse_frames_from_buf(stream_id, is_ctrl, now)

        # FIN on bidi request stream → STREAM_ENDED event
        var sbuf4 = self._stream_bufs[key].copy()
        if not sbuf4.is_uni and fin:
            var h3ev = H3Event(H3Event.STREAM_ENDED)
            h3ev.stream_id = stream_id
            self._h3_events.append(h3ev^)
        self._stream_bufs[key] = sbuf4^

        # B1 exit (fall-through path 4).
        @parameter
        if PROFILE_ACCEPT:
            if Int(self.profile_ptr) != 0:
                self.profile_ptr[].record_drain_stream(monotonic_us() - t_start_drain)
```

**Notes:**
- B3a fires once per `_drain_stream` invocation (early-returns also record B3a so the field is consistent).
- B1 records at all 4 exit sites; B3a records at all 4 exit sites OR at the natural exit before `_parse_frames_from_buf` (the 3 early-return paths emit BOTH B3a and B1; the natural fall-through path emits B3a once before `_parse_frames_from_buf` and B1 once at fall-through).

- [ ] **Step 3: Add B3b (`buf_accumulate` per-iter) + B4 (`frame_parse` per-iter) in `_parse_frames_from_buf`**
Original (lines 471-502):
```mojo
    def _parse_frames_from_buf(mut self, stream_id: UInt64, is_ctrl: Bool, now: UInt64) raises:
        """Parse H3 frames from accumulated bytes. Consumes one frame per iteration."""
        var key = Int(stream_id)
        while True:
            var sbuf = self._stream_bufs[key].copy()
            if len(sbuf.buf) == 0:
                self._stream_bufs[key] = sbuf^
                break
            # Make a separate copy for ByteReader (avoids lifetime conflict)
            var buf_copy = List[UInt8](copy=sbuf.buf)
            var r = ByteReader(Span(buf_copy))
            var ok = True
            var frame = H3RawFrame(UInt64(0), List[UInt8]())
            var consumed = 0
            try:
                frame = parse_h3_frame(r)
                consumed = r.pos
            except:
                ok = False
            if not ok:
                self._stream_bufs[key] = sbuf^
                break
            # Remove consumed bytes from front of buf
            var new_buf = List[UInt8]()
            for i in range(consumed, len(sbuf.buf)):
                new_buf.append(sbuf.buf[i])
            sbuf.buf = new_buf^
            self._stream_bufs[key] = sbuf^
            if is_ctrl:
                self._handle_control_frame(stream_id, frame, now)
            else:
                self._handle_request_frame(stream_id, frame, now)
```

Replace with bracketed version:
```mojo
    def _parse_frames_from_buf(mut self, stream_id: UInt64, is_ctrl: Bool, now: UInt64) raises:
        """Parse H3 frames from accumulated bytes. Consumes one frame per iteration."""
        var key = Int(stream_id)
        # Hoisted per-iter clock-read state (Q1 lesson: hoist to function scope, reassign per iter).
        var t_start_parse: UInt64 = 0
        var t_start_buf: UInt64 = 0
        while True:
            var sbuf = self._stream_bufs[key].copy()
            if len(sbuf.buf) == 0:
                self._stream_bufs[key] = sbuf^
                break
            # Make a separate copy for ByteReader (avoids lifetime conflict)
            var buf_copy = List[UInt8](copy=sbuf.buf)
            var r = ByteReader(Span(buf_copy))
            var ok = True
            var frame = H3RawFrame(UInt64(0), List[UInt8]())
            var consumed = 0
            # B4 entry — wrap parse_h3_frame only.
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    t_start_parse = monotonic_us()
            try:
                frame = parse_h3_frame(r)
                consumed = r.pos
            except:
                ok = False
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    self.profile_ptr[].record_drain_frame_parse(monotonic_us() - t_start_parse)
            if not ok:
                self._stream_bufs[key] = sbuf^
                break
            # B3b entry — wrap residual rebuild + Dict reassign.
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    t_start_buf = monotonic_us()
            # Remove consumed bytes from front of buf
            var new_buf = List[UInt8]()
            for i in range(consumed, len(sbuf.buf)):
                new_buf.append(sbuf.buf[i])
            sbuf.buf = new_buf^
            self._stream_bufs[key] = sbuf^
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    self.profile_ptr[].record_drain_buf_accumulate(monotonic_us() - t_start_buf)
            if is_ctrl:
                self._handle_control_frame(stream_id, frame, now)
            else:
                self._handle_request_frame(stream_id, frame, now)
```

- [ ] **Step 4: Add B5 (`qpack_decode`) in `_handle_request_frame`**
Original (lines 536-554):
```mojo
    def _handle_request_frame(mut self, stream_id: UInt64, frame: H3RawFrame, now: UInt64) raises:
        """Process one frame received on a request/response bidi stream."""
        if frame.frame_type == H3_FRAME_HEADERS:
            var fields = self._dec.decode(frame.payload)
            var h3ev = H3Event(H3Event.HEADERS_RECEIVED)
            ...
```

Replace the `if frame.frame_type == H3_FRAME_HEADERS:` block:
```mojo
    def _handle_request_frame(mut self, stream_id: UInt64, frame: H3RawFrame, now: UInt64) raises:
        """Process one frame received on a request/response bidi stream."""
        var t_start_qpack: UInt64 = 0
        if frame.frame_type == H3_FRAME_HEADERS:
            # B5 — wrap QPACK decode only.
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    t_start_qpack = monotonic_us()
            var fields = self._dec.decode(frame.payload)
            @parameter
            if PROFILE_ACCEPT:
                if Int(self.profile_ptr) != 0:
                    self.profile_ptr[].record_drain_qpack_decode(monotonic_us() - t_start_qpack)
            var h3ev = H3Event(H3Event.HEADERS_RECEIVED)
            h3ev.stream_id = stream_id
            h3ev.fields = fields^
            self._h3_events.append(h3ev^)
        elif frame.frame_type == H3_FRAME_DATA:
            var h3ev = H3Event(H3Event.DATA_RECEIVED)
            h3ev.stream_id = stream_id
            h3ev.data = List[UInt8](copy=frame.payload)
            self._h3_events.append(h3ev^)
        elif frame.frame_type == H3_FRAME_SETTINGS or frame.frame_type == H3_FRAME_GOAWAY:
            # Forbidden on request streams (RFC 9114 §7.2.5)
            self._quic.close(H3_FRAME_UNEXPECTED, "SETTINGS/GOAWAY on request stream", now)
        # else: unknown, ignore
```

- [ ] **Step 5: Run all tests to verify the off-build (PROFILE_ACCEPT=False) compiles and passes**
Run: `bash scripts/run_tests.sh 2>&1 | tail -5`
Expected: `All 77/77 src tests passed.` (off-build = brackets are no-ops; behavior unchanged).

- [ ] **Step 6: Verify on-build also compiles**
Run: `sed -i 's/alias PROFILE_ACCEPT: Bool = False/alias PROFILE_ACCEPT: Bool = True/' src/quic/profile.mojo`
Then: `TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | grep -c '^PASS:'`
Expected: `53` (no test failures on-build).
Then revert: `sed -i 's/alias PROFILE_ACCEPT: Bool = True/alias PROFILE_ACCEPT: Bool = False/' src/quic/profile.mojo`
Verify: `grep "alias PROFILE_ACCEPT" src/quic/profile.mojo` → `False`.

- [ ] **Step 7: Commit T2**
Use the `commit-smart` skill. Message format: `feat(h3): bracket _drain_stream + _parse_frames_from_buf + _handle_request_frame`.

---

## Task 3: Sum-invariant + overshoot-clamp tests [SUBAGENT, TDD]

**Files:**
- Test: `tests/test_quic_profile.mojo` (append 2 tests + register in `main()`).

- [ ] **Step 1: Write T6 — sum-invariant residual happy path**
Append at file tail:
```mojo


def test_drain_subleg_sum_invariant_residual() raises:
    """Synthetic profile: sum of measured legs ≤ parent; residual fills the gap."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain_stream(UInt64(1000))
    p.record_drain_recv_ffi(UInt64(100))
    p.record_drain_buf_accumulate(UInt64(400))
    p.record_drain_frame_parse(UInt64(200))
    p.record_drain_qpack_decode(UInt64(100))
    # Sum of measured legs = 800; total = 1000; residual = 200.
    var de = p._compute_drain_event_dispatch_us()
    assert_equal_int(Int(de), 200, "event_dispatch residual = total - sum_legs = 200")
    var out = p.report_json()
    assert_true('"event_dispatch_us": 200' in out, "JSON event_dispatch=200")
    # sum_legs (with derived event_dispatch) == total exactly.
    assert_true('"sum_legs_us": 1000' in out, "sum_legs (with derived) = 1000")
    # unaccounted_pct after residual = 0.
    assert_true('"unaccounted_pct": 0' in out, "unaccounted_pct=0 (closed)")
    print("PASS: test_drain_subleg_sum_invariant_residual")
```

- [ ] **Step 2: Write T7 — overshoot clamp**
Append at file tail:
```mojo


def test_drain_subleg_residual_clamp_overshoot() raises:
    """Synthetic profile: sum of measured legs > parent. Clamp residual to 0.
    Guards against UInt64 underflow-wrap regression (would surface as a huge
    spurious event_dispatch_us)."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain_stream(UInt64(1000))
    p.record_drain_recv_ffi(UInt64(400))
    p.record_drain_buf_accumulate(UInt64(400))
    p.record_drain_frame_parse(UInt64(200))
    p.record_drain_qpack_decode(UInt64(100))
    # Sum of measured legs = 1100; total = 1000 → overshoot by 100.
    var de = p._compute_drain_event_dispatch_us()
    assert_equal_int(Int(de), 0, "event_dispatch clamped to 0 on overshoot")
    var out_json = p.report_json()
    assert_true('"event_dispatch_us": 0' in out_json, "JSON event_dispatch=0 (clamped)")
    var out_text = p.report_text()
    assert_true("event_dispatch.derived: 0" in out_text, "text event_dispatch=0 (clamped)")
    print("PASS: test_drain_subleg_residual_clamp_overshoot")
```

- [ ] **Step 3: Verify both tests fail or pass appropriately before registration**
Run: `TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | grep -E "test_drain_subleg" | tail`
Expected: tests not yet listed (not registered in `main()`); they exist as defs but aren't called.

- [ ] **Step 4: Register T6 + T7 in `main()`**
After the 5 T1-task tests appended in Task 1 Step 12 (so after `test_report_json_emits_drain_stream_subleg_block()`), add:
```mojo
    test_drain_subleg_sum_invariant_residual()
    test_drain_subleg_residual_clamp_overshoot()
```

- [ ] **Step 5: Run profile tests; verify count 48 → 55**
Run: `TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh 2>&1 | grep -c '^PASS:'`
Expected: `55` (48 + 7).

- [ ] **Step 6: Run full suite**
Run: `bash scripts/run_tests.sh 2>&1 | tail -5`
Expected: `All 79/79 src tests passed.` (72 prior + 7 new).

- [ ] **Step 7: Commit T3**
Use the `commit-smart` skill. Message format: `test: add drain-stream sub-leg sum-invariant + clamp-overshoot tests`.

---

## Task 4: Smoke gate — RPS non-regression on/off-build [PARENT-ONLY]

**Files:** none modified. Captures bench logs.

- [ ] **Step 1: Confirm PROFILE_ACCEPT=False; build off-build post image**
Run: `grep "alias PROFILE_ACCEPT" src/quic/profile.mojo` → `False`.
Run: `BOUCLE_DIR=/home/donokami/Projets/perso/boucle SIMDJSON_DIR=/home/donokami/Projets/perso/json-simd-mojo bash bench/build.sh 2>&1 | tee /tmp/drain-subleg-post-off-build.log | grep -E "Successfully built|^ERROR"`
Then: `docker tag mojo-net-bench:latest mojo-net-bench:drain-subleg-post-off`
Expected: `Successfully built <SHA>`; tag set.

- [ ] **Step 2: Capture off-build post long-conn (n=10) + short-conn (n=10)**
Run: `MOJO_NET_IMAGE=mojo-net-bench:drain-subleg-post-off bench/quic_perf/run_long_conn.sh 10 2>&1 | tee /tmp/drain-subleg-post-off-long.log`
Run: `MOJO_NET_IMAGE=mojo-net-bench:drain-subleg-post-off bench/quic_perf/run_short_conn.sh 10 2>&1 | tee /tmp/drain-subleg-post-off-short.log`
Compute medians.

- [ ] **Step 3: Verify off-build drift gate AC#5 (≥−2.0%) on both cells**
Compare to T0 Step 6 + Step 7 baselines. Compute `(post_median - pre_median) / pre_median × 100`.
Expected: drift ≥ −2.0% on BOTH cells.
**If FAIL:** halt; re-run pre-baselines once for stability sanity (3 iters); if persistent, escalate.

- [ ] **Step 4: Flip PROFILE_ACCEPT=True; build on-build post image**
Run: `sed -i 's/alias PROFILE_ACCEPT: Bool = False/alias PROFILE_ACCEPT: Bool = True/' src/quic/profile.mojo`
Run: `BOUCLE_DIR=/home/donokami/Projets/perso/boucle SIMDJSON_DIR=/home/donokami/Projets/perso/json-simd-mojo bash bench/build.sh 2>&1 | tee /tmp/drain-subleg-post-on-build.log | grep -E "Successfully built|^ERROR"`
Then: `docker tag mojo-net-bench:latest mojo-net-bench:drain-subleg-post-on`

- [ ] **Step 5: Capture on-build post long-conn (n=10) + short-conn (n=10)**
Run: `MOJO_NET_IMAGE=mojo-net-bench:drain-subleg-post-on bench/quic_perf/run_long_conn.sh 10 2>&1 | tee /tmp/drain-subleg-post-on-long.log`
Run: `MOJO_NET_IMAGE=mojo-net-bench:drain-subleg-post-on bench/quic_perf/run_short_conn.sh 10 2>&1 | tee /tmp/drain-subleg-post-on-short.log`

- [ ] **Step 6: Verify on-build drift gates AC#3 + AC#4 (≥−2.0%) on both cells**
Compare to T0 Step 9 baselines.
Expected: drift ≥ −2.0% on BOTH cells.
**If FAIL:** halt; investigate clock-read overhead at the 7-bracket granularity; the spec allows soft-floor 15-25% only on AC#2 (`unaccounted_pct`), not on RPS gates.

- [ ] **Step 7: Revert PROFILE_ACCEPT=False; verify**
Run: `sed -i 's/alias PROFILE_ACCEPT: Bool = True/alias PROFILE_ACCEPT: Bool = False/' src/quic/profile.mojo`
Verify: `grep "alias PROFILE_ACCEPT" src/quic/profile.mojo` → `False`.

- [ ] **Step 8: Commit T4 (smoke gate evidence; no code changes — PROFILE_ACCEPT was flipped+reverted)**
If `git status` shows clean (no source changes — the sed-flip-and-revert produced identical content to T2's commit), commit just the bench logs ONLY if you saved them under `bench/quic_perf/results/profile/`. Otherwise, no commit; T4 evidence is captured in T5's evidence markdown.
**Note:** if `git diff` shows zero changes after this task, skip the commit and proceed to T5.

---

## Task 5: SIGINT sidecars + Hard Gates 1/5/6 verdict [PARENT-ONLY]

**Files:**
- Create: `bench/quic_perf/results/profile/Q-drain-subleg_post_evidence_2026-05-01.md`

- [ ] **Step 1: Verify on-build image still tagged**
Run: `docker images mojo-net-bench:drain-subleg-post-on`
Expected: image present (from T4 Step 4).

- [ ] **Step 2: Capture n=3 post on-build long-conn SIGINT sidecars**
For i=1,2,3 run with PROFILE_ACCEPT-on image, capture sidecar JSON via SIGINT-flush:
```
MOJO_NET_IMAGE=mojo-net-bench:drain-subleg-post-on \
PROFILE_DUMP_PATH=bench/quic_perf/results/profile/INSTRUMENTATION-$(date +%Y%m%d-%H%M%S)-q-drain-subleg-post-long-conn-iter${i}.json \
bench/quic_perf/run_long_conn.sh 1
```
Expected: 3 JSON files in `bench/quic_perf/results/profile/` matching glob `INSTRUMENTATION-*-q-drain-subleg-post-long-conn-iter*.json`.

- [ ] **Step 3: Capture n=3 post on-build short-conn SIGINT sidecars**
Same pattern with `q-drain-subleg-post-short-conn-iter${i}` naming. Expected: 3 more JSON files (6 total post sidecars).

- [ ] **Step 4: Verify Hard Gate 6 (`dcid_mismatch_pkts == 0`) across all 12 sidecars (6 pre + 6 post)**
Run:
```
for f in bench/quic_perf/results/profile/INSTRUMENTATION-*q-drain-subleg-{pre,post}-*.json; do
    echo "$f $(jq '.addr_key_dcid_mismatch.dcid_mismatch_pkts // .dcid_mismatch_pkts' "$f")"
done
```
Expected: `0` for all 12 files.
**If FAIL:** halt; investigate Q3 invariant regression.

- [ ] **Step 5: Verify Hard Gate 5 (sub-leg sum invariant ε≤5%) on all 6 post sidecars**
For each post sidecar:
```
jq '.drain_stream_subleg | {tot: .drain_stream_us_total,
                            sum: (.recv_ffi_us + .buf_accumulate_us + .frame_parse_us + .qpack_decode_us)}' \
    bench/quic_perf/results/profile/INSTRUMENTATION-*q-drain-subleg-post-*.json
```
For each: compute `sum / tot × 100 - 100`. Expected: ε ≤ 5% on all 6.
**If FAIL:** halt; root-cause the bracket overlap (likely double-counting B3a/B3b, or a missed exit-site in B1).

- [ ] **Step 6: Verify Hard Gate 1 — long-conn `unaccounted_pct` ≤ 15% on `quic_post_recv_us`**
This is Q1's residual budget — preserved unchanged by this spec. For each post long-conn sidecar:
```
jq '.h3_phases_us | .post_recv.total / .drain_resp.total' bench/quic_perf/results/profile/INSTRUMENTATION-*q-drain-subleg-post-long-conn-*.json
```
And the existing `unaccounted_pct` field at the top level of the JSON. Expected: ≤ 15% on the median of 3.
**If between 15% and 25%:** mark SHIPPED-with-caveat per spec §8 AC#2 soft floor.
**If > 25%:** halt; investigate.

- [ ] **Step 7: Identify dominant sub-leg (informational — no prediction recorded)**
For each post long-conn sidecar, compute the largest of `recv_ffi_us`, `buf_accumulate_us`, `frame_parse_us`, `qpack_decode_us`, `event_dispatch_us` (derived). Report which leg is largest, and its share of `drain_stream_us_total`.

- [ ] **Step 8: Write Q-drain-subleg_post_evidence_2026-05-01.md**
Mirror Q1's post-evidence structure: image SHAs, AC#3-#5 RPS drift table, AC#2 unaccounted_pct (Q1 budget), AC#6 sum invariant table, AC#7 dcid_mismatch table, dominant phase named (no prediction comparison), short-conn `unaccounted_pct` (informational), all 9 ACs verdicts table. Include "Surprises recorded for retrospective" section.

- [ ] **Step 9: Commit T5**
Use the `commit-smart` skill. Message format: `bench: T5 post-migration evidence + Hard Gate verdicts`.

---

## Task 6: REFERENCE.md + flag revert + project-context advance + final review [PARENT-ONLY]

**Files:**
- Modify: `bench/quic_perf/results/REFERENCE.md` (append new shipped-pass row at file tail).
- Modify: `docs/project-context.md` (phase advance to `spec-quic-h3-drain-stream-subleg-reviewing`; mark plan in-progress → done; session-history entry).
- Verify: `src/quic/profile.mojo` PROFILE_ACCEPT=False.

- [ ] **Step 1: Verify PROFILE_ACCEPT=False**
Run: `grep "alias PROFILE_ACCEPT" src/quic/profile.mojo`
Expected: `False`. If not, `sed -i 's/= True/= False/' src/quic/profile.mojo` and `grep` again.

- [ ] **Step 2: Append REFERENCE.md row**
Read the file tail to find the format of the most recent shipped-pass row (Q1's). Append a new row using the same shape: date, branch, image SHAs (4: pre/post × off/on), all 9 ACs verdicts, dominant phase named (no prediction comparison), short notes on variance behavior.

- [ ] **Step 3: Update project-context.md**
Replace the top "Current phase (QUIC instrumentation track)" line. Mirror Q1's "FF-merged" → "reviewing" pattern but with current data: "spec-quic-h3-drain-stream-subleg-reviewing. All 7 plan tasks (T0-T6) complete on branch `feat/quic-h3-drain-stream-subleg` (off main `7e2eb01`). N commits total ..." Include the dominant-phase finding.

Mark the active-specs row for `specs/2026-05-01-quic-h3-drain-stream-subleg.md` as `done` and reference the merge SHA placeholder (will be filled after FF-merge by finishing-a-development-branch).

Add a new session-history entry at the top: today's date + session jsonl path + bullets: branch built, all 9 ACs PASS (or with caveats), dominant phase named, surprises recorded.

- [ ] **Step 4: Run final cross-cutting review via fresh subagent**
Invoke the combined-reviewer pattern from `atelier:subagent-driven-development` with BASE_SHA=`7e2eb01` and HEAD_SHA=current branch head. Spec section to review: §3 + §4 + §5 + §6 + §7 + §8 of `specs/2026-05-01-quic-h3-drain-stream-subleg.md`.

Expected: ✅ CLEAN. If ❌ ISSUES: implementer fixes, re-dispatch.

- [ ] **Step 5: Commit T6**
Use the `commit-smart` skill. Message format: `docs: T6 REFERENCE.md entry + project-context advance`.

- [ ] **Step 6: Verify branch is clean and tests still pass**
Run: `git status --short` → no uncommitted files (untracked from baselines + sidecars are expected and OK if already committed in T0/T5).
Run: `bash scripts/run_tests.sh 2>&1 | tail -3`
Expected: `All 79/79 src tests passed.`

---

## Pre-save scan

- ✅ Every spec AC#1-#9 maps to a task: AC#1 (T1+T3 tests), AC#2 (T5 Step 6), AC#3 (T4 Step 6), AC#4 (T4 Step 6), AC#5 (T4 Step 3), AC#6 (T5 Step 5), AC#7 (T5 Step 4), AC#8 (T6 Step 2), AC#9 (T6 Step 1).
- ✅ No placeholders (TBD / TODO / "implement later").
- ✅ Test count locked at +7 (T1 ships 5: T1+T2+T3+T4+T5; T3 ships 2: T6+T7); AC#1 anchor 48 → 55.
- ✅ Image hygiene + CPU gate: tag-isolated `mojo-net-bench:drain-subleg-{pre,post}-{off,on}` (4 distinct images); explicit `BOUCLE_DIR` + `SIMDJSON_DIR` env vars on every build; CPU-load assumption stated implicitly (no parallel `mojo run` in other worktrees).
- ✅ Single-pair clock-read pattern with hoisted `var t_start_*: UInt64 = 0` at function scope (Q1 lesson: sub-leg pass T4's Mojo lexical-scope failure mode avoided).
- ✅ Bracket nesting (not disjointness) verified: B1 ⊇ {B2, B3a, B3b, B4, B5}; B3a + B3b accumulate into the same `drain_buf_accumulate_us_total` field.
- ✅ Branch precondition: new branch off main `7e2eb01` (verified in T0 Step 1).
- ✅ Field naming: `<phase>_us_total` (matches Q1's `quic_post_recv_us_total`); method naming: `record_drain_<phase>` with `(mut self, us: UInt64)` signature (matches Q1 at `profile.mojo:284-290`).
- ✅ B1 exit sites enumerated explicitly (4 in-bracket: `:428` UNI empty-buf, `:443` UNI unknown-type, `:452` bidi rejection, `:469` fall-through).
- ✅ Hard Gate 5 ε bound (≤5%) is justified (`monotonic_us` jitter at 14k rps × ~3 brackets × 2 reads = ~84k reads/sec) and is NOT silenced by the residual clamp.
- ✅ Residual computation hoisted to private helper `_compute_drain_event_dispatch_us` (T1 Step 6) — used by both `report_json` (T1 Step 10) and `report_text` (T1 Step 11) to prevent divergence.
- ✅ All step code is verbatim, with exact file:line modify targets and exact commands.

## Appendix A — Test name registry

| Test name | Task | Validates |
|---|---|---|
| `test_record_drain_stream_increments_total` | T1 | `record_drain_stream` accumulates into `drain_stream_us_total` |
| `test_record_drain_recv_ffi_increments_total` | T1 | Same for `recv_ffi` |
| `test_record_drain_buf_accumulate_increments_total` | T1 | Same for `buf_accumulate` (3 calls accumulate — B3a + B3b summing pattern) |
| `test_record_drain_frame_parse_and_qpack_decode_independent` | T1 | Both methods target separate fields; no aliasing |
| `test_report_json_emits_drain_stream_subleg_block` | T1 | JSON `drain_stream_subleg` block has all 8 keys + numeric values |
| `test_drain_subleg_sum_invariant_residual` | T3 | Residual = total - sum_legs; sum_legs (with derived) == total |
| `test_drain_subleg_residual_clamp_overshoot` | T3 | When sum > total, `_compute_drain_event_dispatch_us` returns 0 (no UInt64 wrap); JSON + text both show 0 |

## Appendix B — File:line citation cross-check (current main `7e2eb01`)

| Citation | Confirmed |
|---|---|
| `src/quic/profile.mojo:118` (3 H3 phase totals end) | ✓ |
| `src/quic/profile.mojo:165` (3 H3 phase totals init end) | ✓ |
| `src/quic/profile.mojo:291` (after `record_h3_dispatch`) | ✓ |
| `src/quic/profile.mojo:423` (after `H3 phases:` text block) | ✓ |
| `src/quic/profile.mojo:639` (after `h3_phases_us` JSON block) | ✓ |
| `src/h3/connection.mojo:406` (`_drain_stream` def) | ✓ |
| `src/h3/connection.mojo:410` (early-return) | ✓ |
| `src/h3/connection.mojo:412` (recv_stream_data call) | ✓ |
| `src/h3/connection.mojo:428, :443, :452` (in-bracket returns) | ✓ |
| `src/h3/connection.mojo:469` (fall-through) | ✓ |
| `src/h3/connection.mojo:471` (`_parse_frames_from_buf` def) | ✓ |
| `src/h3/connection.mojo:486` (parse_h3_frame call) | ✓ |
| `src/h3/connection.mojo:494-498` (residual rebuild) | ✓ |
| `src/h3/connection.mojo:536` (`_handle_request_frame` def) | ✓ |
| `src/h3/connection.mojo:539` (_dec.decode call) | ✓ |
| `tests/test_quic_profile.mojo:992` (`def main`) | ✓ |
| `tests/test_quic_profile.mojo:1040` (last Q1 test reg) | ✓ |
