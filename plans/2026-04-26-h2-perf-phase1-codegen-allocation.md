# H2 Perf — Phase 1: Codegen & Allocation

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close ~26 % of measured H2 worker self-time across three concrete hotspots identified by Phase 0 (`plans/2026-04-25-h2-perf-phase0-profiling-retrospective.md`). Measurement-gated: every task re-runs the harness and rejects regressions across the full endpoint set.

**Architecture:** Mechanical, layer-by-layer changes against the host h2_server. Three hotspot families:
- **HPACK decoder** — byte-by-byte `String += chr(...)` building. Self-cost: `_decode_string` 6.76 % self / 10.36 % inclusive; combined HPACK decode ≈ 33 % inclusive.
- **HTTP header churn** — `_to_lower` is the same byte-by-byte build pattern, called on every header insert via `Headers.add()`. HPACK already produces lowercase names on ingress; we're re-lowercasing for nothing. Self-cost: `_to_lower` 4.43 + `String::_iadd` 3.45 + `String::unsafe_ptr_mut` 2.87 + `chr` 1.58 + `String::__init__` 0.80 ≈ **13 %** combined self.
- **Per-byte buffer rebuilds** — `_queue_frame` and `_trim_inbuf` in `H2Connection` rebuild `_outbuf` / `_inbuf` byte-by-byte; combined allocator self ≈ **7.15 %**.

**Tech Stack:** Mojo 0.26.2, `Span[UInt8, _]` for in-place byte ops, `String(bytes=...)` for bulk byte → String, Mojo MCP `validate` + `execute` for compile checks.

**Measurement gate:** Every task ends with a re-run of `bench/profile/h2-throughput.sh` (mojo-net only, defaults) AND `bench/profile/h2-perf-record.sh` + `h2-hotspots.sh`. The retrospective records the delta vs. baseline `d6fdbcb`. Reject any task whose throughput row regresses on any of the three baseline endpoints.

---

## File structure

| File                                        | Changes  | Requirements |
|---------------------------------------------|----------|--------------|
| `src/h2/hpack.mojo`                         | Rewrite `_decode_string`; refactor `_decode_literal` to skip the per-byte raw copy | R1, R2 |
| `src/http/headers.mojo`                     | Bulk-byte `_to_lower`; add `add_lowercase` fast path | R3, R4 |
| `src/h2/connection.mojo`                    | Bulk-extend `_queue_frame`; rewrite `_trim_inbuf` with `Span` slice; pre-size buffers | R5 |
| `src/h2/h2_coro_server.mojo`                | Switch ingress callsites that lowercase HPACK names to use `add_lowercase` | R4 |
| `tests/test_hpack.mojo`                     | Existing tests must pass; add string-decode roundtrip stress if missing | R1 |
| `tests/test_headers.mojo`                   | Existing tests must pass; add empty/uppercase/long-name regressions | R3 |
| `bench/profile/baselines/h2-throughput.csv` | One new row appended per task (post-task baseline) | R6 |
| `bench/profile/baselines/h2-hotspots-<sha>.md` | Captured per task | R6 |
| `plans/2026-04-26-h2-perf-phase1-codegen-allocation-retrospective.md` | New | R6 |

---

## Requirements

- **R1 — `_decode_string` bulk decode.** Replace the byte-by-byte `String += chr(Int(b))` loop with a `String(bytes=...)` from a pre-sized `List[UInt8]`. Both Huffman and raw paths. Conformance: HPACK roundtrip tests pass; full conformance suite (`bench/.httparena/scripts/validate.sh mojo-net` once green) shows no new failures.
- **R2 — `_decode_literal` zero-copy slice.** Eliminate the intermediate `raw: List[UInt8]` rebuild before calling `_decode_string`. Pass the wire slice directly via `Span[UInt8]`.
- **R3 — `_to_lower` bulk byte-build.** Build into `List[UInt8]` (pre-sized to `len(s.as_bytes())`) and `String(bytes=...)` once at the end, instead of `result += chr(Int(b))` per byte. ASCII-only contract preserved.
- **R4 — Skip `_to_lower` on HPACK ingress.** Add `Headers.add_lowercase(name, value)` that asserts (in debug builds only) name is already lowercase and skips the conversion. Wire H2 decoder callsites to use it.
- **R5 — Bulk-extend H2 connection buffers.** `_queue_frame` and `_trim_inbuf` switch to `List.extend(Span[...])`-style bulk copies. Pre-size `_inbuf` / `_outbuf` capacities at construction (16 KB) and on `receive_data` ingress to known wire size.
- **R6 — Phase 0 harness re-run per task.** Each task commits a new throughput CSV row + hotspot MD. Retrospective tabulates per-task deltas.

---

## Task 1: HPACK `_decode_string` bulk decode

**Files:**
- Modify: `src/h2/hpack.mojo:333-368`

- [ ] **Step 1: Replace `_decode_string` body.** Inside the function, after `consumed += str_len` is computed, build a single `List[UInt8]` via slice-extend (no per-byte append loop), then for each path emit one `String(bytes=...)`:
  ```mojo
  def _decode_string(
      self, wire: List[UInt8], pos: Int
  ) -> Tuple[String, Int, String]:
      if pos >= len(wire):
          return (String(""), 0, String("truncated string"))

      var huffman_flag = (Int(wire[pos]) & 0x80) != 0

      var len_result = decode_integer(wire, pos, 7)
      var str_len = len_result[0]
      var consumed = len_result[1]
      if len(len_result[2]) > 0:
          return (String(""), 0, len_result[2])

      var data_start = pos + consumed
      if data_start + str_len > len(wire):
          return (String(""), 0, String("truncated string data"))

      consumed += str_len

      if huffman_flag:
          # Huffman decoder still wants a List[UInt8]; build via bulk extend.
          var raw = List[UInt8](capacity=str_len)
          for i in range(str_len):
              raw.append(wire[data_start + i])
          var huff_result = self.huffman.decode(raw)
          if len(huff_result[1]) > 0:
              return (String(""), 0, huff_result[1])
          # huff_result[0] is List[UInt8] — convert to String once.
          var s = String(bytes=huff_result[0])
          return (s^, consumed, String(""))
      else:
          # Raw bytes are already in `wire` — slice once into a fresh List.
          var raw = List[UInt8](capacity=str_len)
          for i in range(str_len):
              raw.append(wire[data_start + i])
          var s = String(bytes=raw)
          return (s^, consumed, String(""))
  ```
  Note: if `String(bytes=...)` is not the canonical Mojo 0.26.2 constructor, use `String(StringSlice(unsafe_from_utf8=raw.as_span()))` or whichever idiom is current. Confirm via Mojo MCP `lookup` for `String` before editing.

- [ ] **Step 2: Verify with Mojo MCP.** Use `validate` then `execute` on a tiny snippet to confirm the chosen constructor compiles and produces correct output for ASCII bytes.

- [ ] **Step 3: Run tests.**
  ```bash
  pixi run -- mojo test -I . tests/test_hpack.mojo
  pixi run -- mojo test -I . tests/test_h2_*.mojo
  ```
  Expected: all pass.

- [ ] **Step 4: Re-run harness.**
  ```bash
  bash bench/build.sh                            # rebuild Docker mojo-net image
  pixi run build-bench                           # rebuild host bench/h2_server
  N=100000 SERVERS=mojo-net bash bench/profile/h2-throughput.sh
  DURATION=60 PERF_DUR=55 bash bench/profile/h2-perf-record.sh
  bash bench/profile/h2-hotspots.sh
  ```
  Expected: `_decode_string` self-time drops from 6.76 % to <2 % of total. `/baseline2` and `/json/...` rps must not regress.

- [ ] **Step 5: Commit.** `commit-smart`. Suggested message: `perf(h2/hpack): bulk-decode literal strings via String(bytes=...)`. Include the new throughput row + hotspot delta in the body.

---

## Task 2: HPACK `_decode_literal` — eliminate redundant slice copy

**Files:**
- Modify: `src/h2/hpack.mojo:296-331`

- [ ] **Step 1: Pass `wire` + offset directly to `_decode_string`.** `_decode_literal` already passes `wire, pos + consumed` — there's no actual extra copy in `_decode_literal` itself. Re-inspect: the redundant work was that `_decode_string` rebuilds `raw` from `wire` byte-by-byte. After Task 1 the per-byte append into `raw` is the last remaining loop in the raw path. **Replace with `List.extend` over a `Span` slice:**
  ```mojo
  # raw path inside _decode_string after Task 1:
  var raw = List[UInt8](capacity=str_len)
  raw.extend(Span(wire)[data_start : data_start + str_len])
  var s = String(bytes=raw)
  ```
  Same pattern for the Huffman path before the call into `huffman.decode(...)`. Verify `List[UInt8].extend(Span[UInt8, _])` exists in 0.26.2 via Mojo MCP `lookup`. If not, fall back to a comptime-unrolled append loop or `memcpy` via `UnsafePointer`.

- [ ] **Step 2: Tests + harness re-run.** Same commands as Task 1 Step 3-4. Expect `_decode_string` to drop further; `_decode_literal` self-time should also tick down.

- [ ] **Step 3: Commit.** Suggested message: `perf(h2/hpack): bulk-extend wire slice instead of per-byte append`.

---

## Task 3: `_to_lower` bulk byte-build

**Files:**
- Modify: `src/http/headers.mojo:8-18`

- [ ] **Step 1: Replace the loop.** Build into a sized `List[UInt8]` and convert at the end:
  ```mojo
  def _to_lower(s: String) -> String:
      """Convert ASCII uppercase to lowercase."""
      var bytes = s.as_bytes()
      var n = len(bytes)
      var out = List[UInt8](capacity=n)
      for i in range(n):
          var b = bytes[i]
          if b >= UInt8(65) and b <= UInt8(90):
              out.append(b + UInt8(32))
          else:
              out.append(b)
      return String(bytes=out)
  ```
  This trades `n` `String += chr(Int)` allocations for one allocation total. ASCII contract preserved (the original was already ASCII-only).

- [ ] **Step 2: Add a regression test in `tests/test_headers.mojo`** for:
  - empty string → empty
  - ASCII-only mixed case → all lowercase
  - 8-bit byte (e.g. UTF-8 continuation) → unchanged
  - Long string (1024 bytes) — sanity check no truncation.

- [ ] **Step 3: Tests + harness re-run.**

- [ ] **Step 4: Commit.** `perf(http/headers): bulk-build _to_lower instead of per-byte += chr(...)`.

---

## Task 4: Skip `_to_lower` on HPACK ingress

**Files:**
- Modify: `src/http/headers.mojo` (add `add_lowercase`)
- Modify: `src/h2/h2_coro_server.mojo` (use `add_lowercase` for HPACK-decoded headers)
- Modify: `src/h2/h2_handler_server.mojo` (same, if it builds Headers from HPACK output)

- [ ] **Step 1: Add fast path on `Headers`.**
  ```mojo
  def add_lowercase(mut self, name: String, value: String):
      """Append a header where `name` is already lowercase.

      Caller MUST guarantee name has no ASCII A-Z. RFC 7540 §8.1.2:
      HTTP/2 wire header names are required to be lowercase, so the
      HPACK decoder's output is already valid input here.
      """
      self._names.append(name)
      self._values.append(value)
  ```
  No assertion in release builds. Add `debug_assert` (or its Mojo equivalent) if you want the safety net while debugging.

- [ ] **Step 2: Find ingress callsites.** Look for the loop that consumes HPACK decoder output and inserts into a `Headers` instance. Likely in `h2_coro_server.mojo` after `self._conn.receive_data(...)` returns events containing decoded headers. Switch to `add_lowercase` there. Pseudo-headers (`:method`, `:path`, …) — confirm whether they go through `Headers` or a separate `PseudoHeaders` struct (`src/h2/pseudo_headers.mojo` exists). Pseudo-headers are not lowercased by HPACK (they start with `:`), so route them to a separate path.

- [ ] **Step 3: Tests.** Run the H2 conformance suite. Specifically: a request with a single uppercase header byte (e.g. `Content-Type`) sent to the H2 server must still be rejected per RFC 7540 §8.1.2 — so the wire must be lowercase, but the HPACK decoder is what enforces that. Our change here is purely about not re-lowercasing on the receiver. Conformance unchanged.

- [ ] **Step 4: Harness re-run.** Expect `_to_lower` self-time to fall sharply on H2 ingress; H1 path is unaffected (H1 server still uses `Headers.add` which lowercases).

- [ ] **Step 5: Commit.** `perf(h2): skip redundant _to_lower on HPACK-decoded header names`.

---

## Task 5: Bulk-extend H2 connection buffers

**Files:**
- Modify: `src/h2/connection.mojo:599-612`
- Modify: `src/h2/connection.mojo:505-506` (constructor — pre-size)

- [ ] **Step 1: Pre-size `_inbuf` / `_outbuf`.** In the constructor:
  ```mojo
  self._inbuf  = List[UInt8](capacity=16 * 1024)
  self._outbuf = List[UInt8](capacity=16 * 1024)
  ```
  16 KB matches the default H2 max frame size + header overhead — most receives land in one buffer without realloc.

- [ ] **Step 2: Bulk-extend in `_queue_frame`.**
  ```mojo
  def _queue_frame(mut self, frame: Frame):
      var encoded = encode_frame(frame)
      self._outbuf.extend(encoded^)
  ```
  If `extend(List[UInt8])` consumes by move, `encoded^` works. Otherwise use `extend(Span(encoded))` — verify via Mojo MCP `lookup` for `List.extend`.

- [ ] **Step 3: Rewrite `_trim_inbuf` as in-place slide.** The current implementation rebuilds a fresh `List` byte-by-byte. Replace with an in-place memmove via `UnsafePointer`:
  ```mojo
  def _trim_inbuf(mut self, count: Int):
      if count <= 0:
          return
      var n = len(self._inbuf)
      if count >= n:
          self._inbuf.clear()
          return
      var remaining = n - count
      # In-place slide: src=self._inbuf[count:], dst=self._inbuf[:remaining]
      var ptr = self._inbuf.unsafe_ptr()
      memcpy(dest=ptr, src=ptr + count, count=remaining)
      self._inbuf.resize(remaining, UInt8(0))
  ```
  Use the canonical `memcpy` import and `List.resize` signature from Mojo 0.26.2. Confirm `unsafe_uninit_resize`-style API for shrinking without zeroing — json-simd-mojo Plan 8 used `unsafe_uninit_length` but that's for growth; for shrinking just `resize(remaining)` (no fill arg) should suffice.

- [ ] **Step 4: Tests.** All H2 unit + integration tests must pass. Specifically the `tests/test_h2_send_window_exhaustion.mojo` codec test from the prior session.

- [ ] **Step 5: Harness re-run.** Expect `List::_realloc` self/inclusive both to drop. The 18 % inclusive on `_realloc` should fall well below 10 %.

- [ ] **Step 6: Commit.** `perf(h2/connection): pre-size + bulk-extend + memcpy slide for connection buffers`.

---

## Task 6: Final measurement + retrospective

**Files:**
- Create: `plans/2026-04-26-h2-perf-phase1-codegen-allocation-retrospective.md`

- [ ] **Step 1: Final harness capture.** With all five tasks landed, run:
  ```bash
  N=100000 SERVERS="mojo-net hyper" bash bench/profile/h2-throughput.sh
  DURATION=120 PERF_DUR=110 bash bench/profile/h2-perf-record.sh   # longer for tight signal
  bash bench/profile/h2-hotspots.sh
  ```
  Capture is committed to `bench/profile/baselines/` as the new "post-Phase-1" reference.

- [ ] **Step 2: Write the retrospective.** Mirror the json-simd-mojo Plan 6/7/8 retrospective format:
  1. **Built vs. planned** — task checklist, deviations.
  2. **Cumulative numbers table** — req/s and p99 per endpoint, baseline `d6fdbcb` vs each task vs final, with % change column.
  3. **Hotspot delta** — same self-time top 10 from baseline vs final, with annotations.
  4. **Per-task wins** — what each commit moved the needle on, in % of total CPU recovered.
  5. **Open questions** — anything that didn't move as predicted, or that surfaced as a new top-5 item.

- [ ] **Step 3: Decision gate for Phase 2.** Compute new mojo / hyper ratio on `/baseline2` and `/json/...`. **If ≥80 % of hyper, declare victory** and stop perf work. **If <80 %, draft Phase 2** (algorithmic-tier — `Dict::_insert` → `InlineArray`, HPACK encoder fast paths, reduce per-request coro suspends).

- [ ] **Step 4: Commit.** `commit-smart`. Suggested message: `docs(plans): Phase 1 codegen-allocation retrospective`.

---

## Exit criteria for Phase 1

Phase 2 is **not** drafted until Phase 1's retrospective answers:

1. What is mojo-net's req/s on `/baseline2` and `/json/50?m=6` post-Phase-1, and what % of hyper does that represent?
2. Where in the hotspot table did the three target families end up? (Each should be ≤ half its Phase 0 weight, or the task is considered failed.)
3. What is the new top hotspot? (Phase 2 candidate.)
4. Did the cumulative throughput on `/baseline2` cross the 80 % decision gate?

---

## Out of scope (deliberately)

- **HPACK encoder.** Phase 0 didn't show encoder symbols in the top 30 self. If they surface post-Phase-1, fold into Phase 2.
- **Stream-state `Dict` → `InlineArray`.** `Dict::_insert` was 2.95 % self in Phase 0. Phase 2 candidate.
- **Coroutine context-switch reduction.** Architectural; needs its own plan.
- **rustls swap, kTLS, OpenSSL/BoringSSL.** Phase 0 falsified — 0.6 % CPU. Permanently deferred.
- **`/static/*` correctness bug (Open Question O-1).** That's a correctness fix, not perf. Should be addressed before any post-Phase-1 static-file claim, but it's not part of this plan.
- **H1 plain and H3.** This plan is H2 TLS only, where the hotspot data exists.

---

## Risk notes

- **Mojo move semantics on `extend(encoded^)`**: if `extend` doesn't consume by move, the `^` is a syntax error. Verify via MCP before committing each task.
- **`add_lowercase` correctness contract**: if any callsite passes a non-lowercase name (e.g. tests using mixed-case), the wire becomes non-conformant. Cross-grep for `add_lowercase` usage to confirm only HPACK-decoded names reach it.
- **`_trim_inbuf` `memcpy` overlap**: the source and destination overlap (this is the whole point of trim). Use `memmove` semantics — `memcpy` with overlapping regions is UB in C. Mojo's `memcpy` may or may not allow it; check `lookup memmove` or use a `for i in range(remaining)` copy if memmove isn't available.
- **Regression on `/static/*`**: don't optimize against the broken static path until O-1 is resolved, or you're optimizing a placeholder.
