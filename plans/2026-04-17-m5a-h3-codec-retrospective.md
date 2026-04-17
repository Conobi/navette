# M5a Retrospective — H3 Frame Codec + QPACK Static-Only + QC-2

**Date:** 2026-04-17
**Spec:** `specs/2026-04-17-m5a-h3-codec.md`
**Plan:** `plans/2026-04-17-m5a-h3-codec.md`
**Commits:** `3916044..a55a69a` (15 commits including docstring fix + context updates; 14 code commits)
**Tests:** 60/60 src, 35/35 conformance

---

## Built vs. planned

All 8 plan tasks + STREAMS_BLOCKED prereq (3 tasks) delivered:

- **STREAMS_BLOCKED prereq**
  - Task 0: 2 integration tests (failing) in `tests/test_quic_connection.mojo`
  - Task 1: `src/quic/stream_map.mojo` — 4 new fields + `open_stream` flag-setting
  - Task 2: `src/quic/connection.mojo` — §9 STREAMS_BLOCKED emission + MAX_STREAMS reset

- **M5a**
  - Task 0: `src/h3/error.mojo` + `src/h3/__init__.mojo` — H3/QPACK error codes, stream type constants
  - Task 1: `src/h3/frame.mojo` — H3 frame codec (DATA, HEADERS, SETTINGS, pass-through unknown)
  - Task 2: `src/h3/qpack.mojo` (static table) — 99-entry RFC 9204 Appendix A table + lookup functions
  - Task 3: `src/h3/qpack.mojo` (Huffman) — RFC 7541 Appendix B encode/decode, sliding-window accumulator
  - Task 4: `src/h3/qpack.mojo` (QpackEncoder) + `tests/test_h3_qpack.mojo` — encoder + decoder (decoder implemented early to enable encoder roundtrip tests)
  - Task 5: `src/h3/qpack.mojo` (QpackDecoder tests) — error-case tests, Delta Base validation
  - Task 6: `conformance/scripts/oracle_h3.py` + vectors — uses `pylsqpack` directly (not `aioquic.h3.qpack`)
  - Task 7: `conformance/tests/test_h3_frame_cross.mojo` + `conformance/tests/test_qpack_cross.mojo` — 5 frame + 5 QPACK cross-validation tests; runner updates

**LoC delta:** ~1650 lines across 12 files (within spec estimate of 1400–1800).

---

## Deviations and why

### 1. QpackDecoder implemented in T4, not T5

The plan staged T4 as encoder-only. To roundtrip-test the encoder, T4 needed a working decoder. The T4 agent implemented the full decoder, making T5 a test-only task (error cases + Delta Base validation). The plan's separation was artificial — encoder and decoder are tightly coupled in unit tests.

### 2. `pylsqpack` instead of `aioquic.h3.qpack`

The spec mentioned `aioquic.h3.qpack` as the oracle API. During T6 implementation, the agent discovered that aioquic 1.3.0 exposes QPACK only via `pylsqpack` (a C extension), not through a public `aioquic.h3.qpack` module. The oracle script uses `pylsqpack.Encoder`/`Decoder` directly. The vectors are equivalent — `pylsqpack` is aioquic's own QPACK backend, so the cross-validation is valid.

### 3. Oracle `huffman` flag removed

The original oracle stored a `"huffman": True/False` flag per QPACK vector, but `pylsqpack` controls Huffman encoding internally — the flag was set based on the test description string, not the actual output. Removed in commit `966bbee` (before T7 consumed the vectors) so the JSON is not misleading.

### 4. §4.5.4 prefix width: 5-bit → 4-bit fix

The initial T4 implementation used a 5-bit prefix for §4.5.4 name-reference encoding (`qpack_encode_int(idx, 5)`). RFC 9204 §4.5.4 specifies `0 1 T N xxxx` — a 4-bit index prefix. The encoder and decoder were consistent with each other (roundtrips passed) but not RFC-compliant. Fixed in commit `00560c8`. This is the most significant correctness bug caught during reviews — it would have caused interop failures for indices ≥ 16 against any RFC-compliant peer.

### 5. Static table indices: HPACK ≠ QPACK

The plan's example `test_encode_indexed_static` expected `:method GET` at index 4 (HPACK table numbering). RFC 9204 Appendix A places it at index 17. T2 fetched the actual RFC and corrected all 99 entries. The unit test uses index 17 → wire byte `0xD1`. The final cross-cutting review confirmed this was correct.

### 6. Delta Base validation added (T5)

The spec required raising on S=1 with RIC=0. The initial T4 decoder skipped `data[1]` without checking the S bit. Added in commit `bcf6429`: decode the full RIC byte via 8-bit prefix, then check S bit and Delta Base value != 0. Added `test_decode_s_bit_raises` test.

### 7. Short-packet padding fix in connection.mojo (STREAMS_BLOCKED task 2)

During STREAMS_BLOCKED implementation, the agent discovered that 1-RTT packets with payload < 4 bytes would crash header protection (HP sample requires ≥ 4 payload bytes). Added minimum padding to 4 bytes in `_build_packet`. This was an extra change beyond the STREAMS_BLOCKED spec, but correct per RFC 9001 §5.4.2 and discovered organically during the task.

### 8. Huffman: sliding-window UInt64 accumulator for long strings

The plan sketched a single-load approach for Huffman decode. For strings > 8 bytes this overflows. T3 implemented a sliding-window UInt64 accumulator that shifts bits in as each code symbol is emitted. No spec deviation — the plan left "correctness over speed" to the implementer.

### 9. §4.5.6 encoder and decoder both wrong (post-M5a gap closure)

Discovered while rewriting `test_qpack_cross.mojo` to feed real oracle bytes. RFC 9204 §4.5.6 format is `0 0 1 N H nnn` — a single byte combining the section type, N flag, H (Huffman-for-name) flag, and 3-bit name length prefix. The M5a implementation wrote a separate `0x20` flags byte followed by a 7-bit `_qpack_encode_string` header for the name (two bytes where one is required). The encoder and decoder were consistent with each other (roundtrips passed) but non-RFC-compliant. Oracle byte `0x2F` for `x-custom-header` (H=1, 3-bit len=7+4=11) caused a UTF-8 crash when fed to the old decoder, which tried to interpret Huffman-encoded name bytes as a UTF-8 string.

Fixed in post-M5a commit `9e69cb9`:
- Encoder §4.5.6: encode name length with 3-bit prefix, OR H bit into the same byte as `001 N H nnn`
- Decoder §4.5.6: extract H from bit3 of `b`, use `qpack_decode_int(data, pos, 3)` for name length, then `huffman_decode` or `String(unsafe_from_utf8=...)` depending on H
- Also fixed static table entries 52, 57, 58 (missing spaces after semicolons in compound values), and added `test_huffman_encode_known_vector` (RFC 7541 C.4.1 "custom-key").

This is the most significant interop bug in M5a — §4.5.6 custom headers would have been unreadable by any RFC-compliant peer. Root cause: roundtrip-only tests cannot detect format bugs where encoder and decoder make the same mistake symmetrically.

---

## Pain points

- **QPACK static table indices**: The plan's inline examples used HPACK indices (wrong). Any agent that followed the plan examples without fetching the RFC would have produced an incorrect table. The T2 agent fetched RFC 9204 Appendix A directly — this worked, but the plan should have been more explicit.
- **Encoder/decoder roundtrip coupling**: Writing encoder without decoder (as the plan staged it) produces untestable code. Future plans for codec pairs should stage both together in a single task.
- **`pylsqpack` API discovery**: The oracle API (`aioquic.h3.qpack` vs. `pylsqpack`) required trial-and-error at T6. The research doc `qpack-h3-scope.md` referenced the wrong module path. Worth noting in future oracle tasks.
- **Roundtrip tests cannot catch symmetric bugs**: §4.5.4 N/T swap, §4.5.6 format, and static table spacing were all invisible to roundtrip tests. Only oracle cross-validation (feeding external hex bytes to our decoder) exposed them. Future codec specs should require at least one oracle-decode test per instruction type before marking conformance complete.

---

## Open questions

### Required-later (inherited from prior milestones)

| What | Severity | Trigger |
|---|---|---|
| M3c integration test coverage gaps (FC error paths, MAX_STREAM_DATA/DATA flow cycle, CID retire→reissue, loss+retransmit of M3c frame types) | required-later | Before M5b relies on these behaviors end-to-end |
| oACK rejection integration test | required-later | When `PacketNumberSpace.process_ack` or a dedicated ACK-injection path is exposed |

### Deferred from M5a (all resolved in gap-closure commit)

| What | Resolution |
|---|---|
| QC-2 vector coverage: POST /upload and 404 Not Found not cross-validated | Added in `test_cross_decode_post_upload` and `test_cross_decode_404` (commit `9e69cb9`) |
| §4.5.6 encoder/decoder RFC non-compliance | Fixed in commit `9e69cb9` — encoder combines H+3-bit-len into first byte; decoder extracts H from bit3 |
| Post-base indexed dispatch (`0001xxxx`) raises generic error, not explicit QPACK_DECOMPRESSION_FAILED | Still deferred; functionally equivalent for M5a/M5b; add explicit raise when dynamic table support begins |

---

## Next spec recommendations (M5b)

1. **M5b — H3 connection state machine + H3HandlerServer + H3Session + GOAWAY.** M5a closes the codec layer. M5b wires it into the QUIC transport: control stream setup on connection init, SETTINGS exchange, request stream demux (stream_id % 4 → client-initiated bidi), GOAWAY sending/receiving. H3HandlerServer mirrors H2HandlerServer; H3Session mirrors H2Session. Spec should be written now that M5a's actual types are concrete.

2. **QPACK encoder/decoder stream stubs.** M5b opens the unidirectional encoder/decoder streams (type 0x02 / 0x03) but keeps them idle (static-only = no encoder stream data). The H3_STREAM_QPACK_ENCODER / H3_STREAM_QPACK_DECODER constants from `error.mojo` are ready for M5b to use.

3. **QC-2 vector gap closure.** The two missing cross-validation cases (POST and 404) can be added in M5b's conformance task with no new oracle work — the JSON vectors already exist.
