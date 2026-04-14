# M3c Integration Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the integration-test gaps flagged `required-later` in M3c's open follow-ups (`docs/project-context.md:109`), giving M4a a known-good baseline.

**Architecture:** Integration-test-only plan. No production changes. All tests live in the existing `tests/test_quic_connection.mojo` file and reuse the handshake-establishment helper from M3c (`_establish_handshake` / equivalent). The plan closes 5 specific gaps: FC limit-violation error paths, MAX_*_DATA flow cycle, linear MAX_STREAMS growth, CID retire/reissue round-trip, and loss+retransmit for each M3c frame kind.

**Tech Stack:** Mojo 0.26.2, sans-I/O `QuicConnection` loopback harness from M3b.

**Prerequisite for:** `plans/2026-04-15-m4a-quic-cc-core.md`. M4a must not start until this plan lands on main.

---

## File structure

| File | Responsibility | Delta |
|---|---|---|
| `tests/test_quic_connection.mojo` | All 5 new integration tests, added alongside M3c's existing `test_stream_data_transfer`, `test_multi_stream`, `test_reset_stream`, `test_stop_sending`, `test_cid_issuance` etc. | +~300 LoC |

No production file changes. No new test files. No `scripts/run_tests.sh` changes (file already registered since M3c).

## Scope check

Single integration-test subsystem, single file. No split needed.

---

## Phase 1 — FC enforcement paths (Tasks 1-2)

### Task 1: FLOW_CONTROL_ERROR and FINAL_SIZE_ERROR end-to-end

**Files:**
- Modify: `tests/test_quic_connection.mojo` (+~80 LoC, 2 tests)

**Goal:** Exercise the server/peer emitting CONNECTION_CLOSE with `FLOW_CONTROL_ERROR` when the sender exceeds advertised FC limits, and `FINAL_SIZE_ERROR` when a stream's observed final size contradicts a prior RESET_STREAM / STREAM+FIN.

- [ ] **Step 1: Write test skeleton**

```mojo
def test_flow_control_error_on_overflow():
    """Sender exceeds peer's MAX_DATA → peer closes with FLOW_CONTROL_ERROR (0x03)."""
    var c, s = _establish_handshake()
    var sid = c.open_stream(bidi=True)
    # Force client's conn FC limit to a small value by truncating peer's advertised limit.
    # (test-only mutation) — simulate peer advertising max_data=1000.
    c.conn_fc_send.ensure_limit(1000)
    # Client sends 2000 bytes — should violate when exceeding 1000.
    var buf = bytes([UInt8(0x41)] * 2000)
    _ = c.send_stream_data(sid, buf, fin=False)
    # Flush client → server. Server should observe overflow if client ignores FC.
    # In the sans-I/O harness the client's send_stream_data is gated by conn_fc_send.check_limit;
    # force-bypass by directly invoking _handle_stream_frame on the server with an oversized frame:
    var frame = _build_stream_frame(sid, offset=0, data=buf, fin=False)
    try:
        s._handle_stream_frame(frame)
        assert_true(False, "server should have raised FLOW_CONTROL_ERROR")
    except e:
        assert_true(String(e).find("FLOW_CONTROL_ERROR") >= 0 or s.is_closing, "expected FC violation")
    print("PASS: test_flow_control_error_on_overflow")


def test_final_size_error_on_reset_mismatch():
    """RESET_STREAM with final_size less than previously-observed STREAM offset → FINAL_SIZE_ERROR (0x06)."""
    var c, s = _establish_handshake()
    var sid = c.open_stream(bidi=True)
    # Client sends 100 bytes at offset 0.
    _ = c.send_stream_data(sid, bytes([UInt8(0x41)] * 100), fin=False)
    # Flush frames → server sees 100 bytes received.
    _flush(c, s)
    # Now send RESET_STREAM with final_size=50 (contradicting observed 100).
    var reset_frame = _build_reset_stream_frame(sid, app_error=0, final_size=50)
    try:
        s._handle_reset_stream(reset_frame)
        assert_true(False, "server should have raised FINAL_SIZE_ERROR")
    except e:
        assert_true(String(e).find("FINAL_SIZE_ERROR") >= 0 or s.is_closing, "expected final-size violation")
    print("PASS: test_final_size_error_on_reset_mismatch")
```

- [ ] **Step 2: Verify tests fail**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: FAIL — either compile error (missing `_build_stream_frame` helper) or assertion failure if server doesn't raise.

- [ ] **Step 3: Add helper builders if not present**
Check `tests/test_quic_connection.mojo` for existing `_build_stream_frame` / `_build_reset_stream_frame` — if absent, add thin wrappers around `src/quic/frame.mojo` constructors. If helpers exist, use them directly.

- [ ] **Step 4: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: PASS — both assertions succeed.

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `test: add FLOW_CONTROL_ERROR and FINAL_SIZE_ERROR integration tests`

---

### Task 2: MAX_STREAM_DATA / MAX_DATA window cycle

**Files:**
- Modify: `tests/test_quic_connection.mojo` (+~60 LoC, 1 test)

**Goal:** Verify the full flow: sender writes near stream limit, receiver consumes data, receiver emits MAX_STREAM_DATA + MAX_DATA when `should_update` trips at the 50% threshold, sender sees the new limit and writes again.

- [ ] **Step 1: Write test**

```mojo
def test_max_stream_data_and_max_data_cycle():
    """Full FC update round-trip — sender blocks at limit, receiver grants more, sender unblocks."""
    var c, s = _establish_handshake()
    var sid = c.open_stream(bidi=True)

    # M3c default stream FC window is 1 MiB. Fill >50% to trip should_update.
    # Use a 600 KiB payload (above 50% of 1 MiB).
    var chunk = bytes([UInt8(0x41)] * (600 * 1024))
    _ = c.send_stream_data(sid, chunk, fin=False)
    _flush(c, s)

    # Server consumes the data (drains RecvBuf).
    var recv_out = List[UInt8]()
    var _read = s.recv_stream_data(sid, recv_out, max_bytes=600 * 1024)
    assert_true(len(recv_out) == 600 * 1024, "server read 600 KiB")

    # Next send from server should produce MAX_STREAM_DATA (stream FC tripped)
    # and potentially MAX_DATA (conn FC tripped).
    var max_frames = _drain_pending_max_frames(s)
    var saw_max_stream_data = False
    var saw_max_data = False
    for f in max_frames:
        if f.kind == FRAME_MAX_STREAM_DATA and f.stream_id == sid:
            saw_max_stream_data = True
            assert_true(f.limit > 1048576, "new limit above 1 MiB")
        if f.kind == FRAME_MAX_DATA:
            saw_max_data = True
    assert_true(saw_max_stream_data, "server emitted MAX_STREAM_DATA after consume")
    assert_true(saw_max_data, "server emitted MAX_DATA after consume (conn FC tripped too)")

    # Deliver MAX_* frames to client, observe client's FC limits grew.
    _deliver_frames(s, c, max_frames)
    assert_true(c.stream_fc_send_limit(sid) > 1048576, "client stream FC limit advanced")
    assert_true(c.conn_fc_send.limit > 10 * 1048576, "client conn FC limit advanced")

    # Client can now send again.
    var more = bytes([UInt8(0x42)] * 100)
    var written = c.send_stream_data(sid, more, fin=False)
    assert_true(written == 100, "client unblocked, wrote 100 more bytes")

    print("PASS: test_max_stream_data_and_max_data_cycle")
```

- [ ] **Step 2: Verify test fails**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: FAIL — helpers `_drain_pending_max_frames` / `_deliver_frames` missing, or logic incomplete.

- [ ] **Step 3: Add test helpers**
Add `_drain_pending_max_frames(conn) -> List[Frame]` that iterates connection send state for MAX_* frames (using existing `_build_app_frames` output or direct `streams_needing_update` / `fc_needs_update` flags). Add `_deliver_frames(src, dst, frames)` that serializes each frame and calls `dst._dispatch_frame(frame)`.

- [ ] **Step 4: Verify test passes**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: PASS.

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `test: add MAX_STREAM_DATA/MAX_DATA flow cycle integration test`

---

## Phase 2 — Stream concurrency and CID lifecycle (Tasks 3-4)

### Task 3: Linear MAX_STREAMS growth on the wire

**Files:**
- Modify: `tests/test_quic_connection.mojo` (+~60 LoC, 1 test)

**Goal:** Verify `check_max_streams_update`'s linear formula (`new_limit = peer_completed + initial_max_streams`) is emitted correctly when peer completes streams, not the buggy exponential variant caught in M3c review.

- [ ] **Step 1: Write test**

```mojo
def test_max_streams_linear_growth():
    """After peer completes N streams, receiver emits MAX_STREAMS = N + initial_max_streams."""
    var c, s = _establish_handshake()
    # M3c default: initial_max_streams_bidi = 100.

    # Open 50 bidi streams from client side, close them all (send STREAM+FIN, then consume+ack).
    var sids = List[Int]()
    for i in range(50):
        var sid = c.open_stream(bidi=True)
        sids.append(sid)
        _ = c.send_stream_data(sid, bytes([UInt8(0x41)]), fin=True)

    _flush(c, s)

    # Server consumes each stream's single byte, triggering stream closure.
    for sid in sids:
        var out = List[UInt8]()
        _ = s.recv_stream_data(sid, out, max_bytes=1)
    _flush(s, c)  # server's ACKs + MAX_STREAMS

    # Expected MAX_STREAMS(bidi) = 50 (peer_completed) + 100 (initial) = 150.
    var max_streams_emitted = _last_emitted_max_streams(c, bidi=True)
    assert_true(max_streams_emitted == 150,
                "MAX_STREAMS should be 50 + 100 = 150, got " + String(max_streams_emitted))

    # Not exponential: definitely not 200 (= 2*100), not 150*2, etc.
    print("PASS: test_max_streams_linear_growth")
```

- [ ] **Step 2: Verify test fails** (helper missing)
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: FAIL — `_last_emitted_max_streams` undefined.

- [ ] **Step 3: Add helper**
Add `_last_emitted_max_streams(conn, bidi: Bool) -> UInt64` that returns the max limit the connection has granted the peer (read from `stream_map.peer_bidi_limit` / `peer_uni_limit` or equivalent M3c field).

- [ ] **Step 4: Verify test passes**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: PASS.

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `test: add linear MAX_STREAMS growth integration test`

---

### Task 4: CID retire → reissue round-trip

**Files:**
- Modify: `tests/test_quic_connection.mojo` (+~50 LoC, 1 test)

**Goal:** Verify M3c's `CidManager` correctly issues a replacement CID when peer sends RETIRE_CONNECTION_ID, and the new NEW_CONNECTION_ID is advertised.

- [ ] **Step 1: Write test**

```mojo
def test_cid_retire_triggers_reissue():
    """Client retires a peer CID → server issues a replacement NEW_CONNECTION_ID."""
    var c, s = _establish_handshake()

    # After handshake, server has issued initial + at least 1 preferred CID.
    # Record the current active count.
    var initial_active = len(_active_cids(s))
    assert_true(initial_active >= 2, "server has ≥2 active CIDs post-handshake")

    # Find a CID to retire (pick a non-primary one).
    var to_retire = _pick_non_primary_cid(s)
    var retire_frame = _build_retire_cid_frame(sequence=to_retire.sequence)

    s._handle_retire_connection_id(retire_frame)

    # Server's pending NEW_CID queue should now have an entry.
    var pending = s.cid_manager.pending_new_cid_entries()
    assert_true(len(pending) >= 1, "server queued a replacement NEW_CID")
    assert_true(pending[0].advertised == False, "replacement not yet advertised")

    # Drain pending to build frames — marks as advertised.
    var new_frames = s._build_cid_frames()
    assert_true(len(new_frames) >= 1, "built NEW_CONNECTION_ID frame(s)")
    assert_true(pending[0].advertised == True, "marked advertised after build")

    # Active count restored.
    assert_true(len(_active_cids(s)) >= initial_active,
                "active CID count restored after reissue")

    print("PASS: test_cid_retire_triggers_reissue")
```

- [ ] **Step 2: Verify test fails**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: FAIL — helpers missing.

- [ ] **Step 3: Add helpers**
`_active_cids(conn)` returns list of `CidEntry` with state `CID_ACTIVE`. `_pick_non_primary_cid(conn)` picks first active CID whose sequence != primary. `_build_retire_cid_frame(sequence)` wraps `frame.mojo`'s RETIRE_CONNECTION_ID builder.

- [ ] **Step 4: Verify test passes**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: PASS.

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `test: add CID retire-and-reissue integration test`

---

## Phase 3 — Loss + retransmit for M3c frame kinds (Task 5)

### Task 5: Loss + retransmit for RESET_STREAM / STOP_SENDING / MAX_* / NEW_CID

**Files:**
- Modify: `tests/test_quic_connection.mojo` (+~100 LoC, 1 consolidated test with subsections)

**Goal:** Verify each M3c frame kind that goes through SentStreamFrame tracking is correctly re-emitted on loss. Single omnibus test covers all five frame kinds.

- [ ] **Step 1: Write test**

```mojo
def test_m3c_frames_retransmit_on_loss():
    """RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA, MAX_DATA, NEW_CONNECTION_ID
    all re-emitted if their carrier packet is declared lost."""
    var c, s = _establish_handshake()
    var sid = c.open_stream(bidi=True)
    _ = c.send_stream_data(sid, bytes([UInt8(0x41)] * 100), fin=False)
    _flush(c, s)

    # --- Subsection A: RESET_STREAM + STOP_SENDING retransmit ---
    _ = c.reset_stream(sid, app_error=7)
    _ = s.stop_sending(sid, app_error=11)
    var c_pkt = _build_next_outgoing_packet(c)  # contains RESET_STREAM
    var s_pkt = _build_next_outgoing_packet(s)  # contains STOP_SENDING
    # "Lose" both packets without delivering.
    c._on_app_pkt_lost(c_pkt.pn)
    s._on_app_pkt_lost(s_pkt.pn)
    # Next build should re-emit.
    var c_pkt2 = _build_next_outgoing_packet(c)
    var s_pkt2 = _build_next_outgoing_packet(s)
    assert_true(_pkt_contains_frame(c_pkt2, FRAME_RESET_STREAM, sid),
                "client re-emits RESET_STREAM after loss")
    assert_true(_pkt_contains_frame(s_pkt2, FRAME_STOP_SENDING, sid),
                "server re-emits STOP_SENDING after loss")

    # --- Subsection B: MAX_STREAM_DATA / MAX_DATA retransmit ---
    var c2, s2 = _establish_handshake()
    var sid2 = c2.open_stream(bidi=True)
    _ = c2.send_stream_data(sid2, bytes([UInt8(0x41)] * (600 * 1024)), fin=False)
    _flush(c2, s2)
    var out = List[UInt8]()
    _ = s2.recv_stream_data(sid2, out, max_bytes=600 * 1024)
    var upd_pkt = _build_next_outgoing_packet(s2)  # MAX_STREAM_DATA + MAX_DATA
    assert_true(_pkt_contains_frame(upd_pkt, FRAME_MAX_STREAM_DATA, sid2), "emitted initially")
    s2._on_app_pkt_lost(upd_pkt.pn)
    var upd_pkt2 = _build_next_outgoing_packet(s2)
    assert_true(_pkt_contains_frame(upd_pkt2, FRAME_MAX_STREAM_DATA, sid2),
                "server re-emits MAX_STREAM_DATA after loss")
    assert_true(_pkt_contains_frame(upd_pkt2, FRAME_MAX_DATA, 0),
                "server re-emits MAX_DATA after loss")

    # --- Subsection C: NEW_CONNECTION_ID retransmit ---
    var c3, s3 = _establish_handshake()
    var retire = _build_retire_cid_frame(sequence=_pick_non_primary_cid(s3).sequence)
    s3._handle_retire_connection_id(retire)
    var cid_pkt = _build_next_outgoing_packet(s3)
    assert_true(_pkt_contains_frame(cid_pkt, FRAME_NEW_CONNECTION_ID, 0), "NEW_CID emitted")
    s3._on_app_pkt_lost(cid_pkt.pn)
    # Loss should clear `advertised` so the next build re-emits.
    var cid_pkt2 = _build_next_outgoing_packet(s3)
    assert_true(_pkt_contains_frame(cid_pkt2, FRAME_NEW_CONNECTION_ID, 0),
                "server re-emits NEW_CID after loss")

    print("PASS: test_m3c_frames_retransmit_on_loss")
```

- [ ] **Step 2: Verify test fails** (helpers missing / incomplete)
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: FAIL — `_build_next_outgoing_packet`, `_pkt_contains_frame` missing, or direct `_on_app_pkt_lost` access incomplete.

- [ ] **Step 3: Add helpers**
`_build_next_outgoing_packet(conn)` invokes the connection's build-packet path and returns `(pn, frames)`. `_pkt_contains_frame(pkt, frame_kind, stream_id)` scans frame list for matching kind (and stream_id if relevant).

- [ ] **Step 4: Verify test passes**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: PASS.

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `test: add loss-retransmit coverage for M3c frame kinds`

---

## Final verification

- [ ] **Run full test suite**
Run: `bash scripts/run_tests.sh`
Expected: all src tests pass (should be ≥53/53 from M3c; 5 new ones fold into the existing `test_quic_connection.mojo` test-count).

- [ ] **Run conformance**
Run: `bash conformance/scripts/run_tests.sh`
Expected: 33/33 (no regression).

## Deferred

None. This plan exhaustively covers the `required-later` items in M3c's open follow-ups. The `optional`-severity items (BLOCKED emission, pre-commit mutation vs AEAD failure, spurious STREAM_READABLE, app_frames_sent cleanup) remain open for M4a/M4b or later.
