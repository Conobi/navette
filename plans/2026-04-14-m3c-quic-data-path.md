# M3c — QUIC Data Path + CID Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend QuicConnection with stream multiplexing, dual-level flow control, full RESET_STREAM/STOP_SENDING, and CID management so client and server can exchange application data after handshake.
**Architecture:** 4 new modules (flow_control, stream, stream_map, cid) compose into the existing QuicConnection orchestrator via StreamMap and CidManager fields. FlowControl is reused at both connection and per-stream levels. Stream state machines use explicit enums (6 send states, 7 recv states). CidManager handles issuance, retirement, and CVE-2024-22189 stuffing defense.
**Tech Stack:** Mojo 0.26.2, librustls-mojo FFI (existing), Python hmac/os for CID token generation.

---

## File Structure

| File | Purpose | Action |
|------|---------|--------|
| `src/quic/flow_control.mojo` | FlowControl struct with received/consumed split | Create |
| `src/quic/stream.mojo` | SendState, RecvState enums, RecvBuf, SendBuf, Stream struct, helpers | Create |
| `src/quic/stream_map.mojo` | StreamMap — collection, MAX_STREAMS, scheduling, conn-level FC | Create |
| `src/quic/cid.mojo` | CidEntry, CidManager — issuance, retirement, reset tokens | Create |
| `src/quic/connection.mojo` | Wire StreamMap + CidManager, frame dispatch, send path, public API | Modify |
| `tests/test_quic_flow_control.mojo` | FlowControl unit tests | Create |
| `tests/test_quic_stream.mojo` | RecvBuf, SendBuf, Stream state machine tests | Create |
| `tests/test_quic_stream_map.mojo` | StreamMap creation, cleanup, MAX_STREAMS, FC tests | Create |
| `tests/test_quic_cid.mojo` | CidManager issuance, retirement, stuffing defense tests | Create |
| `tests/test_quic_connection.mojo` | Integration tests (extend existing) | Modify |
| `scripts/run_tests.sh` | Add 4 new test entries | Modify |

---

## Phase 1 — Foundation (Tasks 1-2, parallel — no file overlap)

### Task 1: FlowControl

**Files:**
- Create: `src/quic/flow_control.mojo`
- Create: `tests/test_quic_flow_control.mojo`

**Spec:** §2.1 (FlowControl struct), §2.2-2.8 (usage patterns)

Implement the `FlowControl` struct per spec §2.1. Key design: **two counters** — `received` (bytes on wire, for enforcement) and `consumed` (bytes app-read, for window updates). This split prevents the B1 deadlock where enforcement and window updates conflict.

**Struct fields:** `received: UInt64`, `consumed: UInt64`, `limit: UInt64`, `window: UInt64`, `blocked_at: UInt64`.

**Methods:**
- `__init__(out self, limit: UInt64, window: UInt64)` — sets limit and window, zeros rest
- Copy + move constructors (Copyable, Movable)
- `should_update(self) -> Bool` — `(self.limit - self.consumed) < (self.window // 2)`
- `next_limit(self) -> UInt64` — `self.consumed + self.window`
- `update_limit(mut self) -> UInt64` — sets limit to next_limit, returns it
- `add_received(mut self, bytes: UInt64)` — `self.received += bytes`
- `add_consumed(mut self, bytes: UInt64)` — `self.consumed += bytes`
- `check_limit(self, new_bytes: UInt64) -> Bool` — `self.received + new_bytes <= self.limit`
- `available(self) -> UInt64` — `max(0, self.limit - self.received)`
- `ensure_limit(mut self, new_limit: UInt64)` — monotonic update

**Tests (~200 LoC):**

- [ ] **Step 1: Write test file**

```mojo
# tests/test_quic_flow_control.mojo
from src.quic.flow_control import FlowControl

def test_initial_state():
    var fc = FlowControl(limit=1048576, window=1048576)  # 1 MiB
    assert_true(fc.available() == 1048576, "initial available")
    assert_true(not fc.should_update(), "should not update initially")
    assert_true(fc.check_limit(100), "can receive 100 bytes")
    print("PASS: test_initial_state")

def test_add_received_and_available():
    var fc = FlowControl(limit=1000, window=1000)
    fc.add_received(600)
    assert_true(fc.available() == 400, "available after 600 received")
    fc.add_received(400)
    assert_true(fc.available() == 0, "available after 1000 received")
    print("PASS: test_add_received_and_available")

def test_check_limit_enforcement():
    var fc = FlowControl(limit=1000, window=1000)
    fc.add_received(900)
    assert_true(fc.check_limit(100), "exactly at limit")
    assert_true(not fc.check_limit(101), "over limit by 1")
    print("PASS: test_check_limit_enforcement")

def test_should_update_threshold():
    var fc = FlowControl(limit=1000, window=1000)
    # Remaining = limit - consumed = 1000, window//2 = 500 → no update
    assert_true(not fc.should_update(), "no update at start")
    fc.add_consumed(400)
    # Remaining = 1000 - 400 = 600 > 500 → no update
    assert_true(not fc.should_update(), "no update at 400 consumed")
    fc.add_consumed(101)
    # Remaining = 1000 - 501 = 499 < 500 → update!
    assert_true(fc.should_update(), "should update at 501 consumed")
    print("PASS: test_should_update_threshold")

def test_update_limit():
    var fc = FlowControl(limit=1000, window=1000)
    fc.add_consumed(600)
    var new_limit = fc.update_limit()
    # new_limit = consumed + window = 600 + 1000 = 1600
    assert_true(new_limit == 1600, "new limit is 1600")
    assert_true(fc.available() == 1600, "available updated to 1600")
    assert_true(not fc.should_update(), "should not update after update_limit")
    print("PASS: test_update_limit")

def test_ensure_limit_monotonic():
    var fc = FlowControl(limit=1000, window=1000)
    fc.ensure_limit(2000)
    assert_true(fc.available() == 2000, "limit raised to 2000")
    fc.ensure_limit(1500)
    assert_true(fc.available() == 2000, "limit not lowered")
    fc.ensure_limit(3000)
    assert_true(fc.available() == 3000, "limit raised to 3000")
    print("PASS: test_ensure_limit_monotonic")

def test_received_consumed_split():
    """received and consumed are independent — received for enforcement, consumed for window."""
    var fc = FlowControl(limit=1000, window=1000)
    fc.add_received(800)  # 800 bytes on wire
    fc.add_consumed(200)  # app read only 200
    assert_true(fc.available() == 200, "available based on received")
    assert_true(not fc.should_update(), "should_update based on consumed (remaining=800)")
    fc.add_consumed(400)  # app reads more
    # remaining = 1000 - 600 = 400 < 500 → should update
    assert_true(fc.should_update(), "should_update triggers at consumed threshold")
    print("PASS: test_received_consumed_split")

def test_phantom_bytes():
    """RESET_STREAM adds to both received and consumed atomically."""
    var fc = FlowControl(limit=10485760, window=10485760)  # 10 MiB
    fc.add_received(500)   # some data on wire
    fc.add_consumed(200)   # app read some
    # RESET_STREAM with final_size=5000 → phantom = 5000 - 500 = 4500
    var phantom = UInt64(4500)
    fc.add_received(phantom)
    fc.add_consumed(phantom)
    assert_true(fc.received == 5000, "received accounts for phantom")
    assert_true(fc.consumed == 4700, "consumed accounts for phantom")
    print("PASS: test_phantom_bytes")

def test_blocked_at_tracking():
    var fc = FlowControl(limit=1000, window=1000)
    assert_true(fc.blocked_at == 0, "not blocked initially")
    fc.blocked_at = fc.limit
    assert_true(fc.blocked_at == 1000, "blocked at limit")
    fc.ensure_limit(2000)
    # blocked_at not auto-cleared — caller must reset
    print("PASS: test_blocked_at_tracking")

def main():
    test_initial_state()
    test_add_received_and_available()
    test_check_limit_enforcement()
    test_should_update_threshold()
    test_update_limit()
    test_ensure_limit_monotonic()
    test_received_consumed_split()
    test_phantom_bytes()
    test_blocked_at_tracking()
    print("All flow_control tests passed.")
```

- [ ] **Step 2: Verify tests fail** (module not found)
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_flow_control.mojo`
Expected: FAIL — module `src.quic.flow_control` not found

- [ ] **Step 3: Implement FlowControl**
Create `src/quic/flow_control.mojo` with the struct and all methods per spec §2.1.

- [ ] **Step 4: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_flow_control.mojo`
Expected: PASS — "All flow_control tests passed."

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `feat: add FlowControl struct with received/consumed split`

---

### Task 2: CidManager

**Files:**
- Create: `src/quic/cid.mojo`
- Create: `tests/test_quic_cid.mojo`

**Spec:** §5.1-5.10 (CID management)

Implement `CidEntry` and `CidManager` per spec §5. CID generation uses Python `os.urandom(8)`. Reset token generation uses Python `hmac.new(secret, cid, hashlib.sha256).digest()[:16]`.

**CidEntry fields:** `cid: List[UInt8]`, `sequence: UInt64`, `reset_token: List[UInt8]`, `state: UInt8` (0=Active, 1=PendingRetire, 2=Retired).

**CidManager fields:** `local_cids`, `local_next_seq`, `local_retire_prior_to`, `remote_cids`, `remote_active_cid_seq`, `local_active_limit`, `peer_active_limit`, `retire_queue`, `retire_queue_cap`, `highest_retire_prior_to`, `server_secret`.

**CID state constants:** `comptime CID_ACTIVE: UInt8 = 0`, `comptime CID_PENDING_RETIRE: UInt8 = 1`, `comptime CID_RETIRED: UInt8 = 2`.

**Methods on CidManager:**
- `__init__(out self, initial_local_cid: List[UInt8], initial_remote_cid: List[UInt8], local_active_limit: UInt64, peer_active_limit: UInt64)` — initializes with seq=0 CIDs, generates random server_secret
- `generate_cid(mut self) -> List[UInt8]` — 8-byte random via Python
- `generate_reset_token(self, cid: Span[UInt8, _]) -> List[UInt8]` — HMAC-SHA256
- `issue_new_cid(mut self) -> Optional[NewConnectionIdFrame]` — creates new CID at `local_next_seq`, returns frame if within peer_active_limit
- `on_new_connection_id(mut self, frame: NewConnectionIdFrame) raises` — spec §5.6
- `on_retire_connection_id(mut self, sequence: UInt64) raises` — spec §5.7
- `pending_new_cid_frames(mut self) -> List[Frame]` — frames for CIDs needing advertisement
- `pending_retire_frames(mut self) -> List[Frame]` — RETIRE_CONNECTION_ID frames from queue
- `active_local_count(self) -> Int` — count of Active local CIDs
- `active_remote_count(self) -> Int` — count of Active remote CIDs

**Tests (~250 LoC):**

- [ ] **Step 1: Write test file**

Test CID generation uniqueness, reset token determinism, NEW_CONNECTION_ID handling (store peer CIDs, retire_prior_to), retirement queue cap (PROTOCOL_VIOLATION on overflow), late-arriving CID retirement, RETIRE_CONNECTION_ID handling, and issuance within peer_active_limit.

Key tests:
- `test_cid_generation`: 8-byte, unique across 10 generations
- `test_reset_token_deterministic`: same key + CID = same token; different CID = different token
- `test_initial_state`: seq=0 local and remote CIDs present
- `test_issue_new_cid`: issues seq=1, respects peer_active_limit
- `test_on_new_connection_id_basic`: stores peer CID
- `test_retire_prior_to`: retire_prior_to=1 marks seq=0 as PendingRetire
- `test_retirement_queue_cap`: exceed cap → raises PROTOCOL_VIOLATION
- `test_late_arriving_cid`: CID with seq < highest_retire_prior_to → immediately PendingRetire
- `test_on_retire_connection_id`: marks local CID retired, triggers replacement issuance

- [ ] **Step 2: Verify tests fail**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_cid.mojo`
Expected: FAIL — module not found

- [ ] **Step 3: Implement CidManager**
Create `src/quic/cid.mojo` with CidEntry + CidManager per spec §5.

Import `NewConnectionIdFrame` from `src.quic.frame`. Use `from std.python import Python` for `os.urandom` and `hmac`. Frame generation uses the existing `Frame` struct with `_new_cid` and `_retire_cid` optional fields.

- [ ] **Step 4: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_cid.mojo`
Expected: PASS

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `feat: add CidManager with issuance, retirement, and stuffing defense`

---

## Phase 2 — Stream Module (Task 3, depends on Task 1)

### Task 3: Stream Building Blocks + Stream Struct

**Files:**
- Create: `src/quic/stream.mojo`
- Create: `tests/test_quic_stream.mojo`

**Spec:** §1.1-1.6 (state machines, stream ID helpers, Stream struct), §3.1-3.2 (RecvBuf, SendBuf)

This is the largest task (~800 production LoC + ~500 test LoC). Implements everything in `stream.mojo`:

**1. State constants:**
```
comptime SEND_READY: UInt8 = 0
comptime SEND_SEND: UInt8 = 1
comptime SEND_DATA_SENT: UInt8 = 2
comptime SEND_DATA_RECVD: UInt8 = 3  # terminal
comptime SEND_RESET_SENT: UInt8 = 4
comptime SEND_RESET_RECVD: UInt8 = 5  # terminal

comptime RECV_RECV: UInt8 = 0
comptime RECV_SIZE_KNOWN: UInt8 = 1
comptime RECV_DATA_RECVD: UInt8 = 2
comptime RECV_DATA_READ: UInt8 = 3  # terminal
comptime RECV_STOP_SENDING_SENT: UInt8 = 4
comptime RECV_RESET_RECVD: UInt8 = 5
comptime RECV_RESET_READ: UInt8 = 6  # terminal
```

**2. Helper functions:** `stream_is_bidi`, `stream_is_local`, `stream_is_client_initiated`, `send_state_is_terminal`, `recv_state_is_terminal`.

**3. RecvBuf (Copyable, Movable):**
- Fields: `ranges: List[List[UInt64]]` (each entry is [start, end]), `chunks: List[List[UInt8]]` with corresponding `chunk_offsets: List[UInt64]`, `read_offset: UInt64`, `max_gaps: UInt64`
- `write(mut self, offset, data, fin, mut stream_fin_offset) raises -> UInt64` — returns new bytes count. Validates final_size invariant (3 checks per spec §3.1). Merges ranges. Enforces gap limit → PROTOCOL_VIOLATION.
- `read(mut self, stream_fin_offset) -> Tuple[List[UInt8], Bool]` — drain contiguous from read_offset
- `is_complete(self, stream_fin_offset) -> Bool`
- `has_readable(self) -> Bool`

**4. SendBuf (Copyable, Movable):**
- Fields: `data`, `offset`, `unsent_offset`, `acked_offset`, `fin`, `fin_offset: Optional[UInt64]`, `fin_acked`
- `write(mut self, data, fin)` — append
- `has_pending(self) -> Bool`
- `pending_len(self) -> UInt64`
- `make_frame(mut self, stream_id, max_bytes) -> Optional[StreamFrame]` — skips past acked_offset
- `on_ack(mut self, ack_offset, ack_len)` — trims contiguous leading bytes
- `on_loss(mut self, lost_offset, lost_len)` — reset unsent_offset (not past acked_offset)
- `is_fully_acked(self) -> Bool`

**5. Stream struct (Copyable, Movable):** Per spec §1.5. All fields from the spec. Factory methods:
- `Stream.new_local_bidi(id, fc_send_limit, fc_recv_limit, fc_recv_window)` — creates with both sides
- `Stream.new_remote_bidi(id, fc_send_limit, fc_recv_limit, fc_recv_window)` — creates with both sides
- `Stream.new_local_uni(id, fc_send_limit)` — send-side only
- `Stream.new_remote_uni(id, fc_recv_limit, fc_recv_window)` — recv-side only
- `is_fully_closed(self) -> Bool` — checks terminal states on both applicable sides

**Tests (~500 LoC):**
Key test functions:
- `test_stream_id_helpers`: verify bidi/uni/local/client detection
- `test_recv_buf_in_order`: write [0,5), [5,10), read → 10 bytes
- `test_recv_buf_out_of_order`: write [5,10), [0,5), read → 10 bytes
- `test_recv_buf_overlapping`: write [0,10), [5,15), read → 15 bytes (accept-first-copy)
- `test_recv_buf_gap_limit`: exceed max_gaps → raises
- `test_recv_buf_fin`: FIN handling, fin_reached flag
- `test_recv_buf_fin_mismatch`: different final_size → FINAL_SIZE_ERROR
- `test_recv_buf_data_beyond_fin`: data past final_size → FINAL_SIZE_ERROR
- `test_send_buf_write_and_frame`: write data, make_frame, verify StreamFrame
- `test_send_buf_on_ack_trims`: ACK leading bytes, buffer trimmed
- `test_send_buf_on_loss_retransmit`: loss resets unsent_offset, skips acked
- `test_send_buf_fin`: FIN framing and acking
- `test_stream_bidi_lifecycle`: READY→SEND→DATA_SENT→DATA_RECVD + RECV→DATA_READ
- `test_stream_reset_send`: SEND→RESET_SENT→RESET_RECVD
- `test_stream_stop_sending_recv`: RECV→STOP_SENDING_SENT→RESET_RECVD→RESET_READ
- `test_stream_uni_direction`: local uni has send only, remote uni has recv only
- `test_stream_fully_closed`: bidi needs both terminal, uni needs one

- [ ] **Step 1: Write test file** with all tests above
- [ ] **Step 2: Verify tests fail** — module not found
- [ ] **Step 3: Implement stream.mojo** — all types per spec §1 and §3
- [ ] **Step 4: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_stream.mojo`
Expected: PASS
- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `feat: add Stream module with state machines, RecvBuf, and SendBuf`

---

## Phase 3 — StreamMap (Task 4, depends on Task 3)

### Task 4: StreamMap

**Files:**
- Create: `src/quic/stream_map.mojo`
- Create: `tests/test_quic_stream_map.mojo`

**Spec:** §4.1-4.5 (StreamMap struct, creation, cleanup, MAX_STREAMS, scheduling)

**StreamMap fields per spec §4.1.** Additional fields for scheduling:
- `sendable_ids: List[Int]` — ordered list of stream IDs with pending send data
- `send_index: Int` — rotating start for round-robin
- `initial_max_streams_bidi: UInt64` — initial concurrent target (for MAX_STREAMS formula)
- `initial_max_streams_uni: UInt64`
- `needs_max_data: Bool` — flag for MAX_DATA generation
- `needs_max_streams_bidi: Bool` — flag for MAX_STREAMS generation
- `needs_max_streams_uni: Bool`

**Methods:**
- `__init__(out self, is_server, conn_fc_recv_limit, conn_fc_recv_window, conn_fc_send_limit, local/peer stream FC params, local/peer max_streams)`
- `open_stream(mut self, bidi: Bool) raises -> UInt64` — spec §4.2 local creation
- `get_or_create_peer_stream(mut self, stream_id: UInt64) raises -> Tuple[Bool, List[UInt64]]` — returns (created, list_of_newly_created_ids). Spec §4.2 peer creation with implicit streams.
- `get_stream(self, stream_id: Int) raises -> Stream` — raises if not found
- `set_stream(mut self, stream_id: Int, stream: Stream)` — update in Dict
- `maybe_cleanup(mut self, stream_id: Int)` — spec §4.3. Checks terminal states, removes if closed.
- `check_max_streams_update(mut self)` — spec §4.4 formula
- `add_sendable(mut self, stream_id: Int)` — add to sendable_ids if not present
- `remove_sendable(mut self, stream_id: Int)` — remove from sendable_ids

**Tests (~300 LoC):**
Key tests:
- `test_open_stream_bidi_client`: allocates ID 0, 4, 8
- `test_open_stream_bidi_server`: allocates ID 1, 5, 9
- `test_open_stream_uni`: allocates correct IDs
- `test_open_stream_limit`: raises when peer_max_streams reached
- `test_peer_stream_creation`: receiving frame for ID 8 creates streams 0, 4, 8
- `test_peer_stream_limit`: STREAM_LIMIT_ERROR when exceeding local_max_streams
- `test_maybe_cleanup_bidi`: both sides terminal → removed
- `test_maybe_cleanup_uni`: one side terminal → removed
- `test_max_streams_update`: after 50 completions (initial=100), limit becomes 150
- `test_conn_fc_recv_check`: aggregate check across multiple streams
- `test_conn_fc_recv_update`: consumed triggers should_update
- `test_sendable_list`: add/remove, round-robin index management

- [ ] **Step 1: Write test file**
- [ ] **Step 2: Verify tests fail**
- [ ] **Step 3: Implement StreamMap**
- [ ] **Step 4: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_stream_map.mojo`
Expected: PASS
- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `feat: add StreamMap with stream creation, cleanup, and MAX_STREAMS`

---

## Phase 4 — Connection Wiring: Recv Path (Task 5, depends on Tasks 2 + 4)

### Task 5: Connection Init + Frame Dispatch

**Files:**
- Modify: `src/quic/connection.mojo`

**Spec:** §6.1-6.6 (new fields, initialization, frame dispatch), §8 (events)

This task wires StreamMap and CidManager into the existing QuicConnection. **No new test file** — Task 7 (integration tests) covers this.

**Changes to QuicConnection:**

**1. New imports:** Add imports for `StreamMap`, `CidManager`, `FlowControl`, and additional frame constants (`FRAME_STREAM_BASE`, `FRAME_RESET_STREAM`, `FRAME_STOP_SENDING`, `FRAME_MAX_DATA`, `FRAME_MAX_STREAM_DATA`, `FRAME_MAX_STREAMS_BIDI`, `FRAME_MAX_STREAMS_UNI`, `FRAME_DATA_BLOCKED`, `FRAME_STREAM_DATA_BLOCKED`, `FRAME_STREAMS_BLOCKED_BIDI`, `FRAME_STREAMS_BLOCKED_UNI`).

**2. New fields on QuicConnection:**
```
var stream_map: StreamMap
var cid_mgr: CidManager
```

**3. Update `__init__` private constructor:** Initialize `stream_map` with local transport param defaults from §2.7 and `cid_mgr` with initial CIDs.

**4. Update move constructor:** Add `stream_map` and `cid_mgr`.

**5. Update `client()` and `server()` factories:** Set transport params `initial_max_data=10485760`, `initial_max_stream_data_bidi_local=1048576`, `initial_max_stream_data_bidi_remote=1048576`, `initial_max_stream_data_uni=1048576`, `initial_max_streams_bidi=100`, `initial_max_streams_uni=100` in `params_copy` before serializing.

**6. Extend QuicEvent:** Add event type constants (5-9) and `stream_id: UInt64`, `final_size: UInt64` fields. Add factory methods: `stream_readable(id)`, `stream_writable(id)`, `stream_reset(id, error, final_size)`, `stream_stopped(id, error)`, `stream_opened(id)`.

**7. Extend `_dispatch_frame`:** Replace the stream-level stub (`return` at line ~634) with handlers per spec §6.3:
- STREAM (0x08-0x0F): `_handle_stream_frame`
- RESET_STREAM: `_handle_reset_stream`
- STOP_SENDING: `_handle_stop_sending`
- MAX_DATA: `stream_map.conn_fc_send.ensure_limit(value)`
- MAX_STREAM_DATA: update per-stream send FC
- MAX_STREAMS_BIDI/UNI: update peer_max_streams
- DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED: no-op (diagnostic)
- NEW_CONNECTION_ID: `cid_mgr.on_new_connection_id(frame)`
- RETIRE_CONNECTION_ID: `cid_mgr.on_retire_connection_id(seq)`

**8. Add `_handle_stream_frame`:** Per spec §6.4. Validates stream ID, creates peer stream if needed, checks direction/state, validates per-stream + connection FC, writes to RecvBuf, updates FC counters, emits STREAM_READABLE.

**9. Add `_handle_reset_stream`:** Per spec §6.5. Validates final_size invariant, FC limits, accounts phantom bytes, transitions recv state, emits STREAM_RESET, calls maybe_cleanup.

**10. Add `_handle_stop_sending`:** Per spec §6.6. Validates direction, transitions send state to RESET_SENT, queues RESET_STREAM frame (sets needs_reset_stream flag), emits STREAM_STOPPED, calls maybe_cleanup.

**11. Update `_on_handshake_complete` (or equivalent):** After handshake completes and peer transport params are available:
- Initialize `stream_map.conn_fc_send` limit from `peer_params.initial_max_data`
- Initialize per-stream FC limit params from peer params
- Set `stream_map.peer_max_streams_bidi/uni` from peer params
- Issue seq=1 CID via `cid_mgr.issue_new_cid()`

- [ ] **Step 1: Add StreamMap + CidManager fields, imports, init, move constructor**
- [ ] **Step 2: Extend QuicEvent** with stream event types + factory methods
- [ ] **Step 3: Update client()/server() factories** to set FC transport param defaults
- [ ] **Step 4: Update _on_handshake_complete** to init send FC from peer params + issue CID
- [ ] **Step 5: Implement _handle_stream_frame** per spec §6.4
- [ ] **Step 6: Implement _handle_reset_stream** per spec §6.5
- [ ] **Step 7: Implement _handle_stop_sending** per spec §6.6
- [ ] **Step 8: Wire _dispatch_frame** — replace stream stubs + CID stubs with handlers
- [ ] **Step 9: Verify existing tests still pass**
Run: `TESTS_FILTER=quic bash scripts/run_tests.sh`
Expected: PASS — all existing QUIC tests still green (no regressions)
- [ ] **Step 10: Commit**
Use the `commit-smart` skill. Message: `feat: wire StreamMap and CidManager into QuicConnection recv path`

---

## Phase 5 — Connection Wiring: Send Path + API (Task 6, depends on Task 5)

### Task 6: Connection Send Path + Public API

**Files:**
- Modify: `src/quic/connection.mojo`

**Spec:** §6.7-6.9 (send extensions, on_ack, on_loss), §7 (public API), §8 (events)

**1. Extend `_build_frames_for_space`** for Application space (space_idx == 2), after existing CRYPTO frames:
- CID frames from `cid_mgr.pending_new_cid_frames()` + `cid_mgr.pending_retire_frames()`
- MAX_DATA frame if `stream_map.conn_fc_recv.should_update()` or `stream_map.needs_max_data`
- MAX_STREAM_DATA for each stream with `needs_max_stream_data` flag
- MAX_STREAMS_BIDI/UNI if `stream_map.needs_max_streams_bidi/uni`
- RESET_STREAM for streams with `needs_reset_stream` flag
- STOP_SENDING for streams with `needs_stop_sending` flag
- STREAM frames — iterate `stream_map.sendable_ids` round-robin, call `stream.send_buf.make_frame()` respecting `min(stream FC, conn FC)` credit. After framing, update `stream.fc_send.add_received()` and `conn_fc_send.add_received()`.

**2. Extend `_handle_ack`** to handle stream frame types in SentPacket.frames:
- STREAM frames: call `stream.send_buf.on_ack()`. If `is_fully_acked()`, transition DATA_SENT → DATA_RECVD. Call `maybe_cleanup()`.
- RESET_STREAM: clear `needs_reset_stream`, transition RESET_SENT → RESET_RECVD. Call `maybe_cleanup()`.
- MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS: mark as delivered (clear pending flags).
- NEW_CONNECTION_ID, RETIRE_CONNECTION_ID: mark CID as advertised/delivered.

**3. Add on_loss handling** in loss detection:
- STREAM frames: call `stream.send_buf.on_loss()`. Ensure stream is in sendable_ids.
- RESET_STREAM: re-set `needs_reset_stream` flag.
- STOP_SENDING: re-set `needs_stop_sending` flag.
- FC frames: regenerate (values may have increased since original send).
- CID frames: re-queue.

**4. Add public API methods** per spec §7:
- `open_stream(mut self, bidi: Bool) raises -> UInt64` — delegates to `stream_map.open_stream()`, adds to sendable_ids if bidi (send side exists). Checks connection established.
- `send_stream_data(mut self, stream_id: UInt64, data: Span[UInt8, _], fin: Bool) raises` — writes to stream's SendBuf, transitions READY→SEND if needed, adds to sendable_ids.
- `recv_stream_data(mut self, stream_id: UInt64) raises -> Tuple[List[UInt8], Bool]` — reads from RecvBuf, updates consumed FC (stream + connection), sets needs_max_stream_data/needs_max_data flags, checks DATA_READ transition.
- `reset_stream(mut self, stream_id: UInt64, error_code: UInt64) raises` — transitions to RESET_SENT, sets needs_reset_stream + final_size + error, removes from sendable_ids.
- `stop_sending(mut self, stream_id: UInt64, error_code: UInt64) raises` — transitions recv to STOP_SENDING_SENT, sets needs_stop_sending + error.

**5. Track frame types in SentPacket.frames:** The existing `SentPacket.frames` field (from M3b) stores frame data for retransmission. Extend it to include stream frame metadata: stream_id, offset, length for STREAM frames; stream_id for RESET_STREAM/STOP_SENDING; and type tags for FC/CID frames.

- [ ] **Step 1: Add public API methods** (open_stream, send_stream_data, recv_stream_data, reset_stream, stop_sending)
- [ ] **Step 2: Extend _build_frames_for_space** for Application space
- [ ] **Step 3: Extend _handle_ack** for stream/CID frame types
- [ ] **Step 4: Add on_loss handling** for stream/CID frame types
- [ ] **Step 5: Verify existing tests still pass**
Run: `TESTS_FILTER=quic bash scripts/run_tests.sh`
Expected: PASS
- [ ] **Step 6: Commit**
Use the `commit-smart` skill. Message: `feat: add stream send path, public API, and frame ACK/loss handling`

---

## Phase 6 — Integration Tests + Runner (Task 7, depends on Task 6)

### Task 7: Integration Tests + Test Runner

**Files:**
- Modify: `tests/test_quic_connection.mojo`
- Modify: `scripts/run_tests.sh`

**Spec:** §11.2 (integration tests), §11.3 (test runner)

Add integration tests to the existing `test_quic_connection.mojo` file. These use the loopback handshake pattern established in M3b tests (client↔server, feed datagrams between them).

**Test functions to add:**

**`test_stream_data_transfer`:**
1. Complete handshake (reuse existing helper)
2. Client: `open_stream(bidi=True)` → stream_id=0
3. Client: `send_stream_data(0, "hello".as_bytes(), fin=True)`
4. Client: `send(now)` → datagrams
5. Server: `recv(datagram, now)` → poll → STREAM_OPENED(0) + STREAM_READABLE(0)
6. Server: `recv_stream_data(0)` → ("hello", True)
7. Server: `send_stream_data(0, "world".as_bytes(), fin=True)`
8. Server: `send(now)` → datagrams
9. Client: `recv(datagram, now)` → poll → STREAM_READABLE(0)
10. Client: `recv_stream_data(0)` → ("world", True)

**`test_multi_stream`:**
1. Complete handshake
2. Client opens 3 bidi streams (IDs 0, 4, 8), sends distinct data on each
3. Server receives all 3, reads each, verifies correct data and no cross-contamination
4. Server responds on each stream

**`test_unidirectional_stream`:**
1. Complete handshake
2. Client: `open_stream(bidi=False)` → stream_id=2 (client uni)
3. Client sends data + FIN
4. Server receives, reads data
5. Server: `open_stream(bidi=False)` → stream_id=3 (server uni)
6. Server sends data back
7. Client receives and reads

**`test_flow_control_basic`:**
1. Complete handshake with small FC windows (e.g., initial_max_stream_data_bidi_remote=100)
2. Client opens stream, tries to send 200 bytes
3. First send: only 100 bytes fit (stream FC limit)
4. Server reads 100 bytes → MAX_STREAM_DATA issued
5. Client receives MAX_STREAM_DATA → can send remaining 100 bytes

**`test_reset_stream`:**
1. Complete handshake
2. Client opens stream, sends partial data (50 bytes)
3. Client: `reset_stream(stream_id, error_code=42)` 
4. Server receives → poll → STREAM_RESET(stream_id, 42, final_size)
5. Verify server's connection FC accounts for final_size

**`test_stop_sending`:**
1. Complete handshake
2. Client opens bidi stream, sends data
3. Server: `stop_sending(stream_id, error_code=99)`
4. Client receives STOP_SENDING → poll → STREAM_STOPPED(stream_id, 99)
5. Client automatically sends RESET_STREAM
6. Server receives RESET_STREAM → stream fully closed

**`test_cid_issuance`:**
1. Complete handshake
2. Both sides call `send(now)` → verify NEW_CONNECTION_ID frames in datagrams
3. Feed to peer → CidManager stores new CID

**`test_cid_retirement`:**
1. Complete handshake + exchange seq=1 CIDs
2. One side crafts NEW_CONNECTION_ID with retire_prior_to=1
3. Peer processes → queues RETIRE_CONNECTION_ID for seq=0
4. Peer sends → verify RETIRE_CONNECTION_ID frame
5. Original side processes retirement → issues replacement CID

**`test_cid_retirement_flood`:**
1. Complete handshake
2. Rapidly inject many NEW_CONNECTION_ID frames with escalating retire_prior_to
3. Verify retirement queue cap triggers → connection closes with PROTOCOL_VIOLATION

**Test runner update:** Add 4 entries to `scripts/run_tests.sh`:
```
test_quic_flow_control
test_quic_stream
test_quic_stream_map
test_quic_cid
```

- [ ] **Step 1: Add integration tests** to `tests/test_quic_connection.mojo`
- [ ] **Step 2: Update test runner** — add 4 new entries to `scripts/run_tests.sh`
- [ ] **Step 3: Run all integration tests**
Run: `TESTS_FILTER=quic bash scripts/run_tests.sh`
Expected: PASS — all QUIC tests pass (unit + integration)
- [ ] **Step 4: Run full test suite**
Run: `bash scripts/run_tests.sh`
Expected: PASS — all tests pass (no regressions)
- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `test: add stream data path and CID integration tests`

---

## Parallelism Summary

```
Phase 1:  Task 1 (FlowControl)  ||  Task 2 (CidManager)
Phase 2:  Task 3 (Stream) — depends on Task 1
Phase 3:  Task 4 (StreamMap) — depends on Task 3
Phase 4:  Task 5 (Connection recv) — depends on Tasks 2 + 4
Phase 5:  Task 6 (Connection send + API) — depends on Task 5
Phase 6:  Task 7 (Integration tests) — depends on Task 6
```

Tasks 1 and 2 run in parallel (no file overlap). All subsequent tasks are sequential.
