# M3c — QUIC Data Path + CID Management

**Status:** pending
**Depends on:** M3b (connection core — done), M3a (codec & parsing — done)
**Unlocks:** M4 (congestion control + auto-tuning), M5 (HTTP/3 + QPACK)

## Goal

Extend `QuicConnection` so client and server can exchange application data over bidirectional and unidirectional QUIC streams after handshake completion. Includes dual-level flow control, full RESET_STREAM/STOP_SENDING lifecycle, stream state management, and full CID management (issuance, retirement with stuffing defense).

## Architecture

```
QuicConnection (existing — extended with StreamMap + CidManager + public stream API)
  ├── StreamMap (NEW — stream collection, scheduling, conn-level FC)
  │     ├── Stream ×N (NEW — per-stream state machines + buffers + FC)
  │     │     ├── SendState enum (6 states)
  │     │     ├── RecvState enum (7 states, incl. STOP_SENDING_SENT)
  │     │     ├── SendBuf (offset-indexed outgoing data)
  │     │     ├── RecvBuf (reassembly with RangeSet + gap limiting)
  │     │     └── FlowControl ×2 (send + recv per-stream)
  │     └── FlowControl ×2 (send + recv connection-level)
  ├── CidManager (NEW — local/remote CID tracking, issuance, retirement)
  ├── PacketNumberSpace ×3 (existing)
  ├── Recovery (existing)
  ├── CryptoStream ×3 (existing)
  └── PacketProtect (existing)
```

## File structure

| File | Responsibility | Est. LoC |
|------|---------------|----------|
| `src/quic/flow_control.mojo` | `FlowControl` struct — reusable at connection and stream level | ~150 |
| `src/quic/stream.mojo` | `SendState`/`RecvState` enums, `RecvBuf` (RangeSet), `SendBuf`, `Stream` struct | ~800 |
| `src/quic/stream_map.mojo` | `StreamMap` — collection, MAX_STREAMS, stream creation/cleanup, scheduling | ~500 |
| `src/quic/cid.mojo` | `CidManager` — CID table, issuance, retirement, retire_prior_to, reset tokens | ~400 |
| `src/quic/connection.mojo` (modify) | Wire StreamMap + CidManager, public API, frame dispatch, frame generation | ~+450 |

**Total estimate:** ~2300 production LoC + ~1800 test LoC = ~4100 total (M3b actual was 25% over estimate — this accounts for Mojo boilerplate and copy constructors)

---

## §1 Stream State Machines

### 1.1 Send-side states (6)

```
SendState:
    READY           # stream created, no STREAM frame sent yet
    SEND            # sending data (STREAM frames in flight)
    DATA_SENT       # FIN sent, awaiting ACK for all STREAM frames
    DATA_RECVD      # all STREAM frames ACKed (terminal)
    RESET_SENT      # RESET_STREAM sent, awaiting ACK
    RESET_RECVD     # RESET_STREAM ACKed (terminal)
```

**Transitions:**
- READY → SEND: first STREAM or STREAM_DATA_BLOCKED frame sent
- SEND → DATA_SENT: STREAM frame with FIN bit sent
- DATA_SENT → DATA_RECVD: all STREAM frames ACKed by peer
- {READY, SEND, DATA_SENT} → RESET_SENT: application calls `reset_stream()` or STOP_SENDING received from peer
- RESET_SENT → RESET_RECVD: RESET_STREAM frame ACKed

**Key rule:** From DATA_SENT, if STOP_SENDING arrives and all data is already ACKed (DATA_RECVD), RESET_STREAM is unnecessary. Otherwise, sender SHOULD still send RESET_STREAM.

### 1.2 Recv-side states (7)

```
RecvState:
    RECV                # receiving data, FIN not yet seen
    SIZE_KNOWN          # FIN received, but gaps may exist
    DATA_RECVD          # all bytes up to final_size received
    DATA_READ           # application consumed all data (terminal)
    STOP_SENDING_SENT   # STOP_SENDING queued/sent, waiting for peer's RESET_STREAM
    RESET_RECVD         # peer sent RESET_STREAM
    RESET_READ          # application acknowledged the reset (terminal)
```

**Transitions:**
- RECV → SIZE_KNOWN: STREAM frame with FIN received
- SIZE_KNOWN → DATA_RECVD: all bytes up to final_size received (no gaps)
- DATA_RECVD → DATA_READ: application reads all data
- {RECV, SIZE_KNOWN} → STOP_SENDING_SENT: application calls `stop_sending()`
- STOP_SENDING_SENT → RESET_RECVD: peer's RESET_STREAM arrives
- {RECV, SIZE_KNOWN, STOP_SENDING_SENT} → RESET_RECVD: RESET_STREAM received
- DATA_RECVD → DATA_READ: suppress RESET_STREAM when all data is already received (deliver data to app — this is the useful behavior per quinn/ngtcp2)
- RESET_RECVD → RESET_READ: application acknowledges reset

**STOP_SENDING retransmission:** STOP_SENDING is retransmitted while in STOP_SENDING_SENT, until RESET_STREAM arrives from peer (not until FIN — FIN does not mean the sender will stop retransmitting). The original neqo design split this into STOP_SENDING_SENT + WAIT_FOR_RESET, but both states retransmit identically in a sans-I/O model, so M3c collapses them into one.

**DATA_RECVD + RESET_STREAM:** When RESET_STREAM arrives but all data is already received (DATA_RECVD state), suppress the reset and deliver data to the application. This is the default behavior (not optional) — the project's "SHOULD/MAY=MUST" rule applies to security measures, not data delivery.

### 1.3 Bidirectional vs. unidirectional

- **Bidirectional:** each side runs both send and recv state machines independently
- **Locally-initiated unidirectional:** send-side only (recv state = N/A)
- **Remotely-initiated unidirectional:** recv-side only (send state = N/A)

Sending frames for the wrong direction (e.g., STOP_SENDING on a receive-only uni stream) is STREAM_STATE_ERROR.

### 1.4 Stream ID encoding (RFC 9000 §2.1)

```
Client-initiated bidi:  0, 4, 8, 12, ...  (id % 4 == 0)
Server-initiated bidi:  1, 5, 9, 13, ...  (id % 4 == 1)
Client-initiated uni:   2, 6, 10, 14, ... (id % 4 == 2)
Server-initiated uni:   3, 7, 11, 15, ... (id % 4 == 3)
```

Helper functions:
- `stream_is_bidi(id: UInt64) -> Bool`: `(id & 0x02) == 0`
- `stream_is_local(id: UInt64, is_server: Bool) -> Bool`: `((id & 0x01) != 0) == is_server`
- `stream_is_client_initiated(id: UInt64) -> Bool`: `(id & 0x01) == 0`

### 1.5 Stream struct

```
struct Stream(Copyable, Movable):
    var id: UInt64
    var is_bidi: Bool
    var is_local: Bool

    # State machines (Optional because uni streams only have one side)
    var send_state: Optional[UInt8]     # SendState value (None for remote-initiated uni)
    var recv_state: Optional[UInt8]     # RecvState value (None for local-initiated uni)

    # Buffers
    var send_buf: Optional[SendBuf]     # None for remote-initiated uni
    var recv_buf: Optional[RecvBuf]     # None for local-initiated uni

    # Flow control
    var fc_send: Optional[FlowControl]  # None for remote-initiated uni
    var fc_recv: Optional[FlowControl]  # None for local-initiated uni

    # Recv-side tracking (owned by Stream, not RecvBuf — RESET_STREAM bypasses buffer)
    var fin_offset: Optional[UInt64]    # final size if known (via FIN or RESET_STREAM)
    var recv_highest_offset: UInt64     # highest byte offset seen across all STREAM frames

    # Send-side tracking
    var send_fin_offset: Optional[UInt64]  # committed final size when FIN sent
    var reset_error: Optional[UInt64]      # peer's RESET_STREAM error code
    var stop_error: Optional[UInt64]       # peer's STOP_SENDING error code

    # Pending frame flags (for frame generation in send())
    var needs_max_stream_data: Bool     # need to send MAX_STREAM_DATA
    var needs_reset_stream: Bool        # need to send/retransmit RESET_STREAM
    var needs_stop_sending: Bool        # need to send/retransmit STOP_SENDING
    var reset_stream_final_size: UInt64 # final_size for outgoing RESET_STREAM
    var reset_stream_error: UInt64      # error code for outgoing RESET_STREAM
    var stop_sending_error: UInt64      # error code for outgoing STOP_SENDING

    # Priority (for M5/HTTP/3 — defaults only in M3c)
    var urgency: UInt8                  # default 127 (lowest)
    var incremental: Bool               # default False
```

**Copyable requirement:** Mojo 0.26.2 requires `Copyable` for Dict value types. Stream, SendBuf, and RecvBuf must all implement copy constructors (deep-copy lists). This matches the pattern used for `CryptoStream`, `PacketNumberSpace`, etc. in M3b.

### 1.6 final_size invariant (RFC 9000 §4.5)

Once a final size is known (via FIN bit or RESET_STREAM), it cannot change. Violations:
- RESET_STREAM final_size ≠ previously declared FIN offset → FINAL_SIZE_ERROR
- Duplicate RESET_STREAM with different final_size → FINAL_SIZE_ERROR
- Data arriving at or beyond final_size → FINAL_SIZE_ERROR

`fin_offset` lives on `Stream` (not on RecvBuf) because RESET_STREAM bypasses the reassembly buffer entirely. Both RecvBuf.write() and the RESET_STREAM handler validate against `stream.fin_offset`.

`recv_highest_offset` is updated on every RecvBuf.write() as `max(recv_highest_offset, offset + len(data))`. Used for:
- RESET_STREAM validation: `final_size >= recv_highest_offset` (else FINAL_SIZE_ERROR)
- Phantom byte accounting: `final_size - recv_highest_offset` = new bytes to account at connection level

---

## §2 Flow Control

### 2.1 FlowControl struct

FlowControl tracks two distinct counters (review finding B1):
- **`received`**: total bytes received/sent on the wire. Used for **enforcement** (checking incoming data against limits).
- **`consumed`**: total bytes consumed by the application (read by app, or accounted via RESET_STREAM final_size). Used for **window updates** (`should_update()` checks remaining credit relative to consumed bytes).

The distinction matters at the connection level: data can sit in a stream's RecvBuf (received but not yet consumed by the app). Enforcement must check against `received`, while window updates must fire based on `consumed`.

At the per-stream level, `received` and `consumed` diverge when data is buffered but not yet read. At the connection level, the split is critical for preventing deadlocks.

```
struct FlowControl(Copyable, Movable):
    var received: UInt64       # bytes received/sent on wire (for enforcement)
    var consumed: UInt64       # bytes consumed by app or accounted via RESET (for window updates)
    var limit: UInt64          # current limit advertised to/by peer
    var window: UInt64         # window size (static for M3c)
    var blocked_at: UInt64     # limit at which we last sent BLOCKED (0 = not blocked)

    def should_update(self) -> Bool:
        """True when remaining credit based on consumed < window // 2."""
        var remaining = self.limit - self.consumed
        return remaining < (self.window // 2)

    def next_limit(self) -> UInt64:
        """Calculate the next limit to advertise (based on consumed, not received)."""
        return self.consumed + self.window

    def update_limit(mut self) -> UInt64:
        """Issue a new limit. Returns the new limit value for frame generation."""
        self.limit = self.next_limit()
        return self.limit

    def add_received(mut self, bytes: UInt64):
        """Account for bytes received on wire (non-duplicate only)."""
        self.received += bytes

    def add_consumed(mut self, bytes: UInt64):
        """Account for bytes consumed by application."""
        self.consumed += bytes

    def check_limit(self, new_bytes: UInt64) -> Bool:
        """Check if receiving new_bytes would exceed the limit."""
        return self.received + new_bytes <= self.limit

    def available(self) -> UInt64:
        """Remaining send credit (for sender-side FC)."""
        if self.limit > self.received:
            return self.limit - self.received
        return UInt64(0)

    def ensure_limit(mut self, new_limit: UInt64):
        """Update limit from peer's MAX frame (monotonic — ignore decreases)."""
        if new_limit > self.limit:
            self.limit = new_limit
```

**Send-side usage:** `received` tracks total bytes sent, `consumed` is unused (send-side FC only uses `available()` and `ensure_limit()`). The `should_update()` / `add_consumed()` methods are only meaningful on the recv side.

**Recv-side usage:** `received` tracks total new bytes received on wire (for enforcement via `check_limit()`). `consumed` tracks bytes the app has read (for window updates via `should_update()`). When RESET_STREAM arrives, phantom bytes add to both `received` and `consumed` simultaneously (they were "received" and "consumed" atomically).

### 2.2 Connection-level flow control

Two `FlowControl` instances on `StreamMap`:

- **`conn_fc_recv`** (receiver side): tracks total bytes received across all streams. Initial limit = `initial_max_data` from local transport params (10 MiB default). Generates MAX_DATA frames.
- **`conn_fc_send`** (sender side): tracks total bytes sent. Initial limit = peer's `initial_max_data`. Updated by incoming MAX_DATA frames.

### 2.3 Per-stream flow control

Two `FlowControl` instances on each `Stream`:

- **`fc_recv`**: Initial limit = local `initial_max_stream_data_*` (1 MiB). Generates MAX_STREAM_DATA frames.
- **`fc_send`**: Initial limit = peer's `initial_max_stream_data_*`. Updated by incoming MAX_STREAM_DATA.

The correct initial_max_stream_data depends on stream type and initiator:
- Locally-initiated bidi: peer's `initial_max_stream_data_bidi_remote` (the peer is the receiver of our local stream)
- Remotely-initiated bidi: peer's `initial_max_stream_data_bidi_local` (the peer is the receiver of their own local stream)
- Locally-initiated uni: peer's `initial_max_stream_data_uni`
- Remotely-initiated uni: N/A (we don't send on remotely-initiated uni)

For recv-side initial limits, mirror the above with local params.

### 2.4 Send-side enforcement

Before sending any STREAM frame:
```
can_send = min(stream.fc_send.available(), stream_map.conn_fc_send.available())
```
Never send more than `can_send` bytes. After sending, update: `stream.fc_send.add_received(sent_bytes)` and `conn_fc_send.add_received(sent_bytes)`. (On the send side, `received` tracks total bytes sent — symmetric naming with the recv side.)

### 2.5 Recv-side enforcement

On receiving a STREAM frame:
- Check per-stream: `offset + len(data) <= stream.fc_recv.limit` — if not, FLOW_CONTROL_ERROR
- Calculate `new_bytes` = number of bytes not previously received (non-duplicate, based on `recv_highest_offset` and RecvBuf ranges)
- Check connection: `conn_fc_recv.check_limit(new_bytes)` (i.e., `conn_fc_recv.received + new_bytes <= conn_fc_recv.limit`) — if not, FLOW_CONTROL_ERROR
- Update: `stream.fc_recv.add_received(new_bytes)` and `conn_fc_recv.add_received(new_bytes)`

### 2.6 RESET_STREAM accounting (critical for deadlock prevention)

When RESET_STREAM arrives with `final_size`:
1. Validate: `final_size >= stream.recv_highest_offset` (else FINAL_SIZE_ERROR)
2. Validate: `final_size <= stream.fc_recv.limit` (else FLOW_CONTROL_ERROR)
3. Account "phantom bytes": `conn_fc_recv.add_consumed(final_size - stream.recv_highest_offset)`
4. The phantom bytes were never buffered, so recv credit is immediately reclaimable — `conn_fc_recv` will generate MAX_DATA on next `should_update()` check

### 2.7 Default window sizes

| Parameter | Default value | Transport param |
|-----------|--------------|-----------------|
| `initial_max_data` | 10 MiB (10,485,760) | 0x04 |
| `initial_max_stream_data_bidi_local` | 1 MiB (1,048,576) | 0x05 |
| `initial_max_stream_data_bidi_remote` | 1 MiB (1,048,576) | 0x06 |
| `initial_max_stream_data_uni` | 1 MiB (1,048,576) | 0x07 |
| `initial_max_streams_bidi` | 100 | 0x08 |
| `initial_max_streams_uni` | 100 | 0x09 |

These are set in the local `TransportParams` passed to `QuicConnection.client()` / `.server()`. M3b already serializes and exchanges transport params — M3c must populate these fields with the defaults above.

### 2.8 DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED

**Sending:** When the send side is blocked by flow control and no ack-eliciting packets are in flight, send the appropriate BLOCKED frame (at most once per blocking event — tracked by `blocked_at` field).

**Receiving:** Log and ignore. Do NOT auto-issue credit in response.

---

## §3 RecvBuf & SendBuf

### 3.1 RecvBuf (stream reassembly)

```
struct RecvBuf(Movable):
    var ranges: List[Tuple[UInt64, UInt64]]  # sorted non-overlapping (start, end) received ranges
    var chunks: List[Tuple[UInt64, List[UInt8]]]  # (offset, data) — ordered by offset
    var read_offset: UInt64    # next byte to deliver to application
    var fin_offset: Optional[UInt64]  # final size if known
    var max_gaps: UInt64       # gap count limit: max(64, recv_window // 512)
```

**Operations:**
- `write(offset, data, fin, stream_fin_offset) raises`: Insert data, merge ranges, validate. The `stream_fin_offset` parameter is the Stream's `fin_offset` (owned by Stream, not RecvBuf). Validation steps:
  1. If `fin` is set: compute `this_fin = offset + len(data)`. If `stream_fin_offset` is set and differs from `this_fin` → FINAL_SIZE_ERROR. Otherwise set `stream_fin_offset = this_fin`.
  2. If `stream_fin_offset` is set and `offset + len(data) > stream_fin_offset` → FINAL_SIZE_ERROR (data beyond final size).
  3. If `len(ranges) >= max_gaps` and this write creates a new gap → PROTOCOL_VIOLATION (resource exhaustion attack).
  4. Insert data into chunks, merge overlapping ranges (accept-first-copy, no content comparison).
  5. Return the count of new (non-duplicate) bytes inserted (for FC accounting).
- `read() -> Tuple[List[UInt8], Bool]`: Drain contiguous bytes from read_offset, return (data, fin_reached). `fin_reached` is true when `read_offset == stream_fin_offset` and no gaps remain.
- `is_complete(stream_fin_offset) -> Bool`: all bytes up to stream_fin_offset received (no gaps)
- `has_readable() -> Bool`: contiguous bytes available starting at read_offset

**Range merging:** After inserting (offset, offset+len), scan ranges list for overlaps and merge. Accept-first-copy for overlapping data (no content comparison).

**Gap limit enforcement:** If `len(ranges) > max_gaps` and a new write would create an additional gap, raise PROTOCOL_VIOLATION. This is a resource exhaustion attack — the peer is deliberately creating excessive gaps to consume memory.

### 3.2 SendBuf

```
struct SendBuf(Copyable, Movable):
    var data: List[UInt8]        # queued outgoing data (trimmed from front as ACKed)
    var offset: UInt64           # byte offset of data[0] in the stream
    var unsent_offset: UInt64    # first unsent byte (absolute stream offset)
    var acked_offset: UInt64     # contiguous bytes ACKed from start of stream
    var fin: Bool                # FIN queued
    var fin_offset: Optional[UInt64]  # committed final size (set when FIN is framed)
    var fin_acked: Bool          # whether the FIN has been ACKed
```

**Operations:**
- `write(data, fin)`: Append to buffer, set fin flag
- `pending_len() -> UInt64`: bytes not yet framed
- `has_pending() -> Bool`: unsent data or unsent FIN
- `make_frame(stream_id, max_bytes) -> Optional[StreamFrame]`: Create a STREAM frame consuming up to max_bytes from unsent data. Skips already-ACKed ranges (compares against `acked_offset`). Sets `fin_offset` when FIN is first framed.
- `on_ack(ack_offset, ack_len)`: Mark byte range as ACKed. If this extends the contiguous `acked_offset`, trim the leading bytes from `data` and advance `offset` (frees memory for long-running streams). If FIN offset is ACKed, set `fin_acked = True`.
- `on_loss(lost_offset, lost_len)`: Mark bytes for retransmission. Sets `unsent_offset = min(unsent_offset, lost_offset)`. Does NOT retransmit bytes where `lost_offset < acked_offset` (already ACKed via a different packet).
- `is_fully_acked() -> Bool`: `acked_offset == fin_offset and fin_acked` (all data + FIN confirmed)

**Buffer trimming (I7 fix):** `on_ack()` trims contiguous leading bytes. If bytes [0,100) and [100,200) are ACKed, `acked_offset` advances to 200, `offset` advances to 200, and the first 200 bytes are removed from `data`. This keeps memory bounded to `in_flight` bytes, not `total_sent`.

**Retransmission:** On loss, `unsent_offset` is set to `min(unsent_offset, lost_offset)` but `make_frame()` skips past `acked_offset`, so already-ACKed bytes in a lost packet are not re-sent.

---

## §4 StreamMap

### 4.1 StreamMap struct

```
struct StreamMap(Movable):
    var streams: Dict[Int, Stream]  # stream_id -> Stream (Int because Dict needs KeyElement)
    var is_server: Bool

    # Connection-level flow control
    var conn_fc_recv: FlowControl
    var conn_fc_send: FlowControl

    # Stream concurrency limits (cumulative counts, not concurrent)
    var local_max_streams_bidi: UInt64   # limit we advertise to peer
    var local_max_streams_uni: UInt64
    var peer_max_streams_bidi: UInt64    # limit peer advertises to us
    var peer_max_streams_uni: UInt64
    var local_opened_bidi: UInt64        # count of locally-initiated bidi streams
    var local_opened_uni: UInt64
    var peer_opened_bidi: UInt64         # count of peer-initiated streams
    var peer_opened_uni: UInt64
    var peer_completed_bidi: UInt64      # count of fully-closed peer streams
    var peer_completed_uni: UInt64

    # Stream creation defaults (from local transport params)
    var local_stream_fc_window_bidi_local: UInt64
    var local_stream_fc_window_bidi_remote: UInt64
    var local_stream_fc_window_uni: UInt64
    # Peer's initial stream FC limits (from peer transport params)
    var peer_stream_fc_limit_bidi_local: UInt64
    var peer_stream_fc_limit_bidi_remote: UInt64
    var peer_stream_fc_limit_uni: UInt64
```

### 4.2 Stream creation

**Local stream creation** (`open_stream`):
1. Check `local_opened_bidi < peer_max_streams_bidi` (or uni equivalent)
2. Allocate stream ID: `local_opened_bidi * 4 + (1 if is_server else 0)` for bidi
3. Create Stream with appropriate FC limits
4. Increment `local_opened_bidi`
5. Return stream ID

**Peer stream creation** (on receiving frame for unknown stream ID):
1. Validate stream ID type matches expectations (peer-initiated)
2. Compute `stream_ordinal = stream_id / 4` (0-based index within the stream type)
3. Validate `stream_ordinal + 1 <= local_max_streams_bidi` → else STREAM_LIMIT_ERROR
4. Implicitly create all streams with lower IDs of the same type that don't exist yet (RFC 9000 §3.2). Emit STREAM_OPENED event for each.
5. Create the target Stream with appropriate FC limits
6. Set `peer_opened_bidi = max(peer_opened_bidi, stream_ordinal + 1)` (not increment by 1 — accounts for implicit streams)

### 4.3 Stream cleanup

Called after every state transition (`maybe_cleanup`):
- If stream is bidi: both send and recv sides must be in terminal states
- If stream is locally-initiated uni: send side must be terminal
- If stream is remotely-initiated uni: recv side must be terminal

When fully closed:
1. Remove from `streams` Dict
2. Increment `peer_completed_*` if peer-initiated
3. Check if MAX_STREAMS should be sent

### 4.4 MAX_STREAMS update strategy

Track `initial_max_streams_bidi` (the initial concurrent target, e.g., 100). The invariant is: the peer should always be able to have ~`initial_max_streams` concurrent streams open.

```
new_limit = peer_completed_bidi + initial_max_streams_bidi
```

When `new_limit > local_max_streams_bidi`: send MAX_STREAMS_BIDI with `new_limit`, update `local_max_streams_bidi = new_limit`.

This is linear growth (not exponential): if initial=100 and 50 streams complete, new limit = 150. Next time 50 more complete (100 total), new limit = 200. The peer always has ~100 concurrent stream slots available.

Same pattern for uni.

### 4.5 Scheduling (send path)

Simple round-robin across all streams with pending send data. No priority scheduling in M3c — all streams at default urgency. The `Stream` struct includes `urgency: UInt8` and `incremental: Bool` fields for M5 (HTTP/3) to set later.

Maintain a `sendable_ids: List[Int]` — an ordered list of stream IDs with pending send data, with a rotating `send_index: Int` for round-robin fairness. Dict iteration order is non-deterministic, so a separate ordered list is needed. Updated when streams become sendable or are cleaned up. M5 will replace this with a priority-aware scheduling structure.

---

## §5 CID Management

### 5.1 CidEntry struct

```
struct CidEntry(Copyable, Movable):
    var cid: List[UInt8]         # connection ID bytes
    var sequence: UInt64         # sequence number
    var reset_token: List[UInt8] # 16-byte stateless reset token
    var state: UInt8             # 0=Active, 1=PendingRetire, 2=Retired
```

### 5.2 CidManager struct

```
struct CidManager(Movable):
    # Local CIDs (we issued these; peer uses them as DCID)
    var local_cids: List[CidEntry]
    var local_next_seq: UInt64         # next sequence number to issue
    var local_retire_prior_to: UInt64  # our retire_prior_to for outgoing NEW_CID

    # Remote CIDs (peer issued these; we use them as DCID)
    var remote_cids: List[CidEntry]
    var remote_active_cid_seq: UInt64  # sequence of the CID we're currently using

    # Limits
    var local_active_limit: UInt64   # our active_connection_id_limit (advertised to peer)
    var peer_active_limit: UInt64    # peer's active_connection_id_limit

    # Retirement queue
    var retire_queue: List[UInt64]     # sequence numbers to send RETIRE_CONNECTION_ID for
    var retire_queue_cap: Int          # max: peer_active_limit * 8
    var highest_retire_prior_to: UInt64  # highest retire_prior_to received from peer

    # Reset token generation
    var server_secret: List[UInt8]     # 32-byte random key for HMAC-SHA256
```

**M3c simplification:** `server_secret` is generated per-connection (random 32 bytes). This means tokens from connection A cannot be verified by connection B, which breaks stateless reset's purpose. For M3c (loopback testing), this is acceptable — stateless reset detection is out of scope. M4/production must accept `server_secret` as a parameter to `QuicConnection.server()` (injected from process-level config).

### 5.3 CID generation

8-byte random CIDs via Python `os.urandom(8)` (matches existing pattern in `QuicConnection.client()` / `.server()`).

### 5.4 Stateless reset token generation

`HMAC-SHA256(server_secret, cid)[:16]` via Python's `hmac` module:
```python
import hmac, hashlib
token = hmac.new(server_secret, cid_bytes, hashlib.sha256).digest()[:16]
```

This is deterministic: same key + same CID = same token. For M3c (loopback testing), Python is acceptable. A Rust FFI function (`rlsm_hmac_sha256`) can be added in M4 for production performance.

### 5.5 Initial CID issuance

During handshake (already done in M3b):
- Client generates random 8-byte DCID + random 8-byte SCID
- Server receives client's DCID, generates its own SCID
- Both sides derive Initial keys from client's random DCID

After handshake completion:
- Both sides issue one additional CID (seq=1) via NEW_CONNECTION_ID frame to satisfy `active_connection_id_limit=2`
- The NEW_CONNECTION_ID frame includes the 16-byte reset token

### 5.6 Incoming NEW_CONNECTION_ID handling

On receiving NEW_CONNECTION_ID:
1. Parse: sequence, retire_prior_to, CID, reset_token
2. If `retire_prior_to > highest_retire_prior_to`: update, queue retirements for all remote CIDs with seq < retire_prior_to
3. If retirement queue exceeds cap (`peer_active_limit * 8`): CONNECTION_CLOSE with PROTOCOL_VIOLATION
4. If seq < highest_retire_prior_to: immediately mark as PendingRetire (late-arriving CID)
5. Otherwise: store as Active remote CID
6. Validate: number of active remote CIDs does not exceed `local_active_limit` (considering pending retirements)

### 5.7 Incoming RETIRE_CONNECTION_ID handling

On receiving RETIRE_CONNECTION_ID:
1. Parse: sequence number
2. Find local CID with that sequence
3. Mark as Retired, remove from active tracking
4. If the number of active local CIDs drops below `peer_active_limit`: issue a new CID (NEW_CONNECTION_ID frame)

### 5.8 Retirement queue cap (CVE-2024-22189 defense)

Cap = `peer_active_limit * 8` (TQUIC's `dcid_limit * 4` is the minimum; we use 8× for extra margin). If the cap is exceeded, close the connection with PROTOCOL_VIOLATION — the peer is either buggy or malicious.

### 5.9 Frame generation

CidManager produces frames:
- `pending_new_cid_frames() -> List[Frame]`: NEW_CONNECTION_ID frames for CIDs that need to be advertised
- `pending_retire_frames() -> List[Frame]`: RETIRE_CONNECTION_ID frames from the retirement queue

### 5.10 active_connection_id_limit

- Advertise `active_connection_id_limit=2` (RFC minimum) in local transport params
- Respect peer's limit: never have more than `peer_active_limit` active local CIDs

---

## §6 QuicConnection Extensions

### 6.1 New fields

```
# Add to QuicConnection:
var stream_map: StreamMap        # stream collection + FC
var cid_mgr: CidManager          # CID management
```

### 6.2 Initialization

In `QuicConnection.client()` and `.server()`:
- Create `StreamMap` with local transport param defaults for FC windows + stream limits
- Create `CidManager` with the initial CIDs from the handshake + random server_secret
- Set `initial_max_data`, `initial_max_stream_data_*`, `initial_max_streams_*` in local transport params to the default values from §2.7

After handshake completion (peer transport params available):
- Initialize `conn_fc_send.limit = peer.initial_max_data`
- Initialize per-stream send FC limits from peer params
- Initialize `peer_max_streams_bidi = peer.initial_max_streams_bidi` (and uni)
- Issue seq=1 CID via CidManager

### 6.3 _dispatch_frame extensions

Replace the stream-level frame stub (`return` at the end of `_dispatch_frame`) with actual handlers:

| Frame type | Handler |
|-----------|---------|
| STREAM (0x08-0x0F) | `_handle_stream_frame(stream_frame, space_idx)` |
| RESET_STREAM | `_handle_reset_stream(reset_frame)` |
| STOP_SENDING | `_handle_stop_sending(stop_frame)` |
| MAX_DATA | `stream_map.conn_fc_send.ensure_limit(value)` |
| MAX_STREAM_DATA | `stream_map.streams[id].fc_send.ensure_limit(value)` |
| MAX_STREAMS_BIDI | `stream_map.peer_max_streams_bidi = max(current, value)` |
| MAX_STREAMS_UNI | `stream_map.peer_max_streams_uni = max(current, value)` |
| DATA_BLOCKED | no-op (diagnostic) |
| STREAM_DATA_BLOCKED | no-op (diagnostic) |
| STREAMS_BLOCKED_BIDI/UNI | no-op (diagnostic) |
| NEW_CONNECTION_ID | `cid_mgr.on_new_connection_id(frame)` |
| RETIRE_CONNECTION_ID | `cid_mgr.on_retire_connection_id(seq)` |

### 6.4 _handle_stream_frame

1. Extract stream_id, offset, data, fin from StreamFrame
2. Validate stream ID: if peer-initiated and not yet created → create via `stream_map`
3. Validate direction: if locally-initiated uni and frame is incoming data → STREAM_STATE_ERROR
4. Validate recv state: must be in {RECV, SIZE_KNOWN} (not already reset/read)
5. Validate per-stream flow control: `offset + len(data) <= stream.fc_recv.limit`
6. Write data to `stream.recv_buf.write(offset, data, fin, stream.fin_offset)` → returns `new_bytes` count
7. Update `stream.recv_highest_offset = max(stream.recv_highest_offset, offset + len(data))`
8. Validate connection flow control: `conn_fc_recv.check_limit(new_bytes)` — if not, FLOW_CONTROL_ERROR
9. Update FC tracking: `stream.fc_recv.add_received(new_bytes)`, `conn_fc_recv.add_received(new_bytes)`
10. If stream now has readable data → emit STREAM_READABLE event
11. If fin → transition recv state to SIZE_KNOWN (or DATA_RECVD if `recv_buf.is_complete()`)

### 6.5 _handle_reset_stream

1. Extract stream_id, error_code, final_size
2. Validate stream exists or create it (peer-initiated)
3. Validate final_size invariant (§1.5)
4. Validate final_size vs. flow control limits
5. Account phantom bytes at connection level (§2.6)
6. Transition recv state → RESET_RECVD
7. Emit STREAM_RESET event
8. Call `maybe_cleanup()`

### 6.6 _handle_stop_sending

1. Extract stream_id, error_code
2. Validate stream exists
3. Validate direction (must target our send side)
4. If send state ∈ {READY, SEND, DATA_SENT}: transition → RESET_SENT, queue RESET_STREAM frame
5. If send state already in {RESET_SENT, RESET_RECVD, DATA_RECVD}: ignore
6. Emit STREAM_STOPPED event
7. Call `maybe_cleanup()`

### 6.7 send() extensions

In `_build_frames_for_space` for Application space (space_idx == 2), after CRYPTO frames:
1. CID frames: `cid_mgr.pending_new_cid_frames()` + `cid_mgr.pending_retire_frames()`
2. MAX_DATA if `stream_map.conn_fc_recv.should_update()`
3. MAX_STREAM_DATA for each stream with `fc_recv.should_update()`
4. MAX_STREAMS_BIDI/UNI if stream credit threshold met
5. RESET_STREAM for streams with `needs_reset_stream` flag (retransmit until ACKed)
6. STOP_SENDING for streams with `needs_stop_sending` flag (retransmit until RESET_STREAM received from peer)
7. STREAM frames — round-robin across sendable streams, respecting `min(stream FC, conn FC)` credit

### 6.8 on_ack extensions

When STREAM frames in a SentPacket are ACKed:
- Update stream's SendBuf (mark bytes as ACKed)
- If all bytes + FIN ACKed → send state DATA_SENT → DATA_RECVD
- If RESET_STREAM ACKed → send state RESET_SENT → RESET_RECVD
- Call `maybe_cleanup()`

When flow control frames (MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS) are ACKed: mark as delivered (stop retransmitting).

When CID frames are ACKed: mark CID as advertised / retirement as delivered.

### 6.9 on_loss extensions

When STREAM frames are lost: retransmit (reset SendBuf.unsent_offset).
When RESET_STREAM is lost: retransmit.
When STOP_SENDING is lost: retransmit.
When flow control frames are lost: regenerate with current values (not exact retransmit — values may have increased).
When CID frames are lost: retransmit.

---

## §7 Public API

### 7.1 Stream operations

```
def open_stream(mut self, bidi: Bool) raises -> UInt64:
    """Open a new locally-initiated stream. Returns the stream ID.
    Raises if MAX_STREAMS limit is reached."""

def send_stream_data(mut self, stream_id: UInt64, data: Span[UInt8, _], fin: Bool) raises:
    """Queue data for sending on a stream. Set fin=True for last write.
    Raises if stream doesn't exist or send state is invalid."""

def recv_stream_data(mut self, stream_id: UInt64) raises -> Tuple[List[UInt8], Bool]:
    """Read available contiguous data from a stream.
    Returns (data, fin_reached). Updates flow control (issues MAX_STREAM_DATA
    and MAX_DATA as needed). Raises if stream doesn't exist."""

def reset_stream(mut self, stream_id: UInt64, error_code: UInt64) raises:
    """Abort the send side of a stream. Sends RESET_STREAM to peer.
    Raises if stream doesn't exist or send state is terminal."""

def stop_sending(mut self, stream_id: UInt64, error_code: UInt64) raises:
    """Request the peer to stop sending on a stream. Sends STOP_SENDING.
    Raises if stream doesn't exist or recv state is terminal."""
```

### 7.2 recv_stream_data flow control integration

When the application reads data via `recv_stream_data`:
1. Drain contiguous bytes from RecvBuf
2. Update consumed counters: `stream.fc_recv.add_consumed(len(drained))` and `stream_map.conn_fc_recv.add_consumed(len(drained))`
3. If `stream.fc_recv.should_update()`: set `stream.needs_max_stream_data = True`
4. If `stream_map.conn_fc_recv.should_update()`: mark connection for MAX_DATA generation
5. If recv state is DATA_RECVD and all data read → transition to DATA_READ, call `maybe_cleanup()`

---

## §8 Events

### 8.1 New event types for QuicEvent

Add to the existing `QuicEvent` tagged struct (existing: 1=HANDSHAKE_COMPLETE, 2=CONNECTION_CLOSED, 3=PEER_TRANSPORT_PARAMS):

```
# 4 = reserved for future connection-level events (e.g., IDLE_TIMEOUT)
STREAM_READABLE   = 5   # stream_id: UInt64
STREAM_WRITABLE   = 6   # stream_id: UInt64
STREAM_RESET      = 7   # stream_id: UInt64, error_code: UInt64, final_size: UInt64
STREAM_STOPPED    = 8   # stream_id: UInt64, error_code: UInt64
STREAM_OPENED     = 9   # stream_id: UInt64
```

**STREAM_READABLE:** emitted when new contiguous data is available (recv state transition or new data fills a gap).
**STREAM_WRITABLE:** emitted when send FC credit becomes available (received MAX_STREAM_DATA or MAX_DATA).
**STREAM_RESET:** emitted when RESET_STREAM received from peer.
**STREAM_STOPPED:** emitted when STOP_SENDING received from peer.
**STREAM_OPENED:** emitted when a peer-initiated stream is first seen.

---

## §9 Frame Dispatch Table (complete, post-M3c)

| Frame | Space | M3b handler | M3c handler |
|-------|-------|-------------|-------------|
| PADDING | any | no-op | no-op |
| PING | any | no-op (ack tracked) | no-op |
| ACK | any | `_handle_ack` | extended with on_ack for stream frames |
| CRYPTO | I/H/1 | crypto_stream.receive | same |
| CONNECTION_CLOSE | any | drain timer | same |
| HANDSHAKE_DONE | 1-RTT | confirm handshake | same + issue seq=1 CID |
| NEW_TOKEN | 1-RTT | ignore | ignore (M4) |
| NEW_CONNECTION_ID | 1-RTT | ignore | `cid_mgr.on_new_connection_id` |
| RETIRE_CONNECTION_ID | 1-RTT | ignore | `cid_mgr.on_retire_connection_id` |
| STREAM | 0/1-RTT | ignore | `_handle_stream_frame` |
| RESET_STREAM | 0/1-RTT | ignore | `_handle_reset_stream` |
| STOP_SENDING | 0/1-RTT | ignore | `_handle_stop_sending` |
| MAX_DATA | 0/1-RTT | ignore | `conn_fc_send.ensure_limit` |
| MAX_STREAM_DATA | 0/1-RTT | ignore | `stream.fc_send.ensure_limit` |
| MAX_STREAMS | 0/1-RTT | ignore | update peer_max_streams |
| DATA_BLOCKED | 0/1-RTT | ignore | log only |
| STREAM_DATA_BLOCKED | 0/1-RTT | ignore | log only |
| STREAMS_BLOCKED | 0/1-RTT | ignore | log only |
| PATH_CHALLENGE | 1-RTT | ignore | ignore (migration) |
| PATH_RESPONSE | 1-RTT | ignore | ignore (migration) |

---

## §10 Out of Scope

Items NOT in M3c:

| Item | Severity | Trigger |
|------|----------|---------|
| Stream priority scheduling (RFC 9218) | required-later | M5 (HTTP/3) sets urgency/incremental per stream |
| Flow control auto-tuning | required-later | M4 (congestion control provides RTT estimates) |
| 0-RTT data | optional | M4+ interop hardening |
| Connection migration | required-later | Dedicated migration milestone |
| PATH_CHALLENGE / PATH_RESPONSE | required-later | Migration milestone |
| Stateless reset sending/detection | optional | Production deployment |
| CID rotation (timer/traffic-based) | optional | Migration milestone |
| Proactive CID issuance beyond seq=1 | optional | Migration milestone |
| NEW_TOKEN frame handling | optional | M4 |
| send_window local cap (quinn pattern) | optional | M4 performance hardening |

---

## §11 Testing Strategy

### 11.1 Unit tests

**`tests/test_quic_flow_control.mojo`** (~200 LoC):
- FlowControl basic: initial state, add_consumed, should_update at threshold
- Monotonic ensure_limit: ignore decreasing values
- available() with various consumed/limit states
- Blocked tracking

**`tests/test_quic_stream.mojo`** (~500 LoC):
- SendState transitions: READY→SEND→DATA_SENT→DATA_RECVD
- SendState reset: SEND→RESET_SENT→RESET_RECVD
- RecvState transitions: RECV→SIZE_KNOWN→DATA_RECVD→DATA_READ
- RecvState with STOP_SENDING: RECV→STOP_SENDING_SENT→WAIT_FOR_RESET→RESET_RECVD→RESET_READ
- RecvBuf: in-order, out-of-order, overlapping, gap limiting, FIN handling
- RecvBuf: empty FIN, FIN before all data, duplicate FIN same/different final_size
- SendBuf: write, make_frame, on_ack, on_loss retransmission
- final_size invariant: RESET_STREAM with matching/mismatching final_size
- Direction validation: STOP_SENDING on wrong-direction uni

**`tests/test_quic_stream_map.mojo`** (~300 LoC):
- Stream creation: local bidi/uni, peer bidi/uni
- Stream ID allocation: correct ID encoding
- MAX_STREAMS enforcement: at limit, over limit (STREAM_LIMIT_ERROR)
- Implicit stream creation: receiving frame for stream N implies N-4, N-8 exist
- Stream cleanup: both sides terminal → removed from map
- MAX_STREAMS update: threshold-based increase after peer streams close
- Connection flow control: aggregate check across multiple streams
- RESET_STREAM phantom bytes: connection FC properly adjusted

**`tests/test_quic_cid.mojo`** (~250 LoC):
- CID generation: 8-byte random, unique
- Reset token generation: deterministic (same key+CID = same token)
- NEW_CONNECTION_ID handling: store peer CIDs, retire_prior_to semantics
- Retirement queue: cap enforcement, PROTOCOL_VIOLATION on overflow
- Late-arriving CID with seq < highest_retire_prior_to: immediately retired
- RETIRE_CONNECTION_ID: mark local CID retired, issue replacement
- Issuance: seq=1 after handshake, respect peer_active_limit

### 11.2 Integration tests (in `tests/test_quic_connection.mojo`, extending existing)

**`test_stream_data_transfer`**: Client opens bidi stream, sends "hello", server echoes. Verify data arrives.

**`test_multi_stream`**: Client opens 3 bidi streams, sends on all. Server reads from all and responds. Verify no cross-contamination.

**`test_unidirectional_stream`**: Client opens uni stream, sends data. Server receives. Server opens uni stream back.

**`test_flow_control_basic`**: Send data up to stream FC limit. Verify STREAM_DATA_BLOCKED. Read on receiver → MAX_STREAM_DATA issued → sender unblocked.

**`test_connection_flow_control`**: Multiple streams exhaust connection-level credit. Verify DATA_BLOCKED. Read on receiver → MAX_DATA → sender unblocked.

**`test_reset_stream`**: Client sends partial data, then RESET_STREAM. Server receives STREAM_RESET event. Verify connection FC accounts for final_size.

**`test_stop_sending`**: Server sends STOP_SENDING on a stream. Client receives STREAM_STOPPED, responds with RESET_STREAM. Stream fully closed.

**`test_cid_issuance`**: After handshake, both sides issue seq=1 CID via NEW_CONNECTION_ID. Verify frames exchanged.

**`test_cid_retirement`**: One side sends NEW_CONNECTION_ID with retire_prior_to. Peer retires old CIDs and sends RETIRE_CONNECTION_ID. Verify new CID issued in replacement.

**`test_cid_retirement_flood`**: Rapid NEW_CONNECTION_ID with escalating retire_prior_to. Verify retirement queue cap triggers PROTOCOL_VIOLATION.

### 11.3 Test runner

Add new test entries to `scripts/run_tests.sh`:
- `test_quic_flow_control`
- `test_quic_stream`
- `test_quic_stream_map`
- `test_quic_cid`

Existing `test_quic_connection` is extended in-place.
