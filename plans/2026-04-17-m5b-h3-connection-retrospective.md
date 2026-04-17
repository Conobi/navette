# M5b Retrospective — H3 Connection Layer

**Date:** 2026-04-17
**Spec:** `specs/2026-04-17-m5b-h3-connection.md`
**Plan:** `plans/2026-04-17-m5b-h3-connection.md`
**Commits:** `591c665..2ffc4e1` (15 commits including fixes and reviews)
**Tests:** 62/62 src, 35/35 conformance

---

## Built vs. planned

All 4 plan tasks delivered:

- **Task 0** — `src/h3/connection.mojo`: H3Event (Copyable, Movable, 8 kind constants), `_H3StreamBuf` (Copyable, Movable), H3Connection skeleton (17 fields, all methods stubbed). `tests/test_h3_connection.mojo`: 4 pure unit tests.

- **Task 1** — Full H3Connection implementation: `feed_datagram` (QuicEvent dispatch), `drain_datagrams`, `_bootstrap_local_streams` (3 uni streams + SETTINGS), `_drain_stream` (type-byte dispatch, frame accumulation), `_parse_frames_from_buf` (ByteReader loop), `_handle_control_frame` (SETTINGS/GOAWAY/forbidden), `_handle_request_frame` (HEADERS/DATA/forbidden), `send_headers`/`send_data`/`send_goaway`/`reset_stream`/`open_bidi_stream`. QUIC loopback test `test_h3_control_stream_setup` (SETTINGS_RECEIVED confirmed within 50 pump rounds).

- **Task 2** — `src/h3/h3_handler_server.mojo`: H3HandlerServer[H: StreamHandler] with heap-allocated `_H3StreamCtx`, full event dispatch (HEADERS/DATA/STREAM_ENDED/STREAM_RESET), `_drain_responses`, `_maybe_cleanup`. `tests/test_h3_e2e.mojo`: `test_h3_simple_get` + `test_h3_post_with_body`.

- **Task 3** — `src/h3/h3_session.mojo`: H3Session (Session trait) with heap-allocated `_H3ClientCtx`, `submit`/`run_one`/`run_until`/`close`/`capabilities`/`alpn`, `received_goaway: Bool` field. Added `test_h3_session_get`, `test_h3_multi_request`, `test_h3_goaway` to `test_h3_e2e.mojo`.

- **Task 4** — `src/h3/__init__.mojo` exports (H3Event, H3Connection, H3HandlerServer, H3Session). `scripts/run_tests.sh` updated (62/62).

**LoC delta:** ~1800 lines across 7 files (within spec estimate of 1600–1900).

---

## Deviations and why

### 1. Bidi rejection guard inverted in `_drain_stream`

The plan specified `not self._is_peer_initiated(stream_id)` as the rejection guard. This is logically backwards: only peer-initiated bidi streams from the server are forbidden (RFC 9114 §6.1), not locally-initiated ones. Fixed to `self._is_peer_initiated(stream_id) and not self._is_server`. The plan's guard was a dead no-op because locally-initiated streams are never in `_stream_bufs`.

### 2. Unknown uni-stream type: close → silent return

The plan called for `_quic.close(H3_STREAM_CREATION_ERROR, ...)` on unknown uni-stream type bytes. RFC 9114 §6.2.3 actually requires endpoints to IGNORE unknown stream types. Fixed to a silent `return`. The spec text was inconsistent with the RFC.

### 3. Client bidi streams must be registered in `_stream_bufs` on open

`open_bidi_stream()` was initially left without registering the new stream in `_stream_bufs`. The STREAM_OPENED event fires only for peer-initiated streams. Without registration, `_drain_stream` silently returned on STREAM_READABLE for the client's own request stream, meaning the client would never receive HEADERS_RECEIVED or DATA_RECEIVED. Fixed in `open_bidi_stream` by inserting a `_H3StreamBuf(is_uni=False)` entry.

### 4. `_streams.pop` must precede `free()` in cleanup methods

Both `_maybe_cleanup` and `_on_stream_reset` initially called `destroy_pointee` + `free` before removing the pointer from `_streams`. If the pop (inside `try/except`) failed or ran after the free, a stale pointer remained in `_streams`. Fixed by: (a) removing `try/except` masking, (b) popping from `_streams` before calling `free()`.

### 5. Dead `_set_error` call in `_on_stream_reset`

`_on_stream_reset` called `ctx.recv_body._set_error(...)` after `take_pointee()` moved `ctx` out of the heap slot. The mutation was on a local copy that was immediately discarded — dead code. Removed.

### 6. `init_pointee_move` roundtrip in H3Session `run_one`

The initial `run_one` implementation did `take_pointee()` → manipulate → `init_pointee_move(ctx^)` → `destroy_pointee()` → `free()`. The roundtrip through `init_pointee_move` + `destroy_pointee` was architecturally redundant: after `take_pointee`, the slot is uninit; re-initializing it just to immediately destroy it is unnecessary. Fixed to: `take_pointee()` → use `ctx` → pop both dicts → `ctx_ptr.free()` → let `ctx` drop naturally.

### 7. `test_h3_goaway`: server._h3 direct access

The plan's test accessed `server._h3.send_goaway(...)` directly. Fixed by adding `H3HandlerServer.send_goaway()` delegation method. Client GOAWAY detection was moved to a `received_goaway: Bool` field on `H3Session` (set during `_dispatch_events`) rather than polling `client._h3` directly.

### 8. `RequestHandle` not in `List[RequestHandle]` for multi-request test

The plan's `test_h3_multi_request` used `List[RequestHandle]()` with three appended handles. In Mojo 0.26.2, `RequestHandle` is not `Copyable`, so `List[RequestHandle]` is illegal (List requires Copyable elements). Replaced with three named variables.

### 9. `Tuple` element move restriction

The plan's helper `_h3_create_pair()` returned a `Tuple[H3Connection, H3Connection]`. In Mojo 0.26.2, you cannot move out of a Tuple index via `pair[0]^`. The loopback pair setup was inlined directly in each test instead of going through a helper.

---

## Pain points

- **Bidi guard direction**: The spec and plan both had the guard backwards. The reviewer caught it in the first Task 1 review. The root cause: the guard was written from "what should be rejected" without checking that locally-initiated streams are never in `_stream_bufs` — making the condition a no-op in both directions.
- **Dict pop-before-free discipline**: The H3HandlerServer and H3Session both needed the same fix (pop before free). A code pattern note in the project conventions would prevent this in future milestones.
- **Heap-alloc roundtrip antipattern**: The `init_pointee_move(ctx^) → destroy_pointee()` roundtrip in `run_one` was introduced to satisfy Mojo's partial-move restrictions but produced a logically redundant path. The correct pattern (take_pointee → use local ctx → free raw memory → let local drop) is cleaner and was confirmed in Task 3 review.
- **`Tuple` element move limitation**: The plan assumed `pair[0]^` works, but Mojo 0.26.2 disallows moving from Tuple index positions. The workaround (inline setup in each test) is verbose but correct.

---

## Open questions

### Required-later

| What | Severity | Trigger |
|---|---|---|
| H3HandlerServer._on_request silently drops stream if handler raises (no 4xx/5xx response) | required-later | When H3HandlerServer needs proper error dispatch; same gap as H2HandlerServer |
| aioquic interop loopback (QC-3) | required-later | Before M6 ships to production |
| M3c integration test coverage gaps (FC error paths, MAX_STREAM_DATA flow, CID retire→reissue, loss+retransmit) | required-later | Before M5b behaviors are relied on end-to-end |
| oACK rejection integration test | required-later | When PacketNumberSpace.process_ack path is exposed |

### Optional / deferred

| What | Severity | Trigger |
|---|---|---|
| Duplicate peer control stream not rejected (silent overwrite of _peer_ctrl_sid) | optional | QC-3 conformance testing |
| O(n) poll_event queue rebuild | optional | Performance profiling |
| QPACK dynamic table | optional | M6 or later |
| H3CoroServer (async handler) | optional | After Mojo native async lands |

---

## Next spec recommendations (M6)

1. **M6 — Unified HTTP client.** M5b closes the H3 server+client layer. M6 unifies H1/H2/H3 behind a single `Client` type with protocol selection via ALPN negotiation. Spec should cover: connection pooling (one pool per origin), `Client.get(url)` / `Client.post(url, body)` ergonomic API wrapping `H1Session`/`H2Session`/`H3Session`, connection lifecycle (idle timeout, max connections per origin), TLS certificate validation config. M6 depends on M5.5 + M5b + M2.5b (all done).

2. **QC-3 — H3 interop vectors.** Feed aioquic-generated H3 traffic through our H3Connection and verify correct event emission. The oracle framework from QC-1/QC-2 can be extended. Add duplicate-control-stream rejection test at the same time.
