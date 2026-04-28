# Subagent B Report — Where the 24s of unattributed long-conn busy time lives

## TL;DR

The 24.4s ε (82% of long-conn busy) is **not** scattered across many sites. It is concentrated in the H3 application-layer plumbing that runs **inside** `feed_datagram_from_buffer` but **outside** `recv_from_buffer`'s per-pkt window — and **outside** `record_drain`'s window too. Specifically:

1. **`H3HandlerServer._dispatch_h3_events`** — calls into `BenchHandler.on_request` / `on_body_available` / `on_request_end` synchronously per H3 event. Wholly untimed.
2. **`H3HandlerServer._drain_responses`** — builds H3 HEADERS + DATA frames, QPACK-encodes, calls `_quic.send_stream_data`. Wholly untimed.
3. **`H3Connection.feed_datagram_from_buffer`'s post-recv tail** — `_quic.timeout(now)` + `_quic.poll()` event drain + `_drain_stream` (per-stream H3 frame parsing + QPACK decode). Wholly untimed.

All three live between `record_pkt` (last fires inside `recv_from_buffer` at `connection.mojo:890`) and `record_drain` (begins at `bench/h3_server.mojo:889`). On long-conn — handshake-done, response-heavy — this is the dominant cost.

## 1. Static call graph for one `_flush_impl` for-loop iter (long-conn steady state)

Numbered by `bench/h3_server.mojo` line; bucket attribution in **bold**.

- L723 `pd = self.pending_rx[i].copy()` — **pop_dispatch**
- L727 `t_pop_dispatch_start = profile_monotonic_us()` — opens pop_dispatch window
- L728 `record_loop_iter()`
- L734 `record_arrival_lat(...)` — **pop_dispatch**
- L739 `record_conn_pkt(pd.addr_key)` — **pop_dispatch**
- L742 `_bytes_to_hex(Span(pd.dcid))` — **pop_dispatch**
- L743 `_find_conn_by_dcid(dcid_hex)` — **pop_dispatch**
- L751 `_is_long_header_initial(...)` (only on miss) — **pop_dispatch**
- L762 `is_expected_dcid(...)` (DCID-mismatch counter) — **pop_dispatch**
- L777-794 `QuicConnection.server(...)` (only on first pkt of new conn — rare in long-conn) — **pop_dispatch**
- L822 `H3HandlerServer[BenchHandler](quic=quic^, handler=handler^)` (rare) — **pop_dispatch**
- L854 `record_loop_pop_dispatch(...)` — closes pop_dispatch window
- **L857 `self.conn_h3s[conn_idx][].feed_datagram_from_buffer(pd.payload_ptr, pd.payload_len, now)`** — **MIXED: per_pkt is timed inside, BUT the H3 dispatch + handler + response-build tail is UNATTRIBUTED**. See section 2.
- L866 `t_post_pkt_start = profile_monotonic_us()` — opens post_pkt
- L873 `is_established()` check + `record_conn_hs_complete(...)` — **post_pkt**
- L877-879 `addr_update` peer-address copy loop — **post_pkt**
- L880 `self.conn_addrs[conn_idx] = addr_update^` — **post_pkt**
- L884 `record_loop_post_pkt(...)` — closes post_pkt
- L889 `t_drain_start = profile_monotonic_us()` — opens drain
- L891 `self._drain_and_send(conn_idx, now)` — **drain**
  - calls `H3HandlerServer.drain_datagrams` → `H3Connection.drain_datagrams` → `QuicConnection.send`
  - which calls `_build_frames_for_space` + `_build_app_frames` + `_build_packet` (encrypt + AEAD seal via rustls FFI) + `serialize_frames`
  - then encodes a sendmsg PendingSubmit
- L897 `record_drain(drain_us)` — closes drain
- L900 `consumed_bufs.append(pd.buf_id)` — **UNATTRIBUTED** (between record_drain and next iter; trivial cost)

**Loop teardown** (post-last-iter, L902-909): `pending_rx.clear()` + `record_loop_teardown` — **teardown**.

### Decomposition of L857 `feed_datagram_from_buffer` (the dominant unattributed sink)

`H3HandlerServer.feed_datagram_from_buffer` (`src/h3/h3_handler_server.mojo:122-132`):
1. `self._h3.feed_datagram_from_buffer(buf, buf_len, now)` → `H3Connection.feed_datagram_from_buffer` (`src/h3/connection.mojo:255-296`):
   - L263 `self._quic.recv_from_buffer(buf, buf_len, now)` — **fully timed**: fires `record_pkt` per inner iter, plus per-leg `header_parse / hp / aead / frame_parse / sm / residual` and FFI sub-legs.
   - L264 `self._quic.timeout(now)` — **UNATTRIBUTED**
   - L265-296 `while True: poll()` event loop → `_drain_stream(ev.stream_id, now)` per readable stream — **UNATTRIBUTED**. This is where H3 frame parsing + QPACK decode happens.
2. L130 `self._dispatch_h3_events(now)` (`h3_handler_server.mojo:146-159`) — **UNATTRIBUTED**:
   - HEADERS_RECEIVED → `_on_request` → builds `Request` + `RecvBody` + `ResponseWriter` + **calls `self.handler.on_request(...)` (BenchHandler synchronous handler)**.
   - DATA_RECEIVED → `_on_data` → `recv_body._push(...)` + `self.handler.on_body_available(...)`.
   - STREAM_ENDED → `_on_stream_ended` → `self.handler.on_request_end(...)`.
3. L131-132 `if self._h3.is_established(): self._drain_responses(now)` — **UNATTRIBUTED**:
   - For each open stream: `_take_status` + `_take_headers` + builds `QpackHeaderField` list + `self._h3.send_headers` (which internally QPACK-encodes via `self._enc.encode(fields)` and calls `_quic.send_stream_data`).
   - Drains body frames: `f.is_data()` → `self._h3.send_data(sid, data_copy^, False)` → `_quic.send_stream_data` (this writes into the QUIC stream send buffer; the actual on-wire packet build + AEAD seal happens later inside `_drain_and_send`).

## 2. Top 3 suspected sinks for the 24.4s

Ranked by likely share. All three live in the same untimed region (the post-recv tail of `feed_datagram_from_buffer` plus `_dispatch_h3_events` + `_drain_responses`).

### Rank 1 — Response build path (`_drain_responses`) — LARGE share (likely 12-16s)
- **File:line:** `src/h3/h3_handler_server.mojo:260-329`.
- **Why unattributed:** runs in the post-recv tail of `feed_datagram_from_buffer` (h3_handler_server.mojo:131-132); not inside `recv_from_buffer` (so not captured by `record_pkt`'s per-iter window) and not inside `_drain_and_send` (so not captured by `record_drain`).
- **Cost components per H3 response:**
  - QPACK encode of `:status` + headers (`H3Connection.send_headers` → `self._enc.encode(fields)` at `src/h3/connection.mojo:308`)
  - Wire-frame encode of HeadersFrame + DataFrame (`hf.encode()`, `df.encode()`)
  - `_quic.send_stream_data(...)` per HEADERS + DATA + FIN — 3 STREAM-buffer writes per H3 response.
- **Why on long-conn it dominates:** 14,109 rps × ~3 buffer-writes-per-resp × ~30s ≈ 1.27M operations through this code path. `_drain_responses` is invoked **on every datagram feed** that crosses an established conn.

### Rank 2 — H3 stream-readable drain (`H3Connection._drain_stream`) — MEDIUM-LARGE share (likely 5-8s)
- **File:line:** Called from `src/h3/connection.mojo:283` (inside `feed_datagram_from_buffer`'s `poll()` event loop).
- **Why unattributed:** between `recv_from_buffer` and `_dispatch_h3_events`; outside any record_*.
- **Cost components:** reads STREAM-recv-buffer chunks, parses H3 DataFrame / HeadersFrame headers (varint length-prefixed), QPACK-decodes HEADERS field-section. Per-pkt this is small; aggregated over 14k rps it's substantial.

### Rank 3 — H3 application handler invoke (`BenchHandler.on_request` / `on_body_available` / `on_request_end`) — MEDIUM share (likely 1-3s)
- **File:line:** `src/h3/h3_handler_server.mojo:199, 223, 241`.
- **Why unattributed:** synchronous call inside `_dispatch_h3_events`; no record_* brackets it. Despite `BenchHandler` being a fixed-1k-payload trivial handler, response-builder allocation (`Headers`, `RecvBody`, `ResponseWriter`) happens in `_on_request` itself, plus dict insertion into `self._streams`.

### Honourable mentions (small/negligible share)
- `QuicConnection.timeout(now)` at `src/h3/connection.mojo:264` — runs on every datagram feed; cheap unless a timer fires.
- `QuicConnection.poll()` itself (the event-pump) — cheap when idle, otherwise its callees are the real cost.
- Early-return paths in `recv_from_buffer` that skip `record_pkt`: zero-padding (line 714), VN/Retry (748), no-keys-short-header (760), truncated (757, 770), AEAD-fail (881). These are **legitimately not captured**, but on long-conn steady-state they fire rarely (no AEAD failures expected; no truncations on local loopback). Negligible share of the gap.

## 3. Why long-conn ε is 82% but short-conn ε is only 18%

**Hypothesis confirmed.** Cross-checking the two sidecars:

| Metric | long-conn | short-conn |
|---|---|---|
| `busy_us_total` | 29.57M | 16.12M |
| `per_pkt.sm` | 0.17M | 8.12M |
| `per_pkt.frame_parse` | 1.59M | 1.02M |
| `shim_ffi` | 0.12M | 7.52M |
| `drain` | 3.00M | 2.10M |
| `unaccounted_us_total` | 24.41M | 3.00M |
| `unaccounted_pct` | 82% | 18% |

- **Short-conn is handshake-bound:** `sm` (8.12M) ≈ `shim_ffi` (7.52M) ≈ `read_hs` FFI sub-leg (7.01M). The hot path is `_drive_handshake` calling rustls `read_hs/write_hs/take_keys` — all already instrumented inside `recv_from_buffer`'s window. So short-conn gets clean attribution.
- **Long-conn is response-build-bound:** handshake is essentially done after the first second (`sm` = 0.17M, `shim_ffi` = 0.12M — both 50× smaller than short-conn). The remaining ~28s of busy work is steady-state H3 request → handler → response → STREAM-buffer write, none of which is bracketed by a record_*. Hence the gap balloons to 82%.

This is consistent with the post-migration finding: long-conn is now in the "steady-state per-packet hot path" regime that the project-context flagged as "the next bottleneck" after the demux fix.

## 4. Recommended instrumentation strategy

Bracket the three untimed phases with new `AcceptProfile` legs. Three new fields, three new `record_*` methods, three insertion-point pairs:

1. **`h3_dispatch_us`** — bracket `self._dispatch_h3_events(now)` at `h3_handler_server.mojo:130`. Captures handler invoke + Request/Response/Body construction.
2. **`h3_drain_resp_us`** — bracket `self._drain_responses(now)` at `h3_handler_server.mojo:132`. Captures QPACK encode + H3 frame encode + STREAM-buffer writes.
3. **`quic_post_recv_us`** — bracket the `poll()`-loop tail of `H3Connection.feed_datagram_from_buffer` at `src/h3/connection.mojo:264-296`. Captures `_quic.timeout` + `_drain_stream` + event-pump.

Wiring options:
- **Option A (cleanest):** add the brackets inside `H3HandlerServer.feed_datagram_from_buffer` (`h3_handler_server.mojo:122-132`) and `H3Connection.feed_datagram_from_buffer` (`src/h3/connection.mojo:255-296`). Pass `profile_ptr` down via `H3HandlerServer.__init__` (which already holds the `_h3` field).
- **Option B (minimal-touch):** wrap the L857 call in `bench/h3_server.mojo` with three nested timers — cheap if we accept that we can only measure the OUTER call (no decomposition into dispatch vs drain_resp vs post_recv).

**Recommended: Option A**, mirroring the existing FFI sub-leg pattern (single-pair clock-read with hoisted `var t_start: UInt64 = 0`).

**LoC estimate for the follow-on spec:**
- `src/quic/profile.mojo`: 3 fields + 3 methods + report_json/text wiring → ~30 LoC.
- `src/h3/h3_handler_server.mojo`: 2 brackets + profile_ptr field + ctor change → ~25 LoC.
- `src/h3/connection.mojo`: 1 bracket around the poll-loop tail + profile_ptr field + ctor change → ~20 LoC.
- `bench/h3_server.mojo`: thread profile_ptr through `H3HandlerServer` ctor at line 822 → ~5 LoC.
- Tests: +6 (one per leg + budget closure refresh) → matches the rhythm of the existing T1/T2/T3 split.
- **Total: ~80-100 LoC**, plan-compatible with a single-spec/single-plan pass.

## 5. Spec it now or defer?

**Recommend: spec it next, after the current sub-leg pass closes.** Reasoning:

- The existing `read_hs` deep-dive (Subagent A's scope) targets short-conn's 7.01M μs read_hs total — that is the single largest accounted cost on the short-conn cell, and short-conn is at 46.8% of tquic_server. It's a well-defined optimisation target with clean attribution.
- However, **long-conn is at 16.2% of tquic_server** — the bigger gap. The 24.4s unattributed window IS the long-conn hot path. Optimising read_hs (handshake-only) will not move long-conn rps. The next long-conn-moving optimisation requires this gap closed first.
- The two specs are orthogonal in code (FFI sub-legs vs H3-layer phase legs) so they can be spec'd and shipped sequentially without rebase pain.

**Practical sequencing:**
1. **Now:** finish the current sub-leg pass (project-context says "implementing"); ship + REFERENCE.md entry.
2. **Next spec:** the H3 phase-leg pass described in §4 (~80-100 LoC). Names the dominant long-conn unattributed phase, just as the current pass names the dominant short-conn FFI sub-leg.
3. **Then:** Subagent A's read_hs deep-dive becomes the short-conn-side optimisation; the new H3 phase-leg pass illuminates the long-conn-side optimisation target. The two optimisations can run in parallel after the diagnostic specs both land.

The 24s gap is **not blocking** for read_hs work (short-conn can be optimised in isolation — its ε is only 18%). But it IS blocking for any long-conn optimisation pass: without phase-leg attribution, we can't tell whether to attack QPACK encode, STREAM-buffer write, handler invoke, or the post-recv H3 event drain. Spec it before the next long-conn-targeted optimisation.

## File pointers (absolute paths)

- `/home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main/bench/h3_server.mojo` — `_flush_impl` at L710-938; `_drain_and_send` at L940-962.
- `/home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main/src/quic/connection.mojo` — `recv_from_buffer` L669-924 (record_pkt at L890); `_drive_handshake` L1572-1721 (FFI sub-legs at L1591-1607, 1620-1642, 1673-1687); `send` L1838-1960; `_build_packet` L2251.
- `/home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main/src/h3/h3_handler_server.mojo` — `feed_datagram_from_buffer` L122-132 (the **untimed** call site); `_dispatch_h3_events` L146-159; `_on_request` L161-211 (handler invoke at L199); `_drain_responses` L260-329.
- `/home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main/src/h3/connection.mojo` — `feed_datagram_from_buffer` L255-296 (poll-loop tail at L265-296); `drain_datagrams` L298-300; `send_headers` L304-311 (QPACK encode + send_stream_data); `send_data` L313+.
- Sidecars: `bench/quic_perf/results/profile/INSTRUMENTATION-20260428-015152-postmigration-longconn-subleg.json` (long-conn, ε=82%); `bench/quic_perf/results/profile/INSTRUMENTATION-20260428-015250-postmigration-shortconn-subleg.json` (short-conn, ε=18%).
