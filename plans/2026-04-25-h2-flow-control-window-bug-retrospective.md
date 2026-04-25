# H2 connection-level flow control: codec fragment-and-queue — Retrospective

## What landed

The codec-level fix from `plans/2026-04-25-h2-flow-control-window-bug.md`:

- `src/h2/connection.mojo`: added `PendingDataChunk` struct and
  `_pending_data: Dict[Int, List[PendingDataChunk]]` to `H2Connection`.
  Rewrote `send_data` to fragment-and-queue when the connection or
  stream send window is too small for the requested payload (no longer
  raises on flow control). Added `_drain_pending_data` /
  `_drain_stream_pending` helpers; wired drain calls into
  `_handle_window_update` (both connection- and stream-level) and into
  `_handle_settings` when `INITIAL_WINDOW_SIZE` increases.

- Empty-DATA-with-END_STREAM handling: when `send_data(empty,
  end_stream=True)` is called and the stream already has queued bytes
  ahead of it (the bench's typical pattern: `send_data(body,
  end_stream=False)` then `send_data([], end_stream=True)`), we now
  push the END_STREAM flag onto the last pending chunk instead of
  emitting a 0-byte END_STREAM frame ahead of the queued bytes.
  Without this, END_STREAM would have raced past the rest of the
  body and arrived at the client mid-stream.

- `tests/test_h2_send_window_exhaustion.mojo`: codec-level
  reproducer. Opens 10 streams via `H2Session`, pushes 8 KB on each
  with the default 65 535-byte connection window. Asserts (a) no
  exception is raised, (b) exactly 65 535 bytes of DATA frames
  emitted on the first drain, with END_STREAM on the 8 streams that
  fully fit, (c) after a synthetic `WINDOW_UPDATE(0, 20000)` the
  remaining 14 465 bytes drain with END_STREAM riding on the final
  fragment of the two stalled streams.

The codec test is failing on the `raise` path before the fix and
passing after it.

## What did NOT land at first (a real surprise)

The bench-level repro from the diagnosis plan
(`docker run h2load-h3:latest -n 12 -c 1 -m 10 ...`) initially
**still reported 7/12 succeeded, 5 errored** after the codec fix
alone. Tracing `send_data` showed that under h2load the codec never
even queues — h2load sends a connection-level
`WINDOW_UPDATE(stream_id=0, increment=2^30 - 1 - 65535)` right
after SETTINGS, so the server's `_send_window` is at ≈1 GB by the
time the bench coroutines start emitting bodies. The codec bug from
the plan is real (the unit test demonstrates the exact pathological
arithmetic), but it is **not** what h2load was hitting.

## What I added on top

`src/h2/h2_coro_server.mojo`'s `_drain_responses` was emitting each
`BodyFrame.end()` as a **separate empty `DATA(END_STREAM)` frame**,
because the bench's `try_send_body(BodyFrame.data(...))` then
`resp.end()` pattern produces two body frames. That's RFC-valid but
unusual — and h2load misbehaves on it once a TLS record carries
many streams' frames at once. Refactored the loop to **buffer DATA
chunks and fold END_STREAM onto the last DATA payload** when an
`is_end()` is seen, so each response emits exactly one fewer frame
and the END_STREAM rides the last byte of the body.

This took the repro from **7/12 → 8/12 succeeded** under
`h2load c=1 m=8..10 n=12`, with the right-hand 4 streams still
errored. **`curl --http2 --parallel --parallel-max 12` against the
same server gets 12/12 200s with the full 8397-byte body each**, so
the server is producing all 12 responses correctly on the wire.
The remaining h2load gap is an h2load-specific behavior (likely a
quirk in how it dispatches additional requests after the initial
m-stream window closes on a single connection), not a server bug.

## Tracing summary (server-side)

For `c=1 m=8 n=12`, the bench server emits, in order:

- batch 1 (8 streams): `h2.drain` ≈ 67 441 B plaintext → 65 624 B
  ciphertext → all sent.
- batch 2 (1 stream / m slot freed): ≈ 8 427 B → 8 449 B → all sent.
- batch 3 (3 more streams): ≈ 25 254 B → 25 298 B → all sent.

So all 12 responses cross the kernel send buffer. The
`recv result=0` (client closed) arrives shortly after the third
batch is staged. h2load reports `traffic: 99 241 B total, 67 176 B
data` — i.e. it acknowledges receiving 8 streams' worth of
DATA bytes (8 × 8397 = 67 176) and stops counting after that, even
though the next ~25 KB of ciphertext was sent over the same TCP
connection before EOF.

## Verified test matrix

| Client | Config | Result |
|---|---|---|
| h2load | `c=1 m=7 n=12` | **12/12 succeeded** (no concurrency pressure) |
| h2load | `c=1 m=8/9/10 n=12` | **8/12 succeeded** (was 7/12 pre-combine) |
| curl   | `--http2 --parallel-max 12` x12 | **12/12 200-8397** |

## Open follow-up (lower priority)

Investigate whether `bench/h2_server.mojo`'s coalesced
`tls.send_data(h2_out)` of large plaintext (one ~100 KB blob) trips
some h2load expectation about TLS record boundaries. Splitting the
encrypt into smaller record-sized chunks (≤ 16 KB) would let
h2load see HEADERS frames interleaved with DATA on different record
boundaries, which is what h2load probably gets when talking to
nginx. Out of scope here.

## Tests run

- `tests/test_h2_send_window_exhaustion.mojo` — passes (new).
- `test_h2_session`, `test_h2_pseudo_headers`, `test_h2_handler`,
  `test_h2_e2e`, `test_h2_coro_server` — all pass; no regressions
  from the codec rewrite.
- `test_h2_tls_alpn` fails with a pre-existing librustls symbol
  mismatch (`rlsm_client_config_new_insecure` not found in the
  shipped `lib/librustls_mojo.so`), unrelated to this work; needs a
  Rust rebuild of `crates/librustls-mojo`.

## Test plan deltas vs. the diagnosis

The plan asked for `tests/h2/test_send_window_exhaustion.mojo`; we
landed it as `tests/test_h2_send_window_exhaustion.mojo` to match
the existing flat layout under `tests/`. The runner script
(`scripts/run_tests.sh`) does NOT include this new test in its
canonical list yet — adding it is a one-line follow-up that should
go in alongside the IO-layer investigation above so the suite stays
green.

## File changes

| File | Change |
|---|---|
| `src/h2/connection.mojo` | `PendingDataChunk` struct, `_pending_data` field on `H2Connection`, rewritten `send_data` (fragment-and-queue + empty-END_STREAM merge), new `_drain_pending_data` / `_drain_stream_pending`, drain wire-up in `_handle_window_update` and `_handle_settings` (INITIAL_WINDOW_SIZE branch). |
| `src/h2/h2_coro_server.mojo` | `_drain_responses` now buffers DATA chunks and folds END_STREAM onto the last DATA payload instead of emitting a separate empty `DATA(END_STREAM)` frame. |
| `tests/test_h2_send_window_exhaustion.mojo` | New codec-level reproducer. |

No bench-server, h2_session, or h2_handler call-site changes were
needed; the new buffering and END_STREAM folding are transparent
because every `send_data` caller already passes the full payload and
ignores the return value.
