# H2 connection-level flow control: codec raises instead of buffering

## TL;DR

`src/h2/connection.mojo:843-846` — `Connection.send_data()` raises an
exception when the connection-level (or stream-level) send window is
too small for the requested DATA payload. RFC 7540 §5.2.1 requires the
sender to *defer* the send and resume on `WINDOW_UPDATE`, not to error.
This is the single root cause of the 9300/10000 H2 stream failures
under `-c 100 -m 10` against `/json/50?m=6`. Behaviour is silent on
`/baseline2` (1-byte responses never exhaust the window) and on `m=1`
(no concurrent streams means each request retires before the window
matters).

## Repro

```bash
DATA_DIR=$(pwd)/bench/data STATIC_DIR=/tmp/bench-static \
    CERTS_DIR=$(pwd)/certs LD_LIBRARY_PATH=$(pwd)/lib \
    BENCH_WORKERS=1 BENCH_PROTOCOL=h2 ./bench/launcher &

# Minimal repro: ONE connection, 10 concurrent streams, ~8 KB response.
docker run --rm --network host h2load-h3:latest \
    -v -n 12 -c 1 -m 10 'https://127.0.0.1:8443/json/50?m=6'
# Reports: 7 done, 7 succeeded, 5 errored
# Verbose log shows :status: 200 + content-length: 8397 for 8 streams
# Total data received: 67176 bytes = 8 * 8397
```

The codec accepts 7 full responses (7 × 8397 = 58 779 bytes ≤ 65 535)
plus the HEADERS for the 8th, then raises on the DATA frame for the 8th.
Subsequent stream attempts fail because the connection drops or stalls
after the exception unwinds out of the coro driver.

## Root cause — exact location

`src/h2/connection.mojo`, in `Connection.send_data`:

```mojo
def send_data(mut self, stream_id: UInt32, data: List[UInt8], *, end_stream: Bool = False) raises:
    ...
    var total = len(data)
    if total > self._send_window:
        raise Error("Flow control error: connection send window exhausted")  # line 844
    if total > stream.send_window:
        raise Error("Flow control error: stream send window exhausted")     # line 846
    ...
```

This API contract is wrong: callers cannot recover from a flow-control
exception in any meaningful way. Both call sites
(`src/h2/h2_coro_server.mojo:559-564`,
`src/h2/h2_session.mojo:175,287,290`,
`src/h2/h2_handler_server.mojo:409,414`) just call `send_data` directly
without try/except. When the exception fires the coro body unwinds, the
H2CoroServer drain loop aborts on the connection, and h2load sees the
remaining streams never receive their data.

## Why it's silent elsewhere

- `/baseline2` returns 1-byte responses. 65535 / 1 = 65 535 streams
  before the window matters — far beyond what h2load tests.
- `-m 1` (no concurrent streams) means each stream retires fully before
  the next is opened. h2load sends a WINDOW_UPDATE-equivalent settling
  through after each `END_STREAM` ack, and the server's `_send_window`
  is replenished by `_handle_window_update` (line 971) before the next
  request arrives. No exhaustion.
- HTTP/1 has no equivalent flow-control window, so H1 plain + H1 + TLS
  are unaffected.

## RFC 7540 §5.2.1 expected behaviour

> A sender MUST NOT allow a flow-control window to become negative. If a
> sender receives a WINDOW_UPDATE that causes a flow-control window to
> exceed this maximum, it MUST terminate either the stream or the
> connection, as appropriate.
>
> A sender that receives a flow-controlled frame MUST always account for
> its contribution against the connection flow-control window, unless the
> sender treats this as a connection error (Section 5.4.1).

The contract is: the sender must **never overshoot** the window. When
the window cannot accommodate a full DATA frame, the sender must
**hold the bytes**, send a smaller fragment that fits (or zero), then
send the rest after WINDOW_UPDATE replenishes the window. Erroring out
is not a valid implementation.

## Proposed fix

The send path needs a per-connection "pending DATA" queue and a drain
on every WINDOW_UPDATE. Three concrete changes:

### 1. Replace the `raise` in `send_data` with a fragment-and-queue

`src/h2/connection.mojo` Connection holds a new field:

```mojo
var _pending_data: Dict[Int, List[PendingDataChunk]]   # stream_id -> chunks
```

`send_data(stream_id, data, end_stream)` becomes:

- Compute `available = min(self._send_window, stream.send_window)`.
- If `available >= len(data)`: send the whole thing (existing path),
  decrement both windows, append to outbox.
- Else if `available > 0`: send `data[:available]` as DATA (no
  END_STREAM), decrement windows by `available`, append the remainder
  + the `end_stream` flag to `_pending_data[stream_id]`.
- Else (`available == 0`): append the whole `data` + `end_stream` to
  `_pending_data[stream_id]`.

`send_data` no longer raises on flow-control. It always succeeds.

### 2. Drain `_pending_data` on WINDOW_UPDATE

In `_handle_window_update` (line 971), after incrementing `_send_window`
or a stream's `send_window`, call a new helper:

```mojo
def _drain_pending_data(mut self, stream_id_hint: Int):
    # On connection-level update (stream_id_hint == 0), iterate every
    # entry in _pending_data and drain what fits.
    # On stream-level update, drain just that stream's queue.
    ...
```

The drain helper splits chunks by `min(_send_window, stream.send_window)`,
emits DATA frames into the outbox, decrements windows, and removes
fully-drained entries.

### 3. Drain `_pending_data` on SETTINGS frame `INITIAL_WINDOW_SIZE` increase

`_apply_remote_settings` (line 691) already adjusts per-stream
`send_window` via `_adjust_stream_send_windows` when
`INITIAL_WINDOW_SIZE` changes. After that adjustment, also call
`_drain_pending_data(0)` so any newly-available capacity gets used.

### 4. (Defensive) The drain trigger for `bench_h2_body_fn`

The H2CoroServer's drain loop currently runs on every IO completion. As
long as `_drain_pending_data` is invoked from inside the connection's
event loop (i.e. from `_handle_window_update`), no external trigger is
needed — the coro body simply submits a full-size response into the
codec, and the codec takes care of trickling it out.

If we discover the body fn currently *blocks* on send_data (it doesn't
today; it returns immediately), we'd also need a "send-ready" event for
streams that the body fn uses. Not required for the bench server pattern.

## Test plan

Before the fix lands, write a failing test that exercises the bug
directly, not via h2load.

`tests/h2/test_send_window_exhaustion.mojo`:

1. Build a `Connection` configured as a server.
2. Drive a SETTINGS handshake.
3. Open 10 streams with `_handle_headers` (synthesised request frames).
4. Call `connection.send_headers(...)` on all 10.
5. Call `connection.send_data(stream_id_i, 8000_bytes, end_stream=True)`
   for each in turn.
6. Assert no exception is raised on stream 8+ (current code raises).
7. Drain `connection.poll_send_buf()` → confirm only ~65 KB worth of
   DATA frames emitted (matches available window).
8. Synthesize a `WINDOW_UPDATE(stream_id=0, increment=80000)` frame and
   feed it into `connection.feed`.
9. Drain `poll_send_buf()` → confirm the remaining ~15 KB drains and
   end_stream flags fire on each stream.

Optionally a higher-level test through `H2CoroServer` confirming the
end-to-end round trip with the bench server itself.

## Concrete task breakdown (for a follow-up plan)

| File | Change |
|---|---|
| `src/h2/connection.mojo` | Add `PendingDataChunk` struct + `_pending_data` field; rewrite `send_data` to fragment-and-queue; add `_drain_pending_data`; call it from `_handle_window_update` and `_apply_remote_settings` (INITIAL_WINDOW_SIZE branch) |
| `tests/h2/test_send_window_exhaustion.mojo` | New test reproducing the bug at codec level |
| `tests/h2/test_connection.mojo` | Audit for any test that relies on the current `raise` behaviour and update |
| `bench/h2_server.mojo` | No change required (the bench coro body calls send_data once; the new buffering is transparent) |
| `src/h2/h2_session.mojo`, `src/h2/h2_handler_server.mojo` | No change required for the same reason |

Estimated scope: ~150 LOC in `connection.mojo`, ~80 LOC for the test.
Half a day to implement + verify, including the bench repro disappearing.

## Open question (one)

Is there an upper bound on how big `_pending_data` should be allowed to
grow before applying back-pressure to the body fn (i.e. signalling
`response_end` cannot be enqueued)? RFC 7540 doesn't specify; the body
fn semantics here are "submit the whole response, codec trickles it
out", so it's effectively bounded by the response size and number of
in-flight streams. For now no cap; if memory grows unboundedly under
adversarial clients we add a per-connection ceiling later.

## Other small things noticed

- `send_data` at line 845 also raises on stream-level window exhaustion.
  Same fix shape applies (queue + drain on stream-level WINDOW_UPDATE).
- The h2 coro body fn in `bench/handler.mojo` builds one big List[UInt8]
  per request and submits it through `try_send_body`. If we ever stream
  bodies (chunked encoding, large file responses), the codec's queue
  must support multiple chunks per stream — the proposed
  `List[PendingDataChunk]` design covers that.
