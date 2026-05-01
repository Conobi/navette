# TQUIC + quiche stream-read path — reference for mojo-net Q1 sub-leg taxonomy

Sources investigated:

- TQUIC: `/home/donokami/Projets/perso/tquic-example-c/deps/tquic/src/h3/` (the Rust source vendored under tquic-example-c/deps).
- quiche: `cloudflare/quiche@HEAD`, fetched via `gh api repos/cloudflare/quiche/contents/quiche/src/h3/{mod,frame,stream}.rs` and `quiche/src/stream/recv_buf.rs`. Local copies cached at `/tmp/quiche-research/{mod,frame,stream,recv_buf,qpack-decoder}.rs` and `/tmp/quiche-research/quiche-{server,common}.rs`.

mojo-net code under investigation:

- `/home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main/src/h3/connection.mojo:259-317` — the `quic_post_recv_us` bracket.
- same file `:406-469` (`_drain_stream`), `:471-502` (`_parse_frames_from_buf`), `:536-554` (`_handle_request_frame`).

---

## 1. TQUIC trace — QUIC stream-readable → H3 frame parse → handler dispatch

Application enters via `H3Connection::process_streams()` — the only public entry that wires QUIC events to the HTTP/3 handler.

### 1.1 Outer driver: `process_streams` → `poll`

`tquic/src/h3/connection.rs:1998` — `process_streams(&mut self, conn)`:

```rust
loop {
    match self.poll(conn) {
        Ok((stream_id, Http3Event::Headers { headers, fin })) => {
            self.handler.as_ref().unwrap().on_stream_headers(stream_id, &mut Http3Event::Headers { headers, fin });
        }
        Ok((stream_id, Http3Event::Data)) => {
            self.handler.as_ref().unwrap().on_stream_data(stream_id);
        }
        Ok((stream_id, Http3Event::Finished)) => {
            self.handler.as_ref().unwrap().on_stream_finished(stream_id);
        }
        ...
        Err(Http3Error::Done) => break,
        ...
    }
}
```

(`tquic/src/h3/connection.rs:2007-2050`)

This is the `while True: ev = poll()` loop — semantically identical to mojo-net's `while True: var ev_opt = self._quic.poll()` in `connection.mojo:281-313`.

### 1.2 `poll()` — entry into the readable-stream scan

`tquic/src/h3/connection.rs:1960`:

```rust
pub fn poll(&mut self, conn: &mut Connection) -> Result<(u64, Http3Event)> {
    if conn.local_error().is_some() { return Err(Http3Error::Done); }
    if let Some(stream_id) = self.finished_streams.pop_front() {
        return Ok((stream_id, Http3Event::Finished));
    }
    match self.process_critical_streams(conn) { ... }
    match self.process_readable_streams(conn) { ... }
    if let Some(stream_id) = self.finished_streams.pop_front() {
        return Ok((stream_id, Http3Event::Finished));
    }
    Err(Http3Error::Done)
}
```

`process_critical_streams` (`:1893-1909`) handles control + QPACK enc/dec streams in fixed order.

### 1.3 `process_readable_streams` — iterate `stream_readable_iter()`

`tquic/src/h3/connection.rs:1914-1948`:

```rust
fn process_readable_streams(&mut self, conn: &mut Connection) -> Result<(u64, Http3Event)> {
    for stream_id in conn.stream_readable_iter() {
        trace!("{:?} stream {} readable", conn.trace_id(), stream_id);
        let ev = match self.process_readable_stream(conn, stream_id, true) { ... };
        if conn.stream_finished(stream_id) {
            self.process_finished_stream(stream_id);
            ...
        }
        if let Some(ev) = ev { return Ok(ev); }
    }
    Err(Http3Error::Done)
}
```

`stream_readable_iter()` is defined in `tquic/src/connection/connection.rs:3639` and iterates a per-connection readable-set. mojo-net's analogue is `_quic.poll()` returning a `STREAM_READABLE` event per stream (`connection.mojo:297`).

### 1.4 `process_readable_stream` — fan out by uni/bidi

`tquic/src/h3/connection.rs:1803-1825`:

```rust
match crate::stream::is_bidi(stream_id) {
    false => self.process_readable_uni_stream(conn, stream_id, polling),
    true  => self.process_readable_request_stream(conn, stream_id, polling),
}
```

### 1.5 `process_readable_request_stream` — the FSM driver (the hot inner loop)

`tquic/src/h3/connection.rs:1740-1797` — this is the per-bidi-stream state-machine driver. It reads from `Http3Stream::state()` (`Http3StreamState`) and calls into `stream.rs` parse functions:

```rust
while let Some(stream) = self.streams.get_mut(&stream_id) {
    match stream.state() {
        Http3StreamState::FrameType => {
            stream.parse_frame_type(conn)?;          // -> stream.rs:336
        }
        Http3StreamState::FramePayloadLen => {
            stream.parse_frame_payload_length(conn)?; // -> stream.rs:400
        }
        Http3StreamState::FramePayload => {
            if !polling { break; }
            let (frame, payload_len) = stream.parse_frame_payload(conn)?;  // -> stream.rs:524
            match self.process_frame(conn, stream_id, frame, payload_len) {
                Ok(ev) => return Ok(ev),
                Err(Http3Error::Done) => { if conn.stream_finished(stream_id) { break; } }
                Err(e) => return Err(e),
            };
        }
        Http3StreamState::Data => {
            if !polling || !stream.trigger_data_event() { break; }
            return Ok((stream_id, Http3Event::Data));
        }
        Http3StreamState::ReadFinished => break,
        _ => unreachable!(),
    }
}
```

The key observation is **the FSM stays inside this loop until either an event is produced or no more bytes are available** (`Http3Error::Done`). One outer `poll()` iteration drives the FSM through `FrameType → FramePayloadLen → FramePayload` for one frame, returns the resulting event, then the caller loops `poll()` again. The next `poll()` re-enters the FSM at `FrameType` for the next frame on the same readable stream. **This means there is one FFI `stream_read()` per FSM state per `poll()`, not per frame.** See §1.6 / §1.7.

### 1.6 `parse_frame_type`, `parse_frame_payload_length` — varint slot fill

`tquic/src/h3/stream.rs:336-360`:

```rust
pub fn parse_frame_type(&mut self, conn: &mut crate::Connection) -> Result<()> {
    let frame_type = self.read_and_parse_varint(conn)?;
    match self.set_frame_type(frame_type) { ... }
    Ok(())
}
```

`read_and_parse_varint` (`stream.rs:477-494`):

```rust
fn read_and_parse_varint(&mut self, conn: &mut crate::Connection) -> Result<u64> {
    self.read_and_fill_buffer(conn)?;
    match self.state.parse_varint() {
        Ok(v) => Ok(v),
        Err(Http3Error::Done) => {
            // The length of varint is initially unknown and can only be determined in
            // `self.state.parse_varint()`. For this case, we should try to refill and parse again.
            self.read_and_fill_buffer(conn)?;
            let varint = self.state.parse_varint()?;
            Ok(varint)
        }
        Err(e) => Err(e),
    }
}
```

So a single varint may cost **up to two `stream_read` FFI calls** (one to learn length, one to fill remaining bytes).

### 1.7 `read_and_fill_buffer` — the only place TQUIC calls `stream_read`

`tquic/src/h3/stream.rs:426-474`:

```rust
fn read_and_fill_buffer(&mut self, conn: &mut crate::Connection) -> Result<()> {
    if self.state.ready() { return Ok(()); }
    let buf = &mut self.state.buf[self.state.write_off..self.state.expected_len];
    let read = match conn.stream_read(self.stream_id, buf) {
        Ok((len, _)) => len,
        Err(e) => { ... return Err(e.into()); }
    };
    self.state.increase_off(read);
    if !self.state.ready() {
        self.reset_data_event_state();
        return Err(Http3Error::Done);
    }
    Ok(())
}
```

This is the ONLY FFI recv into the H3 layer. The buffer is a **slot in the FSM's `Http3StateMachine.buf: Vec<u8>` sized to exactly `expected_len - write_off`** (`stream.rs:433`). No copy from a separate accumulator — bytes go straight from the QUIC recv-buffer (per-stream `RecvBuf`) into the H3 FSM's slot.

### 1.8 `parse_frame_payload` — decode + state reset

`tquic/src/h3/stream.rs:497-521`:

```rust
fn parse_frame_payload_inner(&mut self, conn: &mut crate::Connection) -> Result<(frame::Http3Frame, u64)> {
    self.read_and_fill_buffer(conn)?;
    self.reset_data_event_state();
    let payload_len = self.state.expected_len as u64;
    let frame = frame::Http3Frame::decode_payload(
        self.frame_type.unwrap(),
        payload_len,
        &self.state.buf,
    )?;
    self.transition_state(Http3StreamState::FrameType, 1, true)?;
    Ok((frame, payload_len))
}
```

`Http3Frame::decode_payload` is at `tquic/src/h3/frame.rs:202-243`. For HEADERS it just `buf.read(payload_length)` — i.e. **`Vec<u8>::extend_from_slice` of the QPACK header block, no QPACK work yet** (`frame.rs:212-214`).

### 1.9 `process_frame` — frame fan-out

`tquic/src/h3/connection.rs:1423-1515` matches on `Http3Frame` enum and delegates. For HEADERS:

```rust
frame::Http3Frame::Headers { field_section } => {
    return self.on_headers_frame_received(conn, stream_id, field_section);
}
```

(`connection.rs:1456-1458`)

### 1.10 `on_headers_frame_received` — QPACK decode site

`tquic/src/h3/connection.rs:1110-1146`:

```rust
fn on_headers_frame_received(&mut self, conn: &mut Connection, stream_id: u64, field_section: Vec<u8>)
    -> Result<(u64, Http3Event)> {
    let max_field_section_size = self.local_settings.max_field_section_size.unwrap_or(u64::MAX);
    let headers = match self.qpack_decoder.decode(&field_section[..], max_field_section_size) {
        Ok(v) => v.0,
        Err(e) => { ... return Err(e); }
    };
    let headers_event = Http3Event::Headers { headers, fin: conn.stream_finished(stream_id) };
    Ok((stream_id, headers_event))
}
```

`qpack_decoder.decode()` is `tquic/src/h3/qpack/qpack.rs:220` — pure in-memory decode of one header block.

### 1.11 Handler dispatch — back to `process_streams`

The event flows up `parse_frame_payload → process_frame → on_headers_frame_received → process_readable_request_stream` (returns `Ok(ev)`) → `process_readable_streams` (returns `Ok(ev)`) → `poll` → `process_streams` which calls `handler.on_stream_headers(stream_id, ...)`.

### TQUIC call graph summary

```
process_streams                                  connection.rs:1998
└── poll                                         connection.rs:1960
    ├── process_critical_streams                 connection.rs:1893
    │   └── process_readable_uni_stream          connection.rs:1692
    └── process_readable_streams                 connection.rs:1914
        └── for sid in conn.stream_readable_iter():
            └── process_readable_stream          connection.rs:1803
                └── process_readable_request_stream  connection.rs:1740 ← FSM LOOP
                    ├── stream.parse_frame_type           stream.rs:336
                    │   └── read_and_parse_varint         stream.rs:477
                    │       └── read_and_fill_buffer      stream.rs:426  ← FFI conn.stream_read
                    │       └── state.parse_varint        stream.rs:792
                    ├── stream.parse_frame_payload_length stream.rs:400
                    └── stream.parse_frame_payload        stream.rs:524
                        └── parse_frame_payload_inner     stream.rs:497
                            ├── read_and_fill_buffer      stream.rs:426  ← FFI conn.stream_read (payload)
                            └── frame::decode_payload     frame.rs:202
                        process_frame                     connection.rs:1423
                        └── on_headers_frame_received     connection.rs:1110
                            └── qpack_decoder.decode      qpack/qpack.rs:220
```

---

## 2. quiche trace — QUIC stream-readable → H3 frame parse → handler dispatch

quiche's structure is **functionally identical** to TQUIC's (TQUIC was forked off quiche). Same FSM, same `state_buf` design, same `poll → process_readable_stream → try_fill_buffer → try_consume_frame → process_frame` pipeline.

### 2.1 Caller pattern

`quiche-apps/common.rs:1406-1421` (`/tmp/quiche-research/quiche-common.rs`):

```rust
fn handle_requests(&mut self, conn: &mut quiche::Connection, ...) -> quiche::h3::Result<()> {
    loop {
        match self.h3_conn.poll(conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                ...
            }
            Ok((stream_id, quiche::h3::Event::Data)) => { ... }
            ...
        }
    }
}
```

Same outer loop pattern as TQUIC's `process_streams`. quiche does NOT register a callback — caller drives `poll()` themselves.

### 2.2 `Connection::poll`

`quiche/src/h3/mod.rs:2058-2148`:

```rust
pub fn poll<F: BufFactory>(&mut self, conn: &mut super::Connection<F>) -> Result<(u64, Event)> {
    if conn.local_error.is_some() { return Err(Error::Done); }

    if let Some(stream_id) = self.peer_control_stream_id {
        match self.process_control_stream(conn, stream_id) { ... }
    }
    if let Some(stream_id) = self.peer_qpack_streams.encoder_stream_id { ... }
    if let Some(stream_id) = self.peer_qpack_streams.decoder_stream_id { ... }

    if let Some(finished) = self.finished_streams.pop_front() {
        return Ok((finished, Event::Finished));
    }

    for s in conn.readable() {
        trace!("{} stream id {} is readable", conn.trace_id(), s);
        let ev = match self.process_readable_stream(conn, s, true) { ... };
        if conn.stream_finished(s) { self.process_finished_stream(s); }
        if let Some(ev) = ev { return Ok(ev); }
    }

    if let Some(finished) = self.finished_streams.pop_front() {
        ...
        return Ok((finished, Event::Finished));
    }
    Err(Error::Done)
}
```

`conn.readable()` returns an iterator of stream IDs marked readable (per-connection set, just like TQUIC's `stream_readable_iter`).

### 2.3 `process_readable_stream` — FSM driver

`quiche/src/h3/mod.rs:2548-2871` is one huge `while let Some(stream) = self.streams.get_mut(&stream_id) { match stream.state() { ... } }`. Same shape as TQUIC `process_readable_request_stream` but unifies uni + bidi in one function. The relevant `FrameType / FramePayloadLen / FramePayload / Data` arms (`mod.rs:2701-2829`):

```rust
stream::State::FrameType => {
    stream.try_fill_buffer(conn)?;
    let varint = match stream.try_consume_varint() { Ok(v) => v, Err(_) => continue };
    match stream.set_frame_type(varint) { ... }
}
stream::State::FramePayloadLen => {
    stream.try_fill_buffer(conn)?;
    let payload_len = match stream.try_consume_varint() { Ok(v) => v, Err(_) => continue };
    if Some(frame::DATA_FRAME_TYPE_ID) == stream.frame_type() {
        trace!("{} rx frm DATA stream={} wire_payload_len={}", ...);
        qlog_with_type!(QLOG_FRAME_PARSED, conn.qlog, q, { ... });
    }
    if let Err(e) = stream.set_frame_payload_len(payload_len) { ... }
}
stream::State::FramePayload => {
    if !polling { break; }
    stream.try_fill_buffer(conn)?;
    let (frame, payload_len) = match stream.try_consume_frame() { ... };
    match self.process_frame(conn, stream_id, frame, payload_len) {
        Ok(ev) => return Ok(ev),
        Err(Error::Done) => { if conn.stream_finished(stream_id) { break; } }
        Err(e) => return Err(e),
    };
}
stream::State::Data => {
    if !polling { break; }
    if !stream.try_trigger_data_event() { break; }
    return Ok((stream_id, Event::Data));
}
```

### 2.4 `try_fill_buffer` — FFI recv site

`quiche/src/h3/stream.rs:442-509`:

```rust
pub fn try_fill_buffer<F: BufFactory>(&mut self, conn: &mut crate::Connection<F>) -> Result<()> {
    if self.state_buffer_complete() { return Ok(()); }
    let buf = &mut self.state_buf[self.state_off..self.state_len];
    let read = match conn.stream_recv(self.id, buf) {
        Ok((len, fin)) => { ... len }
        Err(e @ crate::Error::StreamReset(_)) => { ... return Err(e.into()); }
        Err(e) => { if e == crate::Error::Done { self.reset_data_event(); } return Err(e.into()); }
    };
    self.state_off += read;
    if !self.state_buffer_complete() { self.reset_data_event(); return Err(Error::Done); }
    Ok(())
}
```

Same shape as TQUIC `read_and_fill_buffer`. The state buffer is `state_buf: Vec<u8>` (`stream.rs:134`, initial cap 16 — `stream.rs:197`).

### 2.5 `try_consume_varint`, `try_consume_frame`

`quiche/src/h3/stream.rs:565-602`:

```rust
pub fn try_consume_varint(&mut self) -> Result<u64> {
    if self.state_off == 1 {
        self.state_len = octets::varint_parse_len(self.state_buf[0]);
        self.state_buf.resize(self.state_len, 0);
    }
    if !self.state_buffer_complete() { return Err(Error::Done); }
    let varint = octets::Octets::with_slice(&self.state_buf).get_varint()?;
    Ok(varint)
}

pub fn try_consume_frame(&mut self) -> Result<(frame::Frame, u64)> {
    debug_assert_eq!(self.state, State::FramePayload);
    self.reset_data_event();
    let payload_len = self.state_len as u64;
    let frame = frame::Frame::from_bytes(self.frame_type.unwrap(), payload_len, &self.state_buf)?;
    self.state_transition(State::FrameType, 1, true)?;
    Ok((frame, payload_len))
}
```

Identical to TQUIC.

### 2.6 `Frame::from_bytes` — frame decode

`quiche/src/h3/frame.rs:107-151`:

```rust
pub fn from_bytes(frame_type: u64, payload_length: u64, bytes: &[u8]) -> Result<Frame> {
    let mut b = octets::Octets::with_slice(bytes);
    let frame = match frame_type {
        DATA_FRAME_TYPE_ID => Frame::Data { payload: b.get_bytes(payload_length as usize)?.to_vec() },
        HEADERS_FRAME_TYPE_ID => Frame::Headers { header_block: b.get_bytes(payload_length as usize)?.to_vec() },
        ...
    };
    Ok(frame)
}
```

`b.get_bytes(...)?.to_vec()` is the same `Vec` allocation as TQUIC.

### 2.7 `process_frame` → QPACK decode

`quiche/src/h3/mod.rs:2895-2997`:

```rust
fn process_frame<F: BufFactory>(&mut self, conn: &mut super::Connection<F>, stream_id: u64,
    frame: frame::Frame, payload_len: u64) -> Result<(u64, Event)> {
    trace!("{} rx frm {:?} stream={} payload_len={}", conn.trace_id(), frame, stream_id, payload_len);
    qlog_with_type!(QLOG_FRAME_PARSED, conn.qlog, q, { ... });
    match frame {
        ...
        frame::Frame::Headers { header_block } => {
            ...
            let headers = match self.qpack_decoder.decode(&header_block[..], max_size) {
                Ok(v) => v,
                Err(e) => { ... return Err(e); }
            };
            ...
            return Ok((stream_id, Event::Headers { list: headers, more_frames: ... }));
        }
        ...
    }
}
```

`qpack_decoder.decode` is at `quiche/src/h3/qpack/decoder.rs:85`.

### quiche call graph summary

```
caller_loop { h3_conn.poll(conn) }                quiche-apps/common.rs:1416
└── poll                                          mod.rs:2058
    ├── process_control_stream (peer_control)
    ├── process_control_stream (peer_qpack_enc)
    ├── process_control_stream (peer_qpack_dec)
    └── for s in conn.readable():                  ← QUIC readable-set iter
        └── process_readable_stream                mod.rs:2548 ← FSM LOOP (uni+bidi unified)
            match stream.state():
            ├── FrameType:
            │   ├── stream.try_fill_buffer         stream.rs:442  ← FFI conn.stream_recv
            │   └── stream.try_consume_varint      stream.rs:565
            ├── FramePayloadLen:
            │   ├── stream.try_fill_buffer         stream.rs:442  ← FFI conn.stream_recv
            │   └── stream.try_consume_varint      stream.rs:565
            └── FramePayload:
                ├── stream.try_fill_buffer         stream.rs:442  ← FFI conn.stream_recv (payload)
                ├── stream.try_consume_frame       stream.rs:585
                │   └── Frame::from_bytes          frame.rs:107
                └── process_frame                  mod.rs:2895
                    └── qpack_decoder.decode       qpack/decoder.rs:85
                    return Event::Headers
```

---

## 3. Buffer data-structure comparison

### Per-H3-stream parse buffer (the "accumulator" mojo-net's `_H3StreamBuf.buf` corresponds to)

| Stack | Type | "Consume N from front" | Allocation behaviour |
|---|---|---|---|
| **TQUIC** | `Http3StateMachine { buf: Vec<u8>, expected_len, write_off }` (`stream.rs:721-736`) | **Never consumes incrementally.** Buffer is exactly `expected_len` bytes. After `parse_frame_payload` succeeds, `transition_state(FrameType, 1, true)` resets `write_off=0, expected_len=1` and `buf.resize(1, 0)` (`stream.rs:766-789`). | `vec![0; INIT_STATE_BUF_SIZE]` (typically 16) at construction; `buf.resize(new_len, 0)` per state transition (`stream.rs:781`). One realloc per state-machine transition; the buffer stays alive between frames but is shrunk back to length 1 after each frame. |
| **quiche** | `Stream { state_buf: Vec<u8>, state_len, state_off }` (`stream.rs:134-142`) | Same pattern: never consumes. After `try_consume_frame` calls `state_transition(State::FrameType, 1, true)` which `state_buf.resize(1, 0)` (`stream.rs:599`, transition impl reuses `Vec::resize`). | `vec![0; 16]` initial (`stream.rs:197`); `state_buf.resize(state_len, 0)` per state transition. |
| **mojo-net** | `_H3StreamBuf.buf: List[UInt8]` (one List per stream, kept in `self._stream_bufs: Dict[Int, _H3StreamBuf]`) | **Linear copy-and-shift.** After parsing a frame, `connection.mojo:493-497` builds a fresh `List[UInt8]` containing bytes `[consumed..len(buf))` and replaces `sbuf.buf`. Every parsed frame allocates a new List sized to the residual. | New List per `_drain_stream` invocation (`new_bytes.copy()` at `:413`); per-byte append loop `:418-419`; per-frame realloc `:494-497`. |

### Underlying QUIC transport recv-buffer (one layer down — common to all three)

| Stack | Type | Consume-front mechanism |
|---|---|---|
| TQUIC | `RecvBuf { data: BTreeMap<u64, RangeBuf>, read_off, ... }` (`tquic/src/connection/stream.rs:1998-2025`). `RangeBuf { data: Bytes, off, len, ... }` (`:2881-2965`). | `RecvBuf::read` (`:2164-2213`) walks `data.first_entry()` and either `buf.consume(buf_len)` (in-place range advance) or `entry.remove()` when fully drained. Uses `bytes::Bytes` reference-counted slices so consuming is just a pointer/length update. |
| quiche | `RecvBuf { data: BTreeMap<u64, RangeBuf>, off, ... }` (`quiche/src/stream/recv_buf.rs:50-58`). Same `RangeBuf`-of-`Bytes` pattern. | `RecvBuf::emit_or_discard` (`:230-292`) — same pattern: `entry.get_mut().consume(buf_len)` or `entry.remove()`. |
| mojo-net | `_quic.recv_stream_data(sid)` returns a fresh `Tuple[List[UInt8], Bool]` per call (see `connection.mojo:412`). | The mojo-net layer **copies bytes out of TQUIC's RangeBuf into a List** at the FFI boundary, then **copies again** from `recv_result[0]` into `sbuf.buf` via the loop `:418-419`. Two copies per stream-readable event before any frame parsing happens. |

**Headline structural difference:** TQUIC and quiche both **size the parse buffer to exactly the bytes-needed-for-the-next-FSM-state** and write directly into that slot from QUIC's recv-buf. They never concatenate-then-slice; the buffer IS the working set. mojo-net's design accumulates an unbounded prefix and rebuilds the residual every frame.

### "Consume N from front" — direct comparison

- **TQUIC / quiche:** N/A. The buffer is never larger than what the current FSM state needs. After `transition_state(..., new_len=1, resize=true)`, the buffer is one byte. The FSM amortises away "consume" by sizing to demand.
- **mojo-net:** `for i in range(consumed, len(sbuf.buf)): new_buf.append(sbuf.buf[i])` (`connection.mojo:495-496`) — O(residual) per frame. With pipelined HEADERS+DATA, this is the dominant residual-shift cost.

---

## 4. QPACK invocation pattern

| Stack | Pattern | Cite |
|---|---|---|
| TQUIC | **Per-HEADERS-frame.** `qpack_decoder.decode(&field_section[..], max_size)` is called from `on_headers_frame_received` (`connection.rs:1122-1124`) which is reached via `process_frame` (`:1457`) which is reached via `parse_frame_payload` (`:1765`). One frame in → one decode call → one `Vec<Header>` out → one `Http3Event::Headers` returned. No batching across frames. | `connection.rs:1110-1146`, `qpack/qpack.rs:220-323` |
| quiche | **Per-HEADERS-frame.** Same shape: `process_frame` matches `Frame::Headers { header_block }` and calls `self.qpack_decoder.decode(&header_block[..], max_size)`, returns `Event::Headers { list, more_frames }`. | `mod.rs:2957-3035`, `qpack/decoder.rs:85` |
| mojo-net | **Per-HEADERS-frame.** `_handle_request_frame` (`connection.mojo:536-554`) calls `self._dec.decode(frame.payload)` per HEADERS frame. Same pattern. | `connection.mojo:536-554` |

**Conclusion:** all three stacks invoke QPACK exactly once per HEADERS frame. The QPACK decoder is stateless for static-table-only requests (TQUIC `qpack/qpack.rs:235-323` returns errors for any dynamic-table reference at lines 247, 261, 280, 293 — TQUIC literally does not implement QPACK dynamic table). quiche's decoder has an identical "TODO: implement dynamic table" gap (`qpack-decoder.rs:109-112, 124-129`).

The **per-frame cost** in TQUIC/quiche is therefore: one `decode_int(buf, 8)` (req_insert_count), one `decode_int(buf, 7)` (base), then a loop over a few-byte indexed/literal entries — sub-microsecond for typical 5-10 header requests.

---

## 5. Maintainer-named cost centers

What TQUIC and quiche maintainers consider "worth naming" — i.e. the cost-buckets they instrument and report.

### 5.1 TQUIC's `ConnectionStats`

`tquic/src/connection/connection.rs:4185-4203`:

```rust
pub struct ConnectionStats {
    pub recv_count: u64,
    pub recv_bytes: u64,
    pub sent_count: u64,
    pub sent_bytes: u64,
    pub lost_count: u64,
    pub lost_bytes: u64,
}
```

That is the total stats surface. **TQUIC does not name H3-frame-parse, QPACK-decode, or stream-buffer cost as separate centres.** Its only timing instrumentation is `Instant::now()` calls in:

- congestion control (`bbr.rs:215, 326, 368`, `cubic.rs:569, 634, 706`, `copa.rs:196`)
- timer queue (`timer_queue.rs:104, 122, 140, 168`)
- path RTT (`path.rs:200, 753, 854, 911`)
- flow control (`flowcontrol.rs:187, 195`)

Grep result for `Instant::now|tracing::span|tracing::instrument|profile|metric|StatsCollect`: zero matches in `src/h3/` — **no timing instrumentation in the H3 path at all.** The H3 layer is logged only via `trace!`/`info!` (e.g. `h3/connection.rs:1916, 1930` "stream readable", "stream finished").

The TQUIC bench dir (`benches/timer_queue.rs`) has only timer-heap benchmarks; no H3 path bench. TQUIC's perf bench is the `interop/` tools exercising the wire protocol end-to-end, not internal phases.

### 5.2 quiche's `h3::Stats`

`quiche/src/h3/mod.rs:927-933`:

```rust
pub struct Stats {
    /// The number of bytes received on the QPACK encoder stream.
    pub qpack_encoder_stream_recv_bytes: u64,
    /// The number of bytes received on the QPACK decoder stream.
    pub qpack_decoder_stream_recv_bytes: u64,
}
```

That is the entire H3-level stats surface — **no per-phase timings, only QPACK byte volumes on the encoder/decoder streams.**

### 5.3 quiche's qlog instrumentation

quiche emits qlog events at four named points in the H3 receive path:

- `QLOG_FRAME_PARSED` — fired after a non-HEADERS frame is decoded (`mod.rs:2756-2767` for DATA, `mod.rs:2907-2920` for general, `mod.rs:2999-3025` for HEADERS).
- `QLOG_FRAME_CREATED` — fired after a frame is encoded for sending.
- `QLOG_STREAM_TYPE_SET` — fired after a uni-stream type is decoded (`mod.rs:2577-2594`).
- `QLOG_PARAMETERS_SET` (referenced earlier in mod.rs) — for SETTINGS.

These are the qlog draft-ietf-quic-qlog-h3-events event names — **the protocol-level analyst's vocabulary**, not the implementor's hot-path. They tell us what observers want to correlate, not what costs MaintainerX cares about.

### 5.4 quiche commit history — what gets perf attention

`gh api repos/cloudflare/quiche/commits?path=quiche/src/h3/mod.rs --per_page=15` recent titles:

```
f4c3552 Fix spurious STREAM_DATA_BLOCKED frames
6ea26ca Retry transient request start errors in the tokio-quiche H3 client
8485903 qlog: fixup Http3Frame alignment to draft-ietf-quic-qlog-h3-events-12
b60449c remove usage of buffer-pool, support bytes::BufMut in quiche
339a782 qlog: update to latest drafts
b9d4b9f qlog: remove H3 prefix from HTTP/3 event types
5caead8 qlog: rename h3 module to http3
da5e00c quiche testutils: ...
7a958f9 chore: refactor quiche::BufFactory into new file. Add debug_asserts in h3
9ad2365 tests: ensure test-related items have #[cfg(test)]
862ab1a Add stats for DATA_BLOCKED and STREAM_DATA_BLOCKED frames sent and received
579d12f Actually increment dgram_recv_count and dgram_sent_count
0a0d3bd fix: proper connection flow control updates with STOP_SENDING and RESET_STREAM
```

**The single perf-related commit is `b60449c remove usage of buffer-pool, support bytes::BufMut in quiche`.** That tells us: the cost center quiche maintainers actually addressed in the H3 layer over the last ~30 commits is **the recv-buffer abstraction and zero-copy hand-off via `BufFactory<F>`/`bytes::BufMut`** — not QPACK, not frame-parse, not FSM state.

`grep "BufFactory\|bytes::BufMut" /tmp/quiche-research/stream.rs` confirms: `try_consume_data` (`stream.rs:605`) takes `OUT: bytes::BufMut` and uses `conn.stream_recv_buf` (a zero-copy variant) — quiche's body-data path can hand callers a `Bytes` slice directly without copying through the application's buffer. **They do NOT do this for the FSM state buffer; that's still a `Vec<u8>`.** The framing FSM was deemed cheap enough that BufFactory was applied only to body data.

### 5.5 TQUIC commit history

```
de47c00 Update tquic-benchmark.yml
d4eeab9 Add pacing to smooth the flow of packets sent onto the network
bb0ba1d Tweak flow control
fbe56f4 Remove the `sfv` feature flag from h3
c0dfdf5 Fix typos in code comments
1e42fd5 Rename error functions for clarity
fd20849 Add more unit tests
3928ff6 Optimize the stream frame write method (merge request !127)
2b548d2 Add quic stream and h3 modules
166239f Initial commit for tquic
```

**One perf commit in the H3 module's history: `3928ff6 Optimize the stream frame write method` — and that's send-side, not the recv path under investigation.** TQUIC's H3 read path has not been perf-touched since the initial fork.

### 5.6 quiche/h3 AGENTS.md — what they tell new contributors matters

`/tmp/quiche-research/AGENTS.md` (reproduced from `gh api repos/cloudflare/quiche/contents/quiche/src/h3/AGENTS.md`):

```
## STRUCTURE

mod.rs       (7549 lines)  H3 Connection, Config, Error, Event, Header, NameValue, Priority
stream.rs    (1565)        H3 stream state machine (Type, State enums; frame parsing FSM)
frame.rs     (1337)        H3 frame encode/decode (Frame enum, settings constants)

## WHERE TO LOOK
| H3 stream lifecycle | stream.rs — Stream struct, State FSM |
| Frame wire format   | frame.rs — Frame enum, encode()/decode() |
| QPACK header compression | qpack/encoder.rs, qpack/decoder.rs |

## NOTES
- Methods are generic over F: BufFactory (zero-copy) ...
- stream.rs Stream ≠ quiche::stream::Stream. H3 stream is a frame-parsing state machine layered on top.
```

The maintainer-curated mental model is **(stream-state-FSM | frame-codec | qpack-codec)** as the three independent things. No mention of "stream buffer accumulation" because in their design there is none — the FSM IS the accumulator.

### 5.7 So what cost centres do they actually name?

There is no published TQUIC or quiche bench harness measuring sub-phases of the H3 read path. Both treat it as a single "process_readable_stream" arena. The only sub-divisions surfaced in API or qlog are:

- **per-stream-type-decode** (uni stream type byte, only happens once per uni stream — `STREAM_TYPE_SET` qlog event)
- **per-frame-parsed** (QPACK or transport bytes consumed — `FRAME_PARSED` qlog event, fires AFTER full parse including QPACK decode)
- **per-event-emitted** (Headers/Data/Finished — application-visible)

**Implication for mojo-net:** if we want a sub-leg taxonomy that is "the smallest decomposition that matches reference-stack vocabulary", the references give us only **(frame-parsed-event-boundary)** as a named hook. Anything finer is novel and we should keep it because mojo-net's hot path differs structurally (see §6 + §7).

---

## 6. Recommended sub-leg taxonomy for mojo-net

Map cleanly onto both reference stacks where structure aligns; flag explicitly where mojo-net has no analogue.

| Sub-leg | What it covers in mojo-net | TQUIC analogue | quiche analogue | Notes |
|---|---|---|---|---|
| **`recv_ffi`** | `self._quic.recv_stream_data(stream_id)` at `connection.mojo:412` — the FFI call into TQUIC's `RecvBuf::read` returning a `Tuple[List[UInt8], Bool]`. | `conn.stream_read` (`stream.rs:435`) → `RecvBuf::read` (`connection/stream.rs:2164`). Single FFI call. | `conn.stream_recv` (`stream.rs:452`) → `RecvBuf::emit` (`recv_buf.rs:212`). Single FFI call. | Timing this isolates the QUIC-layer dequeue cost (BTreeMap walk + Bytes consume in TQUIC) from any H3 work. Direct apples-to-apples vs. reference stacks. |
| **`buf_accumulate`** | The two copies in `_drain_stream` after `recv_stream_data` returns: `new_bytes = recv_result[0].copy()` (`:413`) + the per-byte `for i in range(len(new_bytes)): sbuf.buf.append(...)` loop (`:418-419`) + the residual rebuild loop in `_parse_frames_from_buf` (`:494-497`). | **NO ANALOGUE.** TQUIC writes from `conn.stream_read` directly into the FSM's `state.buf` slot with no intermediate accumulator (`stream.rs:433`). Always zero. | **NO ANALOGUE.** Same as TQUIC — `conn.stream_recv` writes into `state_buf[state_off..state_len]` (`stream.rs:450-452`). Always zero. | Naming this lets us quantify **the architectural gap** between mojo-net and reference stacks. If `buf_accumulate >> 0` and dominates, the optimisation is "remove the accumulator" not "speed up the accumulator". |
| **`frame_parse`** | `parse_h3_frame(r)` (`connection.mojo:486`) — varint frame_type + varint payload_len + payload slice. | `parse_frame_type` + `parse_frame_payload_length` + `parse_frame_payload`/`Http3Frame::decode_payload` (`stream.rs:336/400/524`, `frame.rs:202`). | `try_consume_varint`×2 + `try_consume_frame`/`Frame::from_bytes` (`stream.rs:565/585`, `frame.rs:107`). | Direct match. The cost should be very small — mostly varint decode + a Vec allocation for the HEADERS field-section. |
| **`qpack_decode`** | `self._dec.decode(frame.payload)` in `_handle_request_frame` (around `connection.mojo:536-554`). | `qpack_decoder.decode` (`connection.rs:1122` calling `qpack/qpack.rs:220`). | `qpack_decoder.decode` (`mod.rs:2980` calling `qpack/decoder.rs:85`). | Per-HEADERS-frame. Reference stacks call it once per HEADERS event. Static-table-only in both reference QPACK decoders. |
| **`event_dispatch`** | `self._h3_events.append(...)` in `_handle_request_frame` + the outer `feed_datagram_from_buffer` loop's `if ev.type_id == ...` matching (`connection.mojo:286-312`). | `process_frame` match arms (`connection.rs:1438-1512`) + handler invocation in `process_streams` (`connection.rs:2008-2047`). | `process_frame` match (`mod.rs:2922-...`) + caller's `match h3_conn.poll(conn)` (`quiche-common.rs:1417`). | The `Http3Event` construction and append/return path. Should be small but non-zero. |

**5 sub-legs is tight.** If we want 4, fold `event_dispatch` into `qpack_decode` for HEADERS-dominated workloads (since most events come straight after QPACK in the call graph) and keep `recv_ffi`/`buf_accumulate`/`frame_parse` as standalone.

If we want 6, split `frame_parse` into `frame_parse_varints` (the two varint reads — exactly TQUIC's `parse_frame_type` + `parse_frame_payload_length` boundary) and `frame_parse_payload` (the `Vec`-copy of the HEADERS field-section in `frame::decode_payload`). This is the natural seam in the reference FSMs.

### Mojo-net stages with no reference-stack analogue

- **`buf_accumulate`** — discussed above. Reference stacks have no separate accumulator; `state_buf` IS the working set sized to demand.
- **`recv_stream_data`'s tuple return cost** — TQUIC's `stream_read` writes to a caller-provided `&mut [u8]` slice. mojo-net's `recv_stream_data` returns `Tuple[List[UInt8], Bool]`, requiring a heap allocation per FFI call. Naming this as part of `recv_ffi` is fine; just be aware the cost is ~2× a reference `stream_read` because of the extra allocation.

---

## 7. Surprises / contradictions

### S1. TQUIC and quiche do not separately measure any sub-phase of the H3 read path

The expected payoff of "name the dominant phase" is undermined by the fact that **neither reference stack does this themselves.** Their published stats (`ConnectionStats`, `h3::Stats`) are byte counters, not timing buckets. Their qlog is event-boundary-named, not phase-cost-named. Their bench dirs cover only narrow primitives (timer-heap; not H3 read).

This means the sub-leg taxonomy mojo-net is about to define is **net-new vocabulary, not "mirror the references' vocabulary"**, because the references have none. The mirror is structural (FSM stages match) not nominal (timers don't exist).

### S2. The reference stacks' design eliminates `buf_accumulate` by construction

Both TQUIC and quiche size the parse buffer to **exactly the bytes required by the next FSM state.** When they read from QUIC, they read into that pre-sized slot. There is no concept of an unbounded prefix that gets sliced as frames are parsed — the state buffer transitions through `len=1` (varint length probe) → `len=N` (varint payload) → `len=payload_len` (frame payload) → `len=1` (next varint) and so on. `Vec::resize` is the only memory op per state transition.

mojo-net's design — `_H3StreamBuf.buf` as an unbounded `List[UInt8]` that grows on every readable event and gets sliced after every frame — has no reference analogue and IS the architectural gap. The dominant cost in `_drain_stream`/`_parse_frames_from_buf` plausibly lives in:

1. The per-byte append loop `connection.mojo:418-419` (O(new_bytes) per readable event, with `List.append` overhead per element).
2. The residual rebuild loop `:494-497` (O(residual) per frame parsed).
3. The `recv_result[0].copy()` at `:413` (extra allocation+copy of FFI return).

None of these have a counterpart in TQUIC or quiche, so the diagnostic naming exercise is essentially: **measure how much mojo-net spends on cost centres that don't exist in the references at all.**

### S3. TQUIC and quiche agree on EVERY structural decision in this path

The two stacks' FSMs are byte-for-byte mirrors:

- Same `state_buf: Vec<u8>` field name family (`state_buf`/`state_len`/`state_off` in quiche; `buf`/`expected_len`/`write_off` in TQUIC's `Http3StateMachine`).
- Same `try_fill_buffer` / `read_and_fill_buffer` shape — read into `buf[off..len]`, advance off.
- Same `try_consume_varint` shape — probe length, resize, parse.
- Same `try_consume_frame` / `parse_frame_payload_inner` shape — call frame::from_bytes/decode_payload, transition to FrameType, resize to 1.
- Same `process_frame` enum match → per-frame handler function.
- Same QPACK decoder invocation (per-HEADERS-frame, `decode(buf, max_size) -> Vec<Header>`).
- Same outer `for stream_id in conn.readable()` driving loop.

The only material divergence is that TQUIC splits `process_readable_stream` into `process_readable_request_stream` (`connection.rs:1740`) + `process_readable_uni_stream` (`connection.rs:1692`) + `process_readable_push_stream` (`connection.rs:1538`) + `process_readable_control_stream` (`connection.rs:1601`) by stream type, whereas quiche unifies all four into one giant `match stream.state()` block in `process_readable_stream` (`mod.rs:2548-2871`). Functionally equivalent.

### S4. Recv batching is per-stream-readable, not packet-batched

Both stacks process **one stream at a time**: `for s in conn.readable() { process_readable_stream(s) }`. Within `process_readable_stream`, each FSM state issues exactly one `stream_read`/`stream_recv` FFI call into the QUIC layer (or two in the varint case where the length must be probed first — `stream.rs:484-491`). There is no "drain all streams' bytes in one syscall" optimisation at the H3 layer.

The UDP socket recv loop IS batched (one `recv_from` per packet, looped until `WouldBlock` — `tquic-server.rs:321-355`, `quiche-server.rs:181-263`), but that is below the QUIC `endpoint.recv` boundary, which is itself below the H3 layer. The H3 sees one `for s in conn.readable()` pass per `poll()`, and one `poll()` is called per UDP-receive batch in the typical event loop.

mojo-net's `feed_datagram_from_buffer` (`connection.mojo:259-317`) does the same: one datagram in, then drain all `STREAM_READABLE` events from the resulting `_quic.poll()` queue. This is structurally identical to the references.

### S5. TQUIC has a maintainer-named perf gap — `// TODO: support recvmmsg`

`tquic-server.rs:324` has `// TODO: support recvmmsg`. This is the only perf-TODO in the recv path the maintainers have called out. mojo-net is at the same point (single `recv_from` per packet) — so on the UDP-batching axis, mojo-net is no worse than TQUIC's reference example.

### S6. quiche has zero-copy hand-off for body data, NOT for FSM-state framing

`quiche/src/h3/stream.rs:605-625` — `try_consume_data<F: BufFactory, OUT: bytes::BufMut>` lets the caller hand quiche a `BufMut` and have body bytes written directly into it without going through `state_buf`. **The framing path (varints, HEADERS field-section) does NOT have this — it always copies through `state_buf`.** quiche's maintainers, when given the choice of where to apply BufFactory zero-copy, picked body data and left framing alone. This implies they consider framing cost negligible relative to body throughput.

For mojo-net's long-conn / small-request workload (where every byte is framing/HEADERS, and DATA frames are minimal), this hint says **the architectural gap in `buf_accumulate` is precisely the place quiche doesn't bother optimising — because for them it's already a 1-resize-per-state operation, not a copy-and-shift.**

---

## Appendix A. File:line index for the sub-leg taxonomy

When mojo-net's diagnostic pass instruments these brackets, here are the corresponding TQUIC/quiche timing points to cite if comparing:

| mojo-net sub-leg | TQUIC bracket equivalent | quiche bracket equivalent |
|---|---|---|
| `recv_ffi` | between `read_and_fill_buffer` entry and exit, around `conn.stream_read` (`stream.rs:435`) | between `try_fill_buffer` entry and exit, around `conn.stream_recv` (`stream.rs:452`) |
| `buf_accumulate` | none — measure as 0 in TQUIC | none — measure as 0 in quiche |
| `frame_parse` | from `parse_frame_type` start (`stream.rs:336`) to `parse_frame_payload_inner` decode_payload return (`stream.rs:520`) | from `State::FrameType` arm entry (`mod.rs:2701`) to `try_consume_frame` return (`stream.rs:601`) |
| `qpack_decode` | `qpack_decoder.decode` (`connection.rs:1122-1124`, into `qpack/qpack.rs:220-323`) | `qpack_decoder.decode` (`mod.rs:2979-2981`, into `qpack/decoder.rs:85-...`) |
| `event_dispatch` | `process_frame` match dispatch (`connection.rs:1438-1512`) + handler call in `process_streams` (`connection.rs:2008-2047`) | `process_frame` match dispatch (`mod.rs:2922-...`) + caller match in user code |

## Appendix B. Verbatim citations cross-check

- TQUIC `process_streams`: `tquic/src/h3/connection.rs:1998-2050`
- TQUIC `poll`: `tquic/src/h3/connection.rs:1960-1995`
- TQUIC `process_readable_streams`: `tquic/src/h3/connection.rs:1914-1948`
- TQUIC `process_readable_stream`: `tquic/src/h3/connection.rs:1803-1825`
- TQUIC `process_readable_request_stream` (FSM driver): `tquic/src/h3/connection.rs:1740-1797`
- TQUIC `process_frame`: `tquic/src/h3/connection.rs:1423-1515`
- TQUIC `on_headers_frame_received`: `tquic/src/h3/connection.rs:1110-1146`
- TQUIC `read_and_fill_buffer` (FFI recv): `tquic/src/h3/stream.rs:426-474`
- TQUIC `read_and_parse_varint`: `tquic/src/h3/stream.rs:477-494`
- TQUIC `parse_frame_payload_inner`: `tquic/src/h3/stream.rs:497-521`
- TQUIC `Http3StateMachine` (parse buffer): `tquic/src/h3/stream.rs:721-810`
- TQUIC `Http3Frame::decode_payload`: `tquic/src/h3/frame.rs:202-243`
- TQUIC `RecvBuf` (transport): `tquic/src/connection/stream.rs:1998-2025`, `RecvBuf::read`: `:2164-2213`
- TQUIC `ConnectionStats`: `tquic/src/connection/connection.rs:4185-4203`

- quiche `poll`: `quiche/src/h3/mod.rs:2058-2148`
- quiche `process_readable_stream`: `quiche/src/h3/mod.rs:2548-2871`
- quiche `process_frame`: `quiche/src/h3/mod.rs:2895-3035` (arms continue beyond)
- quiche `try_fill_buffer` (FFI recv): `quiche/src/h3/stream.rs:442-509`
- quiche `try_consume_varint`: `quiche/src/h3/stream.rs:565-580`
- quiche `try_consume_frame`: `quiche/src/h3/stream.rs:585-602`
- quiche `Stream` (parse buffer): `quiche/src/h3/stream.rs:120-220`
- quiche `Frame::from_bytes`: `quiche/src/h3/frame.rs:107-151`
- quiche `RecvBuf` (transport): `quiche/src/stream/recv_buf.rs:50-85`, `emit_or_discard`: `:230-292`
- quiche `h3::Stats`: `quiche/src/h3/mod.rs:927-933`
- quiche `qpack::Decoder::decode`: `quiche/src/h3/qpack/decoder.rs:85-...`
- quiche `qlog_with_type!` invocations in H3 read path: `mod.rs:2756, 2907, 2999`
- quiche AGENTS.md: `quiche/src/h3/AGENTS.md`

- mojo-net post-recv bracket: `src/h3/connection.mojo:259-317`
- mojo-net `_drain_stream`: `src/h3/connection.mojo:406-469`
- mojo-net `_parse_frames_from_buf`: `src/h3/connection.mojo:471-502`
- mojo-net residual rebuild: `src/h3/connection.mojo:494-497`
- mojo-net buf-accumulate copy loop: `src/h3/connection.mojo:413-419`
