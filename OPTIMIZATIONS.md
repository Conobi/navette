# Navette H1 plaintext: optimization opportunities to beat hyper

This document is a critical-path audit of the HTTP/1.1 plaintext lane (the
`bench/flare_compare` line that currently sits behind hyper). It is scoped
to the workload the bench actually measures — `GET /plaintext` →
`Hello, World!`, HTTP/1.1 keep-alive, single worker — and grades each
finding by likely impact and implementation cost.

## 1. Where we are vs. the target

Headline numbers from `bench/flare_compare/results/<latest>/summary.md`
(2026-05-22T1845):

| Server      | Req/s    | Median p99 (ms) | Gap to navette |
|-------------|---------:|----------------:|---------------:|
| nginx (C)   | 41,211   | 12.69           | +51%           |
| **hyper**   | **40,310** | **10.58**     | **+47%**       |
| actix-web   | 37,974   | 11.53           | +39%           |
| flare (Mojo)| 36,396   |  9.98           | +33%           |
| axum        | 36,351   | 10.49           | +33%           |
| navette     | 27,337   |  7.81           | —              |
| go-nethttp  | 23,966   | 11.77           | -12%           |

To close on hyper we need ~47% more throughput per worker. Flare runs the
same language at 36k r/s (+33%), so this is not a Mojo ceiling — most of
the gap is in the navette H1 hot path.

## 2. What the hot path actually does per request

Walking `bench/servers/h1_server.mojo` + `navette/h1/*` for a single
`GET /plaintext\r\nHost: ...\r\n\r\n` → `200 OK ... Hello, World!`:

1. **io_uring CQE** for `recv` (one-shot) on a per-connection 8 KiB heap buffer.
2. `_handle_recv` slices `recv_buf[0:n]` into a `Span` and calls
   `H1HandlerServer.feed(span)`.
3. `H1Connection.receive_data` **`extend`s** the span into `_inbound_buf`
   (one copy).
4. `try_parse_request` runs:
   - `_find_header_end` byte scan (OK, this is fine).
   - Request line: `_bytes_to_string(buf, cursor, sp1)` for method — see §3.1.
   - `_bytes_to_string` for target.
   - `_bytes_to_string` for version, then `version_str == "HTTP/1.1"` compare.
   - `_parse_headers`: for each header line, two more `_bytes_to_string`
     calls (name + value), each followed by `Headers.add(name, value)`
     which **runs `_to_lower(name)` building a third String**.
   - After the loop, `_parse_headers` re-iterates the parallel arrays and
     calls `headers.add(...)` *again* — re-running `_to_lower` a second
     time. That is two lowercasing passes per header per request.
   - Three more semantic-analysis passes (`_iequals` for `content-length`
     / `transfer-encoding` / `host`) over every header.
5. Body framing decision (no body for GET): allocates `List[UInt8]()` and
   wraps in `RequestBody.empty()`.
6. `Request` constructed.
7. `_compact_inbound` allocates a *fresh* `List[UInt8](capacity=keep)` and
   `extend`s into it, even when `keep == 0` — see §3.3.
8. `H1Connection._update_keep_alive` scans every header again with
   `_iequals("connection")` — 4th full headers scan.
9. Handler `BenchHandler.on_request` dispatches via `_starts_with` chain
   (`/plaintext`, `/baseline2`, `/baseline11`, `/json/`, `/static/`),
   each call re-getting `target.as_bytes()`.
10. `handle_plaintext` (bench/lib/handler.mojo:89): allocates
    `String("Hello, World!")`, allocates `Headers()`, runs `_to_lower`
    twice (`content-type`, `content-length`), formats Int→String for
    Content-Length, copies the body String into a `List[UInt8]`, wraps
    it in a `BodyFrame.data(...)`.
11. `H1HandlerServer._dispatch_one` rebuilds: `RecvBody()`, then a
    `body_frames` `List` it drains *one frame at a time* with
    `_pop_body_frame()`, then a `Response(...)`.
12. `H1Connection.send_response` → `serialize_response`:
    - Allocates a fresh `List[UInt8]()`.
    - Builds `_int_to_string(200)` via reversed-digits + `chr(...)` String
      build (§3.2).
    - Walks headers (2 entries), for each: `name.as_bytes()` extend,
      two-byte `: ` append, `value.as_bytes()` extend, two-byte CRLF
      append.
    - `_total_data_len` walks the body once; `_has_trailers` walks it
      again.
    - `_int_to_string(13)` (again) for Content-Length even though we
      already emitted it in the handler.
    - `_append_data_frames` walks the body a third time to extend the
      13 bytes.
13. `H1HandlerServer.drain()` `extend`s into `_outbuf`, then returns it.
14. h1_server `_stage_send` moves the `List` into `send_buf`.
15. `_drain_pending_submits` reads the pointer, submits `send`.
16. On send completion: `_handle_send` allocates a fresh
    `List[UInt8]()` for `send_buf`, queues the next recv.

That is **~15-20 heap allocations per request** just for parsing +
serializing a 13-byte response, plus 4 full passes over the request
header list and 3 over the response body list.

For comparison, hyper's plaintext path keeps the request headers as
`&[u8]` slices into a single reused `BytesMut`, the body is a
`Bytes::from_static(b"Hello, World!")` (zero alloc, refcount bump
only), and the response is encoded into the same reused writer
buffer with a `writev` of one or two iovecs.

## 3. Findings, ranked by impact / effort

Letter grade ≈ expected req/s delta on this specific workload, assuming
single-worker plaintext keep-alive:

| Grade | Estimated impact          |
|-------|---------------------------|
| **S** | >10% (>3k req/s) on its own |
| **A** | 3-10%                     |
| **B** | 1-3%                      |
| **C** | <1% but cheap             |

### 3.1 — S — Stop building Strings from bytes byte-by-byte in the parser

**File**: `navette/h1/parser.mojo:129-136`

```mojo
def _bytes_to_string(data: List[UInt8], start: Int, end: Int) -> String:
    var result = String()
    var i = start
    while i < end:
        result += chr(Int(data[i]))   # ← per-byte String concat
        i += 1
    return result^
```

Every call:
- builds an empty `String`,
- for each byte does `chr(Int(b))` (single-codepoint String allocation),
- then `result += ...` which reallocates / copies the growing String.

This is called once per **method**, **target**, **version**, and twice
per **header** (name + value) on every request. For a typical wrk2
plaintext request (~5 headers) that's ~13 invocations × N bytes of
quadratic-ish growth. This single function probably owns 20-40% of CPU
on this workload.

**Fix**: replace with the bulk-buffer pattern already used in
`navette/http/headers.mojo:8` (`_to_lower`):

```mojo
@always_inline
def _bytes_to_string(data: List[UInt8], start: Int, end: Int) -> String:
    var n = end - start
    var out = List[UInt8](capacity=n)
    out.extend(Span(data)[start:end])
    return String(unsafe_from_utf8=out)
```

Same trick should be applied everywhere `String()` is built with
`chr(...)` in a loop:
- `_decode_chunked` trailer parsing (lines 499, 506).
- `_int_to_string` in `serializer.mojo:63-77` (digits reversed via
  per-char String concat — see §3.2).
- `_int_to_hex_lower` (lines 80-96).
- `_get_extension` in `bench/lib/handler.mojo:178` (per-char ext build).
- `handle_static` filename build (`bench/lib/handler.mojo:565`).

**Expected**: 10-20% req/s on its own. This is the biggest single win.

### 3.2 — S — Pre-built `\r\nContent-Length: <n>\r\n` and stop re-rendering integers

**Files**: `navette/h1/serializer.mojo:63-77`, `bench/lib/handler.mojo:89-103`

`_int_to_string` is called twice per response (status code + content
length), and each call does:
```mojo
var digits = List[UInt8]()  # heap
while v > 0: digits.append(...)
var result = String()
while i >= 0: result += chr(Int(digits[i]))  # heap + per-char concat
```

Two heap allocations and N×String-concat for an integer that on this
workload is `200` and `13`. Worse, the handler `handle_plaintext`
already pre-builds `content-length: <len>` as a String via
`String(body.byte_length())` and `hdrs.add(...)`, then the serializer
does the same thing again via `_append_framing_header` (it does check
`headers.has("content-length")` first, so for this exact handler the
serializer-side render is skipped — but the Stringify in the handler
is not).

**Fix**:
1. Implement an iterative-write helper that emits decimals into a
   buffer without going through `String`:
   ```mojo
   @always_inline
   def _append_decimal(mut buf: List[UInt8], value: Int):
       comptime DIGITS: StaticString = "0123456789"
       var d = DIGITS.unsafe_ptr()
       if value == 0:
           buf.append(d[0]); return
       var start = len(buf)
       var v = value
       while v > 0:
           buf.append(d[v % 10])
           v //= 10
       # reverse in place — no string allocation
       var end = len(buf) - 1
       while start < end:
           var t = buf[start]; buf[start] = buf[end]; buf[end] = t
           start += 1; end -= 1
   ```
2. For the bench-specific path, ship a *precompiled* plaintext response.
   `handle_plaintext` always writes the same bytes:
   ```
   HTTP/1.1 200 OK\r\n
   content-type: text/plain\r\n
   content-length: 13\r\n
   \r\n
   Hello, World!
   ```
   Cache this 79-byte payload as `StaticString` at module init time and
   memcpy it into the outbuf in one go. The bench framework lets us do
   this safely because the handler controls framing.

   Wire it as an optional bypass on `ResponseWriter` (e.g.
   `resp.send_prebuilt(bytes)`) so the runtime adapter can `extend`
   into `_outbuf` directly and skip `serialize_response`.

**Expected**: 5-15% req/s. The bypass alone (precompiled response)
short-circuits steps 11-12 of §2 entirely.

### 3.3 — S — Reusable buffers across requests (no per-request List churn)

**Files**: `navette/h1/connection.mojo:294-298`, `:330-344`,
`navette/h1/handler_server.mojo:55-58`, `bench/servers/h1_server.mojo:410`

The H1 hot path currently allocates a fresh `List[UInt8]()` for almost
every transit:
- `H1Connection.drain()` swaps `_outbound_buf` out and replaces it with
  a fresh empty `List` (line 296).
- `H1HandlerServer.drain()` does the same with `_outbuf` (line 57).
- `H1ServerHandler._handle_send` resets `send_buf` to a new empty
  `List` (line 410).
- `_compact_inbound` allocates a brand-new `List` even when
  `keep == 0` (the common case on keep-alive after a finished request),
  *and* it allocates even when `keep > 0` instead of `memmove`-ing.

Every fresh `List[UInt8]` is a heap allocation. On a 27k req/s server,
that is 27,000 × (3 to 5) = >100k allocs/sec just for these.

**Fix**:
1. Use a "swap-and-clear" pattern. Mojo's `List` does not yet expose a
   trivial `clear()` that preserves capacity (verify against current
   stdlib — `resize(0)` does it). If `resize(0, ...)` retains capacity,
   replace all `self._buf = List[UInt8]()` patterns with
   `self._buf.resize(0, UInt8(0))` plus a `reserve(initial)` at
   construction.
2. For `H1Connection`, hold a single `_outbound_buf` and expose a
   `drain_into(mut sink: List[UInt8])` that uses
   `sink.extend(Span(self._outbound_buf))` and then
   `self._outbound_buf.resize(0, UInt8(0))`. The adapter caller passes
   in its own owned `_outbuf`; no swap-allocate dance.
3. `_compact_inbound`: when `keep == 0`, just set the cursor to 0
   and `resize(0, ...)` — never allocate. When `keep > 0`, use
   `UnsafePointer.memmove` (or stdlib equivalent) over
   `self._inbound_buf.unsafe_ptr()` rather than allocating a new
   buffer.

**Expected**: 3-7% req/s. The allocation counter going from ~5 per
request to ~1 per request is the kind of thing that compounds against
the µopt findings below.

### 3.4 — A — `Headers` storage: drop the dual lowercasing pass

**Files**: `navette/h1/parser.mojo:386-394`, `navette/http/headers.mojo:59-62`

In `_parse_headers`, names are collected into `names: List[String]`
verbatim, then at the end:
```mojo
for i in range(len(names)):
    headers.add(names[i], values[i])    # ← Headers.add runs _to_lower(name)
```
But the parser already validated names are ASCII tokens — we know each
byte's case at parse time. The lowercase form could be built once in
the bulk-copy version of `_bytes_to_string` (§3.1) and then passed via
`Headers.add_lowercase` (already implemented at headers.mojo:64-74 for
the H2 path).

**Fix**:
1. Add `_bytes_to_string_lowercase(data, start, end) -> String` that
   bulk-builds the lowercase form in one pass (one byte test +
   one `+ 32` per A-Z byte).
2. In `_parse_headers`, store `(lowered_name, value)` directly.
3. Call `headers.add_lowercase(...)` to bypass the second `_to_lower`
   pass.
4. While here: change `Headers` to store names as `List[UInt8]` rather
   than `List[String]`. Header-name comparison (`_iequals`,
   `headers.has`, `headers.get`) becomes a byte-by-byte memcmp instead
   of a String build + compare.

**Expected**: 2-4% req/s.

### 3.5 — A — Headers field-name lookup: replace linear scan with a hot-name fast path

**Files**: `navette/h1/parser.mojo:760-775`, `:1013-1026`,
`navette/h1/connection.mojo:346-357`, `navette/http/headers.mojo:97-120`

After header parsing, the request side runs:
- `_iequals(hname, "content-length")` for every header (1 pass)
- `_iequals(hname, "transfer-encoding")` for every header
- `_iequals(hname, "host")` for every header
- Then `_update_keep_alive` runs `_iequals(hname, "connection")` for every header again

That's **4 full linear scans over the header list** per request, each
doing a byte-by-byte case-insensitive compare per header. For a typical
5-header request that is 20 `_iequals` calls per request.

Once names are stored already-lowercased (§3.4), every `_iequals(name,
"content-length")` reduces to a byte memcmp against `"content-length"`,
which is cheap. But the **four passes** are still wasteful — we already
walked the headers during parsing.

**Fix**: track the indices (or values) of the four interesting headers
inside `_parse_headers` while walking it once. Return them via the
existing tuple slot or a small `ParsedFramingHints` struct. Downstream,
read those directly instead of re-scanning. The same hot-name set
(content-length, transfer-encoding, host, connection) shows up in the
response parser; share the helper.

For the public `Headers.get/has`, the common pattern in handlers is
`headers.get("accept-encoding")` etc. — keep the linear scan but build
the lookup key as a `Span[Byte]` once (`StaticString.as_bytes()` is
constant, `Headers.get` does a `_to_lower` *every call* — §3.6).

**Expected**: 2-4% req/s, larger if handlers do many `headers.get`
calls.

### 3.6 — A — `Headers.get/has/set/remove` re-lowercase the lookup key every call

**File**: `navette/http/headers.mojo:97-120`

Every public lookup runs `_to_lower(name)` on the **caller-provided**
name first, allocating a new `String` per call. For literal header
names (the only callers in the bench:
`hdrs.add("content-type", ...)`, `headers.get("accept-encoding")`,
`request.headers.has("content-length")`) this is gratuitous.

**Fix**:
1. Add an `add_lower_static[name: StaticString](mut self, value: String)`
   or similar — comptime-known names skip the `_to_lower` entirely.
2. Provide a byte-slice-keyed variant: `get_bytes(name: Span[Byte])` for
   callers that already have lowercase bytes.
3. For the handler ergonomic API (`headers.get("accept-encoding")`), at
   minimum verify in source whether the string is already lowercase
   before calling `_to_lower` — for the StaticString-literal-only case
   we can lift the check.

**Expected**: 1-3% req/s, mostly on richer routes (`/static/`,
`/json/`) but applies to plaintext too because the bench `Headers()`
gets two `add(...)` calls per response.

### 3.7 — A — Inline + flatten the bench handler -> response writer -> serializer trampoline

**Files**: `bench/lib/handler.mojo:89-103`, `navette/http/handler.mojo:480-572`,
`navette/h1/handler_server.mojo:74-138`

The dispatch chain for one request is:
```
handle_plaintext → ResponseWriter.send_status → captures Optional
                 → ResponseWriter.try_send_body → SendBody.try_write → Deque.append
                 → ResponseWriter.end → SendBody.end → Deque.append
H1HandlerServer._dispatch_one → ResponseWriter._take_status
                              → ResponseWriter._take_headers
                              → loop pop_body_frame → SendBody._pop → Deque.popleft
                              → Response(...) → ServerConnection.send_response
                              → H1Connection.send_response → serialize_response
                              → outbuf.extend
```

Nothing here is `@always_inline`. Each layer takes movable `Optional`
and `Deque` payloads, executes a couple of branches, and forwards to the
next layer. The work is moving frames into a queue, just to pop them
right back out in the same callstack — there's no real backpressure
applied because the buffer is below high-water for a 13-byte body.

**Fix**:
1. Mark every method on `ResponseWriter`, `SendBody`, `H1HandlerServer`,
   `ServerConnection`, `H1Connection` that is on the synchronous
   `on_request` → wire-bytes path as `@always_inline`. Specifically the
   thin getters/setters/`_take_*` / `_pop` / `drain` methods.
2. Reduce `Response` materialization to "headers + a `Span[Byte]` body":
   for the common synchronous case where the handler has emitted exactly
   one Data frame + End in the same call, treat that as a special case
   in `_dispatch_one` — read the single `BodyFrame.data()` directly and
   pass `Span[Byte]` to a `serialize_response_simple()` overload that
   skips the `_total_data_len`/`_has_trailers` loops.
3. Drop the intermediate `_outbuf` in `H1HandlerServer` (line 31). The
   `H1Connection` already has `_outbound_buf`; the only thing
   `_outbuf` adds is one extra `extend(self._conn.drain())` per
   response. Have `H1HandlerServer.drain()` forward directly:
   `return self._conn.drain()`.

**Expected**: 2-5% req/s.

### 3.8 — A — `_str_to_bytes` in handlers, and the body-bytes copy

**File**: `bench/lib/handler.mojo:35-40`

```mojo
def _str_to_bytes(s: String) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    out.extend(b)
    return out^
```

Every handler call (plaintext, 404, baseline2) builds a `String` body,
then copies it into a `List[UInt8]` so it can be wrapped in
`BodyFrame.data(...)`. The body literally never needs to be a String.

**Fix**:
1. Add `BodyFrame.data_from_static(s: StaticString)` that wraps the
   span as a non-owning view (or copies once, but from a `StaticString`
   directly — no intermediate `String` allocation).
2. For `Headers.add` value side, store `List[UInt8]` instead of
   `String` (consistent with the §3.4 change). The serializer then
   skips `value.as_bytes()` and just extends a `Span[Byte]`.
3. Refactor `handle_plaintext`, `handle_404`, `handle_baseline2` to
   use the precompiled response (§3.2) or the direct `Span[Byte]` body
   path.

**Expected**: 1-3% req/s when combined with §3.2.

### 3.9 — A — Enable TCP_NODELAY on accepted sockets

**File**: `bench/servers/h1_server.mojo:293-333`

No `setsockopt(TCP_NODELAY, 1)` on accepted client sockets. With Nagle
on and the wrk2 client running 64 concurrent keep-alive connections,
the kernel can hold 40ms (delayed ACK window) on small writes before
sending. wrk2's coordinated-omission tracking will catch this as
latency on p99/p99.9. The bench gates *pass* (because all requests
eventually arrive within the 50ms p99 budget) but the achieved rps
loses to a stack that flushes immediately.

Both hyper and nginx set `TCP_NODELAY` by default on accepted sockets.

**Fix**: in `_handle_accept`, after `client_fd = result`:
```mojo
var one = _heap_alloc[Int32](1).as_any_origin()
one[0] = 1
_ = external_call["setsockopt", Int32](
    client_fd, Int32(6),  # IPPROTO_TCP
    Int32(1),             # TCP_NODELAY
    one, Int32(4))
one.free()
```
Better yet, stash the option blob as a singleton on `H1ServerHandler`
and reuse.

**Expected**: 1-3% req/s and meaningful p99 / p99.9 tightening.

### 3.10 — A — Switch H1 server to multishot recv + buffer ring (like H2)

**Files**: `bench/servers/h1_server.mojo:252-263`, `:336-359`,
compare with `bench/servers/h2_server.mojo:286-294` + `:546-551`

H2 already runs:
- `IORING_RECVMSG_MULTISHOT` so the kernel keeps producing CQEs without
  resubmission (one syscall amortized over many recvs).
- A shared **provided buffer ring** (`buf_base + buf_id * buf_size`),
  so the kernel selects a buffer per CQE — no per-connection buffer
  allocation, no buffer ownership dance.

H1 still uses one-shot `submit_recv` per request with a dedicated
8 KiB per-connection buffer. Two costs:
1. One io_uring submission per request → SQE write + `io_uring_enter`
   for the recv. With multishot, the kernel keeps the recv armed.
2. Each `H1Conn` carries an 8 KiB `recv_buf` `List[UInt8]` initialized
   with `length=8192, fill=0` (line 131) — that's a 64-bit zero-fill of
   8 KiB at accept time per connection. The buffer ring uses a pool.

The README §"Long-conn parity" already credits multishot recvmsg for
the QUIC throughput catch-up. Same pattern applies here.

**Fix**: clone the H2 buffer-ring path (h2_server.mojo:286, 546-551,
656-674). Specifically:
1. Allocate `_BUF_RING_SIZE * _RECV_BUF_SIZE` shared buffer at server
   startup.
2. Register it with the io_uring as a provided buffer group.
3. Submit one `submit_recv_multishot` per accepted connection.
4. CQE processing reads `buf_id` from `flags`, indexes into the buffer
   base, feeds the slice into the H1 codec, then returns the buffer to
   the ring (re-providing).
5. Drop the per-connection `recv_buf` field on `H1Conn`.

**Expected**: 3-7% req/s, plus a fairly large reduction in
`io_uring_enter` overhead at 27k req/s.

### 3.11 — B — `_parse_headers` building parallel `List[String]` arrays twice

**File**: `navette/h1/parser.mojo:269-395`

`_parse_headers` does:
1. `var names = List[String]()` and `var values = List[String]()`
2. For each line, appends to both.
3. Final loop builds a `Headers()` and calls `add(...)` for each pair —
   *which appends to two more `List[String]` inside `Headers`*.

That is 4 `List[String]` lifetimes per request, plus the double
lowercasing pass already noted in §3.4. We can build directly into the
`Headers` object during the loop. The only reason for the parallel
arrays is the obs-fold continuation logic at line 302 (`values[prev_idx]
= values[prev_idx] + " " + fold_text`), which **also concatenates two
Strings** for every continuation line.

**Fix**:
1. Build straight into a single `Headers` (use `add_lowercase` from §3.4).
2. obs-fold rewrite: keep last `value_at(len-1)` index, append into the
   stored value's underlying `List[UInt8]` if we switch headers to byte
   storage. Even keeping String, `values[prev_idx] += ...` would be
   faster than the 3-String temp.
3. obs-fold path is dead code under strict mode anyway — guard the
   whole branch behind `if config.strictness.allow_obs_fold:` so it can
   be branch-predicted away.

**Expected**: 1-2% req/s.

### 3.12 — B — Custom-method String allocation for the common case

**File**: `navette/http/method.mojo:84-105`, `navette/h1/parser.mojo:729`

The parser always constructs the method name as a String, then calls
`Method.custom(method_str)` which **string-compares against 9 known
methods** to dispatch back to the tagged variant. For `GET`, the
hottest case, this is:
- 3-byte byte slice → `_bytes_to_string` (3 allocations: empty String +
  per-byte concat).
- `Method.custom("GET")` → `if name == "GET"` String compare (cheap) →
  returns `Self(_tag=_GET)` (no allocation).
- The temporary `_custom` is empty.

**Fix**: at the parser, do the byte-comparison directly:
```mojo
@always_inline
def _method_from_bytes(buf: List[UInt8], start: Int, end: Int) -> Method:
    var n = end - start
    if n == 3 and buf[start]==UInt8(ord("G")) and buf[start+1]==UInt8(ord("E")) and buf[start+2]==UInt8(ord("T")):
        return Method.get()
    if n == 4 and buf[start]==UInt8(ord("P")) and buf[start+1]==UInt8(ord("O")) and buf[start+2]==UInt8(ord("S")) and buf[start+3]==UInt8(ord("T")):
        return Method.post()
    # ... etc, fall through to Method.custom(_bytes_to_string(...))
```
Comptime-precompute a small perfect-hash on `n + first_byte` if a
hand-rolled switch starts to look ugly.

Same pattern applies to the HTTP-version check (`HTTP/1.1` is 8 bytes,
compare as a single UInt64 load) — much faster than building a String
and equality-comparing.

**Expected**: 0.5-1% req/s on plaintext, more on routes where the
method check matters.

### 3.13 — B — Bench dispatcher: replace `_starts_with(String, String)` chain with a byte-based dispatch

**File**: `bench/lib/handler.mojo:706-736`

```mojo
def _dispatch_request(...):
    if _starts_with(target, String("/plaintext")):
        handle_plaintext(resp)
    elif _starts_with(target, ...):
        ...
```

Each `_starts_with` rebuilds `target.as_bytes()` and a new bytes view
of the literal. For 5 prefixes that's 5 `.as_bytes()` calls per
request. Also `_starts_with` itself byte-loops.

**Fix**: dispatch on `target_bytes[1]` (the byte after `/`). For the
HttpArena set those first bytes are unambiguous: `p`=plaintext,
`b`=baseline*, `j`=json, `s`=static. One byte compare picks the route,
then verify the remaining bytes against a `StaticString` via SIMD-eq
where available.

```mojo
@always_inline
def _dispatch_request(target_bytes: Span[Byte], ...):
    if len(target_bytes) < 2 or target_bytes[0] != UInt8(ord("/")):
        handle_404(resp); return
    var c = target_bytes[1]
    if c == UInt8(ord("p")):    # /plaintext
        handle_plaintext(resp)
    elif c == UInt8(ord("b")):  # /baseline*
        handle_baseline2(target_bytes, resp)
    elif c == UInt8(ord("j")):  # /json/
        handle_json(target_bytes, resp, state_ptr)
    elif c == UInt8(ord("s")):  # /static/
        handle_static(target_bytes, headers, resp, state_ptr)
    else:
        handle_404(resp)
```
And while doing this: change `req.target` to ship as `Span[Byte]` or
at least keep a `List[UInt8]` alongside the String. The current handler
re-encodes it back to bytes anyway.

**Expected**: 0.5-1% req/s.

### 3.14 — B — `_compact_inbound` allocates even when keep == 0

**File**: `navette/h1/connection.mojo:330-344`

After a complete request is consumed, `_inbound_cursor == len(_inbound_buf)`,
so `keep == 0` and the code path:
```mojo
var new_buf = List[UInt8](capacity=keep)  # alloc empty
if keep > 0: new_buf.extend(...)
self._inbound_buf = new_buf^
self._inbound_cursor = 0
```
does a fresh allocation per request even though we just want to reset.

**Fix**: covered by §3.3 — use `self._inbound_buf.resize(0, UInt8(0))`
and reset cursor. Worth calling out separately because the dependency
on `List.resize` preserving capacity needs verification against the
stdlib version being used.

**Expected**: subsumed into §3.3.

### 3.15 — B — Drop `_to_lower` per-character branch via SIMD or table

**File**: `navette/http/headers.mojo:8-24`, `navette/h1/parser.mojo:122-126`

For ASCII headers, `_to_lower` byte-by-byte is OK once it's bulk-build
(it already is) — but the per-byte branch (`if b >= 65 and b <= 90`)
compiles to two compares plus a branch. SIMD by 16 or 32 bytes via the
`SIMD[DType.uint8, 16]` patterns from `mojo-optimizations` →
"nibble lookup" can do this branchlessly:

```mojo
@always_inline
def _bulk_lower(mut out: List[UInt8], src: Span[UInt8]):
    comptime W = simd_width_of[DType.uint8]()
    var n = len(src)
    var i = 0
    var ptr = src.unsafe_ptr()
    while i + W <= n:
        var v = ptr.load[width=W](i)
        var is_upper = (v >= SIMD[DType.uint8, W](65)) & (v <= SIMD[DType.uint8, W](90))
        var lower = is_upper.select(v + SIMD[DType.uint8, W](32), v)
        out.unsafe_ptr().offset(...).store(lower)  # caller-prepared capacity
        i += W
    while i < n:
        var b = ptr[i]
        if b >= UInt8(65) and b <= UInt8(90):
            out.append(b + UInt8(32))
        else:
            out.append(b)
        i += 1
```
Same trick applies to header-value scans like `_iequals` /
`_icontains`.

**Expected**: 0.5-2% req/s on plaintext; bigger on header-heavy routes.

### 3.16 — C — `serialize_response`: collapse `_total_data_len` + `_has_trailers` + `_append_data_frames` into one pass

**File**: `navette/h1/serializer.mojo:118-141, 216-268`

Three sequential walks over `response.body` (often a 1-element list).
Cheap individually but: the body list is built and torn down on every
request, and the pattern foils inlining.

**Fix**: one pass that records `(total_len, has_trailers)` and
`extend`s data chunks into a temporary `List[Span[Byte]]` so the
write-out doesn't re-walk. Simpler: special-case `len(body) == 1 and
body[0].is_data()`, which is the bench path and most real responses.

**Expected**: 0.5% req/s; mostly hygiene + setup for §3.7's
`serialize_response_simple`.

### 3.17 — C — Drop the `recv_buf.fill=0` initialization

**File**: `bench/servers/h1_server.mojo:131`

```mojo
self.recv_buf = List[UInt8](length=_RECV_BUF_SIZE, fill=UInt8(0))
```
The 8 KiB zero-fill at accept time is unnecessary — the kernel writes
into the buffer before we read it, and we only ever inspect bytes
`[0:n]` after a recv completes. With `_RECV_BUF_SIZE = 8192` and the
short-conn case (which is the harder one), each accept does an
8 KiB `memset` for no reason.

**Fix**: switch to `List[UInt8](capacity=_RECV_BUF_SIZE)` and resize
without fill (or just keep capacity at zero length and `memcpy` into
it from kernel — but that needs a different recv API). Or, when we
move to the buffer-ring approach (§3.10), the per-connection buffer
goes away entirely.

**Expected**: 0.2-0.5% req/s; mostly meaningful for short-conn.

### 3.18 — C — `_inbound_buf.extend(data)` could go to a ring buffer

**File**: `navette/h1/connection.mojo:118-119`

`_inbound_buf.extend(data)` copies the kernel-recv bytes into a
heap List. For plaintext keep-alive where each request is one recv,
the parser then operates on `_inbound_buf` directly, so the copy is
just to satisfy "buffer survives across calls". A ring buffer or
a `Span` that *aliases* `recv_buf` (when the request fits in one recv,
which is the common case) avoids the extend entirely.

Trickier because the parser API takes `List[UInt8]` rather than
`Span[UInt8, _]`. Refactor parser signatures to `Span[Byte, _]` and
pass the recv span directly when `_inbound_buf` is empty.

**Expected**: 0.5-1% req/s; bigger if pipelining gets exercised.

### 3.19 — C — `BodyFrame` is fat for a tagged union (4 fields, 1 used per variant)

**File**: `navette/http/body.mojo:32-35`

```mojo
struct BodyFrame:
    var _tag: Int
    var _data: List[UInt8]
    var _headers: Headers          # always present, only used by Trailers
    var _error: Optional[StreamError]  # always present, only used by Error
```

A Data frame carries an empty `Headers()` and an empty
`Optional[StreamError]`. Each `Headers()` is `List[String] +
List[String]` = 2 unused inline allocations per frame; the Optional is
small. For a 13-byte plaintext body the BodyFrame is a 40-byte struct
where most of it is unused.

**Fix**: replace with a true tagged union (a single payload pointer
discriminated by tag) or, more practically, store frames as
`Variant[DataFrame, TrailersFrame, EndFrame, ErrorFrame]`. The
`Variant` lookup pattern from `mojo-syntax` (`values[i][T].copy()`)
applies.

**Expected**: 0.5-1% req/s; mostly memory bandwidth + better cache
locality of `Deque[BodyFrame]`.

### 3.20 — C — `Capabilities` and `Request` movement copies

**Files**: `navette/http/handler.mojo:18-94`, `navette/http/request.mojo`

`Capabilities` is a 4× Bool + 1× Int struct passed by value to every
`on_request`. Mark it `TrivialRegisterPassable` so it goes through
registers instead of stack. Same for `WriteResult`, `StatusCode`,
`Version`, `Method` (the tagged form when not custom).

`Request` is *not* register-passable (has `String` + `Headers` + body),
which is fine, but `_dispatch_one(self, var req: Request)` and
`on_request(... var req: Request, ...)` both take ownership. Make sure
the move is actually moving and not implicitly copying — verify with a
test build under `-D ASSERT=none -O3` and read the LLVM IR if
suspicious.

**Expected**: 0.2-0.5% req/s, mostly via cleaner inlining.

### 3.21 — C — `body_frames` list in `_dispatch_one` for the single-frame case

**File**: `navette/h1/handler_server.mojo:121-129`

For the plaintext path the handler emits exactly one `Data` frame and
one `End` frame. `_dispatch_one` allocates `body_frames` (a `List`),
loops `_pop_body_frame` (a `Deque.popleft`), discards the End, and
appends the Data. Two allocations for what should be one move.

**Fix**: detect the common case (`len(send_body._frames) == 2 and
frames[0].is_data() and frames[1].is_end()`) and forward the Data
frame directly via a `serialize_response_simple(status, headers,
body_span)` overload (§3.7).

**Expected**: 0.5% req/s.

## 4. Recommended order of attack

In the order most likely to deliver req/s with the least implementation
risk:

1. **§3.1** — fix `_bytes_to_string`. Single function, mechanical
   change, biggest single delta expected.
2. **§3.2** — `_int_to_string` rewrite + precompiled plaintext response
   via a `send_prebuilt` bypass on `ResponseWriter`. Pulls the entire
   serializer off the hot path for the bench endpoint.
3. **§3.3** — reusable buffers. Verify `List.resize(0, ...)` preserves
   capacity; if not, switch to a small handwritten `ByteBuf` struct
   with explicit `.clear()` semantics.
4. **§3.9** — TCP_NODELAY. One-line setsockopt; immediate p99 win.
5. **§3.10** — multishot recv + buffer ring. Copy the H2 path.
6. **§3.4** + **§3.5** — Headers byte-storage and parser-side fast
   path. These compound with §3.1 because they remove the rest of
   the per-header String churn.
7. **§3.7** — `@always_inline` the dispatch chain; do this *after*
   §3.2 so we're inlining a thinner chain.
8. Everything else in any order, re-benchmarking between groups.

Re-benchmark after each group. The bench's σ% is around 1-1.5% on
plaintext, so changes that should clear the noise floor are visible
in single-iteration runs.

## 5. Validation harness checklist

Before merging any of these changes:

- `bash bench/flare_compare/scripts/build-baselines.sh navette` rebuilds
  just the navette image.
- The full integrity gate
  (`bench/flare_compare/scripts/_integrity_check.sh`) MUST still pass —
  it byte-compares the response, and §3.2's precompiled bytes need to
  be exactly the same wire format.
- `tests/h1/` must stay green. The strict parser tests cover the
  invariants that §3.1 / §3.4 changes touch; if any regress, the
  String → bytes refactor probably skipped a code path
  (`_bytes_to_string` shows up in obs-fold and chunked trailer paths
  that the plaintext bench never hits).
- For each major change, also rerun the conformance cross-validators
  (`conformance/` directory) — the parser is cross-validated against
  h11/httptools, and a regression there is a bug regardless of the
  bench number.

## 6. What's NOT on this list

- **Anything below H1 in protocol terms.** QUIC/H3 has its own bench
  (`bench/quic_perf/`) with separate optimization findings recorded in
  `bench/quic_perf/results/REFERENCE.md`. The §"Short-conn gap" in the
  README is already well-characterized and structural — leave it alone
  until the H1 plaintext gap is closed.
- **Multi-worker scaling.** The flare-compare bench is explicitly
  single-worker per the README. Beating hyper at 1w is the stated
  target; SO_REUSEPORT scaling is a separate workstream.
- **TLS path.** The plaintext lane is the one we're chasing here. The
  TLS branch in `_handle_recv_tls` (h1_server.mojo:360) has its own
  set of opportunities (drain_plaintext copies, ALPN single-element
  list), but they don't move the plaintext number.
- **HTTP/2 / HTTP/3 servers.** Out of scope. H2 already uses the
  buffer-ring + multishot pattern that §3.10 proposes for H1.

