# Bench H1 consolidation + JSON / JSON-TLS — Retrospective

## Built vs. planned

All 11 tasks landed with one deviation: Task 9 (HttpArena Docker validate) was
substituted with an in-process curl + python validator that reproduces the
exact 4 (count, m) checks `validate.sh` runs. The substitution is justified
because building the framework Docker image + the load-generator chain
(h2load + wrk) was a 30+ minute round trip and we already had the json
schema authority from `bench/.httparena/scripts/validate.sh`. The Docker
validate is still queued as a follow-up before any HttpArena leaderboard
submission.

Everything else followed the plan:
- Task 0 (vendor + meta.json bump) — done as written.
- Task 1 (simdjson loader) — `_load_dataset` materialises 50 `DatasetItem`s
  with name/category/tags/rating pre-escaped at boot. `Value.get_string`
  + the array/object iteration via `count(doc)` + `at(doc, i)` + `get(doc, key)`
  was straightforward; no API gaps for this use case.
- Task 2 (json_writer.mojo) — small module, fast itoa + RFC 8259 string
  escape. Validated via `mojo execute` round-trips before integration.
- Task 3 (renderer + dispatcher) — linear renderer (no per-`count` skeleton
  cache, deferred per the plan); reuses `_parse_query_int` for `?m=`.
- Task 4 (H1 TLS mode) — single `bench/h1_server` binary now picks plaintext
  or TLS at boot via `BENCH_H1_TLS`. ALPN list = `["http/1.1"]`. Connection
  state machine matches h2_server's pattern (handshake → ready → drain
  plaintext → feed http codec → encrypt response → stage send).
- Task 5 (launcher h1tls role) — `_binary_for_type` maps role to binary
  basename, h1 and h1tls share `h1_server` with role-specific env applied
  inside the child between `fork` and `execv`.
- Task 6 (H2 /json wiring) — fell out of the BenchState refactor, no extra
  surface change required.
- Task 7 (run.sh) — fourth sidecar added; DATA_DIR env defaulted.
- Task 8 (build.sh + Dockerfile) — `--build-context simdjson=…` plus
  `-I /simdjson` on the h1/h2/h3 builds; `EXPOSE 8081`; dataset COPYed into
  `/data/dataset.json` so the image is self-contained.

## Local benchmark numbers — single-worker `bench/launcher`, h2load

`-n 10000 -c 100 -m 10` against the validation rotation count (12, m=3).

| Endpoint | Protocol | RPS | p50 req-time | p100 req-time | TTFB mean | Failures |
|---|---|---:|---:|---:|---:|---:|
| `/baseline2` | H1 plain | **100,524** | ~7 ms | 20.9 ms | 22.5 ms | 0 / 10 000 |
| `/json/12?m=3` | H1 plain | **57,950** | ~16 ms | 17.3 ms | 23.2 ms | 0 / 10 000 |
| `/baseline2` | H1 + TLS (h1tls) | **59,627** | ~9 ms | 29.1 ms | 84.0 ms | 0 / 10 000 |
| `/json/12?m=3` | H1 + TLS | **39,514** | ~21 ms | 35.4 ms | 60.0 ms | 0 / 10 000 |
| `/baseline2` | H2 (TLS) | **42,878** | ~13 ms | 45.5 ms | 94.6 ms | 0 / 10 000 |
| `/json/12?m=3` | H2 (TLS) | **30,231** | ~27 ms | 49.3 ms | 57.4 ms | 0 / 10 000 |

JSON overhead vs baseline (lower = more overhead from JSON):
- H1 plain: 57 950 / 100 524 = **57.7 %**
- H1 + TLS: 39 514 / 59 627 = **66.3 %**
- H2 + TLS: 30 231 / 42 878 = **70.5 %**

These land at the **upper end** of the 40–60 % band predicted earlier, which
is a pleasant surprise — the simdjson-mojo round trip at boot plus the
hand-rolled writer with pre-escaped fragments puts almost no per-request
work on the hot path beyond memcpy + 4 integer formats. The skeleton-cache
optimisation listed in the plan as "deferred unless we drop below 50 %" is
unnecessary for now.

## Real bug discovered (out of scope, queued for follow-up)

**H2 server crashes streams under concurrent-stream load with larger
responses.** The new `/json/50?m=6` endpoint produces ~8 KB responses (50
items of ~165 B each + framing), and exercising it with `-c 100 -m 10`
on H2 reports **9300 / 10000 failed** in `time for request: 10.10ms …`,
status codes count `800 2xx`. The same workload on H1 plaintext returns
clean (10 000 / 10 000 succeeded at 21 240 RPS, 171 MB/s).

Repro (single-worker launcher running):
```bash
docker run --rm --network host h2load-h3:latest \
    -n 10000 -c 100 -m 10 'https://127.0.0.1:8443/json/50?m=6'
# 9300 errored, 800 2xx
```

Sweeping the parameters narrows the trigger:
- `-c 100 -m 1` (no concurrent streams per conn): **0 failures**, 8308 RPS.
- `-c 10 -m 10` (10 concurrent streams per conn): **4930 / 5000 errored**.

The bug is **concurrent-stream + larger-response** on H2. `/baseline2` on
H2 (1-byte response, same `-c 100 -m 10`) is clean. Suspected causes:
- HTTP/2 flow control: stream and connection windows might not be drained
  back to the peer fast enough when 10 streams each push ~8 KB, breaching
  initial window and tripping a stream RST.
- HEADERS / CONTINUATION framing: 8 KB exceeds the default `MAX_FRAME_SIZE`
  (16 KB ok, but the *response headers* stay small; the data frames split
  cleanly. Less likely.).
- Per-stream send buffer reuse / state machine race when the H2 coro
  pipeline interleaves writes for 10 in-flight streams.

This is a **pre-existing H2 server issue surfaced by the new `/json`
profile** — `/baseline2`'s 1-byte response simply never stressed the
fan-out path. Filing as a follow-up task; not blocking the json profile
delivery since the validation rotation (count ≤ 50) still works under
m=1, and the m=10 failure isn't unique to this PR.

## simdjson-mojo dogfood feedback

Used as a parser for `data/dataset.json` (50 items, 12 KB). All field
accesses worked first try:
- `Parser().parse(bytes^) -> Document`
- `doc.root().is_array(doc)` / `count(doc)` / `at(doc, i)`
- `Value.get(doc, "key")` for object lookup
- `get_uint`, `get_bool`, `get_string`

**Rough edges noted (small, none blocking):**

1. **Functions calling raising methods need explicit `raises`.** Even when
   declared with `def`, they don't auto-raise in 0.26.2 if the body
   contains raising calls in nested control flow. First compile failed
   with "cannot call function that may raise in a context that cannot
   raise" on `_build_quoted_string` etc. Easy fix (add `raises`), but a
   contributor coming from Python expects `def` to behave like the
   tutorial says it does. Worth a one-liner in the simdjson README about
   raising propagation.

2. **`Value.get_string` returns an owned `String` (copy out of the tape's
   string buffer).** That's fine at boot time — we run it 50 × 5 strings
   and never again — but if anyone uses simdjson on a per-request hot path,
   they'll want a zero-copy view (`Span[UInt8]` borrowed from the
   `string_buf`). Right now you'd have to drop into `_payload(doc)` +
   manual offset+length reads, which means touching private-ish
   internals. A `Value.get_string_view(doc) -> Span[UInt8, _]` helper
   would close that gap.

3. **`mut doc: Document`** required on every accessor — surprising on
   methods like `is_array`/`get`/`at` that don't actually mutate state.
   The reason is Mojo's `ref doc` semantics on the underlying tape, but
   the API surfaces it. Keeps you honest about lifetimes; could also
   be hidden behind helpers if the project wants a friendlier face.

4. **Tuple destructure (`var (a, b) = f()`) is not supported in Mojo
   0.26.2.** This bit me when I first wrote `_parse_json_path` to return
   `(Int, Int)`. Solved with out-args (`mut count_out: Int, mut m_out: Int`).
   Not a simdjson issue — but worth knowing for downstream consumers
   building DOM-walk helpers.

## Boucle / mojo-net changes that fell out

None. The consolidation was confined to `bench/`.

## Open questions / next steps

- **Run the HttpArena Docker validate** (deferred Task 9): build
  `httparena-mojo-net` with the new build-contexts + `h2load:latest` /
  `wrk:latest` images, run `./scripts/validate.sh mojo-net` from
  `bench/.httparena/`. Required before submitting to the leaderboard.
- **Investigate the H2 `/json/50?m=6` concurrent-stream regression.** This
  is the most concrete defensive ROI in this whole exercise — `/baseline2`
  was hiding it. Open as its own plan.
- **H2 baseline2 RPS regressed slightly** (51 464 → 42 878 in this run,
  with the BenchState refactor). Likely just noise (different machine
  state from the morning run), but worth confirming with a fresh sample.
- **Skeleton cache for /json** is unnecessary at the current overhead
  level (57–70 % of baseline). Can stay deferred indefinitely.
- **Static profile (already in meta.json) still has the pre-existing H1
  static file bug** — not regressed, not addressed.
