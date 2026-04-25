# Bench H1 consolidation + JSON / JSON-TLS profiles

> **For agentic workers:** REQUIRED SUB-SKILL: Use `atelier:subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship HttpArena's `json` and `json-tls` profiles, and as a forcing function collapse the duplicated H1 plaintext + H1-over-TLS server code into a single configurable binary. Avoid writing a fourth duplicate. H2 stays separate (different protocol layer); H3 is out of scope.

**Architecture:**
- One `bench/h1_server.mojo` runs in either *plaintext* or *TLS* mode, selected by env (`BENCH_H1_TLS=0|1`, `BENCH_H1_PORT`, optional `BENCH_H1_ALPN`).
- `bench/launcher.mojo` learns a fourth role `h1tls` and spawns workers with the right env. `BENCH_PROTOCOL` filter accepts `h1`, `h1tls`, `h2`, `h3`.
- `bench/handler.mojo` gains a dataset cache (parsed once at boot via `simdjson` from the `json-simd-mojo` sibling repo) and a `/json/{count}?m=<m>` renderer shared by all servers.
- Hand-rolled JSON writer (no encoder in simdjson-mojo) writing into a pre-allocated scratch buffer with pre-escaped strings.

**Tech stack:** Mojo 0.26.2, boucle (CompletionLoop, multishot accept, rustls TLS via `librustls-mojo`), `json-simd-mojo` (sibling repo, package `simdjson`), HttpArena framework conventions.

**External resources:**
- `../json-simd-mojo/` — sibling repo, package name `simdjson`. Public API: `Parser.parse(List[UInt8]) -> Document` / `Value.get_uint` / `Value.get_string_length` / array + object iteration via tape walk. Build with `-I /path/to/json-simd-mojo`.
- `bench/.httparena/data/dataset.json` — 12 KB, ~50 items, schema `{id, name, category, price, quantity, active, tags[], rating{score,count}}`.
- `bench/.httparena/scripts/validate.sh` — authoritative endpoint validator.

---

## File structure

| Action | File | Responsibility |
|--------|------|---------------|
| Modify | `bench/h1_server.mojo` | Add TLS mode (rustls handshake before H1 codec); read `BENCH_H1_TLS` / `BENCH_H1_PORT` / `BENCH_H1_ALPN` |
| Modify | `bench/handler.mojo` | Add `DatasetItem` + `_load_dataset` (simdjson) + `/json/{count}?m=<m>` renderer + pre-escaped strings + per-count skeleton cache |
| Create | `bench/json_writer.mojo` | Fast itoa, JSON byte-string escaping, scratch-buffer renderer for the response shape |
| Modify | `bench/h2_server.mojo` | Wire `/json` dispatch through the shared handler (no protocol changes) |
| Modify | `bench/launcher.mojo` | Add `h1tls` role; pass `BENCH_H1_TLS=1 BENCH_H1_PORT=8081` env; extend `BENCH_PROTOCOL` filter |
| Modify | `bench/meta.json` | `tests: ["baseline", "json", "baseline-h2", "json-tls"]` |
| Modify | `bench/Dockerfile` | `--build-context simdjson=../json-simd-mojo`; add include path; expose 8081; COPY dataset |
| Modify | `bench/build.sh` | Pass simdjson build context |
| Modify | `bench/run.sh` | Boot 4 binaries (h1-plain, h1-tls, h2, h3) for fallback / single-worker debugging |
| Vendor | `bench/data/dataset.json` | Symlinked or copied from `bench/.httparena/data/dataset.json` so the image is self-contained |
| Modify | `.gitignore` | Ignore `bench/data/dataset.json` if symlinked (already covered if vendored under tracked file) |

---

## Key API reference

### simdjson-mojo (parsing dataset at boot)

```mojo
from simdjson.parser import Parser
from simdjson.document import Document
from simdjson.value import Value

var bytes = read_file("/data/dataset.json").as_bytes_list()
var parser = Parser()
var doc = parser.parse(bytes^)
var root = doc.root()           # Value (TAG_ROOT → array)
# walk root array → for each element, read fields by key, materialise DatasetItem.
```

The parser has no encoder. Walk Document → build `List[DatasetItem]` with **pre-escaped** name/category/tags as `List[UInt8]` byte spans. Encoding the dataset values (`name = "Alpha Widget"` etc.) requires only `\` and `"` escape — full HTML/control-char escape unnecessary because validate accepts any valid JSON.

### JSON response shape

```json
{"count": 12, "items": [
  {"id":1,"name":"Alpha Widget","category":"electronics","price":328,"quantity":15,"active":true,"tags":["sale","heavy-duty","popular"],"rating":{"score":48,"count":53},"total":4920}
, ...
]}
```

`total = price * quantity * m`. The validator's 4 (count, m) pairs `(12,3) (22,7) (31,2) (50,5)` differ from the bench's 7 — caching keyed on `m` is cheating, but caching keyed on `count` and **patching `total` per-item per-request is correct**.

### h2load command (for local smoke / multi-worker validation)

```bash
docker run --rm --network host h2load-h3:latest \
    -n 10000 -c 100 -m 1 --h1 'http://127.0.0.1:8080/json/12?m=3'
docker run --rm --network host h2load-h3:latest \
    -n 10000 -c 100 -m 1 'https://127.0.0.1:8081/json/12?m=3'   # H1 over TLS
docker run --rm --network host h2load-h3:latest \
    -n 10000 -c 100 -m 10 'https://127.0.0.1:8443/json/12?m=3'  # H2 over TLS
```

---

### Task 0: Vendor dataset.json + meta.json bump

**Files:** `bench/data/dataset.json`, `bench/meta.json`

- [ ] Copy `bench/.httparena/data/dataset.json` to `bench/data/dataset.json` (vendor, don't symlink — image build needs to COPY it).
- [ ] Update `bench/meta.json`:
  ```json
  "tests": ["baseline", "json", "baseline-h2", "json-tls"]
  ```
  (Drop `baseline-h3` if H3 isn't being validated through this image; keep if it is.)
- [ ] **Verify**: `cat bench/data/dataset.json | python3 -c 'import sys, json; d=json.load(sys.stdin); print(len(d), d[0].keys())'` → ~50 with the expected keys.
- [ ] Commit (use `commit-smart`): `feat(bench): vendor HttpArena dataset.json + bump meta.json profiles`

---

### Task 1: simdjson dataset loader

**Files:** `bench/handler.mojo`

- [ ] Add `from simdjson.parser import Parser` etc. at the top of `handler.mojo`. The Mojo build will resolve via `-I /path/to/json-simd-mojo` added in Task 8.
- [ ] Define `DatasetItem`:
  ```mojo
  struct DatasetItem(Copyable, Movable):
      var id: Int
      var price: Int
      var quantity: Int
      var active: Bool
      # Pre-escaped JSON byte fragments. These are *fragments*: they include the
      # surrounding quotes for strings and the brackets for tags/rating, so the
      # response renderer can write them verbatim without re-escaping per-request.
      var name_quoted: List[UInt8]            # "Alpha Widget"
      var category_quoted: List[UInt8]        # "electronics"
      var tags_array: List[UInt8]             # ["sale","heavy-duty","popular"]
      var rating_object: List[UInt8]          # {"score":48,"count":53}
  ```
- [ ] Add `def _load_dataset(path: String) raises -> List[DatasetItem]` that:
  - Reads file → bytes.
  - `Parser().parse(bytes^)` → `Document`.
  - Walks the root array. For each element, reads fields with `Value.get_uint` / `Value.get_bool` / `Value.get_string_length` + raw byte access for strings (or convert to Mojo `String` and re-escape — start simple, optimise if profiling says so).
  - Builds the pre-escaped fragments using the JSON writer from Task 2.
- [ ] At handler init, load once: dataset path comes from `DATA_DIR` env (default `/data`), file `dataset.json`. If file missing, log a warning and start with an empty list (so the bench still boots when the data mount is absent). Heap-allocate the list and stash a stable pointer like the static cache does.
- [ ] **Verify**: write a 30-line test that parses `bench/data/dataset.json` and asserts `len == 50`, `dataset[0].id == 1`, `dataset[0].price == 328`. Run via `mojo run`.
- [ ] Commit: `feat(bench): load dataset.json at boot via simdjson`

---

### Task 2: JSON writer module

**Files:** `bench/json_writer.mojo`

- [ ] `fn write_uint(buf: ref List[UInt8], v: UInt64)` — fast itoa: write decimal digits into `buf` without going through `String`. Use a 20-byte scratch on stack, fill back-to-front, copy forward. Inline-friendly.
- [ ] `fn write_int(buf: ref List[UInt8], v: Int64)` — handles sign + delegates to `write_uint`.
- [ ] `fn write_str_escaped(buf: ref List[UInt8], s: Span[UInt8])` — writes `"<escaped>"`. Only escape `"` and `\`; the dataset is ASCII so we don't need full Unicode escaping. **This is used at boot only**, never on the hot path.
- [ ] `fn write_bytes(buf: ref List[UInt8], b: Span[UInt8])` — `memcpy`-style append.
- [ ] **Verify**: small test that round-trips a few items: `write_uint(0)` → `"0"`, `write_uint(12345)` → `"12345"`, `write_str_escaped(b'a"b\\c')` → `"a\"b\\\\c"`.
- [ ] Commit: `feat(bench): add JSON writer primitives (fast itoa + escape)`

---

### Task 3: /json renderer + skeleton cache

**Files:** `bench/handler.mojo`

- [ ] Add `fn render_json_response(items: Span[DatasetItem], count: Int, m: Int, out: ref List[UInt8])` that emits the response body. Layout per item:
  ```
  {"id":<id>,"name":<name_quoted>,"category":<category_quoted>,
   "price":<price>,"quantity":<quantity>,"active":<true|false>,
   "tags":<tags_array>,"rating":<rating_object>,"total":<price*quantity*m>}
  ```
  Wrapped in `{"count":<count>,"items":[ ... ]}`. Items separated by `,`. `out` is a per-handler scratch `List[UInt8]` reset (`.clear()`) at the start of each call.
- [ ] **No skeleton cache in the first pass** — write items linearly. We measure first; only add the per-`count` cache if the linear renderer falls below ~50% of baseline2 RPS.
- [ ] Add a path parser: `_parse_json_path(path: String) -> (count: Int, m: Int)`. Accepts `/json/<count>?m=<m>`. Bound `count` to `[0, len(dataset)]`. Default `m=1` if missing.
- [ ] In the `BenchHandler.dispatch` (and the H2 coro body fn), branch:
  ```
  if path.startswith("/json/"):
      var (count, m) = _parse_json_path(path)
      render_json_response(dataset, count, m, out=scratch)
      respond(200, "application/json", scratch)
  ```
- [ ] **Verify**: against running launcher, run `validate.sh`'s exact 4 (count,m) pairs and parse via `python3 -c 'import json,sys; d=json.load(sys.stdin); ...'` to confirm `count`, `items.length`, `total` correctness.
- [ ] Commit: `feat(bench): add /json/{count}?m endpoint shared across H1/H2`

---

### Task 4: H1 server TLS mode

**Files:** `bench/h1_server.mojo`

- [ ] Read mode env at boot:
  ```mojo
  var tls_enabled = getenv_opt("BENCH_H1_TLS").value_or("0") == "1"
  var port = Int(getenv_opt("BENCH_H1_PORT").value_or(...).value())  # 8080 plaintext, 8081 TLS
  ```
- [ ] When `tls_enabled`:
  - Lift the rustls glue from `h2_server.mojo`: `RustlsLibrary`, `TlsServerConfig` from `cert_pem`/`key_pem`, ALPN list `["http/1.1"]`.
  - Wrap each accepted connection in a TLS server session; feed bytes through the rustls codec → H1 codec → handler → response → rustls codec → socket. Same submit/drain pattern as H2 but without h2 framing.
- [ ] When plaintext: today's path unchanged.
- [ ] Worker prefix: `[h1-w<id>]` in plaintext mode, `[h1tls-w<id>]` in TLS mode (read `BENCH_H1_ROLE` env injected by launcher, default `h1`).
- [ ] **Verify** plaintext: `curl 'http://127.0.0.1:8080/baseline2?a=1&b=2'` → `3`.
- [ ] **Verify** TLS: `BENCH_H1_TLS=1 BENCH_H1_PORT=8081 BENCH_H1_ROLE=h1tls ./bench/h1_server &` then `curl -sk --http1.1 'https://127.0.0.1:8081/baseline2?a=1&b=2'` → `3`, and `curl -sk -o/dev/null -w '%{http_version}\n' --http1.1 https://127.0.0.1:8081/json/1?m=1` → `1.1`.
- [ ] Commit: `refactor(bench): merge H1 plaintext + H1-over-TLS into one binary`

---

### Task 5: Launcher — h1tls role

**Files:** `bench/launcher.mojo`

- [ ] Add `h1tls` to `all_types`. When spawning an `h1tls` worker, set env `BENCH_H1_TLS=1 BENCH_H1_PORT=8081 BENCH_H1_ROLE=h1tls` for the child via `_setenv` before `execv` (already inherits parent environ; just set in parent before fork to keep it simple, then unset after). Cleanest: set env *just before* fork for that role, restore after — or pass via env that's specific per-role and the binary distinguishes by `BENCH_H1_ROLE`.
- [ ] `BENCH_PROTOCOL` filter accepts `h1`, `h1tls`, `h2`, `h3`. If unset, all four are launched.
- [ ] Both `h1` and `h1tls` invoke the same binary path (`_find_binary("h1_server")`), but with different env. Restart logic uses the same role string.
- [ ] **Verify**: `BENCH_WORKERS=1 BENCH_PROTOCOL=h1tls ./bench/launcher` → log shows `[h1tls-w0] h1-bench: listening on https://0.0.0.0:8081`. Smoke with curl above.
- [ ] **Verify** all four: `BENCH_WORKERS=1 ./bench/launcher` → 4 children, ports 8080/8081/8443tcp/8443udp all alive.
- [ ] Commit: `feat(bench/launcher): add h1tls role for H1-over-TLS worker`

---

### Task 6: H2 server — wire /json

**Files:** `bench/h2_server.mojo`

- [ ] Verify `bench_h2_body_fn` already routes through `BenchHandler.dispatch` (it should — Task 3 added the dispatch there). If H2 has its own dispatcher in handler.mojo, ensure both code paths converge on `render_json_response`.
- [ ] **Verify**: `curl -sk --http2 'https://127.0.0.1:8443/json/12?m=3'` → valid JSON with count=12, items.length=12, totals correct.
- [ ] Commit: `feat(bench/h2): support /json endpoint`

---

### Task 7: meta.json + run.sh

**Files:** `bench/meta.json`, `bench/run.sh`

- [ ] meta.json updated in Task 0; double-check.
- [ ] `bench/run.sh` add fourth binary launch: `BENCH_H1_TLS=1 BENCH_H1_PORT=8081 BENCH_H1_ROLE=h1tls "$H1_BIN" &` after the existing H1 plaintext launch. (Same binary, different env.)
- [ ] Commit: `feat(bench/run): launch H1 plaintext + H1-TLS sidecars`

---

### Task 8: build.sh + Dockerfile + .gitignore

**Files:** `bench/build.sh`, `bench/Dockerfile`, `.gitignore`

- [ ] `build.sh`: resolve `SIMDJSON_DIR="${SIMDJSON_DIR:-$(cd "$REPO_ROOT/../json-simd-mojo" && pwd)}"`. Pass `--build-context simdjson="$SIMDJSON_DIR"` to `docker build`.
- [ ] `Dockerfile`:
  - Add `COPY --from=simdjson . /simdjson` in build stage (after the `boucle` copy).
  - Append `-I /simdjson` to the `mojox build` invocation for `bench/h1_server.mojo`, `bench/h2_server.mojo`, `bench/handler.mojo`. (h3 doesn't need it unless we eventually pull dataset there too.)
  - `EXPOSE 8081` alongside existing 8080/8443.
  - `COPY bench/data/dataset.json /data/dataset.json` — image is now self-contained for the json profile.
- [ ] `.gitignore`: ensure `bench/data/dataset.json` is **tracked** (no ignore needed; this is the vendor copy).
- [ ] **Verify**: `bash bench/build.sh` → image `httparena-mojo-net` builds. `docker run --rm --network host httparena-mojo-net` boots all four workers (1 each by default if `BENCH_WORKERS=1` is set; full multi-process otherwise).
- [ ] Commit: `feat(bench/build): wire simdjson include path + ship dataset + expose 8081`

---

### Task 9: Validate via HttpArena

**Files:** none (external)

- [ ] From `bench/.httparena`: `./scripts/validate.sh mojo-net`. Expect PASS on `baseline`, `json`, `baseline-h2`, `json-tls` checks (validator covers Content-Type, count match, items.length, totals, ALPN negotiation on 8081).
- [ ] Capture failures and iterate.
- [ ] Commit follow-up fixes as needed.

---

### Task 10: Local benchmark — measure overhead

**Files:** none (record numbers in retrospective)

- [ ] Single-worker numbers: `BENCH_WORKERS=1 ./bench/launcher` then h2load against `/baseline2`, `/json/12?m=3`, both H1 and H1-TLS, plus H2 baseline + H2 json. Goal: read the `json / baseline2` ratio per protocol. Target band: 40–60% per the public leaderboard. Below 30% = investigate.
- [ ] Full multi-worker: same matrix with `BENCH_WORKERS=$(nproc)`.
- [ ] Record numbers in `plans/2026-04-25-bench-h1-consolidation-and-json-retrospective.md` along with simdjson dogfood feedback (any rough edges in the parser API for this use case).

---

## Spec requirement coverage

- HttpArena `json` profile: ✓ Task 3 (renderer) + Task 0 (meta).
- HttpArena `json-tls` profile: ✓ Task 4 (H1 TLS mode) + Task 5 (launcher h1tls) + Task 7 (run.sh).
- Eliminate H1 / H1-TLS duplication: ✓ Task 4 collapses both into one binary.
- Real-world feedback for `json-simd-mojo`: ✓ Task 1 + Task 10 retrospective.
- H2 unchanged in surface, just gets a new endpoint: ✓ Task 6.
- H3 untouched: ✓ (not in any task).

## Open questions / risks

- **simdjson-mojo string materialisation API.** `Value.get_string_length` returns length, but the snippet I read doesn't show how to *get the bytes*. Task 1 will surface this — if the API is awkward, log it for the retrospective. Worst case: fall back to a scalar string-byte read using the offset returned by `_payload`. This is exactly the kind of feedback the side project benefits from.
- **rustls ALPN list mutation in h1_server.** H2 server hardcodes `["h2"]`; we'll need it to accept `["http/1.1"]` when `BENCH_H1_TLS=1`. Should be a one-line list literal swap, but verify no other H2-specific assumption sneaks in.
- **Per-handler scratch buffer ownership across coroutines (H2).** If `bench_h2_body_fn` runs concurrently across streams on a single connection, we need one scratch buffer per stream, not per handler. Check the H2CoroServer surface during Task 6.
- **m default on `/json/N` (no `?m=`).** Reference go-fasthttp uses `m=1` if missing. Do the same.
- **Image-stage simdjson layout.** Task 8 assumes the package is importable as `simdjson` once `-I /simdjson` is on the include path. Confirm the package layout matches: `/simdjson/simdjson/__init__.mojo` — the include should be `/simdjson` (parent), not `/simdjson/simdjson`.
