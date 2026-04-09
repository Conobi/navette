# M2.5b — Helper Modules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the three protocol-agnostic helper modules sketched in §7 of the M2.5 spec (`priority.mojo`, `alt_svc.mojo`, `sse.mojo`) and wire them into the existing `src/http/` surface without changing the M2.5a trait shapes.

**Architecture:** Three small, independent, sans-I/O modules under `src/http/`. Priority and Alt-Svc are pure parser/serializer pairs backed by a couple of small structs. SSE is slightly larger: it wraps a `DetachedBody` (from M2.5a §5.5) in an incremental `EventStreamReader` and exposes a stateless writer function that serializes `ServerSentEvent` records into an `mut resp: ResponseWriter`. No changes to `src/http/handler.mojo` or `src/http/session.mojo`.

**Tech Stack:** Mojo 0.26.2 (`def` everywhere except `fn __del__(deinit self)`; `comptime` constants; `var` parameter for ownership transfer; explicit `.copy()` for move-only-via-list edge cases). Tests run via `bash scripts/run_tests.sh`. No FFI changes, no conformance vector changes, no boucle integration.

**Spec:** `specs/2026-04-07-m25-unified-http-api.md` — section numbers below refer to that spec.

**Scope of this plan:** **M2.5b only.** M2.5a is already shipped (merge commit `c93aaf9`, pushed to `origin/main`). The three files land as additive, tree-parallel work that does not touch HC-4's critical path.

---

## File structure

### New files (created in this plan)

| Path | Responsibility |
|---|---|
| `src/http/priority.mojo` | `Priority` struct + `parse_header(value) -> Priority` + `Priority.serialize_header(self) -> String`. RFC 9218 §4. |
| `src/http/alt_svc.mojo` | `Origin` (Dict key), `AltSvcEntry`, `parse_alt_svc(value) -> List[AltSvcEntry]`, `AltSvcCache { insert, lookup, clear, clear_expired }`. RFC 7838. |
| `src/http/sse.mojo` | `ServerSentEvent`, `EventStreamReader` (wraps `DetachedBody`, incremental parser), `try_write_event(mut resp, event)` free function for serialization. WHATWG event-stream subset. |
| `tests/test_priority.mojo` | §10.3 row 1 — parse + serialize against RFC 9218 examples |
| `tests/test_alt_svc.mojo` | §10.3 row 2 — parse + cache insert/lookup/expiry against RFC 7838 examples |
| `tests/test_sse.mojo` | §10.3 row 3 — reader parses sample streams; writer round-trips `ServerSentEvent` → bytes → reader |

### Modified files

| Path | Change |
|---|---|
| `src/http/__init__.mojo` | Add `from .priority import Priority`, `from .alt_svc import Origin, AltSvcEntry, AltSvcCache, parse_alt_svc`, `from .sse import ServerSentEvent, EventStreamReader, try_write_event`. |
| `scripts/run_tests.sh` | Append `test_priority`, `test_alt_svc`, `test_sse` to the `TESTS=()` array. |
| `docs/project-context.md` | Final task: mark M2.5b shipped in the milestone table and session history. |

### Files NOT touched

- `src/http/handler.mojo`, `src/http/session.mojo`, `src/http/mock_session.mojo` — M2.5a trait surface is frozen for this plan.
- `src/h1/*` — no wire-format changes.
- `conformance/**` — must continue passing 27/27 untouched.
- `examples/reverse_proxy/main.mojo` — untouched.

---

## Spec ↔ implementation reconciliation (read first)

Two minor deviations from §7 carried over from the M2.5a implementation discipline:

1. **Test layout.** §10.3 sketches `tests/http/test_priority.mojo`. The actual repo layout is flat: `tests/test_priority.mojo`, matching every other test file under `tests/`. Plan uses the flat layout.
2. **`EventStreamWriter` is a free function, not a struct with stored `UnsafePointer[ResponseWriter, …]`.** The spec's sketch of `EventStreamWriter { var _resp: UnsafePointer[ResponseWriter, MutAnyOrigin] }` contradicts its own doc ("caller passes a mutable reference each time"). Storing an unchecked pointer to a `mut resp` parameter is fragile in Mojo 0.26.2 and unnecessary — SSE writers need no per-connection state, so a free function `try_write_event(mut resp: ResponseWriter, event: ServerSentEvent) raises -> WriteResult` is both simpler and matches the spec's "does NOT take ownership" intent. The plan uses this form.

Everything else in §7 is implemented as sketched.

---

## Build order rationale

The three modules are independent of each other and of M2.5a's trait surface *except* SSE's `EventStreamReader`, which wraps `DetachedBody` (§5.5). The order is:

1. **Priority** first — it's the smallest and has no dependencies on anything beyond `String`.
2. **Alt-Svc** second — parser is harder than Priority's, and `AltSvcCache` forces us to verify `Dict[Origin, List[AltSvcEntry]]` compiles with our `Origin` struct as a `KeyElement` (Mojo 0.26.2 constraints). Building this next isolates any container-trait surprises before they pollute SSE.
3. **SSE** third — consumes `DetachedBody` and `ResponseWriter`. If anything is going to trip on M2.5a's live type surface, it will be here.

After each phase, tests green → commit → next phase. Final Task 15 is the docs update / acceptance gate.

---

## Conventions for every task

- **Mojo version: 0.26.2.** `def` for all methods except `fn __del__(deinit self)`. Move ctor: `def __init__(out self, *, deinit take: Self)`. Copy ctor: `def __init__(out self, *, other: Self)`. Explicit `.copy()` for any non-`ImplicitlyCopyable` types. `comptime` constants instead of `@parameter`.
- **Tests use `tests._test_util` helpers** (not `from testing import ...`). Available: `assert_true(cond, msg)`, `assert_false(cond, msg)`, `assert_equal_int(got, expected, msg)`, `assert_equal_str(got, expected, msg)`. Each test function must be `def name() raises:` and `main() raises:` ends with `print("test_X: all tests passed")`.
- **Every new test file must be registered** in `scripts/run_tests.sh`'s `TESTS=()` array or it won't run.
- **List literal syntax:** `var l: List[UInt8] = [UInt8(1), UInt8(2)]`, not `List[UInt8](UInt8(1), UInt8(2))` (the variadic ctor doesn't compile in 0.26.2).
- **Imports inside src/:** `from src.http.handler import ...`, mirroring existing M2.5a layout.
- **Commit message style:** match the M2.5a history (`git log --oneline -15` shows lowercase imperative subject with a `http:` prefix for `src/http/` work).
- **Mojo MCP usage:** when unsure about a 0.26.2 API surface, use `mcp__mojo-mcp__lookup` / `validate` before writing the impl.

---

## Phase 1 — Priority (RFC 9218)

The `Priority` header is a Structured Fields dictionary with two possible members: `u` (urgency, integer 0..7, default 3) and `i` (incremental, boolean, default false). RFC 9218 §4. The parser must accept `u=1`, `u=5, i`, `u=3, i=?0`, and round-trip defaults away.

### Task 1: `Priority` struct + default

**Files:**
- Create: `src/http/priority.mojo`
- Test: `tests/test_priority.mojo`

- [ ] **Step 1: Write failing test**
```mojo
# tests/test_priority.mojo
#
# Unit tests for Priority (RFC 9218, M2.5b §7.1).
from src.http.priority import Priority
from tests._test_util import assert_true, assert_false, assert_equal_int, assert_equal_str


def test_default_priority() raises:
    var p = Priority.default()
    assert_equal_int(p.urgency, 3, "default.urgency")
    assert_false(p.incremental, "default.incremental")


def main() raises:
    test_default_priority()
    print("test_priority: all tests passed")
```

- [ ] **Step 2: Verify it fails**
Run: `bash scripts/run_tests.sh`
Expected: FAIL — `cannot find module 'src.http.priority'`.

- [ ] **Step 3: Write minimal implementation**
```mojo
# src/http/priority.mojo
#
# RFC 9218 Priority header (M2.5b §7.1). Pure parse/serialize — no I/O, no
# integration with the H2/H3 PRIORITY_UPDATE frame (that lands in HC-4/M5).

comptime DEFAULT_URGENCY: Int = 3


struct Priority(Copyable, Movable):
    """RFC 9218 §4 Priority header value."""

    var urgency: Int        # 0..7; default 3
    var incremental: Bool   # default False

    def __init__(out self, *, urgency: Int, incremental: Bool):
        self.urgency = urgency
        self.incremental = incremental

    def __init__(out self, *, other: Self):
        self.urgency = other.urgency
        self.incremental = other.incremental

    def __init__(out self, *, deinit take: Self):
        self.urgency = take.urgency
        self.incremental = take.incremental

    @staticmethod
    def default() -> Self:
        """RFC 9218 §4.1 / §4.2 defaults: u=3, i=false."""
        return Self(urgency=DEFAULT_URGENCY, incremental=False)
```

- [ ] **Step 4: Register the test**
Append `test_priority` to the `TESTS=()` array in `scripts/run_tests.sh`.

- [ ] **Step 5: Verify it passes**
Run: `bash scripts/run_tests.sh`
Expected: PASS — all pre-existing tests still green, `test_priority` reports one passing test.

- [ ] **Step 6: Commit**
```bash
git add src/http/priority.mojo tests/test_priority.mojo scripts/run_tests.sh
git commit -m "http: add Priority struct with RFC 9218 defaults (§7.1)"
```

---

### Task 2: `Priority.parse_header`

**Files:**
- Modify: `src/http/priority.mojo` (append `parse_header` staticmethod)
- Modify: `tests/test_priority.mojo` (add parse cases)

- [ ] **Step 1: Extend the test**
Append to `tests/test_priority.mojo` before `def main()`:
```mojo
def test_parse_urgency_only() raises:
    var p = Priority.parse_header(String("u=1"))
    assert_equal_int(p.urgency, 1, "u=1.urgency")
    assert_false(p.incremental, "u=1.incremental")


def test_parse_urgency_with_incremental_bare() raises:
    var p = Priority.parse_header(String("u=5, i"))
    assert_equal_int(p.urgency, 5, "u=5,i.urgency")
    assert_true(p.incremental, "u=5,i.incremental")


def test_parse_explicit_incremental_false() raises:
    var p = Priority.parse_header(String("u=3, i=?0"))
    assert_equal_int(p.urgency, 3, "i=?0.urgency")
    assert_false(p.incremental, "i=?0.incremental")


def test_parse_explicit_incremental_true() raises:
    var p = Priority.parse_header(String("u=2, i=?1"))
    assert_equal_int(p.urgency, 2, "i=?1.urgency")
    assert_true(p.incremental, "i=?1.incremental")


def test_parse_empty_header_yields_defaults() raises:
    var p = Priority.parse_header(String(""))
    assert_equal_int(p.urgency, 3, "empty.urgency")
    assert_false(p.incremental, "empty.incremental")


def test_parse_out_of_range_urgency_raises() raises:
    var raised = False
    try:
        var _p = Priority.parse_header(String("u=9"))
    except:
        raised = True
    assert_true(raised, "out_of_range_raises")
```

Update `main()`:
```mojo
def main() raises:
    test_default_priority()
    test_parse_urgency_only()
    test_parse_urgency_with_incremental_bare()
    test_parse_explicit_incremental_false()
    test_parse_explicit_incremental_true()
    test_parse_empty_header_yields_defaults()
    test_parse_out_of_range_urgency_raises()
    print("test_priority: all tests passed")
```

- [ ] **Step 2: Verify it fails**
Run: `bash scripts/run_tests.sh`
Expected: FAIL — `parse_header` not found on `Priority`.

- [ ] **Step 3: Write minimal implementation**
Append to `src/http/priority.mojo`:
```mojo
    @staticmethod
    def parse_header(value: String) raises -> Self:
        """Parse an RFC 9218 §4 Priority header value. Accepts `u=N`
        (0..7), bare `i`, and explicit `i=?0` / `i=?1`. Unknown keys are
        ignored per Structured Fields forward-compatibility. Raises if the
        urgency is outside 0..7 or if `u=` is followed by a non-integer."""
        var urgency = DEFAULT_URGENCY
        var incremental = False

        var i = 0
        var n = len(value)
        while i < n:
            # Skip leading whitespace / commas
            while i < n and (value[i] == " " or value[i] == "," or value[i] == "\t"):
                i += 1
            if i >= n:
                break

            # Read the key (letters until '=' or ',' or end)
            var key_start = i
            while i < n and value[i] != "=" and value[i] != "," and value[i] != " " and value[i] != "\t":
                i += 1
            var key = value[key_start:i]

            # Read optional '=' value
            var has_value = False
            var val_str = String("")
            if i < n and value[i] == "=":
                i += 1
                has_value = True
                var val_start = i
                while i < n and value[i] != "," and value[i] != " " and value[i] != "\t":
                    i += 1
                val_str = value[val_start:i]

            if key == "u":
                if not has_value:
                    raise Error("Priority.parse_header: 'u' key requires a value")
                urgency = atol(val_str)
                if urgency < 0 or urgency > 7:
                    raise Error("Priority.parse_header: urgency out of range 0..7")
            elif key == "i":
                if not has_value:
                    incremental = True
                elif val_str == "?1":
                    incremental = True
                elif val_str == "?0":
                    incremental = False
                else:
                    raise Error("Priority.parse_header: 'i' value must be '?0' or '?1'")
            # Unknown keys are silently ignored (forward compat).

        return Self(urgency=urgency, incremental=incremental)
```

Note: `atol` is the Mojo 0.26.2 string-to-int conversion. If `atol` is not the correct name in 0.26.2, verify via `mcp__mojo-mcp__validate` with a minimal snippet before implementation; fall back to `Int(val_str)` or a hand-rolled digit loop if needed.

- [ ] **Step 4: Verify it passes**
Run: `bash scripts/run_tests.sh`
Expected: PASS — all six parse test cases green.

- [ ] **Step 5: Commit**
```bash
git add src/http/priority.mojo tests/test_priority.mojo
git commit -m "http: add Priority.parse_header (RFC 9218 §4)"
```

---

### Task 3: `Priority.serialize_header`

**Files:**
- Modify: `src/http/priority.mojo` (append `serialize_header` method)
- Modify: `tests/test_priority.mojo` (add serialize cases)

- [ ] **Step 1: Extend the test**
Append before `def main()`:
```mojo
def test_serialize_default_omits_all() raises:
    var p = Priority.default()
    assert_equal_str(p.serialize_header(), String(""), "default.serialize")


def test_serialize_non_default_urgency() raises:
    var p = Priority(urgency=1, incremental=False)
    assert_equal_str(p.serialize_header(), String("u=1"), "u1.serialize")


def test_serialize_incremental_only() raises:
    var p = Priority(urgency=3, incremental=True)
    assert_equal_str(p.serialize_header(), String("i"), "i.serialize")


def test_serialize_both() raises:
    var p = Priority(urgency=5, incremental=True)
    assert_equal_str(p.serialize_header(), String("u=5, i"), "u5i.serialize")


def test_roundtrip_non_default() raises:
    var original = Priority(urgency=2, incremental=True)
    var encoded = original.serialize_header()
    var parsed = Priority.parse_header(encoded)
    assert_equal_int(parsed.urgency, 2, "roundtrip.urgency")
    assert_true(parsed.incremental, "roundtrip.incremental")
```

Update `main()` to call all five new tests.

- [ ] **Step 2: Verify it fails**
Run: `bash scripts/run_tests.sh`
Expected: FAIL — `serialize_header` not found.

- [ ] **Step 3: Write minimal implementation**
Append to `src/http/priority.mojo`:
```mojo
    def serialize_header(self) -> String:
        """Render to an RFC 9218 §4 Priority header value. Defaults are
        omitted — an empty string is returned when both fields are at their
        defaults. Non-default urgency is rendered as `u=N`; incremental is
        rendered as the bare token `i` when true."""
        var parts = List[String]()
        if self.urgency != DEFAULT_URGENCY:
            parts.append(String("u=") + String(self.urgency))
        if self.incremental:
            parts.append(String("i"))

        if len(parts) == 0:
            return String("")
        var out = parts[0].copy()
        for idx in range(1, len(parts)):
            out += String(", ")
            out += parts[idx]
        return out^
```

- [ ] **Step 4: Verify it passes**
Run: `bash scripts/run_tests.sh`
Expected: PASS — all Priority tests green, including roundtrip.

- [ ] **Step 5: Re-export from `src/http/__init__.mojo`**
Add this line to `src/http/__init__.mojo` (order: after `Response`):
```mojo
from .priority import Priority
```

Then re-run `bash scripts/run_tests.sh` to ensure nothing broke.

- [ ] **Step 6: Commit**
```bash
git add src/http/priority.mojo tests/test_priority.mojo src/http/__init__.mojo
git commit -m "http: add Priority.serialize_header + re-export (§7.1)"
```

---

## Phase 2 — Alt-Svc (RFC 7838)

The `Alt-Svc` header tells clients that the origin also speaks a different ALPN on a different host:port. Format:

```
Alt-Svc: h3=":443"; ma=3600
Alt-Svc: h2="alt.example.com:443"; ma=86400, h3=":443"; ma=3600
Alt-Svc: clear
```

Phase 2 lands the struct, the parser, and a small `AltSvcCache` (used later by M6 to pick a protocol for a given origin).

### Task 4: `Origin` key struct

**Files:**
- Create: `src/http/alt_svc.mojo`
- Test: `tests/test_alt_svc.mojo`

- [ ] **Step 1: Write failing test**
```mojo
# tests/test_alt_svc.mojo
#
# Unit tests for Alt-Svc (RFC 7838, M2.5b §7.2).
from src.http.alt_svc import Origin
from tests._test_util import assert_true, assert_false, assert_equal_int, assert_equal_str


def test_origin_roundtrip() raises:
    var o = Origin(scheme=String("https"), host=String("example.com"), port=UInt16(443))
    assert_equal_str(o.scheme, String("https"), "origin.scheme")
    assert_equal_str(o.host, String("example.com"), "origin.host")
    assert_equal_int(Int(o.port), 443, "origin.port")


def test_origin_equality() raises:
    var a = Origin(scheme=String("https"), host=String("a.test"), port=UInt16(443))
    var b = Origin(scheme=String("https"), host=String("a.test"), port=UInt16(443))
    var c = Origin(scheme=String("https"), host=String("b.test"), port=UInt16(443))
    assert_true(a == b, "eq.ab")
    assert_false(a == c, "ne.ac")


def main() raises:
    test_origin_roundtrip()
    test_origin_equality()
    print("test_alt_svc: all tests passed")
```

- [ ] **Step 2: Verify it fails**
Run: `bash scripts/run_tests.sh`
Expected: FAIL — `src.http.alt_svc` module not found.

- [ ] **Step 3: Write minimal implementation**
```mojo
# src/http/alt_svc.mojo
#
# RFC 7838 Alt-Svc header (M2.5b §7.2). Ships parsing, the entry struct,
# and an in-memory AltSvcCache keyed by Origin that M6's HttpClient will
# consult during connection establishment.

from std.collections.dict import Dict


struct Origin(Copyable, Movable, Hashable, EqualityComparable):
    """Origin key for the Alt-Svc cache: (scheme, host, port)."""

    var scheme: String   # "https" or "http"
    var host: String
    var port: UInt16

    def __init__(out self, *, scheme: String, host: String, port: UInt16):
        self.scheme = scheme
        self.host = host
        self.port = port

    def __init__(out self, *, other: Self):
        self.scheme = other.scheme.copy()
        self.host = other.host.copy()
        self.port = other.port

    def __init__(out self, *, deinit take: Self):
        self.scheme = take.scheme^
        self.host = take.host^
        self.port = take.port

    def __hash__(self) -> UInt64:
        return hash(self.scheme) ^ hash(self.host) ^ UInt64(self.port)

    def __eq__(self, rhs: Self) -> Bool:
        return (
            self.scheme == rhs.scheme
            and self.host == rhs.host
            and self.port == rhs.port
        )

    def __ne__(self, rhs: Self) -> Bool:
        return not (self == rhs)
```

- [ ] **Step 4: Register the test**
Append `test_alt_svc` to the `TESTS=()` array in `scripts/run_tests.sh`.

- [ ] **Step 5: Verify it passes**
Run: `bash scripts/run_tests.sh`
Expected: PASS.

- [ ] **Step 6: Commit**
```bash
git add src/http/alt_svc.mojo tests/test_alt_svc.mojo scripts/run_tests.sh
git commit -m "http: add Origin key struct for Alt-Svc (§7.2)"
```

---

### Task 5: `AltSvcEntry`

**Files:**
- Modify: `src/http/alt_svc.mojo` (append `AltSvcEntry`)
- Modify: `tests/test_alt_svc.mojo` (add entry tests)

- [ ] **Step 1: Extend the test**
Append before `def main()`:
```mojo
def test_alt_svc_entry_construction() raises:
    var e = AltSvcEntry(
        protocol=String("h3"),
        host=String(""),
        port=UInt16(443),
        max_age_secs=UInt(3600),
        persist=False,
    )
    assert_equal_str(e.protocol, String("h3"), "entry.protocol")
    assert_equal_str(e.host, String(""), "entry.host_empty")
    assert_equal_int(Int(e.port), 443, "entry.port")
    assert_equal_int(Int(e.max_age_secs), 3600, "entry.ma")
    assert_false(e.persist, "entry.persist")
```

And add `AltSvcEntry` to the `from src.http.alt_svc import` line at the top.
Update `main()` to call `test_alt_svc_entry_construction()`.

- [ ] **Step 2: Verify it fails**
Run: `bash scripts/run_tests.sh`
Expected: FAIL — `AltSvcEntry` undefined.

- [ ] **Step 3: Write minimal implementation**
Append to `src/http/alt_svc.mojo`:
```mojo
struct AltSvcEntry(Copyable, Movable):
    """One alternative service advertisement from an Alt-Svc header."""

    var protocol: String       # e.g. "h3", "h2", "h2c", "http/1.1"
    var host: String           # empty = same as origin
    var port: UInt16
    var max_age_secs: UInt     # RFC 7838 §3 — default 24h per RFC
    var persist: Bool          # "persist=1" parameter

    def __init__(
        out self,
        *,
        protocol: String,
        host: String,
        port: UInt16,
        max_age_secs: UInt,
        persist: Bool,
    ):
        self.protocol = protocol
        self.host = host
        self.port = port
        self.max_age_secs = max_age_secs
        self.persist = persist

    def __init__(out self, *, other: Self):
        self.protocol = other.protocol.copy()
        self.host = other.host.copy()
        self.port = other.port
        self.max_age_secs = other.max_age_secs
        self.persist = other.persist

    def __init__(out self, *, deinit take: Self):
        self.protocol = take.protocol^
        self.host = take.host^
        self.port = take.port
        self.max_age_secs = take.max_age_secs
        self.persist = take.persist
```

- [ ] **Step 4: Verify it passes**
Run: `bash scripts/run_tests.sh`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/http/alt_svc.mojo tests/test_alt_svc.mojo
git commit -m "http: add AltSvcEntry struct (§7.2)"
```

---

### Task 6: `parse_alt_svc` free function

**Files:**
- Modify: `src/http/alt_svc.mojo` (append `parse_alt_svc`)
- Modify: `tests/test_alt_svc.mojo` (add parse cases)

- [ ] **Step 1: Extend the test**
Append before `def main()`:
```mojo
def test_parse_single_entry_h3_default_host() raises:
    var entries = parse_alt_svc(String("h3=\":443\"; ma=3600"))
    assert_equal_int(len(entries), 1, "single.count")
    assert_equal_str(entries[0].protocol, String("h3"), "single.protocol")
    assert_equal_str(entries[0].host, String(""), "single.host_default")
    assert_equal_int(Int(entries[0].port), 443, "single.port")
    assert_equal_int(Int(entries[0].max_age_secs), 3600, "single.ma")
    assert_false(entries[0].persist, "single.persist")


def test_parse_multi_entry() raises:
    var entries = parse_alt_svc(
        String("h2=\"alt.example.com:443\"; ma=86400, h3=\":443\"; ma=3600")
    )
    assert_equal_int(len(entries), 2, "multi.count")
    assert_equal_str(entries[0].protocol, String("h2"), "multi[0].proto")
    assert_equal_str(entries[0].host, String("alt.example.com"), "multi[0].host")
    assert_equal_int(Int(entries[0].port), 443, "multi[0].port")
    assert_equal_int(Int(entries[1].max_age_secs), 3600, "multi[1].ma")


def test_parse_clear_returns_empty_list() raises:
    var entries = parse_alt_svc(String("clear"))
    assert_equal_int(len(entries), 0, "clear.empty")


def test_parse_persist_flag() raises:
    var entries = parse_alt_svc(String("h3=\":443\"; ma=3600; persist=1"))
    assert_equal_int(len(entries), 1, "persist.count")
    assert_true(entries[0].persist, "persist.flag")
```

Add `parse_alt_svc` to the imports at the top of the file.
Update `main()` to call all four new tests.

- [ ] **Step 2: Verify it fails**
Run: `bash scripts/run_tests.sh`
Expected: FAIL — `parse_alt_svc` undefined.

- [ ] **Step 3: Write minimal implementation**
Append to `src/http/alt_svc.mojo`:
```mojo
# RFC 7838 §3: default max-age is 24 hours.
comptime _DEFAULT_MAX_AGE_SECS: UInt = UInt(86400)


def parse_alt_svc(value: String) raises -> List[AltSvcEntry]:
    """Parse an Alt-Svc header value into a list of AltSvcEntry records.
    The special value `clear` returns an empty list (RFC 7838 §3).

    Each entry is of the form `alpn="host:port"[;ma=N][;persist=1]`. The
    `host` component may be empty (meaning "same as the origin host"); the
    port is always required.

    Raises on malformed input: missing `=`, missing quotes, missing port,
    non-integer `ma` / `persist` values."""
    var out = List[AltSvcEntry]()

    # RFC 7838 §3 "clear" clears the cache.
    var trimmed = _strip_ws(value)
    if trimmed == "clear":
        return out^
    if len(trimmed) == 0:
        return out^

    # Split the header into top-level entries by ',' that is NOT inside
    # a quoted "host:port" string.
    var entries_raw = _split_top_level(trimmed, ",")
    for i in range(len(entries_raw)):
        var entry_str = _strip_ws(entries_raw[i])
        if len(entry_str) == 0:
            continue
        out.append(_parse_one_entry(entry_str))
    return out^


def _strip_ws(s: String) -> String:
    var n = len(s)
    var start = 0
    while start < n and (s[start] == " " or s[start] == "\t"):
        start += 1
    var end = n
    while end > start and (s[end - 1] == " " or s[end - 1] == "\t"):
        end -= 1
    return s[start:end]


def _split_top_level(s: String, sep: String) -> List[String]:
    """Split by `sep` but skip separators inside double-quoted strings."""
    var out = List[String]()
    var n = len(s)
    var i = 0
    var seg_start = 0
    var in_quotes = False
    while i < n:
        var c = s[i]
        if c == "\"":
            in_quotes = not in_quotes
        elif (not in_quotes) and s[i:i + len(sep)] == sep:
            out.append(s[seg_start:i])
            i += len(sep)
            seg_start = i
            continue
        i += 1
    out.append(s[seg_start:n])
    return out^


def _parse_one_entry(entry: String) raises -> AltSvcEntry:
    # Split at the first '=' to separate protocol from `"host:port"; params`
    var n = len(entry)
    var eq = -1
    var i = 0
    while i < n:
        if entry[i] == "=":
            eq = i
            break
        i += 1
    if eq < 0:
        raise Error("parse_alt_svc: entry missing '=' → " + entry)

    var protocol = _strip_ws(entry[0:eq])
    var rest = _strip_ws(entry[eq + 1:n])

    # rest should start with '"host:port"' then optional `; params`
    if len(rest) == 0 or rest[0] != "\"":
        raise Error("parse_alt_svc: expected quoted host:port → " + entry)
    var close_quote = -1
    var j = 1
    while j < len(rest):
        if rest[j] == "\"":
            close_quote = j
            break
        j += 1
    if close_quote < 0:
        raise Error("parse_alt_svc: unterminated quoted host:port → " + entry)

    var host_port = rest[1:close_quote]
    # Split host:port — host may be empty.
    var colon = -1
    var k = 0
    while k < len(host_port):
        if host_port[k] == ":":
            colon = k
            break
        k += 1
    if colon < 0:
        raise Error("parse_alt_svc: missing port in host:port → " + host_port)
    var host = host_port[0:colon]
    var port_str = host_port[colon + 1:len(host_port)]
    var port = UInt16(atol(port_str))

    # Params after the close quote, separated by ';'
    var max_age = _DEFAULT_MAX_AGE_SECS
    var persist = False
    var params_str = rest[close_quote + 1:len(rest)]
    var params = _split_top_level(params_str, ";")
    for pi in range(len(params)):
        var p = _strip_ws(params[pi])
        if len(p) == 0:
            continue
        # Expect "name=value"
        var pe = -1
        var pj = 0
        while pj < len(p):
            if p[pj] == "=":
                pe = pj
                break
            pj += 1
        if pe < 0:
            continue  # bare param — forward compat, ignore
        var pname = _strip_ws(p[0:pe])
        var pval = _strip_ws(p[pe + 1:len(p)])
        if pname == "ma":
            max_age = UInt(atol(pval))
        elif pname == "persist":
            persist = (pval == "1")
        # unknown params ignored

    return AltSvcEntry(
        protocol=protocol,
        host=host,
        port=port,
        max_age_secs=max_age,
        persist=persist,
    )
```

- [ ] **Step 4: Verify it passes**
Run: `bash scripts/run_tests.sh`
Expected: PASS — all four parse cases green.

- [ ] **Step 5: Commit**
```bash
git add src/http/alt_svc.mojo tests/test_alt_svc.mojo
git commit -m "http: add parse_alt_svc for RFC 7838 (§7.2)"
```

---

### Task 7: `AltSvcCache`

**Files:**
- Modify: `src/http/alt_svc.mojo` (append `AltSvcCache`)
- Modify: `tests/test_alt_svc.mojo` (add cache tests)

- [ ] **Step 1: Extend the test**
Append before `def main()`:
```mojo
def test_cache_insert_and_lookup() raises:
    var cache = AltSvcCache()
    var origin = Origin(scheme=String("https"), host=String("example.com"), port=UInt16(443))
    var entries = parse_alt_svc(String("h3=\":443\"; ma=3600"))
    cache.insert(Origin(other=origin), entries^, UInt(1000))
    var found = cache.lookup(origin, UInt(2000))
    assert_equal_int(len(found), 1, "lookup.count")
    assert_equal_str(found[0].protocol, String("h3"), "lookup.proto")


def test_cache_lookup_expired_returns_empty() raises:
    var cache = AltSvcCache()
    var origin = Origin(scheme=String("https"), host=String("a.test"), port=UInt16(443))
    var entries = parse_alt_svc(String("h3=\":443\"; ma=10"))
    cache.insert(Origin(other=origin), entries^, UInt(1000))
    # now = 2000, received_at = 1000, ma = 10 → expired
    var found = cache.lookup(origin, UInt(2000))
    assert_equal_int(len(found), 0, "expired.empty")


def test_cache_clear() raises:
    var cache = AltSvcCache()
    var origin = Origin(scheme=String("https"), host=String("c.test"), port=UInt16(443))
    var entries = parse_alt_svc(String("h3=\":443\"; ma=3600"))
    cache.insert(Origin(other=origin), entries^, UInt(1000))
    cache.clear(origin)
    var found = cache.lookup(origin, UInt(1500))
    assert_equal_int(len(found), 0, "clear.empty")


def test_cache_clear_expired_prunes() raises:
    var cache = AltSvcCache()
    var fresh = Origin(scheme=String("https"), host=String("fresh.test"), port=UInt16(443))
    var stale = Origin(scheme=String("https"), host=String("stale.test"), port=UInt16(443))
    var fresh_entries = parse_alt_svc(String("h3=\":443\"; ma=3600"))
    var stale_entries = parse_alt_svc(String("h3=\":443\"; ma=10"))
    cache.insert(Origin(other=fresh), fresh_entries^, UInt(1000))
    cache.insert(Origin(other=stale), stale_entries^, UInt(1000))
    cache.clear_expired(UInt(2000))
    var fresh_found = cache.lookup(fresh, UInt(2000))
    var stale_found = cache.lookup(stale, UInt(2000))
    assert_equal_int(len(fresh_found), 1, "fresh.present")
    assert_equal_int(len(stale_found), 0, "stale.removed")
```

Add `AltSvcCache` to the imports.
Update `main()` to call all four new tests.

- [ ] **Step 2: Verify it fails**
Run: `bash scripts/run_tests.sh`
Expected: FAIL — `AltSvcCache` undefined.

- [ ] **Step 3: Write minimal implementation**
Append to `src/http/alt_svc.mojo`:
```mojo
struct AltSvcCache(Movable):
    """In-memory cache of Alt-Svc advertisements, keyed by Origin. Used by
    M6's HttpClient during connection establishment to decide whether to
    upgrade an HTTP/1.1 connection to H2 or H3. Not thread-safe — callers
    that need concurrent access wrap it in a mutex at the M6 layer."""

    var _entries: Dict[Origin, List[AltSvcEntry]]
    var _received_at: Dict[Origin, UInt]   # when insert() was called

    def __init__(out self):
        self._entries = Dict[Origin, List[AltSvcEntry]]()
        self._received_at = Dict[Origin, UInt]()

    def __init__(out self, *, deinit take: Self):
        self._entries = take._entries^
        self._received_at = take._received_at^

    def insert(
        mut self,
        var origin: Origin,
        var entries: List[AltSvcEntry],
        received_at: UInt,
    ):
        """Replace any existing entries for `origin` with the supplied list.
        `received_at` is the wall-clock time (seconds since some epoch the
        caller controls) when the Alt-Svc header was received; lookup uses
        it together with each entry's max_age_secs to compute expiry."""
        self._entries[Origin(other=origin)] = entries^
        self._received_at[origin^] = received_at

    def lookup(self, origin: Origin, now: UInt) -> List[AltSvcEntry]:
        """Return all non-expired entries for `origin`. Returns an empty
        list if the origin is unknown or every entry has expired."""
        var out = List[AltSvcEntry]()
        if origin not in self._entries:
            return out^
        var received_at = self._received_at[origin]
        ref entries = self._entries[origin]
        for i in range(len(entries)):
            if received_at + entries[i].max_age_secs > now:
                out.append(AltSvcEntry(other=entries[i]))
        return out^

    def clear(mut self, var origin: Origin):
        """Drop all entries for `origin`, regardless of expiry."""
        if origin in self._entries:
            _ = self._entries.pop(Origin(other=origin))
            _ = self._received_at.pop(origin^)

    def clear_expired(mut self, now: UInt):
        """Prune origins for which every entry has expired at `now`."""
        var to_drop = List[Origin]()
        for kv in self._entries.items():
            var origin_copy = Origin(other=kv.key)
            var received_at = self._received_at[kv.key]
            var any_live = False
            ref entries = kv.value
            for i in range(len(entries)):
                if received_at + entries[i].max_age_secs > now:
                    any_live = True
                    break
            if not any_live:
                to_drop.append(origin_copy^)
        for j in range(len(to_drop)):
            _ = self._entries.pop(Origin(other=to_drop[j]))
            _ = self._received_at.pop(to_drop[j]^)
```

Note: `Dict.items()` returns key-value pairs; the iteration + mutation pattern in `clear_expired` deliberately collects keys first then mutates in a second pass to avoid iterator invalidation. If Mojo 0.26.2's `Dict.pop(key)` signature doesn't match `_ = self._entries.pop(origin^)`, verify via `mcp__mojo-mcp__validate` with a minimal snippet; fall back to a two-step `dict[key] = List[AltSvcEntry]()` + re-constructing the dict if `pop` is missing.

- [ ] **Step 4: Verify it passes**
Run: `bash scripts/run_tests.sh`
Expected: PASS — all four cache tests green.

- [ ] **Step 5: Re-export from `src/http/__init__.mojo`**
Add this line to `src/http/__init__.mojo` (order: after `Priority`):
```mojo
from .alt_svc import Origin, AltSvcEntry, AltSvcCache, parse_alt_svc
```

Then re-run `bash scripts/run_tests.sh` to ensure nothing broke.

- [ ] **Step 6: Commit**
```bash
git add src/http/alt_svc.mojo tests/test_alt_svc.mojo src/http/__init__.mojo
git commit -m "http: add AltSvcCache with insert/lookup/clear + re-export (§7.2)"
```

---

## Phase 3 — SSE (WHATWG event-stream)

The smallest useful subset of the WHATWG event-stream spec: parse multi-line `data:` events with optional `event:`, `id:`, `retry:` fields, dispatch on blank line, concatenate `data:` lines with `\n`. Consumes a `DetachedBody` (from M2.5a §5.5) via the incremental reader; writer is a stateless free function.

### Task 8: `ServerSentEvent`

**Files:**
- Create: `src/http/sse.mojo`
- Test: `tests/test_sse.mojo`

- [ ] **Step 1: Write failing test**
```mojo
# tests/test_sse.mojo
#
# Unit tests for Server-Sent Events (WHATWG event-stream, M2.5b §7.3).
from std.collections.optional import Optional
from src.http.sse import ServerSentEvent
from tests._test_util import assert_true, assert_false, assert_equal_int, assert_equal_str


def test_event_default_fields() raises:
    var e = ServerSentEvent()
    assert_false(Bool(e.event), "default.event_none")
    assert_equal_str(e.data, String(""), "default.data_empty")
    assert_false(Bool(e.id), "default.id_none")
    assert_false(Bool(e.retry), "default.retry_none")


def test_event_populated() raises:
    var e = ServerSentEvent()
    e.event = Optional[String](String("message"))
    e.data = String("hello")
    e.id = Optional[String](String("42"))
    e.retry = Optional[UInt](UInt(5000))
    assert_equal_str(e.event.value(), String("message"), "populated.event")
    assert_equal_str(e.data, String("hello"), "populated.data")
    assert_equal_str(e.id.value(), String("42"), "populated.id")
    assert_equal_int(Int(e.retry.value()), 5000, "populated.retry")


def main() raises:
    test_event_default_fields()
    test_event_populated()
    print("test_sse: all tests passed")
```

- [ ] **Step 2: Verify it fails**
Run: `bash scripts/run_tests.sh`
Expected: FAIL — `src.http.sse` not found.

- [ ] **Step 3: Write minimal implementation**
```mojo
# src/http/sse.mojo
#
# Server-Sent Events (text/event-stream) — M2.5b §7.3.
#
# WHATWG HTML Living Standard §9.2 "Server-sent events" subset:
#   https://html.spec.whatwg.org/multipage/server-sent-events.html
#
# Not implemented in v1: UTF-8 BOM stripping (assume UTF-8 input),
# cross-field UTF-8 validation (the reader treats input as bytes),
# reconnection policy (that lives in M6's HttpClient).

from std.collections.deque import Deque
from std.collections.optional import Optional
from src.http.body import BodyFrame
from src.http.handler import DetachedBody, ResponseWriter, WriteResult


struct ServerSentEvent(Copyable, Movable):
    """One dispatched Server-Sent Event. Matches the WHATWG `event` dispatch
    step output: a UTF-8 `data` string, an optional type, optional last-event
    id, and an optional reconnection-time hint."""

    var event: Optional[String]
    var data: String
    var id: Optional[String]
    var retry: Optional[UInt]

    def __init__(out self):
        self.event = Optional[String]()
        self.data = String("")
        self.id = Optional[String]()
        self.retry = Optional[UInt]()

    def __init__(out self, *, other: Self):
        self.event = other.event.copy()
        self.data = other.data.copy()
        self.id = other.id.copy()
        self.retry = other.retry.copy()

    def __init__(out self, *, deinit take: Self):
        self.event = take.event^
        self.data = take.data^
        self.id = take.id^
        self.retry = take.retry^
```

- [ ] **Step 4: Register the test**
Append `test_sse` to the `TESTS=()` array in `scripts/run_tests.sh`.

- [ ] **Step 5: Verify it passes**
Run: `bash scripts/run_tests.sh`
Expected: PASS.

- [ ] **Step 6: Commit**
```bash
git add src/http/sse.mojo tests/test_sse.mojo scripts/run_tests.sh
git commit -m "http: add ServerSentEvent struct (§7.3)"
```

---

### Task 9: `EventStreamReader` — incremental parser

**Files:**
- Modify: `src/http/sse.mojo` (append reader)
- Modify: `tests/test_sse.mojo` (add reader tests)

Strategy: the reader keeps a byte buffer of undispatched data pulled from its `DetachedBody`. On each `try_next_event()` call it pulls any frames available (draining Data frames into the byte buffer, observing terminal frames) and scans the buffer for complete events. An event boundary is a blank line (`\n\n` or `\r\n\r\n`). Between boundaries, `field: value` lines accumulate into a pending event: `data:` lines append to `data` with `\n` between them, `event:` / `id:` / `retry:` replace, unknown fields are ignored. Comment lines (`:` prefix) are ignored.

- [ ] **Step 1: Extend the test**
Append before `def main()`:
```mojo
from src.http.sse import EventStreamReader
from src.http.handler import RecvBody, DetachedBody
from src.http.body import BodyFrame


def _bytes_from_str(s: String) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8]()
    for i in range(len(b)):
        out.append(b[i])
    return out^


def test_reader_single_data_event() raises:
    var body = RecvBody()
    body._push(BodyFrame.data(_bytes_from_str("data: hello\n\n")))
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev_opt = reader.try_next_event()
    assert_true(Bool(ev_opt), "single.has_event")
    var ev = ev_opt.value().copy()
    assert_equal_str(ev.data, String("hello"), "single.data")


def test_reader_multi_data_lines_joined_with_lf() raises:
    var body = RecvBody()
    body._push(BodyFrame.data(_bytes_from_str("data: line1\ndata: line2\n\n")))
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev = reader.try_next_event().value().copy()
    assert_equal_str(ev.data, String("line1\nline2"), "multi.data")


def test_reader_event_and_id_fields() raises:
    var body = RecvBody()
    body._push(_bytes_from_str_frame("event: ping\nid: 7\ndata: pong\n\n"))
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev = reader.try_next_event().value().copy()
    assert_equal_str(ev.event.value(), String("ping"), "fields.event")
    assert_equal_str(ev.id.value(), String("7"), "fields.id")
    assert_equal_str(ev.data, String("pong"), "fields.data")


def test_reader_comment_line_ignored() raises:
    var body = RecvBody()
    body._push(_bytes_from_str_frame(": keepalive\ndata: foo\n\n"))
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev = reader.try_next_event().value().copy()
    assert_equal_str(ev.data, String("foo"), "comment.data")


def test_reader_retry_parses_int() raises:
    var body = RecvBody()
    body._push(_bytes_from_str_frame("retry: 5000\ndata: ok\n\n"))
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev = reader.try_next_event().value().copy()
    assert_true(Bool(ev.retry), "retry.some")
    assert_equal_int(Int(ev.retry.value()), 5000, "retry.value")


def test_reader_end_reports_is_end() raises:
    var body = RecvBody()
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev_opt = reader.try_next_event()
    assert_false(Bool(ev_opt), "end.no_event")
    assert_true(reader.is_end(), "end.is_end")


def _bytes_from_str_frame(s: String) -> BodyFrame:
    return BodyFrame.data(_bytes_from_str(s))
```

Update `main()` to call every new test.

- [ ] **Step 2: Verify it fails**
Run: `bash scripts/run_tests.sh`
Expected: FAIL — `EventStreamReader` undefined.

- [ ] **Step 3: Write minimal implementation**
Append to `src/http/sse.mojo`:
```mojo
struct EventStreamReader(Movable):
    """Incremental parser over a DetachedBody carrying a text/event-stream
    response. Pull model: the caller invokes `try_next_event()` which drains
    any newly-arrived BodyFrames from the underlying body and returns the
    next dispatched event if one is now available.

    Frame ordering invariants come from the body: zero-or-more Data frames
    followed by a terminal End or Error. Trailers frames are ignored (SSE
    has no use for them). Terminal errors cause `is_end()` to return True
    without raising — handlers read `is_end()` and stop polling."""

    var _body: DetachedBody
    var _buffer: List[UInt8]   # undispatched bytes
    var _body_ended: Bool

    def __init__(out self, var body: DetachedBody):
        self._body = body^
        self._buffer = List[UInt8]()
        self._body_ended = False

    def __init__(out self, *, deinit take: Self):
        self._body = take._body^
        self._buffer = take._buffer^
        self._body_ended = take._body_ended

    def is_end(self) -> Bool:
        """True once the underlying body is terminated AND the parse buffer
        has no complete event left to dispatch. Callers should poll
        `try_next_event` while this returns False."""
        return self._body_ended and len(self._buffer) == 0

    def try_next_event(mut self) raises -> Optional[ServerSentEvent]:
        # 1. Drain any newly-available frames from the body into the buffer.
        while True:
            var frame_opt = self._body.try_read()
            if not frame_opt:
                break
            var frame = frame_opt.value().copy()
            if frame.is_data():
                ref data = frame.data()
                for i in range(len(data)):
                    self._buffer.append(data[i])
            elif frame.is_end() or frame.is_error():
                self._body_ended = True

        # 2. Scan the buffer for a complete event (blank line terminated).
        var boundary = _find_event_boundary(self._buffer)
        if boundary < 0:
            return Optional[ServerSentEvent]()

        # 3. Parse the prefix (up to but not including the blank line).
        var event_bytes = _slice_bytes(self._buffer, 0, boundary)
        var event = _parse_event_bytes(event_bytes)

        # 4. Advance the buffer past the blank line.
        var consumed = _blank_line_len(self._buffer, boundary)
        self._buffer = _slice_bytes(self._buffer, boundary + consumed, len(self._buffer))
        return Optional[ServerSentEvent](event^)


# --- Parsing helpers ---


def _find_event_boundary(buf: List[UInt8]) -> Int:
    """Return the index in `buf` of the first byte of a blank-line terminator
    (`\\n\\n` or `\\r\\n\\r\\n` or `\\n\\r\\n` etc), or -1 if none yet. The
    returned index is the position of the *terminator*, so the event bytes
    are `buf[0:index]`."""
    var n = len(buf)
    var i = 0
    while i < n:
        # Look for two consecutive line endings at i.
        var first = _line_end_len(buf, i)
        if first > 0:
            var second = _line_end_len(buf, i + first)
            if second > 0:
                return i
            if i + first >= n:
                return -1
            i += first
            continue
        i += 1
    return -1


def _line_end_len(buf: List[UInt8], at: Int) -> Int:
    """Return 2 for `\\r\\n` at `at`, 1 for `\\n` or `\\r` alone, 0 otherwise."""
    if at >= len(buf):
        return 0
    var b = buf[at]
    if b == UInt8(0x0D):
        if at + 1 < len(buf) and buf[at + 1] == UInt8(0x0A):
            return 2
        return 1
    if b == UInt8(0x0A):
        return 1
    return 0


def _blank_line_len(buf: List[UInt8], at: Int) -> Int:
    """Length of the two consecutive line endings that form an event
    boundary starting at `at`. Assumes `_find_event_boundary` placed `at`
    at a valid boundary."""
    var first = _line_end_len(buf, at)
    var second = _line_end_len(buf, at + first)
    return first + second


def _slice_bytes(buf: List[UInt8], start: Int, end: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(start, end):
        out.append(buf[i])
    return out^


def _parse_event_bytes(bytes: List[UInt8]) raises -> ServerSentEvent:
    """Parse one event's worth of bytes (the prefix before the blank line)
    into a ServerSentEvent per WHATWG §9.2."""
    var event = ServerSentEvent()
    var pos = 0
    var n = len(bytes)
    while pos < n:
        # Find the end of this line.
        var line_start = pos
        while pos < n and bytes[pos] != UInt8(0x0A) and bytes[pos] != UInt8(0x0D):
            pos += 1
        var line_end = pos
        # Skip the line ending.
        pos += _line_end_len(bytes, pos)

        if line_start == line_end:
            continue  # blank line inside a multi-line event — ignore

        # Comment line (`:` prefix) — ignore.
        if bytes[line_start] == UInt8(0x3A):  # ':'
            continue

        # Split on ':'
        var colon = -1
        var ci = line_start
        while ci < line_end:
            if bytes[ci] == UInt8(0x3A):
                colon = ci
                break
            ci += 1

        var field_end = line_end if colon < 0 else colon
        var field_name = _bytes_to_string(bytes, line_start, field_end)
        var value_start = line_end if colon < 0 else colon + 1
        # Per WHATWG: skip a single leading space after the colon.
        if value_start < line_end and bytes[value_start] == UInt8(0x20):
            value_start += 1
        var value = _bytes_to_string(bytes, value_start, line_end)

        if field_name == "event":
            event.event = Optional[String](value^)
        elif field_name == "data":
            if len(event.data) > 0:
                event.data += String("\n")
            event.data += value
        elif field_name == "id":
            event.id = Optional[String](value^)
        elif field_name == "retry":
            # WHATWG: ignore non-integer values silently.
            var parsed = _try_parse_uint(value)
            if Bool(parsed):
                event.retry = parsed
        # unknown fields ignored
    return event^


def _bytes_to_string(buf: List[UInt8], start: Int, end: Int) -> String:
    var out = String("")
    for i in range(start, end):
        out += chr(Int(buf[i]))
    return out^


def _try_parse_uint(s: String) -> Optional[UInt]:
    if len(s) == 0:
        return Optional[UInt]()
    var acc: UInt = UInt(0)
    for i in range(len(s)):
        var c = ord(s[i])
        if c < 0x30 or c > 0x39:
            return Optional[UInt]()
        acc = acc * UInt(10) + UInt(c - 0x30)
    return Optional[UInt](acc)
```

Verification notes:
- `chr(Int(b))` / `ord(c)` are the existing M2.5a pattern (see `tests/test_h1_connection.mojo` `_bytes_to_string`). If either is missing in 0.26.2, use the project's `_test_util` helper or a manual `String` concatenation via `UInt8 -> Char -> String`.
- `_find_event_boundary` scans for two consecutive line endings. A CRLFCRLF boundary advances the buffer by 4 bytes; LFLF by 2; mixed (LFCRLF) by 3. `_blank_line_len` handles the arithmetic.
- The helper functions are private-by-convention (`_` prefix), not syntactic private. They live at module scope, not on the struct.

- [ ] **Step 4: Verify it passes**
Run: `bash scripts/run_tests.sh`
Expected: PASS — all six reader tests green.

- [ ] **Step 5: Commit**
```bash
git add src/http/sse.mojo tests/test_sse.mojo
git commit -m "http: add EventStreamReader incremental SSE parser (§7.3)"
```

---

### Task 10: `try_write_event` — stateless writer

**Files:**
- Modify: `src/http/sse.mojo` (append writer)
- Modify: `tests/test_sse.mojo` (add writer tests)

- [ ] **Step 1: Extend the test**
Append before `def main()`:
```mojo
from src.http.sse import try_write_event
from src.http.handler import ResponseWriter
from src.http.headers import Headers
from src.http.status import StatusCode


def test_write_simple_data_event_roundtrips() raises:
    var resp = ResponseWriter()
    resp.send_status(StatusCode(200), Headers())
    var ev = ServerSentEvent()
    ev.data = String("hello world")
    var r = try_write_event(resp, ev)
    assert_true(r.is_ok(), "write.ok")

    # Drain the written bytes through a RecvBody → EventStreamReader and
    # confirm the event comes back out unchanged.
    var recv = RecvBody()
    while True:
        var frame_opt = resp._pop_body_frame()
        if not frame_opt:
            break
        var frame = frame_opt.value().copy()
        if frame.is_data():
            recv._push(BodyFrame.data(frame.data().copy()))
    recv._set_end()
    var reader = EventStreamReader(recv^.detach())
    var decoded = reader.try_next_event().value().copy()
    assert_equal_str(decoded.data, String("hello world"), "roundtrip.data")


def test_write_all_fields_roundtrips() raises:
    var resp = ResponseWriter()
    resp.send_status(StatusCode(200), Headers())
    var ev = ServerSentEvent()
    ev.event = Optional[String](String("message"))
    ev.data = String("line1\nline2")
    ev.id = Optional[String](String("42"))
    ev.retry = Optional[UInt](UInt(3000))
    var r = try_write_event(resp, ev)
    assert_true(r.is_ok(), "all.ok")

    var recv = RecvBody()
    while True:
        var frame_opt = resp._pop_body_frame()
        if not frame_opt:
            break
        var frame = frame_opt.value().copy()
        if frame.is_data():
            recv._push(BodyFrame.data(frame.data().copy()))
    recv._set_end()
    var reader = EventStreamReader(recv^.detach())
    var decoded = reader.try_next_event().value().copy()
    assert_equal_str(decoded.event.value(), String("message"), "all.event")
    assert_equal_str(decoded.data, String("line1\nline2"), "all.data")
    assert_equal_str(decoded.id.value(), String("42"), "all.id")
    assert_equal_int(Int(decoded.retry.value()), 3000, "all.retry")
```

Update `main()` to call both new tests.

- [ ] **Step 2: Verify it fails**
Run: `bash scripts/run_tests.sh`
Expected: FAIL — `try_write_event` undefined.

- [ ] **Step 3: Write minimal implementation**
Append to `src/http/sse.mojo`:
```mojo
def try_write_event(
    mut resp: ResponseWriter,
    event: ServerSentEvent,
) raises -> WriteResult:
    """Serialize `event` into the response body as a text/event-stream
    frame. Stateless — the caller holds the ResponseWriter and passes it
    in on each call. Returns the underlying `try_send_body` result so the
    caller can observe backpressure.

    Spec deviation note: the original §7.3 sketch proposed a stateful
    EventStreamWriter struct wrapping an `UnsafePointer[ResponseWriter]`,
    but that contradicts the sketch's own "does NOT take ownership" line
    and adds lifetime risk in Mojo 0.26.2. SSE writers need no per-call
    state, so a free function is both simpler and safer. HC-4/M5 can
    promote this to a struct if a real use case for state emerges."""
    var buf = String("")

    if Bool(event.event):
        buf += String("event: ")
        buf += event.event.value()
        buf += String("\n")

    if Bool(event.id):
        buf += String("id: ")
        buf += event.id.value()
        buf += String("\n")

    if Bool(event.retry):
        buf += String("retry: ")
        buf += String(event.retry.value())
        buf += String("\n")

    # data: lines — split on '\n' so each chunk becomes its own "data:" line.
    if len(event.data) > 0:
        var start = 0
        var i = 0
        var n = len(event.data)
        while i < n:
            if event.data[i] == "\n":
                buf += String("data: ")
                buf += event.data[start:i]
                buf += String("\n")
                start = i + 1
            i += 1
        buf += String("data: ")
        buf += event.data[start:n]
        buf += String("\n")

    # Event terminator.
    buf += String("\n")

    # Convert to bytes and hand off to SendBody.
    var bytes = List[UInt8]()
    var as_bytes = buf.as_bytes()
    for k in range(len(as_bytes)):
        bytes.append(as_bytes[k])
    return resp.try_send_body(BodyFrame.data(bytes^))
```

- [ ] **Step 4: Verify it passes**
Run: `bash scripts/run_tests.sh`
Expected: PASS — both roundtrip tests green.

- [ ] **Step 5: Re-export from `src/http/__init__.mojo`**
Add this line to `src/http/__init__.mojo` (order: after `AltSvcCache, parse_alt_svc`):
```mojo
from .sse import ServerSentEvent, EventStreamReader, try_write_event
```

Then re-run `bash scripts/run_tests.sh` to ensure nothing broke.

- [ ] **Step 6: Commit**
```bash
git add src/http/sse.mojo tests/test_sse.mojo src/http/__init__.mojo
git commit -m "http: add try_write_event stateless SSE writer + re-export (§7.3)"
```

---

## Phase 4 — Acceptance gate

### Task 11: Full regression + docs update

**Files:**
- Verify: the whole src test suite, conformance suite, reverse-proxy e2e
- Modify: `docs/project-context.md`

- [ ] **Step 1: Run the full src test suite**
Run: `bash scripts/run_tests.sh`
Expected: PASS — every pre-existing M2.5a test plus the three new M2.5b test files. Report the new total count (should be 33/33: 30 from M2.5a + `test_priority` + `test_alt_svc` + `test_sse`).

- [ ] **Step 2: Run the full conformance suite**
Run: `bash conformance/scripts/run_tests.sh`
Expected: PASS — 27/27 unchanged (no wire-format changes in M2.5b).

- [ ] **Step 3: Run the reverse-proxy e2e suite**
Run: `bash scripts/test_reverse_proxy.sh`
Expected: PASS — M2.5b doesn't touch the proxy; both GET and POST should still round-trip.

- [ ] **Step 4: Walk the §11.2 checklist**
For each item in the spec's §11.2, confirm in writing:
1. `src/http/priority.mojo` exists? `ls src/http/priority.mojo`
2. `src/http/alt_svc.mojo` exists? `ls src/http/alt_svc.mojo`
3. `src/http/sse.mojo` exists? `ls src/http/sse.mojo`
4. Unit tests §10.3 green? Already confirmed in Step 1.
5. Priority + Alt-Svc parsers conform to RFC examples? Already covered by tests.
6. SSE parser round-trips through `DetachedBody` + `EventStreamReader`? Already covered by the Task 10 roundtrip tests.

- [ ] **Step 5: Update `docs/project-context.md`**
Edit the file (which is untracked per project convention — no commit needed for this change):
- Bump `Current phase` from `spec-2-implementing (M2.5b)` back to `idle` or to the next milestone's planning phase.
- In the "Active specs and plans" table, mark the M2.5b plan row as `shipped` with the final commit SHA.
- In the "Milestone state" list, change the M2.5b row from `🟢 spec approved` to `✅ shipped`.
- Append a new "Session history" entry describing the M2.5b implementation session and any deviations encountered.

- [ ] **Step 6: Final commit + tag**
There is nothing left to commit in the tree after Step 5 because `docs/` is untracked. Finalize the branch by running:
```bash
git log --oneline main..HEAD
```
and confirming 10 commits landed (one per task except Task 11). No tag — M2.5b is additive and doesn't warrant a release tag on its own. M6 will pick up these modules when it ships.

---

## Open questions (flag at point-of-use during implementation)

1. **`atol` availability in Mojo 0.26.2.** Task 2 and Task 6 use `atol(s)` for string→int conversion. If `atol` is not the right name in 0.26.2, verify via `mcp__mojo-mcp__validate` and fall back to `Int(s)` or a hand-rolled digit loop.
2. **`Dict.pop(key)` return value.** Task 7 writes `_ = self._entries.pop(origin)`. If the signature differs, adjust the discard pattern or use `_entries[key] = List[AltSvcEntry]()` + a separate tombstone set.
3. **`String[i:j]` slice syntax.** Used throughout Tasks 2, 6, 9, 10. If Mojo 0.26.2 requires `s.__getitem__(Slice(i, j))` instead, do the mechanical rewrite at each use site; it doesn't change the logic.
4. **`KeyElement` trait composition for `Origin`.** Task 4 declares `Origin(Copyable, Movable, Hashable, EqualityComparable)`. The `mcp__mojo-mcp__lookup` for `collections.dict.KeyElement` failed, so the trait exists but its exact composition is undocumented. If `Dict[Origin, ...]` rejects the struct in Task 7, add `KeyElement` explicitly as a trait argument: `struct Origin(KeyElement, Copyable, Movable)`.
5. **`WHATWG retry` field negative values.** The WHATWG spec ignores non-integer retry values silently but accepts valid integers. Task 9's `_try_parse_uint` rejects negative inputs by returning `None`. If a test vector wants to reject `retry: -1` with a distinct error, revisit — but the v1 behavior matches the spec.

Each of the first three is a pure syntax question that a `mcp__mojo-mcp__validate` roundtrip will resolve in under a minute. They are flagged here so the implementer doesn't have to rediscover them mid-task.
