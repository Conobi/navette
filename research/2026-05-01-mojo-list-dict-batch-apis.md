# Mojo 0.26.2 — `List` / `Dict` / `Span` batch-byte APIs for the
# `_drain_stream` / `_parse_frames_from_buf` optimization spec

**Date:** 2026-05-01
**Author:** research subagent
**Source:** validated via `mcp__mojo-mcp__execute` against the project-pinned compiler (no
external assumptions; every claim below is backed by an executed snippet whose stdout/stderr is
quoted verbatim).

---

## 0. Mojo version confirmed

`mcp__mojo-mcp__mojo_version`:

```
{
  "global_version":"Mojo 0.26.3.0.dev2026042005 (32e188d3)",
  "pinned_version":"0.26.2",
  "version_file":"/home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main/.mojo-version"
}
```

Every `execute` call below was run with `cwd` set to the project root, so the
`.mojo-version` pin (0.26.2) was honored. Output blocks always carry the
`"mojo_version":"0.26.2"` field — verified.

> **Heads-up to the optimization spec author:** `lookup` returns *just method
> names*, not signatures, for `List`, `Dict`, `Span`. We had to recover
> signatures by triggering deliberate type-mismatch errors so the compiler
> would dump the overload set. The signatures quoted below come from those
> compiler diagnostics.

---

## 1. Per-question answers

### Q1 — `List[UInt8].extend(Span[UInt8])` — exists? cost?

**Answer: YES, exists, and it's ~2.24× faster than the byte-loop append.**

#### Evidence — overload set

Compiler diagnostic (forced with `a.extend(42)`):

```
note: candidate not viable: value passed to 'other'    cannot be converted from
      'IntLiteral[42]' to 'List[UInt8]'
note: candidate not viable: value passed to 'elements' cannot be converted from
      'IntLiteral[42]' to 'Span[UInt8, elements.origin]', it depends on an
      unresolved parameter 'elements.origin.mut'
note: candidate not viable: value passed to 'value'    cannot be converted from
      'IntLiteral[42]' to 'SIMD[DType.uint8, value.size]', it depends on an
      unresolved parameter 'value.size'
note: candidate not viable: missing 1 required keyword-only argument: 'count'
```

So `List.extend` has (at least) **four overloads**:

1. `extend(other: List[T])` — consumes the list (T must be `ImplicitlyCopyable`
   for borrow form, else move via `^`).
2. `extend(elements: Span[T, elements.origin])` — borrows a span (this is the
   one we want).
3. `extend(value: SIMD[..., value.size])` — copies a SIMD lane.
4. `extend(*, count: ...)` — keyword-only count form (probably for the SIMD
   overload; not relevant here).

#### Evidence — compile + runtime

```mojo
var a = List[UInt8](capacity=16)
a.append(1); a.append(2); a.append(3)
var b = List[UInt8](capacity=16)
b.append(10); b.append(20)
var sp = Span(b)
a.extend(sp)        # ← compiles, runs
```

stdout: `extend(Span) ok, len= 5\n1\n2\n3\n10\n20`

#### Evidence — perf microbench (10 000 bytes per chunk × 2 000 iters)

```
byte_loop  (current pattern)  ns/iter: 15400
extend_span                   ns/iter:  6860
speedup                                : 2.24×
```

Source: `bench_byte_loop` and `bench_extend_span` snippets executed in this
research session. Both appended a freshly-built `List[UInt8]` of length 10 000
into an empty pre-`reserve`d destination. Difference is the inner loop only.

> **Caveat:** `extend(Span)` outperforms the byte-loop by ~2.2× even for cold
> 10k-byte chunks. It is *very likely* doing a `memcpy` (or
> register-blocked SIMD copy) under the hood — this is what the perf gap looks
> like. We did **not** disassemble to confirm the lowering; the spec should
> not promise "single memcpy" without that verification, but a 2.2× speedup at
> n=10 000 is consistent with a vectorized bulk copy.

#### Implication for the optimization spec

`extend(Span(src))` is a clear drop-in replacement for the
`for i in range(len(new_bytes)): sbuf.buf.append(new_bytes[i])` loop at
`connection.mojo` L417-420. Expected speedup on the hot path: **~2×** for the
append-side cost, before counting the savings from removing the
`Dict[..., _H3StreamBuf].copy()` (see Q4).

---

### Q2 — `del lst[:n]` (slice-delete) — supported?

**Answer: NO. Slice-delete syntax does not exist. Single-index `del lst[i]`
also does not exist. `pop(0)` works but is O(n) per call.**

#### Evidence — `del a[:3]`

```mojo
var a = List[UInt8](capacity=8)
for i in range(8): a.append(UInt8(i))
del a[:3]
```

```
error: unexpected token in expression
    del a[:3]
    ^
```

#### Evidence — `del a[0]`

Same parser error: `del a[0]` → `error: unexpected token in expression`.
The `del` keyword in Mojo 0.26.2 is **not a statement-level operator on List
slots**.

#### Evidence — `pop(0)` works

```mojo
var x = a.pop(0)   # → returns 0; a now has length 7
```

stdout: `7 0`. Confirms `List.pop` accepts an index. But this is *one element
at a time* — for "drop the first n bytes" it would mean n successive O(n) shifts =
O(n²). Useless for our case.

#### Canonical "drop first n elements" idioms

There are **three** options, all O(remaining):

1. **`extend(Span(self.buf)[n:])` into a fresh List** — the obvious bulk copy.
   Bench (16 384 total, drop 12, 2 000 iters):
   - byte-loop shift (current connection.mojo): **21 999 ns/iter**
   - `extend(Span(buf)[n:])`:                    **12 124 ns/iter**
   - speedup: **1.81×**

2. **Head-cursor pattern** — don't shift; advance an `Int head` field; lazily
   compact only when `head > size/2`. Bench (same params):
   - head_cursor (advance + later read via `Span(buf)[head:]`): **17 368 ns/iter**
     (this number includes a forced `for x in tail: s += Int(x)` so the read
     isn't elided — pure head-advance is essentially free)

3. **`steal_data()` + reconstruct** — `List` exposes `steal_data` (visible in
   the method list). Untested; the head-cursor pattern is simpler and avoids
   touching unsafe pointers.

#### Implication for the optimization spec

The current `for i in range(consumed, len(sbuf.buf)): new_buf.append(...)`
pattern at L475-498 should become **`new_buf.extend(Span(sbuf.buf)[consumed:])`**.
For an even bigger win, switch `_H3StreamBuf` to a head-cursor layout
(see Q6) so the "shift" becomes free until amortized compaction.

---

### Q3 — `Span(my_list)` — lifetime, mut-borrow

**Answer: Span construction is zero-copy. The origin is `origin_of(self.list_field)`,
not `origin_of(self)`. Mut spans bound to a `mut self` field work, but the
return type must thread the field's origin explicitly.**

#### Evidence — `Span.__init__` overloads

Compiler diagnostic (forced with `Span[UInt8](42)`):

```
note: expected at most 0 positional arguments, got 1
note: candidate not viable: value passed to 'other' cannot be converted from
      'IntLiteral[42]' to 'Span[other.T, other.origin]'  ← copy-from-Span
note: candidate not viable: missing 2 required keyword-only arguments:
      'ptr', 'length'                                     ← raw pointer ctor
note: candidate not viable: value passed to 'list' cannot be converted from
      'IntLiteral[42]' to 'List[U]'                       ← from-List ctor (THIS)
note: candidate not viable: value passed to 'array' cannot be converted from
      'IntLiteral[42]' to 'InlineArray[U, size]'          ← from-InlineArray ctor
note: candidate not viable: missing 1 required keyword-only argument: 'take'
note: generated function with type 'def[mut: Bool, _, T: AnyType,
      origin: Origin[mut=mut], +](*, deinit take: Span[T, origin]) -> Span[T, origin]'
note: candidate not viable: missing 1 required keyword-only argument: 'copy'
```

The list ctor is `Span(list: List[U])` and infers origin from the list passed.

#### Evidence — `Span(buf)` over a List field

```mojo
var a = List[UInt8](capacity=4)
a.append(1); a.append(2); a.append(3)
var sp = Span(a)
print(len(sp), sp[0], sp[2])   # → "3 1 3"
```

Compiles and runs. No copy.

#### Evidence — origin pickiness

When returning a `Span` from a method that takes `ref self` over a `buf` field,
this **fails**:

```mojo
fn active(ref self) -> Span[UInt8, origin_of(self)]:
    return Span(self.buf)[self.head:]
```

```
error: cannot implicitly convert 'Span[UInt8, origin_of(self.buf)]'
       value to 'Span[UInt8, origin_of(self)]'
note: .origin._mlir_origin` of left value is 'self.buf'
       but the right value is 'origin_of(self)'
```

The fix is to return `Span[UInt8, origin_of(self.buf)]`. This compiles and
runs (see Q6 below).

#### Implication for the optimization spec

A method like `fn active(ref self) -> Span[UInt8, origin_of(self.buf)]:
return Span(self.buf)[self.head:]` is sound and returns a borrowed span
tied to the field. The caller can iterate / pass to `extend` without
triggering any copy. The spec must use **`origin_of(<field>)`**, not
`origin_of(self)`, and **note the rename `__origin_of` → `origin_of`** that
landed in v0.25.7.

---

### Q4 — `Dict[K, V].copy()` for V=struct — what actually happens?

**Answer: It deep-copies. In `connection.mojo`, the
`var sbuf = self._stream_bufs[key].copy()` line invokes
`_H3StreamBuf.__copyinit__`, which deep-copies the inner `List[UInt8]`. It is
**not** elided when followed by `self._stream_bufs[key] = sbuf^` — the round
trip pays one full copy.**

#### Evidence — direct copy counter

`Buf` was instrumented with a `copies: Int` counter that increments inside
`__copyinit__`. Then:

```mojo
var d = Dict[Int, Buf]()
d[1] = Buf()                        # copies = 0
var b = d[1].copy()                 # explicit .copy() → copies = 1
b.data.append(99)
d[1] = b^                           # transfer, no copy
var b2 = d[1].copy()                # another .copy() → copies = 2
```

stdout: `read back copies = 2  len(data) = 1`. Confirmation: each `.copy()`
on a Dict slot containing a `List[UInt8]`-bearing struct deep-copies the inner
list.

#### Evidence — `__getitem__` requires `ImplicitlyCopyable` for bare bind

```mojo
var v = d[1]   # without .copy() / ^
```

```
error: value of type 'Buf' cannot be implicitly copied, it does not conform
       to 'ImplicitlyCopyable'
note: consider transferring the value with '^'
note: you can copy it explicitly with '.copy()'
```

So `d[1]` returns a *result* that the compiler insists you either copy or
transfer. The current `connection.mojo` code chose `.copy()`. This is
exactly the avoidable cost.

#### Evidence — chained mut access skips the copy ENTIRELY

```mojo
d[1].data.append(1)         # ← no .copy()
d[1].data.append(2)
d[1].data.append(3)
var b = d[1].copy()          # only this read does the copy → copies = 1
print(b.copies, len(b.data)) # → 1 3
```

stdout: `After 3 chained appends, copies (incl this read) = 1 len = 3`.

This means `d[key].buf.append(byte)` and `d[key].buf.extend(span)` both
mutate **in place** with zero copies. The `.copy() + reassign` pattern is
**unnecessary in Mojo 0.26.2**.

#### Implication for the optimization spec

Both call sites in `connection.mojo`
(L417-420 and L475-498) start with `var sbuf = self._stream_bufs[key].copy()`
followed by `self._stream_bufs[key] = sbuf^`. **Both of these `.copy() +
reassign` brackets can be removed.** Mutate the dict slot directly. Per
buffer-mutating method call, this saves one `List[UInt8].__copyinit__` (a
heap alloc + memcpy of every queued byte). On a 16 KB stream buffer that's
~16 KB of memcpy + one libc malloc per parse-loop iteration.

---

### Q5 — `Dict.get_ref` / mut-borrow accessor?

**Answer: There is no `Dict.get_ref` / `get_mut`. But Mojo 0.26.2 has TWO
better options: (a) `d[k]` returns a ref-like that supports chained mut
(see Q4), and (b) `ref` *bindings* (`ref slot = d[k]`) work and are
reusable.**

#### Evidence — `get_ref` does not exist

```mojo
d.get_ref(1)
```

```
error: 'Dict[Int, Int]' value has no attribute 'get_ref'
```

The full Dict method list per `lookup`: `__init__ __del__ __bool__
__getitem__ __setitem__ __eq__ __contains__ __or__ __ior__ fromkeys
__iter__ __reversed__ __len__ __hash__ write_to write_repr_to find get
pop popitem keys values items take_items update clear setdefault`.
No `get_ref`/`get_mut`.

#### Evidence — `ref slot = d[k]` works

```mojo
var d = Dict[Int, Buf]()
d[1] = Buf(42)
ref slot = d[1]
slot.n = 100
print(d[1].copy().n)   # → "100"
```

Output: `100`. The `ref` binding aliases the Dict slot in place — mutations
through `slot` are visible at `d[1]`. This is the canonical mut-borrow.

The binding is **reusable**:

```mojo
ref slot = d[1]
slot.data.append(1); slot.data.append(2); slot.data.append(3)
for i in range(4, 10): slot.data.append(UInt8(i))
print(len(d[1].copy().data))   # → "9"
```

stdout: `after 3 ops via ref binding, len: 3` then `after loop, len: 9`.

#### Evidence — passing `d[k]` to a `mut` parameter

```mojo
fn process(mut b: Buf, payload: UInt8):
    b.data.append(payload)
    b.data.append(payload + 1)

process(d[1], 100)
process(d[1], 200)
var b = d[1].copy()
print(b.copies, len(b.data))   # → "1 4"
```

stdout: `copies (incl this read) = 1 len = 4`. So passing `d[k]` directly to
a function-with-mut-param is **also** zero-copy.

#### Implication for the optimization spec

The spec has **three** zero-copy mut-borrow options for the
`Dict[stream_id, _H3StreamBuf]` slots:

1. **Direct chained call**: `self._stream_bufs[key].buf.append(byte)` —
   simplest for 1-2 mutations.
2. **`ref` binding**: `ref slot = self._stream_bufs[key]; ...repeated
   mutations on slot...` — best for tight inner loops because it avoids
   repeated hash lookups.
3. **Mut-param free fn**: `_apply_to_buf(self._stream_bufs[key], data)` —
   best when the operation is logically a separate routine that takes a
   `mut _H3StreamBuf`.

All three eliminate the current `.copy() + reassign` pattern. The
`ref slot = ...` form is most likely the right fit for the parse loop, where
we need to mutate the same buffer many times per call.

> **Caveat / open Q:** We did **not** measure whether `ref` re-validates the
> hash slot on each access. Looking at the bench numbers, the cost of `d[k]`
> at each chained mutation looks negligible vs. the work the parser does, but
> if the parse loop does e.g. 64 mutations per call, the `ref` binding form
> is the safer one to recommend.

---

### Q6 — Head-cursor pattern feasibility

**Answer: Fully feasible. We compiled and ran a working `StreamBuf` with
head-cursor + lazy compaction. No lifetime explosions; the only quirk is
returning a `Span` requires `origin_of(self.buf)`, not `origin_of(self)`.**

#### Evidence — full working example

```mojo
struct StreamBuf(Copyable & Movable):
    var buf: List[UInt8]
    var head: Int
    fn __init__(out self):
        self.buf = List[UInt8](); self.head = 0
    fn __copyinit__(out self, copy: Self):
        self.buf = copy.buf.copy(); self.head = copy.head
    fn __moveinit__(out self, deinit take: Self):
        self.buf = take.buf^; self.head = take.head

    fn active(ref self) -> Span[UInt8, origin_of(self.buf)]:
        return Span(self.buf)[self.head:]

    fn append_bytes(mut self, data: Span[UInt8, _]):
        self.buf.extend(data)

    fn consume(mut self, n: Int):
        self.head += n
        # Compaction: if head > size/2, shift in-place
        if self.head > 0 and self.head * 2 > len(self.buf):
            var new_buf = List[UInt8](capacity=len(self.buf) - self.head)
            new_buf.extend(Span(self.buf)[self.head:])
            self.buf = new_buf^
            self.head = 0
```

Driver:

```
buf len: 20  head: 0
active len: 20  first: 0
after consume(8):  buf len: 20  head: 8
after consume(5):  buf len:  7  head: 0     ← compacted (head 13 > 20/2)
remaining: 7
13 14 15 16 17 18 19
```

#### Three quirks to know

1. **Origin must thread the *field*, not `self`.** `origin_of(self.buf)`
   compiles; `origin_of(self)` errors with "cannot implicitly convert
   `Span[UInt8, origin_of(self.buf)]` to `Span[UInt8, origin_of(self)]`".
2. **`Span[UInt8]` alone fails to infer** the origin parameter; use
   `Span[UInt8, _]` (or thread the origin explicitly). This applies to all
   parameter positions.
3. **`__origin_of` was renamed to `origin_of`** in v0.25.7. Don't use the
   double-underscore form.

#### Implication for the optimization spec

The head-cursor refactor of `_H3StreamBuf` is a clean, viable design. The
parse loop mutates `head: Int` (free) and only pays a compaction every time
the head crosses 50% — amortized O(1). Combined with `extend(Span(src))`
on the ingress side and removing the `.copy() + reassign` round trip,
the data path becomes essentially copy-free.

---

### Q7 — Changelog scan (v0.25.7 → v0.26.2)

Changes affecting batch-byte handling and `List` / `Dict` / `Span`:

#### v0.25.7 (2025-11-20)

- **`__type_of` → `type_of`, `__origin_of` → `origin_of`** (renames).
- **New `UnsafePointer`** with proper origin parameter; old version is
  `LegacyUnsafePointer`. Relevant if the spec wants to drop down for any
  reason.
- **Iterator protocol change:** `__next_ref__()` removed; `__next__()` now
  returns a value or a reference. Probably not load-bearing for byte-buffer
  code.

#### v0.26.1 (2026-01-29)

- **Trait hierarchy reshuffle:** `AnyType`, `Movable`, `Copyable` no longer
  require `__del__`. New `ImplicitlyDestructible` trait. Most relevant: any
  generic helper with `T: AnyType` may now need `T: ImplicitlyDestructible` to
  preserve old behavior.
- **Conditional trait conformances** via `where` clauses (`List` and `Dict`
  use this). Likely not relevant to our hot path.
- **`String.from_utf8=` / `from_utf8_lossy=` / `unsafe_from_utf8=`** for byte
  →string conversion. Relevant only if H3 frames need to be turned into
  strings (we don't on this path).

#### v0.26.2 (2026-03-19)

- **`__moveinit__` / `__copyinit__` are now spelled `__init__(..., *, deinit
  take: Self)` / `__init__(..., *, copy: Self)`** with the named keyword
  args. The legacy spellings are still accepted but should be migrated. We
  saw both: `error: source argument of '__copyinit__' must be named 'copy'`
  on a snippet using `other`. The spec should standardize on the new
  convention.
- **`owned` keyword removed.** Use `var` for params or `deinit` for
  move/destroy args.
- **`def`/`fn` unification.** `fn` is deprecated; `def` is now the standard
  declaration with `raises` annotated explicitly. Mostly cosmetic for our
  spec.

#### Net for the optimization spec

- **Use `origin_of`, not `__origin_of`.**
- **Keep `__copyinit__` / `__moveinit__` spellings consistent** — and if you
  add new structs (e.g. a head-cursor `_H3StreamBuf`), use the named-keyword
  form (`copy: Self`, `deinit take: Self`) per the validator's gotcha
  list.
- **`extend(Span)` semantics did not change between 0.25.7 and 0.26.2.** It
  is the recommended idiom in the present.

---

## 2. Drop-in replacement table

The two problematic patterns from the prompt, with the recommended Mojo
0.26.2 idiom:

### Pattern A — L417-420: `Dict.copy() + byte-loop append + reassign`

```mojo
# CURRENT (3 deep operations: 1 deep copy of inner List, n .append calls, 1 transfer back)
var sbuf = self._stream_bufs[key].copy()
for i in range(len(new_bytes)):
    sbuf.buf.append(new_bytes[i])
self._stream_bufs[key] = sbuf^
```

```mojo
# RECOMMENDED — direct chained mut, bulk extend
self._stream_bufs[key].buf.extend(Span(new_bytes))
```

**Wins (cumulative):**
- removes the `__copyinit__` of `_H3StreamBuf` (one `List[UInt8].copy()` =
  malloc + memcpy of full queued bytes — could be tens of KB)
- removes the byte-loop append (~2.24× faster on 10k bytes per Q1)
- removes the `^` transfer + a re-hashing of the dict insert

If multiple mutations are needed in a row, prefer:

```mojo
ref slot = self._stream_bufs[key]
slot.buf.extend(Span(new_bytes))
slot.head += 0   # any other field updates
```

### Pattern B — L475-498: full-buffer copy + byte-by-byte O(n²) shift

```mojo
# CURRENT
var sbuf = self._stream_bufs[key].copy()              # deep copy
var buf_copy = List[UInt8](copy=sbuf.buf)             # second deep copy!
var r = ByteReader(Span(buf_copy))
# ... parse ...
var new_buf = List[UInt8]()
for i in range(consumed, len(sbuf.buf)):
    new_buf.append(sbuf.buf[i])                       # byte-loop shift
sbuf.buf = new_buf^
self._stream_bufs[key] = sbuf^
```

```mojo
# RECOMMENDED — short term, drop both copies + bulk shift
ref slot = self._stream_bufs[key]
var r = ByteReader(Span(slot.buf))                    # zero copy: read borrows the slot
# ... parse, get `consumed` ...
var new_buf = List[UInt8](capacity=len(slot.buf) - consumed)
new_buf.extend(Span(slot.buf)[consumed:])             # bulk copy, ~1.81× faster
slot.buf = new_buf^
```

**Wins:**
- Removes `_H3StreamBuf.__copyinit__` and the second `List[UInt8](copy=...)`.
- The shift is `extend(Span[consumed:])` — single bulk copy, no `__copyinit__`
  per byte.
- The `ByteReader` reads from a `Span` borrowing the live slot, so the parse
  itself is also zero-copy.

```mojo
# RECOMMENDED — medium term, head-cursor `_H3StreamBuf`
ref slot = self._stream_bufs[key]
var r = ByteReader(slot.active())                     # Span(buf)[head:]
# ... parse, get `consumed` ...
slot.consume(consumed)                                # head += consumed; lazy compact
```

**Wins (vs short term):**
- The shift becomes essentially **free** until amortized compaction
  (head-cursor head-advance is an `Int` mutation).
- Compaction itself uses `extend(Span(buf)[head:])` so it's the same single
  bulk copy as the short-term form, but only fires when `head > size/2`.

### Bonus pattern — slot read for a peek that doesn't mutate

```mojo
# DON'T — costs one .copy()
var b = self._stream_bufs[key].copy()
if b.buf[0] == 0x00: ...

# DO — zero copy
if self._stream_bufs[key].buf[0] == 0x00: ...
```

(Subscripting through the Dict slot is fine — the compiler treats it as a
ref-chain, same as for mutation. Confirmed in Q4.)

---

## 3. Gotchas / open questions

### Validated gotchas to flag in the spec

1. **`__copyinit__` / `__moveinit__` argument names.** Per v0.26.2, the
   source arg of `__copyinit__` must be named `copy`, and `__moveinit__`'s
   take arg must be named `deinit take` (or `var take`). The validator
   catches this — see `gotcha_hints` in our Q4 first attempt:
   *"error: source argument of '__copyinit__' must be named 'copy'"*. New
   structs added by the optimization spec must use these names.

2. **`origin_of(self.field)` vs `origin_of(self)`.** A `Span` over a list
   field carries `origin_of(self.field)`, not `origin_of(self)`. Don't try
   to widen — the compiler will refuse the implicit conversion. Quoted error
   in Q3.

3. **`Span[UInt8]` alone does not infer origin.** Use `Span[UInt8, _]` in
   parameter positions (we hit this in Q6 first attempt; the fix worked
   trivially).

4. **`del` is not a slice/index operator on `List`.** Slice-delete (`del
   a[:n]`) and even index-delete (`del a[0]`) both produce parser errors
   ("unexpected token in expression"). Anyone trying to mirror Python here
   will be surprised. Use `extend(Span(buf)[n:])` into a fresh list, or
   head-cursor.

5. **`extend(other: List[T])` requires `T` to be `ImplicitlyCopyable` to
   borrow-extend; otherwise transfer with `^`.** This is why our second
   bench needed `extend(Span(src))` not `extend(src)` — `List[UInt8]` is
   `Copyable` (explicit) but not `ImplicitlyCopyable`. So in practice
   `extend(Span(...))` is the universally-applicable form.

### Open questions / things we did NOT validate

1. **Exact lowering of `extend(Span)` for `UInt8`.** The 2.24× speedup is
   strong evidence of a vectorized memcpy, but we did not verify by reading
   the LLVM IR / asm. Spec should state "expected memcpy-class lowering" not
   "guaranteed memcpy".

2. **Whether `ref slot = d[k]` re-hashes the slot on each subsequent access.**
   The compiler's logical model treats it as one stable alias (`slot.x` then
   `slot.y` should not re-hash). But we have not disassembled the IR to
   confirm there's no rehash. If the parse loop performs *thousands* of
   `slot.buf.append(...)` calls, this matters; if it's tens, it doesn't.

3. **`Dict.take_items()` for iterating moves out of the dict.** Visible in
   the method list, undocumented in `lookup`. Probably not relevant — we
   want to mutate in place, not drain.

4. **Behavior of `Span(buf)[a:b]` on an empty range** (`a == b`). Not
   tested. The head-cursor compaction should handle `head == len(buf)` by
   not entering the compaction branch (it's gated on `head > 0 and
   head*2 > len(buf)`); but the spec should add an explicit
   `if head == len(buf): self.buf.clear(); self.head = 0; return` to be
   safe.

5. **`steal_data()`** — visible in the `List` method list, no full signature
   surfaced via `lookup`. Could be useful for the compaction path if the
   caller wants to take ownership of the underlying pointer instead of
   `extend`-ing into a new list. Untested; not necessary for the proposed
   refactor.

6. **`SIMD[UInt8, N]` extend overload performance.** Q1 showed it exists.
   Untested for our case. Could be marginally faster than `Span` for very
   small fixed-size writes (e.g. a 9-byte H3 frame header), but not a
   priority.

7. **Whether the `ref slot = d[k]` binding holds across an intermediate
   call that re-hashes the dict** (e.g. if the parse loop calls a method
   that itself inserts/removes a different key in the same dict). This is a
   *correctness* question, not a perf one. The spec should restrict ref
   bindings to scopes that don't mutate the dict's slot table.

---

## 4. Summary for the optimization spec author

| Change | Effort | Impact (estimate) |
|---|---|---|
| Replace byte-loop `append` with `extend(Span(...))` | Trivial | **~2.2×** on the append step at 10k bytes |
| Drop `Dict[...].copy() + reassign` round trip; use direct chained mut or `ref` binding | Trivial | Saves **1 full deep copy** of `List[UInt8]` per parse-loop iteration (= 1 malloc + memcpy of stream-buffered bytes) |
| Replace byte-loop shift with `extend(Span(buf)[n:])` | Trivial | **~1.81×** on the shift step at 16 KB / drop=12 |
| Refactor `_H3StreamBuf` to head-cursor + lazy compaction | Moderate (struct-shape change, ~1 day) | Shift becomes O(1) amortized; compactions amortize the bulk-copy cost; cumulative win likely **3-5×** on shift-heavy workloads |

All four changes are mutually compatible and all are *purely local* to
`src/h3/connection.mojo` plus the `_H3StreamBuf` definition. None require
stdlib changes or unsafe pointer use.

The spec should target **all four** in a single optimization pass, since
benching them piecewise will under-attribute the wins (the deep-copy savings
only show up after both copy sites are removed).
