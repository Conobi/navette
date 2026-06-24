"""owned_alloc.mojo — `Owned[T]`, a RAII owner over `memory.alloc.Allocation[T]`.

`Owned[T]` wraps the b2 `Allocation[T]` handle in an *implicitly*-destructible
struct. Because a plain struct's `__del__` runs on **every** path — normal
scope exit *and* exception unwind — heap scratch buffers become leak-free
without the per-error-path `dealloc` bookkeeping that the bare
`@explicit_destroy` `Allocation` requires. The deallocation itself stays
compiler-checked inside `__del__` (the `Allocation` is consumed exactly once),
so the safety guarantee is preserved while the call sites stay mechanical.

This replaces the raw `std.memory.unsafe_pointer.alloc` (`_heap_alloc`) +
manual `.free()` pattern, whose `.free()` was silently skipped on any
intervening `raise` (a latent leak-on-error). With `Owned[T]` that free is
automatic on the raise path too.

Storage is **uninitialized**, exactly like the raw allocator it replaces —
initialize before reading.

Usage:

```mojo
var buf = Owned[UInt8](48)
var p = buf.ptr()          # borrow; the borrow keeps `buf` alive while `p` is used
for i in range(buf.count()):
    p[i] = UInt8(0)
some_ffi_call(p)           # if this raises, `buf` is freed on the unwind path
# no manual free — `buf` is freed at its last use (ASAP) or scope exit
```
"""

from std.memory import UnsafePointer
from std.memory.alloc import alloc, dealloc, Layout, Allocation


struct Owned[T: AnyType](Movable):
    """A RAII owner of `count` uninitialized heap elements of `T`.

    Auto-frees on all control-flow paths, including exception unwind. Move-only
    (no implicit copy), so ownership of the storage is unique.
    """

    var _alloc: Allocation[Self.T]
    var _count: Int

    def __init__(out self, count: Int):
        """Allocate `count` elements of `T` with `T`'s natural alignment.

        A `count` of 0 allocates a single element so the returned pointer stays
        valid for a length-0 FFI call (matching the old `_heap_alloc(0)`):
        `alloc(count=0)` aborts under `ASSERT=all`. `count()` still reports the
        requested 0.

        Args:
            count: Number of elements to allocate. Storage is uninitialized.
        """
        self._count = count
        self._alloc = alloc(Layout[Self.T](count=count if count > 0 else 1))

    def __init__(out self, *, count: Int, alignment: Int):
        """Allocate `count` elements of `T` with an explicit byte `alignment`.

        Args:
            count: Number of elements to allocate. Storage is uninitialized.
            alignment: Byte alignment; must be a power of two and at least
                `T`'s natural alignment.
        """
        self._count = count
        self._alloc = alloc(
            Layout[Self.T](count=count if count > 0 else 1, alignment=alignment)
        )

    def __del__(deinit self):
        """Deallocate the storage. Compiler-checked: consumed exactly once."""
        dealloc(self._alloc^)

    def ptr(mut self) -> UnsafePointer[Self.T, origin_of(self)]:
        """Borrow a mutable pointer to the storage.

        The returned pointer's origin is tied to `self`, so the borrow keeps
        `self` (and therefore the storage) alive for as long as the pointer is
        in use — preventing an ASAP-destruction use-after-free across an FFI
        call.

        Returns:
            A pointer to the (uninitialized) storage, valid while `self` lives.
        """
        return self._alloc.unsafe_ptr().unsafe_origin_cast[origin_of(self)]()

    def count(self) -> Int:
        """Return the requested element count (the value passed to the ctor).

        Returns the requested count even when it is 0 (the storage is clamped to
        a single element internally; see `__init__`).
        """
        return self._count
