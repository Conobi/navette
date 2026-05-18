"""PtrBox[T] — typed, Copyable+Movable wrapper around a heap-allocated
UnsafePointer[T, MutAnyOrigin].

Replaces the scattered `UInt64`-as-address pattern previously used in h2/h3
session and server adapters (`_ClientStreamPtr`, `_StreamPtr`,
`_CoroStreamPtr`, `_StreamingCtxPtr`, and the `_free: List[UInt64]` pool in
`h2_sync_server`). Stores the pointer directly — no `Int(...)` roundtrip.

Invariant: a PtrBox is either null (default-constructed via `null()`) or
points to a live, `init_pointee_move`-d T on the heap. Copying a PtrBox
aliases the pointer; the unique owner is responsible for exactly-one
`destroy_pointee()` + `free()` on the pointee+memory it manages.
"""

from std.memory import UnsafePointer


struct PtrBox[T: AnyType](Copyable, Movable):
    var _ptr: UnsafePointer[Self.T, MutAnyOrigin]

    def __init__(out self, ptr: UnsafePointer[Self.T, MutAnyOrigin]):
        self._ptr = ptr

    @staticmethod
    def null() -> Self:
        return PtrBox[Self.T](UnsafePointer[Self.T, MutAnyOrigin]())

    def __init__(out self, *, other: Self):
        self._ptr = other._ptr

    def __init__(out self, *, deinit take: Self):
        self._ptr = take._ptr

    def ptr(self) -> UnsafePointer[Self.T, MutAnyOrigin]:
        return self._ptr

    def is_some(self) -> Bool:
        return Int(self._ptr) != 0
