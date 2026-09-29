"""CtxPool[T] — generic typed memory pool for heap-allocated per-stream contexts.

Recycles T-sized heap blocks across requests on the same connection.
The caller owns initialisation/destruction of the pointee; the pool
only manages the underlying memory.
"""

from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc


struct CtxPool[T: AnyType](Movable):
    """Free-list of typed T-sized heap blocks.

    On `acquire`, the caller initialises the returned block via
    `unsafe_write`; on `release`, the caller has already destroyed
    the pointee and hands the bare memory back.
    """

    var _free: List[Pointer[Self.T, MutUntrackedOrigin]]
    var _capacity: Int

    def __init__(out self, *, capacity: Int = 16):
        self._free = List[Pointer[Self.T, MutUntrackedOrigin]]()
        self._capacity = capacity

    def __deinit__(deinit self):
        for ref ptr in self._free:
            ptr.unsafe_free()

    def acquire(mut self) -> Pointer[Self.T, MutUntrackedOrigin]:
        """Take a free slot if available, else allocate fresh."""
        if len(self._free) > 0:
            return self._free.pop()
        return _heap_alloc[Self.T](1)

    def release(mut self, ptr: Pointer[Self.T, MutUntrackedOrigin]):
        """Return a slot whose pointee has already been destroyed."""
        if len(self._free) < self._capacity:
            self._free.append(ptr)
        else:
            ptr.unsafe_free()

    def idle_count(self) -> Int:
        """Number of recycled blocks available for reuse."""
        return len(self._free)
