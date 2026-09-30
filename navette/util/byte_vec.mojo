"""Fixed-capacity byte buffer types for zero-alloc networking."""

from std.memory import OwnedPointer, Pointer
from std.collections.span import Span


@fieldwise_init
struct ByteVec[capacity: Int](Movable, Copyable, Sized):
    """Stack-allocated, fixed-capacity byte buffer. Raises on overflow."""

    var _storage: Array[Byte, Self.capacity]
    var _len: Int

    def __init__(out self):
        self._storage = Array[Byte, Self.capacity](fill=0)
        self._len = 0

    def __len__(self) -> Int:
        return self._len

    @always_inline
    def __getitem__(ref self, idx: Int) -> ref [self._storage] Byte:
        debug_assert(idx >= 0 and idx < self._len, "ByteVec index out of range")
        return self._storage[idx]

    @always_inline
    def __setitem__(mut self, idx: Int, value: Byte):
        debug_assert(idx >= 0 and idx < self._len, "ByteVec index out of range")
        self._storage[idx] = value

    def append(mut self, b: Byte) raises:
        if self._len >= Self.capacity:
            raise "ByteVec overflow: capacity=" + String(Self.capacity)
        self._storage[self._len] = b
        self._len += 1

    def extend(mut self, data: Span[Byte, _]) raises:
        if self._len + len(data) > Self.capacity:
            raise "ByteVec overflow: need " + String(len(data)) + ", have " + String(Self.capacity - self._len)
        for i in range(len(data)):
            self._storage[self._len + i] = data[i]
        self._len += len(data)

    def as_span(ref self) -> Span[Byte, origin_of(self._storage)]:
        return Span(unsafe_ptr=Pointer(to=self._storage.unsafe_ptr()[]), length=self._len)

    def clear(mut self):
        self._len = 0

    def remaining_capacity(self) -> Int:
        return Self.capacity - self._len

    def unsafe_ptr(ref self) -> UnsafePointer[Byte, origin_of(self._storage)]:
        """Pointer to the first byte; valid only while `self` is alive."""
        return self._storage.unsafe_ptr()


@fieldwise_init
struct OwnedBuf[capacity: Int](Movable, Sized):
    """Heap-allocated-once, fixed-capacity byte buffer. Raises on overflow.

    Struct holds 16 bytes (pointer + length). The backing
    Array[Byte, capacity] lives at a stable heap address for the
    struct's lifetime. No reallocation.
    """

    var _storage: OwnedPointer[Array[Byte, Self.capacity]]
    var _len: Int

    def __init__(out self):
        self._storage = OwnedPointer(Array[Byte, Self.capacity](fill=0))
        self._len = 0

    def __len__(self) -> Int:
        return self._len

    @always_inline
    def __getitem__(self, idx: Int) -> Byte:
        debug_assert(idx >= 0 and idx < self._len, "OwnedBuf index out of range")
        return self._storage[][idx]

    @always_inline
    def __setitem__(mut self, idx: Int, value: Byte):
        debug_assert(idx >= 0 and idx < self._len, "OwnedBuf index out of range")
        self._storage[][idx] = value

    def append(mut self, b: Byte) raises:
        if self._len >= Self.capacity:
            raise "OwnedBuf overflow: capacity=" + String(Self.capacity)
        self._storage[][self._len] = b
        self._len += 1

    def extend(mut self, data: Span[Byte, _]) raises:
        if self._len + len(data) > Self.capacity:
            raise "OwnedBuf overflow: need " + String(len(data)) + ", have " + String(Self.capacity - self._len)
        for i in range(len(data)):
            self._storage[][self._len + i] = data[i]
        self._len += len(data)

    def as_span(ref self) -> Span[Byte, origin_of(self._storage[])]:
        # Return a Span whose lifetime is tied to the dereferenced Array.
        return Span(unsafe_ptr=self._storage[].unsafe_ptr(), length=self._len)

    def clear(mut self):
        self._len = 0

    def remaining_capacity(self) -> Int:
        return Self.capacity - self._len

    def unsafe_ptr(ref self) -> UnsafePointer[Byte, origin_of(self._storage[])]:
        """Pointer to the heap backing store; valid only while `self` is alive."""
        return self._storage[].unsafe_ptr()
