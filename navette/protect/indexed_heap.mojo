"""Exact indexed binary max-heap over item ids in [0, capacity).

Keys are a lexicographic pair `(hi, lo)`. Fair share keys sources by
`(count, admission_seq)`, so the peek returns the largest source with
ties going to the most recent admission; the memory budget keys them by
`(mem, 0)`. Updates are O(log n) and the peek is O(1); the position
index makes every update and removal a direct sift, never a scan.
"""

comptime _ABSENT: Int32 = -1


struct IndexedMaxHeap(Movable, Sized):
    """Items are ids the caller owns; `set` inserts or re-keys, `remove` deletes."""

    var _heap: List[Int32]
    var _pos: List[Int32]
    var _hi: List[UInt64]
    var _lo: List[UInt64]

    def __init__(out self, capacity: Int):
        self._heap = List[Int32](capacity=capacity)
        self._pos = List[Int32](length=capacity, fill=_ABSENT)
        self._hi = List[UInt64](length=capacity, fill=UInt64(0))
        self._lo = List[UInt64](length=capacity, fill=UInt64(0))

    def __len__(self) -> Int:
        return len(self._heap)

    def contains(self, item: Int) -> Bool:
        return self._pos[item] != _ABSENT

    def top(self) -> Int:
        """Item with the largest key, or -1 when empty."""
        if len(self._heap) == 0:
            return -1
        return Int(self._heap[0])

    def key_hi(self, item: Int) -> UInt64:
        return self._hi[item]

    @always_inline
    def _above(self, a: Int, b: Int) -> Bool:
        """Item `a` strictly outranks item `b`."""
        if self._hi[a] != self._hi[b]:
            return self._hi[a] > self._hi[b]
        return self._lo[a] > self._lo[b]

    def _swap(mut self, i: Int, j: Int):
        var a = self._heap[i]
        var b = self._heap[j]
        self._heap[i] = b
        self._heap[j] = a
        self._pos[Int(b)] = Int32(i)
        self._pos[Int(a)] = Int32(j)

    def _sift_up(mut self, var i: Int):
        while i > 0:
            var p = (i - 1) // 2
            if not self._above(Int(self._heap[i]), Int(self._heap[p])):
                return
            self._swap(i, p)
            i = p

    def _sift_down(mut self, var i: Int):
        var n = len(self._heap)
        while True:
            var l = 2 * i + 1
            if l >= n:
                return
            var best = l
            var r = l + 1
            if r < n and self._above(Int(self._heap[r]), Int(self._heap[l])):
                best = r
            if not self._above(Int(self._heap[best]), Int(self._heap[i])):
                return
            self._swap(i, best)
            i = best

    def set(mut self, item: Int, hi: UInt64, lo: UInt64):
        """Insert `item` or change its key."""
        self._hi[item] = hi
        self._lo[item] = lo
        var p = self._pos[item]
        if p == _ABSENT:
            self._heap.append(Int32(item))
            self._pos[item] = Int32(len(self._heap) - 1)
            self._sift_up(len(self._heap) - 1)
            return
        self._sift_up(Int(p))
        self._sift_down(Int(self._pos[item]))

    def remove(mut self, item: Int):
        """Delete `item`; a no-op when absent."""
        var p = self._pos[item]
        if p == _ABSENT:
            return
        var last = len(self._heap) - 1
        if Int(p) != last:
            self._swap(Int(p), last)
        _ = self._heap.pop()
        self._pos[item] = _ABSENT
        if Int(p) < len(self._heap):
            self._sift_up(Int(p))
            self._sift_down(Int(p))

    def heap_property_holds(self) -> Bool:
        """Test oracle: parent ≥ child everywhere and `_pos` mirrors `_heap`."""
        for i in range(len(self._heap)):
            if Int(self._pos[Int(self._heap[i])]) != i:
                return False
            if i > 0 and self._above(Int(self._heap[i]), Int(self._heap[(i - 1) // 2])):
                return False
        return True
