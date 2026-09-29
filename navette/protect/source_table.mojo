"""Fixed-capacity `SourceKey` → dense slot map, open addressing with backward-shift deletion.

Keys are placed by SipHash-1-3 under a per-process random key, so a
client cannot choose addresses that collide into one probe chain.
Deletion shifts the following cluster back instead of leaving
tombstones: probe lengths never grow with churn, which is what keeps
admission and close O(1) under a connect/disconnect flood.
"""

from navette.protect.source_key import SourceKey
from navette.util.siphash import SipKey

comptime _EMPTY: Int32 = -1


def _pow2_at_least(n: Int) -> Int:
    var p = 1
    while p < n:
        p <<= 1
    return p


struct SourceTable(Movable, Sized):
    """At most `capacity` live sources; slot ids are dense in [0, capacity) and reused after `remove`.

    The cell array is at least twice the capacity (load ≤ 0.5), so an
    insert never fails while fewer than `capacity` sources are live.
    """

    var _cells: List[Int32]
    var _mask: Int
    var _keys: List[SourceKey]
    var _homes: List[Int]
    var _live: List[Bool]
    var _free: List[Int32]
    var _len: Int
    var _sip: SipKey

    def __init__(out self, capacity: Int, sip: SipKey):
        var cap = max(capacity, 1)
        var ncells = _pow2_at_least(2 * cap)
        self._cells = List[Int32](length=ncells, fill=_EMPTY)
        self._mask = ncells - 1
        self._keys = List[SourceKey](capacity=cap)
        for _ in range(cap):
            self._keys.append(SourceKey())
        self._homes = List[Int](length=cap, fill=0)
        self._live = List[Bool](length=cap, fill=False)
        self._free = List[Int32](capacity=cap)
        for i in range(cap - 1, -1, -1):
            self._free.append(Int32(i))
        self._len = 0
        self._sip = SipKey(k0=sip.k0, k1=sip.k1)

    def __len__(self) -> Int:
        return self._len

    def capacity(self) -> Int:
        return len(self._keys)

    def key_of(self, slot: Int) -> SourceKey:
        return self._keys[slot].copy()

    def is_live(self, slot: Int) -> Bool:
        return self._live[slot]

    def _cell_of(self, key: SourceKey) -> Int:
        """Cell holding `key`, or -1. One chain walk, no tombstones to skip."""
        var c = Int(key.hash(self._sip)) & self._mask
        while True:
            var s = self._cells[c]
            if s == _EMPTY:
                return -1
            if self._keys[Int(s)] == key:
                return c
            c = (c + 1) & self._mask

    def find(self, key: SourceKey) -> Int:
        """Slot of `key`, or -1 when absent."""
        var c = self._cell_of(key)
        if c < 0:
            return -1
        return Int(self._cells[c])

    def insert(mut self, key: SourceKey) -> Int:
        """Slot of `key`, allocating one if absent; -1 when `capacity` sources are live."""
        var home = Int(key.hash(self._sip)) & self._mask
        var c = home
        while True:
            var s = self._cells[c]
            if s == _EMPTY:
                break
            if self._keys[Int(s)] == key:
                return Int(s)
            c = (c + 1) & self._mask
        if len(self._free) == 0:
            return -1
        var slot = Int(self._free.pop())
        self._keys[slot] = key.copy()
        self._homes[slot] = home
        self._live[slot] = True
        self._cells[c] = Int32(slot)
        self._len += 1
        return slot

    def remove(mut self, key: SourceKey) -> Bool:
        """Delete `key` with backward shift; False when absent."""
        var hole = self._cell_of(key)
        if hole < 0:
            return False
        var slot = Int(self._cells[hole])
        self._live[slot] = False
        self._free.append(Int32(slot))
        self._len -= 1
        var c = (hole + 1) & self._mask
        while self._cells[c] != _EMPTY:
            var home = self._homes[Int(self._cells[c])]
            # Move the entry back iff its home is not cyclically in (hole, c].
            var dist_c = (c - home) & self._mask
            var dist_hole = (hole - home) & self._mask
            if dist_hole < dist_c:
                self._cells[hole] = self._cells[c]
                hole = c
            c = (c + 1) & self._mask
        self._cells[hole] = _EMPTY
        return True

    def probe_invariant_holds(self) -> Bool:
        """Test oracle: every live entry is reachable from its home cell without crossing an empty cell."""
        var seen = 0
        for c in range(len(self._cells)):
            var s = self._cells[c]
            if s == _EMPTY:
                continue
            seen += 1
            if not self._live[Int(s)]:
                return False
            var h = self._homes[Int(s)]
            var i = h
            while i != c:
                if self._cells[i] == _EMPTY:
                    return False
                i = (i + 1) & self._mask
        return seen == self._len
