"""Process-wide memory budget with per-source eviction.

One `MemoryBudget` spans every server in the process. Each connection
that buffers bytes (send or receive side) holds a handle and reports its
current total with `set_mem`; the budget keeps `Σ mem`, the per-source
sums and an exact max-heap over them.

While `Σ mem > budget`, `pick_victim` names the heaviest connection of
the heaviest source, but only if that source holds more than
`share = budget / sources_active`. A source at or below its share is
never picked, so attackers can shrink an honest source to `budget / k`
and never below it.

Unvalidated connections (H3 before address validation) are
unattributed: their bytes count towards `Σ mem` but towards no source,
and they never make a source active, so spoofed Initials cannot inflate
any source's share or weight.
"""

from navette.protect.descriptor_budget import MAX_CONN_CAP, MAX_CLOSING_CAP
from navette.protect.indexed_heap import IndexedMaxHeap
from navette.protect.source_key import SourceKey
from navette.protect.source_table import SourceTable
from navette.util.siphash import SipKey

comptime DEFAULT_MEM_BUDGET_BYTES: Int = 512 * 1024 * 1024
comptime _NONE: Int32 = -1
comptime _MAX_HANDLES: Int = 1 << 31


struct MemoryBudget(Movable):
    """Shared by pointer (`ArcPointer`) across the servers of one process; single-threaded."""

    var budget: Int
    var total: Int
    var memory_evictions: UInt64

    var _table: SourceTable
    var _src_mem: List[Int]
    var _src_head: List[Int32]
    var _heap: IndexedMaxHeap
    var _sip: SipKey

    var _server: List[Int32]
    var _conn: List[Int32]
    var _key: List[SourceKey]
    var _src: List[Int32]
    var _mem: List[Int]
    var _prev: List[Int32]
    var _next: List[Int32]
    var _live: List[Bool]
    var _free: List[Int32]

    def __init__(out self, budget_bytes: Int, max_conns: Int, sip: SipKey) raises:
        """`max_conns` bounds live handles across all servers; `reserve` raises it before the first handle.

        Raises when `budget_bytes < 1` (a zero budget would evict every
        attributed connection) or `max_conns ≥ 2^31` (handles are Int32).
        """
        if budget_bytes < 1:
            raise "MemoryBudget: budget_bytes must be >= 1"
        if max_conns >= _MAX_HANDLES:
            raise "MemoryBudget: max_conns must be below 2^31"
        self.budget = budget_bytes
        self.total = 0
        self.memory_evictions = UInt64(0)
        self._sip = SipKey(k0=sip.k0, k1=sip.k1)
        self._table = SourceTable(max(max_conns, 1), sip)
        self._src_mem = List[Int]()
        self._src_head = List[Int32]()
        self._heap = IndexedMaxHeap(max(max_conns, 1))
        self._server = List[Int32]()
        self._conn = List[Int32]()
        self._key = List[SourceKey]()
        self._src = List[Int32]()
        self._mem = List[Int]()
        self._prev = List[Int32]()
        self._next = List[Int32]()
        self._live = List[Bool]()
        self._free = List[Int32]()
        self._grow(max(max_conns, 1))

    def _grow(mut self, n: Int):
        var old = len(self._server)
        for _ in range(old, n):
            self._server.append(_NONE)
            self._conn.append(_NONE)
            self._key.append(SourceKey())
            self._src.append(_NONE)
            self._mem.append(0)
            self._prev.append(_NONE)
            self._next.append(_NONE)
            self._live.append(False)
            self._src_mem.append(0)
            self._src_head.append(_NONE)
        self._free = List[Int32](capacity=n)
        for i in range(n - 1, -1, -1):
            if not self._live[i]:
                self._free.append(Int32(i))

    def capacity(self) -> Int:
        return len(self._server)

    def reserve(mut self, extra_conns: Int) raises:
        """Grow capacity by `extra_conns` handles; each server calls it once in `start()`, before any handle exists.

        Raises unless `extra_conns` is in `[0, MAX_CONN_CAP + MAX_CLOSING_CAP]`
        (one server's ids) and the new capacity stays below 2^31: handles
        are stored as Int32, and a negative value would shrink the tables
        below `capacity()`.
        """
        if self.handles() != 0:
            raise "MemoryBudget.reserve: size the budget before the first connection"
        if extra_conns < 0 or extra_conns > MAX_CONN_CAP + MAX_CLOSING_CAP:
            raise "MemoryBudget.reserve: extra_conns must be in 0.." + String(MAX_CONN_CAP + MAX_CLOSING_CAP)
        var n = self.capacity() + extra_conns
        if n >= _MAX_HANDLES:
            raise "MemoryBudget.reserve: capacity would reach 2^31 handles"
        self._grow(n)
        self._table = SourceTable(n, self._sip)
        self._heap = IndexedMaxHeap(n)

    def handles(self) -> Int:
        return self.capacity() - len(self._free)

    def sources_active(self) -> Int:
        """Sources with at least one validated connection holding a handle."""
        return len(self._table)

    def over_budget(self) -> Bool:
        return self.total > self.budget

    def share(self) -> Int:
        """`budget / sources_active`; the whole budget when no source is active."""
        var k = len(self._table)
        if k == 0:
            return self.budget
        return self.budget // k

    def source_mem(self, key: SourceKey) -> Int:
        var s = self._table.find(key)
        if s < 0:
            return 0
        return self._src_mem[s]

    def server_of(self, h: Int) -> Int:
        return Int(self._server[h])

    def conn_of(self, h: Int) -> Int:
        return Int(self._conn[h])

    def mem_of(self, h: Int) -> Int:
        return self._mem[h]

    def key_of(self, h: Int) -> SourceKey:
        return self._key[h].copy()

    def _attach(mut self, h: Int):
        var s = self._table.insert(self._key[h])
        self._src[h] = Int32(s)
        var head = self._src_head[s]
        self._prev[h] = _NONE
        self._next[h] = head
        if head != _NONE:
            self._prev[Int(head)] = Int32(h)
        self._src_head[s] = Int32(h)
        self._src_mem[s] += self._mem[h]
        self._heap.set(s, UInt64(self._src_mem[s]), UInt64(0))

    def _detach(mut self, h: Int):
        var s = Int(self._src[h])
        var p = self._prev[h]
        var nx = self._next[h]
        if p == _NONE:
            self._src_head[s] = nx
        else:
            self._next[Int(p)] = nx
        if nx != _NONE:
            self._prev[Int(nx)] = p
        self._src_mem[s] -= self._mem[h]
        self._src[h] = _NONE
        if self._src_head[s] == _NONE:
            self._heap.remove(s)
            _ = self._table.remove(self._key[h])
            self._src_mem[s] = 0
        else:
            self._heap.set(s, UInt64(self._src_mem[s]), UInt64(0))

    def register(mut self, server_id: Int, conn_id: Int, key: SourceKey, validated: Bool) -> Int:
        """New handle with 0 bytes; -1 when every handle is taken (the caller then runs unaccounted)."""
        if len(self._free) == 0:
            return -1
        var h = Int(self._free.pop())
        self._live[h] = True
        self._server[h] = Int32(server_id)
        self._conn[h] = Int32(conn_id)
        self._key[h] = key.copy()
        self._mem[h] = 0
        self._src[h] = _NONE
        if validated:
            self._attach(h)
        return h

    def validate(mut self, h: Int):
        """The connection's address is now validated: start counting it for its source."""
        if h >= 0 and self._live[h] and self._src[h] == _NONE:
            self._attach(h)

    def set_mem(mut self, h: Int, bytes: Int):
        """Report the connection's current buffered bytes (send + receive); O(log sources) when attributed.

        A no-op on -1 or a dead handle, so a connection running unaccounted
        can report unconditionally. Negative `bytes` count as 0: a negative
        source sum would wrap its unsigned heap key and pin that source as
        the heaviest.
        """
        if h < 0 or not self._live[h]:
            return
        var clamped = max(bytes, 0)
        var delta = clamped - self._mem[h]
        if delta == 0:
            return
        self._mem[h] = clamped
        self.total += delta
        if self._src[h] != _NONE:
            var s = Int(self._src[h])
            self._src_mem[s] += delta
            self._heap.set(s, UInt64(self._src_mem[s]), UInt64(0))

    def unregister(mut self, h: Int):
        """Drop the handle and its bytes; a no-op on -1 or a dead handle."""
        if h < 0 or not self._live[h]:
            return
        self.set_mem(h, 0)
        if self._src[h] != _NONE:
            self._detach(h)
        self._live[h] = False
        self._free.append(Int32(h))

    def pick_victim(self) -> Int:
        """Handle to evict now, or -1: over budget and the heaviest source above its share → its heaviest connection.

        O(connections of that source) per call: the heaviest connection is
        found by scanning the source's list (eviction is the rare path).
        """
        if not self.over_budget():
            return -1
        var s = self._heap.top()
        if s < 0 or self._src_mem[s] <= self.share():
            return -1
        var best = -1
        var h = self._src_head[s]
        while h != _NONE:
            if best < 0 or self._mem[Int(h)] > self._mem[best]:
                best = Int(h)
            h = self._next[Int(h)]
        return best

    def note_eviction(mut self):
        self.memory_evictions += 1

    def invariant_violation(self) -> String:
        """Empty when totals, per-source sums, heap keys, the source table and per-source lists agree; tests only.

        Every attributed handle's key must be its source slot's key, and
        the table's live count and probe chains must be intact.
        Each live source's list must reach exactly its attributed handles,
        with consistent back links and no cycle; a dead source has no list.
        Unattributed handles only count towards the total.
        """
        var n = self.capacity()
        var total = 0
        var attributed = 0
        var sums = List[Int](length=n, fill=0)
        for h in range(n):
            if not self._live[h]:
                continue
            total += self._mem[h]
            if self._src[h] != _NONE:
                var s = Int(self._src[h])
                attributed += 1
                sums[s] += self._mem[h]
                if not self._table.is_live(s) or self._table.key_of(s) != self._key[h]:
                    return "handle " + String(h) + " points at a wrong source"
        if total != self.total:
            return "total drifted"
        var live_sources = 0
        for s in range(n):
            if self._table.is_live(s):
                live_sources += 1
                if sums[s] != self._src_mem[s]:
                    return "source sum drifted"
                if not self._heap.contains(s) or self._heap.key_hi(s) != UInt64(sums[s]):
                    return "heap key drifted"
                if self._src_head[s] == _NONE:
                    return "live source without connections"
            elif self._heap.contains(s):
                return "dead source in heap"
        if live_sources != len(self._table):
            return "sources_active drifted"
        if not self._table.probe_invariant_holds():
            return "source table probe chain broken"
        if not self._heap.heap_property_holds():
            return "heap broken"
        var listed = 0
        for s in range(n):
            var h = self._src_head[s]
            if not self._table.is_live(s):
                if h != _NONE:
                    return "dead source " + String(s) + " still has a list"
                continue
            var prev = _NONE
            var steps = 0
            while h != _NONE:
                steps += 1
                if steps > n:
                    return "source " + String(s) + " list loops"
                var hi = Int(h)
                if not self._live[hi] or Int(self._src[hi]) != s:
                    return "handle " + String(hi) + " in the list of source " + String(s)
                if self._prev[hi] != prev:
                    return "source " + String(s) + " back link broken at handle " + String(hi)
                prev = h
                h = self._next[hi]
            listed += steps
        if listed != attributed:
            return "attributed handle missing from its source list"
        return ""
