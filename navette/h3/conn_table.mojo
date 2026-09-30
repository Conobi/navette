"""Stable H3 connection ids, their generation tags and every DCID demux key they own.

The server keeps connections in a swap-and-pop array, so a connection's
slot index moves; its id does not. Demux keys map to `(generation, id)`,
and an id's generation is bumped when it is released, so a key can never
route to the connection that reused the id. The table also carries the
per-connection "address not validated yet" flag and its live count, the
input of the Retry threshold.
"""

from navette.quic.cid import MAX_ISSUED_CIDS

# The client's Initial DCID plus every CID we issued.
comptime KEYS_PER_CONN: Int = 1 + MAX_ISSUED_CIDS


struct ConnTable(Movable):
    """Fixed-capacity id allocator plus a key -> connection map; nothing allocates after construction.

    Invariants (`invariant_violation` checks them): every map entry
    belongs to a live id that lists the key, and the map holds exactly
    the keys the ids list; `unvalidated_count` equals the flagged live
    ids; free ids plus live ids equal the capacity. Ids come from a LIFO
    free list; an external allocator can replace it later without
    changing the rest of the contract.
    """

    var capacity: Int
    var live: Int
    var unvalidated_count: Int
    var _slot: List[Int32]  # -1 while the id is free
    var _gen: List[UInt32]
    var _keys: List[UInt64]  # capacity x KEYS_PER_CONN, first _nkeys[id] used
    var _nkeys: List[UInt8]
    var _unval: List[Bool]
    var _free: List[Int32]
    var _map: Dict[UInt64, UInt64]  # key -> gen << 32 | id

    def __init__(out self, capacity: Int):
        self.capacity = capacity
        self.live = 0
        self.unvalidated_count = 0
        self._slot = List[Int32](length=capacity, fill=Int32(-1))
        self._gen = List[UInt32](length=capacity, fill=UInt32(0))
        self._keys = List[UInt64](length=capacity * KEYS_PER_CONN, fill=UInt64(0))
        self._nkeys = List[UInt8](length=capacity, fill=UInt8(0))
        self._unval = List[Bool](length=capacity, fill=False)
        self._free = List[Int32](capacity=capacity)
        for i in range(capacity - 1, -1, -1):
            self._free.append(Int32(i))
        self._map = Dict[UInt64, UInt64](capacity=max(capacity * KEYS_PER_CONN, 8))

    def open(mut self, slot: Int, unvalidated: Bool) -> Int:
        """A fresh id placed at `slot`, or -1 when every id is live."""
        if len(self._free) == 0:
            return -1
        var id = Int(self._free.pop())
        self._slot[id] = Int32(slot)
        self._nkeys[id] = 0
        self._unval[id] = unvalidated
        if unvalidated:
            self.unvalidated_count += 1
        self.live += 1
        return id

    def add_key(mut self, id: Int, key: UInt64) -> Bool:
        """Route `key` to `id`. False when another id owns the key or `id` already holds KEYS_PER_CONN keys.

        Re-adding a key `id` already owns is True and changes nothing, so
        two DCIDs that collide on one key cannot be split between
        connections.
        """
        var cur = self._map.find(key)
        if cur:
            return cur.value() == self._tag(id)
        var n = Int(self._nkeys[id])
        if n >= KEYS_PER_CONN:
            return False
        self._keys[id * KEYS_PER_CONN + n] = key
        self._nkeys[id] = UInt8(n + 1)
        self._map[key] = self._tag(id)
        return True

    def remove_key(mut self, id: Int, key: UInt64):
        """Stop routing `key`; a no-op unless `id` owns it."""
        var cur = self._map.find(key)
        if not cur or cur.value() != self._tag(id):
            return
        _ = self._map.pop(key, UInt64(0))
        var base = id * KEYS_PER_CONN
        var n = Int(self._nkeys[id])
        for i in range(n):
            if self._keys[base + i] == key:
                self._keys[base + i] = self._keys[base + n - 1]
                self._nkeys[id] = UInt8(n - 1)
                return

    def validate(mut self, id: Int):
        """Mark the peer's address validated (Retry token or handshake done); idempotent."""
        if self._unval[id]:
            self._unval[id] = False
            self.unvalidated_count -= 1

    def moved(mut self, id: Int, slot: Int):
        """Record that the server moved `id`'s connection to `slot` (swap-and-pop)."""
        self._slot[id] = Int32(slot)

    def release(mut self, id: Int, gen: UInt32):
        """Free `id` and every key it owns, if `gen` is its current generation.

        A release with an older generation (a double free after the id was
        reused) is a no-op, so it cannot tear down the new connection.
        """
        if id < 0 or id >= self.capacity or self._slot[id] < 0 or self._gen[id] != gen:
            return
        var base = id * KEYS_PER_CONN
        for i in range(Int(self._nkeys[id])):
            _ = self._map.pop(self._keys[base + i], UInt64(0))
        self._nkeys[id] = 0
        self.validate(id)
        self._gen[id] = gen + 1
        self._slot[id] = -1
        self._free.append(Int32(id))
        self.live -= 1

    @always_inline
    def lookup(self, key: UInt64) -> Int:
        """The slot of the connection owning `key`, or -1: one map probe."""
        var id = self.id_of_key(key)
        if id < 0:
            return -1
        return Int(self._slot[id])

    @always_inline
    def id_of_key(self, key: UInt64) -> Int:
        """The live id owning `key`, or -1 (absent, or tagged with a generation no longer current)."""
        var cur = self._map.find(key)
        if not cur:
            return -1
        var tag = cur.value()
        var id = Int(tag & 0xFFFF_FFFF)
        if self._gen[id] != UInt32(tag >> 32) or self._slot[id] < 0:
            return -1
        return id

    def gen_of(self, id: Int) -> UInt32:
        return self._gen[id]

    def slot_of(self, id: Int) -> Int:
        """-1 while `id` is free."""
        return Int(self._slot[id])

    def is_unvalidated(self, id: Int) -> Bool:
        return self._unval[id]

    def key_count(self, id: Int) -> Int:
        return Int(self._nkeys[id])

    def key_at(self, id: Int, i: Int) -> UInt64:
        """The `i`-th key `id` owns, `i < key_count(id)`; order changes on `remove_key`."""
        return self._keys[id * KEYS_PER_CONN + i]

    @always_inline
    def _tag(self, id: Int) -> UInt64:
        return (UInt64(self._gen[id]) << 32) | UInt64(id)

    def invariant_violation(self) -> String:
        """Empty when every invariant holds, else the first one broken (for tests and debug asserts)."""
        var total = 0
        var flagged = 0
        var live = 0
        for id in range(self.capacity):
            if self._slot[id] < 0:
                if self._nkeys[id] != 0 or self._unval[id]:
                    return "free id " + String(id) + " holds keys or a flag"
                continue
            live += 1
            if self._unval[id]:
                flagged += 1
            var n = Int(self._nkeys[id])
            total += n
            for i in range(n):
                var key = self._keys[id * KEYS_PER_CONN + i]
                var cur = self._map.find(key)
                if not cur or cur.value() != self._tag(id):
                    return "id " + String(id) + " lists key " + String(key) + " the map does not route to it"
        if total != len(self._map):
            return "map holds " + String(len(self._map)) + " keys, ids list " + String(total)
        if flagged != self.unvalidated_count:
            return "unvalidated_count " + String(self.unvalidated_count) + " != flagged " + String(flagged)
        if live != self.live or live + len(self._free) != self.capacity:
            return "live " + String(self.live) + " / " + String(live) + ", free " + String(len(self._free))
        return String()
