"""Connection pools, per-source counts and max-min fair-share admission.

One `ConnPool` per server. It owns the connection ids (dense in
`[0, conn_cap + closing_cap)`), so every other structure — the server's
own slots, the ready list, the memory budget — refers to a connection by
a stable id that never moves; H3 swap-and-pop only rewrites the server's
id ↔ slot map.

Invariants at every method boundary (checked by `invariant_violation`):
- every id is in exactly one of free / admitted / closing;
- `admitted ≤ conn_cap`, `closing ≤ closing_cap`;
- `count[src]` = validated admitted connections of `src`, and a source
  is in the table iff its count is > 0 (`sources_active`);
- unvalidated connections belong to no source and sit in one FIFO;
- `handshaking` = number of flagged ids (cleared on established, on
  entering closing, on release).

The pool decides; the server acts. `admit` returns what to do with an
evicted victim and with a closing entry force-closed to make room.
Only validated connections (and never-admitted H1 flushes) enter the
closing pool: an unvalidated QUIC peer has established no state, so it
gets its close once and no closing state (RFC 9000 Section 10.2), and a
flood of forged addresses cannot occupy the pool. A full closing pool
only ever gives up an entry of the requester's own source: one address
churning connections must not be able to cut another source's drain or
flush short.
Every transition taking an id is a no-op on a negative id, and every
read accessor answers a neutral value (free, not validated/busy/
handshaking, source -1, empty key, deadline and kind 0), so the -1
"none" that `admit` and `pop_expired_closing` return can be passed back
unchecked.
"""

from navette.protect.descriptor_budget import check_pool_caps
from navette.protect.indexed_heap import IndexedMaxHeap
from navette.protect.source_key import SourceKey
from navette.protect.source_table import SourceTable
from navette.util.siphash import SipKey

comptime POOL_FREE: UInt8 = 0
comptime POOL_ADMITTED: UInt8 = 1
comptime POOL_CLOSING: UInt8 = 2

comptime CLOSE_FLUSH: UInt8 = 1
comptime CLOSE_DRAIN: UInt8 = 2
comptime CLOSE_QUIC: UInt8 = 3

comptime FLUSH_DEADLINE_US: UInt64 = 2_000_000
comptime DRAIN_DEADLINE_US: UInt64 = 10_000_000

comptime ADMIT: Int = 0
comptime ADMIT_EVICT_UNVALIDATED: Int = 1
comptime ADMIT_EVICT_FAIR: Int = 2
comptime REJECT: Int = 3

comptime CLOSING_REFUSED: Int = -2
"""`to_closing` result: the id may not enter closing (it is unvalidated, or the pool is full with no entry of its source); nothing changed, so the caller closes it outright and releases it."""

comptime _NONE: Int32 = -1


@fieldwise_init
struct AdmitOutcome(Copyable, Movable):
    """What `admit` did and what the server must now do.

    - `id`: the new connection's id, -1 on `REJECT`.
    - `victim`: the evicted connection, -1 when none. When
      `victim_drains` is False its id is already released — and may be the
      very `id` handed to the newcomer — so tear the victim down through
      the server's id map BEFORE binding `id`: kill it silently
      (unvalidated H3) or with RST / GOAWAY+close, and never call
      `release` on it. When True it is now in the closing pool
      as a drain: send GOAWAY and let the request in progress finish.
      A busy victim is killed rather than drained when the closing pool
      is full and holds no entry of the victim's own source.
    - `forced`: a closing entry of the victim's source force-closed (and
      released) to make room for the draining victim, -1 when none; also
      torn down before `id` is bound.
    """

    var kind: Int
    var id: Int
    var victim: Int
    var victim_drains: Bool
    var forced: Int


@fieldwise_init
struct ClosingEntry(Copyable, Movable):
    """`id` of a connection placed straight into the closing pool (-1 when refused), and the `forced` entry released for it (-1 when none)."""

    var id: Int
    var forced: Int


struct ConnPool(Movable):
    """Per-server admitted and closing pools with fair-share admission; see the module docstring."""

    var conn_cap: Int
    var closing_cap: Int
    var admitted: Int
    var closing: Int
    var unvalidated: Int
    var handshaking: Int
    var closing_refused: UInt64
    """Closes turned away by a full closing pool: `to_closing` refusals of a validated id (fair-share drains included) and `enter_closing` -1."""
    var busy_victims_killed: UInt64
    """Busy fair-share victims closed outright because the closing pool had no room for their drain."""

    var _pool: List[UInt8]
    var _key: List[SourceKey]
    var _src: List[Int32]
    var _busy: List[Bool]
    var _hs: List[Bool]
    var _list: List[Int32]
    var _prev: List[Int32]
    var _next: List[Int32]
    var _deadline: List[UInt64]
    var _close_kind: List[UInt8]
    var _free_ids: List[Int32]

    var _table: SourceTable
    var _count: List[Int]
    var _adm_seq: List[UInt64]
    var _heap: IndexedMaxHeap
    var _heads: List[Int32]
    var _tails: List[Int32]
    var _seq: UInt64

    def __init__(out self, conn_cap: Int, closing_cap: Int, sip: SipKey) raises:
        """Allocate every table for `conn_cap + closing_cap` ids; nothing allocates afterwards.

        Raises unless `conn_cap` is in `[1, MAX_CONN_CAP]` and `closing_cap`
        in `[1, MAX_CLOSING_CAP]`: with no closing entry a busy victim
        could never drain, and the bounds keep `conn_cap + closing_cap`
        from wrapping.
        """
        check_pool_caps(conn_cap, closing_cap, 1)
        self.conn_cap = conn_cap
        self.closing_cap = closing_cap
        self.admitted = 0
        self.closing = 0
        self.unvalidated = 0
        self.handshaking = 0
        self.closing_refused = 0
        self.busy_victims_killed = 0
        var n = conn_cap + closing_cap
        self._pool = List[UInt8](length=n, fill=POOL_FREE)
        self._key = List[SourceKey](capacity=n)
        for _ in range(n):
            self._key.append(SourceKey())
        self._src = List[Int32](length=n, fill=_NONE)
        self._busy = List[Bool](length=n, fill=False)
        self._hs = List[Bool](length=n, fill=False)
        self._list = List[Int32](length=n, fill=_NONE)
        self._prev = List[Int32](length=n, fill=_NONE)
        self._next = List[Int32](length=n, fill=_NONE)
        self._deadline = List[UInt64](length=n, fill=UInt64(0))
        self._close_kind = List[UInt8](length=n, fill=UInt8(0))
        self._free_ids = List[Int32](capacity=n)
        for i in range(n - 1, -1, -1):
            self._free_ids.append(Int32(i))
        self._table = SourceTable(n, sip)
        self._count = List[Int](length=n, fill=0)
        self._adm_seq = List[UInt64](length=n, fill=UInt64(0))
        self._heap = IndexedMaxHeap(n)
        # Lists: 2*s idle, 2*s+1 busy for source slot s; then the
        # unvalidated FIFO and the closing list.
        self._heads = List[Int32](length=2 * n + 2, fill=_NONE)
        self._tails = List[Int32](length=2 * n + 2, fill=_NONE)
        self._seq = UInt64(0)

    # ── Intrusive lists ────────────────────────────────────────────

    @always_inline
    def _unvalidated_list(self) -> Int:
        return 2 * len(self._pool)

    @always_inline
    def _closing_list(self) -> Int:
        return 2 * len(self._pool) + 1

    def _link_tail(mut self, id: Int, lst: Int):
        var t = self._tails[lst]
        self._list[id] = Int32(lst)
        self._prev[id] = t
        self._next[id] = _NONE
        if t == _NONE:
            self._heads[lst] = Int32(id)
        else:
            self._next[Int(t)] = Int32(id)
        self._tails[lst] = Int32(id)

    def _unlink(mut self, id: Int):
        var lst = self._list[id]
        if lst == _NONE:
            return
        var p = self._prev[id]
        var nx = self._next[id]
        if p == _NONE:
            self._heads[Int(lst)] = nx
        else:
            self._next[Int(p)] = nx
        if nx == _NONE:
            self._tails[Int(lst)] = p
        else:
            self._prev[Int(nx)] = p
        self._list[id] = _NONE
        self._prev[id] = _NONE
        self._next[id] = _NONE

    @always_inline
    def _source_list(self, id: Int) -> Int:
        return 2 * Int(self._src[id]) + (1 if self._busy[id] else 0)

    # ── Sources ────────────────────────────────────────────────────

    def sources_active(self) -> Int:
        """Sources with at least one validated admitted connection."""
        return len(self._table)

    def count_of(self, key: SourceKey) -> Int:
        var s = self._table.find(key)
        if s < 0:
            return 0
        return self._count[s]

    def source_of(self, id: Int) -> Int:
        """Source slot of a validated admitted connection, -1 otherwise."""
        if id < 0:
            return -1
        return Int(self._src[id])

    def dispatch_sources(self) -> Int:
        """Source count to size this pool's `ReadyList` with: every source slot, then the closing pseudo-source."""
        return len(self._pool) + 1

    def dispatch_source_of(self, id: Int) -> Int:
        """The `ReadyList` source to queue `id` under; -1 for a free, unvalidated or negative id.

        A validated admitted id dispatches as its source slot. Every closing
        entry (a drained victim finishing its request, a flush) dispatches
        as the closing pseudo-source `dispatch_sources() - 1`: its old slot
        may already be reused by another source. The answer changes on
        `validate` and `to_closing`, so push a queued id again after either
        (a push under a new source moves it).

        Ordering contract for the run loop, since `ReadyList.push` raises
        on -1: push only an id this answers >= 0 for (an unvalidated H3
        connection is validated first, or not queued). The pool releases
        some ids itself before the caller sees them (an `admit` victim or
        forced entry, `pop_expired_closing`), so `remove` a released id
        from the ready list before it is rebound or any further pool call,
        as `AdmitOutcome` requires; a stale entry then never outlives its
        connection. Otherwise a peer can trigger the raise.
        """
        if id < 0:
            return -1
        var p = self._pool[id]
        if p == POOL_CLOSING:
            return len(self._pool)
        if p == POOL_ADMITTED:
            return Int(self._src[id])
        return -1

    def key_of(self, id: Int) -> SourceKey:
        """The id's source key; the empty key for -1."""
        if id < 0:
            return SourceKey()
        return self._key[id].copy()

    def largest_source(self) -> Int:
        """Source slot with the most validated connections; ties go to the most recent admission. -1 when none."""
        return self._heap.top()

    def largest_count(self) -> Int:
        var s = self._heap.top()
        if s < 0:
            return 0
        return self._count[s]

    def _attach(mut self, id: Int):
        """Count a validated admitted id towards its source (an admission)."""
        var s = self._table.insert(self._key[id])
        self._src[id] = Int32(s)
        self._count[s] += 1
        self._seq += 1
        self._adm_seq[s] = self._seq
        self._heap.set(s, UInt64(self._count[s]), self._seq)
        self._link_tail(id, self._source_list(id))

    def _detach(mut self, id: Int):
        """Stop counting `id`; drop the source when its count reaches 0."""
        var s = Int(self._src[id])
        self._unlink(id)
        self._src[id] = _NONE
        self._count[s] -= 1
        if self._count[s] == 0:
            self._heap.remove(s)
            _ = self._table.remove(self._key[id])
        else:
            self._heap.set(s, UInt64(self._count[s]), self._adm_seq[s])

    # ── Admission ──────────────────────────────────────────────────

    def _victim_of(self, s: Int) -> Int:
        """Least recently active idle connection of source `s`, else its least recently active busy one."""
        var idle = self._heads[2 * s]
        if idle != _NONE:
            return Int(idle)
        return Int(self._heads[2 * s + 1])

    def decide(self, key: SourceKey, validated: Bool) -> Int:
        """The max-min fair-share rule; pure. Returns ADMIT, ADMIT_EVICT_UNVALIDATED, ADMIT_EVICT_FAIR or REJECT."""
        if self.admitted < self.conn_cap:
            return ADMIT
        if validated and self._heads[self._unvalidated_list()] != _NONE:
            return ADMIT_EVICT_UNVALIDATED
        var l = self._heap.top()
        if validated and l >= 0 and self.count_of(key) + 1 < self._count[l]:
            return ADMIT_EVICT_FAIR
        return REJECT

    def admit(mut self, key: SourceKey, validated: Bool, handshaking: Bool, now_us: UInt64) -> AdmitOutcome:
        """Apply `decide`, evicting as it says, then register the new connection."""
        var kind = self.decide(key, validated)
        if kind == REJECT:
            return AdmitOutcome(kind=REJECT, id=-1, victim=-1, victim_drains=False, forced=-1)
        var victim = -1
        var drains = False
        var forced = -1
        if kind == ADMIT_EVICT_UNVALIDATED:
            victim = Int(self._heads[self._unvalidated_list()])
            self.release(victim)
        elif kind == ADMIT_EVICT_FAIR:
            victim = self._victim_of(self._heap.top())
            if self._busy[victim]:
                forced = self.to_closing(victim, now_us + DRAIN_DEADLINE_US, CLOSE_DRAIN)
                drains = forced != CLOSING_REFUSED
                if not drains:
                    forced = -1
                    self.busy_victims_killed += 1
                    self.release(victim)
            else:
                self.release(victim)
        var id = Int(self._free_ids.pop())
        self._pool[id] = POOL_ADMITTED
        self._key[id] = key.copy()
        self._busy[id] = False
        self._hs[id] = handshaking
        if handshaking:
            self.handshaking += 1
        self.admitted += 1
        if validated:
            self._attach(id)
        else:
            self.unvalidated += 1
            self._link_tail(id, self._unvalidated_list())
        return AdmitOutcome(kind=kind, id=id, victim=victim, victim_drains=drains, forced=forced)

    def validate(mut self, id: Int):
        """An unvalidated admitted connection proved its address (valid token or handshake done)."""
        if id < 0 or self._pool[id] != POOL_ADMITTED or self._src[id] != _NONE:
            return
        self._unlink(id)
        self.unvalidated -= 1
        self._attach(id)

    def is_validated(self, id: Int) -> Bool:
        return id >= 0 and self._src[id] != _NONE

    def touch(mut self, id: Int):
        """Request activity: move a validated connection to the most-recent end of its source's list."""
        if id < 0 or self._src[id] == _NONE:
            return
        self._unlink(id)
        self._link_tail(id, self._source_list(id))

    def set_busy(mut self, id: Int, busy: Bool):
        """A request started (headers complete) or the last one finished; a no-op unless `id` is admitted.

        A closing connection keeps the flag it had when it left the pool,
        and a free id stays idle, so a late call from the server can't
        mark a slot busy that `admit` would then hand out.
        """
        if id < 0 or self._pool[id] != POOL_ADMITTED or self._busy[id] == busy:
            return
        self._busy[id] = busy
        if self._src[id] != _NONE:
            self._unlink(id)
            self._link_tail(id, self._source_list(id))

    def is_busy(self, id: Int) -> Bool:
        return id >= 0 and self._busy[id]

    def is_handshaking(self, id: Int) -> Bool:
        return id >= 0 and self._hs[id]

    def handshake_done(mut self, id: Int):
        """Clear the once-only handshake flag; idempotent."""
        if id >= 0 and self._hs[id]:
            self._hs[id] = False
            self.handshaking -= 1

    def pool_of(self, id: Int) -> UInt8:
        """POOL_FREE for -1."""
        if id < 0:
            return POOL_FREE
        return self._pool[id]

    # ── Closing pool ───────────────────────────────────────────────

    def closing_at_most_half_full(self) -> Bool:
        """408 entries may enter the closing pool only while this holds."""
        return 2 * self.closing <= self.closing_cap

    def closing_at_least_half_full(self) -> Bool:
        """Rejections get RST instead of a closing entry while this holds."""
        return 2 * self.closing >= self.closing_cap

    def earliest_closing(self) -> Int:
        """Closing entry with the earliest deadline, -1 when empty. Scans ≤ closing_cap entries (rare path)."""
        var best = -1
        var c = self._heads[self._closing_list()]
        while c != _NONE:
            if best < 0 or self._deadline[Int(c)] < self._deadline[best]:
                best = Int(c)
            c = self._next[Int(c)]
        return best

    def pop_expired_closing(mut self, now_us: UInt64) -> Int:
        """Release and return one closing entry whose deadline passed, -1 when none; the server force-closes it."""
        var e = self.earliest_closing()
        if e < 0 or self._deadline[e] > now_us:
            return -1
        self.release(e)
        return e

    def closing_deadline(self, id: Int) -> UInt64:
        """0 for -1."""
        if id < 0:
            return UInt64(0)
        return self._deadline[id]

    def closing_kind(self, id: Int) -> UInt8:
        """0 (no close kind) for -1."""
        if id < 0:
            return UInt8(0)
        return self._close_kind[id]

    def _earliest_closing_of(self, key: SourceKey) -> Int:
        """Earliest-deadline closing entry carrying `key`, -1 when none. Scans ≤ closing_cap entries."""
        var best = -1
        var c = self._heads[self._closing_list()]
        while c != _NONE:
            var ci = Int(c)
            if self._key[ci] == key and (best < 0 or self._deadline[ci] < self._deadline[best]):
                best = ci
            c = self._next[ci]
        return best

    def _closing_room_for(self, key: SourceKey) -> Int:
        """-1 when the closing pool has a free entry; else the entry to force-close for `key`, or CLOSING_REFUSED.

        Only an entry of the requester's own (proven) source may be
        displaced: otherwise one address could churn connections through
        the full pool and kill another source's in-flight drains and
        flushes at its connect rate.
        """
        if self.closing < self.closing_cap:
            return -1
        var e = self._earliest_closing_of(key)
        return e if e >= 0 else CLOSING_REFUSED

    def to_closing(mut self, id: Int, deadline_us: UInt64, kind: UInt8) -> Int:
        """Move a validated admitted connection to the closing pool; returns the force-closed entry, -1, or CLOSING_REFUSED.

        CLOSING_REFUSED changes nothing; the caller closes `id` outright
        (RST, or one CONNECTION_CLOSE) and releases it. It is returned for
        an unvalidated id, whose key is spoofable and which has no state
        worth a closing period, and for a full pool with no entry of
        `id`'s source to give up (room comes only from its earliest-deadline one).
        A no-op returning -1 when `id` is free or already closing: moving
        it anyway would unlink it from the wrong list and drift the pool
        counters, and a repeated close would force-close an innocent entry.
        """
        if id < 0 or self._pool[id] != POOL_ADMITTED:
            return -1
        if self._src[id] == _NONE:
            return CLOSING_REFUSED
        var forced = self._closing_room_for(self._key[id])
        if forced == CLOSING_REFUSED:
            self.closing_refused += 1
            return CLOSING_REFUSED
        self.release(forced)
        self._detach(id)
        self.handshake_done(id)
        self.admitted -= 1
        self._pool[id] = POOL_CLOSING
        self.closing += 1
        self._deadline[id] = deadline_us
        self._close_kind[id] = kind
        self._link_tail(id, self._closing_list())
        return forced

    def enter_closing(mut self, key: SourceKey, deadline_us: UInt64, kind: UInt8) -> ClosingEntry:
        """Place a never-admitted connection (an H1 503 flush) straight into the closing pool.

        `key` must be a proven address (a TCP peer). When the pool is full,
        room comes only from the earliest-deadline entry of `key`'s source;
        with none, returns id -1 and changes nothing (send an RST instead).
        """
        var forced = self._closing_room_for(key)
        if forced == CLOSING_REFUSED:
            self.closing_refused += 1
            return ClosingEntry(id=-1, forced=-1)
        self.release(forced)
        var id = Int(self._free_ids.pop())
        self._pool[id] = POOL_CLOSING
        self._key[id] = key.copy()
        self._busy[id] = False
        self._hs[id] = False
        self.closing += 1
        self._deadline[id] = deadline_us
        self._close_kind[id] = kind
        self._link_tail(id, self._closing_list())
        return ClosingEntry(id=id, forced=forced)

    def release(mut self, id: Int):
        """Free `id` from whichever pool holds it; a no-op on a free id."""
        if id < 0:
            return
        var p = self._pool[id]
        if p == POOL_FREE:
            return
        if p == POOL_ADMITTED:
            if self._src[id] != _NONE:
                self._detach(id)
            else:
                self._unlink(id)
                self.unvalidated -= 1
            self.admitted -= 1
        else:
            self._unlink(id)
            self.closing -= 1
        self.handshake_done(id)
        self._busy[id] = False
        self._pool[id] = POOL_FREE
        self._free_ids.append(Int32(id))

    # ── Test oracle ────────────────────────────────────────────────

    def invariant_violation(self) -> String:
        """Empty when every module-docstring invariant holds; otherwise the first one broken. O(n), tests only."""
        var n = len(self._pool)
        var adm = 0
        var clo = 0
        var unv = 0
        var hs = 0
        var free = 0
        var counts = List[Int](length=n, fill=0)
        for id in range(n):
            var p = self._pool[id]
            if self._hs[id]:
                hs += 1
            if p == POOL_FREE:
                free += 1
                if self._list[id] != _NONE or self._hs[id] or self._busy[id]:
                    return "free id " + String(id) + " still linked or flagged"
            elif p == POOL_ADMITTED:
                adm += 1
                if self._src[id] == _NONE:
                    unv += 1
                    if Int(self._list[id]) != self._unvalidated_list():
                        return "unvalidated id " + String(id) + " not in the FIFO"
                else:
                    var s = Int(self._src[id])
                    counts[s] += 1
                    if not self._table.is_live(s) or self._table.key_of(s) != self._key[id]:
                        return "id " + String(id) + " points at a wrong source"
                    if Int(self._list[id]) != self._source_list(id):
                        return "id " + String(id) + " in the wrong source list"
            else:
                clo += 1
                if self._src[id] != _NONE or Int(self._list[id]) != self._closing_list():
                    return "closing id " + String(id) + " counted or unlisted"
                if self._hs[id]:
                    return "closing id " + String(id) + " still handshaking"
        if adm != self.admitted or clo != self.closing or unv != self.unvalidated or hs != self.handshaking:
            return "pool counters drifted"
        if adm > self.conn_cap or clo > self.closing_cap:
            return "pool bound exceeded"
        if free != len(self._free_ids):
            return "free list size drifted"
        var live_sources = 0
        for s in range(n):
            if self._table.is_live(s):
                live_sources += 1
                if counts[s] == 0 or counts[s] != self._count[s]:
                    return "count of source " + String(s) + " wrong"
                if not self._heap.contains(s) or self._heap.key_hi(s) != UInt64(counts[s]):
                    return "heap key of source " + String(s) + " wrong"
            elif self._heap.contains(s) or counts[s] != 0:
                return "dead source " + String(s) + " still counted"
        if live_sources != len(self._table):
            return "sources_active drifted"
        if not self._table.probe_invariant_holds():
            return "source table has tombstones"
        if not self._heap.heap_property_holds():
            return "count heap broken"
        # Every list is a consistent doubly-linked chain whose members agree on `_list`.
        for lst in range(len(self._heads)):
            var prev = _NONE
            var c = self._heads[lst]
            while c != _NONE:
                if Int(self._list[Int(c)]) != lst or self._prev[Int(c)] != prev:
                    return "list " + String(lst) + " links broken"
                prev = c
                c = self._next[Int(c)]
            if self._tails[lst] != prev:
                return "list " + String(lst) + " tail wrong"
        return ""
