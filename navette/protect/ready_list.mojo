"""Two-level round-robin dispatch: fair per source, then per connection.

The ring holds sources; each source holds a ring of its ready
connections. `next` hands out up to 16 dispatches per source per round,
rotating across that source's connections, and stops when the pass
budget (1,024) is spent. A host with 2,000 connections therefore gets
the same dispatch share per pass as a host with one. Push, remove and
next are O(1); nothing allocates after construction.
"""

comptime DISPATCH_PER_SOURCE_ROUND: Int = 16
comptime DISPATCH_PASS_BUDGET: Int = 1024
comptime _NONE: Int32 = -1


struct ReadyList(Movable, Sized):
    """Connection ids in [0, max_conns), source slots in [0, max_sources)."""

    var _csrc: List[Int32]
    var _cprev: List[Int32]
    var _cnext: List[Int32]
    var _shead: List[Int32]
    var _sprev: List[Int32]
    var _snext: List[Int32]
    var _cursor: Int32
    var _quota: Int
    var _pass_left: Int
    var _len: Int

    def __init__(out self, max_conns: Int, max_sources: Int):
        self._csrc = List[Int32](length=max_conns, fill=_NONE)
        self._cprev = List[Int32](length=max_conns, fill=_NONE)
        self._cnext = List[Int32](length=max_conns, fill=_NONE)
        self._shead = List[Int32](length=max_sources, fill=_NONE)
        self._sprev = List[Int32](length=max_sources, fill=_NONE)
        self._snext = List[Int32](length=max_sources, fill=_NONE)
        self._cursor = _NONE
        self._quota = DISPATCH_PER_SOURCE_ROUND
        self._pass_left = 0
        self._len = 0

    def __len__(self) -> Int:
        return self._len

    def contains(self, conn: Int) -> Bool:
        """False for ids outside [0, max_conns), including -1."""
        return self._conn_in_range(conn) and self._csrc[conn] != _NONE

    @always_inline
    def _conn_in_range(self, conn: Int) -> Bool:
        return conn >= 0 and conn < len(self._csrc)

    def begin_pass(mut self):
        """Refill the pass budget; the round position carries over, so no source restarts ahead of its turn."""
        self._pass_left = DISPATCH_PASS_BUDGET

    def push(mut self, conn: Int, src: Int) raises:
        """Queue `conn` (of source slot `src`) at the end of its source's rotation.

        Idempotent under the same `src`; under another one the connection
        moves (its source changed, e.g. it entered the closing pool).
        Raises when `conn` or `src` is out of range (including -1): a
        dropped push would leave a connection with work never dispatched.
        Callers must make that unreachable from the network: take `src`
        from `ConnPool.dispatch_source_of` only after checking it is >= 0
        (validate before push). `ConnPool` itself releases ids (an `admit`
        victim or forced entry, `pop_expired_closing`) before the caller
        sees them, so `remove` a released id before it is rebound or any
        further pool call, as `AdmitOutcome` requires.
        """
        if not self._conn_in_range(conn) or src < 0 or src >= len(self._shead):
            raise Error("ReadyList.push: connection " + String(conn) + " / source " + String(src) + " out of range")
        var cur = self._csrc[conn]
        if Int(cur) == src:
            return
        if cur != _NONE:
            self.remove(conn)
        self._csrc[conn] = Int32(src)
        self._len += 1
        var h = self._shead[src]
        if h == _NONE:
            self._cprev[conn] = Int32(conn)
            self._cnext[conn] = Int32(conn)
            self._shead[src] = Int32(conn)
            self._link_source(src)
            return
        var tail = self._cprev[Int(h)]
        self._cprev[conn] = tail
        self._cnext[conn] = h
        self._cnext[Int(tail)] = Int32(conn)
        self._cprev[Int(h)] = Int32(conn)

    def _link_source(mut self, src: Int):
        """New source enters just before the cursor: last in the current round."""
        if self._cursor == _NONE:
            self._sprev[src] = Int32(src)
            self._snext[src] = Int32(src)
            self._cursor = Int32(src)
            self._quota = DISPATCH_PER_SOURCE_ROUND
            return
        var c = Int(self._cursor)
        var p = self._sprev[c]
        self._sprev[src] = p
        self._snext[src] = Int32(c)
        self._snext[Int(p)] = Int32(src)
        self._sprev[c] = Int32(src)

    def _unlink_source(mut self, src: Int):
        var nx = self._snext[src]
        if Int(nx) == src:
            self._cursor = _NONE
        else:
            var p = self._sprev[src]
            self._snext[Int(p)] = nx
            self._sprev[Int(nx)] = p
            if Int(self._cursor) == src:
                self._cursor = nx
                self._quota = DISPATCH_PER_SOURCE_ROUND
        self._sprev[src] = _NONE
        self._snext[src] = _NONE

    def remove(mut self, conn: Int):
        """Dequeue `conn` (nothing left to dispatch, or it closed); a no-op when absent or out of range."""
        if not self._conn_in_range(conn):
            return
        var s32 = self._csrc[conn]
        if s32 == _NONE:
            return
        var src = Int(s32)
        self._csrc[conn] = _NONE
        self._len -= 1
        var nx = self._cnext[conn]
        if Int(nx) == conn:
            self._shead[src] = _NONE
            self._unlink_source(src)
        else:
            var p = self._cprev[conn]
            self._cnext[Int(p)] = nx
            self._cprev[Int(nx)] = p
            if Int(self._shead[src]) == conn:
                self._shead[src] = nx
        self._cprev[conn] = _NONE
        self._cnext[conn] = _NONE

    def next(mut self) -> Int:
        """Connection owed the next dispatch, or -1 when the list is empty or the pass budget is spent.

        The connection stays queued; the caller removes it once it has
        nothing more to dispatch.
        """
        if self._pass_left == 0 or self._cursor == _NONE:
            return -1
        var s = Int(self._cursor)
        var c = Int(self._shead[s])
        self._shead[s] = self._cnext[c]
        self._pass_left -= 1
        self._quota -= 1
        if self._quota == 0:
            self._cursor = self._snext[s]
            self._quota = DISPATCH_PER_SOURCE_ROUND
        return c
