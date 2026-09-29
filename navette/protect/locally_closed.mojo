"""Bitmap of client-initiated H2 streams we refused or reset.

Covers the 1,024 most recent client stream ids (odd ids spanning 2,048
values ending at `last`, the highest id the peer opened). Frames on a
marked stream are ignored instead of answered, so a peer that keeps
sending after our RST_STREAM costs no output and no error budget. Ids
older than the window are no longer marked; the caller treats them as
ordinary closed streams.
"""

from std.collections import InlineArray

comptime LOCALLY_CLOSED_WINDOW: Int = 1024
comptime _WORDS: Int = LOCALLY_CLOSED_WINDOW // 64


struct LocallyClosedSet(Copyable, Movable):
    """`advance` must follow every increase of the peer's highest stream id before `mark` / `is_marked`."""

    var _bits: InlineArray[UInt64, _WORDS]
    var _last: UInt32

    def __init__(out self):
        self._bits = InlineArray[UInt64, _WORDS](fill=UInt64(0))
        self._last = 0

    @always_inline
    def _index(self, sid: UInt32) -> Int:
        return Int((sid >> 1) & UInt32(LOCALLY_CLOSED_WINDOW - 1))

    def in_window(self, sid: UInt32) -> Bool:
        return (sid & 1) == 1 and sid <= self._last and self._last - sid < UInt32(2 * LOCALLY_CLOSED_WINDOW)

    def advance(mut self, new_last: UInt32):
        """Slide the window to end at `new_last`, clearing the bits the new ids reuse."""
        if new_last <= self._last:
            return
        var first = self._last + (UInt32(2) if (self._last & 1) == 1 else UInt32(1))
        var n = 0 if first > new_last else Int((new_last - first) // 2) + 1
        if n >= LOCALLY_CLOSED_WINDOW:
            for i in range(_WORDS):
                self._bits[i] = 0
        else:
            for k in range(n):
                var idx = self._index(first + UInt32(2 * k))
                self._bits[idx >> 6] &= ~(UInt64(1) << UInt64(idx & 63))
        self._last = new_last

    def mark(mut self, sid: UInt32):
        """Mark a stream we refused or reset; ignored outside the window."""
        if not self.in_window(sid):
            return
        var idx = self._index(sid)
        self._bits[idx >> 6] |= UInt64(1) << UInt64(idx & 63)

    def is_marked(self, sid: UInt32) -> Bool:
        if not self.in_window(sid):
            return False
        var idx = self._index(sid)
        return (self._bits[idx >> 6] >> UInt64(idx & 63)) & 1 == 1
