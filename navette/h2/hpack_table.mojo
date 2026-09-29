# src/h2/hpack_table.mojo
#
# HPACK static and dynamic tables per RFC 7541 Section 2.3 and Appendix A.

from .header import Header
from navette.http.header_table_index import StaticTableIndex


struct StaticTable(Copyable, Movable):
    """HPACK static table -- 61 entries from RFC 7541 Appendix A."""

    var _entries: List[Tuple[String, String]]
    var _index: StaticTableIndex

    def __init__(out self):
        # RFC 7541 Appendix A — 61 entries as interleaved (name, value) literals.
        # Index 0 is unused (1-based indexing); a dummy ("","") entry leads.
        var d: List[String] = [
            "", "",  ":authority", "",  ":method", "GET",  ":method", "POST",
            ":path", "/",  ":path", "/index.html",  ":scheme", "http",
            ":scheme", "https",  ":status", "200",  ":status", "204",
            ":status", "206",  ":status", "304",  ":status", "400",
            ":status", "404",  ":status", "500",  "accept-charset", "",
            "accept-encoding", "gzip, deflate",  "accept-language", "",
            "accept-ranges", "",  "accept", "",
            "access-control-allow-origin", "",  "age", "",  "allow", "",
            "authorization", "",  "cache-control", "",  "content-disposition", "",
            "content-encoding", "",  "content-language", "",  "content-length", "",
            "content-location", "",  "content-range", "",  "content-type", "",
            "cookie", "",  "date", "",  "etag", "",  "expect", "",
            "expires", "",  "from", "",  "host", "",  "if-match", "",
            "if-modified-since", "",  "if-none-match", "",  "if-range", "",
            "if-unmodified-since", "",  "last-modified", "",  "link", "",
            "location", "",  "max-forwards", "",  "proxy-authenticate", "",
            "proxy-authorization", "",  "range", "",  "referer", "",
            "refresh", "",  "retry-after", "",  "server", "",
            "set-cookie", "",  "strict-transport-security", "",
            "transfer-encoding", "",  "user-agent", "",  "vary", "",
            "via", "",  "www-authenticate", "",
        ]
        self._entries = List[Tuple[String, String]](capacity=62)
        for i in range(62):
            self._entries.append((d[i * 2], d[i * 2 + 1]))
        self._index = StaticTableIndex(self._entries, start_index=1)

    def lookup(self, index: Int) -> Tuple[String, String]:
        """Get (name, value) at 1-based index (1-61).

        Returns ("","") if out of range.
        """
        if index < 1 or index > 61:
            return (String(""), String(""))
        return (self._entries[index][0], self._entries[index][1])

    def find(self, name: String, value: String) -> Tuple[Int, Bool]:
        """O(1) header lookup via index. Returns (index, exact_match).

        index=0 if not found (HPACK convention).
        """
        try:
            var result = self._index.find(name, value)
            if result[0] < 0:
                return (0, False)
            return result
        except:
            return (0, False)


struct DynamicTable(Movable):
    """HPACK dynamic table -- FIFO with size tracking and Dict index.

    Index 0 = newest entry. Eviction from the end (oldest).
    Maintains Dict indices for O(1) header lookup by name and name+value.
    """

    var entries: List[Header]
    var max_size: Int
    var current_size: Int
    var _next_seq: Int
    var _exact_index: Dict[String, Int]
    var _name_index: Dict[String, Int]

    def __init__(out self, max_size: Int = 4096):
        self.entries = List[Header]()
        self.max_size = max_size
        self.current_size = 0
        self._next_seq = 0
        self._exact_index = Dict[String, Int]()
        self._name_index = Dict[String, Int]()

    def _exact_key(self, name: String, value: String) -> String:
        """Build composite key for exact-match index."""
        return name + "\x00" + value

    def _evict_oldest(mut self):
        """Remove the oldest (back) entry and clean up Dict indices."""
        var idx = len(self.entries) - 1
        var evicted_name = self.entries[idx].name
        var evicted_value = self.entries[idx].value
        self.current_size -= evicted_name.byte_length() + evicted_value.byte_length() + 32

        # Sequence number of the evicted entry (oldest = lowest seq still in table)
        var evicted_seq = self._next_seq - len(self.entries)

        # Only remove Dict entries if they still point to the evicted seq
        var exact_key = self._exact_key(evicted_name, evicted_value)
        try:
            if self._exact_index[exact_key] == evicted_seq:
                _ = self._exact_index.pop(exact_key)
        except:
            pass
        try:
            if self._name_index[evicted_name] == evicted_seq:
                _ = self._name_index.pop(evicted_name)
        except:
            pass

        _ = self.entries.pop()

    def insert(mut self, name: String, value: String):
        """Insert at front. Evict from back until current_size <= max_size."""
        var entry_size = name.byte_length() + value.byte_length() + 32  # RFC 7541 Section 4.1
        # Evict oldest entries until there is room
        while self.current_size + entry_size > self.max_size and len(
            self.entries
        ) > 0:
            self._evict_oldest()
        # If entry itself is too large, table is cleared (entry is not added)
        if entry_size > self.max_size:
            return
        # Update Dict indices (unconditionally overwrite -- newest wins)
        var seq = self._next_seq
        self._exact_index[self._exact_key(name, value)] = seq
        self._name_index[name] = seq
        self._next_seq += 1
        # Insert at front by rebuilding
        var new_entries = List[Header]()
        new_entries.append(Header(name, value))
        for ref entry in self.entries:
            new_entries.append(
                Header(entry.name, entry.value)
            )
        self.entries = new_entries^
        self.current_size += entry_size

    def lookup(self, index: Int) -> Tuple[String, String]:
        """Get entry at 0-based dynamic index.

        CALLER converts from HPACK wire index: dynamic_index = wire_index - 62.
        """
        if index < 0 or index >= len(self.entries):
            return (String(""), String(""))
        return (self.entries[index].name, self.entries[index].value)

    def find(self, name: String, value: String) -> Tuple[Int, Bool]:
        """O(1) header lookup via Dict indices. Returns (0-based index, exact_match).

        Returns (-1, False) if not found.
        """
        # Try exact match first
        try:
            var seq = self._exact_index[self._exact_key(name, value)]
            var wire_idx = (self._next_seq - 1) - seq
            return (wire_idx, True)
        except:
            pass
        # Try name-only match
        try:
            var seq = self._name_index[name]
            var wire_idx = (self._next_seq - 1) - seq
            return (wire_idx, False)
        except:
            pass
        return (-1, False)

    def set_max_size(mut self, new_max: Int):
        """Set new max. Evict if needed. new_max=0 clears all entries."""
        self.max_size = new_max
        if new_max == 0:
            self.entries.clear()
            self.current_size = 0
            self._exact_index = Dict[String, Int]()
            self._name_index = Dict[String, Int]()
            return
        while self.current_size > self.max_size and len(self.entries) > 0:
            self._evict_oldest()

    def size(self) -> Int:
        """Number of entries."""
        return len(self.entries)

    def byte_size(self) -> Int:
        """Current size in bytes."""
        return self.current_size

    def entries_list(self) -> List[Header]:
        """Return copy of entries for test assertion."""
        var result = List[Header]()
        for ref entry in self.entries:
            result.append(
                Header(entry.name, entry.value)
            )
        return result^
