# src/h2/hpack_table.mojo
#
# HPACK static and dynamic tables per RFC 7541 Section 2.3 and Appendix A.

from .header import Header


struct StaticTable:
    """HPACK static table -- 61 entries from RFC 7541 Appendix A."""

    var _entries: List[Tuple[String, String]]

    def __init__(out self):
        self._entries = List[Tuple[String, String]]()
        # Index 0 is unused (1-based indexing); store a dummy entry.
        self._entries.append((String(""), String("")))
        #  1
        self._entries.append((String(":authority"), String("")))
        #  2
        self._entries.append((String(":method"), String("GET")))
        #  3
        self._entries.append((String(":method"), String("POST")))
        #  4
        self._entries.append((String(":path"), String("/")))
        #  5
        self._entries.append((String(":path"), String("/index.html")))
        #  6
        self._entries.append((String(":scheme"), String("http")))
        #  7
        self._entries.append((String(":scheme"), String("https")))
        #  8
        self._entries.append((String(":status"), String("200")))
        #  9
        self._entries.append((String(":status"), String("204")))
        # 10
        self._entries.append((String(":status"), String("206")))
        # 11
        self._entries.append((String(":status"), String("304")))
        # 12
        self._entries.append((String(":status"), String("400")))
        # 13
        self._entries.append((String(":status"), String("404")))
        # 14
        self._entries.append((String(":status"), String("500")))
        # 15
        self._entries.append((String("accept-charset"), String("")))
        # 16
        self._entries.append((String("accept-encoding"), String("gzip, deflate")))
        # 17
        self._entries.append((String("accept-language"), String("")))
        # 18
        self._entries.append((String("accept-ranges"), String("")))
        # 19
        self._entries.append((String("accept"), String("")))
        # 20
        self._entries.append((String("access-control-allow-origin"), String("")))
        # 21
        self._entries.append((String("age"), String("")))
        # 22
        self._entries.append((String("allow"), String("")))
        # 23
        self._entries.append((String("authorization"), String("")))
        # 24
        self._entries.append((String("cache-control"), String("")))
        # 25
        self._entries.append((String("content-disposition"), String("")))
        # 26
        self._entries.append((String("content-encoding"), String("")))
        # 27
        self._entries.append((String("content-language"), String("")))
        # 28
        self._entries.append((String("content-length"), String("")))
        # 29
        self._entries.append((String("content-location"), String("")))
        # 30
        self._entries.append((String("content-range"), String("")))
        # 31
        self._entries.append((String("content-type"), String("")))
        # 32
        self._entries.append((String("cookie"), String("")))
        # 33
        self._entries.append((String("date"), String("")))
        # 34
        self._entries.append((String("etag"), String("")))
        # 35
        self._entries.append((String("expect"), String("")))
        # 36
        self._entries.append((String("expires"), String("")))
        # 37
        self._entries.append((String("from"), String("")))
        # 38
        self._entries.append((String("host"), String("")))
        # 39
        self._entries.append((String("if-match"), String("")))
        # 40
        self._entries.append((String("if-modified-since"), String("")))
        # 41
        self._entries.append((String("if-none-match"), String("")))
        # 42
        self._entries.append((String("if-range"), String("")))
        # 43
        self._entries.append((String("if-unmodified-since"), String("")))
        # 44
        self._entries.append((String("last-modified"), String("")))
        # 45
        self._entries.append((String("link"), String("")))
        # 46
        self._entries.append((String("location"), String("")))
        # 47
        self._entries.append((String("max-forwards"), String("")))
        # 48
        self._entries.append((String("proxy-authenticate"), String("")))
        # 49
        self._entries.append((String("proxy-authorization"), String("")))
        # 50
        self._entries.append((String("range"), String("")))
        # 51
        self._entries.append((String("referer"), String("")))
        # 52
        self._entries.append((String("refresh"), String("")))
        # 53
        self._entries.append((String("retry-after"), String("")))
        # 54
        self._entries.append((String("server"), String("")))
        # 55
        self._entries.append((String("set-cookie"), String("")))
        # 56
        self._entries.append((String("strict-transport-security"), String("")))
        # 57
        self._entries.append((String("transfer-encoding"), String("")))
        # 58
        self._entries.append((String("user-agent"), String("")))
        # 59
        self._entries.append((String("vary"), String("")))
        # 60
        self._entries.append((String("via"), String("")))
        # 61
        self._entries.append((String("www-authenticate"), String("")))

    def lookup(self, index: Int) -> Tuple[String, String]:
        """Get (name, value) at 1-based index (1-61).

        Returns ("","") if out of range.
        """
        if index < 1 or index > 61:
            return (String(""), String(""))
        return (self._entries[index][0], self._entries[index][1])

    def find(self, name: String, value: String) -> Tuple[Int, Bool]:
        """Search for header. Returns (index, exact_match).

        index=0 if name not found. exact_match=True if name+value both match.
        """
        var name_match_idx = 0
        for i in range(1, 62):
            if self._entries[i][0] == name:
                if self._entries[i][1] == value:
                    return (i, True)
                if name_match_idx == 0:
                    name_match_idx = i
        return (name_match_idx, False)


struct DynamicTable(Movable):
    """HPACK dynamic table -- FIFO with size tracking.

    Index 0 = newest entry. Eviction from the end (oldest).
    """

    var entries: List[Header]
    var max_size: Int
    var current_size: Int

    def __init__(out self, max_size: Int = 4096):
        self.entries = List[Header]()
        self.max_size = max_size
        self.current_size = 0

    def __init__(out self, *, deinit take: Self):
        self.entries = take.entries^
        self.max_size = take.max_size
        self.current_size = take.current_size

    def insert(mut self, name: String, value: String):
        """Insert at front. Evict from back until current_size <= max_size."""
        var entry_size = name.byte_length() + value.byte_length() + 32  # RFC 7541 Section 4.1
        # Evict oldest entries until there is room
        while self.current_size + entry_size > self.max_size and len(
            self.entries
        ) > 0:
            var idx = len(self.entries) - 1
            self.current_size -= self.entries[idx].name.byte_length() + self.entries[idx].value.byte_length() + 32
            _ = self.entries.pop()
        # If entry itself is too large, table is cleared (entry is not added)
        if entry_size > self.max_size:
            return
        # Insert at front by rebuilding
        var new_entries = List[Header]()
        new_entries.append(Header(name, value))
        for i in range(len(self.entries)):
            new_entries.append(
                Header(self.entries[i].name, self.entries[i].value)
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
        """Search for header. Returns (0-based index, exact_match).

        Returns (-1, False) if not found.
        """
        var name_match_idx = -1
        for i in range(len(self.entries)):
            if self.entries[i].name == name:
                if self.entries[i].value == value:
                    return (i, True)
                if name_match_idx < 0:
                    name_match_idx = i
        return (name_match_idx, False)

    def set_max_size(mut self, new_max: Int):
        """Set new max. Evict if needed. new_max=0 clears all entries."""
        self.max_size = new_max
        while self.current_size > self.max_size and len(self.entries) > 0:
            var idx = len(self.entries) - 1
            self.current_size -= self.entries[idx].name.byte_length() + self.entries[idx].value.byte_length() + 32
            _ = self.entries.pop()

    def size(self) -> Int:
        """Number of entries."""
        return len(self.entries)

    def byte_size(self) -> Int:
        """Current size in bytes."""
        return self.current_size

    def entries_list(self) -> List[Header]:
        """Return copy of entries for test assertion."""
        var result = List[Header]()
        for i in range(len(self.entries)):
            result.append(
                Header(self.entries[i].name, self.entries[i].value)
            )
        return result^
