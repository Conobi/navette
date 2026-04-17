# src/h3/qpack.mojo
# QPACK codec: static table, Huffman, encoder, decoder
# RFC 9204 (QPACK), RFC 7541 Appendix B (Huffman table)


struct QpackStaticEntry(Copyable, Movable):
    var name: String
    var value: String

    def __init__(out self, name: String, value: String):
        self.name = name
        self.value = value

    def __init__(out self, *, copy_from: Self):
        self.name = copy_from.name
        self.value = copy_from.value


struct QpackHeaderField(Copyable, Movable):
    var name: String
    var value: String

    def __init__(out self, name: String, value: String):
        self.name = name
        self.value = value

    def __init__(out self, *, copy_from: Self):
        self.name = copy_from.name
        self.value = copy_from.value


# QPACK static table — RFC 9204 Appendix A (99 entries, indices 0–98)
comptime QPACK_STATIC_TABLE_SIZE: Int = 99


def _qpack_static_table() -> List[QpackStaticEntry]:
    var t = List[QpackStaticEntry]()
    # RFC 9204 Appendix A — complete table, indices 0–98
    t.append(QpackStaticEntry(":authority", ""))               # 0
    t.append(QpackStaticEntry(":path", "/"))                   # 1
    t.append(QpackStaticEntry("age", "0"))                     # 2
    t.append(QpackStaticEntry("content-disposition", ""))      # 3
    t.append(QpackStaticEntry("content-length", "0"))          # 4
    t.append(QpackStaticEntry("cookie", ""))                   # 5
    t.append(QpackStaticEntry("date", ""))                     # 6
    t.append(QpackStaticEntry("etag", ""))                     # 7
    t.append(QpackStaticEntry("if-modified-since", ""))        # 8
    t.append(QpackStaticEntry("if-none-match", ""))            # 9
    t.append(QpackStaticEntry("last-modified", ""))            # 10
    t.append(QpackStaticEntry("link", ""))                     # 11
    t.append(QpackStaticEntry("location", ""))                 # 12
    t.append(QpackStaticEntry("referer", ""))                  # 13
    t.append(QpackStaticEntry("set-cookie", ""))               # 14
    t.append(QpackStaticEntry(":method", "CONNECT"))           # 15
    t.append(QpackStaticEntry(":method", "DELETE"))            # 16
    t.append(QpackStaticEntry(":method", "GET"))               # 17
    t.append(QpackStaticEntry(":method", "HEAD"))              # 18
    t.append(QpackStaticEntry(":method", "OPTIONS"))           # 19
    t.append(QpackStaticEntry(":method", "POST"))              # 20
    t.append(QpackStaticEntry(":method", "PUT"))               # 21
    t.append(QpackStaticEntry(":scheme", "http"))              # 22
    t.append(QpackStaticEntry(":scheme", "https"))             # 23
    t.append(QpackStaticEntry(":status", "103"))               # 24
    t.append(QpackStaticEntry(":status", "200"))               # 25
    t.append(QpackStaticEntry(":status", "304"))               # 26
    t.append(QpackStaticEntry(":status", "404"))               # 27
    t.append(QpackStaticEntry(":status", "503"))               # 28
    t.append(QpackStaticEntry("accept", "*/*"))                # 29
    t.append(QpackStaticEntry("accept", "application/dns-message"))  # 30
    t.append(QpackStaticEntry("accept-encoding", "gzip, deflate, br"))  # 31
    t.append(QpackStaticEntry("accept-ranges", "bytes"))       # 32
    t.append(QpackStaticEntry("access-control-allow-headers", "cache-control"))  # 33
    t.append(QpackStaticEntry("access-control-allow-headers", "content-type"))   # 34
    t.append(QpackStaticEntry("access-control-allow-origin", "*"))               # 35
    t.append(QpackStaticEntry("cache-control", "max-age=0"))                     # 36
    t.append(QpackStaticEntry("cache-control", "max-age=2592000"))               # 37
    t.append(QpackStaticEntry("cache-control", "max-age=604800"))                # 38
    t.append(QpackStaticEntry("cache-control", "no-cache"))                      # 39
    t.append(QpackStaticEntry("cache-control", "no-store"))                      # 40
    t.append(QpackStaticEntry("cache-control", "public, max-age=31536000"))      # 41
    t.append(QpackStaticEntry("content-encoding", "br"))                         # 42
    t.append(QpackStaticEntry("content-encoding", "gzip"))                       # 43
    t.append(QpackStaticEntry("content-type", "application/dns-message"))        # 44
    t.append(QpackStaticEntry("content-type", "application/javascript"))         # 45
    t.append(QpackStaticEntry("content-type", "application/json"))               # 46
    t.append(QpackStaticEntry("content-type", "application/x-www-form-urlencoded"))  # 47
    t.append(QpackStaticEntry("content-type", "image/gif"))                      # 48
    t.append(QpackStaticEntry("content-type", "image/jpeg"))                     # 49
    t.append(QpackStaticEntry("content-type", "image/png"))                      # 50
    t.append(QpackStaticEntry("content-type", "text/css"))                       # 51
    t.append(QpackStaticEntry("content-type", "text/html;charset=utf-8"))        # 52
    t.append(QpackStaticEntry("content-type", "text/plain"))                     # 53
    t.append(QpackStaticEntry("content-type", "text/plain;charset=utf-8"))       # 54
    t.append(QpackStaticEntry("range", "bytes=0-"))                              # 55
    t.append(QpackStaticEntry("strict-transport-security", "max-age=31536000"))  # 56
    t.append(QpackStaticEntry("strict-transport-security", "max-age=31536000;includesubdomains"))          # 57
    t.append(QpackStaticEntry("strict-transport-security", "max-age=31536000;includesubdomains;preload"))  # 58
    t.append(QpackStaticEntry("vary", "accept-encoding"))                        # 59
    t.append(QpackStaticEntry("vary", "origin"))                                 # 60
    t.append(QpackStaticEntry("x-content-type-options", "nosniff"))              # 61
    t.append(QpackStaticEntry("x-xss-protection", "1; mode=block"))              # 62
    t.append(QpackStaticEntry(":status", "100"))                                 # 63
    t.append(QpackStaticEntry(":status", "204"))                                 # 64
    t.append(QpackStaticEntry(":status", "206"))                                 # 65
    t.append(QpackStaticEntry(":status", "302"))                                 # 66
    t.append(QpackStaticEntry(":status", "400"))                                 # 67
    t.append(QpackStaticEntry(":status", "403"))                                 # 68
    t.append(QpackStaticEntry(":status", "421"))                                 # 69
    t.append(QpackStaticEntry(":status", "425"))                                 # 70
    t.append(QpackStaticEntry(":status", "500"))                                 # 71
    t.append(QpackStaticEntry("accept-language", ""))                            # 72
    t.append(QpackStaticEntry("access-control-allow-credentials", "FALSE"))      # 73
    t.append(QpackStaticEntry("access-control-allow-credentials", "TRUE"))       # 74
    t.append(QpackStaticEntry("access-control-allow-headers", "*"))              # 75
    t.append(QpackStaticEntry("access-control-allow-methods", "get"))            # 76
    t.append(QpackStaticEntry("access-control-allow-methods", "get, post, options"))  # 77
    t.append(QpackStaticEntry("access-control-allow-methods", "options"))        # 78
    t.append(QpackStaticEntry("access-control-expose-headers", "content-length"))  # 79
    t.append(QpackStaticEntry("access-control-request-headers", "content-type")) # 80
    t.append(QpackStaticEntry("access-control-request-method", "get"))           # 81
    t.append(QpackStaticEntry("access-control-request-method", "post"))          # 82
    t.append(QpackStaticEntry("alt-svc", "clear"))                               # 83
    t.append(QpackStaticEntry("authorization", ""))                              # 84
    t.append(QpackStaticEntry("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"))  # 85
    t.append(QpackStaticEntry("early-data", "1"))                                # 86
    t.append(QpackStaticEntry("expect-ct", ""))                                  # 87
    t.append(QpackStaticEntry("forwarded", ""))                                  # 88
    t.append(QpackStaticEntry("if-range", ""))                                   # 89
    t.append(QpackStaticEntry("origin", ""))                                     # 90
    t.append(QpackStaticEntry("purpose", "prefetch"))                            # 91
    t.append(QpackStaticEntry("server", ""))                                     # 92
    t.append(QpackStaticEntry("timing-allow-origin", "*"))                       # 93
    t.append(QpackStaticEntry("upgrade-insecure-requests", "1"))                 # 94
    t.append(QpackStaticEntry("user-agent", ""))                                 # 95
    t.append(QpackStaticEntry("x-forwarded-for", ""))                            # 96
    t.append(QpackStaticEntry("x-frame-options", "deny"))                        # 97
    t.append(QpackStaticEntry("x-frame-options", "sameorigin"))                  # 98
    return t^


def qpack_static_get(index: Int) raises -> QpackStaticEntry:
    """Return the static table entry at the given index. Raises if out of range."""
    if index < 0 or index >= QPACK_STATIC_TABLE_SIZE:
        raise "QPACK: static table index out of range: " + String(index)
    var table = _qpack_static_table()
    return table[index].copy()


def qpack_static_find(name: String, value: String) -> Optional[Int]:
    """Find the first static table index where both name and value match exactly."""
    var table = _qpack_static_table()
    for i in range(len(table)):
        if table[i].name == name and table[i].value == value:
            return Optional[Int](i)
    return Optional[Int](None)


def qpack_static_find_name(name: String) -> Optional[Int]:
    """Find the first static table index where name matches (any value)."""
    var table = _qpack_static_table()
    for i in range(len(table)):
        if table[i].name == name:
            return Optional[Int](i)
    return Optional[Int](None)


# ---------------------------------------------------------------------------
# Stubs — Huffman, encoder, decoder (implemented in T3-T5)
# ---------------------------------------------------------------------------

def huffman_encode(data: List[UInt8]) -> List[UInt8] raises:
    """Huffman-encode a byte sequence (stub — T3)."""
    raise "huffman_encode: not yet implemented"
    return List[UInt8]()


def huffman_decode(data: List[UInt8]) -> List[UInt8] raises:
    """Huffman-decode a byte sequence (stub — T3)."""
    raise "huffman_decode: not yet implemented"
    return List[UInt8]()


struct QpackEncoder(Copyable, Movable):
    """QPACK encoder stub — implemented in T4."""

    def __init__(out self):
        pass

    def __init__(out self, *, copy_from: Self):
        pass


struct QpackDecoder(Copyable, Movable):
    """QPACK decoder stub — implemented in T5."""

    def __init__(out self):
        pass

    def __init__(out self, *, copy_from: Self):
        pass
