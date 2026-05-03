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

    def __init__(out self, var name: String, var value: String):
        self.name = name^
        self.value = value^

    def __init__(out self, *, copy_from: Self):
        self.name = copy_from.name
        self.value = copy_from.value

    def consume_value(deinit self) -> String:
        """Consume self and return the value String. Used by H3HandlerServer's
        _on_request to move the value out of a popped field instead of copying."""
        return self.value^


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
    t.append(QpackStaticEntry("content-type", "text/html; charset=utf-8"))       # 52
    t.append(QpackStaticEntry("content-type", "text/plain"))                     # 53
    t.append(QpackStaticEntry("content-type", "text/plain;charset=utf-8"))       # 54
    t.append(QpackStaticEntry("range", "bytes=0-"))                              # 55
    t.append(QpackStaticEntry("strict-transport-security", "max-age=31536000"))  # 56
    t.append(QpackStaticEntry("strict-transport-security", "max-age=31536000; includesubdomains"))         # 57
    t.append(QpackStaticEntry("strict-transport-security", "max-age=31536000; includesubdomains; preload")) # 58
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
# Huffman encode/decode — RFC 7541 Appendix B
# ---------------------------------------------------------------------------

struct HuffmanEntry(Copyable, Movable):
    var code: UInt32
    var nbits: UInt8

    def __init__(out self, code: UInt32, nbits: UInt8):
        self.code = code
        self.nbits = nbits

    def __init__(out self, *, copy_from: Self):
        self.code = copy_from.code
        self.nbits = copy_from.nbits


def _huffman_encode_table() -> List[HuffmanEntry]:
    """256-entry Huffman encode table from RFC 7541 Appendix B."""
    var t = List[HuffmanEntry]()
    t.append(HuffmanEntry(0x1ff8, 13))       # 0
    t.append(HuffmanEntry(0x7fffd8, 23))     # 1
    t.append(HuffmanEntry(0xfffffe2, 28))    # 2
    t.append(HuffmanEntry(0xfffffe3, 28))    # 3
    t.append(HuffmanEntry(0xfffffe4, 28))    # 4
    t.append(HuffmanEntry(0xfffffe5, 28))    # 5
    t.append(HuffmanEntry(0xfffffe6, 28))    # 6
    t.append(HuffmanEntry(0xfffffe7, 28))    # 7
    t.append(HuffmanEntry(0xfffffe8, 28))    # 8
    t.append(HuffmanEntry(0xffffea, 24))     # 9
    t.append(HuffmanEntry(0x3ffffffc, 30))   # 10
    t.append(HuffmanEntry(0xfffffe9, 28))    # 11
    t.append(HuffmanEntry(0xfffffea, 28))    # 12
    t.append(HuffmanEntry(0x3ffffffd, 30))   # 13
    t.append(HuffmanEntry(0xfffffeb, 28))    # 14
    t.append(HuffmanEntry(0xfffffec, 28))    # 15
    t.append(HuffmanEntry(0xfffffed, 28))    # 16
    t.append(HuffmanEntry(0xfffffee, 28))    # 17
    t.append(HuffmanEntry(0xfffffef, 28))    # 18
    t.append(HuffmanEntry(0xffffff0, 28))    # 19
    t.append(HuffmanEntry(0xffffff1, 28))    # 20
    t.append(HuffmanEntry(0xffffff2, 28))    # 21
    t.append(HuffmanEntry(0x3ffffffe, 30))   # 22
    t.append(HuffmanEntry(0xffffff3, 28))    # 23
    t.append(HuffmanEntry(0xffffff4, 28))    # 24
    t.append(HuffmanEntry(0xffffff5, 28))    # 25
    t.append(HuffmanEntry(0xffffff6, 28))    # 26
    t.append(HuffmanEntry(0xffffff7, 28))    # 27
    t.append(HuffmanEntry(0xffffff8, 28))    # 28
    t.append(HuffmanEntry(0xffffff9, 28))    # 29
    t.append(HuffmanEntry(0xffffffa, 28))    # 30
    t.append(HuffmanEntry(0xffffffb, 28))    # 31
    t.append(HuffmanEntry(0x14, 6))          # 32 ' '
    t.append(HuffmanEntry(0x3f8, 10))        # 33 '!'
    t.append(HuffmanEntry(0x3f9, 10))        # 34 '"'
    t.append(HuffmanEntry(0xffa, 12))        # 35 '#'
    t.append(HuffmanEntry(0x1ff9, 13))       # 36 '$'
    t.append(HuffmanEntry(0x15, 6))          # 37 '%'
    t.append(HuffmanEntry(0xf8, 8))          # 38 '&'
    t.append(HuffmanEntry(0x7fa, 11))        # 39 "'"
    t.append(HuffmanEntry(0x3fa, 10))        # 40 '('
    t.append(HuffmanEntry(0x3fb, 10))        # 41 ')'
    t.append(HuffmanEntry(0xf9, 8))          # 42 '*'
    t.append(HuffmanEntry(0x7fb, 11))        # 43 '+'
    t.append(HuffmanEntry(0xfa, 8))          # 44 ','
    t.append(HuffmanEntry(0x16, 6))          # 45 '-'
    t.append(HuffmanEntry(0x17, 6))          # 46 '.'
    t.append(HuffmanEntry(0x18, 6))          # 47 '/'
    t.append(HuffmanEntry(0x0, 5))           # 48 '0'
    t.append(HuffmanEntry(0x1, 5))           # 49 '1'
    t.append(HuffmanEntry(0x2, 5))           # 50 '2'
    t.append(HuffmanEntry(0x19, 6))          # 51 '3'
    t.append(HuffmanEntry(0x1a, 6))          # 52 '4'
    t.append(HuffmanEntry(0x1b, 6))          # 53 '5'
    t.append(HuffmanEntry(0x1c, 6))          # 54 '6'
    t.append(HuffmanEntry(0x1d, 6))          # 55 '7'
    t.append(HuffmanEntry(0x1e, 6))          # 56 '8'
    t.append(HuffmanEntry(0x1f, 6))          # 57 '9'
    t.append(HuffmanEntry(0x5c, 7))          # 58 ':'
    t.append(HuffmanEntry(0xfb, 8))          # 59 ';'
    t.append(HuffmanEntry(0x7ffc, 15))       # 60 '<'
    t.append(HuffmanEntry(0x20, 6))          # 61 '='
    t.append(HuffmanEntry(0xffb, 12))        # 62 '>'
    t.append(HuffmanEntry(0x3fc, 10))        # 63 '?'
    t.append(HuffmanEntry(0x1ffa, 13))       # 64 '@'
    t.append(HuffmanEntry(0x21, 6))          # 65 'A'
    t.append(HuffmanEntry(0x5d, 7))          # 66 'B'
    t.append(HuffmanEntry(0x5e, 7))          # 67 'C'
    t.append(HuffmanEntry(0x5f, 7))          # 68 'D'
    t.append(HuffmanEntry(0x60, 7))          # 69 'E'
    t.append(HuffmanEntry(0x61, 7))          # 70 'F'
    t.append(HuffmanEntry(0x62, 7))          # 71 'G'
    t.append(HuffmanEntry(0x63, 7))          # 72 'H'
    t.append(HuffmanEntry(0x64, 7))          # 73 'I'
    t.append(HuffmanEntry(0x65, 7))          # 74 'J'
    t.append(HuffmanEntry(0x66, 7))          # 75 'K'
    t.append(HuffmanEntry(0x67, 7))          # 76 'L'
    t.append(HuffmanEntry(0x68, 7))          # 77 'M'
    t.append(HuffmanEntry(0x69, 7))          # 78 'N'
    t.append(HuffmanEntry(0x6a, 7))          # 79 'O'
    t.append(HuffmanEntry(0x6b, 7))          # 80 'P'
    t.append(HuffmanEntry(0x6c, 7))          # 81 'Q'
    t.append(HuffmanEntry(0x6d, 7))          # 82 'R'
    t.append(HuffmanEntry(0x6e, 7))          # 83 'S'
    t.append(HuffmanEntry(0x6f, 7))          # 84 'T'
    t.append(HuffmanEntry(0x70, 7))          # 85 'U'
    t.append(HuffmanEntry(0x71, 7))          # 86 'V'
    t.append(HuffmanEntry(0x72, 7))          # 87 'W'
    t.append(HuffmanEntry(0xfc, 8))          # 88 'X'
    t.append(HuffmanEntry(0x73, 7))          # 89 'Y'
    t.append(HuffmanEntry(0xfd, 8))          # 90 'Z'
    t.append(HuffmanEntry(0x1ffb, 13))       # 91 '['
    t.append(HuffmanEntry(0x7fff0, 19))      # 92 '\'
    t.append(HuffmanEntry(0x1ffc, 13))       # 93 ']'
    t.append(HuffmanEntry(0x3ffc, 14))       # 94 '^'
    t.append(HuffmanEntry(0x22, 6))          # 95 '_'
    t.append(HuffmanEntry(0x7ffd, 15))       # 96 '`'
    t.append(HuffmanEntry(0x3, 5))           # 97 'a'
    t.append(HuffmanEntry(0x23, 6))          # 98 'b'
    t.append(HuffmanEntry(0x4, 5))           # 99 'c'
    t.append(HuffmanEntry(0x24, 6))          # 100 'd'
    t.append(HuffmanEntry(0x5, 5))           # 101 'e'
    t.append(HuffmanEntry(0x25, 6))          # 102 'f'
    t.append(HuffmanEntry(0x26, 6))          # 103 'g'
    t.append(HuffmanEntry(0x27, 6))          # 104 'h'
    t.append(HuffmanEntry(0x6, 5))           # 105 'i'
    t.append(HuffmanEntry(0x74, 7))          # 106 'j'
    t.append(HuffmanEntry(0x75, 7))          # 107 'k'
    t.append(HuffmanEntry(0x28, 6))          # 108 'l'
    t.append(HuffmanEntry(0x29, 6))          # 109 'm'
    t.append(HuffmanEntry(0x2a, 6))          # 110 'n'
    t.append(HuffmanEntry(0x7, 5))           # 111 'o'
    t.append(HuffmanEntry(0x2b, 6))          # 112 'p'
    t.append(HuffmanEntry(0x76, 7))          # 113 'q'
    t.append(HuffmanEntry(0x2c, 6))          # 114 'r'
    t.append(HuffmanEntry(0x8, 5))           # 115 's'
    t.append(HuffmanEntry(0x9, 5))           # 116 't'
    t.append(HuffmanEntry(0x2d, 6))          # 117 'u'
    t.append(HuffmanEntry(0x77, 7))          # 118 'v'
    t.append(HuffmanEntry(0x78, 7))          # 119 'w'
    t.append(HuffmanEntry(0x79, 7))          # 120 'x'
    t.append(HuffmanEntry(0x7a, 7))          # 121 'y'
    t.append(HuffmanEntry(0x7b, 7))          # 122 'z'
    t.append(HuffmanEntry(0x7ffe, 15))       # 123 '{'
    t.append(HuffmanEntry(0x7fc, 11))        # 124 '|'
    t.append(HuffmanEntry(0x3ffd, 14))       # 125 '}'
    t.append(HuffmanEntry(0x1ffd, 13))       # 126 '~'
    t.append(HuffmanEntry(0xffffffc, 28))    # 127
    t.append(HuffmanEntry(0xfffe6, 20))      # 128
    t.append(HuffmanEntry(0x3fffd2, 22))     # 129
    t.append(HuffmanEntry(0xfffe7, 20))      # 130
    t.append(HuffmanEntry(0xfffe8, 20))      # 131
    t.append(HuffmanEntry(0x3fffd3, 22))     # 132
    t.append(HuffmanEntry(0x3fffd4, 22))     # 133
    t.append(HuffmanEntry(0x3fffd5, 22))     # 134
    t.append(HuffmanEntry(0x7fffd9, 23))     # 135
    t.append(HuffmanEntry(0x3fffd6, 22))     # 136
    t.append(HuffmanEntry(0x7fffda, 23))     # 137
    t.append(HuffmanEntry(0x7fffdb, 23))     # 138
    t.append(HuffmanEntry(0x7fffdc, 23))     # 139
    t.append(HuffmanEntry(0x7fffdd, 23))     # 140
    t.append(HuffmanEntry(0x7fffde, 23))     # 141
    t.append(HuffmanEntry(0xffffeb, 24))     # 142
    t.append(HuffmanEntry(0x7fffdf, 23))     # 143
    t.append(HuffmanEntry(0xffffec, 24))     # 144
    t.append(HuffmanEntry(0xffffed, 24))     # 145
    t.append(HuffmanEntry(0x3fffd7, 22))     # 146
    t.append(HuffmanEntry(0x7fffe0, 23))     # 147
    t.append(HuffmanEntry(0xffffee, 24))     # 148
    t.append(HuffmanEntry(0x7fffe1, 23))     # 149
    t.append(HuffmanEntry(0x7fffe2, 23))     # 150
    t.append(HuffmanEntry(0x7fffe3, 23))     # 151
    t.append(HuffmanEntry(0x7fffe4, 23))     # 152
    t.append(HuffmanEntry(0x1fffdc, 21))     # 153
    t.append(HuffmanEntry(0x3fffd8, 22))     # 154
    t.append(HuffmanEntry(0x7fffe5, 23))     # 155
    t.append(HuffmanEntry(0x3fffd9, 22))     # 156
    t.append(HuffmanEntry(0x7fffe6, 23))     # 157
    t.append(HuffmanEntry(0x7fffe7, 23))     # 158
    t.append(HuffmanEntry(0xffffef, 24))     # 159
    t.append(HuffmanEntry(0x3fffda, 22))     # 160
    t.append(HuffmanEntry(0x1fffdd, 21))     # 161
    t.append(HuffmanEntry(0xfffe9, 20))      # 162
    t.append(HuffmanEntry(0x3fffdb, 22))     # 163
    t.append(HuffmanEntry(0x3fffdc, 22))     # 164
    t.append(HuffmanEntry(0x7fffe8, 23))     # 165
    t.append(HuffmanEntry(0x7fffe9, 23))     # 166
    t.append(HuffmanEntry(0x1fffde, 21))     # 167
    t.append(HuffmanEntry(0x7fffea, 23))     # 168
    t.append(HuffmanEntry(0x3fffdd, 22))     # 169
    t.append(HuffmanEntry(0x3fffde, 22))     # 170
    t.append(HuffmanEntry(0xfffff0, 24))     # 171
    t.append(HuffmanEntry(0x1fffdf, 21))     # 172
    t.append(HuffmanEntry(0x3fffdf, 22))     # 173
    t.append(HuffmanEntry(0x7fffeb, 23))     # 174
    t.append(HuffmanEntry(0x7fffec, 23))     # 175
    t.append(HuffmanEntry(0x1fffe0, 21))     # 176
    t.append(HuffmanEntry(0x1fffe1, 21))     # 177
    t.append(HuffmanEntry(0x3fffe0, 22))     # 178
    t.append(HuffmanEntry(0x1fffe2, 21))     # 179
    t.append(HuffmanEntry(0x7fffed, 23))     # 180
    t.append(HuffmanEntry(0x3fffe1, 22))     # 181
    t.append(HuffmanEntry(0x7fffee, 23))     # 182
    t.append(HuffmanEntry(0x7fffef, 23))     # 183
    t.append(HuffmanEntry(0xfffea, 20))      # 184
    t.append(HuffmanEntry(0x3fffe2, 22))     # 185
    t.append(HuffmanEntry(0x3fffe3, 22))     # 186
    t.append(HuffmanEntry(0x3fffe4, 22))     # 187
    t.append(HuffmanEntry(0x7ffff0, 23))     # 188
    t.append(HuffmanEntry(0x3fffe5, 22))     # 189
    t.append(HuffmanEntry(0x3fffe6, 22))     # 190
    t.append(HuffmanEntry(0x7ffff1, 23))     # 191
    t.append(HuffmanEntry(0x3ffffe0, 26))    # 192
    t.append(HuffmanEntry(0x3ffffe1, 26))    # 193
    t.append(HuffmanEntry(0xfffeb, 20))      # 194
    t.append(HuffmanEntry(0x7fff1, 19))      # 195
    t.append(HuffmanEntry(0x3fffe7, 22))     # 196
    t.append(HuffmanEntry(0x7ffff2, 23))     # 197
    t.append(HuffmanEntry(0x3fffe8, 22))     # 198
    t.append(HuffmanEntry(0x1ffffec, 25))    # 199
    t.append(HuffmanEntry(0x3ffffe2, 26))    # 200
    t.append(HuffmanEntry(0x3ffffe3, 26))    # 201
    t.append(HuffmanEntry(0x3ffffe4, 26))    # 202
    t.append(HuffmanEntry(0x7ffffde, 27))    # 203
    t.append(HuffmanEntry(0x7ffffdf, 27))    # 204
    t.append(HuffmanEntry(0x3ffffe5, 26))    # 205
    t.append(HuffmanEntry(0xfffff1, 24))     # 206
    t.append(HuffmanEntry(0x1ffffed, 25))    # 207
    t.append(HuffmanEntry(0x7fff2, 19))      # 208
    t.append(HuffmanEntry(0x1fffe3, 21))     # 209
    t.append(HuffmanEntry(0x3ffffe6, 26))    # 210
    t.append(HuffmanEntry(0x7ffffe0, 27))    # 211
    t.append(HuffmanEntry(0x7ffffe1, 27))    # 212
    t.append(HuffmanEntry(0x3ffffe7, 26))    # 213
    t.append(HuffmanEntry(0x7ffffe2, 27))    # 214
    t.append(HuffmanEntry(0xfffff2, 24))     # 215
    t.append(HuffmanEntry(0x1fffe4, 21))     # 216
    t.append(HuffmanEntry(0x1fffe5, 21))     # 217
    t.append(HuffmanEntry(0x3ffffe8, 26))    # 218
    t.append(HuffmanEntry(0x3ffffe9, 26))    # 219
    t.append(HuffmanEntry(0xffffffd, 28))    # 220
    t.append(HuffmanEntry(0x7ffffe3, 27))    # 221
    t.append(HuffmanEntry(0x7ffffe4, 27))    # 222
    t.append(HuffmanEntry(0x7ffffe5, 27))    # 223
    t.append(HuffmanEntry(0xfffec, 20))      # 224
    t.append(HuffmanEntry(0xfffff3, 24))     # 225
    t.append(HuffmanEntry(0xfffed, 20))      # 226
    t.append(HuffmanEntry(0x1fffe6, 21))     # 227
    t.append(HuffmanEntry(0x3fffe9, 22))     # 228
    t.append(HuffmanEntry(0x1fffe7, 21))     # 229
    t.append(HuffmanEntry(0x1fffe8, 21))     # 230
    t.append(HuffmanEntry(0x7ffff3, 23))     # 231
    t.append(HuffmanEntry(0x3fffea, 22))     # 232
    t.append(HuffmanEntry(0x3fffeb, 22))     # 233
    t.append(HuffmanEntry(0x1ffffee, 25))    # 234
    t.append(HuffmanEntry(0x1ffffef, 25))    # 235
    t.append(HuffmanEntry(0xfffff4, 24))     # 236
    t.append(HuffmanEntry(0xfffff5, 24))     # 237
    t.append(HuffmanEntry(0x3ffffea, 26))    # 238
    t.append(HuffmanEntry(0x7ffff4, 23))     # 239
    t.append(HuffmanEntry(0x3ffffeb, 26))    # 240
    t.append(HuffmanEntry(0x7ffffe6, 27))    # 241
    t.append(HuffmanEntry(0x3ffffec, 26))    # 242
    t.append(HuffmanEntry(0x3ffffed, 26))    # 243
    t.append(HuffmanEntry(0x7ffffe7, 27))    # 244
    t.append(HuffmanEntry(0x7ffffe8, 27))    # 245
    t.append(HuffmanEntry(0x7ffffe9, 27))    # 246
    t.append(HuffmanEntry(0x7ffffea, 27))    # 247
    t.append(HuffmanEntry(0x7ffffeb, 27))    # 248
    t.append(HuffmanEntry(0xffffffe, 28))    # 249
    t.append(HuffmanEntry(0x7ffffec, 27))    # 250
    t.append(HuffmanEntry(0x7ffffed, 27))    # 251
    t.append(HuffmanEntry(0x7ffffee, 27))    # 252
    t.append(HuffmanEntry(0x7ffffef, 27))    # 253
    t.append(HuffmanEntry(0x7fffff0, 27))    # 254
    t.append(HuffmanEntry(0x3ffffee, 26))    # 255
    return t^


comptime HUFFMAN_EOS_CODE: UInt32 = 0x3fffffff
comptime HUFFMAN_EOS_BITS: UInt8 = 30


# ---------------------------------------------------------------------------
# State-machine Huffman decoder — TQUIC pattern, 4-bit-at-a-time.
#
# Mirrors TQUIC's `const DECODE_TABLE: [[(usize, u8, u8); 16]; 256]`
# (`tquic/src/h3/qpack/huffman.rs:422-...`). 4096 entries × (next_state,
# output_byte, flags). Decode 1 nibble at a time → O(1) per nibble vs
# the naïve O(N×K) match loop.
#
# Microbench (mojo-net 0.26.2): 11,736 ns → 132 ns per huffman_decode of
# "example.com" = ~89× speedup. Build cost ~115 μs (one-time, paid at
# QpackDecoder __init__).
#
# Mojo 0.26.2 doesn't support TQUIC's `const ARR: [...; 4096]` pattern
# at module level (no global mutable state, comptime InlineArray fold
# breaks at 256+ entries), so we build at instance __init__ from the
# encode table. The table-build is a standard binary-tree → 4-bit-state
# walk; correctness is verified by roundtripping huffman_encode →
# huffman_decode_sm against the original `huffman_decode`.
# ---------------------------------------------------------------------------

# Sentinel encoding for the binary-tree representation.
# child >= 0 → internal node ID
# child == -1 → no child (path doesn't exist; only happens for invalid input)
# child <= -2 → leaf with symbol = -(child + 2). Symbols are 0..255.
fn _huff_is_leaf(child: Int) -> Bool:
    return child <= -2

fn _huff_leaf_symbol(child: Int) -> Int:
    return -child - 2

fn _huff_encode_leaf(symbol: Int) -> Int:
    return -symbol - 2


struct HuffDecodeTable(Copyable, Movable):
    """4-bit-at-a-time Huffman decode state machine.
    next_state[state*16+nibble] → next_state, output_byte (if FLAG_DECODED),
    flags (FLAG_DECODED=2, FLAG_ERROR=4)."""

    var next_state: List[UInt16]
    var output_byte: List[UInt8]
    var flags: List[UInt8]

    def __init__(out self):
        # Step 1: build binary tree from encode table.
        var encode = _huffman_encode_table()
        var tree_left = List[Int]()
        var tree_right = List[Int]()
        tree_left.append(-1)
        tree_right.append(-1)
        for sym in range(256):
            var code = encode[sym].code
            var nbits = Int(encode[sym].nbits)
            var cur: Int = 0
            for bit_pos in range(nbits - 1, -1, -1):
                var bit = Int((code >> UInt32(bit_pos)) & 1)
                if bit_pos == 0:
                    if bit == 0:
                        tree_left[cur] = _huff_encode_leaf(sym)
                    else:
                        tree_right[cur] = _huff_encode_leaf(sym)
                else:
                    var child: Int
                    if bit == 0:
                        child = tree_left[cur]
                    else:
                        child = tree_right[cur]
                    if child == -1:
                        var new_id = len(tree_left)
                        tree_left.append(-1)
                        tree_right.append(-1)
                        if bit == 0:
                            tree_left[cur] = new_id
                        else:
                            tree_right[cur] = new_id
                        cur = new_id
                    else:
                        cur = child
        var n_nodes = len(tree_left)

        # Step 2: walk the tree as a 4-bit state machine.
        var FLAG_NONE: UInt8 = 0
        var FLAG_DECODED: UInt8 = 2
        var FLAG_ERROR: UInt8 = 4

        self.next_state = List[UInt16](capacity=n_nodes * 16)
        self.output_byte = List[UInt8](capacity=n_nodes * 16)
        self.flags = List[UInt8](capacity=n_nodes * 16)
        for _ in range(n_nodes * 16):
            self.next_state.append(UInt16(0))
            self.output_byte.append(UInt8(0))
            self.flags.append(FLAG_NONE)

        for state in range(n_nodes):
            for nibble in range(16):
                var cur = state
                var emitted_sym: Int = -1
                var valid = True
                for bit_pos in range(3, -1, -1):
                    var bit = (nibble >> bit_pos) & 1
                    var child: Int
                    if bit == 0:
                        child = tree_left[cur]
                    else:
                        child = tree_right[cur]
                    if child == -1:
                        valid = False
                        break
                    if _huff_is_leaf(child):
                        emitted_sym = _huff_leaf_symbol(child)
                        cur = 0  # restart at root after symbol emit
                    else:
                        cur = child
                var idx = state * 16 + nibble
                if not valid:
                    self.flags[idx] = FLAG_ERROR
                    self.next_state[idx] = UInt16(0)
                else:
                    self.next_state[idx] = UInt16(cur)
                    if emitted_sym >= 0:
                        self.output_byte[idx] = UInt8(emitted_sym)
                        self.flags[idx] = FLAG_DECODED

    def __init__(out self, *, copy_from: Self):
        self.next_state = copy_from.next_state.copy()
        self.output_byte = copy_from.output_byte.copy()
        self.flags = copy_from.flags.copy()

    @staticmethod
    fn empty() -> Self:
        """Construct an unbuilt placeholder. Used when a shared-pointer
        owner provides the real table externally; the local fields stay
        as empty Lists (no heap allocation)."""
        return Self(_skip_build=True)

    def __init__(out self, *, _skip_build: Bool):
        # Bypass the 4096-entry build; for shared-pointer mode.
        self.next_state = List[UInt16]()
        self.output_byte = List[UInt8]()
        self.flags = List[UInt8]()


# ---------------------------------------------------------------------------
# QpackSharedTables — process-shared rodata-equivalent for QPACK
# ---------------------------------------------------------------------------

struct QpackSharedTables(Movable):
    """Process-shared QPACK constant tables: Huffman decode SM (4096
    entries), Huffman encode (256 entries), static table (99 entries).

    Allocated once at server startup; the pointer is threaded into every
    new H3Connection's QpackDecoder + QpackEncoder so per-connection
    __init__ skips the table builds. At ~1k new conn/sec (short-conn
    workload) this eliminates the dominant per-conn QPACK init cost.

    Mirrors TQUIC's `const STATIC_ENCODE_TABLE` + `const DECODE_TABLE`
    rodata pattern; Mojo 0.26.2 lacks module-level mutable state so the
    pointer must be threaded explicitly.

    Two name-keyed indices built once at init mirror TQUIC's
    Lazy<HashMap<&str, usize>> dispatch — mojo-net previously did
    O(99) linear scans per header per response in _static_find /
    _static_find_name. The static table has non-contiguous name
    groups (`:status` at 24-28 + 63-71, `access-control-allow-headers`
    at 33-34 + 75), so a forward-walk-while-name-matches won't catch
    the second group. Hence two Dicts:

      name_first_idx: name → first index whose name matches (any value).
        Used by _static_find_name. Encoder uses the result to encode
        "Literal With Name Reference"; any matching name-index is fine.

      name_value_idx: "name\\x00value" → exact static-table index.
        Used by _static_find for exact (name, value) match.
    """
    var huff_decode: HuffDecodeTable
    var huff_encode: List[HuffmanEntry]
    var static_table: List[QpackStaticEntry]
    var name_first_idx: Dict[String, Int]
    var name_value_idx: Dict[String, Int]

    def __init__(out self):
        self.huff_decode = HuffDecodeTable()
        self.huff_encode = _huffman_encode_table()
        self.static_table = _qpack_static_table()
        self.name_first_idx = _build_static_name_index(self.static_table)
        self.name_value_idx = _build_static_name_value_index(self.static_table)

    def __init__(out self, *, deinit take: Self):
        self.huff_decode = take.huff_decode^
        self.huff_encode = take.huff_encode^
        self.static_table = take.static_table^
        self.name_first_idx = take.name_first_idx^
        self.name_value_idx = take.name_value_idx^


def _build_static_name_index(read static_table: List[QpackStaticEntry]) -> Dict[String, Int]:
    """Build name→first-static-table-index map. Walks the static table
    once and records the first index at which each unique name appears.
    """
    var m = Dict[String, Int]()
    for i in range(len(static_table)):
        var name = static_table[i].name
        if name not in m:
            m[name] = i
    return m^


def _build_static_name_value_index(read static_table: List[QpackStaticEntry]) -> Dict[String, Int]:
    """Build "name\\x00value" → static-table-index map for O(1) exact
    (name, value) lookup. The NUL separator avoids collisions like
    "ab" + "" colliding with "a" + "b"."""
    var m = Dict[String, Int]()
    for i in range(len(static_table)):
        var key = static_table[i].name + "\x00" + static_table[i].value
        m[key] = i
    return m^


def huffman_decode_sm(data: List[UInt8], read tbl: HuffDecodeTable) raises -> String:
    """4-bit state-machine Huffman decoder. ~89× faster than `huffman_decode`.
    Mirrors TQUIC's `decode4` loop (`tquic/src/h3/qpack/huffman.rs:90-108`)."""
    var n = len(data)
    if n == 0:
        return String("")
    var FLAG_DECODED: UInt8 = 2
    var FLAG_ERROR: UInt8 = 4
    # Worst-case decode is ~8/5 compression ratio; reserve 2× to avoid
    # List re-allocations across the inner loop.
    var out = List[UInt8](capacity=n * 2)
    var state: Int = 0
    var data_ptr = data.unsafe_ptr()
    var flags_ptr = tbl.flags.unsafe_ptr()
    var out_byte_ptr = tbl.output_byte.unsafe_ptr()
    var next_state_ptr = tbl.next_state.unsafe_ptr()
    for i in range(n):
        var byte = data_ptr[i]
        var idx_hi = state * 16 + Int(byte >> 4)
        var f_hi = flags_ptr[idx_hi]
        if f_hi == FLAG_ERROR:
            raise "Huffman: invalid bit pattern (high nibble)"
        if f_hi & FLAG_DECODED:
            out.append(out_byte_ptr[idx_hi])
        state = Int(next_state_ptr[idx_hi])
        var idx_lo = state * 16 + Int(byte & 0xf)
        var f_lo = flags_ptr[idx_lo]
        if f_lo == FLAG_ERROR:
            raise "Huffman: invalid bit pattern (low nibble)"
        if f_lo & FLAG_DECODED:
            out.append(out_byte_ptr[idx_lo])
        state = Int(next_state_ptr[idx_lo])
    return String(unsafe_from_utf8=out)


def huffman_encode(s: String) raises -> List[UInt8]:
    """Huffman-encode a string per RFC 7541 §5.2."""
    var table = _huffman_encode_table()
    var result = List[UInt8]()
    var acc: UInt64 = 0   # bit accumulator
    var bits: Int = 0     # bits in accumulator
    var sbytes = s.as_bytes()

    for i in range(len(sbytes)):
        var sym = Int(sbytes[i])
        if sym >= len(table):
            raise "Huffman: symbol out of range: " + String(sym)
        var entry = table[sym].copy()
        acc = (acc << UInt64(entry.nbits)) | UInt64(entry.code)
        bits += Int(entry.nbits)
        while bits >= 8:
            bits -= 8
            result.append(UInt8((acc >> UInt64(bits)) & 0xFF))

    # Pad with EOS prefix (all-1s) to fill the last byte
    # `bits` pending bits live in the low bits of acc; shift them to high bits
    # and fill the remaining (8 - bits) low bits with 1s.
    if bits > 0:
        var pad_bits_count = 8 - bits
        var pad = UInt8(((UInt32(1) << UInt32(pad_bits_count)) - 1) & 0xFF)
        var last_byte = UInt8((acc << UInt64(pad_bits_count)) & 0xFF) | pad
        result.append(last_byte)

    return result^


def huffman_decode(data: List[UInt8]) raises -> String:
    """Huffman-decode bytes per RFC 7541 §5.2.
    Uses a sliding window accumulator to avoid 64-bit overflow on long inputs.
    Raises on invalid padding or EOS in non-terminal position.
    """
    if len(data) == 0:
        return String("")

    var table = _huffman_encode_table()
    var result = String("")

    # Sliding-window accumulator: keep up to 64 bits, refill as consumed
    var acc: UInt64 = 0
    var acc_bits: Int = 0
    var byte_idx: Int = 0
    var total_bits: Int = len(data) * 8
    var consumed_bits: Int = 0

    # Initial fill
    while byte_idx < len(data) and acc_bits <= 56:
        acc = (acc << 8) | UInt64(data[byte_idx])
        acc_bits += 8
        byte_idx += 1

    while True:
        var matched = False
        for nbits in range(1, 31):
            if acc_bits < nbits:
                break
            # Extract top `nbits` bits from acc
            var code_val = UInt32(acc >> UInt64(acc_bits - nbits)) & UInt32((UInt64(1) << UInt64(nbits)) - 1)

            # Check EOS
            if nbits == Int(HUFFMAN_EOS_BITS) and code_val == HUFFMAN_EOS_CODE:
                consumed_bits += nbits
                var remaining = total_bits - consumed_bits
                if remaining > 7:
                    raise "Huffman: excess padding (EOS not at end)"
                return result

            # Check all symbols
            for sym in range(len(table)):
                if Int(table[sym].nbits) == nbits and table[sym].code == code_val:
                    result += chr(sym)
                    acc_bits -= nbits
                    consumed_bits += nbits
                    matched = True
                    break
            if matched:
                break

        if not matched:
            var remaining = acc_bits
            if remaining > 7:
                raise "Huffman: no symbol matched and too many bits remaining"
            if remaining == 0:
                break
            # Verify all remaining bits are 1 (valid padding)
            var pad_val = UInt32(acc & ((UInt64(1) << UInt64(remaining)) - 1))
            var expected_pad = UInt32((1 << remaining) - 1)
            if pad_val != expected_pad:
                raise "Huffman: invalid padding (not all-ones)"
            break

        # Refill accumulator
        while byte_idx < len(data) and acc_bits <= 56:
            acc = (acc << 8) | UInt64(data[byte_idx])
            acc_bits += 8
            byte_idx += 1

    return result


# ---------------------------------------------------------------------------
# Prefix integer helpers (RFC 7541 §5.1)
# ---------------------------------------------------------------------------

def qpack_encode_int(value: UInt64, prefix_bits: UInt8) -> List[UInt8]:
    """Encode an integer with N-bit prefix per RFC 7541 §5.1.
    Returns only the integer bytes; caller OR-s the high flag bits into first byte.
    """
    var result = List[UInt8]()
    _ = qpack_encode_int_into(value, prefix_bits, result)
    return result^


def qpack_encode_int_into(
    value: UInt64, prefix_bits: UInt8, mut out: List[UInt8]
) -> Int:
    """Encode integer per RFC 7541 §5.1 directly into `out`. Returns the
    index of the first appended byte so the caller can OR flag bits into
    it. Avoids the per-field List[UInt8] allocation that the older
    qpack_encode_int return-and-extend pattern triggers in hot encode
    paths."""
    var max_first = UInt64((1 << Int(prefix_bits)) - 1)
    var first_idx = len(out)
    if value < max_first:
        out.append(UInt8(value))
        return first_idx
    out.append(UInt8(max_first))
    var v = value - max_first
    while v >= 128:
        out.append(UInt8((v & 0x7F) | 0x80))
        v >>= 7
    out.append(UInt8(v))
    return first_idx


struct _IntDecodeResult(Copyable, Movable):
    var value: UInt64
    var new_offset: Int

    def __init__(out self, value: UInt64, new_offset: Int):
        self.value = value
        self.new_offset = new_offset

    def __init__(out self, *, copy_from: Self):
        self.value = copy_from.value
        self.new_offset = copy_from.new_offset


def qpack_decode_int(data: List[UInt8], offset: Int, prefix_bits: UInt8) raises -> _IntDecodeResult:
    """Decode a prefix integer per RFC 7541 §5.1."""
    var max_first = UInt64((1 << Int(prefix_bits)) - 1)
    var first = UInt64(data[offset]) & max_first
    if first < max_first:
        return _IntDecodeResult(first, offset + 1)
    var value = max_first
    var shift = UInt64(0)
    var pos = offset + 1
    while pos < len(data):
        var b = UInt64(data[pos])
        pos += 1
        value += (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            return _IntDecodeResult(value, pos)
    raise "QPACK: truncated integer encoding"


struct _StrDecodeResult(Copyable, Movable):
    var value: String
    var new_offset: Int

    def __init__(out self, value: String, new_offset: Int):
        self.value = value
        self.new_offset = new_offset

    def __init__(out self, *, copy_from: Self):
        self.value = copy_from.value
        self.new_offset = copy_from.new_offset


def _qpack_encode_string(s: String, use_huffman: Bool) raises -> List[UInt8]:
    """Encode a string literal per RFC 7541 §5.2 / RFC 9204 §4.1.2."""
    var result = List[UInt8]()
    if use_huffman:
        var huff = huffman_encode(s)
        var len_bytes = qpack_encode_int(UInt64(len(huff)), 7)
        len_bytes[0] |= 0x80  # Set H bit
        result.extend(Span(len_bytes))
        result.extend(Span(huff))
    else:
        var raw = s.as_bytes()
        var len_bytes = qpack_encode_int(UInt64(len(raw)), 7)
        result.extend(Span(len_bytes))
        result.extend(raw)
    return result^


def _qpack_decode_string(data: List[UInt8], offset: Int) raises -> _StrDecodeResult:
    """Decode a QPACK/HPACK string literal from data at offset."""
    if offset >= len(data):
        raise "QPACK: truncated string at offset " + String(offset)
    var h_bit = (data[offset] & 0x80) != 0
    var ir = qpack_decode_int(data, offset, 7)
    var length = Int(ir.value)
    var pos = ir.new_offset
    if pos + length > len(data):
        raise "QPACK: string data truncated"
    var raw = List[UInt8](capacity=length)
    raw.extend(Span(data)[pos:pos + length])
    pos += length
    if h_bit:
        return _StrDecodeResult(huffman_decode(raw), pos)
    else:
        var s = String(unsafe_from_utf8=raw)
        return _StrDecodeResult(s, pos)


# ---------------------------------------------------------------------------
# QpackEncoder (static table only; no dynamic table)
# ---------------------------------------------------------------------------

struct QpackEncoder(Copyable, Movable):
    """QPACK encoder — static table only (no dynamic table).

    Caches the static table and Huffman encode table as instance fields
    built once in `__init__`. Mirrors `QpackDecoder`'s caching strategy.
    Per-instance cost: ~10 KB static + ~3 KB Huffman = ~13 KB.

    Avoids per-call rebuild in `qpack_static_find`, `qpack_static_find_name`,
    and `huffman_encode`. The free-function variants are retained for
    callers without an encoder instance.
    """

    var use_huffman: Bool
    var static_table: List[QpackStaticEntry]
    var huff_table: List[HuffmanEntry]
    # When non-null, the shared tables override `static_table` + `huff_table`.
    # The local fields stay as empty Lists in that mode (no heap alloc).
    var shared_tables_ptr: UnsafePointer[QpackSharedTables, MutAnyOrigin]

    def __init__(out self, use_huffman: Bool = True):
        # Default path: build local. Used by tests + clients + fallback.
        self.use_huffman = use_huffman
        self.static_table = _qpack_static_table()
        self.huff_table = _huffman_encode_table()
        self.shared_tables_ptr = UnsafePointer[QpackSharedTables, MutAnyOrigin]()

    def __init__(out self, use_huffman: Bool, *, shared: UnsafePointer[QpackSharedTables, MutAnyOrigin]):
        # Shared path: skip both local builds.
        self.use_huffman = use_huffman
        self.static_table = List[QpackStaticEntry]()
        self.huff_table = List[HuffmanEntry]()
        self.shared_tables_ptr = shared

    def __init__(out self, *, copy_from: Self):
        self.use_huffman = copy_from.use_huffman
        self.static_table = copy_from.static_table.copy()
        self.huff_table = copy_from.huff_table.copy()
        self.shared_tables_ptr = copy_from.shared_tables_ptr

    def _huffman_encode(self, s: String) raises -> List[UInt8]:
        """Method form of `huffman_encode` using either `self.huff_table`
        or `self.shared_tables_ptr[].huff_encode` (skips per-conn build)."""
        var result = List[UInt8]()
        var acc: UInt64 = 0
        var bits: Int = 0
        var sbytes = s.as_bytes()
        var use_shared = Int(self.shared_tables_ptr) != 0
        for i in range(len(sbytes)):
            var sym = Int(sbytes[i])
            var code: UInt32
            var nbits: Int
            if use_shared:
                ref tbl = self.shared_tables_ptr[].huff_encode
                if sym >= len(tbl):
                    raise "Huffman: symbol out of range: " + String(sym)
                code = tbl[sym].code
                nbits = Int(tbl[sym].nbits)
            else:
                if sym >= len(self.huff_table):
                    raise "Huffman: symbol out of range: " + String(sym)
                code = self.huff_table[sym].code
                nbits = Int(self.huff_table[sym].nbits)
            acc = (acc << UInt64(nbits)) | UInt64(code)
            bits += nbits
            while bits >= 8:
                bits -= 8
                result.append(UInt8((acc >> UInt64(bits)) & 0xFF))
        if bits > 0:
            var pad_bits_count = 8 - bits
            var pad = UInt8(((UInt32(1) << UInt32(pad_bits_count)) - 1) & 0xFF)
            var last_byte = UInt8((acc << UInt64(pad_bits_count)) & 0xFF) | pad
            result.append(last_byte)
        return result^

    def _static_find(self, name: String, value: String) raises -> Optional[Int]:
        """Find an exact (name, value) match in the static table.

        O(1) Dict lookup via prebuilt name_value_idx when shared tables
        are bound; linear fallback otherwise (test/legacy callers).
        Mirrors TQUIC's `Lazy<HashMap<&str, usize>>` dispatch.
        """
        if Int(self.shared_tables_ptr) != 0:
            ref idx_map = self.shared_tables_ptr[].name_value_idx
            var key = name + "\x00" + value
            if key not in idx_map:
                return Optional[Int](None)
            return Optional[Int](idx_map[key])
        for i in range(len(self.static_table)):
            if self.static_table[i].name == name and self.static_table[i].value == value:
                return Optional[Int](i)
        return Optional[Int](None)

    def _static_find_name(self, name: String) raises -> Optional[Int]:
        """Find first index whose name matches. O(1) via name_first_idx
        when shared tables are bound; linear fallback otherwise.
        """
        if Int(self.shared_tables_ptr) != 0:
            ref idx_map = self.shared_tables_ptr[].name_first_idx
            if name not in idx_map:
                return Optional[Int](None)
            return Optional[Int](idx_map[name])
        for i in range(len(self.static_table)):
            if self.static_table[i].name == name:
                return Optional[Int](i)
        return Optional[Int](None)

    def _encode_string(self, s: String, use_huffman: Bool) raises -> List[UInt8]:
        """Method form of `_qpack_encode_string` using cached Huffman table."""
        var result = List[UInt8]()
        self._encode_string_into(s, use_huffman, result)
        return result^

    def _encode_string_into(
        self, s: String, use_huffman: Bool, mut out: List[UInt8]
    ) raises:
        """Append a QPACK length-prefixed string directly into `out`.
        Drops the per-field-value temp List that the older _encode_string
        return-and-extend pattern triggered."""
        if use_huffman:
            var huff = self._huffman_encode(s)
            var first_idx = qpack_encode_int_into(UInt64(len(huff)), 7, out)
            out[first_idx] |= 0x80
            out.extend(Span(huff))
        else:
            var raw = s.as_bytes()
            var first_idx = qpack_encode_int_into(UInt64(len(raw)), 7, out)
            _ = first_idx
            out.extend(raw)

    def encode(self, headers: List[QpackHeaderField]) raises -> List[UInt8]:
        """Encode a header list as a QPACK field section block.

        Prefix: [Required Insert Count=0, S=0, Delta Base=0] = [0x00, 0x00].
        Each field:
          - Indexed Static Field Line (§4.5.2): 11xxxxxx (6-bit index)
          - Literal Field Line With Name Reference (§4.5.4): 0 1 N T xxxx (N=0, T=1, 4-bit index)
          - Literal Field Line Without Name Reference (§4.5.6): 0 0 1 N H nnn | name | value
        """
        var result = List[UInt8]()
        result.append(0x00)  # Required Insert Count = 0
        result.append(0x00)  # S bit = 0, Delta Base = 0

        for i in range(len(headers)):
            var field_bytes = self._encode_field(headers[i].name, headers[i].value)
            result.extend(Span(field_bytes))

        return result^

    def _encode_field(self, name: String, value: String) raises -> List[UInt8]:
        var result = List[UInt8]()
        self._encode_field_into(name, value, result)
        return result^

    def _encode_field_into(self, name: String, value: String, mut out: List[UInt8]) raises:
        """Append a single QPACK-encoded field to `out`. Avoids the per-field
        List[UInt8] allocation + extend-copy that the older _encode_field
        return-and-extend pattern triggered. Hot path for response encode
        (~6 fields per response × 51k req/s long-conn)."""
        # 1. Try exact static match → Indexed Static Field Line (§4.5.2)
        var exact = self._static_find(name, value)
        if exact.__bool__():
            var idx = exact.value()
            var first_idx = qpack_encode_int_into(UInt64(idx), 6, out)
            out[first_idx] |= 0xC0  # bits 7-6 = 11
            return

        # 2. Try name-only match → Literal With Static Name Reference (§4.5.4)
        # Format: 0 1 N T xxxx where N=0 (may-index), T=1 (static)
        # = 0101 xxxx = 0x50 with 4-bit index prefix
        var name_match = self._static_find_name(name)
        if name_match.__bool__():
            var idx = name_match.value()
            var first_idx = qpack_encode_int_into(UInt64(idx), 4, out)
            out[first_idx] |= 0x50  # bits 7-6 = 0 1, bit 5 = N=0, bit 4 = T=1
            self._encode_string_into(value, self.use_huffman, out)
            return

        # 3. Literal Without Name Reference (§4.5.6)
        # Format: 0 0 1 N H nnn | name_bytes | H 7-bit-value-len | value_bytes
        # bit 4 = N=0 (may-index), bit 3 = H (Huffman for name), bits 2:0 = 3-bit name length prefix
        var name_raw = List[UInt8]()
        var name_h_bit: UInt8 = 0x00
        if self.use_huffman:
            name_raw = huffman_encode(name)
            name_h_bit = 0x08  # bit 3 = H=1
        else:
            var name_span = name.as_bytes()
            name_raw = List[UInt8](capacity=len(name_span))
            name_raw.extend(name_span)
        var first_idx = qpack_encode_int_into(UInt64(len(name_raw)), 3, out)
        out[first_idx] |= 0x20 | name_h_bit  # 001 N=0 H nnn
        out.extend(Span(name_raw))
        var val_bytes = _qpack_encode_string(value, self.use_huffman)
        out.extend(Span(val_bytes))


# ---------------------------------------------------------------------------
# QpackDecoder (static table only; no dynamic table)
# ---------------------------------------------------------------------------

struct QpackDecoder(Copyable, Movable):
    """QPACK decoder — static table only (RFC 9204 §3.2.4).

    Caches two tables as instance fields built once in `__init__`:
      1. The 99-entry static table (`static_table`) — saves ~99 String
         allocs per indexed lookup vs rebuilding via `qpack_static_get`.
         Microbench: 391× faster on isolated `static_table[idx]`.
      2. The 4096-entry Huffman decode state machine (`huff_decode`) —
         see `HuffDecodeTable`. Microbench: 89× faster on
         `huffman_decode_sm` vs `huffman_decode` for an 11-char value.

    Mirrors TQUIC's `const STATIC_DECODE_TABLE` + `const DECODE_TABLE`
    rodata pattern using Mojo's only available approximation (per-instance
    runtime cache, since Mojo 0.26.2 lacks module-level mutable state).

    Per-instance cost: ~10 KB static table + ~16 KB huffman table = ~26 KB.
    One decoder per H3Connection; cache lifetime = connection lifetime.
    Build cost: ~115 μs at __init__.
    """

    var static_table: List[QpackStaticEntry]
    var huff_decode: HuffDecodeTable
    # When non-null, points at a process-shared QpackSharedTables (allocated
    # once at server startup). The local `static_table` and `huff_decode`
    # fields stay empty in that mode (List[]() / HuffDecodeTable.empty())
    # — saves ~25-30k ops (HuffDecodeTable) + 99 list appends (static_table)
    # per QpackDecoder __init__. The bulk of short-conn per-connection cost.
    # Mojo 0.26.2 lacks module-level mutable state, so the pointer is
    # threaded explicitly through the construction chain.
    var shared_tables_ptr: UnsafePointer[QpackSharedTables, MutAnyOrigin]

    def __init__(out self):
        # Default path: build the tables locally. Used by tests + clients +
        # any caller that hasn't been migrated to the shared-pointer path.
        self.static_table = _qpack_static_table()
        self.huff_decode = HuffDecodeTable()
        self.shared_tables_ptr = UnsafePointer[QpackSharedTables, MutAnyOrigin]()

    def __init__(out self, *, shared: UnsafePointer[QpackSharedTables, MutAnyOrigin]):
        # Shared path: skip both local builds (static_table + HuffDecodeTable).
        self.static_table = List[QpackStaticEntry]()
        self.huff_decode = HuffDecodeTable.empty()
        self.shared_tables_ptr = shared

    def __init__(out self, *, copy_from: Self):
        self.static_table = copy_from.static_table.copy()
        self.huff_decode = HuffDecodeTable(copy_from=copy_from.huff_decode)
        self.shared_tables_ptr = copy_from.shared_tables_ptr

    def _decode_string(self, data: List[UInt8], offset: Int) raises -> _StrDecodeResult:
        """Method form of `_qpack_decode_string` using the cached state-machine
        Huffman decoder when the H bit is set."""
        if offset >= len(data):
            raise "QPACK: truncated string at offset " + String(offset)
        var h_bit = (data[offset] & 0x80) != 0
        var ir = qpack_decode_int(data, offset, 7)
        var length = Int(ir.value)
        var pos = ir.new_offset
        if pos + length > len(data):
            raise "QPACK: string data truncated"
        var raw = List[UInt8](capacity=length)
        raw.extend(Span(data)[pos:pos + length])
        pos += length
        if h_bit:
            if Int(self.shared_tables_ptr) != 0:
                return _StrDecodeResult(huffman_decode_sm(raw, self.shared_tables_ptr[].huff_decode), pos)
            return _StrDecodeResult(huffman_decode_sm(raw, self.huff_decode), pos)
        return _StrDecodeResult(String(unsafe_from_utf8=raw), pos)

    def decode(mut self, data: List[UInt8]) raises -> List[QpackHeaderField]:
        """Decode a QPACK field section block.

        Skips the 2-byte prefix (Required Insert Count + Delta Base),
        then decodes each field instruction until data is exhausted.
        Indexed-table lookups read from `self.static_table` directly
        (no per-call rebuild).
        """
        if len(data) < 2:
            raise "QPACK: field section too short"
        # RFC 9204 §4.5.1: Required Insert Count encoded with 8-bit prefix.
        # Static-only decoders only support RIC = 0.
        var ric_result = qpack_decode_int(data, 0, 8)
        if ric_result.value != 0:
            raise "QPACK: non-zero Required Insert Count not supported (dynamic table not implemented)"
        var result = List[QpackHeaderField]()
        # RFC 9204 §4.5.1: Parse Delta Base byte — S bit (bit 7) + 7-bit Delta Base value.
        # Static-only decoders only support S=0 and Delta Base=0.
        var base_byte_raw = UInt64(data[ric_result.new_offset])
        if (base_byte_raw & 0x80) != 0:
            raise "QPACK: S=1 (negative delta base) not supported; dynamic table required"
        var base_result = qpack_decode_int(data, ric_result.new_offset, 7)
        if base_result.value != 0:
            raise "QPACK: non-zero Delta Base not supported; dynamic table required"
        var pos = base_result.new_offset

        while pos < len(data):
            var b = data[pos]

            if (b & 0x80) != 0:
                # §4.5.2: Indexed Field Line
                # 1xxxxxxx — bit 6 is T (T=1 = static)
                var t_bit = (b & 0x40) != 0
                var ir = qpack_decode_int(data, pos, 6)
                var idx = Int(ir.value)
                pos = ir.new_offset
                if t_bit:
                    # Static table reference — O(1) read from cached table.
                    if idx < 0 or idx >= QPACK_STATIC_TABLE_SIZE:
                        raise "QPACK: static table index out of range: " + String(idx)
                    # ref binding skips the per-call entry.copy() (2 String
                    # clones); the constructor still copies into the new
                    # QpackHeaderField fields.
                    if Int(self.shared_tables_ptr) != 0:
                        ref entry = self.shared_tables_ptr[].static_table[idx]
                        result.append(QpackHeaderField(entry.name, entry.value))
                    else:
                        ref entry = self.static_table[idx]
                        result.append(QpackHeaderField(entry.name, entry.value))
                else:
                    raise "QPACK: dynamic table not supported (indexed)"

            elif (b & 0xC0) == 0x40:
                # §4.5.4: Literal Field Line With Name Reference
                # 0 1 N T xxxx — bit 5 is N (never-indexed), bit 4 is T (T=1 = static)
                var t_bit = (b & 0x10) != 0
                var ir = qpack_decode_int(data, pos, 4)
                var idx = Int(ir.value)
                pos = ir.new_offset
                var sr = self._decode_string(data, pos)
                var value = sr.value
                pos = sr.new_offset
                if t_bit:
                    if idx < 0 or idx >= QPACK_STATIC_TABLE_SIZE:
                        raise "QPACK: static table index out of range: " + String(idx)
                    if Int(self.shared_tables_ptr) != 0:
                        ref entry = self.shared_tables_ptr[].static_table[idx]
                        result.append(QpackHeaderField(entry.name, value))
                    else:
                        ref entry = self.static_table[idx]
                        result.append(QpackHeaderField(entry.name, value))
                else:
                    raise "QPACK: dynamic table not supported (literal name ref)"

            elif (b & 0xE0) == 0x20:
                # §4.5.6: Literal Field Line Without Name Reference
                # 0 0 1 N H nnn — bit 3 = H (Huffman for name), bits 2:0 = 3-bit name length prefix
                var name_huffman = (b & 0x08) != 0
                var name_len_r = qpack_decode_int(data, pos, 3)
                pos = name_len_r.new_offset
                var name_len = Int(name_len_r.value)
                if pos + name_len > len(data):
                    raise "QPACK: §4.5.6 name data truncated"
                var name_raw = List[UInt8](capacity=name_len)
                name_raw.extend(Span(data)[pos:pos + name_len])
                pos += name_len
                var field_name: String
                if name_huffman:
                    if Int(self.shared_tables_ptr) != 0:
                        field_name = huffman_decode_sm(name_raw, self.shared_tables_ptr[].huff_decode)
                    else:
                        field_name = huffman_decode_sm(name_raw, self.huff_decode)
                else:
                    field_name = String(unsafe_from_utf8=name_raw)
                var vr = self._decode_string(data, pos)
                var value = vr.value
                pos = vr.new_offset
                result.append(QpackHeaderField(field_name, value))

            else:
                raise "QPACK: unknown field instruction byte: " + String(Int(b))

        return result^
