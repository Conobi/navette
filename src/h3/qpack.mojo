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
    var max_first = UInt64((1 << Int(prefix_bits)) - 1)
    var result = List[UInt8]()
    if value < max_first:
        result.append(UInt8(value))
        return result^
    result.append(UInt8(max_first))
    var v = value - max_first
    while v >= 128:
        result.append(UInt8((v & 0x7F) | 0x80))
        v >>= 7
    result.append(UInt8(v))
    return result^


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
        for i in range(len(len_bytes)):
            result.append(len_bytes[i])
        for i in range(len(huff)):
            result.append(huff[i])
    else:
        var raw = s.as_bytes()
        var len_bytes = qpack_encode_int(UInt64(len(raw)), 7)
        for i in range(len(len_bytes)):
            result.append(len_bytes[i])
        for i in range(len(raw)):
            result.append(raw[i])
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
    var raw = List[UInt8]()
    for i in range(length):
        raw.append(data[pos + i])
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
    var use_huffman: Bool

    def __init__(out self, use_huffman: Bool = True):
        self.use_huffman = use_huffman

    def __init__(out self, *, copy_from: Self):
        self.use_huffman = copy_from.use_huffman

    def encode(self, headers: List[QpackHeaderField]) raises -> List[UInt8]:
        """Encode a header list as a QPACK field section block.

        Prefix: [Required Insert Count=0, S=0, Delta Base=0] = [0x00, 0x00].
        Each field:
          - Indexed Static Field Line (§4.5.2): 11xxxxxx (6-bit index)
          - Literal Field Line With Name Reference (§4.5.4): 01011nnn (T=1, 3-bit index)
          - Literal Field Line Without Name Reference (§4.5.6): 00100000 + name + value
        """
        var result = List[UInt8]()
        result.append(0x00)  # Required Insert Count = 0
        result.append(0x00)  # S bit = 0, Delta Base = 0

        for i in range(len(headers)):
            var field_bytes = self._encode_field(headers[i].name, headers[i].value)
            for j in range(len(field_bytes)):
                result.append(field_bytes[j])

        return result^

    def _encode_field(self, name: String, value: String) raises -> List[UInt8]:
        # 1. Try exact static match → Indexed Static Field Line (§4.5.2)
        var exact = qpack_static_find(name, value)
        if exact.__bool__():
            var idx = exact.value()
            var idx_bytes = qpack_encode_int(UInt64(idx), 6)
            idx_bytes[0] |= 0xC0  # bits 7-6 = 11
            return idx_bytes^

        # 2. Try name-only match → Literal With Static Name Reference (§4.5.4)
        # Format: 0 1 T N xxxx where T=1 (static), N=0 (may-index)
        # = 0110 xxxx = 0x60 with 4-bit index prefix
        var name_match = qpack_static_find_name(name)
        if name_match.__bool__():
            var idx = name_match.value()
            var idx_bytes = qpack_encode_int(UInt64(idx), 4)
            idx_bytes[0] |= 0x60  # bits 7-6 = 0 1, bit 5 = T=1 (static), bit 4 = N=0 (may-index)
            var result = List[UInt8]()
            for i in range(len(idx_bytes)):
                result.append(idx_bytes[i])
            var val_bytes = _qpack_encode_string(value, self.use_huffman)
            for i in range(len(val_bytes)):
                result.append(val_bytes[i])
            return result^

        # 3. Literal Without Name Reference (§4.5.6)
        var result = List[UInt8]()
        result.append(0x20)  # 0010 0000, N=0
        var name_bytes = _qpack_encode_string(name, self.use_huffman)
        for i in range(len(name_bytes)):
            result.append(name_bytes[i])
        var val_bytes = _qpack_encode_string(value, self.use_huffman)
        for i in range(len(val_bytes)):
            result.append(val_bytes[i])
        return result^


# ---------------------------------------------------------------------------
# QpackDecoder (static table only; no dynamic table)
# ---------------------------------------------------------------------------

struct QpackDecoder(Copyable, Movable):
    """QPACK decoder — static table only (RFC 9204 §3.2.4)."""

    def __init__(out self):
        pass

    def __init__(out self, *, copy_from: Self):
        pass

    def decode(self, data: List[UInt8]) raises -> List[QpackHeaderField]:
        """Decode a QPACK field section block.

        Skips the 2-byte prefix (Required Insert Count + Delta Base),
        then decodes each field instruction until data is exhausted.
        """
        if len(data) < 2:
            raise "QPACK: field section too short"
        # RFC 9204 §4.5.1: Required Insert Count encoded with 8-bit prefix.
        # Static-only decoders only support RIC = 0.
        var ric_result = qpack_decode_int(data, 0, 8)
        if ric_result.value != 0:
            raise "QPACK: non-zero Required Insert Count not supported (dynamic table not implemented)"
        var result = List[QpackHeaderField]()
        var pos = Int(ric_result.new_offset) + 1  # skip RIC byte(s) + Delta Base byte

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
                    # Static table reference
                    var entry = qpack_static_get(idx)
                    result.append(QpackHeaderField(entry.name, entry.value))
                else:
                    raise "QPACK: dynamic table not supported (indexed)"

            elif (b & 0xC0) == 0x40:
                # §4.5.4: Literal Field Line With Name Reference
                # 0 1 T N xxxx — bit 5 is T (T=1 = static), bit 4 is N (never-indexed)
                var t_bit = (b & 0x20) != 0
                var ir = qpack_decode_int(data, pos, 4)
                var idx = Int(ir.value)
                pos = ir.new_offset
                var sr = _qpack_decode_string(data, pos)
                var value = sr.value
                pos = sr.new_offset
                if t_bit:
                    var entry = qpack_static_get(idx)
                    result.append(QpackHeaderField(entry.name, value))
                else:
                    raise "QPACK: dynamic table not supported (literal name ref)"

            elif (b & 0xE0) == 0x20:
                # §4.5.6: Literal Field Line Without Name Reference
                # 001xxxxx — skip flags byte
                pos += 1
                var nr = _qpack_decode_string(data, pos)
                var name = nr.value
                pos = nr.new_offset
                var vr = _qpack_decode_string(data, pos)
                var value = vr.value
                pos = vr.new_offset
                result.append(QpackHeaderField(name, value))

            else:
                raise "QPACK: unknown field instruction byte: " + String(Int(b))

        return result^
