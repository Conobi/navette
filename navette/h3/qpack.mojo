# src/h3/qpack.mojo
# QPACK codec: static table, encoder, decoder
# RFC 9204 (QPACK). Huffman table from navette.codec.huffman (RFC 7541 Appendix B).


from std.collections import Span
from std.memory.alloc import unsafe_alloc
from navette.util.byte_string import bytes_to_string
from navette.util.null_ptr import null_ptr
from navette.http.header_table_index import StaticTableIndex
from navette.quic.codec import hpack_encode_int_at
from navette.codec.huffman import (
    HuffmanEntry,
    HuffTrieNode,
    HuffFastEntry,
    build_huffman_table,
    build_huffman_trie_from,
    build_huffman_fast,
    hpack_encode_string_into,
    huffman_encode_into as _codec_huffman_encode_into,
    huffman_encoded_len as _codec_huffman_encoded_len,
    huffman_decode_with_tables as _codec_huffman_decode_with_tables,
    huffman_decode as _codec_huffman_decode,
    HUFFMAN_EOS_CODE,
    HUFFMAN_EOS_BITS,
)

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


# QPACK static table — RFC 9204 Appendix A (99 entries, indices 0–98)
comptime QPACK_STATIC_TABLE_SIZE: Int = 99


def _qpack_static_table() -> List[QpackStaticEntry]:
    # RFC 9204 Appendix A — 99 entries as interleaved (name, value) literals.
    var d: List[String] = [
        ":authority", "",  ":path", "/",  "age", "0",  "content-disposition", "",
        "content-length", "0",  "cookie", "",  "date", "",  "etag", "",
        "if-modified-since", "",  "if-none-match", "",  "last-modified", "",  "link", "",
        "location", "",  "referer", "",  "set-cookie", "",  ":method", "CONNECT",
        ":method", "DELETE",  ":method", "GET",  ":method", "HEAD",  ":method", "OPTIONS",
        ":method", "POST",  ":method", "PUT",  ":scheme", "http",  ":scheme", "https",
        ":status", "103",  ":status", "200",  ":status", "304",  ":status", "404",
        ":status", "503",  "accept", "*/*",  "accept", "application/dns-message",
        "accept-encoding", "gzip, deflate, br",  "accept-ranges", "bytes",
        "access-control-allow-headers", "cache-control",
        "access-control-allow-headers", "content-type",
        "access-control-allow-origin", "*",
        "cache-control", "max-age=0",  "cache-control", "max-age=2592000",
        "cache-control", "max-age=604800",  "cache-control", "no-cache",
        "cache-control", "no-store",  "cache-control", "public, max-age=31536000",
        "content-encoding", "br",  "content-encoding", "gzip",
        "content-type", "application/dns-message",  "content-type", "application/javascript",
        "content-type", "application/json",
        "content-type", "application/x-www-form-urlencoded",
        "content-type", "image/gif",  "content-type", "image/jpeg",
        "content-type", "image/png",  "content-type", "text/css",
        "content-type", "text/html; charset=utf-8",  "content-type", "text/plain",
        "content-type", "text/plain;charset=utf-8",  "range", "bytes=0-",
        "strict-transport-security", "max-age=31536000",
        "strict-transport-security", "max-age=31536000; includesubdomains",
        "strict-transport-security", "max-age=31536000; includesubdomains; preload",
        "vary", "accept-encoding",  "vary", "origin",
        "x-content-type-options", "nosniff",  "x-xss-protection", "1; mode=block",
        ":status", "100",  ":status", "204",  ":status", "206",  ":status", "302",
        ":status", "400",  ":status", "403",  ":status", "421",  ":status", "425",
        ":status", "500",  "accept-language", "",
        "access-control-allow-credentials", "FALSE",
        "access-control-allow-credentials", "TRUE",
        "access-control-allow-headers", "*",
        "access-control-allow-methods", "get",
        "access-control-allow-methods", "get, post, options",
        "access-control-allow-methods", "options",
        "access-control-expose-headers", "content-length",
        "access-control-request-headers", "content-type",
        "access-control-request-method", "get",
        "access-control-request-method", "post",
        "alt-svc", "clear",  "authorization", "",
        "content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'",
        "early-data", "1",  "expect-ct", "",  "forwarded", "",  "if-range", "",
        "origin", "",  "purpose", "prefetch",  "server", "",
        "timing-allow-origin", "*",  "upgrade-insecure-requests", "1",
        "user-agent", "",  "x-forwarded-for", "",
        "x-frame-options", "deny",  "x-frame-options", "sameorigin",
    ]
    var t = List[QpackStaticEntry](capacity=99)
    for i in range(99):
        t.append(QpackStaticEntry(d[i * 2], d[i * 2 + 1]))
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
# Huffman encode/decode — delegated to navette.codec.huffman
# ---------------------------------------------------------------------------


def huffman_encode(mut buf: List[Byte], s: String) raises:
    """Huffman-encode a string, appending directly to buf."""
    var table = build_huffman_table()
    _codec_huffman_encode_into(buf, s, table)


def huffman_encoded_len(s: String) raises -> Int:
    """Return the byte length of the Huffman encoding without materializing it."""
    var table = build_huffman_table()
    return _codec_huffman_encoded_len(s, table)


def huffman_decode(data: List[Byte]) raises -> String:
    """Huffman-decode bytes per RFC 7541 §5.2."""
    return _codec_huffman_decode(data)


# ---------------------------------------------------------------------------
# Prefix integer helpers (RFC 7541 §5.1)
# ---------------------------------------------------------------------------


struct _IntDecodeResult(Copyable, Movable):
    var value: UInt64
    var new_offset: Int

    def __init__(out self, value: UInt64, new_offset: Int):
        self.value = value
        self.new_offset = new_offset

    def __init__(out self, *, copy_from: Self):
        self.value = copy_from.value
        self.new_offset = copy_from.new_offset


# RFC 9204 Section 4.1.1: decoders must handle integers up to 62 bits and
# treat larger values as a decoding error. 2^62-1 also keeps any
# `pos + Int(value)` sum far from Int overflow in callers.
comptime QPACK_INT_MAX: UInt64 = (UInt64(1) << 62) - 1
# Continuation bytes cover shifts 0, 7, ..., 63; an 11th can only be an
# overlong encoding (or a CPU-burning stream of 0x80 bytes).
comptime _QPACK_INT_MAX_SHIFT: UInt64 = 63


def qpack_decode_int(data: List[Byte], offset: Int, prefix_bits: UInt8) raises -> _IntDecodeResult:
    """Decode a prefix integer per RFC 7541 Section 5.1, bounded to 62 bits.

    Raises on `offset` outside `data`, truncation, more than 10
    continuation bytes, or a value above QPACK_INT_MAX, so callers may
    convert the result to Int and add it to an in-bounds offset.
    """
    if offset < 0 or offset >= len(data):
        raise "QPACK: truncated integer encoding"
    var max_first = UInt64((1 << Int(prefix_bits)) - 1)
    var first = UInt64(data[offset]) & max_first
    if first < max_first:
        return _IntDecodeResult(first, offset + 1)
    var value = max_first
    var shift = UInt64(0)
    var pos = offset + 1
    while pos < len(data):
        if shift > _QPACK_INT_MAX_SHIFT:
            raise "QPACK: integer encoding too long"
        var chunk = UInt64(data[pos]) & 0x7F
        var more = (data[pos] & 0x80) != 0
        pos += 1
        if chunk != 0:
            # chunk <= MAX >> shift keeps chunk << shift <= MAX; the sum of
            # two such terms stays below 2^63, so the next check is exact.
            if shift >= 62 or chunk > (QPACK_INT_MAX >> shift):
                raise "QPACK: integer exceeds 62 bits"
            value += chunk << shift
            if value > QPACK_INT_MAX:
                raise "QPACK: integer exceeds 62 bits"
        shift += 7
        if not more:
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


def _qpack_decode_string_with_tables(
    data: List[Byte],
    offset: Int,
    trie: List[HuffTrieNode],
    fast: List[HuffFastEntry],
) raises -> _StrDecodeResult:
    """Decode a QPACK string literal, reusing pre-built Huffman tables."""
    if offset >= len(data):
        raise "QPACK: truncated string at offset " + String(offset)
    var h_bit = (data[offset] & 0x80) != 0
    var ir = qpack_decode_int(data, offset, 7)
    var length = Int(ir.value)
    var pos = ir.new_offset
    if pos + length > len(data):
        raise "QPACK: string data truncated"
    var end = pos + length
    if h_bit:
        var slice = List[Byte](capacity=length)
        for i in range(pos, end):
            slice.append(data[i])
        pos = end
        return _StrDecodeResult(_codec_huffman_decode_with_tables(slice, trie, fast), pos)
    else:
        var raw = List[Byte](capacity=length)
        for i in range(pos, end):
            raw.append(data[i])
        pos = end
        var s = bytes_to_string(raw^)
        return _StrDecodeResult(s, pos)


# ---------------------------------------------------------------------------
# QpackCodecTables — RFC-static tables shared across connections
# ---------------------------------------------------------------------------

struct QpackCodecTables(Movable):
    """Pre-built RFC-static codec tables for QPACK/Huffman.

    Built once per server and shared by pointer across all connections,
    avoiding per-connection rebuild of the ~790-node Huffman trie,
    256-entry fast table, 99-entry static table, and StaticTableIndex.
    """

    var static_table: List[QpackStaticEntry]
    var huff_encode: List[HuffmanEntry]
    var huff_trie: List[HuffTrieNode]
    var huff_fast: List[HuffFastEntry]
    var static_index: StaticTableIndex

    def __init__(out self):
        self.static_table = _qpack_static_table()
        self.huff_encode = build_huffman_table()
        try:
            self.huff_trie = build_huffman_trie_from(self.huff_encode)
            self.huff_fast = build_huffman_fast(self.huff_trie)
        except:
            self.huff_trie = List[HuffTrieNode]()
            self.huff_fast = List[HuffFastEntry]()
        var pairs = List[Tuple[String, String]]()
        for i in range(len(self.static_table)):
            pairs.append(Tuple(self.static_table[i].name, self.static_table[i].value))
        self.static_index = StaticTableIndex(pairs, start_index=0)


# ---------------------------------------------------------------------------
# QpackEncoder (static table only; no dynamic table)
# ---------------------------------------------------------------------------

struct QpackEncoder(Movable):
    """QPACK encoder using shared or owned codec tables.

    In production, tables are shared via pointer from the server.
    The standalone constructor heap-allocates its own tables for tests.
    """

    var use_huffman: Bool
    var _tables: Pointer[QpackCodecTables, MutUntrackedOrigin]
    var _owns_tables: Bool

    def __init__(out self, use_huffman: Bool = True):
        """Standalone constructor — builds and owns tables internally."""
        self.use_huffman = use_huffman
        self._tables = unsafe_alloc[QpackCodecTables](1)
        self._tables.unsafe_write(QpackCodecTables())
        self._owns_tables = True

    def __init__(out self, use_huffman: Bool, tables: Pointer[QpackCodecTables, MutUntrackedOrigin]):
        """Shared-tables constructor — borrows pre-built tables from caller."""
        self.use_huffman = use_huffman
        self._tables = tables
        self._owns_tables = False

    def __deinit__(deinit self):
        if self._owns_tables:
            self._tables.unsafe_deinit_pointee()
            self._tables.unsafe_free()

    def encode(self, mut buf: List[Byte], headers: List[QpackHeaderField]) raises:
        """Encode a header list as a QPACK field section block, appending directly to buf.

        Prefix: [Required Insert Count=0, S=0, Delta Base=0] = [0x00, 0x00].
        Each field:
          - Indexed Static Field Line (§4.5.2): 11xxxxxx (6-bit index)
          - Literal Field Line With Name Reference (§4.5.4): 0 1 N T xxxx (N=0, T=1, 4-bit index)
          - Literal Field Line Without Name Reference (§4.5.6): 0 0 1 N H nnn | name | value
        """
        buf.append(0x00)  # Required Insert Count = 0
        buf.append(0x00)  # S bit = 0, Delta Base = 0

        for ref hdr in headers:
            self._encode_field(buf, hdr.name, hdr.value)

    def _encode_field(self, mut buf: List[Byte], name: String, value: String) raises:
        """Encode one header field, appending directly to buf."""
        var result = self._tables[].static_index.find(name, value)
        var match_idx = result[0]
        var is_exact = result[1]

        # 1. Exact static match -> Indexed Static Field Line
        if match_idx >= 0 and is_exact:
            var idx = len(buf)
            buf.resize(idx + 6, Byte(0))
            buf[idx] = UInt8(0xC0)
            var n = hpack_encode_int_at(buf, idx, match_idx, 6)
            buf.resize(idx + n, Byte(0))
            return

        # 2. Name-only match -> Literal With Static Name Reference
        if match_idx >= 0:
            var idx = len(buf)
            buf.resize(idx + 6, Byte(0))
            buf[idx] = UInt8(0x50)
            var n = hpack_encode_int_at(buf, idx, match_idx, 4)
            buf.resize(idx + n, Byte(0))
            self._qpack_encode_string_into_cached(buf, value)
            return

        # 3. Literal Without Name Reference (§4.5.6)
        if self.use_huffman:
            var name_huff_len = _codec_huffman_encoded_len(name, self._tables[].huff_encode)
            var idx = len(buf)
            buf.resize(idx + 6, Byte(0))
            buf[idx] = UInt8(0x20 | 0x08)
            var n = hpack_encode_int_at(buf, idx, name_huff_len, 3)
            buf.resize(idx + n, Byte(0))
            _codec_huffman_encode_into(buf, name, self._tables[].huff_encode)
        else:
            var name_span = name.as_bytes()
            var idx = len(buf)
            buf.resize(idx + 6, Byte(0))
            buf[idx] = UInt8(0x20)
            var n = hpack_encode_int_at(buf, idx, len(name_span), 3)
            buf.resize(idx + n, Byte(0))
            buf.extend(Span(name_span))
        self._qpack_encode_string_into_cached(buf, value)

    def _qpack_encode_string_into_cached(self, mut buf: List[Byte], s: String) raises:
        """Encode string using cached Huffman table."""
        hpack_encode_string_into(buf, s, self.use_huffman, self._tables[].huff_encode)


# ---------------------------------------------------------------------------
# QpackDecoder (static table only; no dynamic table)
# ---------------------------------------------------------------------------

struct QpackDecoder(Movable):
    """QPACK decoder using shared or owned codec tables.

    In production, tables are shared via pointer from the server.
    The standalone constructor heap-allocates its own tables for tests.
    """

    var _tables: Pointer[QpackCodecTables, MutUntrackedOrigin]
    var _owns_tables: Bool

    def __init__(out self):
        """Standalone constructor — builds and owns tables internally."""
        self._tables = unsafe_alloc[QpackCodecTables](1)
        self._tables.unsafe_write(QpackCodecTables())
        self._owns_tables = True

    def __init__(out self, tables: Pointer[QpackCodecTables, MutUntrackedOrigin]):
        """Shared-tables constructor — borrows pre-built tables from caller."""
        self._tables = tables
        self._owns_tables = False

    def __deinit__(deinit self):
        if self._owns_tables:
            self._tables.unsafe_deinit_pointee()
            self._tables.unsafe_free()

    def _decode_string(mut self, ref data: List[Byte], offset: Int) raises -> _StrDecodeResult:
        """Decode a QPACK string literal, reusing scratch decode buffer."""
        if offset >= len(data):
            raise "QPACK: truncated string at offset " + String(offset)
        var h_bit = (data[offset] & 0x80) != 0
        var ir = qpack_decode_int(data, offset, 7)
        var length = Int(ir.value)
        var pos = ir.new_offset
        if pos + length > len(data):
            raise "QPACK: string data truncated"
        var end = pos + length
        if h_bit:
            var raw = List[Byte](capacity=length)
            for i in range(pos, end):
                raw.append(data[i])
            pos = end
            return _StrDecodeResult(
                _codec_huffman_decode_with_tables(raw, self._tables[].huff_trie, self._tables[].huff_fast),
                pos,
            )
        else:
            var raw = List[Byte](capacity=length)
            for i in range(pos, end):
                raw.append(data[i])
            pos = end
            var s = bytes_to_string(raw^)
            return _StrDecodeResult(s, pos)

    def decode(mut self, data: List[Byte]) raises -> List[QpackHeaderField]:
        """Decode a QPACK field section block.

        Skips the 2-byte prefix (Required Insert Count + Delta Base),
        then decodes each field instruction until data is exhausted.

        Reuses the cached Huffman decode tables stored on the decoder.
        """
        if len(data) < 2:
            raise "QPACK: field section too short"
        # RFC 9204 §4.5.1: Required Insert Count encoded with 8-bit prefix.
        # Static-only decoders only support RIC = 0.
        var ric_result = qpack_decode_int(data, 0, 8)
        if ric_result.value != 0:
            raise "QPACK: non-zero Required Insert Count not supported (dynamic table not implemented)"
        var result = List[QpackHeaderField](capacity=16)
        # RFC 9204 §4.5.1: Parse Delta Base byte — S bit (bit 7) + 7-bit Delta Base value.
        # Static-only decoders only support S=0 and Delta Base=0.
        var base_byte_raw = UInt64(data[ric_result.new_offset])
        if (base_byte_raw & 0x80) != 0:
            raise "QPACK: S=1 (negative delta base) not supported; dynamic table required"
        var base_result = qpack_decode_int(data, ric_result.new_offset, 7)
        if base_result.value != 0:
            raise "QPACK: non-zero Delta Base not supported; dynamic table required"
        var pos = base_result.new_offset

        ref trie = self._tables[].huff_trie
        ref fast = self._tables[].huff_fast

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
                    if idx < 0 or idx >= len(self._tables[].static_table):
                        raise "QPACK: invalid static table index"
                    result.append(QpackHeaderField(self._tables[].static_table[idx].name, self._tables[].static_table[idx].value))
                else:
                    raise "QPACK: dynamic table not supported (indexed)"

            elif (b & 0xC0) == 0x40:
                # §4.5.4: Literal Field Line With Name Reference
                # 0 1 N T xxxx — bit 5 is N (never-indexed), bit 4 is T (T=1 = static)
                var t_bit = (b & 0x10) != 0
                var ir = qpack_decode_int(data, pos, 4)
                var idx = Int(ir.value)
                pos = ir.new_offset
                var sr = _qpack_decode_string_with_tables(data, pos, trie, fast)
                var value = sr.value
                pos = sr.new_offset
                if t_bit:
                    if idx < 0 or idx >= len(self._tables[].static_table):
                        raise "QPACK: invalid static table index"
                    result.append(QpackHeaderField(self._tables[].static_table[idx].name, value))
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
                var name_raw = List[Byte](capacity=name_len)
                for j in range(name_len):
                    name_raw.append(data[pos + j])
                pos += name_len
                var field_name: String
                if name_huffman:
                    field_name = _codec_huffman_decode_with_tables(name_raw, trie, fast)
                else:
                    field_name = bytes_to_string(name_raw^)
                var vr = _qpack_decode_string_with_tables(data, pos, trie, fast)
                var value = vr.value
                pos = vr.new_offset
                result.append(QpackHeaderField(field_name, value))

            else:
                raise "QPACK: unknown field instruction byte: " + String(Int(b))

        return result^
