# src/h2/hpack.mojo
#
# HPACK decoder per RFC 7541 Section 6.
# Decodes compressed header blocks, updating the dynamic table as needed.

from .header import Header
from .hpack_integer import encode_integer, decode_integer
from .hpack_huffman import HuffmanCodec
from .hpack_table import StaticTable, DynamicTable


struct HpackConfig(Copyable, Movable):
    """Configuration for the HPACK codec."""

    var max_header_table_size: Int
    var max_header_list_size: Int
    var max_integer_value: Int
    var use_huffman: Bool

    def __init__(
        out self,
        max_header_table_size: Int = 4096,
        max_header_list_size: Int = 65536,
        max_integer_value: Int = 2147483647,
        use_huffman: Bool = True,
    ):
        self.max_header_table_size = max_header_table_size
        self.max_header_list_size = max_header_list_size
        self.max_integer_value = max_integer_value
        self.use_huffman = use_huffman

    def __init__(out self, *, other: Self):
        self.max_header_table_size = other.max_header_table_size
        self.max_header_list_size = other.max_header_list_size
        self.max_integer_value = other.max_integer_value
        self.use_huffman = other.use_huffman

    def __init__(out self, *, deinit take: Self):
        self.max_header_table_size = take.max_header_table_size
        self.max_header_list_size = take.max_header_list_size
        self.max_integer_value = take.max_integer_value
        self.use_huffman = take.use_huffman


struct HpackEncoder(Movable):
    """HPACK header block encoder (RFC 7541 Section 6)."""

    var static_table: StaticTable
    var dynamic_table: DynamicTable
    var huffman: HuffmanCodec
    var config: HpackConfig
    var _pending_table_size: Int  # -1 = no pending update

    def __init__(out self, config: HpackConfig = HpackConfig()):
        self.static_table = StaticTable()
        self.dynamic_table = DynamicTable(config.max_header_table_size)
        self.huffman = HuffmanCodec()
        self.config = HpackConfig(other=config)
        self._pending_table_size = -1

    def __init__(out self, *, deinit take: Self):
        self.static_table = StaticTable()
        self.dynamic_table = take.dynamic_table^
        self.huffman = take.huffman^
        self.config = take.config^
        self._pending_table_size = take._pending_table_size

    def encode(mut self, headers: List[Header]) -> List[UInt8]:
        """Encode headers into HPACK wire bytes. Updates dynamic table."""
        var wire = List[UInt8]()

        # Emit pending table size update
        if self._pending_table_size >= 0:
            var size_bytes = encode_integer(self._pending_table_size, 5)
            size_bytes[0] = size_bytes[0] | UInt8(0x20)
            wire.extend(Span(size_bytes))
            self.dynamic_table.set_max_size(self._pending_table_size)
            self._pending_table_size = -1

        for i in range(len(headers)):
            var name = headers[i].name
            var value = headers[i].value

            var static_result = self.static_table.find(name, value)
            var static_idx = static_result[0]
            var static_exact = static_result[1]

            if static_exact:
                self._emit_indexed(wire, static_idx)
                continue

            var dyn_result = self.dynamic_table.find(name, value)
            var dyn_idx = dyn_result[0]
            var dyn_exact = dyn_result[1]

            if dyn_exact:
                self._emit_indexed(wire, dyn_idx + 62)
                continue

            var name_idx = 0
            if static_idx > 0:
                name_idx = static_idx
            elif dyn_idx >= 0:
                name_idx = dyn_idx + 62

            self._emit_literal_indexed(wire, name_idx, name, value)
            self.dynamic_table.insert(name, value)

        return wire^

    def set_max_table_size(mut self, new_max: Int):
        """Queue table size update for next encode call."""
        self._pending_table_size = new_max

    def _emit_indexed(self, mut wire: List[UInt8], index: Int):
        """Emit indexed header field: 1XXXXXXX."""
        var bytes = encode_integer(index, 7)
        bytes[0] = bytes[0] | UInt8(0x80)
        wire.extend(Span(bytes))

    def _emit_literal_indexed(
        self,
        mut wire: List[UInt8],
        name_idx: Int,
        name: String,
        value: String,
    ):
        """Emit literal with incremental indexing: 01XXXXXX."""
        var idx_bytes = encode_integer(name_idx, 6)
        idx_bytes[0] = idx_bytes[0] | UInt8(0x40)
        wire.extend(Span(idx_bytes))

        if name_idx == 0:
            self._emit_string(wire, name)

        self._emit_string(wire, value)

    def _emit_string(self, mut wire: List[UInt8], s: String):
        """Emit HPACK string literal (with optional Huffman)."""
        var s_bytes = s.as_bytes()
        var raw = List[UInt8](capacity=len(s_bytes))
        raw.extend(s_bytes)

        if self.config.use_huffman:
            var encoded = self.huffman.encode(raw)
            var len_bytes = encode_integer(len(encoded), 7)
            len_bytes[0] = len_bytes[0] | UInt8(0x80)
            wire.extend(Span(len_bytes))
            wire.extend(Span(encoded))
        else:
            var len_bytes = encode_integer(len(raw), 7)
            wire.extend(Span(len_bytes))
            wire.extend(Span(raw))


struct HpackDecoder(Movable):
    """HPACK header block decoder (RFC 7541 Section 6)."""

    var static_table: StaticTable
    var dynamic_table: DynamicTable
    var huffman: HuffmanCodec
    var config: HpackConfig

    def __init__(out self, config: HpackConfig = HpackConfig()):
        self.static_table = StaticTable()
        self.dynamic_table = DynamicTable(config.max_header_table_size)
        self.huffman = HuffmanCodec()
        self.config = HpackConfig(other=config)

    def __init__(out self, *, deinit take: Self):
        self.static_table = StaticTable()
        self.dynamic_table = take.dynamic_table^
        self.huffman = take.huffman^
        self.config = take.config^

    def decode(
        mut self, wire: List[UInt8]
    ) -> Tuple[List[Header], String]:
        """Decode one HPACK header block. Updates dynamic table.

        Returns (headers, error). Error is empty on success.
        """
        var headers = List[Header]()
        var pos = 0
        var cumulative_size = 0
        var past_table_updates = False

        while pos < len(wire):
            var byte = Int(wire[pos])

            if byte & 0x80:
                past_table_updates = True
                var result = decode_integer(wire, pos, 7)
                var index = result[0]
                pos += result[1]
                if result[2].byte_length() > 0:
                    return (List[Header](), result[2])
                if index == 0:
                    return (List[Header](), String("index 0 is invalid"))

                var header = self._lookup_index(index)
                if header[0].byte_length() == 0 and header[1].byte_length() == 0:
                    return (
                        List[Header](),
                        String("invalid index ") + String(index),
                    )
                headers.append(Header(header[0], header[1]))
                cumulative_size += header[0].byte_length() + header[1].byte_length() + 32

            elif byte & 0x40:
                past_table_updates = True
                var result = self._decode_literal(wire, pos, 6)
                var name = result[0]
                var value = result[1]
                pos += result[2]
                if result[3].byte_length() > 0:
                    return (List[Header](), result[3])

                self.dynamic_table.insert(name, value)
                headers.append(Header(name, value))
                cumulative_size += name.byte_length() + value.byte_length() + 32

            elif byte & 0x20:
                if past_table_updates:
                    return (
                        List[Header](),
                        String(
                            "table size update after header field"
                        ),
                    )
                var result = decode_integer(wire, pos, 5)
                var new_size = result[0]
                pos += result[1]
                if result[2].byte_length() > 0:
                    return (List[Header](), result[2])
                if new_size > self.config.max_header_table_size:
                    return (
                        List[Header](),
                        String(
                            "table size update exceeds protocol limit"
                        ),
                    )
                self.dynamic_table.set_max_size(new_size)

            elif byte & 0x10:
                past_table_updates = True
                var result = self._decode_literal(wire, pos, 4)
                pos += result[2]
                if result[3].byte_length() > 0:
                    return (List[Header](), result[3])
                headers.append(Header(result[0], result[1]))
                cumulative_size += (
                    result[0].byte_length() + result[1].byte_length() + 32
                )

            else:
                past_table_updates = True
                var result = self._decode_literal(wire, pos, 4)
                pos += result[2]
                if result[3].byte_length() > 0:
                    return (List[Header](), result[3])
                headers.append(Header(result[0], result[1]))
                cumulative_size += (
                    result[0].byte_length() + result[1].byte_length() + 32
                )

            if cumulative_size > self.config.max_header_list_size:
                return (
                    List[Header](),
                    String("header list size exceeds maximum"),
                )

        return (headers^, String(""))

    def set_max_table_size(mut self, new_max: Int):
        """Called when SETTINGS_HEADER_TABLE_SIZE changes."""
        self.dynamic_table.set_max_size(new_max)

    def _lookup_index(
        self, index: Int
    ) -> Tuple[String, String]:
        """Look up a header by HPACK wire index."""
        if index <= 61:
            return self.static_table.lookup(index)
        else:
            return self.dynamic_table.lookup(index - 62)

    def _decode_literal(
        mut self,
        wire: List[UInt8],
        pos: Int,
        prefix_bits: Int,
    ) -> Tuple[String, String, Int, String]:
        """Decode a literal header field.

        Returns (name, value, bytes_consumed, error).
        """
        var consumed = 0

        var idx_result = decode_integer(wire, pos, prefix_bits)
        var name_index = idx_result[0]
        consumed += idx_result[1]
        if idx_result[2].byte_length() > 0:
            return (String(""), String(""), 0, idx_result[2])

        var name: String
        if name_index > 0:
            var lookup = self._lookup_index(name_index)
            name = lookup[0]
        else:
            var str_result = self._decode_string(wire, pos + consumed)
            name = str_result[0]
            consumed += str_result[1]
            if str_result[2].byte_length() > 0:
                return (String(""), String(""), 0, str_result[2])

        var val_result = self._decode_string(wire, pos + consumed)
        var value = val_result[0]
        consumed += val_result[1]
        if val_result[2].byte_length() > 0:
            return (String(""), String(""), 0, val_result[2])

        return (name^, value^, consumed, String(""))

    def _decode_string(
        self, wire: List[UInt8], pos: Int
    ) -> Tuple[String, Int, String]:
        """Decode an HPACK string literal (RFC 7541 Section 5.2)."""
        if pos >= len(wire):
            return (String(""), 0, String("truncated string"))

        var huffman_flag = (Int(wire[pos]) & 0x80) != 0

        var len_result = decode_integer(wire, pos, 7)
        var str_len = len_result[0]
        var consumed = len_result[1]
        if len_result[2].byte_length() > 0:
            return (String(""), 0, len_result[2])

        if pos + consumed + str_len > len(wire):
            return (String(""), 0, String("truncated string data"))

        var data_start = pos + consumed
        var data_end = data_start + str_len
        consumed += str_len

        if huffman_flag:
            var raw = List[UInt8](capacity=str_len)
            raw.extend(Span(wire)[data_start:data_end])
            var huff_result = self.huffman.decode(raw)
            if huff_result[1].byte_length() > 0:
                return (String(""), 0, huff_result[1])
            var s = String(unsafe_from_utf8=huff_result[0])
            return (s^, consumed, String(""))
        else:
            var raw = List[UInt8](capacity=str_len)
            raw.extend(Span(wire)[data_start:data_end])
            var s = String(unsafe_from_utf8=raw)
            return (s^, consumed, String(""))
