# src/quic/packet.mojo
# QUIC packet header codec and packet number encode/decode.
# RFC 9000 Section 17 (headers), Appendix A (PN decode).

from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_encode_into, varint_decode, varint_len

# --- Constants ---

comptime MIN_INITIAL_PACKET_SIZE: Int = 1200


def initial_packet_needs_padding(packet_len: Int) -> Int:
    if MIN_INITIAL_PACKET_SIZE > packet_len:
        return MIN_INITIAL_PACKET_SIZE - packet_len
    return 0


# --- PacketType ---


struct PacketType(ImplicitlyCopyable, Equatable):
    var _value: UInt8

    # Packet type values.
    comptime INITIAL: UInt8 = 0
    comptime ZERO_RTT: UInt8 = 1
    comptime HANDSHAKE: UInt8 = 2
    comptime RETRY: UInt8 = 3
    comptime ONE_RTT: UInt8 = 4
    comptime VERSION_NEGOTIATION: UInt8 = 5

    def __init__(out self, value: UInt8):
        self._value = value

    def __init__(out self, *, copy: Self):
        self._value = copy._value

    def __init__(out self, *, deinit move: Self):
        self._value = move._value

    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    def __ne__(self, other: Self) -> Bool:
        return self._value != other._value

    @staticmethod
    def initial() -> PacketType:
        return PacketType(PacketType.INITIAL)

    @staticmethod
    def zero_rtt() -> PacketType:
        return PacketType(PacketType.ZERO_RTT)

    @staticmethod
    def handshake() -> PacketType:
        return PacketType(PacketType.HANDSHAKE)

    @staticmethod
    def retry() -> PacketType:
        return PacketType(PacketType.RETRY)

    @staticmethod
    def one_rtt() -> PacketType:
        return PacketType(PacketType.ONE_RTT)

    @staticmethod
    def version_negotiation() -> PacketType:
        return PacketType(PacketType.VERSION_NEGOTIATION)

    def is_long_header(self) -> Bool:
        return self._value != PacketType.ONE_RTT


# --- PacketHeader ---


struct PacketHeader(Copyable, Movable):
    var is_long_header: Bool
    var packet_type: PacketType
    var version: UInt32
    var dcid: List[UInt8]
    var scid: List[UInt8]
    var token: List[UInt8]
    var payload_length: UInt64
    var pn_offset: Int
    var supported_versions: List[UInt32]
    var retry_integrity_tag: List[UInt8]

    def __init__(out self):
        self.is_long_header = False
        self.packet_type = PacketType.one_rtt()
        self.version = UInt32(0)
        self.dcid = List[UInt8]()
        self.scid = List[UInt8]()
        self.token = List[UInt8]()
        self.payload_length = UInt64(0)
        self.pn_offset = 0
        self.supported_versions = List[UInt32]()
        self.retry_integrity_tag = List[UInt8]()

    def __init__(out self, *, copy: Self):
        self.is_long_header = copy.is_long_header
        self.packet_type = copy.packet_type
        self.version = copy.version
        self.dcid = List[UInt8](copy=copy.dcid)
        self.scid = List[UInt8](copy=copy.scid)
        self.token = List[UInt8](copy=copy.token)
        self.payload_length = copy.payload_length
        self.pn_offset = copy.pn_offset
        self.supported_versions = List[UInt32](copy=copy.supported_versions)
        self.retry_integrity_tag = List[UInt8](copy=copy.retry_integrity_tag)

    def __init__(out self, *, deinit move: Self):
        self.is_long_header = move.is_long_header
        self.packet_type = move.packet_type
        self.version = move.version
        self.dcid = move.dcid^
        self.scid = move.scid^
        self.token = move.token^
        self.payload_length = move.payload_length
        self.pn_offset = move.pn_offset
        self.supported_versions = move.supported_versions^
        self.retry_integrity_tag = move.retry_integrity_tag^


# --- Fast-path DCID inspection (server demux helpers) ---


def is_long_header_initial(payload: Span[UInt8, _]) -> Bool:
    """True iff the QUIC packet's first byte indicates a long-header Initial.

    First byte (RFC 9000 v1):
      bit 7 (0x80): header form. 1 = long, 0 = short.
      bits 5-4 (0x30): packet type for long header.
        0b00 = 0x00 = Initial
        0b01 = 0x10 = 0-RTT
        0b10 = 0x20 = Handshake
        0b11 = 0x30 = Retry

    Empty `payload` returns False (defensive).
    QUIC v1 only.
    """
    if len(payload) == 0:
        return False
    var first = payload[0]
    if (first & 0x80) == 0:
        return False  # short header
    return (first & 0x30) == 0x00


def is_long_header_zero_rtt(payload: Span[UInt8, _]) -> Bool:
    """True iff the QUIC packet's first byte indicates a long-header 0-RTT.

    Uses the same v1 layout as `is_long_header_initial` (RFC 9000 §17.2 +
    §17.2.3): long-header form bit set (0x80) and packet-type field
    (bits 5-4, mask 0x30) equal to 0b01 (0x10).

    Empty `payload` returns False (defensive). QUIC v1 only.

    Per RFC 9001 §5.5, a server that has not enabled 0-RTT
    (`max_early_data_size = 0`) holds no 0-RTT keys and MUST drop the
    packet silently; this helper lets the receive loop short-circuit
    before invoking the AEAD path against keys that do not exist.
    """
    if len(payload) == 0:
        return False
    var first = payload[0]
    if (first & 0x80) == 0:
        return False  # short header
    return (first & 0x30) == 0x10


struct DcidBuf(Copyable, Movable):
    """Fixed-size DCID buffer (max 20 bytes per RFC 9000)."""
    var data: InlineArray[UInt8, 20]
    var len: UInt8

    def __init__(out self):
        self.data = InlineArray[UInt8, 20](fill=UInt8(0))
        self.len = 0

    def __init__(out self, src: Span[UInt8, _]):
        """Construct from a Span, copying up to 20 bytes."""
        self.data = InlineArray[UInt8, 20](fill=UInt8(0))
        var n = min(len(src), 20)
        for i in range(n):
            self.data[i] = src[i]
        self.len = UInt8(n)

    def __init__(out self, *, copy: Self):
        self.data = InlineArray[UInt8, 20](copy=copy.data)
        self.len = copy.len

    def __init__(out self, *, deinit move: Self):
        self.data = move.data^
        self.len = move.len

    def as_span(self) -> Span[UInt8, origin_of(self.data)]:
        """View the DCID bytes as a Span."""
        return Span(unsafe_ptr=self.data.unsafe_ptr(), length=Int(self.len))


def extract_dcid(data: Span[UInt8, _]) raises -> DcidBuf:
    """Extract the DCID from an incoming QUIC packet."""
    if len(data) < 6:
        raise "extract_dcid: packet too short"

    var first = Int(data[0])
    if (first & 0x80) != 0:
        var dcid_len = Int(data[5])
        if len(data) < 6 + dcid_len:
            raise "extract_dcid: packet too short for DCID"
        var buf = DcidBuf()
        for i in range(min(dcid_len, 20)):
            buf.data[i] = data[6 + i]
        buf.len = UInt8(min(dcid_len, 20))
        return buf^
    else:
        var result = parse_packet_header(data, 8)
        return DcidBuf(Span(result[0].dcid))


# --- parse_packet_header ---


def parse_packet_header[
    origin: Origin
](buf: Span[UInt8, origin], local_cid_len: Int) raises -> Tuple[PacketHeader, Int]:
    if len(buf) < 1:
        raise "packet too short"

    var reader = ByteReader[origin](buf)
    var first_byte = reader.read_u8()
    var header = PacketHeader()

    var is_long = Bool((first_byte & 0x80) != 0)
    header.is_long_header = is_long

    if is_long:
        # Long header.
        if reader.remaining() < 4:
            raise "packet too short for version"
        var version = reader.read_u32_be()
        header.version = version

        # Read DCID.
        var dcid_len = Int(reader.read_u8())
        if dcid_len > 20:
            raise "DCID length exceeds 20"
        header.dcid = reader.read_bytes(dcid_len)

        # Read SCID.
        var scid_len = Int(reader.read_u8())
        if scid_len > 20:
            raise "SCID length exceeds 20"
        header.scid = reader.read_bytes(scid_len)

        if version == 0:
            # Version Negotiation: fixed bit is undefined for VN packets.
            header.packet_type = PacketType.version_negotiation()
            var versions = List[UInt32]()
            while reader.remaining() >= 4:
                versions.append(reader.read_u32_be())
            header.supported_versions = versions^
            header.pn_offset = 0
            return Tuple[PacketHeader, Int](header^, reader.pos)

        # Fixed bit (bit 6) must be 1 for non-VN long header packets.
        if (first_byte & 0x40) == 0:
            raise "fixed bit not set in long header"

        # Determine packet type from bits 4-5.
        var ptype_bits = Int((first_byte >> 4) & 0x03)
        if ptype_bits == 0:
            header.packet_type = PacketType.initial()
        elif ptype_bits == 1:
            header.packet_type = PacketType.zero_rtt()
        elif ptype_bits == 2:
            header.packet_type = PacketType.handshake()
        else:
            header.packet_type = PacketType.retry()

        if header.packet_type == PacketType.retry():
            # Retry: remaining - 16 = token, last 16 = integrity tag.
            var rem = reader.remaining()
            if rem < 16:
                raise "Retry packet too short for integrity tag"
            var token_len = rem - 16
            header.token = reader.read_bytes(token_len)
            header.retry_integrity_tag = reader.read_bytes(16)
            header.pn_offset = 0
            return Tuple[PacketHeader, Int](header^, reader.pos)

        if header.packet_type == PacketType.initial():
            # Read token length (varint) and token.
            var token_len = varint_decode[origin](reader)
            if token_len > 0:
                header.token = reader.read_bytes(Int(token_len))

        # Read payload length (varint) for Initial, Handshake, 0-RTT.
        header.payload_length = varint_decode[origin](reader)
        header.pn_offset = reader.pos
        return Tuple[PacketHeader, Int](header^, reader.pos)

    else:
        # Short header (1-RTT).
        if (first_byte & UInt8(0x40)) == UInt8(0):
            raise "short header: fixed bit not set"
        header.packet_type = PacketType.one_rtt()
        header.is_long_header = False
        header.version = UInt32(0)

        if reader.remaining() < local_cid_len:
            raise "packet too short for DCID"
        header.dcid = reader.read_bytes(local_cid_len)
        header.pn_offset = 1 + local_cid_len
        return Tuple[PacketHeader, Int](header^, reader.pos)


# --- Serialize functions ---


def serialize_long_header(header: PacketHeader, mut writer: ByteWriter) raises:
    # Build first byte: form bit (0x80) | fixed bit (0x40) | type bits | reserved.
    var first_byte = UInt8(0xC0)  # long header + fixed bit

    if header.packet_type == PacketType.initial():
        first_byte = first_byte | UInt8(0x00)
    elif header.packet_type == PacketType.zero_rtt():
        first_byte = first_byte | UInt8(0x10)
    elif header.packet_type == PacketType.handshake():
        first_byte = first_byte | UInt8(0x20)
    elif header.packet_type == PacketType.retry():
        first_byte = first_byte | UInt8(0x30)

    writer.write_u8(first_byte)
    writer.write_u32_be(header.version)

    # DCID.
    if len(header.dcid) > 20:
        raise "DCID length exceeds 20"
    writer.write_u8(UInt8(len(header.dcid)))
    writer.write_bytes(Span[UInt8, origin_of(header.dcid)](header.dcid))

    # SCID.
    if len(header.scid) > 20:
        raise "SCID length exceeds 20"
    writer.write_u8(UInt8(len(header.scid)))
    writer.write_bytes(Span[UInt8, origin_of(header.scid)](header.scid))

    if header.packet_type == PacketType.initial():
        # Token length + token.
        varint_encode(writer, UInt64(len(header.token)))
        if len(header.token) > 0:
            writer.write_bytes(Span[UInt8, origin_of(header.token)](header.token))

    if header.packet_type != PacketType.retry():
        # Payload length.
        varint_encode(writer, header.payload_length)


def serialize_short_header(dcid: Span[UInt8, _], mut writer: ByteWriter):
    # First byte: form=0, fixed bit=1 -> 0x40. Spin, reserved, key phase, PN len TBD by caller.
    writer.write_u8(UInt8(0x40))
    writer.write_bytes(dcid)


def serialize_long_header_into(header: PacketHeader, mut buf: List[UInt8]) raises:
    """Write a long header directly into a pre-allocated buffer.

    Same layout as serialize_long_header but bypasses ByteWriter indirection.
    """
    # Build first byte: form bit (0x80) | fixed bit (0x40) | type bits.
    var first_byte = UInt8(0xC0)  # long header + fixed bit

    if header.packet_type == PacketType.initial():
        first_byte = first_byte | UInt8(0x00)
    elif header.packet_type == PacketType.zero_rtt():
        first_byte = first_byte | UInt8(0x10)
    elif header.packet_type == PacketType.handshake():
        first_byte = first_byte | UInt8(0x20)
    elif header.packet_type == PacketType.retry():
        first_byte = first_byte | UInt8(0x30)

    buf.append(first_byte)

    # Version (4 bytes BE).
    buf.append(UInt8((header.version >> 24) & 0xFF))
    buf.append(UInt8((header.version >> 16) & 0xFF))
    buf.append(UInt8((header.version >> 8) & 0xFF))
    buf.append(UInt8(header.version & 0xFF))

    # DCID.
    if len(header.dcid) > 20:
        raise "DCID length exceeds 20"
    buf.append(UInt8(len(header.dcid)))
    buf.extend(Span[UInt8, origin_of(header.dcid)](header.dcid))

    # SCID.
    if len(header.scid) > 20:
        raise "SCID length exceeds 20"
    buf.append(UInt8(len(header.scid)))
    buf.extend(Span[UInt8, origin_of(header.scid)](header.scid))

    if header.packet_type == PacketType.initial():
        # Token length + token.
        varint_encode_into(buf, UInt64(len(header.token)))
        if len(header.token) > 0:
            buf.extend(Span[UInt8, origin_of(header.token)](header.token))

    if header.packet_type != PacketType.retry():
        # Payload length.
        varint_encode_into(buf, header.payload_length)


def serialize_short_header_into(dcid: Span[UInt8, _], mut buf: List[UInt8]):
    """Write a 1-RTT short header directly into a pre-allocated buffer.

    Writes the fixed-bit flag byte (0x40) followed by the DCID.
    The caller sets PN-length bits and appends PN bytes afterward.
    """
    buf.append(UInt8(0x40))
    buf.extend(dcid)


def serialize_retry_packet(
    version: UInt32,
    dcid: Span[UInt8, _],
    scid: Span[UInt8, _],
    token: Span[UInt8, _],
    integrity_tag: Span[UInt8, _],
    mut writer: ByteWriter,
) raises:
    if len(dcid) > 20:
        raise "DCID length exceeds 20"
    if len(scid) > 20:
        raise "SCID length exceeds 20"
    if len(integrity_tag) != 16:
        raise "Retry integrity tag must be 16 bytes"

    # First byte: long header + fixed + Retry type (0x30).
    writer.write_u8(UInt8(0xF0))
    writer.write_u32_be(version)
    writer.write_u8(UInt8(len(dcid)))
    writer.write_bytes(dcid)
    writer.write_u8(UInt8(len(scid)))
    writer.write_bytes(scid)
    writer.write_bytes(token)
    writer.write_bytes(integrity_tag)


def serialize_version_negotiation(
    dcid: Span[UInt8, _],
    scid: Span[UInt8, _],
    versions: List[UInt32],
    mut writer: ByteWriter,
):
    # First byte: long header form bit set, rest can be random; use 0x80.
    writer.write_u8(UInt8(0x80))
    # Version = 0 for VN.
    writer.write_u32_be(UInt32(0))
    writer.write_u8(UInt8(len(dcid)))
    writer.write_bytes(dcid)
    writer.write_u8(UInt8(len(scid)))
    writer.write_bytes(scid)
    for i in range(len(versions)):
        writer.write_u32_be(versions[i])


# --- Packet Number encode/decode (RFC 9000 Appendix A) ---


def pn_encode_length(full_pn: UInt64, largest_acked: UInt64) -> Int:
    # Use 2x the distance + 1 to determine encoding length.
    # If nothing acked yet, largest_acked should be passed as 0 and full_pn >= 0.
    var num_unacked: UInt64
    if full_pn > largest_acked:
        num_unacked = (full_pn - largest_acked) * 2
    else:
        num_unacked = UInt64(0)

    if num_unacked <= UInt64(0x100):
        return 1
    elif num_unacked <= UInt64(0x10000):
        return 2
    elif num_unacked <= UInt64(0x1000000):
        return 3
    else:
        return 4


def pn_truncate(full_pn: UInt64, pn_length: Int) -> UInt64:
    return full_pn & ((UInt64(1) << UInt64(pn_length * 8)) - 1)


def pn_decode(truncated_pn: UInt64, pn_length: Int, largest_pn: UInt64) -> UInt64:
    # RFC 9000 Appendix A, corrected per PR #3188.
    # Use signed Int internally to avoid unsigned underflow.
    var pn_nbits = UInt64(8 * pn_length)
    var pn_win = UInt64(1) << pn_nbits
    var pn_hwin = pn_win >> 1
    var pn_mask = pn_win - 1

    var expected_pn = largest_pn + 1
    var candidate = (expected_pn & ~pn_mask) | truncated_pn

    # Signed comparisons to avoid underflow when expected_pn < pn_hwin
    var s_candidate = Int(candidate)
    var s_expected = Int(expected_pn)
    var s_pn_hwin = Int(pn_hwin)
    var s_pn_win = Int(pn_win)

    if s_candidate <= s_expected - s_pn_hwin and s_candidate < (1 << 62) - s_pn_win:
        candidate += pn_win
        s_candidate = Int(candidate)  # Refresh after adjustment
    if s_candidate > s_expected + s_pn_hwin and candidate >= pn_win:
        candidate -= pn_win
    return candidate
