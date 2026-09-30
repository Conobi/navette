# src/quic/packet.mojo
# QUIC packet header codec and packet number encode/decode.
# RFC 9000 Section 17 (headers), Appendix A (PN decode).

from std.sys.info import size_of

from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_encode_at, write_u8_at, write_u32_be_at, varint_decode, varint_len
from navette.quic.cid_buf import CidBuf

# Inline capacities for wire-parsed variable-length header fields, keeping
# the struct a fixed, stack-allocatable size. A token is copied inline only
# when it fits (navette's own Retry tokens are <=89 bytes); a longer one,
# which another server may legitimately send in a Retry, is still parsed
# and located by `token_offset`. QUIC v1 defines one version.
comptime MAX_TOKEN_LEN: Int = 232
comptime MAX_SUPPORTED_VERSIONS: Int = 16
comptime RETRY_INTEGRITY_TAG_LEN: Int = 16

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
    """Decoded QUIC packet header (RFC 9000 Section 17).

    Variable-length wire fields (token, VN supported-versions list) are
    stored in fixed-capacity `InlineArray`s with a companion `_len` field
    tracking the number of valid entries, rather than heap-backed `List`s,
    so parsing a packet header never allocates. `token_len` and
    `token_offset` (from the start of the parsed span) locate the token of
    an Initial/Retry packet, of any length; `token` holds a copy of it only
    when `token_len <= MAX_TOKEN_LEN`, `supported_versions`/`versions_len` only for
    Version Negotiation, and `retry_integrity_tag` only for Retry (always
    exactly 16 bytes, so it carries no separate length field).
    """

    var is_long_header: Bool
    var packet_type: PacketType
    var version: UInt32
    var dcid: CidBuf
    var scid: CidBuf
    var token: InlineArray[UInt8, MAX_TOKEN_LEN]
    var token_len: UInt16
    var token_offset: UInt16
    var payload_length: UInt64
    var pn_offset: Int
    var supported_versions: InlineArray[UInt32, MAX_SUPPORTED_VERSIONS]
    var versions_len: UInt8
    var retry_integrity_tag: InlineArray[UInt8, RETRY_INTEGRITY_TAG_LEN]

    def __init__(out self):
        _check_packet_header_size()
        self.is_long_header = False
        self.packet_type = PacketType.one_rtt()
        self.version = UInt32(0)
        self.dcid = CidBuf.empty()
        self.scid = CidBuf.empty()
        self.token = InlineArray[UInt8, MAX_TOKEN_LEN](fill=Byte(0))
        self.token_len = UInt16(0)
        self.token_offset = UInt16(0)
        self.payload_length = UInt64(0)
        self.pn_offset = 0
        self.supported_versions = InlineArray[UInt32, MAX_SUPPORTED_VERSIONS](fill=UInt32(0))
        self.versions_len = UInt8(0)
        self.retry_integrity_tag = InlineArray[UInt8, RETRY_INTEGRITY_TAG_LEN](fill=Byte(0))

    def __init__(out self, *, copy: Self):
        self.is_long_header = copy.is_long_header
        self.packet_type = copy.packet_type
        self.version = copy.version
        self.dcid = CidBuf(copy=copy.dcid)
        self.scid = CidBuf(copy=copy.scid)
        self.token = InlineArray[UInt8, MAX_TOKEN_LEN](copy=copy.token)
        self.token_len = copy.token_len
        self.token_offset = copy.token_offset
        self.payload_length = copy.payload_length
        self.pn_offset = copy.pn_offset
        self.supported_versions = InlineArray[UInt32, MAX_SUPPORTED_VERSIONS](copy=copy.supported_versions)
        self.versions_len = copy.versions_len
        self.retry_integrity_tag = InlineArray[UInt8, RETRY_INTEGRITY_TAG_LEN](copy=copy.retry_integrity_tag)

    def token_span(self) -> Span[Byte, origin_of(self.token)]:
        """Borrow the inline token copy: the whole token when `token_len <= MAX_TOKEN_LEN`, else empty.

        A longer token is read from the packet at `token_offset`.
        """
        if Int(self.token_len) > MAX_TOKEN_LEN:
            return Span(unsafe_ptr=self.token.unsafe_ptr(), length=0)
        return Span(unsafe_ptr=self.token.unsafe_ptr(), length=Int(self.token_len))

    def retry_integrity_tag_span(self) -> Span[Byte, origin_of(self.retry_integrity_tag)]:
        """Borrow the 16-byte AEAD integrity tag (always fully populated for Retry packets)."""
        return Span(unsafe_ptr=self.retry_integrity_tag.unsafe_ptr(), length=RETRY_INTEGRITY_TAG_LEN)


def _check_packet_header_size():
    """Compile-time size gate: catches an accidental capacity bump (e.g.
    MAX_TOKEN_LEN) turning PacketHeader back into something too large to
    cheaply copy/move around the hot parse/build path."""
    comptime assert size_of[PacketHeader]() <= 400, "PacketHeader exceeds 400 bytes"


# --- Fast-path DCID inspection (server demux helpers) ---


def is_long_header_initial(payload: Span[Byte, _]) -> Bool:
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


def is_long_header_zero_rtt(payload: Span[Byte, _]) -> Bool:
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


def extract_dcid(data: Span[Byte, _]) raises -> CidBuf:
    """Extract the DCID from an incoming QUIC packet.

    The long-header branch reads the DCID length directly off the wire
    (byte 5) before any RFC 9000 validation has run, so it is clamped to
    20 bytes here rather than handed to `CidBuf.from_span` unclamped —
    that call aborts the process on an over-length span, which would
    turn a malformed/malicious packet into a remote DoS.
    """
    if len(data) < 6:
        raise "extract_dcid: packet too short"

    var first = Int(data[0])
    if (first & 0x80) != 0:
        var dcid_len = Int(data[5])
        if len(data) < 6 + dcid_len:
            raise "extract_dcid: packet too short for DCID"
        var n = min(dcid_len, 20)
        return CidBuf.from_span(data[6 : 6 + n])
    else:
        var result = parse_packet_header(data, 8)
        return result[0].dcid.copy()


# --- parse_packet_header ---


def parse_packet_header[
    origin: Origin
](buf: Span[Byte, origin], local_cid_len: Int) raises -> Tuple[PacketHeader, Int]:
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
        header.dcid = CidBuf.from_span(reader.read_span(dcid_len))

        # Read SCID.
        var scid_len = Int(reader.read_u8())
        if scid_len > 20:
            raise "SCID length exceeds 20"
        header.scid = CidBuf.from_span(reader.read_span(scid_len))

        if version == 0:
            # Version Negotiation: fixed bit is undefined for VN packets.
            header.packet_type = PacketType.version_negotiation()
            var version_count = 0
            while reader.remaining() >= 4:
                if version_count >= MAX_SUPPORTED_VERSIONS:
                    raise "VN packet exceeds " + String(MAX_SUPPORTED_VERSIONS) + " supported versions"
                header.supported_versions[version_count] = reader.read_u32_be()
                version_count += 1
            header.versions_len = UInt8(version_count)
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
            if rem < RETRY_INTEGRITY_TAG_LEN:
                raise "Retry packet too short for integrity tag"
            var token_len = rem - RETRY_INTEGRITY_TAG_LEN
            if reader.pos + token_len > 65535:
                raise "Retry packet longer than a UDP datagram"
            header.token_offset = UInt16(reader.pos)
            var token_bytes = reader.read_span(token_len)
            if token_len <= MAX_TOKEN_LEN:
                for i in range(token_len):
                    header.token[i] = token_bytes[i]
            header.token_len = UInt16(token_len)
            var tag_bytes = reader.read_span(RETRY_INTEGRITY_TAG_LEN)
            for i in range(RETRY_INTEGRITY_TAG_LEN):
                header.retry_integrity_tag[i] = tag_bytes[i]
            header.pn_offset = 0
            return Tuple[PacketHeader, Int](header^, reader.pos)

        if header.packet_type == PacketType.initial():
            # Read token length (varint) and token.
            var token_len_varint = varint_decode[origin](reader)
            if token_len_varint > UInt64(reader.remaining()):
                raise "Initial token longer than the packet"
            var token_len = Int(token_len_varint)
            if reader.pos + token_len > 65535:
                raise "Initial packet longer than a UDP datagram"
            header.token_offset = UInt16(reader.pos)
            if token_len > 0:
                var token_bytes = reader.read_span(token_len)
                if token_len <= MAX_TOKEN_LEN:
                    for i in range(token_len):
                        header.token[i] = token_bytes[i]
            header.token_len = UInt16(token_len)

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
        header.dcid = CidBuf.from_span(reader.read_span(local_cid_len))
        header.pn_offset = 1 + local_cid_len
        return Tuple[PacketHeader, Int](header^, reader.pos)


# --- Serialize functions ---


def serialize_long_header(header: PacketHeader, mut writer: ByteWriter) raises:
    """Serialize a long header via ByteWriter (delegates to _into variant)."""
    var buf = List[Byte]()
    serialize_long_header_into(header, buf)
    writer.write_bytes(Span(buf))


def serialize_short_header(dcid: Span[Byte, _], mut writer: ByteWriter):
    # First byte: form=0, fixed bit=1 -> 0x40. Spin, reserved, key phase, PN len TBD by caller.
    writer.write_u8(UInt8(0x40))
    writer.write_bytes(dcid)


def serialize_long_header_into(header: PacketHeader, mut buf: List[Byte]) raises:
    """Write a long header directly into a pre-allocated buffer.

    Same layout as serialize_long_header but bypasses ByteWriter
    indirection. An Initial carries `header.token_span()`.
    """
    serialize_long_header_with_token_into(header, header.token_span(), buf)


def serialize_long_header_with_token_into(
    header: PacketHeader, token: Span[Byte, _], mut buf: List[Byte]
) raises:
    """`serialize_long_header_into` with the Initial's token given apart, so it may exceed `MAX_TOKEN_LEN`."""
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

    # First byte + version (5 fixed bytes).
    var base = len(buf)
    buf.resize(base + 5, Byte(0))
    var pos = base
    pos += write_u8_at(buf, pos, first_byte)
    pos += write_u32_be_at(buf, pos, header.version)

    # DCID.
    buf.append(UInt8(len(header.dcid)))
    buf.extend(header.dcid.as_span())

    # SCID.
    buf.append(UInt8(len(header.scid)))
    buf.extend(header.scid.as_span())

    if header.packet_type == PacketType.initial():
        # Token length + token.
        var tl_len = varint_len(UInt64(len(token)))
        var tl_base = len(buf)
        buf.resize(tl_base + tl_len, Byte(0))
        _ = varint_encode_at(buf, tl_base, UInt64(len(token)))
        if len(token) > 0:
            buf.extend(token)

    if header.packet_type != PacketType.retry():
        # Payload length.
        var pl_len = varint_len(header.payload_length)
        var pl_base = len(buf)
        buf.resize(pl_base + pl_len, Byte(0))
        _ = varint_encode_at(buf, pl_base, header.payload_length)


def serialize_short_header_into(dcid: Span[Byte, _], mut buf: List[Byte]):
    """Write a 1-RTT short header directly into a pre-allocated buffer.

    Writes the fixed-bit flag byte (0x40) followed by the DCID.
    The caller sets PN-length bits and appends PN bytes afterward.
    """
    buf.append(UInt8(0x40))
    buf.extend(dcid)


def serialize_retry_packet(
    version: UInt32,
    dcid: Span[Byte, _],
    scid: Span[Byte, _],
    token: Span[Byte, _],
    integrity_tag: Span[Byte, _],
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
    dcid: Span[Byte, _],
    scid: Span[Byte, _],
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
    for ref ver in versions:
        writer.write_u32_be(ver)


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
