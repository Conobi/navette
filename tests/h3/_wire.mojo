"""Raw QUIC datagram builders for the ingress-guard tests.

Each builder returns exactly `total` bytes: a header laid out byte by
byte (so malformed lengths are expressible), then filler. Nothing here
is encrypted; the guard never looks past the header.
"""


def filled(v: UInt8, n: Int) -> List[Byte]:
    return List[Byte](length=n, fill=v)


def _append_u32(mut out: List[Byte], v: UInt32):
    for i in range(4):
        out.append(UInt8((v >> UInt32(8 * (3 - i))) & 0xFF))


def _append_varint(mut out: List[Byte], v: Int):
    """1-, 2- or 4-byte QUIC varint; `v` < 2^30."""
    if v < 64:
        out.append(UInt8(v))
    elif v < 16384:
        out.append(UInt8(0x40 | (v >> 8)))
        out.append(UInt8(v & 0xFF))
    else:
        out.append(UInt8(0x80 | (v >> 24)))
        out.append(UInt8((v >> 16) & 0xFF))
        out.append(UInt8((v >> 8) & 0xFF))
        out.append(UInt8(v & 0xFF))


def _pad_long(var out: List[Byte], total: Int) -> List[Byte]:
    """Append a 2-byte length field covering the rest, then filler up to `total` bytes."""
    var rest = total - len(out) - 2
    out.append(UInt8(0x40 | ((max(rest, 0) >> 8) & 0x3F)))
    out.append(UInt8(max(rest, 0) & 0xFF))
    while len(out) < total:
        out.append(0xA5)
    return out^


def long_packet(version: UInt32, total: Int, first: UInt8 = 0xC3, dcid_len: Int = 8, scid_len: Int = 8) -> List[Byte]:
    """Long header of any version: first byte, version, DCID 0xD1.., SCID 0x5C.., then a length and filler."""
    var out = List[Byte](capacity=max(total, 64))
    out.append(first)
    _append_u32(out, version)
    out.append(UInt8(dcid_len))
    for _ in range(dcid_len):
        out.append(0xD1)
    out.append(UInt8(scid_len))
    for _ in range(scid_len):
        out.append(0x5C)
    return _pad_long(out^, total)


def initial(
    total: Int,
    dcid: List[Byte],
    token: List[Byte] = List[Byte](),
    scid: List[Byte] = filled(0x5C, 8),
) -> List[Byte]:
    """QUIC v1 Initial with the given DCID, SCID and token."""
    var out = List[Byte](capacity=max(total, 64))
    out.append(0xC3)
    _append_u32(out, 1)
    out.append(UInt8(len(dcid)))
    out.extend(Span(dcid))
    out.append(UInt8(len(scid)))
    out.extend(Span(scid))
    _append_varint(out, len(token))
    out.extend(Span(token))
    return _pad_long(out^, total)


def initial_n(dcid_len: Int, total: Int) -> List[Byte]:
    """QUIC v1 Initial with a `dcid_len`-byte DCID (the wire length byte may exceed 20)."""
    return initial(total, filled(0xD1, dcid_len))


def handshake(total: Int) -> List[Byte]:
    """QUIC v1 Handshake packet with an 8-byte DCID."""
    return long_packet(1, total, first=0xE3)


def short_packet(total: Int) -> List[Byte]:
    """1-RTT short header: first byte 0x43, then filler (the DCID is the first 8 filler bytes)."""
    var out = List[Byte](capacity=total)
    out.append(0x43)
    while len(out) < total:
        out.append(0xB7)
    return out^
