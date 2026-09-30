# tests/test_quic_packet.mojo
#
# Tests for QUIC packet header codec and PN encode/decode (src/quic/packet.mojo).
# Covers: QC-1 header vectors, PN vectors, round-trip, edge cases, errors,
# and the padding utility.
#
# Run with:
#   cd ~/Projets/perso/navette && uv run mojo run -I . -I conformance \
#     -D ASSERT=all tests/test_quic_packet.mojo

from std.python import Python, PythonObject

from navette.quic.codec import ByteReader, ByteWriter, varint_encode
from navette.quic.cid_buf import CidBuf
from navette.quic.packet import (
    PacketHeader,
    PacketType,
    initial_packet_needs_padding,
    parse_packet_header,
    pn_decode,
    pn_encode_length,
    pn_truncate,
    serialize_long_header,
    serialize_retry_packet,
    serialize_short_header,
    serialize_version_negotiation,
)

from oracle.test_util import hex_decode, hex_encode, load_vectors
from tests._test_util import assert_true, assert_equal_int, assert_equal_str


# --- Helpers ---


def packet_type_to_string(pt: PacketType) -> String:
    if pt == PacketType.initial():
        return "initial"
    if pt == PacketType.zero_rtt():
        return "zero_rtt"
    if pt == PacketType.handshake():
        return "handshake"
    if pt == PacketType.retry():
        return "retry"
    if pt == PacketType.one_rtt():
        return "one_rtt"
    if pt == PacketType.version_negotiation():
        return "version_negotiation"
    return "unknown"


def _has_key(obj: PythonObject, key: String) -> Bool:
    try:
        var builtins = Python.import_module("builtins")
        return Bool(builtins.bool(key in obj))
    except:
        return False


# === Section 1: QC-1 packet header vector tests ===


def test_packet_header_vectors() raises:
    var vectors = load_vectors("conformance/vectors/rfc9000/packet_header.json")
    var builtins = Python.import_module("builtins")
    var count = Int(py=builtins.len(vectors))
    assert_true(count >= 18, "expected at least 18 header vectors, got " + String(count))
    var n_pass = 0
    var n_reject = 0

    for i in range(count):
        var vec = vectors[i]
        var vid = String(vec["id"])
        var wire_hex = String(vec["input"]["wire_hex"])
        var host_cid_len = Int(py=vec["input"]["host_cid_length"])
        var wire_bytes = hex_decode(wire_hex)

        var expected = vec["expected"]

        # Check if this is a reject vector.
        var is_reject = False
        if _has_key(expected, "behavior"):
            if String(expected["behavior"]) == "reject":
                is_reject = True

        if is_reject:
            var caught = False
            try:
                _ = parse_packet_header(Span(wire_bytes), host_cid_len)
            except:
                caught = True
            assert_true(caught, vid + ": expected reject but parse succeeded")
            n_reject += 1
            continue

        # Accept vector: parse and check fields.
        var result = parse_packet_header(Span(wire_bytes), host_cid_len)

        # is_long_header
        var exp_long = Bool(py=expected["is_long_header"])
        assert_true(
            result[0].is_long_header == exp_long,
            vid + ": is_long_header mismatch: got " + String(result[0].is_long_header) + " expected " + String(exp_long),
        )

        # packet_type
        var exp_type = String(expected["packet_type"])
        var got_type = packet_type_to_string(result[0].packet_type)
        assert_equal_str(got_type, exp_type, vid + ".packet_type")

        # version
        var exp_version = Int(py=expected["version"])
        assert_equal_int(Int(result[0].version), exp_version, vid + ".version")

        # destination_cid_hex
        var exp_dcid = String(expected["destination_cid_hex"])
        var got_dcid = hex_encode(List[Byte](result[0].dcid.as_span()))
        assert_equal_str(got_dcid, exp_dcid, vid + ".dcid")

        # source_cid_hex
        var exp_scid = String(expected["source_cid_hex"])
        var got_scid = hex_encode(List[Byte](result[0].scid.as_span()))
        assert_equal_str(got_scid, exp_scid, vid + ".scid")

        # token_hex
        var exp_token = String(expected["token_hex"])
        var got_token = hex_encode(List[Byte](result[0].token_span()))
        assert_equal_str(got_token, exp_token, vid + ".token")

        # packet_length: for long headers with payload_length it is
        # pn_offset + payload_length; for retry it is bytes_consumed;
        # for short header it is total wire length.
        var exp_pkt_len = Int(py=expected["packet_length"])
        if result[0].packet_type == PacketType.initial() or result[0].packet_type == PacketType.handshake() or result[0].packet_type == PacketType.zero_rtt():
            var got_pkt_len = result[0].pn_offset + Int(result[0].payload_length)
            assert_equal_int(got_pkt_len, exp_pkt_len, vid + ".packet_length")
        elif result[0].packet_type == PacketType.retry():
            assert_equal_int(result[1], exp_pkt_len, vid + ".packet_length(retry)")
        else:
            # Short header: packet_length == wire length.
            assert_equal_int(len(wire_bytes), exp_pkt_len, vid + ".packet_length(short)")

        n_pass += 1

    print(
        "  packet_header_vectors: PASS ("
        + String(n_pass)
        + " accept, "
        + String(n_reject)
        + " reject)"
    )


# === Section 2: PN vector tests ===


def test_pn_vectors() raises:
    var vectors = load_vectors("conformance/vectors/rfc9000/packet_number.json")
    var builtins = Python.import_module("builtins")
    var count = Int(py=builtins.len(vectors))
    assert_true(count >= 30, "expected at least 30 PN vectors, got " + String(count))
    var n_decode = 0
    var n_encode = 0

    for i in range(count):
        var vec = vectors[i]
        var name = String(vec["name"])
        var op = String(vec["operation"])

        if op == "decode":
            var truncated_pn = UInt64(Int(py=vec["input"]["truncated_pn"]))
            var pn_nbits = Int(py=vec["input"]["pn_nbits"])
            var pn_length = pn_nbits // 8
            var largest_pn = UInt64(Int(py=vec["input"]["largest_pn"]))
            var expected_full = UInt64(Int(py=vec["expected"]["full_pn"]))

            var got = pn_decode(truncated_pn, pn_length, largest_pn)
            assert_equal_int(
                Int(got), Int(expected_full), name + ": pn_decode"
            )
            n_decode += 1

        elif op == "encode":
            var full_pn = UInt64(Int(py=vec["input"]["full_pn"]))
            var largest_acked_py = vec["input"]["largest_acked"]
            # Handle largest_acked == -1 (nothing acked yet) -> pass 0.
            var la_int = Int(py=largest_acked_py)
            var largest_acked: UInt64
            if la_int < 0:
                largest_acked = UInt64(0)
            else:
                largest_acked = UInt64(la_int)
            var expected_len = Int(py=vec["expected"]["pn_length"])

            var got_len = pn_encode_length(full_pn, largest_acked)
            assert_equal_int(got_len, expected_len, name + ": pn_encode_length")
            n_encode += 1

    print(
        "  pn_vectors: PASS ("
        + String(n_decode)
        + " decode, "
        + String(n_encode)
        + " encode)"
    )


# === Section 3: Round-trip tests ===


def test_roundtrip_initial() raises:
    var hdr = PacketHeader()
    hdr.is_long_header = True
    hdr.packet_type = PacketType.initial()
    hdr.version = UInt32(1)
    hdr.dcid = CidBuf.from_span(Span(hex_decode("0102030405060708")))
    hdr.scid = CidBuf.from_span(Span(hex_decode("aabbccdd")))
    var initial_token = hex_decode("cafebabe")
    for i in range(len(initial_token)):
        hdr.token[i] = initial_token[i]
    hdr.token_len = UInt16(len(initial_token))
    hdr.payload_length = UInt64(100)

    var w = ByteWriter()
    serialize_long_header(hdr, w)
    var wire = w.finish()

    var result = parse_packet_header(Span(wire), 8)

    assert_true(result[0].is_long_header, "roundtrip initial: expected long header")
    assert_true(result[0].packet_type == PacketType.initial(), "roundtrip initial: wrong packet type")
    assert_equal_int(Int(result[0].version), 1, "roundtrip initial: version")
    assert_equal_str(hex_encode(List[Byte](result[0].dcid.as_span())), "0102030405060708", "roundtrip initial: dcid")
    assert_equal_str(hex_encode(List[Byte](result[0].scid.as_span())), "aabbccdd", "roundtrip initial: scid")
    assert_equal_str(hex_encode(List[Byte](result[0].token_span())), "cafebabe", "roundtrip initial: token")
    assert_equal_int(Int(result[0].payload_length), 100, "roundtrip initial: payload_length")
    print("  roundtrip_initial: PASS")


def test_roundtrip_handshake() raises:
    var hdr = PacketHeader()
    hdr.is_long_header = True
    hdr.packet_type = PacketType.handshake()
    hdr.version = UInt32(1)
    hdr.dcid = CidBuf.from_span(Span(hex_decode("aabbccdd")))
    hdr.scid = CidBuf.from_span(Span(hex_decode("11223344")))
    hdr.payload_length = UInt64(50)

    var w = ByteWriter()
    serialize_long_header(hdr, w)
    var wire = w.finish()

    var result = parse_packet_header(Span(wire), 4)

    assert_true(result[0].is_long_header, "roundtrip handshake: expected long header")
    assert_true(result[0].packet_type == PacketType.handshake(), "roundtrip handshake: wrong packet type")
    assert_equal_int(Int(result[0].version), 1, "roundtrip handshake: version")
    assert_equal_str(hex_encode(List[Byte](result[0].dcid.as_span())), "aabbccdd", "roundtrip handshake: dcid")
    assert_equal_str(hex_encode(List[Byte](result[0].scid.as_span())), "11223344", "roundtrip handshake: scid")
    assert_equal_int(Int(result[0].payload_length), 50, "roundtrip handshake: payload_length")
    print("  roundtrip_handshake: PASS")


def test_roundtrip_short_header() raises:
    var dcid = hex_decode("0102030405060708")
    var w = ByteWriter()
    serialize_short_header(Span(dcid), w)
    var wire = w.finish()

    var result = parse_packet_header(Span(wire), 8)

    assert_true(not result[0].is_long_header, "roundtrip short: expected short header")
    assert_true(result[0].packet_type == PacketType.one_rtt(), "roundtrip short: wrong packet type")
    assert_equal_str(hex_encode(List[Byte](result[0].dcid.as_span())), "0102030405060708", "roundtrip short: dcid")
    print("  roundtrip_short_header: PASS")


def test_roundtrip_version_negotiation() raises:
    var dcid = hex_decode("0102030405060708")
    var scid = hex_decode("aabbccdd")
    var versions = List[UInt32]()
    versions.append(UInt32(1))
    versions.append(UInt32(0xFF000020))

    var w = ByteWriter()
    serialize_version_negotiation(Span(dcid), Span(scid), versions, w)
    var wire = w.finish()

    var result = parse_packet_header(Span(wire), 8)

    assert_true(result[0].is_long_header, "roundtrip VN: expected long header")
    assert_true(
        result[0].packet_type == PacketType.version_negotiation(),
        "roundtrip VN: wrong packet type",
    )
    assert_equal_int(Int(result[0].version), 0, "roundtrip VN: version")
    assert_equal_str(hex_encode(List[Byte](result[0].dcid.as_span())), "0102030405060708", "roundtrip VN: dcid")
    assert_equal_str(hex_encode(List[Byte](result[0].scid.as_span())), "aabbccdd", "roundtrip VN: scid")
    assert_equal_int(Int(result[0].versions_len), 2, "roundtrip VN: version count")
    assert_equal_int(Int(result[0].supported_versions[0]), 1, "roundtrip VN: version[0]")
    assert_equal_int(
        Int(result[0].supported_versions[1]),
        Int(UInt32(0xFF000020)),
        "roundtrip VN: version[1]",
    )
    print("  roundtrip_version_negotiation: PASS")


def test_roundtrip_retry() raises:
    var dcid = hex_decode("0102030405060708")
    var scid = hex_decode("aabbccdd")
    var token = hex_decode("cafebabe")
    var integrity_tag = hex_decode("00112233445566778899aabbccddeeff")

    var w = ByteWriter()
    serialize_retry_packet(
        UInt32(1),
        Span(dcid),
        Span(scid),
        Span(token),
        Span(integrity_tag),
        w,
    )
    var wire = w.finish()

    var result = parse_packet_header(Span(wire), 8)

    assert_true(result[0].is_long_header, "roundtrip retry: expected long header")
    assert_true(result[0].packet_type == PacketType.retry(), "roundtrip retry: wrong packet type")
    assert_equal_int(Int(result[0].version), 1, "roundtrip retry: version")
    assert_equal_str(hex_encode(List[Byte](result[0].dcid.as_span())), "0102030405060708", "roundtrip retry: dcid")
    assert_equal_str(hex_encode(List[Byte](result[0].scid.as_span())), "aabbccdd", "roundtrip retry: scid")
    assert_equal_str(hex_encode(List[Byte](result[0].token_span())), "cafebabe", "roundtrip retry: token")
    assert_equal_str(
        hex_encode(List[Byte](result[0].retry_integrity_tag_span())),
        "00112233445566778899aabbccddeeff",
        "roundtrip retry: integrity_tag",
    )
    print("  roundtrip_retry: PASS")


# === Section 4: PN edge cases ===


def test_pn_edge_cases() raises:
    # pn=0, largest_acked=0 -> encode_length returns 1
    assert_equal_int(
        pn_encode_length(UInt64(0), UInt64(0)), 1,
        "pn edge: pn=0 la=0",
    )

    # pn=100, largest_acked=95 -> 1 byte
    assert_equal_int(
        pn_encode_length(UInt64(100), UInt64(95)), 1,
        "pn edge: pn=100 la=95",
    )

    # pn=256, largest_acked=0 -> 2 bytes
    assert_equal_int(
        pn_encode_length(UInt64(256), UInt64(0)), 2,
        "pn edge: pn=256 la=0",
    )

    # Round-trip: truncate + decode == original
    var full_pn = UInt64(1234567)
    var largest_acked = UInt64(1234560)
    var enc_len = pn_encode_length(full_pn, largest_acked)
    var truncated = pn_truncate(full_pn, enc_len)
    var decoded = pn_decode(truncated, enc_len, largest_acked)
    assert_equal_int(Int(decoded), Int(full_pn), "pn roundtrip")

    print("  pn_edge_cases: PASS")


# === Section 5: Error cases ===


def test_error_dcid_too_long() raises:
    # Build a long header with DCID length > 20 -- should raise.
    var wire = List[Byte]()
    wire.append(UInt8(0xC0))  # long header + fixed bit
    # Version.
    wire.append(UInt8(0x00))
    wire.append(UInt8(0x00))
    wire.append(UInt8(0x00))
    wire.append(UInt8(0x01))
    # DCID length = 21 (exceeds 20).
    wire.append(UInt8(21))
    # Pad 21 bytes for DCID.
    for _ in range(21):
        wire.append(UInt8(0x00))

    var caught = False
    try:
        _ = parse_packet_header(Span(wire), 8)
    except:
        caught = True
    assert_true(caught, "expected error for DCID > 20")
    print("  error_dcid_too_long: PASS")


def test_error_truncated_long_header() raises:
    # Only 2 bytes -- too short for version after first byte.
    var wire = hex_decode("c000")
    var caught = False
    try:
        _ = parse_packet_header(Span(wire), 8)
    except:
        caught = True
    assert_true(caught, "expected error for truncated long header")
    print("  error_truncated_long_header: PASS")


def test_error_short_header_fixed_bit() raises:
    # Short header (bit 7 = 0) but fixed bit (bit 6) = 0 -> should raise.
    var wire = List[Byte]()
    wire.append(UInt8(0x00))  # form=0, fixed=0
    for _ in range(8):
        wire.append(UInt8(0x00))
    var caught = False
    try:
        _ = parse_packet_header(Span(wire), 8)
    except:
        caught = True
    assert_true(caught, "expected error for short header with fixed bit = 0")
    print("  error_short_header_fixed_bit: PASS")


def test_error_initial_token_too_long() raises:
    # Initial packet whose wire-declared token length (233) runs past the
    # end of the packet -- must raise rather than read out of bounds.
    var w = ByteWriter()
    w.write_u8(UInt8(0xC0))  # long header + fixed bit, ptype bits 00 = Initial
    w.write_u32_be(UInt32(1))  # version
    w.write_u8(UInt8(0))  # dcid_len = 0
    w.write_u8(UInt8(0))  # scid_len = 0
    varint_encode(w, UInt64(233))  # token_len with no token bytes behind it
    var wire = w.finish()

    var caught = False
    try:
        _ = parse_packet_header(Span(wire), 8)
    except:
        caught = True
    assert_true(caught, "expected error for an Initial token past the packet end")
    print("  error_initial_token_too_long: PASS")


def test_retry_token_beyond_inline_capacity() raises:
    # A Retry token longer than the inline copy (233 > MAX_TOKEN_LEN) still
    # parses: it is located by offset, and token_span() is empty.
    var wire = List[Byte]()
    wire.append(UInt8(0xF0))  # long header + fixed bit + Retry type (0x30)
    wire.append(UInt8(0x00))
    wire.append(UInt8(0x00))
    wire.append(UInt8(0x00))
    wire.append(UInt8(0x01))  # version = 1
    wire.append(Byte(0))  # dcid_len = 0
    wire.append(Byte(0))  # scid_len = 0
    for i in range(249):  # 249 - 16 (integrity tag) = 233 token bytes
        wire.append(UInt8(i & 0xFF))

    var h = parse_packet_header(Span(wire), 8)[0].copy()
    assert_equal_int(Int(h.token_len), 233, "whole token length")
    assert_equal_int(Int(h.token_offset), 7, "token starts after the SCID length")
    assert_equal_int(len(h.token_span()), 0, "no inline copy past MAX_TOKEN_LEN")
    assert_equal_int(Int(h.retry_integrity_tag[0]), 233, "tag follows the token")
    print("  retry_token_beyond_inline_capacity: PASS")


def test_error_vn_too_many_versions() raises:
    # Version Negotiation packet listing 17 versions -- exceeds the 16-slot
    # InlineArray capacity backing PacketHeader.supported_versions.
    var wire = List[Byte]()
    wire.append(UInt8(0x80))  # long header form bit; VN's fixed bit is undefined
    wire.append(UInt8(0x00))
    wire.append(UInt8(0x00))
    wire.append(UInt8(0x00))
    wire.append(UInt8(0x00))  # version = 0 (VN)
    wire.append(Byte(0))  # dcid_len = 0
    wire.append(Byte(0))  # scid_len = 0
    for _ in range(17):  # MAX_SUPPORTED_VERSIONS (16) + 1
        wire.append(UInt8(0x00))
        wire.append(UInt8(0x00))
        wire.append(UInt8(0x00))
        wire.append(UInt8(0x01))

    var caught = False
    try:
        _ = parse_packet_header(Span(wire), 8)
    except:
        caught = True
    assert_true(caught, "expected error for VN packet exceeding 16 supported versions")
    print("  error_vn_too_many_versions: PASS")


# === Section 6: Padding utility ===


def test_initial_packet_needs_padding() raises:
    assert_equal_int(initial_packet_needs_padding(1200), 0, "padding(1200)")
    assert_equal_int(initial_packet_needs_padding(500), 700, "padding(500)")
    assert_equal_int(initial_packet_needs_padding(1500), 0, "padding(1500)")
    print("  initial_packet_needs_padding: PASS")


# === Section 7: PN unsigned boundary edge cases ===


def test_pn_decode_unsigned_boundary() raises:
    # When expected_pn (1) < pn_hwin (128), unsigned subtraction would underflow.
    var got1 = pn_decode(UInt64(5), 1, UInt64(0))
    assert_equal_int(Int(got1), 5, "pn_decode(5,1,0) unsigned boundary")

    # Wrap-forward near 1-byte boundary: largest_pn=255 -> expected_pn=256,
    # candidate should wrap forward to 256.
    var got2 = pn_decode(UInt64(0), 1, UInt64(255))
    assert_equal_int(Int(got2), 256, "pn_decode(0,1,255) wrap-forward")

    # expected_pn=1, candidate=0, wrap-down guard when expected < pn_hwin
    var got3 = pn_decode(UInt64(0), 1, UInt64(0))
    assert_equal_int(Int(got3), 0, "pn_decode(0,1,0) boundary")

    # 2-byte boundary: expected_pn=1 < pn_hwin=32768
    var got4 = pn_decode(UInt64(100), 2, UInt64(0))
    assert_equal_int(Int(got4), 100, "pn_decode(100,2,0) 2-byte boundary")

    print("  pn_decode_unsigned_boundary: PASS")


# === Main ===


def main() raises:
    print("test_quic_packet:")

    # 1. QC-1 packet header vectors
    test_packet_header_vectors()

    # 2. PN vectors
    test_pn_vectors()

    # 3. Round-trip tests
    test_roundtrip_initial()
    test_roundtrip_handshake()
    test_roundtrip_short_header()
    test_roundtrip_version_negotiation()
    test_roundtrip_retry()

    # 4. PN edge cases
    test_pn_edge_cases()

    # 5. Error cases
    test_error_dcid_too_long()
    test_error_truncated_long_header()
    test_error_short_header_fixed_bit()
    test_error_initial_token_too_long()
    test_retry_token_beyond_inline_capacity()
    test_error_vn_too_many_versions()

    # 6. Padding utility
    test_initial_packet_needs_padding()

    # 7. PN unsigned boundary edge cases
    test_pn_decode_unsigned_boundary()

    print("All test_quic_packet tests passed.")
