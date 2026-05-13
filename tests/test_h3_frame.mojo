from mojo_net.h3.frame import (
    H3_FRAME_DATA, H3_FRAME_HEADERS, H3_FRAME_SETTINGS, H3_FRAME_GOAWAY,
    SETTINGS_QPACK_MAX_TABLE_CAPACITY, SETTINGS_MAX_FIELD_SECTION_SIZE,
    SETTINGS_QPACK_BLOCKED_STREAMS,
    H3RawFrame, DataFrame, HeadersFrame, SettingsPair, SettingsFrame,
    parse_h3_frame,
)
from mojo_net.quic.codec import ByteReader, ByteWriter, varint_encode
from tests._test_util import assert_true, assert_false, assert_equal_int


def test_data_frame_round_trip() raises:
    var payload = List[UInt8]()
    payload.append(0x68)  # 'h'
    payload.append(0x69)  # 'i'
    var df = DataFrame(payload)
    var encoded = df.encode()
    # wire: type=0x00 (1 byte), length=2 (1 byte), payload=hi
    assert_equal_int(len(encoded), 4, "encoded length")
    assert_equal_int(Int(encoded[0]), 0x00, "DATA frame type")
    assert_equal_int(Int(encoded[1]), 0x02, "length byte")
    assert_equal_int(Int(encoded[2]), 0x68, "payload[0]")
    assert_equal_int(Int(encoded[3]), 0x69, "payload[1]")
    var r = ByteReader(Span(encoded))
    var raw = parse_h3_frame(r)
    assert_equal_int(Int(raw.frame_type), 0x00, "raw frame_type")
    assert_equal_int(len(raw.payload), 2, "raw payload len")
    var decoded = DataFrame.decode(raw.payload)
    assert_equal_int(len(decoded.data), 2, "decoded data len")
    assert_equal_int(Int(decoded.data[0]), 0x68, "decoded data[0]")
    print("  test_data_frame_round_trip: PASS")


def test_headers_frame_round_trip() raises:
    var fields = List[UInt8]()
    fields.append(0x00)
    fields.append(0x00)
    fields.append(0xC2)  # fake QPACK indexed field for :method GET
    var hf = HeadersFrame(fields)
    var encoded = hf.encode()
    assert_equal_int(Int(encoded[0]), 0x01, "HEADERS frame type")
    assert_equal_int(Int(encoded[1]), 0x03, "length=3")
    var r = ByteReader(Span(encoded))
    var raw = parse_h3_frame(r)
    assert_equal_int(Int(raw.frame_type), 0x01, "raw frame_type")
    var decoded = HeadersFrame.decode(raw.payload)
    assert_equal_int(len(decoded.encoded_fields), 3, "decoded fields len")
    assert_equal_int(Int(decoded.encoded_fields[2]), 0xC2, "decoded fields[2]")
    print("  test_headers_frame_round_trip: PASS")


def test_settings_encode_decode() raises:
    var sf = SettingsFrame(List[SettingsPair]())
    sf.pairs.append(SettingsPair(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 4096))
    sf.pairs.append(SettingsPair(SETTINGS_MAX_FIELD_SECTION_SIZE, 65536))
    var encoded = sf.encode()
    assert_equal_int(Int(encoded[0]), 0x04, "SETTINGS frame type")
    var r = ByteReader(Span(encoded))
    var raw = parse_h3_frame(r)
    assert_equal_int(Int(raw.frame_type), 0x04, "raw frame_type")
    var decoded = SettingsFrame.decode(raw.payload)
    assert_equal_int(len(decoded.pairs), 2, "decoded pairs len")
    assert_equal_int(Int(decoded.pairs[0].id), Int(SETTINGS_QPACK_MAX_TABLE_CAPACITY), "pair[0].id")
    assert_equal_int(Int(decoded.pairs[0].value), 4096, "pair[0].value")
    assert_equal_int(Int(decoded.pairs[1].id), Int(SETTINGS_MAX_FIELD_SECTION_SIZE), "pair[1].id")
    assert_equal_int(Int(decoded.pairs[1].value), 65536, "pair[1].value")
    print("  test_settings_encode_decode: PASS")


def test_settings_unknown_id_preserved() raises:
    var sf = SettingsFrame(List[SettingsPair]())
    sf.pairs.append(SettingsPair(UInt64(0xFFFF), UInt64(42)))  # unknown id
    sf.pairs.append(SettingsPair(SETTINGS_QPACK_BLOCKED_STREAMS, UInt64(100)))
    var encoded = sf.encode()
    var r = ByteReader(Span(encoded))
    var raw = parse_h3_frame(r)
    var decoded = SettingsFrame.decode(raw.payload)
    assert_equal_int(len(decoded.pairs), 2, "decoded pairs len")
    assert_equal_int(Int(decoded.pairs[0].id), 0xFFFF, "unknown id preserved")
    assert_equal_int(Int(decoded.pairs[0].value), 42, "unknown value preserved")
    assert_equal_int(Int(decoded.pairs[1].id), Int(SETTINGS_QPACK_BLOCKED_STREAMS), "pair[1].id")
    assert_equal_int(Int(decoded.pairs[1].value), 100, "pair[1].value")
    print("  test_settings_unknown_id_preserved: PASS")


def test_settings_get_returns_value() raises:
    var sf = SettingsFrame(List[SettingsPair]())
    sf.pairs.append(SettingsPair(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 1024))
    var result = sf.get(SETTINGS_QPACK_MAX_TABLE_CAPACITY)
    assert_true(result.__bool__(), "result is some")
    assert_equal_int(Int(result.value()), 1024, "result value")
    print("  test_settings_get_returns_value: PASS")


def test_settings_get_missing() raises:
    var sf = SettingsFrame(List[SettingsPair]())
    var result = sf.get(SETTINGS_QPACK_MAX_TABLE_CAPACITY)
    assert_false(result.__bool__(), "result is none")
    print("  test_settings_get_missing: PASS")


def test_parse_multiple_frames_sequential() raises:
    # Encode two frames back-to-back and parse them sequentially
    var df = DataFrame(List[UInt8]())
    df.data.append(0x41)  # 'A'
    var enc1 = df.encode()

    var sf = SettingsFrame(List[SettingsPair]())
    sf.pairs.append(SettingsPair(SETTINGS_QPACK_BLOCKED_STREAMS, UInt64(0)))
    var enc2 = sf.encode()

    var combined = List[UInt8]()
    for i in range(len(enc1)):
        combined.append(enc1[i])
    for i in range(len(enc2)):
        combined.append(enc2[i])

    var r = ByteReader(Span(combined))
    var f1 = parse_h3_frame(r)
    var f2 = parse_h3_frame(r)
    assert_equal_int(Int(f1.frame_type), 0x00, "f1 frame_type")
    assert_equal_int(Int(f2.frame_type), 0x04, "f2 frame_type")
    print("  test_parse_multiple_frames_sequential: PASS")


def test_parse_truncated_raises() raises:
    # Only type byte, no length
    var data = List[UInt8]()
    data.append(0x00)
    var r = ByteReader(Span(data))
    var raised = False
    try:
        _ = parse_h3_frame(r)
    except:
        raised = True
    assert_true(raised, "truncated raises")
    print("  test_parse_truncated_raises: PASS")


def test_parse_unknown_frame_type_preserved() raises:
    # Write a frame with type 0x21 (not defined in M5a)
    var w = ByteWriter()
    varint_encode(w, UInt64(0x21))
    varint_encode(w, UInt64(2))  # length=2
    w.write_u8(0xAA)
    w.write_u8(0xBB)
    var encoded = w.finish()
    var r = ByteReader(Span(encoded))
    var raw = parse_h3_frame(r)
    assert_equal_int(Int(raw.frame_type), 0x21, "unknown frame type")
    assert_equal_int(len(raw.payload), 2, "unknown frame payload len")
    assert_equal_int(Int(raw.payload[0]), 0xAA, "payload[0]")
    assert_equal_int(Int(raw.payload[1]), 0xBB, "payload[1]")
    print("  test_parse_unknown_frame_type_preserved: PASS")


def test_frame_large_payload() raises:
    # DATA frame with 300 bytes payload (length varint > 1 byte)
    var payload = List[UInt8]()
    for i in range(300):
        payload.append(UInt8(i & 0xFF))
    var df = DataFrame(payload)
    var encoded = df.encode()
    # type=0x00 (1 byte), length=300 needs 2-byte varint (>=64 triggers 2-byte)
    # varint 300 = 0x4000 | 300 = 0x412C => 2 bytes
    assert_equal_int(Int(encoded[0]), 0x00, "type byte")
    assert_equal_int(Int(encoded[1]), 0x41, "varint high byte for 300")
    assert_equal_int(Int(encoded[2]), 0x2C, "varint low byte for 300")
    var r = ByteReader(Span(encoded))
    var raw = parse_h3_frame(r)
    assert_equal_int(Int(raw.frame_type), 0x00, "frame_type")
    assert_equal_int(len(raw.payload), 300, "payload len")
    for i in range(300):
        assert_equal_int(Int(raw.payload[i]), i & 0xFF, "payload byte")
    print("  test_frame_large_payload: PASS")


def main() raises:
    print("=== test_h3_frame ===")
    test_data_frame_round_trip()
    test_headers_frame_round_trip()
    test_settings_encode_decode()
    test_settings_unknown_id_preserved()
    test_settings_get_returns_value()
    test_settings_get_missing()
    test_parse_multiple_frames_sequential()
    test_parse_truncated_raises()
    test_parse_unknown_frame_type_preserved()
    test_frame_large_payload()
    print("All tests passed.")
