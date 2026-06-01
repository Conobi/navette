from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode
from navette.quic.frame import (
    Frame,
    AckFrame,
    AckRange,
    CryptoFrame,
    StreamFrame,
    ResetStreamFrame,
    StopSendingFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    StreamDataBlockedFrame,
    StreamsBlockedFrame,
    NewConnectionIdFrame,
    ConnectionCloseFrame,
    parse_frame,
    serialize_frame,
    frame_allowed_in_packet_type,
    FRAME_PADDING,
    FRAME_PING,
    FRAME_ACK,
    FRAME_ACK_ECN,
    FRAME_RESET_STREAM,
    FRAME_STOP_SENDING,
    FRAME_CRYPTO,
    FRAME_NEW_TOKEN,
    FRAME_STREAM_BASE,
    FRAME_MAX_DATA,
    FRAME_MAX_STREAM_DATA,
    FRAME_MAX_STREAMS_BIDI,
    FRAME_MAX_STREAMS_UNI,
    FRAME_DATA_BLOCKED,
    FRAME_STREAM_DATA_BLOCKED,
    FRAME_STREAMS_BLOCKED_BIDI,
    FRAME_STREAMS_BLOCKED_UNI,
    FRAME_NEW_CONNECTION_ID,
    FRAME_RETIRE_CONNECTION_ID,
    FRAME_PATH_CHALLENGE,
    FRAME_PATH_RESPONSE,
    FRAME_CONNECTION_CLOSE_TRANSPORT,
    FRAME_CONNECTION_CLOSE_APP,
    FRAME_HANDSHAKE_DONE,
    FRAME_DATAGRAM,
    FRAME_DATAGRAM_LEN,
)


# ── Helpers ──────────────────────────────────────────────────────────────


def _serialize_and_parse_back(frame: Frame) raises -> Frame:
    """Serialize a Frame, then parse it back from the serialized bytes."""
    var w = ByteWriter()
    serialize_frame(frame, w)
    var buf = w.finish()
    var r = ByteReader(Span(buf))
    return parse_frame(r)


def _assert_eq(got: UInt64, expected: UInt64, msg: String) raises:
    if got != expected:
        raise msg + ": got " + String(Int(got)) + " expected " + String(Int(expected))


def _assert_eq_int(got: Int, expected: Int, msg: String) raises:
    if got != expected:
        raise msg + ": got " + String(got) + " expected " + String(expected)


def _assert_true(cond: Bool, msg: String) raises:
    if not cond:
        raise msg


def _assert_false(cond: Bool, msg: String) raises:
    if cond:
        raise msg


def _assert_bytes_eq(got: List[UInt8], expected: List[UInt8], msg: String) raises:
    if len(got) != len(expected):
        raise msg + ": length mismatch, got " + String(len(got)) + " expected " + String(len(expected))
    for i in range(len(got)):
        if got[i] != expected[i]:
            raise msg + ": byte " + String(i) + " differs, got " + String(Int(got[i])) + " expected " + String(Int(expected[i]))


def _hex_byte_value(b: UInt8) raises -> Int:
    """Convert a hex byte (0-9, a-f, A-F) to its value."""
    if b >= UInt8(ord("0")) and b <= UInt8(ord("9")):
        return Int(b) - ord("0")
    if b >= UInt8(ord("a")) and b <= UInt8(ord("f")):
        return Int(b) - ord("a") + 10
    if b >= UInt8(ord("A")) and b <= UInt8(ord("F")):
        return Int(b) - ord("A") + 10
    raise "invalid hex byte"


def _hex_decode(hex_str: String) raises -> List[UInt8]:
    """Decode a hex string to bytes."""
    var result = List[UInt8]()
    if len(hex_str) % 2 != 0:
        raise "hex string has odd length"
    var bs = hex_str.as_bytes()
    var i = 0
    while i < len(bs):
        var hi = _hex_byte_value(bs[i])
        var lo = _hex_byte_value(bs[i + 1])
        result.append(UInt8(hi * 16 + lo))
        i += 2
    return result^


def _bytes_to_hex(data: List[UInt8]) -> String:
    """Convert bytes to lowercase hex string."""
    var chars = String("0123456789abcdef")
    var result = String()
    for i in range(len(data)):
        var b = Int(data[i])
        var idx1 = (b >> 4) & 0xF
        var idx2 = b & 0xF
        # Build single-char strings from bytes
        var j = 0
        for cp in chars.codepoint_slices():
            if j == idx1:
                result += cp
                break
            j += 1
        j = 0
        for cp in chars.codepoint_slices():
            if j == idx2:
                result += cp
                break
            j += 1
    return result^


def _string_to_bytes(s: String) -> List[UInt8]:
    """Convert a string to a list of bytes (ASCII only)."""
    var result = List[UInt8]()
    var bs = s.as_bytes()
    for i in range(len(bs)):
        result.append(bs[i])
    return result^


# ── 1. Round-trip tests ──────────────────────────────────────────────────


def test_roundtrip_padding() raises:
    var frame = Frame.padding()
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_padding(), "should be PADDING")
    _assert_eq(rt.type_id, FRAME_PADDING, "type_id")
    print("  roundtrip_padding: PASS")


def test_roundtrip_ping() raises:
    var frame = Frame.ping()
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_ping(), "should be PING")
    _assert_eq(rt.type_id, FRAME_PING, "type_id")
    print("  roundtrip_ping: PASS")


def test_roundtrip_handshake_done() raises:
    var frame = Frame.handshake_done()
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_handshake_done(), "should be HANDSHAKE_DONE")
    _assert_eq(rt.type_id, FRAME_HANDSHAKE_DONE, "type_id")
    print("  roundtrip_handshake_done: PASS")


def test_roundtrip_ack_with_ranges() raises:
    var ack = AckFrame()
    ack.largest_ack = UInt64(100)
    ack.ack_delay = UInt64(25)
    ack.first_ack_range = UInt64(10)
    ack.ranges.append(AckRange(UInt64(5), UInt64(3)))
    ack.ranges.append(AckRange(UInt64(2), UInt64(1)))
    var frame = Frame.ack(ack)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_ack(), "should be ACK")
    _assert_eq(rt.type_id, FRAME_ACK, "type_id should be ACK (no ECN)")
    ref ra = rt.as_ack()
    _assert_eq(ra.largest_ack, UInt64(100), "largest_ack")
    _assert_eq(ra.ack_delay, UInt64(25), "ack_delay")
    _assert_eq(ra.first_ack_range, UInt64(10), "first_ack_range")
    _assert_eq_int(len(ra.ranges), 2, "range count")
    _assert_eq(ra.ranges[0].gap, UInt64(5), "range[0].gap")
    _assert_eq(ra.ranges[0].ack_range, UInt64(3), "range[0].ack_range")
    _assert_eq(ra.ranges[1].gap, UInt64(2), "range[1].gap")
    _assert_eq(ra.ranges[1].ack_range, UInt64(1), "range[1].ack_range")
    _assert_false(ra.has_ecn, "should not have ECN")
    print("  roundtrip_ack_with_ranges: PASS")


def test_roundtrip_ack_ecn() raises:
    var ack = AckFrame()
    ack.largest_ack = UInt64(100)
    ack.ack_delay = UInt64(25)
    ack.first_ack_range = UInt64(10)
    ack.ranges.append(AckRange(UInt64(5), UInt64(3)))
    ack.ranges.append(AckRange(UInt64(2), UInt64(1)))
    ack.has_ecn = True
    ack.ecn_ect0 = UInt64(50)
    ack.ecn_ect1 = UInt64(20)
    ack.ecn_ce = UInt64(5)
    var frame = Frame.ack(ack)
    var rt = _serialize_and_parse_back(frame)
    _assert_eq(rt.type_id, FRAME_ACK_ECN, "type_id should be ACK_ECN")
    ref ra = rt.as_ack()
    _assert_eq(ra.largest_ack, UInt64(100), "largest_ack")
    _assert_eq(ra.ack_delay, UInt64(25), "ack_delay")
    _assert_eq(ra.first_ack_range, UInt64(10), "first_ack_range")
    _assert_eq_int(len(ra.ranges), 2, "range count")
    _assert_true(ra.has_ecn, "should have ECN")
    _assert_eq(ra.ecn_ect0, UInt64(50), "ecn_ect0")
    _assert_eq(ra.ecn_ect1, UInt64(20), "ecn_ect1")
    _assert_eq(ra.ecn_ce, UInt64(5), "ecn_ce")
    print("  roundtrip_ack_ecn: PASS")


def test_roundtrip_crypto() raises:
    var data = List[UInt8]()
    data.append(UInt8(0x01))
    data.append(UInt8(0x02))
    data.append(UInt8(0x03))
    var cf = CryptoFrame(UInt64(0), data)
    var frame = Frame.crypto(cf)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_crypto(), "should be CRYPTO")
    ref rc = rt.as_crypto()
    _assert_eq(rc.offset, UInt64(0), "offset")
    _assert_eq_int(len(rc.data), 3, "data length")
    _assert_bytes_eq(rc.data, data, "crypto data")
    print("  roundtrip_crypto: PASS")


def test_roundtrip_stream_base() raises:
    """STREAM with offset=0, no FIN -- serializer emits LEN bit."""
    var data = List[UInt8]()
    for i in range(5):
        data.append(UInt8(0x48 + i))  # H, I, J, K, L
    var sf = StreamFrame(UInt64(4), UInt64(0), data, False)
    var frame = Frame.stream(sf)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_stream(), "should be STREAM")
    ref rs = rt.as_stream()
    _assert_eq(rs.stream_id, UInt64(4), "stream_id")
    _assert_eq(rs.offset, UInt64(0), "offset")
    _assert_false(rs.fin, "fin should be false")
    _assert_eq_int(len(rs.data), 5, "data length")
    _assert_bytes_eq(rs.data, data, "stream data")
    print("  roundtrip_stream_base: PASS")


def test_roundtrip_stream_off_len() raises:
    """STREAM with OFF+LEN flags."""
    var data = List[UInt8]()
    for i in range(5):
        data.append(UInt8(0x48 + i))
    var sf = StreamFrame(UInt64(4), UInt64(300), data, False)
    var frame = Frame.stream(sf)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_stream(), "should be STREAM")
    ref rs = rt.as_stream()
    _assert_eq(rs.stream_id, UInt64(4), "stream_id")
    _assert_eq(rs.offset, UInt64(300), "offset")
    _assert_false(rs.fin, "fin should be false")
    _assert_bytes_eq(rs.data, data, "stream data")
    print("  roundtrip_stream_off_len: PASS")


def test_roundtrip_stream_off_len_fin() raises:
    """STREAM with OFF+LEN+FIN flags."""
    var data = List[UInt8]()
    for i in range(5):
        data.append(UInt8(0x48 + i))
    var sf = StreamFrame(UInt64(4), UInt64(400), data, True)
    var frame = Frame.stream(sf)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_stream(), "should be STREAM")
    ref rs = rt.as_stream()
    _assert_eq(rs.stream_id, UInt64(4), "stream_id")
    _assert_eq(rs.offset, UInt64(400), "offset")
    _assert_true(rs.fin, "fin should be true")
    _assert_bytes_eq(rs.data, data, "stream data")
    print("  roundtrip_stream_off_len_fin: PASS")


def test_roundtrip_stream_empty_fin() raises:
    """STREAM with empty data + FIN (legal edge case)."""
    var data = List[UInt8]()
    var sf = StreamFrame(UInt64(4), UInt64(500), data, True)
    var frame = Frame.stream(sf)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_stream(), "should be STREAM")
    ref rs = rt.as_stream()
    _assert_eq(rs.stream_id, UInt64(4), "stream_id")
    _assert_eq(rs.offset, UInt64(500), "offset")
    _assert_true(rs.fin, "fin should be true")
    _assert_eq_int(len(rs.data), 0, "data should be empty")
    print("  roundtrip_stream_empty_fin: PASS")


def test_roundtrip_reset_stream() raises:
    var rsf = ResetStreamFrame(UInt64(4), UInt64(0x42), UInt64(1000))
    var frame = Frame.reset_stream(rsf)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_reset_stream(), "should be RESET_STREAM")
    ref rr = rt.as_reset_stream()
    _assert_eq(rr.stream_id, UInt64(4), "stream_id")
    _assert_eq(rr.error_code, UInt64(0x42), "error_code")
    _assert_eq(rr.final_size, UInt64(1000), "final_size")
    print("  roundtrip_reset_stream: PASS")


def test_roundtrip_stop_sending() raises:
    var ssf = StopSendingFrame(UInt64(4), UInt64(0x42))
    var frame = Frame.stop_sending(ssf)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_stop_sending(), "should be STOP_SENDING")
    ref rs = rt.as_stop_sending()
    _assert_eq(rs.stream_id, UInt64(4), "stream_id")
    _assert_eq(rs.error_code, UInt64(0x42), "error_code")
    print("  roundtrip_stop_sending: PASS")


def test_roundtrip_max_data() raises:
    var frame = Frame.max_data(UInt64(1048576))
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_max_data(), "should be MAX_DATA")
    _assert_eq(rt.as_max_data(), UInt64(1048576), "maximum")
    print("  roundtrip_max_data: PASS")


def test_roundtrip_max_stream_data() raises:
    var msd = MaxStreamDataFrame(UInt64(4), UInt64(524288))
    var frame = Frame.max_stream_data(msd)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_max_stream_data(), "should be MAX_STREAM_DATA")
    ref rm = rt.as_max_stream_data()
    _assert_eq(rm.stream_id, UInt64(4), "stream_id")
    _assert_eq(rm.maximum, UInt64(524288), "maximum")
    print("  roundtrip_max_stream_data: PASS")


def test_roundtrip_max_streams_bidi() raises:
    var ms = MaxStreamsFrame(UInt64(100), True)
    var frame = Frame.max_streams(ms)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_max_streams(), "should be MAX_STREAMS")
    _assert_eq(rt.type_id, FRAME_MAX_STREAMS_BIDI, "type_id should be bidi")
    ref rm = rt.as_max_streams()
    _assert_eq(rm.maximum, UInt64(100), "maximum")
    _assert_true(rm.bidi, "should be bidi")
    print("  roundtrip_max_streams_bidi: PASS")


def test_roundtrip_max_streams_uni() raises:
    var ms = MaxStreamsFrame(UInt64(50), False)
    var frame = Frame.max_streams(ms)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_max_streams(), "should be MAX_STREAMS")
    _assert_eq(rt.type_id, FRAME_MAX_STREAMS_UNI, "type_id should be uni")
    ref rm = rt.as_max_streams()
    _assert_eq(rm.maximum, UInt64(50), "maximum")
    _assert_false(rm.bidi, "should be uni")
    print("  roundtrip_max_streams_uni: PASS")


def test_roundtrip_new_connection_id() raises:
    var ncid = NewConnectionIdFrame()
    ncid.sequence = UInt64(5)
    ncid.retire_prior_to = UInt64(3)
    # 8-byte CID
    for i in range(8):
        ncid.cid.append(UInt8(i + 1))
    # 16-byte stateless reset token
    for i in range(16):
        ncid.stateless_reset_token.append(UInt8(i + 0x10))
    var frame = Frame.new_connection_id(ncid)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_new_connection_id(), "should be NEW_CONNECTION_ID")
    ref rn = rt.as_new_connection_id()
    _assert_eq(rn.sequence, UInt64(5), "sequence")
    _assert_eq(rn.retire_prior_to, UInt64(3), "retire_prior_to")
    _assert_eq_int(len(rn.cid), 8, "cid length")
    _assert_bytes_eq(rn.cid, ncid.cid, "cid")
    _assert_eq_int(len(rn.stateless_reset_token), 16, "token length")
    _assert_bytes_eq(rn.stateless_reset_token, ncid.stateless_reset_token, "reset token")
    print("  roundtrip_new_connection_id: PASS")


def test_roundtrip_retire_connection_id() raises:
    var frame = Frame.retire_connection_id(UInt64(2))
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_retire_connection_id(), "should be RETIRE_CONNECTION_ID")
    _assert_eq(rt.as_retire_connection_id(), UInt64(2), "sequence")
    print("  roundtrip_retire_connection_id: PASS")


def test_roundtrip_connection_close_transport() raises:
    var cc = ConnectionCloseFrame()
    cc.is_transport = True
    cc.error_code = UInt64(0x0A)
    cc.frame_type = UInt64(0x06)
    # reason = "test"
    var reason_bytes = _string_to_bytes("test")
    for i in range(len(reason_bytes)):
        cc.reason.append(reason_bytes[i])
    var frame = Frame.connection_close(cc)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_connection_close(), "should be CONNECTION_CLOSE")
    _assert_eq(rt.type_id, FRAME_CONNECTION_CLOSE_TRANSPORT, "type_id transport")
    ref rc = rt.as_connection_close()
    _assert_true(rc.is_transport, "should be transport")
    _assert_eq(rc.error_code, UInt64(0x0A), "error_code")
    _assert_eq(rc.frame_type, UInt64(0x06), "frame_type")
    _assert_bytes_eq(rc.reason, cc.reason, "reason")
    print("  roundtrip_connection_close_transport: PASS")


def test_roundtrip_connection_close_app() raises:
    var cc = ConnectionCloseFrame()
    cc.is_transport = False
    cc.error_code = UInt64(0x42)
    # reason = "app error"
    var reason_bytes = _string_to_bytes("app error")
    for i in range(len(reason_bytes)):
        cc.reason.append(reason_bytes[i])
    var frame = Frame.connection_close(cc)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_connection_close(), "should be CONNECTION_CLOSE")
    _assert_eq(rt.type_id, FRAME_CONNECTION_CLOSE_APP, "type_id app")
    ref rc = rt.as_connection_close()
    _assert_false(rc.is_transport, "should be app")
    _assert_eq(rc.error_code, UInt64(0x42), "error_code")
    _assert_bytes_eq(rc.reason, cc.reason, "reason")
    print("  roundtrip_connection_close_app: PASS")


def test_roundtrip_new_token() raises:
    var token = List[UInt8]()
    for _ in range(16):
        token.append(UInt8(0))
    var frame = Frame.new_token(token)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_new_token(), "should be NEW_TOKEN")
    ref rt_token = rt.as_new_token()
    _assert_eq_int(len(rt_token), 16, "token length")
    _assert_bytes_eq(rt_token, token, "token data")
    print("  roundtrip_new_token: PASS")


def test_roundtrip_path_challenge() raises:
    var data = List[UInt8]()
    for i in range(8):
        data.append(UInt8(i + 1))
    var frame = Frame.path_challenge(data)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_path_challenge(), "should be PATH_CHALLENGE")
    ref rd = rt.as_path_data()
    _assert_eq_int(len(rd), 8, "data length")
    _assert_bytes_eq(rd, data, "path challenge data")
    print("  roundtrip_path_challenge: PASS")


def test_roundtrip_path_response() raises:
    var data = List[UInt8]()
    for i in range(8):
        data.append(UInt8(i + 1))
    var frame = Frame.path_response(data)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_path_response(), "should be PATH_RESPONSE")
    ref rd = rt.as_path_data()
    _assert_eq_int(len(rd), 8, "data length")
    _assert_bytes_eq(rd, data, "path response data")
    print("  roundtrip_path_response: PASS")


def test_roundtrip_data_blocked() raises:
    var frame = Frame.data_blocked(UInt64(1048576))
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_data_blocked(), "should be DATA_BLOCKED")
    _assert_eq(rt.as_max_data(), UInt64(1048576), "maximum")
    print("  roundtrip_data_blocked: PASS")


def test_roundtrip_stream_data_blocked() raises:
    var sdb = StreamDataBlockedFrame(UInt64(4), UInt64(524288))
    var frame = Frame.stream_data_blocked(sdb)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_stream_data_blocked(), "should be STREAM_DATA_BLOCKED")
    ref rm = rt.as_max_stream_data()
    _assert_eq(rm.stream_id, UInt64(4), "stream_id")
    _assert_eq(rm.maximum, UInt64(524288), "maximum")
    print("  roundtrip_stream_data_blocked: PASS")


def test_roundtrip_streams_blocked_bidi() raises:
    var sb = StreamsBlockedFrame(UInt64(100), True)
    var frame = Frame.streams_blocked(sb)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_streams_blocked(), "should be STREAMS_BLOCKED")
    _assert_eq(rt.type_id, FRAME_STREAMS_BLOCKED_BIDI, "type_id bidi")
    ref rm = rt.as_max_streams()
    _assert_eq(rm.maximum, UInt64(100), "maximum")
    _assert_true(rm.bidi, "should be bidi")
    print("  roundtrip_streams_blocked_bidi: PASS")


def test_roundtrip_streams_blocked_uni() raises:
    var sb = StreamsBlockedFrame(UInt64(50), False)
    var frame = Frame.streams_blocked(sb)
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_streams_blocked(), "should be STREAMS_BLOCKED")
    _assert_eq(rt.type_id, FRAME_STREAMS_BLOCKED_UNI, "type_id uni")
    ref rm = rt.as_max_streams()
    _assert_eq(rm.maximum, UInt64(50), "maximum")
    _assert_false(rm.bidi, "should be uni")
    print("  roundtrip_streams_blocked_uni: PASS")


def test_roundtrip_datagram_with_len() raises:
    """RFC 9221 §4 — DATAGRAM_LEN (0x31) round-trip with a 7-byte payload."""
    var payload = List[UInt8]()
    for i in range(7):
        payload.append(UInt8(i + 1))
    var frame = Frame.datagram_with_len(payload)
    _assert_true(frame.is_datagram(), "factory: should be DATAGRAM")
    _assert_eq(frame.type_id, FRAME_DATAGRAM_LEN, "factory: type_id DATAGRAM_LEN")
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_datagram(), "rt: should be DATAGRAM")
    _assert_eq(rt.type_id, FRAME_DATAGRAM_LEN, "rt: type_id DATAGRAM_LEN")
    _assert_false(rt.is_unknown(), "DATAGRAM_LEN must not be classified unknown")
    ref data = rt.as_datagram_payload()
    _assert_eq_int(len(data), 7, "payload length")
    _assert_bytes_eq(data, payload, "payload bytes")
    print("  roundtrip_datagram_with_len: PASS")


def test_roundtrip_datagram_no_length() raises:
    """RFC 9221 §4 — DATAGRAM (0x30) round-trip; payload extends to end of packet."""
    var payload = List[UInt8]()
    for i in range(11):
        payload.append(UInt8(0xA0 + i))
    var frame = Frame.datagram(payload)
    _assert_true(frame.is_datagram(), "factory: should be DATAGRAM")
    _assert_eq(frame.type_id, FRAME_DATAGRAM, "factory: type_id DATAGRAM")
    var rt = _serialize_and_parse_back(frame)
    _assert_true(rt.is_datagram(), "rt: should be DATAGRAM")
    _assert_eq(rt.type_id, FRAME_DATAGRAM, "rt: type_id DATAGRAM")
    _assert_false(rt.is_unknown(), "DATAGRAM must not be classified unknown")
    ref data = rt.as_datagram_payload()
    _assert_eq_int(len(data), 11, "payload length")
    _assert_bytes_eq(data, payload, "payload bytes")
    print("  roundtrip_datagram_no_length: PASS")


def test_datagram_packet_type_permissions() raises:
    """RFC 9221 §5 — DATAGRAM/DATAGRAM_LEN are 1-RTT only.

    Per the dispatch contract in `frame_allowed_in_packet_type`, the
    extension frames must be permitted in 1-RTT (packet type 4) and
    refused in Initial (0), 0-RTT (1), and Handshake (2).
    """
    _assert_true(
        frame_allowed_in_packet_type(FRAME_DATAGRAM, UInt8(4)),
        "DATAGRAM allowed in 1-RTT",
    )
    _assert_true(
        frame_allowed_in_packet_type(FRAME_DATAGRAM_LEN, UInt8(4)),
        "DATAGRAM_LEN allowed in 1-RTT",
    )
    _assert_false(
        frame_allowed_in_packet_type(FRAME_DATAGRAM, UInt8(0)),
        "DATAGRAM forbidden in Initial",
    )
    _assert_false(
        frame_allowed_in_packet_type(FRAME_DATAGRAM, UInt8(1)),
        "DATAGRAM forbidden in 0-RTT",
    )
    _assert_false(
        frame_allowed_in_packet_type(FRAME_DATAGRAM, UInt8(2)),
        "DATAGRAM forbidden in Handshake",
    )
    _assert_false(
        frame_allowed_in_packet_type(FRAME_DATAGRAM_LEN, UInt8(2)),
        "DATAGRAM_LEN forbidden in Handshake",
    )
    print("  datagram_packet_type_permissions: PASS")


# ── 2. Vector tests ─────────────────────────────────────────────────────


def test_vectors() raises:
    from std.python import Python

    var json_mod = Python.import_module("json")
    var builtins = Python.import_module("builtins")
    var f = builtins.open("conformance/vectors/rfc9000/frame.json", "r")
    var vectors = json_mod.load(f)
    f.close()

    var total = Int(py=builtins.len(vectors))
    var pass_count = 0

    for i in range(total):
        var vec = vectors[i]
        var vec_id = String(vec["id"])
        var wire_hex = String(vec["wire_hex"])
        var wire_bytes = _hex_decode(wire_hex)

        # Check if this is an error vector or an unknown-sentinel vector.
        # Pre-F10 (RFC 9000 §12.4) the parser raised on unknown types; the
        # F10 cycle replaced that with the `Frame.unknown` sentinel so the
        # dispatch site can close with FRAME_ENCODING_ERROR. Vectors keep
        # the explicit distinction via `expect: "unknown_sentinel"`.
        var expect_error = False
        var expect_unknown = False
        try:
            var expect_val = vec["expect"]
            if String(expect_val) == "error":
                expect_error = True
            elif String(expect_val) == "unknown_sentinel":
                expect_unknown = True
        except:
            pass

        if expect_error:
            # Should raise on parse
            var caught = False
            try:
                var r = ByteReader(Span(wire_bytes))
                _ = parse_frame(r)
            except:
                caught = True
            if not caught:
                raise "vector " + vec_id + ": expected parse error but succeeded"
            pass_count += 1
            continue

        if expect_unknown:
            var r = ByteReader(Span(wire_bytes))
            var frame = parse_frame(r)
            if not frame.is_unknown():
                raise "vector " + vec_id + ": expected Frame.unknown sentinel"
            pass_count += 1
            continue

        # Parse should succeed
        var r = ByteReader(Span(wire_bytes))
        var frame = parse_frame(r)
        var expected = vec["expected"]

        # Check frame_type_value if present
        try:
            var ftv = Int(py=expected["frame_type_value"])
            _assert_eq(frame.type_id, UInt64(ftv), "vector " + vec_id + " frame_type_value")
        except:
            pass

        # Check ACK fields
        if frame.is_ack():
            ref ack = frame.as_ack()
            try:
                var la = Int(py=expected["largest_ack"])
                _assert_eq(ack.largest_ack, UInt64(la), "vector " + vec_id + " largest_ack")
            except:
                pass
            try:
                var ad = Int(py=expected["ack_delay"])
                _assert_eq(ack.ack_delay, UInt64(ad), "vector " + vec_id + " ack_delay")
            except:
                pass
            try:
                var far = Int(py=expected["first_ack_range"])
                _assert_eq(ack.first_ack_range, UInt64(far), "vector " + vec_id + " first_ack_range")
            except:
                pass
            try:
                var arc = Int(py=expected["ack_range_count"])
                _assert_eq_int(len(ack.ranges), arc, "vector " + vec_id + " ack_range_count")
            except:
                pass
            try:
                var ranges_arr = expected["ack_ranges"]
                var range_count = Int(py=builtins.len(ranges_arr))
                for j in range(range_count):
                    var rng = ranges_arr[j]
                    var exp_gap = Int(py=rng["gap"])
                    var exp_ar = Int(py=rng["ack_range"])
                    _assert_eq(ack.ranges[j].gap, UInt64(exp_gap), "vector " + vec_id + " range[" + String(j) + "].gap")
                    _assert_eq(ack.ranges[j].ack_range, UInt64(exp_ar), "vector " + vec_id + " range[" + String(j) + "].ack_range")
            except:
                pass
            # ECN fields
            if ack.has_ecn:
                try:
                    var ect0 = Int(py=expected["ect0_count"])
                    _assert_eq(ack.ecn_ect0, UInt64(ect0), "vector " + vec_id + " ect0_count")
                except:
                    pass
                try:
                    var ect1 = Int(py=expected["ect1_count"])
                    _assert_eq(ack.ecn_ect1, UInt64(ect1), "vector " + vec_id + " ect1_count")
                except:
                    pass
                try:
                    var ecn_ce = Int(py=expected["ecn_ce_count"])
                    _assert_eq(ack.ecn_ce, UInt64(ecn_ce), "vector " + vec_id + " ecn_ce_count")
                except:
                    pass

        # Check CRYPTO fields
        if frame.is_crypto():
            ref cf = frame.as_crypto()
            try:
                var off = Int(py=expected["offset"])
                _assert_eq(cf.offset, UInt64(off), "vector " + vec_id + " offset")
            except:
                pass
            try:
                var data_len = Int(py=expected["length"])
                _assert_eq_int(len(cf.data), data_len, "vector " + vec_id + " length")
            except:
                pass
            try:
                var data_hex = String(expected["data_hex"])
                var actual_hex = _bytes_to_hex(cf.data)
                if actual_hex != data_hex:
                    raise "vector " + vec_id + " data_hex: got " + actual_hex + " expected " + data_hex
            except e:
                if "vector" in String(e):
                    raise e^

        # Check STREAM fields
        if frame.is_stream():
            ref sf = frame.as_stream()
            try:
                var sid = Int(py=expected["stream_id"])
                _assert_eq(sf.stream_id, UInt64(sid), "vector " + vec_id + " stream_id")
            except:
                pass
            try:
                var off = Int(py=expected["offset"])
                _assert_eq(sf.offset, UInt64(off), "vector " + vec_id + " offset")
            except:
                pass
            try:
                var data_len = Int(py=expected["length"])
                _assert_eq_int(len(sf.data), data_len, "vector " + vec_id + " length")
            except:
                pass
            try:
                var fin_val = Bool(sf.fin)
                var expected_fin = Bool(expected["fin"])
                if fin_val != expected_fin:
                    raise "vector " + vec_id + " fin mismatch"
            except e:
                if "vector" in String(e):
                    raise e^
            try:
                var data_hex = String(expected["data_hex"])
                var actual_hex = _bytes_to_hex(sf.data)
                if actual_hex != data_hex:
                    raise "vector " + vec_id + " data_hex: got " + actual_hex + " expected " + data_hex
            except e:
                if "vector" in String(e):
                    raise e^

        # Check RESET_STREAM fields
        if frame.is_reset_stream():
            ref rs = frame.as_reset_stream()
            try:
                var sid = Int(py=expected["stream_id"])
                _assert_eq(rs.stream_id, UInt64(sid), "vector " + vec_id + " stream_id")
            except:
                pass
            try:
                var ec = Int(py=expected["error_code"])
                _assert_eq(rs.error_code, UInt64(ec), "vector " + vec_id + " error_code")
            except:
                pass
            try:
                var fs = Int(py=expected["final_size"])
                _assert_eq(rs.final_size, UInt64(fs), "vector " + vec_id + " final_size")
            except:
                pass

        # Check STOP_SENDING fields
        if frame.is_stop_sending():
            ref ss = frame.as_stop_sending()
            try:
                var sid = Int(py=expected["stream_id"])
                _assert_eq(ss.stream_id, UInt64(sid), "vector " + vec_id + " stream_id")
            except:
                pass
            try:
                var ec = Int(py=expected["error_code"])
                _assert_eq(ss.error_code, UInt64(ec), "vector " + vec_id + " error_code")
            except:
                pass

        # Check MAX_DATA / DATA_BLOCKED fields
        if frame.is_max_data() or frame.is_data_blocked():
            try:
                var maximum = Int(py=expected["maximum"])
                _assert_eq(frame.as_max_data(), UInt64(maximum), "vector " + vec_id + " maximum")
            except:
                pass

        # Check MAX_STREAM_DATA / STREAM_DATA_BLOCKED fields
        if frame.is_max_stream_data() or frame.is_stream_data_blocked():
            ref msd = frame.as_max_stream_data()
            try:
                var sid = Int(py=expected["stream_id"])
                _assert_eq(msd.stream_id, UInt64(sid), "vector " + vec_id + " stream_id")
            except:
                pass
            try:
                var maximum = Int(py=expected["maximum"])
                _assert_eq(msd.maximum, UInt64(maximum), "vector " + vec_id + " maximum")
            except:
                pass

        # Check MAX_STREAMS / STREAMS_BLOCKED fields
        if frame.is_max_streams() or frame.is_streams_blocked():
            ref ms = frame.as_max_streams()
            try:
                var maximum = Int(py=expected["maximum"])
                _assert_eq(ms.maximum, UInt64(maximum), "vector " + vec_id + " maximum")
            except:
                pass

        # Check NEW_CONNECTION_ID fields
        if frame.is_new_connection_id():
            ref ncid = frame.as_new_connection_id()
            try:
                var seq = Int(py=expected["sequence_number"])
                _assert_eq(ncid.sequence, UInt64(seq), "vector " + vec_id + " sequence_number")
            except:
                pass
            try:
                var rpt = Int(py=expected["retire_prior_to"])
                _assert_eq(ncid.retire_prior_to, UInt64(rpt), "vector " + vec_id + " retire_prior_to")
            except:
                pass
            try:
                var cid_len = Int(py=expected["connection_id_length"])
                _assert_eq_int(len(ncid.cid), cid_len, "vector " + vec_id + " connection_id_length")
            except:
                pass
            try:
                var cid_hex = String(expected["connection_id_hex"])
                var actual_cid_hex = _bytes_to_hex(ncid.cid)
                if actual_cid_hex != cid_hex:
                    raise "vector " + vec_id + " connection_id_hex: got " + actual_cid_hex + " expected " + cid_hex
            except e:
                if "vector" in String(e):
                    raise e^
            try:
                var token_hex = String(expected["stateless_reset_token_hex"])
                var actual_token_hex = _bytes_to_hex(ncid.stateless_reset_token)
                if actual_token_hex != token_hex:
                    raise "vector " + vec_id + " stateless_reset_token_hex: got " + actual_token_hex + " expected " + token_hex
            except e:
                if "vector" in String(e):
                    raise e^

        # Check RETIRE_CONNECTION_ID fields
        if frame.is_retire_connection_id():
            try:
                var seq = Int(py=expected["sequence_number"])
                _assert_eq(frame.as_retire_connection_id(), UInt64(seq), "vector " + vec_id + " sequence_number")
            except:
                pass

        # Check CONNECTION_CLOSE fields
        if frame.is_connection_close():
            ref cc = frame.as_connection_close()
            try:
                var ec = Int(py=expected["error_code"])
                _assert_eq(cc.error_code, UInt64(ec), "vector " + vec_id + " error_code")
            except:
                pass
            try:
                var ct = String(expected["close_type"])
                if ct == "transport":
                    _assert_true(cc.is_transport, "vector " + vec_id + " should be transport")
                else:
                    _assert_false(cc.is_transport, "vector " + vec_id + " should be app")
            except e:
                if "vector" in String(e):
                    raise e^
            if cc.is_transport:
                try:
                    var ft = Int(py=expected["frame_type"])
                    _assert_eq(cc.frame_type, UInt64(ft), "vector " + vec_id + " frame_type")
                except:
                    pass
            try:
                var rpl = Int(py=expected["reason_phrase_length"])
                _assert_eq_int(len(cc.reason), rpl, "vector " + vec_id + " reason_phrase_length")
            except:
                pass
            try:
                var rp = String(expected["reason_phrase"])
                var actual_reason = String()
                for j in range(len(cc.reason)):
                    actual_reason += chr(Int(cc.reason[j]))
                if actual_reason != rp:
                    raise "vector " + vec_id + " reason_phrase: got '" + actual_reason + "' expected '" + rp + "'"
            except e:
                if "vector" in String(e):
                    raise e^

        # Check NEW_TOKEN fields
        if frame.is_new_token():
            ref token = frame.as_new_token()
            try:
                var tl = Int(py=expected["token_length"])
                _assert_eq_int(len(token), tl, "vector " + vec_id + " token_length")
            except:
                pass
            try:
                var th = String(expected["token_hex"])
                var actual_th = _bytes_to_hex(token)
                if actual_th != th:
                    raise "vector " + vec_id + " token_hex: got " + actual_th + " expected " + th
            except e:
                if "vector" in String(e):
                    raise e^

        # Check PATH_CHALLENGE / PATH_RESPONSE fields
        if frame.is_path_challenge() or frame.is_path_response():
            ref pd = frame.as_path_data()
            try:
                var dh = String(expected["data_hex"])
                var actual_dh = _bytes_to_hex(pd)
                if actual_dh != dh:
                    raise "vector " + vec_id + " data_hex: got " + actual_dh + " expected " + dh
            except e:
                if "vector" in String(e):
                    raise e^

        pass_count += 1

    print("  vectors: PASS (" + String(pass_count) + "/" + String(total) + " vectors)")


# ── 3. Error tests ──────────────────────────────────────────────────────


def test_error_unknown_frame_type() raises:
    """Unknown frame type 0xFF (varint-encoded as 2-byte 0x40FF) returns
    the `Frame.unknown` sentinel so the dispatch site can close with
    FRAME_ENCODING_ERROR (RFC 9000 §12.4)."""
    var wire = _hex_decode("40ff")
    var r = ByteReader(Span(wire))
    var frame = parse_frame(r)
    _assert_true(
        frame.is_unknown(),
        "unknown frame type 0xFF must return an unknown sentinel"
    )
    _assert_true(
        frame.type_id == UInt64(0xFF),
        "sentinel preserves the wire type_id"
    )
    print("  error_unknown_frame_type: PASS")


def test_error_truncated_ack() raises:
    """Truncated ACK: just the type byte 0x02, no fields."""
    var wire = List[UInt8]()
    wire.append(UInt8(0x02))
    var r = ByteReader(Span(wire))
    var caught = False
    try:
        _ = parse_frame(r)
    except:
        caught = True
    _assert_true(caught, "truncated ACK should raise")
    print("  error_truncated_ack: PASS")


def test_error_ack_first_range_exceeds_largest() raises:
    """ACK with first_ack_range > largest_ack should raise."""
    var w = ByteWriter()
    varint_encode(w, FRAME_ACK)
    varint_encode(w, UInt64(10))  # largest_ack
    varint_encode(w, UInt64(0))   # ack_delay
    varint_encode(w, UInt64(0))   # range_count
    varint_encode(w, UInt64(20))  # first_ack_range > largest_ack
    var wire = w.finish()
    var r = ByteReader(Span(wire))
    var caught = False
    try:
        _ = parse_frame(r)
    except:
        caught = True
    _assert_true(caught, "ACK with first_ack_range > largest_ack should raise")
    print("  error_ack_first_range_exceeds_largest: PASS")


def test_parse_new_cid_length_zero_accepted() raises:
    """NEW_CONNECTION_ID with CID length 0 parses successfully.

    The encoding-level check (RFC 9000 §19.15) is enforced at dispatch
    via the F23 guard (`check_new_connection_id_length`) so the parser
    surfaces the malformed frame to the caller rather than raising.
    Over-length (>20) inputs continue to raise because the read would
    over-consume bytes the RFC does not allow.
    """
    var w = ByteWriter()
    varint_encode(w, FRAME_NEW_CONNECTION_ID)
    varint_encode(w, UInt64(1))  # sequence
    varint_encode(w, UInt64(0))  # retire_prior_to
    w.write_u8(UInt8(0))         # cid_length = 0
    # 16 bytes of stateless_reset_token follow.
    for _ in range(16):
        w.write_u8(UInt8(0))
    var wire = w.finish()
    var r = ByteReader(Span(wire))
    var frame = parse_frame(r)
    _assert_true(frame.is_new_connection_id(), "should parse as NEW_CONNECTION_ID")
    ref nc = frame.as_new_connection_id()
    _assert_eq_int(len(nc.cid), 0, "cid is zero-length")
    _assert_eq_int(len(nc.stateless_reset_token), 16, "token preserved")
    print("  parse_new_cid_length_zero_accepted: PASS")


def test_error_new_cid_length_over_max() raises:
    """NEW_CONNECTION_ID with cid_length > 20 still raises at parse time."""
    var w = ByteWriter()
    varint_encode(w, FRAME_NEW_CONNECTION_ID)
    varint_encode(w, UInt64(1))  # sequence
    varint_encode(w, UInt64(0))  # retire_prior_to
    w.write_u8(UInt8(21))        # cid_length = 21 (over RFC max of 20)
    for _ in range(21):
        w.write_u8(UInt8(0xAA))
    for _ in range(16):
        w.write_u8(UInt8(0))
    var wire = w.finish()
    var r = ByteReader(Span(wire))
    var caught = False
    try:
        _ = parse_frame(r)
    except:
        caught = True
    _assert_true(caught, "cid_length == 21 should raise")
    print("  error_new_cid_length_over_max: PASS")


def test_parse_new_cid_retire_exceeds_seq_accepted() raises:
    """NEW_CONNECTION_ID with retire_prior_to > sequence parses successfully.

    The wire-encoding check (RFC 9000 §19.15) is enforced at dispatch via
    the F22 guard (`check_new_connection_id_retire_prior`) so the parser
    surfaces the malformed frame to the caller rather than raising.
    """
    var w = ByteWriter()
    varint_encode(w, FRAME_NEW_CONNECTION_ID)
    varint_encode(w, UInt64(5))   # sequence
    varint_encode(w, UInt64(10))  # retire_prior_to > sequence
    w.write_u8(UInt8(8))          # cid_length = 8
    for _ in range(8):
        w.write_u8(UInt8(0x01))
    for _ in range(16):
        w.write_u8(UInt8(0x00))
    var wire = w.finish()
    var r = ByteReader(Span(wire))
    var frame = parse_frame(r)
    _assert_true(frame.is_new_connection_id(), "should parse as NEW_CONNECTION_ID")
    ref nc = frame.as_new_connection_id()
    _assert_eq(nc.sequence, UInt64(5), "sequence preserved")
    _assert_eq(nc.retire_prior_to, UInt64(10), "retire_prior_to preserved")
    print("  parse_new_cid_retire_exceeds_seq_accepted: PASS")


# ── 4. frame_allowed_in_packet_type spot-checks ─────────────────────────


def test_frame_allowed_initial() raises:
    """Initial (packet_type=0): PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE ok; STREAM, HANDSHAKE_DONE not."""
    var ptype = UInt8(0)  # Initial
    _assert_true(frame_allowed_in_packet_type(FRAME_PADDING, ptype), "Initial: PADDING allowed")
    _assert_true(frame_allowed_in_packet_type(FRAME_PING, ptype), "Initial: PING allowed")
    _assert_true(frame_allowed_in_packet_type(FRAME_ACK, ptype), "Initial: ACK allowed")
    _assert_true(frame_allowed_in_packet_type(FRAME_CRYPTO, ptype), "Initial: CRYPTO allowed")
    _assert_true(frame_allowed_in_packet_type(FRAME_CONNECTION_CLOSE_TRANSPORT, ptype), "Initial: CONNECTION_CLOSE allowed")
    _assert_false(frame_allowed_in_packet_type(FRAME_STREAM_BASE, ptype), "Initial: STREAM not allowed")
    _assert_false(frame_allowed_in_packet_type(FRAME_HANDSHAKE_DONE, ptype), "Initial: HANDSHAKE_DONE not allowed")
    print("  frame_allowed_initial: PASS")


def test_frame_allowed_one_rtt() raises:
    """1-RTT (packet_type=4): all frame types allowed."""
    var ptype = UInt8(4)  # 1-RTT
    _assert_true(frame_allowed_in_packet_type(FRAME_PADDING, ptype), "1-RTT: PADDING")
    _assert_true(frame_allowed_in_packet_type(FRAME_PING, ptype), "1-RTT: PING")
    _assert_true(frame_allowed_in_packet_type(FRAME_ACK, ptype), "1-RTT: ACK")
    _assert_true(frame_allowed_in_packet_type(FRAME_ACK_ECN, ptype), "1-RTT: ACK_ECN")
    _assert_true(frame_allowed_in_packet_type(FRAME_CRYPTO, ptype), "1-RTT: CRYPTO")
    _assert_true(frame_allowed_in_packet_type(FRAME_NEW_TOKEN, ptype), "1-RTT: NEW_TOKEN")
    _assert_true(frame_allowed_in_packet_type(FRAME_STREAM_BASE, ptype), "1-RTT: STREAM")
    _assert_true(frame_allowed_in_packet_type(FRAME_RESET_STREAM, ptype), "1-RTT: RESET_STREAM")
    _assert_true(frame_allowed_in_packet_type(FRAME_STOP_SENDING, ptype), "1-RTT: STOP_SENDING")
    _assert_true(frame_allowed_in_packet_type(FRAME_MAX_DATA, ptype), "1-RTT: MAX_DATA")
    _assert_true(frame_allowed_in_packet_type(FRAME_MAX_STREAM_DATA, ptype), "1-RTT: MAX_STREAM_DATA")
    _assert_true(frame_allowed_in_packet_type(FRAME_MAX_STREAMS_BIDI, ptype), "1-RTT: MAX_STREAMS_BIDI")
    _assert_true(frame_allowed_in_packet_type(FRAME_MAX_STREAMS_UNI, ptype), "1-RTT: MAX_STREAMS_UNI")
    _assert_true(frame_allowed_in_packet_type(FRAME_DATA_BLOCKED, ptype), "1-RTT: DATA_BLOCKED")
    _assert_true(frame_allowed_in_packet_type(FRAME_STREAM_DATA_BLOCKED, ptype), "1-RTT: STREAM_DATA_BLOCKED")
    _assert_true(frame_allowed_in_packet_type(FRAME_STREAMS_BLOCKED_BIDI, ptype), "1-RTT: STREAMS_BLOCKED_BIDI")
    _assert_true(frame_allowed_in_packet_type(FRAME_STREAMS_BLOCKED_UNI, ptype), "1-RTT: STREAMS_BLOCKED_UNI")
    _assert_true(frame_allowed_in_packet_type(FRAME_NEW_CONNECTION_ID, ptype), "1-RTT: NEW_CONNECTION_ID")
    _assert_true(frame_allowed_in_packet_type(FRAME_RETIRE_CONNECTION_ID, ptype), "1-RTT: RETIRE_CONNECTION_ID")
    _assert_true(frame_allowed_in_packet_type(FRAME_PATH_CHALLENGE, ptype), "1-RTT: PATH_CHALLENGE")
    _assert_true(frame_allowed_in_packet_type(FRAME_PATH_RESPONSE, ptype), "1-RTT: PATH_RESPONSE")
    _assert_true(frame_allowed_in_packet_type(FRAME_CONNECTION_CLOSE_TRANSPORT, ptype), "1-RTT: CONNECTION_CLOSE_TRANSPORT")
    _assert_true(frame_allowed_in_packet_type(FRAME_CONNECTION_CLOSE_APP, ptype), "1-RTT: CONNECTION_CLOSE_APP")
    _assert_true(frame_allowed_in_packet_type(FRAME_HANDSHAKE_DONE, ptype), "1-RTT: HANDSHAKE_DONE")
    print("  frame_allowed_one_rtt: PASS")


# ── 5. is_ack_eliciting checks ──────────────────────────────────────────


def test_is_ack_eliciting() raises:
    # Not ACK-eliciting: PADDING, ACK, CONNECTION_CLOSE
    _assert_false(Frame.padding().is_ack_eliciting(), "PADDING not ack-eliciting")
    var ack = AckFrame()
    ack.largest_ack = UInt64(0)
    ack.ack_delay = UInt64(0)
    ack.first_ack_range = UInt64(0)
    _assert_false(Frame.ack(ack).is_ack_eliciting(), "ACK not ack-eliciting")
    var cc = ConnectionCloseFrame()
    cc.is_transport = True
    _assert_false(Frame.connection_close(cc).is_ack_eliciting(), "CONNECTION_CLOSE not ack-eliciting")

    # ACK-eliciting: PING, STREAM, CRYPTO
    _assert_true(Frame.ping().is_ack_eliciting(), "PING is ack-eliciting")
    var sf = StreamFrame(UInt64(0), UInt64(0), List[UInt8](), False)
    _assert_true(Frame.stream(sf).is_ack_eliciting(), "STREAM is ack-eliciting")
    var cf = CryptoFrame(UInt64(0), List[UInt8]())
    _assert_true(Frame.crypto(cf).is_ack_eliciting(), "CRYPTO is ack-eliciting")
    print("  is_ack_eliciting: PASS")


# ── Main ─────────────────────────────────────────────────────────────────


def main() raises:
    print("test_quic_frame:")

    # 1. Round-trip tests
    print("  -- Round-trip tests --")
    test_roundtrip_padding()
    test_roundtrip_ping()
    test_roundtrip_handshake_done()
    test_roundtrip_ack_with_ranges()
    test_roundtrip_ack_ecn()
    test_roundtrip_crypto()
    test_roundtrip_stream_base()
    test_roundtrip_stream_off_len()
    test_roundtrip_stream_off_len_fin()
    test_roundtrip_stream_empty_fin()
    test_roundtrip_reset_stream()
    test_roundtrip_stop_sending()
    test_roundtrip_max_data()
    test_roundtrip_max_stream_data()
    test_roundtrip_max_streams_bidi()
    test_roundtrip_max_streams_uni()
    test_roundtrip_new_connection_id()
    test_roundtrip_retire_connection_id()
    test_roundtrip_connection_close_transport()
    test_roundtrip_connection_close_app()
    test_roundtrip_new_token()
    test_roundtrip_path_challenge()
    test_roundtrip_path_response()
    test_roundtrip_data_blocked()
    test_roundtrip_stream_data_blocked()
    test_roundtrip_streams_blocked_bidi()
    test_roundtrip_streams_blocked_uni()
    test_roundtrip_datagram_with_len()
    test_roundtrip_datagram_no_length()
    test_datagram_packet_type_permissions()

    # 2. Vector tests
    print("  -- Vector tests --")
    test_vectors()

    # 3. Error tests
    print("  -- Error tests --")
    test_error_unknown_frame_type()
    test_error_truncated_ack()
    test_error_ack_first_range_exceeds_largest()
    test_parse_new_cid_length_zero_accepted()
    test_error_new_cid_length_over_max()
    test_parse_new_cid_retire_exceeds_seq_accepted()

    # 4. Packet-type permission checks
    print("  -- Packet-type permission checks --")
    test_frame_allowed_initial()
    test_frame_allowed_one_rtt()

    # 5. ACK-eliciting checks
    print("  -- ACK-eliciting checks --")
    test_is_ack_eliciting()

    print("All test_quic_frame tests passed.")
