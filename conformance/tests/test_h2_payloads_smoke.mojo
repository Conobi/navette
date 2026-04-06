from lib.http2.payloads import (
    DataPayload,
    decode_data_payload,
    HeadersPayload,
    decode_headers_payload,
    PriorityPayload,
    decode_priority_payload,
    RstStreamPayload,
    decode_rst_stream_payload,
    Setting,
    SettingsPayload,
    decode_settings_payload,
    PushPromisePayload,
    decode_push_promise_payload,
    PingPayload,
    decode_ping_payload,
    GoawayPayload,
    decode_goaway_payload,
    WindowUpdatePayload,
    decode_window_update_payload,
    ContinuationPayload,
    decode_continuation_payload,
)
from lib.http2.frame import Frame, decode_frame
from lib.test_util import hex_decode
from std.testing import assert_true, assert_equal


def test_settings_one_entry() raises:
    # SETTINGS frame: type=4, flags=0, stream=0, payload=6 bytes
    # Setting: id=5 (MAX_FRAME_SIZE), value=32768 (0x8000)
    var wire = hex_decode("000006040000000000" + "000500008000")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var settings = decode_settings_payload(frame)
    assert_true(settings.ok(), "settings decode failed: " + settings.error)
    assert_equal(len(settings.settings), 1)
    assert_equal(settings.settings[0].id, 5)
    assert_equal(settings.settings[0].value, 32768)
    assert_equal(settings.ack, False)


def test_settings_ack() raises:
    # SETTINGS ACK: type=4, flags=1, stream=0, length=0
    var wire = hex_decode("000000040100000000")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var settings = decode_settings_payload(frame)
    assert_true(settings.ok(), "settings decode failed: " + settings.error)
    assert_equal(settings.ack, True)
    assert_equal(len(settings.settings), 0)


def test_ping() raises:
    # PING: type=6, flags=0, stream=0, 8 bytes opaque data
    var wire = hex_decode("000008060000000000" + "0102030405060708")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var ping = decode_ping_payload(frame)
    assert_true(ping.ok(), "ping decode failed: " + ping.error)
    assert_equal(ping.ack, False)
    assert_equal(len(ping.opaque_data), 8)
    assert_equal(Int(ping.opaque_data[0]), 1)
    assert_equal(Int(ping.opaque_data[7]), 8)


def test_ping_ack() raises:
    # PING ACK: type=6, flags=1, stream=0, 8 bytes
    var wire = hex_decode("000008060100000000" + "0102030405060708")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var ping = decode_ping_payload(frame)
    assert_true(ping.ok(), "ping decode failed: " + ping.error)
    assert_equal(ping.ack, True)


def test_window_update() raises:
    # WINDOW_UPDATE: type=8, flags=0, stream=1, increment=65535 (0x0000FFFF)
    var wire = hex_decode("000004080000000001" + "0000FFFF")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var wu = decode_window_update_payload(frame)
    assert_true(wu.ok(), "window_update decode failed: " + wu.error)
    assert_equal(wu.window_increment, 65535)


def test_rst_stream() raises:
    # RST_STREAM: type=3, flags=0, stream=1, error_code=2 (INTERNAL_ERROR)
    var wire = hex_decode("000004030000000001" + "00000002")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var rst = decode_rst_stream_payload(frame)
    assert_true(rst.ok(), "rst_stream decode failed: " + rst.error)
    assert_equal(rst.error_code, 2)


def test_goaway() raises:
    # GOAWAY: type=7, flags=0, stream=0
    # last_stream_id=1, error_code=0 (NO_ERROR), debug_data="hi"
    var wire = hex_decode("00000A070000000000" + "00000001" + "00000000" + "6869")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var goaway = decode_goaway_payload(frame)
    assert_true(goaway.ok(), "goaway decode failed: " + goaway.error)
    assert_equal(goaway.last_stream_id, 1)
    assert_equal(goaway.error_code, 0)
    assert_equal(len(goaway.debug_data), 2)
    assert_equal(Int(goaway.debug_data[0]), 0x68)  # 'h'
    assert_equal(Int(goaway.debug_data[1]), 0x69)  # 'i'


def test_priority() raises:
    # PRIORITY: type=2, flags=0, stream=1
    # exclusive=1, dep=0, weight byte=15 -> weight=16
    var wire = hex_decode("000005020000000001" + "800000000F")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var prio = decode_priority_payload(frame)
    assert_true(prio.ok(), "priority decode failed: " + prio.error)
    assert_equal(prio.exclusive, True)
    assert_equal(prio.stream_dependency, 0)
    assert_equal(prio.weight, 16)


def test_data_no_padding() raises:
    # DATA: type=0, flags=0, stream=1, payload="hello" (68656c6c6f)
    var wire = hex_decode("000005000000000001" + "68656C6C6F")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var data = decode_data_payload(frame)
    assert_true(data.ok(), "data decode failed: " + data.error)
    assert_equal(len(data.data), 5)
    assert_equal(data.padding_length, 0)
    assert_equal(Int(data.data[0]), 0x68)  # 'h'


def test_data_with_padding() raises:
    # DATA: type=0, flags=0x08 (PADDED), stream=1
    # pad_length=2, data="hi" (6869), padding=0000
    var wire = hex_decode("000005000800000001" + "02" + "6869" + "0000")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var data = decode_data_payload(frame)
    assert_true(data.ok(), "data decode failed: " + data.error)
    assert_equal(data.padding_length, 2)
    assert_equal(len(data.data), 2)
    assert_equal(Int(data.data[0]), 0x68)  # 'h'
    assert_equal(Int(data.data[1]), 0x69)  # 'i'


def test_headers_simple() raises:
    # HEADERS: type=1, flags=0, stream=1, payload = header block "abc"
    var wire = hex_decode("000003010000000001" + "616263")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var headers = decode_headers_payload(frame)
    assert_true(headers.ok(), "headers decode failed: " + headers.error)
    assert_equal(len(headers.headers_block), 3)
    assert_equal(headers.priority_present, False)
    assert_equal(headers.padding_length, 0)


def test_headers_with_priority() raises:
    # HEADERS: type=1, flags=0x20 (PRIORITY), stream=1
    # exclusive=0, dep=0, weight_byte=255 -> weight=256, header block "ab"
    var wire = hex_decode("000007012000000001" + "00000000" + "FF" + "6162")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var headers = decode_headers_payload(frame)
    assert_true(headers.ok(), "headers decode failed: " + headers.error)
    assert_equal(headers.priority_present, True)
    assert_equal(headers.exclusive, False)
    assert_equal(headers.stream_dependency, 0)
    assert_equal(headers.weight, 256)
    assert_equal(len(headers.headers_block), 2)


def test_continuation() raises:
    # CONTINUATION: type=9, flags=0, stream=1, header block "xyz"
    var wire = hex_decode("000003090000000001" + "78797A")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var cont = decode_continuation_payload(frame)
    assert_true(cont.ok(), "continuation decode failed: " + cont.error)
    assert_equal(len(cont.headers_block), 3)
    assert_equal(Int(cont.headers_block[0]), 0x78)  # 'x'


def test_push_promise() raises:
    # PUSH_PROMISE: type=5, flags=0, stream=1
    # promised_stream_id=2, header block "ab"
    var wire = hex_decode("000006050000000001" + "00000002" + "6162")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var pp = decode_push_promise_payload(frame)
    assert_true(pp.ok(), "push_promise decode failed: " + pp.error)
    assert_equal(pp.promised_stream_id, 2)
    assert_equal(len(pp.headers_block), 2)
    assert_equal(pp.padding_length, 0)


def test_settings_multiple_entries() raises:
    # SETTINGS with 2 entries:
    # id=1 (HEADER_TABLE_SIZE), value=4096
    # id=3 (MAX_CONCURRENT_STREAMS), value=100
    var wire = hex_decode(
        "00000C040000000000" + "000100001000" + "000300000064"
    )
    var result = decode_frame(wire)
    var frame = result[0].copy()
    assert_true(frame.ok(), "frame decode failed: " + frame.error)
    var settings = decode_settings_payload(frame)
    assert_true(settings.ok(), "settings decode failed: " + settings.error)
    assert_equal(len(settings.settings), 2)
    assert_equal(settings.settings[0].id, 1)
    assert_equal(settings.settings[0].value, 4096)
    assert_equal(settings.settings[1].id, 3)
    assert_equal(settings.settings[1].value, 100)


def test_wrong_frame_type_error() raises:
    # Try to decode a PING frame as SETTINGS — should fail gracefully
    var wire = hex_decode("000008060000000000" + "0102030405060708")
    var result = decode_frame(wire)
    var frame = result[0].copy()
    var settings = decode_settings_payload(frame)
    assert_equal(settings.ok(), False)


def main() raises:
    test_settings_one_entry()
    test_settings_ack()
    test_settings_multiple_entries()
    test_ping()
    test_ping_ack()
    test_window_update()
    test_rst_stream()
    test_goaway()
    test_priority()
    test_data_no_padding()
    test_data_with_padding()
    test_headers_simple()
    test_headers_with_priority()
    test_continuation()
    test_push_promise()
    test_wrong_frame_type_error()
    print("All payload decoder tests passed.")
