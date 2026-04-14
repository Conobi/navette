# tests/test_quic_transport_params.mojo
#
# Tests for QUIC transport parameter codec (src/quic/trans_param.mojo).
# Covers: vector-driven parsing, round-trip encode/decode, validation
# errors, and default values.
#
# Run with:
#   cd ~/Projets/perso/mojo-net && uv run mojo run -I . -I conformance \
#     -D ASSERT=all tests/test_quic_transport_params.mojo

from std.collections import Dict, Optional
from std.python import Python, PythonObject

from src.quic.trans_param import (
    TransportParams,
    default_transport_params,
    parse_transport_params,
    serialize_transport_params,
)
from src.quic.codec import ByteReader, ByteWriter, varint_encode, varint_len

from lib.test_util import hex_decode, hex_encode, load_vectors
from tests._test_util import assert_true, assert_equal_int


# ── Helpers ─────────────────────────────────────────────────────────────


def _has_key(obj: PythonObject, key: String) -> Bool:
    try:
        var builtins = Python.import_module("builtins")
        return Bool(builtins.bool(key in obj))
    except:
        return False


def _bytes_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def _assert_bytes_equal(got: List[UInt8], expected: List[UInt8], msg: String) raises:
    if not _bytes_equal(got, expected):
        print(
            "ASSERTION FAILED ["
            + msg
            + "]: got "
            + hex_encode(got)
            + " expected "
            + hex_encode(expected)
        )
        raise "assertion failed: " + msg


def _assert_raises(msg: String, raised: Bool) raises:
    if not raised:
        print("ASSERTION FAILED: expected error for " + msg)
        raise "assertion failed: expected error for " + msg


# ── 1. Vector tests ────────────────────────────────────────────────────


def test_vectors() raises:
    print("--- vector tests ---")
    var vectors = load_vectors("conformance/vectors/rfc9000/transport_params.json")
    var builtins = Python.import_module("builtins")
    var count = Int(py=builtins.len(vectors))
    assert_true(count >= 15, "expected at least 15 transport param vectors, got " + String(count))
    var passed = 0

    for i in range(count):
        var vec = vectors[i]
        var vec_id = String(vec["id"])
        var wire_hex = String(vec["wire_hex"])
        var wire = hex_decode(wire_hex)

        # Error vectors: assert parse raises.
        if _has_key(vec, "expect") and String(vec["expect"]) == "error":
            var raised = False
            try:
                _ = parse_transport_params(Span(wire))
            except:
                raised = True
            _assert_raises(vec_id, raised)
            passed += 1
            continue

        # Success vectors: parse and check expected fields.
        var params = parse_transport_params(Span(wire))
        var expected = vec["expected"]

        if _has_key(expected, "max_idle_timeout"):
            assert_equal_int(
                Int(params.max_idle_timeout),
                Int(py=expected["max_idle_timeout"]),
                vec_id + ".max_idle_timeout",
            )

        if _has_key(expected, "max_udp_payload_size"):
            assert_equal_int(
                Int(params.max_udp_payload_size),
                Int(py=expected["max_udp_payload_size"]),
                vec_id + ".max_udp_payload_size",
            )

        if _has_key(expected, "initial_max_data"):
            assert_equal_int(
                Int(params.initial_max_data),
                Int(py=expected["initial_max_data"]),
                vec_id + ".initial_max_data",
            )

        if _has_key(expected, "initial_max_stream_data_bidi_local"):
            assert_equal_int(
                Int(params.initial_max_stream_data_bidi_local),
                Int(py=expected["initial_max_stream_data_bidi_local"]),
                vec_id + ".initial_max_stream_data_bidi_local",
            )

        if _has_key(expected, "initial_max_stream_data_bidi_remote"):
            assert_equal_int(
                Int(params.initial_max_stream_data_bidi_remote),
                Int(py=expected["initial_max_stream_data_bidi_remote"]),
                vec_id + ".initial_max_stream_data_bidi_remote",
            )

        if _has_key(expected, "initial_max_stream_data_uni"):
            assert_equal_int(
                Int(params.initial_max_stream_data_uni),
                Int(py=expected["initial_max_stream_data_uni"]),
                vec_id + ".initial_max_stream_data_uni",
            )

        if _has_key(expected, "initial_max_streams_bidi"):
            assert_equal_int(
                Int(params.initial_max_streams_bidi),
                Int(py=expected["initial_max_streams_bidi"]),
                vec_id + ".initial_max_streams_bidi",
            )

        if _has_key(expected, "initial_max_streams_uni"):
            assert_equal_int(
                Int(params.initial_max_streams_uni),
                Int(py=expected["initial_max_streams_uni"]),
                vec_id + ".initial_max_streams_uni",
            )

        if _has_key(expected, "ack_delay_exponent"):
            assert_equal_int(
                Int(params.ack_delay_exponent),
                Int(py=expected["ack_delay_exponent"]),
                vec_id + ".ack_delay_exponent",
            )

        if _has_key(expected, "max_ack_delay"):
            assert_equal_int(
                Int(params.max_ack_delay),
                Int(py=expected["max_ack_delay"]),
                vec_id + ".max_ack_delay",
            )

        if _has_key(expected, "disable_active_migration"):
            var expected_val = Bool(py=expected["disable_active_migration"])
            assert_true(
                params.disable_active_migration == expected_val,
                vec_id + ".disable_active_migration: got "
                + String(params.disable_active_migration)
                + " expected "
                + String(expected_val),
            )

        if _has_key(expected, "active_connection_id_limit"):
            assert_equal_int(
                Int(params.active_connection_id_limit),
                Int(py=expected["active_connection_id_limit"]),
                vec_id + ".active_connection_id_limit",
            )

        # CID fields (hex-encoded in vector).
        if _has_key(expected, "original_destination_connection_id_hex"):
            var expected_hex = String(expected["original_destination_connection_id_hex"])
            assert_true(
                Bool(params.original_dcid),
                vec_id + ": original_dcid should be Some",
            )
            var actual_hex = hex_encode(params.original_dcid.value().copy())
            assert_true(
                actual_hex == expected_hex,
                vec_id + ".original_dcid: got " + actual_hex + " expected " + expected_hex,
            )

        if _has_key(expected, "initial_source_connection_id_hex"):
            var expected_hex = String(expected["initial_source_connection_id_hex"])
            assert_true(
                Bool(params.initial_scid),
                vec_id + ": initial_scid should be Some",
            )
            var actual_hex = hex_encode(params.initial_scid.value().copy())
            assert_true(
                actual_hex == expected_hex,
                vec_id + ".initial_scid: got " + actual_hex + " expected " + expected_hex,
            )

        # Stateless reset token (hex-encoded in vector).
        if _has_key(expected, "stateless_reset_token_hex"):
            var expected_hex = String(expected["stateless_reset_token_hex"])
            assert_true(
                Bool(params.stateless_reset_token),
                vec_id + ": stateless_reset_token should be Some",
            )
            var actual_hex = hex_encode(params.stateless_reset_token.value().copy())
            assert_true(
                actual_hex == expected_hex,
                vec_id + ".stateless_reset_token: got " + actual_hex + " expected " + expected_hex,
            )

        # Unknown parameters.
        if _has_key(expected, "unknown_parameters"):
            var unknown_list = expected["unknown_parameters"]
            var ucount = Int(py=builtins.len(unknown_list))
            for ui in range(ucount):
                var uentry = unknown_list[ui]
                var pid = Int(py=uentry["param_id"])
                var vhex = String(uentry["value_hex"])
                assert_true(
                    pid in params.unknown,
                    vec_id + ": unknown param " + String(pid) + " not found",
                )
                var actual_vhex = hex_encode(params.unknown[pid].copy())
                assert_true(
                    actual_vhex == vhex,
                    vec_id + ".unknown[" + String(pid) + "]: got " + actual_vhex + " expected " + vhex,
                )

        # Preferred address.
        if _has_key(expected, "preferred_address"):
            var pa_expected = expected["preferred_address"]
            assert_true(
                Bool(params.preferred_address),
                vec_id + ": preferred_address should be Some",
            )
            var pa = params.preferred_address.value().copy()

            assert_equal_int(
                Int(pa.ipv4_port),
                Int(py=pa_expected["ipv4_port"]),
                vec_id + ".preferred_address.ipv4_port",
            )
            assert_equal_int(
                Int(pa.ipv6_port),
                Int(py=pa_expected["ipv6_port"]),
                vec_id + ".preferred_address.ipv6_port",
            )

            var cid_hex = hex_encode(pa.cid.copy())
            var expected_cid_hex = String(pa_expected["connection_id_hex"])
            assert_true(
                cid_hex == expected_cid_hex,
                vec_id + ".preferred_address.cid: got " + cid_hex + " expected " + expected_cid_hex,
            )

            var srt_hex = hex_encode(pa.stateless_reset_token.copy())
            var expected_srt_hex = String(pa_expected["stateless_reset_token_hex"])
            assert_true(
                srt_hex == expected_srt_hex,
                vec_id + ".preferred_address.srt: got " + srt_hex + " expected " + expected_srt_hex,
            )

        passed += 1

    print("  vector tests: PASS (" + String(passed) + "/" + String(count) + " vectors)")


# ── 2. Round-trip tests ────────────────────────────────────────────────


def test_roundtrip_full() raises:
    """Non-default values for every field: serialize -> parse -> match."""
    var orig = TransportParams()
    orig.max_idle_timeout = 30000
    orig.max_udp_payload_size = 1400
    orig.initial_max_data = 10485760
    orig.initial_max_stream_data_bidi_local = 1048576
    orig.initial_max_stream_data_bidi_remote = 1048576
    orig.initial_max_stream_data_uni = 1048576
    orig.initial_max_streams_bidi = 100
    orig.initial_max_streams_uni = 50
    orig.ack_delay_exponent = 5
    orig.max_ack_delay = 50
    orig.active_connection_id_limit = 4
    orig.disable_active_migration = True

    # 8-byte CIDs.
    var dcid = List[UInt8]()
    for i in range(8):
        dcid.append(UInt8(0x10 + i))
    orig.original_dcid = dcid^

    var scid = List[UInt8]()
    for i in range(8):
        scid.append(UInt8(0x20 + i))
    orig.initial_scid = scid^

    # Serialize.
    var w = ByteWriter()
    serialize_transport_params(orig, w)
    var wire = w.finish()
    assert_true(len(wire) > 0, "serialized bytes should be non-empty")

    # Parse back.
    var parsed = parse_transport_params(Span(wire))

    # Assert all fields match.
    assert_equal_int(Int(parsed.max_idle_timeout), 30000, "rt.max_idle_timeout")
    assert_equal_int(Int(parsed.max_udp_payload_size), 1400, "rt.max_udp_payload_size")
    assert_equal_int(Int(parsed.initial_max_data), 10485760, "rt.initial_max_data")
    assert_equal_int(Int(parsed.initial_max_stream_data_bidi_local), 1048576, "rt.bidi_local")
    assert_equal_int(Int(parsed.initial_max_stream_data_bidi_remote), 1048576, "rt.bidi_remote")
    assert_equal_int(Int(parsed.initial_max_stream_data_uni), 1048576, "rt.stream_data_uni")
    assert_equal_int(Int(parsed.initial_max_streams_bidi), 100, "rt.streams_bidi")
    assert_equal_int(Int(parsed.initial_max_streams_uni), 50, "rt.streams_uni")
    assert_equal_int(Int(parsed.ack_delay_exponent), 5, "rt.ack_delay_exponent")
    assert_equal_int(Int(parsed.max_ack_delay), 50, "rt.max_ack_delay")
    assert_equal_int(Int(parsed.active_connection_id_limit), 4, "rt.active_connection_id_limit")
    assert_true(parsed.disable_active_migration, "rt.disable_active_migration")

    assert_true(Bool(parsed.original_dcid), "rt.original_dcid should be Some")
    var parsed_dcid = parsed.original_dcid.value().copy()
    assert_equal_int(len(parsed_dcid), 8, "rt.original_dcid length")
    for i in range(8):
        assert_true(
            parsed_dcid[i] == UInt8(0x10 + i),
            "rt.original_dcid[" + String(i) + "]",
        )

    assert_true(Bool(parsed.initial_scid), "rt.initial_scid should be Some")
    var parsed_scid = parsed.initial_scid.value().copy()
    assert_equal_int(len(parsed_scid), 8, "rt.initial_scid length")
    for i in range(8):
        assert_true(
            parsed_scid[i] == UInt8(0x20 + i),
            "rt.initial_scid[" + String(i) + "]",
        )

    print("  roundtrip_full: PASS")


def test_roundtrip_defaults() raises:
    """Default transport params: serialize -> parse -> all defaults."""
    var orig = default_transport_params()
    var w = ByteWriter()
    serialize_transport_params(orig, w)
    var wire = w.finish()

    # Default params should produce minimal (possibly empty) encoding.
    var parsed = parse_transport_params(Span(wire))

    assert_equal_int(Int(parsed.max_idle_timeout), 0, "def.max_idle_timeout")
    assert_equal_int(Int(parsed.max_udp_payload_size), 65527, "def.max_udp_payload_size")
    assert_equal_int(Int(parsed.initial_max_data), 0, "def.initial_max_data")
    assert_equal_int(Int(parsed.initial_max_stream_data_bidi_local), 0, "def.bidi_local")
    assert_equal_int(Int(parsed.initial_max_stream_data_bidi_remote), 0, "def.bidi_remote")
    assert_equal_int(Int(parsed.initial_max_stream_data_uni), 0, "def.stream_data_uni")
    assert_equal_int(Int(parsed.initial_max_streams_bidi), 0, "def.streams_bidi")
    assert_equal_int(Int(parsed.initial_max_streams_uni), 0, "def.streams_uni")
    assert_equal_int(Int(parsed.ack_delay_exponent), 3, "def.ack_delay_exponent")
    assert_equal_int(Int(parsed.max_ack_delay), 25, "def.max_ack_delay")
    assert_equal_int(Int(parsed.active_connection_id_limit), 2, "def.active_connection_id_limit")
    assert_true(not parsed.disable_active_migration, "def.disable_active_migration should be False")
    assert_true(not Bool(parsed.original_dcid), "def.original_dcid should be None")
    assert_true(not Bool(parsed.initial_scid), "def.initial_scid should be None")
    assert_true(not Bool(parsed.retry_scid), "def.retry_scid should be None")
    assert_true(not Bool(parsed.stateless_reset_token), "def.stateless_reset_token should be None")

    print("  roundtrip_defaults: PASS")


def test_roundtrip_unknown_param() raises:
    """Unknown parameter preserved through serialize -> parse."""
    var orig = TransportParams()
    var value = List[UInt8]()
    value.append(UInt8(0xDE))
    value.append(UInt8(0xAD))
    value.append(UInt8(0xBE))
    value.append(UInt8(0xEF))
    orig.unknown[0xFFFF] = value^

    var w = ByteWriter()
    serialize_transport_params(orig, w)
    var wire = w.finish()
    assert_true(len(wire) > 0, "unknown param wire should be non-empty")

    var parsed = parse_transport_params(Span(wire))
    assert_true(0xFFFF in parsed.unknown, "unknown param 0xFFFF should be preserved")
    var parsed_val = parsed.unknown[0xFFFF].copy()
    assert_equal_int(len(parsed_val), 4, "unknown param value length")
    assert_true(parsed_val[0] == UInt8(0xDE), "unknown[0]")
    assert_true(parsed_val[1] == UInt8(0xAD), "unknown[1]")
    assert_true(parsed_val[2] == UInt8(0xBE), "unknown[2]")
    assert_true(parsed_val[3] == UInt8(0xEF), "unknown[3]")

    print("  roundtrip_unknown_param: PASS")


# ── 3. Validation error tests ──────────────────────────────────────────


def test_error_duplicate_param() raises:
    """Duplicate parameter ID raises."""
    var w = ByteWriter()
    # Write max_idle_timeout twice (param_id=0x01).
    varint_encode(w, UInt64(0x01))  # param_id
    varint_encode(w, UInt64(2))     # length: 2-byte varint
    varint_encode(w, UInt64(1000))  # value
    varint_encode(w, UInt64(0x01))  # param_id (duplicate)
    varint_encode(w, UInt64(2))     # length
    varint_encode(w, UInt64(2000))  # value
    var wire = w.finish()

    var raised = False
    try:
        _ = parse_transport_params(Span(wire))
    except:
        raised = True
    _assert_raises("duplicate param", raised)
    print("  error_duplicate_param: PASS")


def test_error_max_udp_payload_too_small() raises:
    """Reject max_udp_payload_size = 1199 (< 1200 minimum)."""
    var w = ByteWriter()
    varint_encode(w, UInt64(0x03))  # TP_MAX_UDP_PAYLOAD_SIZE
    var vlen = varint_len(UInt64(1199))
    varint_encode(w, UInt64(vlen))
    varint_encode(w, UInt64(1199))
    var wire = w.finish()

    var raised = False
    try:
        _ = parse_transport_params(Span(wire))
    except:
        raised = True
    _assert_raises("max_udp_payload_size=1199", raised)
    print("  error_max_udp_payload_too_small: PASS")


def test_error_ack_delay_exponent_too_large() raises:
    """Reject ack_delay_exponent = 21 (> 20 maximum)."""
    var w = ByteWriter()
    varint_encode(w, UInt64(0x0A))  # TP_ACK_DELAY_EXPONENT
    var vlen = varint_len(UInt64(21))
    varint_encode(w, UInt64(vlen))
    varint_encode(w, UInt64(21))
    var wire = w.finish()

    var raised = False
    try:
        _ = parse_transport_params(Span(wire))
    except:
        raised = True
    _assert_raises("ack_delay_exponent=21", raised)
    print("  error_ack_delay_exponent_too_large: PASS")


def test_error_max_ack_delay_too_large() raises:
    """Reject max_ack_delay = 16384 (>= 2^14)."""
    var w = ByteWriter()
    varint_encode(w, UInt64(0x0B))  # TP_MAX_ACK_DELAY
    var vlen = varint_len(UInt64(16384))
    varint_encode(w, UInt64(vlen))
    varint_encode(w, UInt64(16384))
    var wire = w.finish()

    var raised = False
    try:
        _ = parse_transport_params(Span(wire))
    except:
        raised = True
    _assert_raises("max_ack_delay=16384", raised)
    print("  error_max_ack_delay_too_large: PASS")


def test_error_active_cid_limit_too_small() raises:
    """Reject active_connection_id_limit = 1 (< 2 minimum)."""
    var w = ByteWriter()
    varint_encode(w, UInt64(0x0E))  # TP_ACTIVE_CONNECTION_ID_LIMIT
    var vlen = varint_len(UInt64(1))
    varint_encode(w, UInt64(vlen))
    varint_encode(w, UInt64(1))
    var wire = w.finish()

    var raised = False
    try:
        _ = parse_transport_params(Span(wire))
    except:
        raised = True
    _assert_raises("active_connection_id_limit=1", raised)
    print("  error_active_cid_limit_too_small: PASS")


def test_error_truncated_value() raises:
    """Truncated value (length says 4, only 2 available) raises."""
    var w = ByteWriter()
    varint_encode(w, UInt64(0x04))  # TP_INITIAL_MAX_DATA
    varint_encode(w, UInt64(4))     # claims 4 bytes follow
    w.write_u8(UInt8(0x80))         # only 2 bytes actually written
    w.write_u8(UInt8(0x10))
    var wire = w.finish()

    var raised = False
    try:
        _ = parse_transport_params(Span(wire))
    except:
        raised = True
    _assert_raises("truncated value", raised)
    print("  error_truncated_value: PASS")


# ── 4. Default values test ─────────────────────────────────────────────


def test_default_values() raises:
    """Verify default_transport_params() returns correct RFC 9000 defaults."""
    var p = default_transport_params()

    assert_equal_int(Int(p.max_idle_timeout), 0, "default.max_idle_timeout")
    assert_equal_int(Int(p.max_udp_payload_size), 65527, "default.max_udp_payload_size")
    assert_equal_int(Int(p.ack_delay_exponent), 3, "default.ack_delay_exponent")
    assert_equal_int(Int(p.max_ack_delay), 25, "default.max_ack_delay")
    assert_equal_int(Int(p.active_connection_id_limit), 2, "default.active_connection_id_limit")
    assert_equal_int(Int(p.initial_max_data), 0, "default.initial_max_data")
    assert_equal_int(Int(p.initial_max_stream_data_bidi_local), 0, "default.bidi_local")
    assert_equal_int(Int(p.initial_max_stream_data_bidi_remote), 0, "default.bidi_remote")
    assert_equal_int(Int(p.initial_max_stream_data_uni), 0, "default.stream_data_uni")
    assert_equal_int(Int(p.initial_max_streams_bidi), 0, "default.streams_bidi")
    assert_equal_int(Int(p.initial_max_streams_uni), 0, "default.streams_uni")
    assert_true(not p.disable_active_migration, "default.disable_active_migration should be False")
    assert_true(not Bool(p.original_dcid), "default.original_dcid should be None")
    assert_true(not Bool(p.initial_scid), "default.initial_scid should be None")
    assert_true(not Bool(p.retry_scid), "default.retry_scid should be None")
    assert_true(not Bool(p.stateless_reset_token), "default.stateless_reset_token should be None")
    assert_true(not Bool(p.preferred_address), "default.preferred_address should be None")

    print("  default_values: PASS")


# ── Main ────────────────────────────────────────────────────────────────


def main() raises:
    print("test_quic_transport_params:")

    # 1. Vector tests
    test_vectors()

    # 2. Round-trip tests
    print("--- round-trip tests ---")
    test_roundtrip_full()
    test_roundtrip_defaults()
    test_roundtrip_unknown_param()

    # 3. Validation error tests
    print("--- validation error tests ---")
    test_error_duplicate_param()
    test_error_max_udp_payload_too_small()
    test_error_ack_delay_exponent_too_large()
    test_error_max_ack_delay_too_large()
    test_error_active_cid_limit_too_small()
    test_error_truncated_value()

    # 4. Default values test
    print("--- default values test ---")
    test_default_values()

    print("All test_quic_transport_params tests passed.")
