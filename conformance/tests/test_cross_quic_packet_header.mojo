# conformance/tests/test_cross_quic_packet_header.mojo
#
# QC-1 Category 2: QUIC packet header parse vectors.
# Loads vectors/rfc9000/packet_header.json and cross-checks the
# Mojo parse_packet_header implementation against expected fields.

from lib.test_util import hex_decode, hex_encode, load_vectors, assert_true, assert_equal
from python import Python, PythonObject
from mojo_net.quic.packet import parse_packet_header, PacketType, PacketHeader


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


def main() raises:
    # Verify assertions are working.
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing")

    var vectors = load_vectors("vectors/rfc9000/packet_header.json")
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
            vid + ": is_long_header mismatch",
        )

        # packet_type
        var exp_type = String(expected["packet_type"])
        var got_type = packet_type_to_string(result[0].packet_type)
        assert_true(
            got_type == exp_type,
            vid + ": packet_type mismatch: got " + got_type + " expected " + exp_type,
        )

        # version
        var exp_version = Int(py=expected["version"])
        assert_equal(
            Int(result[0].version), exp_version, vid + ".version",
        )

        # destination_cid_hex
        var exp_dcid = String(expected["destination_cid_hex"])
        var got_dcid = hex_encode(result[0].dcid)
        assert_true(
            got_dcid == exp_dcid,
            vid + ": dcid mismatch: got " + got_dcid + " expected " + exp_dcid,
        )

        # source_cid_hex
        var exp_scid = String(expected["source_cid_hex"])
        var got_scid = hex_encode(result[0].scid)
        assert_true(
            got_scid == exp_scid,
            vid + ": scid mismatch: got " + got_scid + " expected " + exp_scid,
        )

        # token_hex
        var exp_token = String(expected["token_hex"])
        var got_token = hex_encode(result[0].token)
        assert_true(
            got_token == exp_token,
            vid + ": token mismatch: got " + got_token + " expected " + exp_token,
        )

        # packet_length
        var exp_pkt_len = Int(py=expected["packet_length"])
        if result[0].packet_type == PacketType.initial() or result[0].packet_type == PacketType.handshake() or result[0].packet_type == PacketType.zero_rtt():
            var got_pkt_len = result[0].pn_offset + Int(result[0].payload_length)
            assert_equal(got_pkt_len, exp_pkt_len, vid + ".packet_length")
        elif result[0].packet_type == PacketType.retry():
            assert_equal(result[1], exp_pkt_len, vid + ".packet_length(retry)")
        else:
            # Short header: packet_length == wire length.
            assert_equal(len(wire_bytes), exp_pkt_len, vid + ".packet_length(short)")

        n_pass += 1

    print(
        "test_cross_quic_packet_header: PASS ("
        + String(n_pass)
        + " accept, "
        + String(n_reject)
        + " reject)"
    )
