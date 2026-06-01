"""Unit tests for validate_client_transport_params (F02–F06) and
parse_transport_params range checks (F07/F08/F09).

RFC 9000 §7.3 + §18.2: the server MUST validate client-supplied transport
parameters immediately after parsing. This module exercises the predicate
in isolation; wiring into the handshake path is a separate task.

F07/F08/F09 exercise the range guards that fire inside parse_transport_params
itself when a decoded value falls outside its RFC-mandated bounds.
"""

from navette.quic.trans_param import (
    TransportParams,
    PreferredAddress,
    validate_client_transport_params,
    parse_transport_params,
    serialize_transport_params,
    TP_MAX_DATAGRAM_FRAME_SIZE,
    MAX_DATAGRAM_FRAME_SIZE_DISABLED,
    MAX_DATAGRAM_FRAME_SIZE_CAP,
)
from navette.quic.codec import ByteWriter
from navette.quic.guard_tags import (
    GUARD_TAG_TP_INITIAL_SCID_MISSING,
    GUARD_TAG_TP_ORIGINAL_DCID_FORBIDDEN,
    GUARD_TAG_TP_PREFERRED_ADDR_FORBIDDEN,
    GUARD_TAG_TP_RETRY_SCID_FORBIDDEN,
    GUARD_TAG_TP_STATELESS_RESET_FORBIDDEN,
    GUARD_TAG_TP_MAX_UDP_PAYLOAD_RANGE,
    GUARD_TAG_TP_ACK_DELAY_EXP_RANGE,
    GUARD_TAG_TP_MAX_ACK_DELAY_RANGE,
)
from std.memory import Span
from tests._test_util import assert_true


# ── Helpers ─────────────────────────────────────────────────────────────────


def _well_formed_client_tp() -> TransportParams:
    """Build a baseline well-formed client TP block.

    RFC 9000 §7.3 requires clients to include initial_source_connection_id.
    All server-only fields (original_dcid, preferred_address, retry_scid,
    stateless_reset_token) must be absent.
    """
    var p = TransportParams()
    # Set initial_scid to an 8-byte CID (presence required for clients).
    var scid = List[UInt8]()
    for _ in range(8):
        scid.append(UInt8(0xAA))
    p.initial_scid = scid^
    return p^


# ── Tests ────────────────────────────────────────────────────────────────────


def test_f02_missing_initial_scid_raises() raises:
    """F02: validate_client_transport_params raises when initial_source_connection_id is absent.

    RFC 9000 §7.3: A client MUST include the initial_source_connection_id
    parameter. Absence is a TRANSPORT_PARAMETER_ERROR.
    """
    var p = TransportParams()
    # initial_scid defaults to None — do not set it, leaving it absent.
    var caught = False
    try:
        validate_client_transport_params(p)
    except e:
        caught = True
        var msg = String(e)
        assert_true(
            String(GUARD_TAG_TP_INITIAL_SCID_MISSING) in msg,
            "F02 raised wrong tag: " + msg,
        )
    assert_true(caught, "F02 did not raise")
    print("PASS test_f02_missing_initial_scid_raises")


def test_f03_original_dcid_forbidden() raises:
    """F03: original_destination_connection_id is a server-only parameter.

    RFC 9000 §18.2: original_destination_connection_id MUST NOT appear
    in a client's transport parameters.
    """
    var p = _well_formed_client_tp()
    var dcid = List[UInt8]()
    for _ in range(8):
        dcid.append(UInt8(0xBB))
    p.original_dcid = dcid^

    var caught = False
    try:
        validate_client_transport_params(p)
    except e:
        caught = True
        var msg = String(e)
        assert_true(
            String(GUARD_TAG_TP_ORIGINAL_DCID_FORBIDDEN) in msg,
            "F03 raised wrong tag: " + msg,
        )
    assert_true(caught, "F03 did not raise")
    print("PASS test_f03_original_dcid_forbidden")


def test_f04_preferred_addr_forbidden() raises:
    """F04: preferred_address is a server-only parameter.

    RFC 9000 §18.2: preferred_address MUST NOT appear in a client's
    transport parameters.
    """
    var p = _well_formed_client_tp()
    var ipv4 = List[UInt8]()
    for _i in range(4):
        ipv4.append(UInt8(127))
    var ipv6 = List[UInt8]()
    for _i in range(16):
        ipv6.append(UInt8(0))
    var cid = List[UInt8]()
    cid.append(UInt8(0xCC))
    var srt = List[UInt8]()
    for _i in range(16):
        srt.append(UInt8(0xFF))
    p.preferred_address = PreferredAddress(
        ipv4_address=ipv4^,
        ipv4_port=4433,
        ipv6_address=ipv6^,
        ipv6_port=4433,
        cid=cid^,
        stateless_reset_token=srt^,
    )

    var caught = False
    try:
        validate_client_transport_params(p)
    except e:
        caught = True
        var msg = String(e)
        assert_true(
            String(GUARD_TAG_TP_PREFERRED_ADDR_FORBIDDEN) in msg,
            "F04 raised wrong tag: " + msg,
        )
    assert_true(caught, "F04 did not raise")
    print("PASS test_f04_preferred_addr_forbidden")


def test_f05_retry_scid_forbidden() raises:
    """F05: retry_source_connection_id is a server-only parameter.

    RFC 9000 §18.2: retry_source_connection_id MUST NOT appear in a
    client's transport parameters.
    """
    var p = _well_formed_client_tp()
    var rscid = List[UInt8]()
    for _ in range(8):
        rscid.append(UInt8(0xDD))
    p.retry_scid = rscid^

    var caught = False
    try:
        validate_client_transport_params(p)
    except e:
        caught = True
        var msg = String(e)
        assert_true(
            String(GUARD_TAG_TP_RETRY_SCID_FORBIDDEN) in msg,
            "F05 raised wrong tag: " + msg,
        )
    assert_true(caught, "F05 did not raise")
    print("PASS test_f05_retry_scid_forbidden")


def test_f06_stateless_reset_forbidden() raises:
    """F06: stateless_reset_token is a server-only parameter.

    RFC 9000 §18.2: stateless_reset_token MUST NOT appear in a client's
    transport parameters.
    """
    var p = _well_formed_client_tp()
    var tok = List[UInt8]()
    for _i in range(16):
        tok.append(UInt8(0xEE))
    p.stateless_reset_token = tok^

    var caught = False
    try:
        validate_client_transport_params(p)
    except e:
        caught = True
        var msg = String(e)
        assert_true(
            String(GUARD_TAG_TP_STATELESS_RESET_FORBIDDEN) in msg,
            "F06 raised wrong tag: " + msg,
        )
    assert_true(caught, "F06 did not raise")
    print("PASS test_f06_stateless_reset_forbidden")


def test_well_formed_passes() raises:
    """Baseline: a well-formed client TP passes validation without raising."""
    var p = _well_formed_client_tp()
    validate_client_transport_params(p)
    print("PASS test_well_formed_passes")


def test_f07_max_udp_payload_below_1200_raises() raises:
    """F07: parse_transport_params raises with GUARD_TAG_TP_MAX_UDP_PAYLOAD_RANGE when max_udp_payload_size < 1200.

    RFC 9000 §18.2: max_udp_payload_size MUST NOT be below 1200.  The value
    1100 is used here; it is encoded as a 2-byte QUIC varint (1100 < 2^14):
    top byte = 0x40 | (1100 >> 8) = 0x44, low byte = 1100 & 0xff = 0x4c.
    Wire: [id=0x03, len=0x02, 0x44, 0x4c].
    """
    var buf = List[UInt8]()
    buf.append(0x03)  # ID: max_udp_payload_size
    buf.append(0x02)  # length: 2 bytes
    buf.append(0x44)  # value high byte (14-bit varint form, 0x40 prefix)
    buf.append(0x4c)  # value low byte (1100)
    var caught = False
    try:
        _ = parse_transport_params(Span(buf))
    except e:
        caught = True
        var msg = String(e)
        if String(GUARD_TAG_TP_MAX_UDP_PAYLOAD_RANGE) not in msg:
            raise "F07 raised but wrong tag: " + msg
    if not caught:
        raise "F07 did not raise"
    print("PASS test_f07_max_udp_payload_below_1200_raises")


def test_f08_ack_delay_exponent_above_20_raises() raises:
    """F08: ack_delay_exponent = 21 must raise with GUARD_TAG_TP_ACK_DELAY_EXP_RANGE.

    RFC 9000 §18.2: ack_delay_exponent MUST NOT exceed 20.  21 encodes as a
    single-byte QUIC varint (0x15).
    Wire: [id=0x0a, len=0x01, 0x15].
    """
    var buf = List[UInt8]()
    buf.append(0x0a)  # ID: ack_delay_exponent
    buf.append(0x01)  # length: 1 byte
    buf.append(0x15)  # value: 21
    var caught = False
    try:
        _ = parse_transport_params(Span(buf))
    except e:
        caught = True
        if String(GUARD_TAG_TP_ACK_DELAY_EXP_RANGE) not in String(e):
            raise "F08 raised wrong tag: " + String(e)
    if not caught:
        raise "F08 did not raise"
    print("PASS test_f08_ack_delay_exponent_above_20_raises")


def test_f09_max_ack_delay_above_threshold_raises() raises:
    """F09: max_ack_delay = 16384 (= 2^14) must raise with GUARD_TAG_TP_MAX_ACK_DELAY_RANGE.

    RFC 9000 §18.2: max_ack_delay MUST be strictly less than 2^14 (16384).
    16384 encodes as a 4-byte QUIC varint (≥ 2^14 requires the 4-byte form):
    top 2 bits = 10 → first byte = 0x80 | (16384 >> 24) = 0x80,
    then 0x00, then (16384 >> 8) & 0xff = 0x40, then 0x00.
    Wire: [id=0x0b, len=0x04, 0x80, 0x00, 0x40, 0x00].
    """
    var buf = List[UInt8]()
    buf.append(0x0b)  # ID: max_ack_delay
    buf.append(0x04)  # length: 4 bytes
    buf.append(0x80)  # varint 4-byte prefix + high bits
    buf.append(0x00)
    buf.append(0x40)  # 16384 >> 8 = 0x40
    buf.append(0x00)  # low byte
    var caught = False
    try:
        _ = parse_transport_params(Span(buf))
    except e:
        caught = True
        if String(GUARD_TAG_TP_MAX_ACK_DELAY_RANGE) not in String(e):
            raise "F09 raised wrong tag: " + String(e)
    if not caught:
        raise "F09 did not raise"
    print("PASS test_f09_max_ack_delay_above_threshold_raises")


# ── RFC 9221 §3 — max_datagram_frame_size transport parameter ─────────


def test_max_datagram_frame_size_default_disabled() raises:
    """A default-constructed TransportParams must have DATAGRAM disabled.

    RFC 9221 §3: absent or 0 means the endpoint cannot receive DATAGRAM
    frames; the local side MUST NOT send any. The constructor MUST NOT
    accidentally opt the connection in.
    """
    var p = TransportParams()
    assert_true(
        p.max_datagram_frame_size == MAX_DATAGRAM_FRAME_SIZE_DISABLED,
        "default max_datagram_frame_size must be DISABLED (0)",
    )
    print("PASS test_max_datagram_frame_size_default_disabled")


def test_max_datagram_frame_size_roundtrip() raises:
    """Encode + parse round-trip for a typical 1200-byte cap.

    RFC 9221 §3: max_datagram_frame_size is a varint TP keyed by 0x20.
    A non-zero value MUST survive the serialize → parse cycle so the
    handshake-event path can route it to the peer-params snapshot.
    """
    var p = TransportParams()
    var scid = List[UInt8]()
    for _ in range(8):
        scid.append(UInt8(0xAA))
    p.initial_scid = scid^
    p.max_datagram_frame_size = UInt64(1200)
    var w = ByteWriter()
    serialize_transport_params(p, w)
    var wire = w.finish()
    var parsed = parse_transport_params(Span(wire))
    assert_true(
        parsed.max_datagram_frame_size == UInt64(1200),
        "round-trip preserves max_datagram_frame_size=1200",
    )
    print("PASS test_max_datagram_frame_size_roundtrip")


def test_max_datagram_frame_size_zero_omitted_on_serialize() raises:
    """Default-value (0) MUST be omitted from the wire.

    RFC 9221 §3 makes absence and explicit-0 semantically identical. The
    serializer drops the parameter to keep the TP block compact for the
    common "DATAGRAM disabled" case; parse_transport_params then leaves
    the field at its default. Test asserts both: wire ID 0x20 absent,
    and the parsed value matches the default.
    """
    var p = TransportParams()
    var scid = List[UInt8]()
    for _ in range(8):
        scid.append(UInt8(0xBB))
    p.initial_scid = scid^
    # max_datagram_frame_size stays at default (0 == disabled).
    var w = ByteWriter()
    serialize_transport_params(p, w)
    var wire = w.finish()
    # ID 0x20 fits in a single varint byte. Confirm the wire does NOT
    # contain it by scanning for the literal byte; this is sufficient
    # because all other TP IDs that appear are < 0x20 in single-byte form.
    var found = False
    for i in range(len(wire)):
        if wire[i] == UInt8(0x20):
            found = True
            break
    assert_true(not found, "0x20 byte must not appear when value is default")
    var parsed = parse_transport_params(Span(wire))
    assert_true(
        parsed.max_datagram_frame_size == MAX_DATAGRAM_FRAME_SIZE_DISABLED,
        "parsed default is DISABLED",
    )
    print("PASS test_max_datagram_frame_size_zero_omitted_on_serialize")


def test_max_datagram_frame_size_overflow_rejected() raises:
    """Values above 65535 (RFC 9221 §3 cap) must raise at parse time.

    Wire form for value 65536 (= 2^16, requires 4-byte varint):
      ID 0x20, length 0x04, value 0x80 0x01 0x00 0x00.
    """
    var buf = List[UInt8]()
    buf.append(0x20)  # ID: max_datagram_frame_size
    buf.append(0x04)  # length: 4 bytes
    buf.append(0x80)  # varint 4-byte prefix
    buf.append(0x01)  # 65536 high byte
    buf.append(0x00)
    buf.append(0x00)
    var caught = False
    try:
        _ = parse_transport_params(Span(buf))
    except e:
        caught = True
        var msg = String(e)
        assert_true(
            "max_datagram_frame_size" in msg,
            "overflow raised wrong message: " + msg,
        )
    assert_true(caught, "max_datagram_frame_size > 65535 must raise")
    # Also lock in the symbolic cap.
    assert_true(
        MAX_DATAGRAM_FRAME_SIZE_CAP == UInt64(65535),
        "MAX_DATAGRAM_FRAME_SIZE_CAP must equal 65535",
    )
    print("PASS test_max_datagram_frame_size_overflow_rejected")


# ── Main ─────────────────────────────────────────────────────────────────────


def main() raises:
    test_f02_missing_initial_scid_raises()
    test_f03_original_dcid_forbidden()
    test_f04_preferred_addr_forbidden()
    test_f05_retry_scid_forbidden()
    test_f06_stateless_reset_forbidden()
    test_well_formed_passes()
    test_f07_max_udp_payload_below_1200_raises()
    test_f08_ack_delay_exponent_above_20_raises()
    test_f09_max_ack_delay_above_threshold_raises()
    test_max_datagram_frame_size_default_disabled()
    test_max_datagram_frame_size_roundtrip()
    test_max_datagram_frame_size_zero_omitted_on_serialize()
    test_max_datagram_frame_size_overflow_rejected()
    print("All trans-param validator tests passed.")
