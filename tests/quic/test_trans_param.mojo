"""Unit tests for validate_client_transport_params (F02/F03/F04/F05/F06).

RFC 9000 §7.3 + §18.2: the server MUST validate client-supplied transport
parameters immediately after parsing. This module exercises the predicate
in isolation; wiring into the handshake path is a separate task.
"""

from navette.quic.trans_param import (
    TransportParams,
    PreferredAddress,
    validate_client_transport_params,
)
from navette.quic.guard_tags import (
    GUARD_TAG_TP_INITIAL_SCID_MISSING,
    GUARD_TAG_TP_ORIGINAL_DCID_FORBIDDEN,
    GUARD_TAG_TP_PREFERRED_ADDR_FORBIDDEN,
    GUARD_TAG_TP_RETRY_SCID_FORBIDDEN,
    GUARD_TAG_TP_STATELESS_RESET_FORBIDDEN,
)
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


# ── Main ─────────────────────────────────────────────────────────────────────


def main() raises:
    test_f02_missing_initial_scid_raises()
    test_f03_original_dcid_forbidden()
    test_f04_preferred_addr_forbidden()
    test_f05_retry_scid_forbidden()
    test_f06_stateless_reset_forbidden()
    test_well_formed_passes()
    print("All trans-param validator tests passed.")
