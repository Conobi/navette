"""Retry / VN / stateless close: wire layout and acceptance by a reference client."""

from std.collections import Span

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.event import QuicEvent, ConnectionClosedPayload
from navette.quic.packet import PacketType, parse_packet_header
from navette.quic.packet_protect import PacketProtect
from navette.quic.retry import compute_retry_integrity_tag
from navette.quic.stateless import (
    build_retry,
    build_version_negotiation,
    build_stateless_close_initial,
)
from navette.quic.trans_param import default_transport_params
from tests._test_util import assert_true, assert_equal_int, load_test_ca


def _bytes(v: UInt8, n: Int) -> List[Byte]:
    return List[Byte](length=n, fill=v)


def _eq(a: Span[Byte, _], b: Span[Byte, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def test_retry_layout_and_tag(lib: SharedLibrary) raises:
    var client_dcid = _bytes(0x11, 20)
    var client_scid = _bytes(0x22, 8)
    var retry_scid = _bytes(0x33, 8)
    var token = _bytes(0x01, 90)
    var out = List[Byte](capacity=1252)
    build_retry(out, lib, Span(client_dcid), Span(client_scid), Span(retry_scid), Span(token))
    assert_equal_int(len(out), 1 + 4 + 1 + 8 + 1 + 8 + 90 + 16, "129 B for an 8-byte client SCID")
    var hr = parse_packet_header(Span(out), 8)
    assert_true(hr[0].packet_type == PacketType.retry(), "Retry type")
    assert_equal_int(Int(hr[0].version), 1, "QUIC v1")
    assert_true(_eq(hr[0].dcid.as_span(), Span(client_scid)), "DCID = client SCID")
    assert_true(_eq(hr[0].scid.as_span(), Span(retry_scid)), "SCID = fresh Retry SCID")
    assert_true(_eq(hr[0].token_span(), Span(token)), "token carried verbatim")
    var tag = List[Byte]()
    compute_retry_integrity_tag(tag, lib, Span(client_dcid), Span(out)[: len(out) - 16])
    assert_true(_eq(Span(tag), Span(out)[len(out) - 16 :]), "integrity tag over orig DCID")
    print("  test_retry_layout_and_tag: PASS")


def test_retry_rejects_bad_inputs(lib: SharedLibrary) raises:
    """Oversized CIDs and an empty token raise instead of emitting a malformed Retry."""
    var a = _bytes(0x11, 8)
    var b = _bytes(0x12, 8)
    var c = _bytes(0x13, 8)
    var big = _bytes(0x14, 21)
    var tok = _bytes(0x01, 70)
    var empty = List[Byte]()
    var out = List[Byte](capacity=1252)
    var raised = 0
    try:
        build_retry(out, lib, Span(big), Span(b), Span(c), Span(tok))
    except:
        raised += 1
    try:
        build_retry(out, lib, Span(a), Span(big), Span(c), Span(tok))
    except:
        raised += 1
    try:
        build_retry(out, lib, Span(a), Span(b), Span(big), Span(tok))
    except:
        raised += 1
    try:
        build_retry(out, lib, Span(a), Span(b), Span(c), Span(empty))
    except:
        raised += 1
    assert_equal_int(raised, 4, "every bad input raises")
    print("  test_retry_rejects_bad_inputs: PASS")


def test_version_negotiation() raises:
    var out = List[Byte](capacity=1252)
    build_version_negotiation(out, Span(_bytes(0x44, 12)), Span(_bytes(0x55, 5)))
    assert_equal_int(len(out), 1 + 4 + 1 + 5 + 1 + 12 + 4, "one version")
    assert_true((out[0] & 0x80) != 0, "long header form bit")
    var hr = parse_packet_header(Span(out), 8)
    assert_true(hr[0].packet_type == PacketType.version_negotiation(), "VN")
    assert_true(_eq(hr[0].dcid.as_span(), Span(_bytes(0x55, 5))), "DCID = client SCID")
    assert_true(_eq(hr[0].scid.as_span(), Span(_bytes(0x44, 12))), "SCID = client DCID")
    assert_equal_int(Int(hr[0].versions_len), 1, "one version")
    assert_equal_int(Int(hr[0].supported_versions[0]), 1, "QUIC v1")
    print("  test_version_negotiation: PASS")


def _closed_code(mut conn: QuicConnection) -> UInt64:
    """Error code of the first CONNECTION_CLOSED event, `UInt64.MAX` if none."""
    while True:
        var ev = conn.poll()
        if not ev:
            return UInt64.MAX
        if ev.value().type_id == QuicEvent.CONNECTION_CLOSED:
            return ev.value().payload[ConnectionClosedPayload].error_code


def test_close_parses_on_reference_client() raises:
    """The close decrypts under the client's Initial keys and the client sees INVALID_TOKEN, then CONNECTION_REFUSED."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ca_bytes = load_test_ca()
    var ccfg = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var now = UInt64(1_000_000)
    for code in [UInt64(0x0B), UInt64(0x02)]:
        var client = QuicConnection.client(tls.shared(), ccfg, "localhost", default_transport_params(), now)
        var sent = List[List[Byte]]()
        _ = client.send(now, sent)
        var protect = PacketProtect(tls.shared())
        var out = List[Byte](capacity=1252)
        build_stateless_close_initial(
            out,
            protect,
            client.initial_dcid.as_span(),
            client.local_cid.as_span(),
            Span(_bytes(0x66, 8)),
            code,
        )
        assert_true(len(out) < 200, "no amplification: well under the 1,200 B Initial")
        var hr = parse_packet_header(Span(out), 8)
        assert_true(hr[0].packet_type == PacketType.initial(), "Initial")
        assert_true(_eq(hr[0].dcid.as_span(), client.local_cid.as_span()), "DCID = client SCID")
        assert_equal_int(Int(hr[0].token_len), 0, "no token")
        client.recv(Span(out), now)
        assert_equal_int(Int(_closed_code(client)), Int(code), "client saw the close code")
    _ = tls.shared()
    print("  test_close_parses_on_reference_client: PASS")


def main() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var shared = tls.shared()
    print("test_quic_stateless:")
    test_retry_layout_and_tag(shared)
    test_retry_rejects_bad_inputs(shared)
    test_version_negotiation()
    test_close_parses_on_reference_client()
    print("PASS: test_quic_stateless")
    _ = tls^
