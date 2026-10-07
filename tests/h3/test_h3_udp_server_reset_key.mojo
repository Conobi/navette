"""Stateless reset tokens derive from one key per server (RFC 9000 Section 10.3).

Every connection of a server computes the same token for a CID, two servers
compute different ones, the key is not the ingress guard's Retry secret, and
a token reaches the client byte-exact in NEW_CONNECTION_ID.

Every harness test ends with `_ = h.slot_count()` (ASAP destruction).
"""

from tests._test_util import assert_true, assert_equal_int
from tests.h3._udp_server_harness import UdpServerHarness, HarnessClient
from tests.h3.test_h3_udp_server import BigHandler, make_big_handler, _params


def test_connections_of_one_server_share_the_key() raises:
    var h = UdpServerHarness[BigHandler](make_big_handler, _params(), _params())
    var c1 = h.new_client()
    var c2 = h.new_client()
    assert_true(h.handshake(c1), "handshake 1")
    assert_true(h.handshake(c2), "handshake 2")
    assert_equal_int(h.slot_count(), 2, "two connections")
    var probe: List[Byte] = [1, 2, 3, 4, 5, 6, 7, 8]
    ref m0 = h.server_conn(0)[]._h3._quic.cid_mgr
    ref m1 = h.server_conn(1)[]._h3._quic.cid_mgr
    assert_true(Span(m0._reset_key) == Span(h.srv[]._reset_key), "slot 0 holds the server key")
    assert_true(Span(m1._reset_key) == Span(h.srv[]._reset_key), "slot 1 holds the server key")
    assert_true(
        m0.generate_reset_token(Span(probe)).as_span() == m1.generate_reset_token(Span(probe)).as_span(),
        "same CID, same token on both connections",
    )
    _ = c1^
    _ = c2^
    _ = h.slot_count()
    print("PASS: test_connections_of_one_server_share_the_key")


def test_two_servers_derive_different_tokens() raises:
    var h1 = UdpServerHarness[BigHandler](make_big_handler, _params(), _params())
    var h2 = UdpServerHarness[BigHandler](make_big_handler, _params(), _params())
    var c1 = h1.new_client()
    var c2 = h2.new_client()
    assert_true(h1.handshake(c1), "handshake 1")
    assert_true(h2.handshake(c2), "handshake 2")
    assert_true(Span(h1.srv[]._reset_key) != Span(h2.srv[]._reset_key), "keys differ")
    var probe: List[Byte] = [1, 2, 3, 4, 5, 6, 7, 8]
    ref m1 = h1.server_conn(0)[]._h3._quic.cid_mgr
    ref m2 = h2.server_conn(0)[]._h3._quic.cid_mgr
    assert_true(
        m1.generate_reset_token(Span(probe)).as_span() != m2.generate_reset_token(Span(probe)).as_span(),
        "same CID, different tokens across servers",
    )
    _ = c1^
    _ = c2^
    _ = h1.slot_count()
    _ = h2.slot_count()
    print("PASS: test_two_servers_derive_different_tokens")


def test_reset_key_is_not_the_retry_secret() raises:
    var h = UdpServerHarness[BigHandler](make_big_handler, _params(), _params())
    ref reset = h.srv[]._reset_key
    ref retry = h.srv[]._guard.value()._secret
    assert_true(
        Int(reset.unsafe_ptr()) != Int(retry.unsafe_ptr()), "distinct buffers"
    )
    assert_true(Span(reset)[:16] != Span(retry), "distinct values")
    var zero = InlineArray[UInt8, 32](fill=UInt8(0))
    assert_true(Span(reset) != Span(zero), "reset key drawn")
    _ = h.slot_count()
    print("PASS: test_reset_key_is_not_the_retry_secret")


def test_new_connection_id_carries_the_token() raises:
    """Each server-issued CID reaches the client with the server's token, byte-exact."""
    var h = UdpServerHarness[BigHandler](make_big_handler, _params(), _params())
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    for _ in range(3):
        _ = h.pump(c)
    ref srv_mgr = h.server_conn(0)[]._h3._quic.cid_mgr
    var checked = 0
    for ref r in c.h3._quic.cid_mgr.remote_cids:
        if r.sequence == UInt64(0):
            continue
        var found = False
        for ref l in srv_mgr.local_cids:
            if l.sequence != r.sequence:
                continue
            found = True
            assert_true(r.cid.as_span() == l.cid.as_span(), "CID round-trips")
            assert_true(r.reset_token.as_span() == l.reset_token.as_span(), "token round-trips")
            assert_true(
                r.reset_token.as_span() == srv_mgr.generate_reset_token(l.cid.as_span()).as_span(),
                "token is the server key's HMAC of the CID",
            )
        assert_true(found, "client CID seq " + String(r.sequence) + " issued by the server")
        checked += 1
    assert_true(checked > 0, "the client received at least one NEW_CONNECTION_ID")
    _ = c^
    _ = h.slot_count()
    print("PASS: test_new_connection_id_carries_the_token")


def main() raises:
    test_connections_of_one_server_share_the_key()
    test_two_servers_derive_different_tokens()
    test_reset_key_is_not_the_retry_secret()
    test_new_connection_id_carries_the_token()
