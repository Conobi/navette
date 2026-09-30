"""A client whose address changes mid-connection (NAT rebinding) keeps being served at the new address (RFC 9000 Section 9).

The server validates the new address with a PATH_CHALLENGE sent there and,
once answered, serves it in full; the old address gets nothing.

Every harness test ends with `_ = h.slot_count()` (ASAP destruction).
"""

from bouclette import Socket

from tests._test_util import assert_true, assert_equal_int
from tests.h3._udp_server_harness import UdpServerHarness, HarnessClient
from tests.h3.test_h3_udp_server import (
    BigHandler,
    make_big_handler,
    BIG_BODY_BYTES,
    _params,
    _send_get,
)


def test_rebind_serves_new_address() raises:
    """With no spare CID of the client's left on the server: validation still completes and the body reaches the new address only."""
    var h = UdpServerHarness[BigHandler](make_big_handler, _params(), _params())
    var c = h.new_client()
    assert_true(h.handshake(c), "handshake")
    for _ in range(3):
        _ = h.pump(c)
    # Retire the client's spare CIDs on the server: rotation is impossible,
    # as with a zero-length or exhausted CID set.
    var conn = h.server_conn(0)
    var i = 0
    while i < len(conn[]._h3._quic.cid_mgr.remote_cids):
        if conn[]._h3._quic.cid_mgr.remote_cids[i].sequence != conn[]._h3._quic.cid_mgr.remote_active_cid_seq:
            _ = conn[]._h3._quic.cid_mgr.remote_cids.pop(i)
        else:
            i += 1
    assert_equal_int(len(conn[]._h3._quic.cid_mgr.remote_cids), 1, "server holds no spare CID")
    # Rebind: from now on the client sends and receives on a fresh socket.
    var old = h.new_socket()
    swap(old, c.sock)
    _ = h.recv_raw(old, 0)
    _ = _send_get(c)
    var start = c.recv_bytes
    var at_old = 0
    for _ in range(150):
        _ = h.pump(c)
        for ref d in h.recv_raw(old, 0):
            at_old += len(d)
        if c.recv_bytes - start >= BIG_BODY_BYTES:
            break
    var got = c.recv_bytes - start
    assert_true(got >= BIG_BODY_BYTES, "the body reaches the new address; got " + String(got))
    assert_equal_int(at_old, 0, "nothing goes to the old address")
    assert_equal_int(len(h.server_conn(0)[]._h3._quic.path.validator.pending), 0, "validation completed")
    _ = old^
    _ = c^
    _ = h.slot_count()
    print("PASS: test_rebind_serves_new_address")


def main() raises:
    test_rebind_serves_new_address()
