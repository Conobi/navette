"""Reserved header bits are checked only after a packet authenticates (RFC 9000 Section 17.2).

Before header protection is removed with the right keys, the reserved
bits of a forged packet are random: checking them first let any sender
who knows a connection's DCID close it with PROTOCOL_VIOLATION about one
packet in four.
"""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import default_transport_params
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca
from tests.protect._prop import Rng


def _send_all(mut conn: QuicConnection, now: UInt64) raises -> List[List[Byte]]:
    var out = List[List[Byte]]()
    for _ in range(16):
        var batch = List[List[Byte]]()
        if conn.send(now, batch) == 0:
            break
        for ref d in batch:
            out.append(d.copy())
    return out^


def test_forged_initials_never_close() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert = ck[0].copy()
    var key = ck[1].copy()
    var ca = load_test_ca()
    var scfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
    var ccfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(tls.shared(), ccfg, "localhost", default_transport_params(), now)
    var first = _send_all(client, now)
    var orig = List[Byte](client.initial_dcid.as_span())
    var orig2 = orig.copy()
    var server = QuicConnection.server(tls.shared(), scfg, default_transport_params(), Span(orig), Span(orig2), now)
    for ref d in first:
        server.recv(Span(d), now)
    # Same header as the genuine Initial, random bytes from the packet number on.
    var hdr_len = 6 + len(orig) + 1 + len(client.local_cid) + 1 + 2
    var rng = Rng(UInt64(0x5E5E))
    for i in range(24):
        var forged = first[0].copy()
        for j in range(hdr_len, len(forged)):
            forged[j] = Byte(rng.next() & 0xFF)
        try:
            server.recv(Span(forged), now)
        except:
            pass
        assert_true(not server.close.pending, "forged Initial " + String(i) + " closed the connection")
    _ = tls^
    print("  test_forged_initials_never_close: PASS")


def main() raises:
    print("test_quic_reserved_bits_after_decrypt:")
    test_forged_initials_never_close()
    print("PASS: test_quic_reserved_bits_after_decrypt")
