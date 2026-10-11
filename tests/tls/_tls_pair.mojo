# tests/tls/_tls_pair.mojo
"""In-memory TLS pair helpers for the boundary suites (no sockets)."""
from std.collections import Span
from navette.tls import TlsConnection
from tests._test_util import assert_true


def tls_handshake(mut client: TlsConnection, mut server: TlsConnection) raises:
    """Shuttle whole ciphertext buffers until both sides finish (100 rounds max)."""
    for _ in range(100):
        if not client.is_handshaking() and not server.is_handshaking():
            return
        var c2s = client.drain_ciphertext()
        if len(c2s) > 0:
            server.receive_data(Span(c2s))
        var s2c = server.drain_ciphertext()
        if len(s2c) > 0:
            client.receive_data(Span(s2c))
    assert_true(False, "TLS handshake did not finish in 100 rounds")


def sealed(mut sender: TlsConnection, data: List[Byte]) raises -> List[Byte]:
    """Ciphertext for `data`, encrypted in 16 KiB slices (works on every navette version)."""
    var ct = List[Byte]()
    var off = 0
    while off < len(data):
        var end = min(off + 16384, len(data))
        sender.send_data(Span(data)[off:end])
        sender.drain_ciphertext_into(ct)
        off = end
    return ct^


def sealed_records(
    mut sender: TlsConnection, data: List[Byte], layout: List[Int],
) raises -> List[Byte]:
    """Ciphertext whose records carry exactly `layout` plaintext bytes each.

    One `send_data` per record and a single drain at the end, so the records
    queue up back to back as a peer would emit them. `layout` must sum to
    `len(data)` and every entry must be at most 16 KiB.
    """
    var off = 0
    for i in range(len(layout)):
        sender.send_data(Span(data)[off:off + layout[i]])
        off += layout[i]
    assert_true(off == len(data), "layout does not cover the payload")
    return sender.drain_ciphertext()
