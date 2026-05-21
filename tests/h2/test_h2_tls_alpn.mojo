# tests/test_h2_tls_alpn.mojo
#
# Verify TLS ALPN negotiation works correctly for HTTP/2 and HTTP/1.1.
#
# Uses in-process TLS roundtrip (no sockets) with the self-signed test cert
# in crates/librustls-mojo/testdata/. Requires librustls_mojo.so built with
# `--features insecure`.
from navette.tls import RustlsLibrary, TlsClientConfig, TlsServerConfig, TlsConnection
from tests._test_util import assert_true, assert_equal_str
from std.memory import Span
from std.io.file import FileHandle


def _read_file(path: String) raises -> List[UInt8]:
    """Read a file into a byte list using native Mojo file I/O."""
    var fh = FileHandle(path, "r")
    var bytes = fh.read_bytes()
    fh.close()
    return bytes^


def _shuttle(mut client: TlsConnection, mut server: TlsConnection) raises -> Int:
    """Bounce ciphertext client->server and server->client.

    Returns total bytes transferred this iteration.
    """
    var total = 0

    var c2s = client.drain_ciphertext()
    if len(c2s) > 0:
        server.receive_data(Span(c2s))
        total += len(c2s)

    var s2c = server.drain_ciphertext()
    if len(s2c) > 0:
        client.receive_data(Span(s2c))
        total += len(s2c)

    return total


def _do_handshake(mut client: TlsConnection, mut server: TlsConnection) raises:
    """Complete the TLS handshake between client and server."""
    var iterations = 0
    while client.is_handshaking() or server.is_handshaking():
        var transferred = _shuttle(client, server)
        iterations += 1
        if transferred == 0:
            raise "handshake stalled at iteration " + String(iterations)
        assert_true(
            iterations < 100,
            "handshake did not complete in 100 iterations",
        )
    assert_true(not client.is_handshaking(), "client handshake complete")
    assert_true(not server.is_handshaking(), "server handshake complete")


def test_alpn_h2_negotiated() raises:
    """Both sides offer [h2, http/1.1] — h2 should be negotiated."""
    var lib = RustlsLibrary()

    var cert_pem = _read_file("crates/librustls-mojo/testdata/server.crt")
    var key_pem = _read_file("crates/librustls-mojo/testdata/server.key")

    var cli_cfg = TlsClientConfig(lib, insecure=True)
    var srv_cfg = TlsServerConfig(lib, Span(cert_pem), Span(key_pem))

    # Set ALPN on both sides: prefer h2
    var alpn_list = List[String]()
    alpn_list.append("h2")
    alpn_list.append("http/1.1")
    cli_cfg.set_alpn_protocols(lib, alpn_list)
    srv_cfg.set_alpn_protocols(lib, alpn_list)

    var client = TlsConnection.new_client(lib, cli_cfg, "localhost")
    var server = TlsConnection.new_server(lib, srv_cfg)

    # Complete the handshake
    _do_handshake(client, server)

    # Both sides should report h2 as the negotiated protocol
    var client_alpn = client.alpn()
    assert_true(Bool(client_alpn), "client should have negotiated ALPN")
    assert_equal_str(client_alpn.value(), "h2", "client ALPN should be h2")

    var server_alpn = server.alpn()
    assert_true(Bool(server_alpn), "server should have negotiated ALPN")
    assert_equal_str(server_alpn.value(), "h2", "server ALPN should be h2")

    # RAII cleanup: connections first, then configs, then lib
    _ = client^
    _ = server^
    _ = cli_cfg^
    _ = srv_cfg^
    _ = lib^


def test_alpn_fallback_h1() raises:
    """Client offers [h2, http/1.1], server only offers [http/1.1] — should fall back to http/1.1."""
    var lib = RustlsLibrary()

    var cert_pem = _read_file("crates/librustls-mojo/testdata/server.crt")
    var key_pem = _read_file("crates/librustls-mojo/testdata/server.key")

    var cli_cfg = TlsClientConfig(lib, insecure=True)
    var srv_cfg = TlsServerConfig(lib, Span(cert_pem), Span(key_pem))

    # Client prefers h2, server only supports http/1.1
    var client_protos = List[String]()
    client_protos.append("h2")
    client_protos.append("http/1.1")
    cli_cfg.set_alpn_protocols(lib, client_protos)

    var server_protos = List[String]()
    server_protos.append("http/1.1")
    srv_cfg.set_alpn_protocols(lib, server_protos)

    var client = TlsConnection.new_client(lib, cli_cfg, "localhost")
    var server = TlsConnection.new_server(lib, srv_cfg)

    # Complete the handshake
    _do_handshake(client, server)

    # Both sides should report http/1.1 as the negotiated protocol
    var client_alpn = client.alpn()
    assert_true(Bool(client_alpn), "client should have negotiated ALPN")
    assert_equal_str(
        client_alpn.value(),
        "http/1.1",
        "client ALPN should be http/1.1",
    )

    var server_alpn = server.alpn()
    assert_true(Bool(server_alpn), "server should have negotiated ALPN")
    assert_equal_str(
        server_alpn.value(),
        "http/1.1",
        "server ALPN should be http/1.1",
    )

    # RAII cleanup
    _ = client^
    _ = server^
    _ = cli_cfg^
    _ = srv_cfg^
    _ = lib^


def main() raises:
    var passed = 0
    var total = 0

    total += 1
    try:
        test_alpn_h2_negotiated()
        print("PASS: test_alpn_h2_negotiated")
        passed += 1
    except e:
        print("FAIL: test_alpn_h2_negotiated:", String(e))

    total += 1
    try:
        test_alpn_fallback_h1()
        print("PASS: test_alpn_fallback_h1")
        passed += 1
    except e:
        print("FAIL: test_alpn_fallback_h1:", String(e))

    print("")
    print(
        "test_h2_tls_alpn: "
        + String(passed)
        + "/"
        + String(total)
        + " passed"
    )
    if passed != total:
        raise "some ALPN tests failed"
