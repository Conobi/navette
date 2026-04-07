# tests/test_tls_connection.mojo
#
# In-process TLS roundtrip test (no sockets).
#
# Mirrors crates/librustls-mojo/tests/test_tcp.rs but exercises the safe
# Mojo wrappers from src/tls/. Uses an insecure client config to accept
# the self-signed test cert in crates/librustls-mojo/testdata/.
#
# Requires librustls_mojo.so built with `--features insecure`.
from src.tls import RustlsLibrary, TlsClientConfig, TlsServerConfig, TlsConnection
from tests._test_util import assert_true, assert_equal_int, assert_equal_str
from std.memory import Span
from std.io.file import FileHandle


def _read_file(path: String) raises -> List[UInt8]:
    """Read a file into a byte list using native Mojo file I/O."""
    var fh = FileHandle(path, "r")
    var bytes = fh.read_bytes()
    fh.close()
    return bytes^


def _bytes_to_string(bytes: List[UInt8]) -> String:
    """Convert a List[UInt8] to a String (assumes ASCII content)."""
    var s = String()
    for i in range(len(bytes)):
        s += chr(Int(bytes[i]))
    return s^


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


def test_handshake_and_data_roundtrip() raises:
    """Complete TLS handshake + plaintext exchange without sockets."""
    var lib = RustlsLibrary()

    var cert_pem = _read_file("crates/librustls-mojo/testdata/server.crt")
    var key_pem = _read_file("crates/librustls-mojo/testdata/server.key")

    var cli_cfg = TlsClientConfig(lib, insecure=True)
    var srv_cfg = TlsServerConfig(lib, Span(cert_pem), Span(key_pem))

    var client = TlsConnection.new_client(lib, cli_cfg, "localhost")
    var server = TlsConnection.new_server(lib, srv_cfg)

    # Client should have ClientHello buffered immediately after construction.
    assert_true(client.wants_write(), "client should have ClientHello buffered")
    assert_true(client.is_handshaking(), "client should be handshaking")
    assert_true(server.is_handshaking(), "server should be handshaking")

    # -- Run the handshake --
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

    # -- Client sends plaintext --
    var msg = String("Hello from Mojo!")
    var msg_bytes = msg.as_bytes()
    client.send_data(Span(msg_bytes))

    var ct = client.drain_ciphertext()
    assert_true(len(ct) > 0, "client should produce ciphertext after send_data")
    server.receive_data(Span(ct))

    var plaintext = server.drain_plaintext()
    assert_true(len(plaintext) > 0, "server should have plaintext available")

    var received = _bytes_to_string(plaintext)
    assert_equal_str(received, msg, "server received client message")

    # -- Server sends reply --
    var reply = String("Hello back!")
    var reply_bytes = reply.as_bytes()
    server.send_data(Span(reply_bytes))

    var ct2 = server.drain_ciphertext()
    assert_true(len(ct2) > 0, "server should produce ciphertext after send_data")
    client.receive_data(Span(ct2))

    var pt2 = client.drain_plaintext()
    assert_true(len(pt2) > 0, "client should have reply plaintext")

    var reply_received = _bytes_to_string(pt2)
    assert_equal_str(reply_received, reply, "client received server reply")

    # -- RAII cleanup: connections first, then configs, then lib --
    _ = client^
    _ = server^
    _ = cli_cfg^
    _ = srv_cfg^
    _ = lib^


def test_is_handshaking_before_handshake() raises:
    """Newly created connections report is_handshaking() == True."""
    var lib = RustlsLibrary()
    var cert_pem = _read_file("crates/librustls-mojo/testdata/server.crt")
    var key_pem = _read_file("crates/librustls-mojo/testdata/server.key")

    var cli_cfg = TlsClientConfig(lib, insecure=True)
    var srv_cfg = TlsServerConfig(lib, Span(cert_pem), Span(key_pem))

    var client = TlsConnection.new_client(lib, cli_cfg, "localhost")
    var server = TlsConnection.new_server(lib, srv_cfg)

    assert_true(client.is_handshaking(), "fresh client is handshaking")
    assert_true(server.is_handshaking(), "fresh server is handshaking")

    _ = client^
    _ = server^
    _ = cli_cfg^
    _ = srv_cfg^
    _ = lib^


def test_wants_write_after_construction() raises:
    """Client buffers ClientHello after construction; server has nothing yet."""
    var lib = RustlsLibrary()
    var cert_pem = _read_file("crates/librustls-mojo/testdata/server.crt")
    var key_pem = _read_file("crates/librustls-mojo/testdata/server.key")

    var cli_cfg = TlsClientConfig(lib, insecure=True)
    var srv_cfg = TlsServerConfig(lib, Span(cert_pem), Span(key_pem))

    var client = TlsConnection.new_client(lib, cli_cfg, "localhost")
    var server = TlsConnection.new_server(lib, srv_cfg)

    assert_true(client.wants_write(), "client wants_write (ClientHello)")
    assert_true(
        not server.wants_write(),
        "server has nothing to send before receiving ClientHello",
    )

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
        test_handshake_and_data_roundtrip()
        print("PASS: test_handshake_and_data_roundtrip")
        passed += 1
    except e:
        print("FAIL: test_handshake_and_data_roundtrip:", String(e))

    total += 1
    try:
        test_is_handshaking_before_handshake()
        print("PASS: test_is_handshaking_before_handshake")
        passed += 1
    except e:
        print("FAIL: test_is_handshaking_before_handshake:", String(e))

    total += 1
    try:
        test_wants_write_after_construction()
        print("PASS: test_wants_write_after_construction")
        passed += 1
    except e:
        print("FAIL: test_wants_write_after_construction:", String(e))

    print("")
    print("test_tls_connection: " + String(passed) + "/" + String(total) + " passed")
    if passed != total:
        raise "some tls tests failed"
