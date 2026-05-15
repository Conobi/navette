# tests/_test_util.mojo
#
# Shared helpers for the production test suite (`tests/`).
# Imported by every test file in tests/ to avoid drift across files.

def load_test_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    """Load the baked P-256 server leaf cert + key from `tests/fixtures/tls/`.

    Returns `(leaf_cert_pem, leaf_key_pem)` — the leaf signed by the test
    CA. Pair with `load_test_ca()` for the client's trust root: modern
    rustls/webpki refuses a CA-marked cert as a TLS end-entity, so server
    identity and trust anchor must be different certs.

    Fixtures regenerable via `scripts/regen_test_certs.sh`.
    """
    var crt = FileHandle("tests/fixtures/tls/server.crt", "r")
    var key = FileHandle("tests/fixtures/tls/server.key", "r")
    var cert_bytes = crt.read_bytes()
    var key_bytes = key.read_bytes()
    crt.close()
    key.close()
    return (cert_bytes^, key_bytes^)


def load_test_ca() raises -> List[UInt8]:
    """Load the baked test CA cert from `tests/fixtures/tls/ca.crt`.

    Pass these bytes to `quic_client_config_with_ca` (or any client trust
    setup) so the client trusts the issuer of the leaf returned by
    `load_test_cert()`.
    """
    var ca = FileHandle("tests/fixtures/tls/ca.crt", "r")
    var ca_bytes = ca.read_bytes()
    ca.close()
    return ca_bytes^


def assert_true(cond: Bool, msg: String) raises:
    """Assert a boolean condition; raise on failure with the given message."""
    if not cond:
        print("ASSERTION FAILED: " + msg)
        raise "assertion failed: " + msg


def assert_false(cond: Bool, msg: String) raises:
    """Assert a boolean condition is false; raise on failure."""
    if cond:
        print("ASSERTION FAILED: " + msg)
        raise "assertion failed: " + msg


def assert_equal_str(got: String, expected: String, msg: String) raises:
    """Assert two strings are equal; raise on mismatch."""
    if got != expected:
        print("ASSERTION FAILED [" + msg + "]: got '" + got + "' expected '" + expected + "'")
        raise "assertion failed: " + msg


def assert_equal_int(got: Int, expected: Int, msg: String) raises:
    """Assert two ints are equal; raise on mismatch."""
    if got != expected:
        print("ASSERTION FAILED [" + msg + "]: got " + String(got) + " expected " + String(expected))
        raise "assertion failed: " + msg
