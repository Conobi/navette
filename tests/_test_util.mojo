# tests/_test_util.mojo
#
# Shared helpers for the production test suite (`tests/`).
# Imported by every test file in tests/ to avoid drift across files.

def load_test_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    """Load the baked P-256 self-signed test cert + key from `tests/fixtures/tls/`.

    Returns `(cert_pem, key_pem)`. Replaces per-test `cryptography.x509`
    cert-gen blocks — see plans/2026-05-13-deps-enhancement.md §3.1.
    The fixture is regenerable via `scripts/regen_test_certs.sh`.
    """
    var crt = FileHandle("tests/fixtures/tls/server.crt", "r")
    var key = FileHandle("tests/fixtures/tls/server.key", "r")
    var cert_bytes = crt.read_bytes()
    var key_bytes = key.read_bytes()
    crt.close()
    key.close()
    return (cert_bytes^, key_bytes^)


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
