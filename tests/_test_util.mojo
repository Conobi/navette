# tests/_test_util.mojo
#
# Shared assertion helpers for the production test suite (`tests/`).
# Imported by every test file in tests/ to avoid drift across files.


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
