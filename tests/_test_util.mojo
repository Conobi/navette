# tests/_test_util.mojo
#
# Shared helpers for the production test suite (`tests/`).
# Imported by every test file in tests/ to avoid drift across files.

from std.ffi import external_call
from std.memory.alloc import unsafe_alloc
from std.os import getenv, listdir, remove, rmdir
from std.os.path import isdir, islink


def _remove_tree(path: String):
    """Best-effort recursive delete; symlinks are unlinked, never followed."""
    try:
        if isdir(path) and not islink(path):
            for name in listdir(path):
                _remove_tree(path + "/" + name)
            rmdir(path)
        else:
            remove(path)
    except:
        pass


struct TempDir(Movable):
    """Private scratch directory, deleted recursively when the value dies.

    Made with `mkdtemp(3)` under `$TMPDIR` (else `/tmp`): unique, mode 0700 and
    owned by the caller, so no other user can pre-create or symlink-redirect its
    entries (CWE-377). Hold one per test as a local and end the test with
    `_ = td^`: Mojo destroys locals after their last use, so without it the
    directory could vanish early. It is also removed when the test raises.
    """

    var dir: String

    def __init__(out self) raises:
        var base = getenv("TMPDIR", "/tmp")
        while base.byte_length() > 1 and base.endswith("/"):
            var shorter = String(base[byte=: base.byte_length() - 1])
            base = shorter^
        var template = base + "/navette-test-XXXXXX"
        var tb = template.as_bytes()
        var buf = unsafe_alloc[UInt8](len(tb) + 1)
        for i in range(len(tb)):
            buf[unsafe_offset=i] = tb[i]
        buf[unsafe_offset=len(tb)] = 0  # mkdtemp needs a NUL terminator
        var rc = external_call["mkdtemp", Int](buf)
        if rc == 0:
            buf.unsafe_free()
            raise "mkdtemp failed for " + template
        var out = List[UInt8]()
        var j = 0
        while buf[unsafe_offset=j] != 0:
            out.append(buf[unsafe_offset=j])
            j += 1
        buf.unsafe_free()
        self.dir = String(from_utf8_lossy=out)

    def __deinit__(deinit self):
        _remove_tree(self.dir)

    def path(self, name: String) -> String:
        """Path of `name` inside the directory; the file is not created."""
        return self.dir + "/" + name

def load_test_cert() raises -> Tuple[List[Byte], List[Byte]]:
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


def load_test_ca() raises -> List[Byte]:
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
