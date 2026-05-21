# tests/test_interop_file_io.mojo
#
# Unit tests for interop/file_io.mojo
# Run with: uv run mojo run -I . tests/test_interop_file_io.mojo

from interop.file_io import read_file, write_file, mkdir_p, list_dir, getenv, getenv_opt, setenv, basename
from tests._test_util import assert_true, assert_equal_int


# ── helpers ───────────────────────────────────────────────────────────────────


def _make_data(size: Int, seed: Int = 0) -> List[UInt8]:
    """Build a deterministic byte list of the given size."""
    var result = List[UInt8](capacity=size)
    for i in range(size):
        result.append(UInt8((i + seed) % 256))
    return result^


# ── test_write_and_read_file ──────────────────────────────────────────────────


def test_write_and_read_file() raises:
    var size = 256
    var data = _make_data(size)
    write_file("/tmp/mojo_test_rw.bin", Span(data))
    var got = read_file("/tmp/mojo_test_rw.bin")
    assert_equal_int(len(got), size, "read length")
    for i in range(size):
        assert_equal_int(Int(got[i]), Int(data[i]), "byte " + String(i))
    print("PASS test_write_and_read_file")


# ── test_read_large_file ──────────────────────────────────────────────────────


def test_read_large_file() raises:
    var size = 1024 * 1024  # 1 MB
    var data = _make_data(size, seed=7)
    write_file("/tmp/mojo_test_large.bin", Span(data))
    var got = read_file("/tmp/mojo_test_large.bin")
    assert_equal_int(len(got), size, "large read length")
    assert_equal_int(Int(got[0]), Int(data[0]), "first byte")
    assert_equal_int(Int(got[size - 1]), Int(data[size - 1]), "last byte")
    assert_equal_int(Int(got[65535]), Int(data[65535]), "boundary byte 65535")
    assert_equal_int(Int(got[65536]), Int(data[65536]), "boundary byte 65536")
    print("PASS test_read_large_file")


# ── test_mkdir_p ──────────────────────────────────────────────────────────────


def test_mkdir_p() raises:
    var dir = "/tmp/mojo_test_mkdir_p_a/b/c"
    mkdir_p(dir)
    # Write a file inside the nested directory
    var path = "/tmp/mojo_test_mkdir_p_a/b/c/hello.bin"
    var data = List[UInt8]()
    data.append(0xAB); data.append(0xCD)
    write_file(path, Span(data))
    var got = read_file(path)
    assert_equal_int(len(got), 2, "mkdir_p file length")
    assert_equal_int(Int(got[0]), 0xAB, "mkdir_p byte 0")
    assert_equal_int(Int(got[1]), 0xCD, "mkdir_p byte 1")
    print("PASS test_mkdir_p")


# ── test_list_dir ─────────────────────────────────────────────────────────────


def test_list_dir() raises:
    var dir = "/tmp/mojo_test_listdir2"
    mkdir_p(dir)
    # Create two known files
    var empty = List[UInt8]()
    write_file(dir + "/alpha.txt", Span(empty))
    write_file(dir + "/beta.txt", Span(empty))
    var names = list_dir(dir)
    var found_alpha = False
    var found_beta = False
    for i in range(len(names)):
        if names[i] == "alpha.txt":
            found_alpha = True
        if names[i] == "beta.txt":
            found_beta = True
    assert_true(found_alpha, "list_dir found alpha.txt")
    assert_true(found_beta, "list_dir found beta.txt")
    print("PASS test_list_dir")


# ── test_setenv_getenv ────────────────────────────────────────────────────────


def test_setenv_getenv() raises:
    setenv("MOJO_TEST_VAR_42", "hello_mojo")
    var val = getenv("MOJO_TEST_VAR_42")
    assert_true(val == "hello_mojo", "getenv value matches")
    print("PASS test_setenv_getenv")


# ── test_getenv_opt_missing ───────────────────────────────────────────────────


def test_getenv_opt_missing() raises:
    var opt = getenv_opt("MOJO_TEST_DEFINITELY_NOT_SET_XYZ_12345")
    assert_true(not opt.__bool__(), "getenv_opt missing returns None")
    print("PASS test_getenv_opt_missing")


# ── test_basename ─────────────────────────────────────────────────────────────


def test_basename() raises:
    assert_true(basename("/path/to/file.txt") == "file.txt", "nested path")
    assert_true(basename("/file.txt") == "file.txt", "root file")
    assert_true(basename("file.txt") == "file.txt", "no slash")
    assert_true(basename("/a/b/c") == "c", "no extension")
    print("PASS test_basename")


# ── main ──────────────────────────────────────────────────────────────────────


def main() raises:
    test_write_and_read_file()
    test_read_large_file()
    test_mkdir_p()
    test_list_dir()
    test_setenv_getenv()
    test_getenv_opt_missing()
    test_basename()
    print("All tests passed.")
