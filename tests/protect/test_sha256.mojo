"""SHA-256: FIPS 180-4 vectors plus a differential property against Python's hashlib."""

from std.python import Python

from navette.util.sha256 import sha256
from tests._test_util import assert_true, assert_equal_str
from tests.protect._prop import Rng


def _hex(d: InlineArray[UInt8, 32]) -> String:
    var digits = "0123456789abcdef"
    var s = String("")
    for i in range(32):
        s += digits[byte=Int(d[i] >> 4)]
        s += digits[byte=Int(d[i] & 0x0F)]
    return s^


def _bytes(s: String) -> List[Byte]:
    var out = List[Byte]()
    out.extend(s.as_bytes())
    return out^


def test_fips_vectors() raises:
    var empty = List[Byte]()
    assert_equal_str(_hex(sha256(Span(empty))), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty")
    var abc = _bytes("abc")
    assert_equal_str(_hex(sha256(Span(abc))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc")
    var two = _bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    assert_equal_str(_hex(sha256(Span(two))), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "448-bit")
    print("PASS: test_fips_vectors")


def test_padding_boundary_lengths() raises:
    """Message bytes i & 0xFF at every padding boundary; digests from Python hashlib."""
    var lens = [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128]
    var want = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59",
        "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562",
        "2fe741af801cc238602ac0ec6a7b0c3a8a87c7fc7d7f02a3fe03d1c12eac4d8f",
        "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488",
        "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
        "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781",
        "da18797ed7c3a777f0847f429724a2d8cd5138e6ed2895c3fa1a6d39d18f7ec6",
        "f52b23db1fbb6ded89ef42a23ce0c8922c45f25c50b568a93bf1c075420bbb7c",
        "92ca0fa6651ee2f97b884b7246a562fa71250fedefe5ebf270d31c546bfea976",
        "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5",
    ]
    for i in range(len(lens)):
        var m = List[Byte](capacity=lens[i])
        for j in range(lens[i]):
            m.append(Byte(j & 0xFF))
        assert_equal_str(_hex(sha256(Span(m))), want[i], "len " + String(lens[i]))
    print("PASS: test_padding_boundary_lengths")


def test_matches_hashlib_property() raises:
    """400 random messages of 0..200 bytes (every padding branch) match hashlib."""
    var hashlib = Python.import_module("hashlib")
    var builtins = Python.import_module("builtins")
    var rng = Rng(0x5A256)
    for ci in range(400):
        var m = rng.bytes(rng.below(201))
        var py_list = builtins.list()
        for i in range(len(m)):
            py_list.append(Int(m[i]))
        var want = String(hashlib.sha256(builtins.bytes(py_list)).hexdigest())
        assert_equal_str(_hex(sha256(Span(m))), want, "case " + String(ci) + " len " + String(len(m)))
    print("PASS: test_matches_hashlib_property")


def main() raises:
    test_fips_vectors()
    test_padding_boundary_lengths()
    test_matches_hashlib_property()
