from python import Python, PythonObject


def hex_decode(s: String) raises -> List[UInt8]:
    """Decode a hex string like '7fff' into bytes."""
    var result = List[UInt8]()
    var hex_str = s
    if len(hex_str) % 2 != 0:
        raise "hex string must have even length, got: " + hex_str

    # Convert string to bytes first
    var bytes = hex_str.as_bytes()

    var i = 0
    while i < len(bytes):
        var c1 = bytes[i]
        var c2 = bytes[i + 1]

        var v1 = _hex_byte_value(c1)
        var v2 = _hex_byte_value(c2)
        result.append(UInt8(v1 * 16 + v2))
        i += 2

    return result^


def _hex_byte_value(b: UInt8) raises -> Int:
    """Convert a hex byte (0-9, a-f, A-F) to its value."""
    if b >= UInt8(ord("0")) and b <= UInt8(ord("9")):
        return Int(b) - ord("0")
    if b >= UInt8(ord("a")) and b <= UInt8(ord("f")):
        return Int(b) - ord("a") + 10
    if b >= UInt8(ord("A")) and b <= UInt8(ord("F")):
        return Int(b) - ord("A") + 10
    raise "invalid hex byte"


def hex_encode(buf: List[UInt8]) -> String:
    """Encode bytes to a lowercase hex string, zero-padded."""
    var chars = "0123456789abcdef"
    var result = String()
    for i in range(len(buf)):
        var b = Int(buf[i])
        var idx1 = (b >> 4) & 0xF
        var idx2 = b & 0xF

        # Get character at idx1
        var j = 0
        for cp in chars.codepoint_slices():
            if j == idx1:
                result += cp
                break
            j += 1

        # Get character at idx2
        j = 0
        for cp in chars.codepoint_slices():
            if j == idx2:
                result += cp
                break
            j += 1

    return result^


def load_vectors(path: String) raises -> PythonObject:
    """Load a JSON test vector file. Returns a Python list of dicts."""
    var json = Python.import_module("json")
    var builtins = Python.import_module("builtins")
    var f = builtins.open(path, "r")
    var data = json.load(f)
    f.close()
    return data


def assert_true(cond: Bool, msg: String) raises:
    """Unconditional assertion. Always raises on failure, unlike debug_assert."""
    if not cond:
        print("ASSERTION FAILED: " + msg)
        raise "assertion failed: " + msg


def assert_equal(got: Int, expected: Int, msg: String) raises:
    """Assert two integers are equal. Always raises on failure."""
    if got != expected:
        print(
            "ASSERTION FAILED ["
            + msg
            + "]: got "
            + String(got)
            + " expected "
            + String(expected)
        )
        raise "assertion failed: " + msg


def assert_bytes_equal(
    got: List[UInt8], expected: List[UInt8], name: String
) raises:
    """Assert two byte lists are equal. On failure, print hex diff."""
    if len(got) != len(expected):
        print(
            "FAIL ["
            + name
            + "]: length mismatch: got "
            + String(len(got))
            + " bytes, expected "
            + String(len(expected))
            + " bytes"
        )
        print("  expected: " + hex_encode(expected))
        print("  got:      " + hex_encode(got))
        raise "assertion failed: " + name

    for i in range(len(got)):
        if got[i] != expected[i]:
            print(
                "FAIL ["
                + name
                + "]: first diff at byte "
                + String(i)
            )
            print("  expected: " + hex_encode(expected))
            print("  got:      " + hex_encode(got))
            raise "assertion failed: " + name
