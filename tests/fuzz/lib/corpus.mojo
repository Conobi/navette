# tests/fuzz/lib/corpus.mojo
#
# Corpus loader + disagreement saver for fuzz harnesses.
#
# Mojo 0.26.2 has no stdlib directory iterator and no std.hash.sha256, so this
# module uses Python interop (glob, hashlib, builtins.open). These runtime
# Python calls are SCOPED TO TEST INFRASTRUCTURE — they file-system mediate
# between harness and disk corpus. The §3.3 dependency-enhancement rule that
# prohibits live Python oracles at test time applies to the parser oracle
# layer, NOT to harness-level file I/O.

from std.python import Python


struct CorpusEntry(Copyable, Movable):
    var bytes: List[UInt8]
    var name: String

    def __init__(out self, var bytes: List[UInt8], name: String):
        self.bytes = bytes^
        self.name = name

    def __init__(out self, *, deinit take: Self):
        self.bytes = take.bytes^
        self.name = take.name^


def _read_bytes(path: String) raises -> List[UInt8]:
    var builtins = Python.import_module("builtins")
    var f = builtins.open(path, "rb")
    var py_data = f.read()
    f.close()
    var n = Int(py=builtins.len(py_data))
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8(Int(py=py_data[i])))
    return out^


def _write_bytes(path: String, b: List[UInt8]) raises:
    var builtins = Python.import_module("builtins")
    var f = builtins.open(path, "wb")
    # Build a Python bytes object byte-by-byte.
    var py_list = builtins.bytearray()
    for i in range(len(b)):
        py_list.append(Int(b[i]))
    f.write(builtins.bytes(py_list))
    f.close()


def _write_text(path: String, s: String) raises:
    var builtins = Python.import_module("builtins")
    var f = builtins.open(path, "w")
    f.write(s)
    f.close()


def _ensure_dir(path: String) raises:
    var os = Python.import_module("os")
    os.makedirs(path, exist_ok=True)


def _sha256_hex12(b: List[UInt8]) raises -> String:
    var hashlib = Python.import_module("hashlib")
    var builtins = Python.import_module("builtins")
    var py_list = builtins.bytearray()
    for i in range(len(b)):
        py_list.append(Int(b[i]))
    var py_bytes = builtins.bytes(py_list)
    var digest = hashlib.sha256(py_bytes).hexdigest()
    var s = String(digest)
    # First 12 hex chars
    var bs = s.as_bytes()
    var out = String("")
    for i in range(min(12, len(bs))):
        out += chr(Int(bs[i]))
    return out


def load_corpus_dir(path: String) raises -> List[CorpusEntry]:
    """Load every `*.bin` file from `path` as a CorpusEntry, sorted by name."""
    var glob = Python.import_module("glob")
    var os = Python.import_module("os")
    var builtins = Python.import_module("builtins")
    var out = List[CorpusEntry]()
    if not Bool(os.path.isdir(path)):
        return out^
    var py_paths = builtins.sorted(glob.glob(path + "/*.bin"))
    var n = Int(py=builtins.len(py_paths))
    for i in range(n):
        var p = String(py_paths[i])
        var bs = _read_bytes(p)
        var name = String(os.path.basename(p))
        out.append(CorpusEntry(bs^, name))
    return out^


def save_disagreement(
    harness: String,
    seed: UInt64,
    input: List[UInt8],
    observed_a: String,
    observed_b: String,
) raises -> String:
    """Save a disagreement-discovery to conformance/fuzz/corpus/<harness>/.

    Writes `<seed:hex>-<sha256[:12]>.bin` (the input bytes) and a sibling
    `.txt` file with the two observed outputs. Returns the bin file path.
    """
    var dir = String("conformance/fuzz/corpus/") + harness
    _ensure_dir(dir)
    var hash12 = _sha256_hex12(input)
    var seed_hex = hex(Int(seed))  # Mojo builtin
    var stem = dir + "/" + seed_hex + "-" + hash12
    var bin_path = stem + ".bin"
    var txt_path = stem + ".txt"
    _write_bytes(bin_path, input)
    var report = String("harness: ") + harness + String("\n")
    report += String("seed: 0x") + hex(Int(seed)) + String("\n")
    report += String("input_len: ") + String(len(input)) + String("\n")
    report += String("observed_a: ") + observed_a + String("\n")
    report += String("observed_b: ") + observed_b + String("\n")
    _write_text(txt_path, report)
    return bin_path
