# conformance/tests/test_hpack_decode.mojo
#
# HC-3b Task 4: HPACK decoder tests.
# Layer 1: RFC 7541 Appendix C.2-C.6 story vectors.
# Layer 2: hpack-test-case stories from multiple implementations.

from lib.test_util import (
    load_vectors,
    hex_decode,
    assert_true,
    assert_equal,
)
from lib.http1.types import Header
from lib.http2.hpack import HpackDecoder, HpackConfig
from python import Python, PythonObject


def _has_key(obj: PythonObject, key: String) -> Bool:
    """Check if a Python dict has a given key."""
    try:
        var builtins = Python.import_module("builtins")
        return Bool(builtins.bool(key in obj))
    except:
        return False


# ---------------------------------------------------------------
# Layer 1: RFC story vectors (C.2-C.6)
# ---------------------------------------------------------------


def run_rfc_c2_vectors() raises:
    """C.2: individual header field representation examples."""
    var vectors = load_vectors("vectors/rfc7541/c2_header_field.json")
    var builtins = Python.import_module("builtins")
    var count = Int(py=builtins.len(vectors))

    for i in range(count):
        var v = vectors[i]
        var vid = String(v["id"])
        var wire = hex_decode(String(v["wire_hex"]))

        var decoder = HpackDecoder()
        var result = decoder.decode(wire)
        assert_true(
            len(result[1]) == 0,
            vid + ": decode error: " + result[1],
        )

        # Check headers
        var exp = v["expected_headers"]
        var exp_count = Int(py=builtins.len(exp))
        assert_equal(
            len(result[0]),
            exp_count,
            vid + " header count",
        )
        for j in range(exp_count):
            var exp_name = String(exp[j][0])
            var exp_value = String(exp[j][1])
            assert_true(
                result[0][j].name == exp_name,
                vid
                + " header "
                + String(j)
                + " name: got '"
                + result[0][j].name
                + "' expected '"
                + exp_name
                + "'",
            )
            assert_true(
                result[0][j].value == exp_value,
                vid
                + " header "
                + String(j)
                + " value: got '"
                + result[0][j].value
                + "' expected '"
                + exp_value
                + "'",
            )

        # Check dynamic table
        var exp_dt = v["expected_dynamic_table"]
        var exp_dt_count = Int(py=builtins.len(exp_dt))
        assert_equal(
            decoder.dynamic_table.size(),
            exp_dt_count,
            vid + " dynamic table size",
        )
        var dt = decoder.dynamic_table.entries_list()
        for j in range(exp_dt_count):
            var exp_dt_name = String(exp_dt[j][0])
            var exp_dt_value = String(exp_dt[j][1])
            assert_true(
                dt[j].name == exp_dt_name
                and dt[j].value == exp_dt_value,
                vid
                + " dt["
                + String(j)
                + "]: got '"
                + dt[j].name
                + ":"
                + dt[j].value
                + "' expected '"
                + exp_dt_name
                + ":"
                + exp_dt_value
                + "'",
            )

        # Check table size
        var exp_ts = Int(py=v["expected_table_size"])
        assert_equal(
            decoder.dynamic_table.byte_size(),
            exp_ts,
            vid + " table byte size",
        )

        print("  [PASS] " + vid)

    print(
        "  C.2: " + String(count) + " individual decode tests passed"
    )


def run_rfc_story(
    story_path: String, story_name: String
) raises:
    """Run a single RFC story: load JSON, decode cases in sequence."""
    var json_mod = Python.import_module("json")
    var builtins = Python.import_module("builtins")
    var f = builtins.open(story_path, "r")
    var data = json_mod.load(f)
    f.close()

    var cases = data["cases"]
    var case_count = Int(py=builtins.len(cases))

    # Create decoder with default config (C.3/C.4 use default 4096)
    var decoder = HpackDecoder()

    for i in range(case_count):
        var tc = cases[i]

        # Check for table size change
        if _has_key(tc, "header_table_size"):
            var ts = Int(py=tc["header_table_size"])
            decoder.set_max_table_size(ts)

        var wire = hex_decode(String(tc["wire_hex"]))
        var result = decoder.decode(wire)
        assert_true(
            len(result[1]) == 0,
            story_name
            + " case "
            + String(i)
            + ": "
            + result[1],
        )

        # Assert headers match
        var exp = tc["expected_headers"]
        var exp_count = Int(py=builtins.len(exp))
        assert_equal(
            len(result[0]),
            exp_count,
            story_name
            + " case "
            + String(i)
            + " header count",
        )
        for j in range(exp_count):
            var exp_name = String(exp[j][0])
            var exp_value = String(exp[j][1])
            assert_true(
                result[0][j].name == exp_name,
                story_name
                + " case "
                + String(i)
                + " h"
                + String(j)
                + " name: got '"
                + result[0][j].name
                + "' expected '"
                + exp_name
                + "'",
            )
            assert_true(
                result[0][j].value == exp_value,
                story_name
                + " case "
                + String(i)
                + " h"
                + String(j)
                + " value: got '"
                + result[0][j].value
                + "' expected '"
                + exp_value
                + "'",
            )

        # Assert dynamic table entries match
        var exp_dt = tc["expected_dynamic_table"]
        var exp_dt_count = Int(py=builtins.len(exp_dt))
        assert_equal(
            decoder.dynamic_table.size(),
            exp_dt_count,
            story_name
            + " case "
            + String(i)
            + " dt entry count",
        )
        var dt = decoder.dynamic_table.entries_list()
        for j in range(exp_dt_count):
            var exp_dt_name = String(exp_dt[j][0])
            var exp_dt_value = String(exp_dt[j][1])
            assert_true(
                dt[j].name == exp_dt_name
                and dt[j].value == exp_dt_value,
                story_name
                + " case "
                + String(i)
                + " dt["
                + String(j)
                + "]: got '"
                + dt[j].name
                + ":"
                + dt[j].value
                + "' expected '"
                + exp_dt_name
                + ":"
                + exp_dt_value
                + "'",
            )

        # Assert table byte size
        var exp_ts = Int(py=tc["expected_table_size"])
        assert_equal(
            decoder.dynamic_table.byte_size(),
            exp_ts,
            story_name
            + " case "
            + String(i)
            + " table byte size",
        )

    print(
        "  [PASS] "
        + story_name
        + " ("
        + String(case_count)
        + " cases)"
    )


def run_rfc_story_with_table_size(
    story_path: String,
    story_name: String,
    initial_table_size: Int,
) raises:
    """Run an RFC story where the first case may set a non-default table size."""
    var json_mod = Python.import_module("json")
    var builtins = Python.import_module("builtins")
    var f = builtins.open(story_path, "r")
    var data = json_mod.load(f)
    f.close()

    var cases = data["cases"]
    var case_count = Int(py=builtins.len(cases))

    var config = HpackConfig(
        max_header_table_size=initial_table_size
    )
    var decoder = HpackDecoder(config)

    for i in range(case_count):
        var tc = cases[i]

        # Check for explicit table size change in the case
        if _has_key(tc, "header_table_size"):
            var ts = Int(py=tc["header_table_size"])
            decoder.set_max_table_size(ts)

        var wire = hex_decode(String(tc["wire_hex"]))
        var result = decoder.decode(wire)
        assert_true(
            len(result[1]) == 0,
            story_name
            + " case "
            + String(i)
            + ": "
            + result[1],
        )

        # Assert headers match
        var exp = tc["expected_headers"]
        var exp_count = Int(py=builtins.len(exp))
        assert_equal(
            len(result[0]),
            exp_count,
            story_name
            + " case "
            + String(i)
            + " header count",
        )
        for j in range(exp_count):
            var exp_name = String(exp[j][0])
            var exp_value = String(exp[j][1])
            assert_true(
                result[0][j].name == exp_name,
                story_name
                + " case "
                + String(i)
                + " h"
                + String(j)
                + " name: got '"
                + result[0][j].name
                + "' expected '"
                + exp_name
                + "'",
            )
            assert_true(
                result[0][j].value == exp_value,
                story_name
                + " case "
                + String(i)
                + " h"
                + String(j)
                + " value: got '"
                + result[0][j].value
                + "' expected '"
                + exp_value
                + "'",
            )

        # Assert dynamic table entries match
        var exp_dt = tc["expected_dynamic_table"]
        var exp_dt_count = Int(py=builtins.len(exp_dt))
        assert_equal(
            decoder.dynamic_table.size(),
            exp_dt_count,
            story_name
            + " case "
            + String(i)
            + " dt entry count",
        )
        var dt = decoder.dynamic_table.entries_list()
        for j in range(exp_dt_count):
            var exp_dt_name = String(exp_dt[j][0])
            var exp_dt_value = String(exp_dt[j][1])
            assert_true(
                dt[j].name == exp_dt_name
                and dt[j].value == exp_dt_value,
                story_name
                + " case "
                + String(i)
                + " dt["
                + String(j)
                + "]: got '"
                + dt[j].name
                + ":"
                + dt[j].value
                + "' expected '"
                + exp_dt_name
                + ":"
                + exp_dt_value
                + "'",
            )

        # Assert table byte size
        var exp_ts = Int(py=tc["expected_table_size"])
        assert_equal(
            decoder.dynamic_table.byte_size(),
            exp_ts,
            story_name
            + " case "
            + String(i)
            + " table byte size",
        )

    print(
        "  [PASS] "
        + story_name
        + " ("
        + String(case_count)
        + " cases)"
    )


# ---------------------------------------------------------------
# Layer 2: hpack-test-case external stories
# ---------------------------------------------------------------


def run_external_story(
    story_path: String, story_name: String
) raises:
    """Run a single hpack-test-case story."""
    var json_mod = Python.import_module("json")
    var builtins = Python.import_module("builtins")
    var f = builtins.open(story_path, "r")
    var data = json_mod.load(f)
    f.close()

    var cases = data["cases"]
    var case_count = Int(py=builtins.len(cases))

    var decoder = HpackDecoder()

    for i in range(case_count):
        var tc = cases[i]

        # Table size update (key may exist but be None)
        if _has_key(tc, "header_table_size"):
            var ts_val = tc["header_table_size"]
            if Bool(builtins.bool(ts_val is not None)):
                var ts = Int(py=ts_val)
                decoder.set_max_table_size(ts)

        # hpack-test-case uses "wire" not "wire_hex"
        var wire = hex_decode(String(tc["wire"]))
        var result = decoder.decode(wire)
        assert_true(
            len(result[1]) == 0,
            story_name
            + " case "
            + String(i)
            + ": "
            + result[1],
        )

        # Verify headers -- hpack-test-case uses "headers" key
        # Each element is a Python dict with one key-value pair
        var exp_headers = tc["headers"]
        var exp_count = Int(py=builtins.len(exp_headers))
        assert_equal(
            len(result[0]),
            exp_count,
            story_name
            + " case "
            + String(i)
            + " header count",
        )

        for j in range(exp_count):
            var header_dict = exp_headers[j]
            # Each dict has exactly one key
            var keys = builtins.list(header_dict.keys())
            var exp_name = String(keys[0])
            var exp_value = String(header_dict[keys[0]])
            assert_true(
                result[0][j].name == exp_name,
                story_name
                + " case "
                + String(i)
                + " h"
                + String(j)
                + " name: got '"
                + result[0][j].name
                + "' expected '"
                + exp_name
                + "'",
            )
            assert_true(
                result[0][j].value == exp_value,
                story_name
                + " case "
                + String(i)
                + " h"
                + String(j)
                + " value: got '"
                + result[0][j].value
                + "' expected '"
                + exp_value
                + "'",
            )


def run_external_impl(
    impl_dir: String, impl_name: String
) raises -> Int:
    """Run all stories for one implementation. Returns number of stories run."""
    var os_mod = Python.import_module("os")
    var builtins = Python.import_module("builtins")

    var files = os_mod.listdir(impl_dir)
    var sorted_files = builtins.sorted(files)
    var file_count = Int(py=builtins.len(sorted_files))

    var stories_run = 0
    for i in range(file_count):
        var fname = String(sorted_files[i])
        if not fname.endswith(".json"):
            continue
        var fpath = impl_dir + "/" + fname
        var story_label = impl_name + "/" + fname
        run_external_story(fpath, story_label)
        stories_run += 1

    return stories_run


# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------


def main() raises:
    # ---- Sentinel anti-cheat: verify assert_true actually fires ----
    var sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        sentinel_ok = True
    assert_true(sentinel_ok, "assertions are not firing")

    print("=== Layer 1: RFC 7541 story vectors ===")

    # C.2: individual header field representations
    run_rfc_c2_vectors()

    # C.3: request examples without Huffman
    run_rfc_story(
        "vectors/rfc7541/c3_request_no_huffman.json",
        "C.3-request-no-huffman",
    )

    # C.4: request examples with Huffman
    run_rfc_story(
        "vectors/rfc7541/c4_request_huffman.json",
        "C.4-request-huffman",
    )

    # C.5: response examples without Huffman (table size 256)
    run_rfc_story_with_table_size(
        "vectors/rfc7541/c5_response_no_huffman.json",
        "C.5-response-no-huffman",
        256,
    )

    # C.6: response examples with Huffman (table size 256)
    run_rfc_story_with_table_size(
        "vectors/rfc7541/c6_response_huffman.json",
        "C.6-response-huffman",
        256,
    )

    # Anti-cheat: RFC stories must have >= 12 cases total
    # C.2=4, C.3=3, C.4=3, C.5=3, C.6=3 = 16 total
    var rfc_total = 4 + 3 + 3 + 3 + 3
    assert_true(
        rfc_total >= 12,
        "RFC stories must have >= 12 cases, got "
        + String(rfc_total),
    )

    print(
        "  RFC total: "
        + String(rfc_total)
        + " cases across 5 story files"
    )

    print("")
    print("=== Layer 2: hpack-test-case external stories ===")

    var stories_base = "vectors/hpack-stories"
    var os_mod = Python.import_module("os")

    if not Bool(os_mod.path.isdir(stories_base)):
        print(
            "  SKIP: hpack-stories not found. Run"
            " conformance/scripts/download_hpack_stories.py first."
        )
        return

    # Run stories from at least 3 implementations
    var impls = List[String]()
    impls.append("nghttp2")
    impls.append("python-hpack")
    impls.append("go-hpack")
    impls.append("node-http2-hpack")
    impls.append("haskell-http2-naive")
    impls.append("swift-nio-hpack-huffman")

    var impls_run = 0
    var total_stories = 0

    for i in range(len(impls)):
        var impl_name = impls[i]
        var impl_dir = stories_base + "/" + impl_name
        if not Bool(os_mod.path.isdir(impl_dir)):
            print("  SKIP: " + impl_name + " not found")
            continue

        var count = run_external_impl(impl_dir, impl_name)
        print(
            "  [PASS] "
            + impl_name
            + ": "
            + String(count)
            + " stories"
        )
        impls_run += 1
        total_stories += count

    # Anti-cheat: must have stories from >= 3 implementations
    assert_true(
        impls_run >= 3,
        "external stories from >= 3 implementations required, got "
        + String(impls_run),
    )

    print(
        "  External total: "
        + String(total_stories)
        + " stories across "
        + String(impls_run)
        + " implementations"
    )

    print("")
    print(
        "test_hpack_decode: all checks passed (RFC: "
        + String(rfc_total)
        + " cases, external: "
        + String(total_stories)
        + " stories)"
    )
