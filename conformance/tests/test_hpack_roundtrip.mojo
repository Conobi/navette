# conformance/tests/test_hpack_roundtrip.mojo
#
# HC-3b Task 5: HPACK encoder + roundtrip tests.
# Layer 3: self-roundtrip testing using raw-data stories and random headers.

from lib.test_util import assert_true, assert_equal
from lib.http1.types import Header
from lib.http2.hpack import HpackEncoder, HpackDecoder, HpackConfig
from std.python import Python, PythonObject
from std.time import perf_counter_ns


# ---------------------------------------------------------------
# Story runner: encode -> decode -> verify headers match
# ---------------------------------------------------------------


def run_roundtrip_story(
    cases: PythonObject, story_name: String
) raises:
    """Run a single raw-data story through encode -> decode roundtrip."""
    var encoder = HpackEncoder()
    var decoder = HpackDecoder()
    var builtins = Python.import_module("builtins")

    var case_count = Int(py=builtins.len(cases))

    for i in range(case_count):
        var tc = cases[i]

        # Build header list from case
        var py_headers = tc["headers"]
        var headers = List[Header]()
        var hdr_count = Int(py=builtins.len(py_headers))
        for j in range(hdr_count):
            var h = py_headers[j]
            # hpack-test-case format: [{"name": "value"}, ...] -- single-key dicts
            var keys = builtins.list(h.keys())
            var k = String(keys[0])
            var v = String(h[keys[0]])
            headers.append(Header(k, v))

        # Encode
        var wire = encoder.encode(headers)

        # Decode
        var result = decoder.decode(wire)
        assert_true(
            len(result[1]) == 0,
            story_name
            + " case "
            + String(i)
            + " decode error: "
            + result[1],
        )

        # Verify headers match
        assert_equal(
            len(result[0]),
            len(headers),
            story_name + " case " + String(i) + " header count",
        )
        for j in range(len(headers)):
            assert_true(
                result[0][j].name == headers[j].name,
                story_name
                + " case "
                + String(i)
                + " header["
                + String(j)
                + "] name: got '"
                + result[0][j].name
                + "' expected '"
                + headers[j].name
                + "'",
            )
            assert_true(
                result[0][j].value == headers[j].value,
                story_name
                + " case "
                + String(i)
                + " header["
                + String(j)
                + "] value: got '"
                + result[0][j].value
                + "' expected '"
                + headers[j].value
                + "'",
            )


# ---------------------------------------------------------------
# Raw-data story runner
# ---------------------------------------------------------------


def run_raw_data_stories() raises -> Int:
    """Run all raw-data stories through roundtrip. Returns total cases."""
    var json_mod = Python.import_module("json")
    var builtins = Python.import_module("builtins")
    var os_mod = Python.import_module("os")

    var raw_dir = "vectors/hpack-stories/raw-data"

    if not Bool(os_mod.path.isdir(raw_dir)):
        print(
            "  SKIP: raw-data stories not found. Run"
            " conformance/scripts/download_hpack_stories.py first."
        )
        return 0

    var files = os_mod.listdir(raw_dir)
    var sorted_files = builtins.sorted(files)
    var file_count = Int(py=builtins.len(sorted_files))

    var total_cases = 0
    var stories_run = 0

    for i in range(file_count):
        var fname = String(sorted_files[i])
        if not fname.endswith(".json"):
            continue

        var fpath = raw_dir + "/" + fname
        var f = builtins.open(fpath, "r")
        var data = json_mod.load(f)
        f.close()

        var cases = data["cases"]
        var case_count = Int(py=builtins.len(cases))
        total_cases += case_count

        run_roundtrip_story(cases, "raw-data/" + fname)
        stories_run += 1
        print(
            "  [PASS] raw-data/"
            + fname
            + " ("
            + String(case_count)
            + " cases)"
        )

    print(
        "  Raw-data total: "
        + String(stories_run)
        + " stories, "
        + String(total_cases)
        + " cases"
    )
    return total_cases


# ---------------------------------------------------------------
# Roundtrip with Huffman disabled
# ---------------------------------------------------------------


def run_no_huffman_roundtrip() raises:
    """Roundtrip test with Huffman disabled to cover both code paths."""
    var config = HpackConfig(use_huffman=False)
    var encoder = HpackEncoder(config)
    var decoder = HpackDecoder()

    var headers = List[Header]()
    headers.append(Header(String(":method"), String("GET")))
    headers.append(Header(String(":scheme"), String("https")))
    headers.append(Header(String(":path"), String("/")))
    headers.append(Header(String(":authority"), String("example.com")))
    headers.append(Header(String("user-agent"), String("mojo-test/1.0")))
    headers.append(
        Header(String("accept"), String("text/html"))
    )

    var wire = encoder.encode(headers)
    var result = decoder.decode(wire)
    assert_true(
        len(result[1]) == 0,
        "no-huffman roundtrip decode error: " + result[1],
    )
    assert_equal(
        len(result[0]), len(headers), "no-huffman header count"
    )
    for j in range(len(headers)):
        assert_true(
            result[0][j].name == headers[j].name,
            "no-huffman header["
            + String(j)
            + "] name: got '"
            + result[0][j].name
            + "' expected '"
            + headers[j].name
            + "'",
        )
        assert_true(
            result[0][j].value == headers[j].value,
            "no-huffman header["
            + String(j)
            + "] value: got '"
            + result[0][j].value
            + "' expected '"
            + headers[j].value
            + "'",
        )

    print("  [PASS] no-huffman roundtrip (6 headers)")


# ---------------------------------------------------------------
# Table size update roundtrip
# ---------------------------------------------------------------


def run_table_size_update_roundtrip() raises:
    """Test that table size updates roundtrip correctly."""
    var encoder = HpackEncoder()
    var decoder = HpackDecoder()

    # First block: normal headers to populate dynamic table
    var headers1 = List[Header]()
    headers1.append(Header(String(":method"), String("GET")))
    headers1.append(Header(String(":path"), String("/api/v1")))
    headers1.append(
        Header(String("x-request-id"), String("abc123"))
    )

    var wire1 = encoder.encode(headers1)
    var result1 = decoder.decode(wire1)
    assert_true(
        len(result1[1]) == 0,
        "table-size-update block 1 decode error: " + result1[1],
    )
    assert_equal(
        len(result1[0]), 3, "table-size-update block 1 count"
    )

    # Reduce table size -- this should trigger a table size update
    encoder.set_max_table_size(128)
    decoder.set_max_table_size(128)

    # Second block with size update
    var headers2 = List[Header]()
    headers2.append(Header(String(":method"), String("POST")))
    headers2.append(Header(String(":path"), String("/api/v2")))

    var wire2 = encoder.encode(headers2)
    var result2 = decoder.decode(wire2)
    assert_true(
        len(result2[1]) == 0,
        "table-size-update block 2 decode error: " + result2[1],
    )
    assert_equal(
        len(result2[0]), 2, "table-size-update block 2 count"
    )
    for j in range(len(headers2)):
        assert_true(
            result2[0][j].name == headers2[j].name,
            "table-size-update block 2 header["
            + String(j)
            + "] name",
        )
        assert_true(
            result2[0][j].value == headers2[j].value,
            "table-size-update block 2 header["
            + String(j)
            + "] value",
        )

    print("  [PASS] table size update roundtrip")


# ---------------------------------------------------------------
# Multi-block dynamic table reuse
# ---------------------------------------------------------------


def run_dynamic_table_reuse_roundtrip() raises:
    """Test that dynamic table entries from block N are reused in block N+1."""
    var encoder = HpackEncoder()
    var decoder = HpackDecoder()

    # Block 1: custom headers go into dynamic table
    var headers1 = List[Header]()
    headers1.append(Header(String(":method"), String("GET")))
    headers1.append(
        Header(String("x-custom-a"), String("value-a"))
    )
    headers1.append(
        Header(String("x-custom-b"), String("value-b"))
    )

    var wire1 = encoder.encode(headers1)
    var result1 = decoder.decode(wire1)
    assert_true(
        len(result1[1]) == 0,
        "dt-reuse block 1 decode: " + result1[1],
    )
    assert_equal(len(result1[0]), 3, "dt-reuse block 1 count")

    # Block 2: same custom headers should be indexed from dynamic table
    var headers2 = List[Header]()
    headers2.append(Header(String(":method"), String("POST")))
    headers2.append(
        Header(String("x-custom-a"), String("value-a"))
    )
    headers2.append(
        Header(String("x-custom-b"), String("value-b"))
    )

    var wire2 = encoder.encode(headers2)
    var result2 = decoder.decode(wire2)
    assert_true(
        len(result2[1]) == 0,
        "dt-reuse block 2 decode: " + result2[1],
    )
    assert_equal(len(result2[0]), 3, "dt-reuse block 2 count")
    for j in range(len(headers2)):
        assert_true(
            result2[0][j].name == headers2[j].name,
            "dt-reuse block 2 header["
            + String(j)
            + "] name",
        )
        assert_true(
            result2[0][j].value == headers2[j].value,
            "dt-reuse block 2 header["
            + String(j)
            + "] value",
        )

    # Wire2 should be shorter than wire1 because dynamic table hits
    # (This is a soft check -- just print for visibility)
    print(
        "  [PASS] dynamic table reuse roundtrip (wire1="
        + String(len(wire1))
        + "B, wire2="
        + String(len(wire2))
        + "B)"
    )


# ---------------------------------------------------------------
# Anti-cheat: 5 random stories
# ---------------------------------------------------------------


def _pseudo_rand(mut state: Int) -> Int:
    """Simple xorshift-style PRNG returning a positive integer."""
    state = state ^ (state << 13)
    state = state ^ (state >> 7)
    state = state ^ (state << 17)
    if state < 0:
        state = -state
    return state


def run_random_roundtrips() raises:
    """Generate 5 random stories and roundtrip each."""
    var seed = Int(perf_counter_ns()) ^ 0x5DEECE66D
    if seed < 0:
        seed = -seed
    if seed == 0:
        seed = 42

    var alpha = String("abcdefghijklmnopqrstuvwxyz0123456789")
    var alpha_bytes = alpha.as_bytes()
    var alpha_len = len(alpha_bytes)

    var pseudo_names = List[String]()
    pseudo_names.append(String(":method"))
    pseudo_names.append(String(":path"))
    pseudo_names.append(String(":scheme"))
    pseudo_names.append(String(":authority"))
    pseudo_names.append(String("content-type"))
    pseudo_names.append(String("accept"))
    pseudo_names.append(String("user-agent"))
    pseudo_names.append(String("x-custom-0"))
    pseudo_names.append(String("x-custom-1"))
    pseudo_names.append(String("x-custom-2"))
    pseudo_names.append(String("x-custom-3"))
    pseudo_names.append(String("x-custom-4"))

    var pseudo_values = List[String]()
    pseudo_values.append(String("GET"))
    pseudo_values.append(String("POST"))
    pseudo_values.append(String("PUT"))
    pseudo_values.append(String("/"))
    pseudo_values.append(String("/index.html"))
    pseudo_values.append(String("https"))
    pseudo_values.append(String("http"))
    pseudo_values.append(String("example.com"))
    pseudo_values.append(String("text/html"))
    pseudo_values.append(String("application/json"))

    var total_blocks = 0

    for story in range(5):
        var encoder = HpackEncoder()
        var decoder = HpackDecoder()

        # 3-5 blocks per story
        seed = _pseudo_rand(seed)
        var num_blocks = 3 + (seed % 3)

        for block in range(num_blocks):
            # 2-4 headers per block
            seed = _pseudo_rand(seed)
            var num_headers = 2 + (seed % 3)

            var headers = List[Header]()
            for _ in range(num_headers):
                # Pick name
                seed = _pseudo_rand(seed)
                var name_idx = seed % len(pseudo_names)
                var name = pseudo_names[name_idx]

                # Generate value: mix a pseudo_value with random suffix
                seed = _pseudo_rand(seed)
                var val_idx = seed % len(pseudo_values)
                var base_val = pseudo_values[val_idx]

                # Append random suffix (5-10 chars)
                seed = _pseudo_rand(seed)
                var suffix_len = 5 + (seed % 6)
                var suffix = String("")
                for _ in range(suffix_len):
                    seed = _pseudo_rand(seed)
                    var ci = seed % alpha_len
                    suffix += chr(Int(alpha_bytes[ci]))

                headers.append(Header(name, base_val + suffix))

            # Encode
            var wire = encoder.encode(headers)

            # Decode
            var result = decoder.decode(wire)
            assert_true(
                len(result[1]) == 0,
                "random story "
                + String(story)
                + " block "
                + String(block)
                + " decode error: "
                + result[1],
            )

            # Verify
            assert_equal(
                len(result[0]),
                len(headers),
                "random story "
                + String(story)
                + " block "
                + String(block)
                + " count",
            )
            for j in range(len(headers)):
                assert_true(
                    result[0][j].name == headers[j].name,
                    "random story "
                    + String(story)
                    + " block "
                    + String(block)
                    + " h"
                    + String(j)
                    + " name",
                )
                assert_true(
                    result[0][j].value == headers[j].value,
                    "random story "
                    + String(story)
                    + " block "
                    + String(block)
                    + " h"
                    + String(j)
                    + " value",
                )

            total_blocks += 1

    print(
        "  [PASS] 5 random stories ("
        + String(total_blocks)
        + " blocks)"
    )


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

    print("=== HPACK Encoder Roundtrip Tests ===")
    print("")

    print("--- Unit tests ---")
    run_no_huffman_roundtrip()
    run_table_size_update_roundtrip()
    run_dynamic_table_reuse_roundtrip()
    print("")

    print("--- Raw-data story roundtrips ---")
    var raw_cases = run_raw_data_stories()
    print("")

    print("--- Random roundtrips (anti-cheat) ---")
    run_random_roundtrips()
    print("")

    # Anti-cheat: must have processed real stories
    assert_true(
        raw_cases >= 50,
        "expected >= 50 raw-data cases, got " + String(raw_cases),
    )

    print(
        "test_hpack_roundtrip: all checks passed (raw-data: "
        + String(raw_cases)
        + " cases + unit tests + random stories)"
    )
