# conformance/tests/test_hpack_cross.mojo
#
# HC-3b Task 6: HPACK cross-validation against Python hpack oracle.
# Layer 4: bidirectional cross-validation — our encoder vs Python decoder,
# Python encoder vs our decoder, over raw-data stories and random headers.

from lib.test_util import hex_decode, hex_encode, assert_true, assert_equal
from lib.http1.types import Header
from lib.http2.hpack import HpackEncoder, HpackDecoder, HpackConfig
from lib.http2.oracles import (
    hpack_decode_with_python,
    hpack_encode_with_python,
    hpack_story_decode_with_python,
    hpack_story_encode_with_python,
)
from std.python import Python, PythonObject
from std.time import perf_counter_ns


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------


def _wire_to_hex(wire: List[UInt8]) -> String:
    """Convert wire bytes to hex string."""
    return hex_encode(wire)


def _compare_headers_to_python(
    py_headers: PythonObject,
    expected: List[Header],
    context: String,
) raises:
    """Assert Python-decoded headers match our expected headers."""
    var builtins = Python.import_module("builtins")
    var py_count = Int(py=builtins.len(py_headers))
    assert_equal(
        py_count,
        len(expected),
        context + " header count",
    )
    for j in range(len(expected)):
        var py_name = String(py_headers[j][0])
        var py_value = String(py_headers[j][1])
        assert_true(
            py_name == expected[j].name,
            context
            + " header["
            + String(j)
            + "] name: python='"
            + py_name
            + "' expected='"
            + expected[j].name
            + "'",
        )
        assert_true(
            py_value == expected[j].value,
            context
            + " header["
            + String(j)
            + "] value: python='"
            + py_value
            + "' expected='"
            + expected[j].value
            + "'",
        )


# ---------------------------------------------------------------
# Phase 1: Our encode -> Python decode (raw-data stories)
# ---------------------------------------------------------------


def run_phase1_our_encode_python_decode() raises -> Int:
    """Encode with our encoder, decode with Python hpack.
    Uses first 5 raw-data stories. Returns total cases."""
    var json_mod = Python.import_module("json")
    var builtins = Python.import_module("builtins")
    var os_mod = Python.import_module("os")

    var raw_dir = "vectors/hpack-stories/raw-data"
    if not Bool(os_mod.path.isdir(raw_dir)):
        print(
            "  SKIP: raw-data stories not found."
        )
        return 0

    var files = builtins.sorted(os_mod.listdir(raw_dir))
    var file_count = Int(py=builtins.len(files))
    var total_cases = 0
    var stories_run = 0

    for fi in range(file_count):
        if stories_run >= 5:
            break
        var fname = String(files[fi])
        if not fname.endswith(".json"):
            continue

        var fpath = raw_dir + "/" + fname
        var f = builtins.open(fpath, "r")
        var data = json_mod.load(f)
        f.close()

        var cases = data["cases"]
        var case_count = Int(py=builtins.len(cases))

        # Fresh encoder for each story
        var encoder = HpackEncoder()
        # Collect all wire hex strings for stateful Python decode
        var wire_hex_list = List[String]()
        # Collect all expected headers per case
        var all_expected = List[List[Header]]()

        for i in range(case_count):
            var tc = cases[i]
            var py_headers = tc["headers"]
            var headers = List[Header]()
            var hdr_count = Int(py=builtins.len(py_headers))
            for j in range(hdr_count):
                var h = py_headers[j]
                var keys = builtins.list(h.keys())
                var k = String(keys[0])
                var v = String(h[keys[0]])
                headers.append(Header(k, v))

            # Encode with our encoder
            var wire = encoder.encode(headers)
            wire_hex_list.append(_wire_to_hex(wire))
            all_expected.append(headers^)

        # Decode all blocks statefully with Python
        var py_result = hpack_story_decode_with_python(wire_hex_list)
        var py_err = py_result["error"]
        assert_true(
            Bool(py_err is None),
            "phase1 " + fname + " python decode error: " + String(py_err),
        )

        var py_results = py_result["results"]
        var result_count = Int(py=builtins.len(py_results))
        assert_equal(
            result_count,
            case_count,
            "phase1 " + fname + " result count",
        )

        for i in range(case_count):
            _compare_headers_to_python(
                py_results[i],
                all_expected[i],
                "phase1 " + fname + " case " + String(i),
            )

        total_cases += case_count
        stories_run += 1
        print(
            "  [PASS] phase1 our-encode->py-decode: "
            + fname
            + " ("
            + String(case_count)
            + " cases)"
        )

    return total_cases


# ---------------------------------------------------------------
# Phase 2: Python encode -> Our decode (raw-data stories)
# ---------------------------------------------------------------


def run_phase2_python_encode_our_decode() raises -> Int:
    """Encode with Python hpack, decode with our decoder.
    Uses first 5 raw-data stories. Returns total cases."""
    var json_mod = Python.import_module("json")
    var builtins = Python.import_module("builtins")
    var os_mod = Python.import_module("os")

    var raw_dir = "vectors/hpack-stories/raw-data"
    if not Bool(os_mod.path.isdir(raw_dir)):
        print(
            "  SKIP: raw-data stories not found."
        )
        return 0

    var files = builtins.sorted(os_mod.listdir(raw_dir))
    var file_count = Int(py=builtins.len(files))
    var total_cases = 0
    var stories_run = 0

    for fi in range(file_count):
        if stories_run >= 5:
            break
        var fname = String(files[fi])
        if not fname.endswith(".json"):
            continue

        var fpath = raw_dir + "/" + fname
        var f = builtins.open(fpath, "r")
        var data = json_mod.load(f)
        f.close()

        var cases = data["cases"]
        var case_count = Int(py=builtins.len(cases))

        # Collect all headers as List[List[Header]]
        var all_headers = List[List[Header]]()
        for i in range(case_count):
            var tc = cases[i]
            var py_headers = tc["headers"]
            var headers = List[Header]()
            var hdr_count = Int(py=builtins.len(py_headers))
            for j in range(hdr_count):
                var h = py_headers[j]
                var keys = builtins.list(h.keys())
                var k = String(keys[0])
                var v = String(h[keys[0]])
                headers.append(Header(k, v))
            all_headers.append(headers^)

        # Encode all blocks statefully with Python
        var py_result = hpack_story_encode_with_python(all_headers)
        var py_err = py_result["error"]
        assert_true(
            Bool(py_err is None),
            "phase2 " + fname + " python encode error: " + String(py_err),
        )

        var wire_hex_list = py_result["wire_hex_list"]
        var wire_count = Int(py=builtins.len(wire_hex_list))
        assert_equal(
            wire_count,
            case_count,
            "phase2 " + fname + " wire count",
        )

        # Decode each block with our decoder (stateful)
        var decoder = HpackDecoder()
        for i in range(case_count):
            var wire_hex = String(wire_hex_list[i])
            var wire = hex_decode(wire_hex)
            var result = decoder.decode(wire)
            assert_true(
                len(result[1]) == 0,
                "phase2 "
                + fname
                + " case "
                + String(i)
                + " decode error: "
                + result[1],
            )

            assert_equal(
                len(result[0]),
                len(all_headers[i]),
                "phase2 "
                + fname
                + " case "
                + String(i)
                + " header count",
            )
            for j in range(len(all_headers[i])):
                assert_true(
                    result[0][j].name == all_headers[i][j].name,
                    "phase2 "
                    + fname
                    + " case "
                    + String(i)
                    + " header["
                    + String(j)
                    + "] name: got '"
                    + result[0][j].name
                    + "' expected '"
                    + all_headers[i][j].name
                    + "'",
                )
                assert_true(
                    result[0][j].value == all_headers[i][j].value,
                    "phase2 "
                    + fname
                    + " case "
                    + String(i)
                    + " header["
                    + String(j)
                    + "] value: got '"
                    + result[0][j].value
                    + "' expected '"
                    + all_headers[i][j].value
                    + "'",
                )

        total_cases += case_count
        stories_run += 1
        print(
            "  [PASS] phase2 py-encode->our-decode: "
            + fname
            + " ("
            + String(case_count)
            + " cases)"
        )

    return total_cases


# ---------------------------------------------------------------
# Phase 3: Random stories cross-validated both directions
# ---------------------------------------------------------------


def _pseudo_rand(mut state: Int) -> Int:
    """Simple xorshift-style PRNG returning a positive integer."""
    state = state ^ (state << 13)
    state = state ^ (state >> 7)
    state = state ^ (state << 17)
    if state < 0:
        state = -state
    return state


def run_phase3_random_cross() raises:
    """Generate 5 random stories and cross-validate both directions."""
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

    var builtins = Python.import_module("builtins")
    var total_blocks = 0

    for story in range(5):
        # Generate random blocks for this story
        seed = _pseudo_rand(seed)
        var num_blocks = 3 + (seed % 3)

        var all_headers = List[List[Header]]()
        for _ in range(num_blocks):
            seed = _pseudo_rand(seed)
            var num_headers = 2 + (seed % 3)
            var headers = List[Header]()
            for _ in range(num_headers):
                seed = _pseudo_rand(seed)
                var name_idx = seed % len(pseudo_names)
                var name = pseudo_names[name_idx]
                seed = _pseudo_rand(seed)
                var val_idx = seed % len(pseudo_values)
                var base_val = pseudo_values[val_idx]
                seed = _pseudo_rand(seed)
                var suffix_len = 5 + (seed % 6)
                var suffix = String("")
                for _ in range(suffix_len):
                    seed = _pseudo_rand(seed)
                    var ci = seed % alpha_len
                    suffix += chr(Int(alpha_bytes[ci]))
                headers.append(Header(name, base_val + suffix))
            all_headers.append(headers^)

        # --- Direction A: our encode -> Python decode ---
        var encoder = HpackEncoder()
        var wire_hex_list = List[String]()
        for bi in range(len(all_headers)):
            var wire = encoder.encode(all_headers[bi])
            wire_hex_list.append(_wire_to_hex(wire))

        var py_dec_result = hpack_story_decode_with_python(wire_hex_list)
        var py_dec_err = py_dec_result["error"]
        assert_true(
            Bool(py_dec_err is None),
            "phase3 story "
            + String(story)
            + " dir-A python decode error: "
            + String(py_dec_err),
        )
        var py_dec_results = py_dec_result["results"]
        var dec_count = Int(py=builtins.len(py_dec_results))
        assert_equal(
            dec_count,
            len(all_headers),
            "phase3 story " + String(story) + " dir-A result count",
        )
        for bi in range(len(all_headers)):
            _compare_headers_to_python(
                py_dec_results[bi],
                all_headers[bi],
                "phase3 story "
                + String(story)
                + " dir-A block "
                + String(bi),
            )

        # --- Direction B: Python encode -> our decode ---
        var py_enc_result = hpack_story_encode_with_python(all_headers)
        var py_enc_err = py_enc_result["error"]
        assert_true(
            Bool(py_enc_err is None),
            "phase3 story "
            + String(story)
            + " dir-B python encode error: "
            + String(py_enc_err),
        )
        var py_wire_list = py_enc_result["wire_hex_list"]
        var enc_count = Int(py=builtins.len(py_wire_list))
        assert_equal(
            enc_count,
            len(all_headers),
            "phase3 story " + String(story) + " dir-B wire count",
        )

        var decoder = HpackDecoder()
        for bi in range(len(all_headers)):
            var wire_hex = String(py_wire_list[bi])
            var wire = hex_decode(wire_hex)
            var result = decoder.decode(wire)
            assert_true(
                len(result[1]) == 0,
                "phase3 story "
                + String(story)
                + " dir-B block "
                + String(bi)
                + " decode error: "
                + result[1],
            )
            assert_equal(
                len(result[0]),
                len(all_headers[bi]),
                "phase3 story "
                + String(story)
                + " dir-B block "
                + String(bi)
                + " header count",
            )
            for j in range(len(all_headers[bi])):
                assert_true(
                    result[0][j].name == all_headers[bi][j].name,
                    "phase3 story "
                    + String(story)
                    + " dir-B block "
                    + String(bi)
                    + " h"
                    + String(j)
                    + " name: got '"
                    + result[0][j].name
                    + "' expected '"
                    + all_headers[bi][j].name
                    + "'",
                )
                assert_true(
                    result[0][j].value == all_headers[bi][j].value,
                    "phase3 story "
                    + String(story)
                    + " dir-B block "
                    + String(bi)
                    + " h"
                    + String(j)
                    + " value: got '"
                    + result[0][j].value
                    + "' expected '"
                    + all_headers[bi][j].value
                    + "'",
                )

        total_blocks += len(all_headers)

    print(
        "  [PASS] phase3 random cross-validation: 5 stories ("
        + String(total_blocks)
        + " blocks, both directions)"
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

    print("=== HPACK Cross-Validation Tests (vs Python hpack) ===")
    print("")

    print("--- Phase 1: Our encode -> Python decode ---")
    var phase1_cases = run_phase1_our_encode_python_decode()
    print("")

    print("--- Phase 2: Python encode -> Our decode ---")
    var phase2_cases = run_phase2_python_encode_our_decode()
    print("")

    print("--- Phase 3: Random stories (both directions) ---")
    run_phase3_random_cross()
    print("")

    # Anti-cheat: must have processed real stories in both directions
    assert_true(
        phase1_cases >= 5,
        "phase1: expected >= 5 cross-validated cases, got "
        + String(phase1_cases),
    )
    assert_true(
        phase2_cases >= 5,
        "phase2: expected >= 5 cross-validated cases, got "
        + String(phase2_cases),
    )

    print(
        "test_hpack_cross: all checks passed (phase1: "
        + String(phase1_cases)
        + " cases, phase2: "
        + String(phase2_cases)
        + " cases, phase3: 5 random stories)"
    )
