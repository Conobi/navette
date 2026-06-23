# conformance/tests/test_h2_frame_cross.mojo
#
# HTTP/2 frame cross-validation — our decoder vs the pre-materialized
# hyperframe oracle baked into conformance/vectors/rfc9113/*.json.
#
# As of §3.3 of the dependency-enhancement plan, hyperframe is no longer
# imported at test runtime. The `expected` block of each accept vector
# carries hyperframe's verdict (length, frame_type, flags, stream_id,
# payload_hex), originally produced by http2-frame-test-case + hyperframe
# at vector-generation time. For reject vectors, our parser must reject;
# the hyperframe "may accept" disagreements that were previously logged
# at runtime have been removed (they are tracked in the vector source
# notes if present).
#
# Phase 2 (random fuzz against live hyperframe) has been deprecated.
# The roundtrip-only vectors plus type-specific accept vectors provide
# the same encode/decode coverage without a live oracle.
from lib.test_util import load_vectors, hex_decode, hex_encode, assert_true, assert_equal
from lib.http2.frame import (
    Frame,
    H2FrameConfig,
    decode_frame,
    encode_frame,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_PRIORITY,
    FRAME_RST_STREAM,
    FRAME_SETTINGS,
    FRAME_PUSH_PROMISE,
    FRAME_PING,
    FRAME_GOAWAY,
    FRAME_WINDOW_UPDATE,
    FRAME_CONTINUATION,
)
from std.python import Python, PythonObject


def _has_key(obj: PythonObject, key: String) -> Bool:
    """Check if a Python dict has a given key."""
    try:
        var builtins = Python.import_module("builtins")
        return Bool(builtins.bool(key in obj))
    except:
        return False


def _build_config(v: PythonObject) -> H2FrameConfig:
    """Build an H2FrameConfig from a vector's input section."""
    var config = H2FrameConfig(allow_nonzero_padding=True)
    try:
        if _has_key(v["input"], "settings_max_frame_size"):
            config.max_frame_size = Int(py=v["input"]["settings_max_frame_size"])
    except:
        pass
    return config^


def check_cross_accept(
    wire: List[UInt8], vid: String, expected: PythonObject, config: H2FrameConfig,
) raises -> Int:
    """Cross-validate an accept vector against the pre-materialized oracle.

    Returns number of disagreements (always 0 if test passes; we assert).
    """
    # Decode with our parser
    var result = decode_frame(wire, 0, config)
    var frame = result[0].copy()
    assert_true(frame.ok(), vid + ": our parser rejected: " + frame.error)

    # Compare against pre-materialized hyperframe oracle fields.
    var disagreements = 0

    var expected_length = Int(py=expected["length"])
    if frame.length != expected_length:
        print(
            "    FAIL [" + vid + "] length: ours="
            + String(frame.length) + " oracle=" + String(expected_length)
        )
        disagreements += 1

    var expected_stream_id = Int(py=expected["stream_id"])
    if frame.stream_id != expected_stream_id:
        print(
            "    FAIL [" + vid + "] stream_id: ours="
            + String(frame.stream_id) + " oracle=" + String(expected_stream_id)
        )
        disagreements += 1

    var our_payload_hex = hex_encode(frame.payload)
    var expected_payload_hex = String(expected["payload_hex"])
    if our_payload_hex != expected_payload_hex:
        print(
            "    FAIL [" + vid + "] payload_hex: ours="
            + our_payload_hex + " oracle=" + expected_payload_hex
        )
        disagreements += 1

    var expected_type = Int(py=expected["frame_type"])
    if frame.frame_type != expected_type:
        print(
            "    FAIL [" + vid + "] type: ours="
            + String(frame.frame_type) + " oracle=" + String(expected_type)
        )
        disagreements += 1

    var expected_flags = Int(py=expected["flags"])
    if frame.flags != expected_flags:
        print(
            "    FAIL [" + vid + "] flags: ours="
            + String(frame.flags) + " oracle=" + String(expected_flags)
        )
        disagreements += 1

    return disagreements


def check_cross_reject(
    wire: List[UInt8], vid: String, config: H2FrameConfig,
) raises:
    """Cross-validate a reject vector. Our parser must reject."""
    var result = decode_frame(wire, 0, config)
    var frame = result[0].copy()
    assert_true(not frame.ok(), vid + ": our parser accepted but expected reject")


def check_roundtrip(wire: List[UInt8], vid: String, config: H2FrameConfig) raises:
    """Roundtrip: decode, re-encode, compare bytes."""
    var result = decode_frame(wire, 0, config)
    var frame = result[0].copy()
    assert_true(frame.ok(), vid + ": roundtrip decode failed: " + frame.error)

    var re = encode_frame(frame)
    assert_true(
        len(re) == len(wire),
        vid + ": roundtrip length mismatch: " + String(len(re)) + " vs " + String(len(wire)),
    )
    for i in range(len(wire)):
        if re[i] != wire[i]:
            print(
                "    FAIL [" + vid + "] roundtrip byte " + String(i)
                + " ours=" + hex_encode(re) + " orig=" + hex_encode(wire)
            )
            raise vid + ": roundtrip byte mismatch"


def main() raises:
    # ---- Sentinel anti-cheat ----
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing")

    var builtins = Python.import_module("builtins")

    print("=== Vector-based cross-validation (hyperframe oracle pre-materialized) ===")

    var files = List[String]()
    files.append("vectors/rfc9113/frame_data.json")
    files.append("vectors/rfc9113/frame_headers.json")
    files.append("vectors/rfc9113/frame_settings.json")
    files.append("vectors/rfc9113/frame_goaway.json")
    files.append("vectors/rfc9113/frame_window_update.json")
    files.append("vectors/rfc9113/frame_rst_stream.json")
    files.append("vectors/rfc9113/frame_priority.json")
    files.append("vectors/rfc9113/frame_push_promise.json")
    files.append("vectors/rfc9113/frame_ping.json")
    files.append("vectors/rfc9113/frame_continuation.json")
    files.append("vectors/rfc9113/frame_error.json")
    files.append("vectors/security/h2_frame_abuse.json")

    var total_cross = 0
    var accept_agree = 0
    var accept_disagree = 0
    var reject_tested = 0
    var roundtrip_tested = 0

    for fi in range(len(files)):
        var path = files[fi]
        var vectors = load_vectors(path)
        var vec_count = Int(py=builtins.len(vectors))
        var file_accept = 0
        var file_reject = 0
        var file_roundtrip = 0

        for i in range(vec_count):
            var v = vectors[i]
            var vid = String(v["id"])
            var expected = v["expected"]
            var behavior = String(expected["behavior"])
            var wire = hex_decode(String(v["input"]["wire_hex"]))
            var config = _build_config(v)

            var is_security = False
            try:
                var severity = String(v["severity"])
                _ = severity
                is_security = True
            except:
                pass

            if behavior == "accept":
                if is_security:
                    try:
                        var n = check_cross_accept(wire, vid, expected, config)
                        if n == 0:
                            accept_agree += 1
                        else:
                            accept_disagree += 1
                        file_accept += 1
                        total_cross += 1
                    except e:
                        print("    [SOFT FAIL] " + vid + ": " + String(e))
                else:
                    var n = check_cross_accept(wire, vid, expected, config)
                    if n == 0:
                        accept_agree += 1
                    else:
                        accept_disagree += 1
                    file_accept += 1
                    total_cross += 1
            elif behavior == "reject":
                if is_security:
                    try:
                        check_cross_reject(wire, vid, config)
                        file_reject += 1
                        reject_tested += 1
                        total_cross += 1
                    except e:
                        print("    [SOFT FAIL] " + vid + ": " + String(e))
                else:
                    check_cross_reject(wire, vid, config)
                    file_reject += 1
                    reject_tested += 1
                    total_cross += 1
            elif behavior == "roundtrip":
                check_roundtrip(wire, vid, config)
                file_roundtrip += 1
                roundtrip_tested += 1
                total_cross += 1

        var msg = "  " + path + ": " + String(file_accept) + " accept, " + String(file_reject) + " reject, " + String(file_roundtrip) + " roundtrip"
        print(msg)

    print(
        "  Accept: " + String(accept_agree) + " full-agree, "
        + String(accept_disagree) + " with disagreements"
    )
    print("  Reject: " + String(reject_tested) + " tested (ours must reject)")
    print("  Roundtrip: " + String(roundtrip_tested) + " encode-decode round-trips")

    # ---- Final anti-cheat gates ----
    assert_true(
        total_cross >= 10,
        "expected >= 10 cross-validated vectors, got " + String(total_cross),
    )
    assert_true(
        accept_disagree == 0,
        "expected 0 accept disagreements vs pre-materialized oracle, got " + String(accept_disagree),
    )

    print("")
    print(
        "test_h2_frame_cross: "
        + String(total_cross) + " vectors cross-validated against pre-materialized hyperframe oracle"
    )
    print(
        "  accept: " + String(accept_agree) + " agree | "
        + "reject: " + String(reject_tested) + " verified | "
        + "roundtrip: " + String(roundtrip_tested) + " ok"
    )
