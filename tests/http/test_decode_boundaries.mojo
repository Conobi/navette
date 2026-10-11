# tests/http/test_decode_boundaries.mojo
"""Step API of ContentDecoder: per-step caps, unchanged-on-raise, finish path,
trailing data, lifecycle and poisoning."""
from std.collections import Span
from navette.http.decode import ContentDecoder, ContentEncoding, DecodeStatus, DecodeStep
from navette.compress.lib import DecoderLimits
from tests._test_util import assert_true, assert_equal_int
from tests._split_harness import MAX_DRIVE_ITERS, assert_bytes_equal
from tests.http.test_decode_boundaries_existing_api import fixture


def _hello_gz() -> List[Byte]:
    var b: List[Byte] = [31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 203, 72, 205, 201, 201, 87, 40, 207, 47, 202, 73, 1, 0, 133, 17, 74, 13, 11, 0, 0, 0]
    return b^


def test_step_respects_max_out_and_terminates() raises:
    var data = fixture("text_262145.gz")
    var dec = ContentDecoder(ContentEncoding.gzip(), DecoderLimits(0, 0, 0))
    var out = List[Byte]()
    var off = 0
    for _ in range(MAX_DRIVE_ITERS):
        var before = len(out)
        var step = dec.step_into(out, Span(data)[off:], 1000)
        assert_true(step.produced <= 1000, "produced > max_out")
        assert_equal_int(len(out) - before, step.produced, "produced matches appended bytes")
        off += step.consumed
        if off == len(data) and step.status != DecodeStatus.NEED_OUTPUT:
            break
    assert_equal_int(off, len(data), "all input consumed")
    assert_equal_int(len(out), 262145, "all output produced")
    var fin = dec.finish_step_into(out, 1000)
    assert_true(fin.status == DecodeStatus.DONE, "finish is DONE")
    # A closed decoder rejects further steps, even empty ones.
    var empty = List[Byte]()
    var after_finish = String("")
    try:
        _ = dec.step_into(out, Span(empty), 1000)
    except e:
        after_finish = String(e)
    assert_true("feed after finish" in after_finish, "step after finish must raise 'feed after finish'")


def test_bomb_ratio_error_across_steps() raises:
    var data = fixture("zeros_32m.gz")
    var dec = ContentDecoder(ContentEncoding.gzip(), DecoderLimits(0, 0, 10000))
    var out = List[Byte]()
    var off = 0
    var raised = False
    for _ in range(MAX_DRIVE_ITERS):
        var before = len(out)
        try:
            var step = dec.step_into(out, Span(data)[off:], 65536)
            off += step.consumed
            if off == len(data) and step.status != DecodeStatus.NEED_OUTPUT:
                break
        except e:
            raised = "(-4)" in String(e)
            assert_equal_int(len(out), before, "failing step must not change len(out)")
            break
    assert_true(raised, "bomb must hit the ratio cap (-4) across steps")
    assert_true(len(out) <= (len(data) if len(data) > 1024 else 1024) * 100 + 65536, "output bounded by the ratio")


def test_output_cap_exact_and_minus_one() raises:
    var data = fixture("text_262144.gz")
    var ok = ContentDecoder(ContentEncoding.gzip(), DecoderLimits(0, 262144, 0))
    var out = List[Byte]()
    ok.feed_into(out, data)
    ok.finish_into(out)
    assert_equal_int(len(out), 262144, "cap equal to decoded size succeeds")
    var tight = ContentDecoder(ContentEncoding.gzip(), DecoderLimits(0, 262143, 0))
    var out2 = List[Byte]()
    var off = 0
    var raised = False
    for _ in range(MAX_DRIVE_ITERS):
        var before = len(out2)
        try:
            var step = tight.step_into(out2, Span(data)[off:], 65536)
            off += step.consumed
            if off == len(data) and step.status != DecodeStatus.NEED_OUTPUT:
                _ = tight.finish_step_into(out2, 65536)
                break
        except e:
            raised = "(-3)" in String(e)
            assert_equal_int(len(out2), before, "failing step must not change len(out)")
            # Three full 64 KiB steps fit under the cap; the fourth produces
            # the sentinel byte past it and is the only one rolled back.
            assert_equal_int(len(out2), 196608, "earlier steps keep their output")
            break
    assert_true(raised, "cap one less than decoded size must raise (-3)")


def test_caps_enforced_on_finish_path() raises:
    var encs: List[String] = ["gz", "br"]
    for i in range(len(encs)):
        var is_gz = encs[i] == "gz"
        var data = fixture("zeros_32m.gz" if is_gz else "zeros_64m.br")
        var dec = ContentDecoder(
            ContentEncoding.gzip() if is_gz else ContentEncoding.brotli(),
            DecoderLimits(0, 1000, 0),
        )
        var out = List[Byte]()
        var step = DecodeStep(consumed=0, produced=0, status=DecodeStatus.DONE)
        try:
            step = dec.step_into(out, Span(data), 1000)
        except e:
            assert_true(False, encs[i] + ": first step must not raise: " + String(e))
        assert_equal_int(step.produced, 1000, encs[i] + ": first step fills max_out")
        assert_true(step.status == DecodeStatus.NEED_OUTPUT, encs[i] + ": output pending")
        var raised = False
        try:
            _ = dec.finish_step_into(out, 1000)
        except e:
            raised = "(-3)" in String(e)
        assert_true(raised, encs[i] + ": finish must enforce the output cap (-3)")
        assert_equal_int(len(out), 1000, encs[i] + ": failing finish must not change len(out)")


def test_trailing_garbage_discarded_flag_and_cap() raises:
    var data = _hello_gz()
    var junk = String("trailing junk")
    data.extend(junk.as_bytes())
    var dec = ContentDecoder(ContentEncoding.gzip())
    var out = dec.feed(data)
    out.extend(dec.finish())
    assert_true(String(StringSlice(unsafe_from_utf8=Span(out))) == "hello world", "decoded member only")
    assert_true(dec.trailing_garbage_seen(), "trailing flag set")
    var held = _hello_gz()
    held.append(0x1F)
    var dec2 = ContentDecoder(ContentEncoding.gzip())
    _ = dec2.feed(held)
    _ = dec2.finish()
    assert_true(dec2.trailing_garbage_seen(), "held 0x1f at finish counts as trailing")
    var huge = _hello_gz()
    huge.extend(List[Byte](length=1 << 20, fill=0))
    var dec3 = ContentDecoder(ContentEncoding.gzip(), DecoderLimits(UInt64(len(_hello_gz()) + 1000), 0, 0))
    var raised = False
    try:
        _ = dec3.feed(huge)
    except e:
        raised = "(-2)" in String(e)
    assert_true(raised, "huge trailing tail hits the input cap (-2)")


def test_finish_twice_and_feed_after_finish() raises:
    var gz = _hello_gz()
    var dec = ContentDecoder(ContentEncoding.gzip())
    _ = dec.feed(gz)
    _ = dec.finish()
    assert_equal_int(len(dec.finish()), 0, "second finish returns nothing")
    var raised = False
    try:
        _ = dec.feed(gz)
    except e:
        raised = "feed after finish" in String(e)
    assert_true(raised, "gzip feed after finish must raise")
    var br = fixture("text_262143.br")
    # 59 bytes inflating to 256 KiB trips the default 100:1 ratio; disable it.
    var dbr = ContentDecoder(ContentEncoding.brotli(), DecoderLimits(0, 0, 0))
    _ = dbr.feed(br)
    _ = dbr.finish()
    assert_equal_int(len(dbr.finish()), 0, "brotli second finish returns nothing")
    var raised_br = False
    try:
        _ = dbr.feed(br)
    except e:
        raised_br = "feed after finish" in String(e)
    assert_true(raised_br, "brotli feed after finish must raise")


def test_error_poisons_decoder() raises:
    var data = fixture("zeros_32m.gz")
    var dec = ContentDecoder(ContentEncoding.gzip(), DecoderLimits(0, 0, 10000))
    var failed = False
    try:
        _ = dec.feed(data)
    except:
        failed = True
    assert_true(failed, "bomb must fail first")
    var fin_poisoned = False
    var sink = List[Byte]()
    try:
        _ = dec.finish_step_into(sink, 64)
    except e:
        fin_poisoned = "decoder failed" in String(e)
    assert_true(fin_poisoned, "finish after an error must raise 'decoder failed'")
    var poisoned = False
    try:
        _ = dec.feed(_hello_gz())
    except e:
        poisoned = "decoder failed" in String(e)
    assert_true(poisoned, "step after an error must raise 'decoder failed'")


def test_empty_inputs() raises:
    var encs: List[String] = ["gz", "br", "id"]
    for i in range(len(encs)):
        var enc = ContentEncoding.gzip() if encs[i] == "gz" else (
            ContentEncoding.brotli() if encs[i] == "br" else ContentEncoding.identity()
        )
        var dec = ContentDecoder(enc)
        var out = List[Byte]()
        var empty = List[Byte]()
        var step = dec.step_into(out, Span(empty), 64)
        assert_equal_int(step.consumed, 0, encs[i] + ": empty step consumes nothing")
        assert_equal_int(step.produced, 0, encs[i] + ": empty step produces nothing")
        assert_true(step.status == DecodeStatus.NEED_INPUT, encs[i] + ": empty step is NEED_INPUT")
        dec.feed_into(out, empty)
        assert_equal_int(len(out), 0, encs[i] + ": empty feed appends nothing")


def test_max_out_below_one_raises() raises:
    var encs: List[String] = ["gz", "br", "id"]
    for i in range(len(encs)):
        var enc = ContentEncoding.gzip() if encs[i] == "gz" else (
            ContentEncoding.brotli() if encs[i] == "br" else ContentEncoding.identity()
        )
        var dec = ContentDecoder(enc)
        var out = List[Byte]()
        # Valid input of each decoder's own format, so only max_out can fail.
        var input = fixture("text_262143.br") if encs[i] == "br" else _hello_gz()
        var msg = String("")
        try:
            _ = dec.step_into(out, Span(input), 0)
        except e:
            msg = String(e)
        assert_true("max_out" in msg, encs[i] + ": max_out=0 must raise the max_out error, got '" + msg + "'")
        assert_equal_int(len(out), 0, encs[i] + ": max_out=0 appends nothing")


def test_brotli_trailing_after_success() raises:
    var br = fixture("text_262143.br")
    var data = br.copy()
    data.extend(String("junk").as_bytes())
    var dec = ContentDecoder(ContentEncoding.brotli(), DecoderLimits(0, 0, 0))
    var out = List[Byte]()
    var off = 0
    for _ in range(MAX_DRIVE_ITERS):
        var step = dec.step_into(out, Span(data)[off:], 65536)
        off += step.consumed
        if off == len(data) and step.status != DecodeStatus.NEED_OUTPUT:
            assert_true(step.status == DecodeStatus.DONE, "br: stream end is DONE")
            break
    assert_equal_int(off, len(data), "br: trailing bytes are consumed")
    assert_equal_int(len(out), 262143, "br: trailing bytes produce no output")
    assert_true(dec.trailing_garbage_seen(), "br: trailing flag set")
    # Trailing bytes count against input_cap like any other input.
    var capped = ContentDecoder(ContentEncoding.brotli(), DecoderLimits(UInt64(len(br) + 3), 0, 0))
    var sink = List[Byte]()
    capped.feed_into(sink, br)
    var junk = List[Byte]()
    junk.extend(String("junk").as_bytes())
    var raised = False
    try:
        capped.feed_into(sink, junk)
    except e:
        raised = "(-2)" in String(e)
    assert_true(raised, "br: trailing bytes past input_cap raise (-2)")


def test_held_1f_then_non_member_byte() raises:
    var dec = ContentDecoder(ContentEncoding.gzip())
    var out = List[Byte]()
    var first = _hello_gz()
    first.append(0x1F)
    var s1 = dec.step_into(out, Span(first), 64)
    assert_equal_int(s1.consumed, len(first), "held 0x1f is consumed")
    var tail: List[Byte] = [0x41, 0x42]
    var s2 = dec.step_into(out, Span(tail), 64)
    assert_equal_int(s2.consumed, 2, "non-member tail is consumed")
    assert_equal_int(s2.produced, 0, "non-member tail produces nothing")
    var fin = dec.finish_step_into(out, 64)
    assert_true(fin.status == DecodeStatus.DONE, "finish is DONE")
    assert_true(String(StringSlice(unsafe_from_utf8=Span(out))) == "hello world", "output unchanged")
    assert_true(dec.trailing_garbage_seen(), "held 0x1f + non-0x8b is trailing garbage")


def test_ratio_enforced_on_finish_path() raises:
    var encs: List[String] = ["gz", "br"]
    for i in range(len(encs)):
        var is_gz = encs[i] == "gz"
        var data = fixture("zeros_32m.gz" if is_gz else "zeros_64m.br")
        var dec = ContentDecoder(
            ContentEncoding.gzip() if is_gz else ContentEncoding.brotli(),
            DecoderLimits(0, 0, 10000),
        )
        var out = List[Byte]()
        # 100:1 over the 1 KiB floor: exactly 102400 bytes are allowed.
        var step = dec.step_into(out, Span(data), 102400)
        assert_true(step.status == DecodeStatus.NEED_OUTPUT, encs[i] + ": output pending")
        var msg = String("")
        try:
            _ = dec.finish_step_into(out, 1000)
        except e:
            msg = String(e)
        assert_true("(-4)" in msg, encs[i] + ": finish must enforce the ratio cap (-4), got '" + msg + "'")
        assert_equal_int(len(out), step.produced, encs[i] + ": failing finish must not change len(out)")


def test_brotli_finish_need_output_then_done() raises:
    var data = fixture("text_262143.br")
    var dec = ContentDecoder(ContentEncoding.brotli(), DecoderLimits(0, 0, 0))
    var out = List[Byte]()
    var off = 0
    for _ in range(MAX_DRIVE_ITERS):
        if off == len(data):
            break
        off += dec.step_into(out, Span(data)[off:], 1000).consumed
    assert_equal_int(off, len(data), "all input consumed")
    var saw_need_output = False
    var done = False
    for _ in range(MAX_DRIVE_ITERS):
        var fin = dec.finish_step_into(out, 65536)
        if fin.status == DecodeStatus.DONE:
            done = True
            break
        saw_need_output = saw_need_output or fin.status == DecodeStatus.NEED_OUTPUT
    assert_true(saw_need_output, "finish reports NEED_OUTPUT while output is pending")
    assert_true(done, "finish completes")
    assert_bytes_equal(out, fixture("text_262143.bin"), "brotli finish drain")


def main() raises:
    var passed = 0
    var total = 13
    var names: List[String] = [
        "test_step_respects_max_out_and_terminates", "test_bomb_ratio_error_across_steps",
        "test_output_cap_exact_and_minus_one", "test_caps_enforced_on_finish_path",
        "test_trailing_garbage_discarded_flag_and_cap", "test_finish_twice_and_feed_after_finish",
        "test_error_poisons_decoder", "test_empty_inputs",
        "test_max_out_below_one_raises", "test_brotli_trailing_after_success",
        "test_held_1f_then_non_member_byte", "test_ratio_enforced_on_finish_path",
        "test_brotli_finish_need_output_then_done",
    ]
    for i in range(total):
        try:
            if i == 0: test_step_respects_max_out_and_terminates()
            elif i == 1: test_bomb_ratio_error_across_steps()
            elif i == 2: test_output_cap_exact_and_minus_one()
            elif i == 3: test_caps_enforced_on_finish_path()
            elif i == 4: test_trailing_garbage_discarded_flag_and_cap()
            elif i == 5: test_finish_twice_and_feed_after_finish()
            elif i == 6: test_error_poisons_decoder()
            elif i == 7: test_empty_inputs()
            elif i == 8: test_max_out_below_one_raises()
            elif i == 9: test_brotli_trailing_after_success()
            elif i == 10: test_held_1f_then_non_member_byte()
            elif i == 11: test_ratio_enforced_on_finish_path()
            else: test_brotli_finish_need_output_then_done()
            print("PASS: " + names[i])
            passed += 1
        except e:
            print("FAIL: " + names[i] + ": " + String(e))
    print("test_decode_boundaries: " + String(passed) + "/" + String(total) + " passed")
    if passed != total:
        raise "some decoder step tests failed"
