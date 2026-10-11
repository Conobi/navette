# tests/http/test_decode_boundaries_existing_api.mojo
"""Red Gate (existing API): gzip/brotli bodies must decode fully at any split,
cut-off streams must fail at finish, and the caps must hold.

On main, one `feed` produces at most 256 KiB and drops the unconsumed
input, `finish` accepts truncated streams, and the ratio cap is disarmed
below 1 KiB of input.
"""
from std.collections import Span
from std.io.file import FileHandle
from navette.http.decode import ContentDecoder, ContentEncoding
from navette.compress.lib import DecoderLimits
from tests._test_util import assert_true
from tests._split_harness import split_plans, assert_bytes_equal


comptime FIX = "tests/fixtures/compress/"


def fixture(name: String) raises -> List[Byte]:
    """Read a generated fixture; tells the reader how to create it when missing."""
    try:
        var fh = FileHandle(FIX + name, "r")
        var b = fh.read_bytes()
        fh.close()
        return b^
    except:
        raise Error("missing fixture " + FIX + name + ": run scripts/gen_compress_fixtures.sh")


def _decode_plan(enc: ContentEncoding, data: List[Byte], chunks: List[Int], limits: DecoderLimits) raises -> List[Byte]:
    """Decode `data` fed per `chunks`, then finish. Raises like the decoder does."""
    var dec = ContentDecoder(enc, limits)
    var out = List[Byte]()
    var off = 0
    for i in range(len(chunks)):
        var piece = List[Byte]()
        piece.extend(Span(data)[off:off + chunks[i]])
        dec.feed_into(out, piece)
        off += chunks[i]
    dec.finish_into(out)
    return out^


def test_sizes_and_splits() raises:
    var sizes: List[Int] = [262143, 262144, 262145, 1048576]
    var encs: List[String] = ["gz", "br"]
    for si in range(len(sizes)):
        var plain = fixture("text_" + String(sizes[si]) + ".bin")
        for ei in range(len(encs)):
            var enc = ContentEncoding.gzip() if encs[ei] == "gz" else ContentEncoding.brotli()
            var data = fixture("text_" + String(sizes[si]) + "." + encs[ei])
            var plans = split_plans(
                len(data), UInt64(sizes[si]), sampled=8, randoms=4, exhaustive_max=0,
            )
            for p in range(len(plans)):
                var label = encs[ei] + " size=" + String(sizes[si]) + " plan=" + plans[p].label
                var got: List[Byte]
                try:
                    got = _decode_plan(enc, data, plans[p].chunks, DecoderLimits(0, 0, 0))
                except e:
                    assert_true(False, label + ": raised " + String(e))
                    return
                assert_bytes_equal(got, plain, label)


def test_truncated_streams_raise_on_finish() raises:
    var encs: List[String] = ["gz", "br"]
    for ei in range(len(encs)):
        var enc = ContentEncoding.gzip() if encs[ei] == "gz" else ContentEncoding.brotli()
        var data = fixture("text_262145." + encs[ei])
        var cuts: List[Int] = [1, 2, 10, len(data) // 2, len(data) - 9, len(data) - 1]
        for ci in range(len(cuts)):
            var chunks: List[Int] = [cuts[ci]]
            var label = encs[ei] + " cut@" + String(cuts[ci])
            var raised = False
            try:
                _ = _decode_plan(enc, data, chunks, DecoderLimits(0, 0, 0))
            except e:
                raised = True
                assert_true("truncated" in String(e), label + ": wrong error " + String(e))
            assert_true(raised, label + ": truncated stream decoded without error")


def test_one_call_body_input_cap_exact() raises:
    var plain = fixture("noise_2m.bin")
    var encs: List[String] = ["gz", "br"]
    for ei in range(len(encs)):
        var enc = ContentEncoding.gzip() if encs[ei] == "gz" else ContentEncoding.brotli()
        var data = fixture("noise_2m." + encs[ei])
        var whole: List[Int] = [len(data)]
        var label = encs[ei] + " one-call 2 MiB body, input_cap = compressed length"
        var got: List[Byte]
        try:
            got = _decode_plan(enc, data, whole, DecoderLimits(UInt64(len(data)), 0, 0))
        except e:
            assert_true(False, label + ": raised " + String(e))
            return
        assert_bytes_equal(got, plain, label)


def test_small_brotli_bomb_unbounded_output_cap() raises:
    var data = fixture("zeros_64m.br")
    assert_true(len(data) < 1024, "fixture must be a sub-1 KiB bomb")
    var whole: List[Int] = [len(data)]
    try:
        _ = _decode_plan(ContentEncoding.brotli(), data, whole, DecoderLimits(0, 0, 10000))
    except e:
        assert_true(
            "(-4)" in String(e),
            "sub-1 KiB brotli bomb raised the wrong error: " + String(e),
        )
        return
    assert_true(False, "sub-1 KiB brotli bomb with output_cap=0 must hit the ratio cap (-4)")


def test_multimember_split_at_member_boundary() raises:
    var data = fixture("multi.gz")
    var plain = fixture("multi.bin")
    var bstr = String(StringSlice(unsafe_from_utf8=Span(fixture("multi.boundary"))))
    var boundary = atol(bstr.strip())
    # Member A's 8-byte trailer and member B's 10-byte header.
    for delta in range(-8, 11):
        var cut = boundary + delta
        var chunks: List[Int] = [cut, len(data) - cut]
        var label = "multi.gz cut@" + String(cut)
        var got: List[Byte]
        try:
            got = _decode_plan(ContentEncoding.gzip(), data, chunks, DecoderLimits(0, 0, 0))
        except e:
            assert_true(False, label + ": raised " + String(e))
            return
        assert_bytes_equal(got, plain, label)


def test_empty_body_finish_done() raises:
    var encs: List[String] = ["gz", "br"]
    for ei in range(len(encs)):
        var enc = ContentEncoding.gzip() if encs[ei] == "gz" else ContentEncoding.brotli()
        var dec = ContentDecoder(enc)
        try:
            var out = dec.finish()
            assert_true(len(out) == 0, encs[ei] + ": empty body produced output")
        except e:
            assert_true(False, encs[ei] + ": finish on empty body raised " + String(e))


def main() raises:
    var passed = 0
    var total = 6
    try:
        test_sizes_and_splits(); print("PASS: test_sizes_and_splits"); passed += 1
    except e:
        print("FAIL: test_sizes_and_splits: " + String(e))
    try:
        test_truncated_streams_raise_on_finish(); print("PASS: test_truncated_streams_raise_on_finish"); passed += 1
    except e:
        print("FAIL: test_truncated_streams_raise_on_finish: " + String(e))
    try:
        test_one_call_body_input_cap_exact(); print("PASS: test_one_call_body_input_cap_exact"); passed += 1
    except e:
        print("FAIL: test_one_call_body_input_cap_exact: " + String(e))
    try:
        test_small_brotli_bomb_unbounded_output_cap(); print("PASS: test_small_brotli_bomb_unbounded_output_cap"); passed += 1
    except e:
        print("FAIL: test_small_brotli_bomb_unbounded_output_cap: " + String(e))
    try:
        test_multimember_split_at_member_boundary(); print("PASS: test_multimember_split_at_member_boundary"); passed += 1
    except e:
        print("FAIL: test_multimember_split_at_member_boundary: " + String(e))
    try:
        test_empty_body_finish_done(); print("PASS: test_empty_body_finish_done"); passed += 1
    except e:
        print("FAIL: test_empty_body_finish_done: " + String(e))
    print("test_decode_boundaries_existing_api: " + String(passed) + "/" + String(total) + " passed")
    if passed != total:
        raise "some decoder boundary tests failed"
