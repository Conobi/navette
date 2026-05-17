# tests/test_compress_limits.mojo
#
# Limit-enforcement tests for ContentDecoder via libcompress_mojo.so.
# AC3: limits must be explicit Mojo-side knobs, not magic constants in
# the C wrapper. AC4 (no caller-visible API change) is covered by
# tests/test_decode.mojo — this file is the *new* surface check.
from navette.http.decode import ContentDecoder, ContentEncoding
from navette.compress.lib import DecoderLimits
from tests._test_util import assert_true, assert_equal_int


def _make_gzip_hello_world() -> List[UInt8]:
    """Shared fixture: gzip.compress(b'hello world') with mtime=0."""
    var b = List[UInt8]()
    b.append(31); b.append(139); b.append(8); b.append(0)
    b.append(0); b.append(0); b.append(0); b.append(0)
    b.append(2); b.append(255); b.append(203); b.append(72)
    b.append(205); b.append(201); b.append(201); b.append(87)
    b.append(40); b.append(207); b.append(47); b.append(202)
    b.append(73); b.append(1); b.append(0); b.append(133)
    b.append(17); b.append(74); b.append(13); b.append(11)
    b.append(0); b.append(0); b.append(0)
    return b^


def _make_brotli_hello_world() -> List[UInt8]:
    """Shared fixture: brotli.compress(b'hello world')."""
    var b = List[UInt8]()
    b.append(11); b.append(5); b.append(128); b.append(104)
    b.append(101); b.append(108); b.append(108); b.append(111)
    b.append(32); b.append(119); b.append(111); b.append(114)
    b.append(108); b.append(100); b.append(3)
    return b^


# -- gzip input cap -----------------------------------------------------------

def test_gzip_input_cap_enforced() raises:
    """31-byte gzip fed under an 8-byte input cap raises -2."""
    var limits = DecoderLimits(input_cap=8, output_cap=1 << 20, ratio_x100=0)
    var dec = ContentDecoder(ContentEncoding.gzip(), limits)
    var raised = False
    try:
        var _out = dec.feed(_make_gzip_hello_world())
    except e:
        raised = True
        # Message format: "ContentDecoder.feed: decompression error (-2)"
        var msg = String(e)
        assert_true("(-2)" in msg, "expected (-2), got: " + msg)
    assert_true(raised, "gzip.input_cap must raise")
    print("PASS: test_gzip_input_cap_enforced")


# -- brotli input cap ---------------------------------------------------------

def test_brotli_input_cap_enforced() raises:
    """15-byte brotli fed under a 4-byte input cap raises -2."""
    var limits = DecoderLimits(input_cap=4, output_cap=1 << 20, ratio_x100=0)
    var dec = ContentDecoder(ContentEncoding.brotli(), limits)
    var raised = False
    try:
        var _out = dec.feed(_make_brotli_hello_world())
    except e:
        raised = True
        var msg = String(e)
        assert_true("(-2)" in msg, "expected (-2), got: " + msg)
    assert_true(raised, "brotli.input_cap must raise")
    print("PASS: test_brotli_input_cap_enforced")


# -- gzip output cap ----------------------------------------------------------

def test_gzip_output_cap_enforced() raises:
    """11-byte decompressed output under a 4-byte output cap raises -3."""
    var limits = DecoderLimits(input_cap=1 << 20, output_cap=4, ratio_x100=0)
    var dec = ContentDecoder(ContentEncoding.gzip(), limits)
    var raised = False
    try:
        var _out = dec.feed(_make_gzip_hello_world())
    except e:
        raised = True
        var msg = String(e)
        assert_true("(-3)" in msg, "expected (-3), got: " + msg)
    assert_true(raised, "gzip.output_cap must raise")
    print("PASS: test_gzip_output_cap_enforced")


# -- default DecoderLimits sanity ---------------------------------------------

def test_default_decoder_limits() raises:
    """Defaults are the documented 64 MiB / 256 MiB / 100:1."""
    var d = DecoderLimits.default()
    assert_equal_int(Int(d.input_cap),  64 * 1024 * 1024, "default.input_cap")
    assert_equal_int(Int(d.output_cap), 256 * 1024 * 1024, "default.output_cap")
    assert_equal_int(Int(d.ratio_x100), 10000,             "default.ratio_x100")
    print("PASS: test_default_decoder_limits")


# -- unlimited DecoderLimits passthrough --------------------------------------

def test_unlimited_decoder_limits_decodes() raises:
    """unlimited() = (0, 0, 0) — all checks disabled, decode succeeds."""
    var limits = DecoderLimits.unlimited()
    var dec = ContentDecoder(ContentEncoding.gzip(), limits)
    var out = dec.feed(_make_gzip_hello_world())
    var tail = dec.finish()
    for i in range(len(tail)):
        out.append(tail[i])
    assert_equal_int(len(out), 11, "unlimited.gzip.len")
    print("PASS: test_unlimited_decoder_limits_decodes")


def main() raises:
    test_default_decoder_limits()
    test_unlimited_decoder_limits_decodes()
    test_gzip_input_cap_enforced()
    test_brotli_input_cap_enforced()
    test_gzip_output_cap_enforced()
    print("ALL COMPRESS-LIMITS TESTS PASSED")
