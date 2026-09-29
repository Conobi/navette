# tests/h2/test_hpack_static_table.mojo
#
# Full-surface validation of the HPACK static table against RFC 7541 Appendix A.

from navette.h2.hpack_table import StaticTable
from tests._test_util import assert_equal_int


def test_static_table_full_surface() raises:
    """Validate every HPACK static table entry against RFC 7541 Appendix A."""
    # RFC 7541 Appendix A — 61 entries (1-based), interleaved (name, value).
    # Independently typed from the RFC, not copy-pasted from production code.
    var expected: List[String] = [
        ":authority", "",
        ":method", "GET",  ":method", "POST",
        ":path", "/",  ":path", "/index.html",
        ":scheme", "http",  ":scheme", "https",
        ":status", "200",  ":status", "204",  ":status", "206",
        ":status", "304",  ":status", "400",  ":status", "404",  ":status", "500",
        "accept-charset", "",
        "accept-encoding", "gzip, deflate",
        "accept-language", "",
        "accept-ranges", "",
        "accept", "",
        "access-control-allow-origin", "",
        "age", "",
        "allow", "",
        "authorization", "",
        "cache-control", "",
        "content-disposition", "",
        "content-encoding", "",
        "content-language", "",
        "content-length", "",
        "content-location", "",
        "content-range", "",
        "content-type", "",
        "cookie", "",
        "date", "",
        "etag", "",
        "expect", "",
        "expires", "",
        "from", "",
        "host", "",
        "if-match", "",
        "if-modified-since", "",
        "if-none-match", "",
        "if-range", "",
        "if-unmodified-since", "",
        "last-modified", "",
        "link", "",
        "location", "",
        "max-forwards", "",
        "proxy-authenticate", "",
        "proxy-authorization", "",
        "range", "",
        "referer", "",
        "refresh", "",
        "retry-after", "",
        "server", "",
        "set-cookie", "",
        "strict-transport-security", "",
        "transfer-encoding", "",
        "user-agent", "",
        "vary", "",
        "via", "",
        "www-authenticate", "",
    ]
    assert_equal_int(len(expected), 122, "oracle data must have 122 elements (61 pairs)")
    var table = StaticTable()
    for i in range(1, 62):
        var entry = table.lookup(i)
        var exp_name = expected[(i - 1) * 2]
        var exp_value = expected[(i - 1) * 2 + 1]
        if entry[0] != exp_name or entry[1] != exp_value:
            raise Error(
                "HPACK static table mismatch at index " + String(i)
                + ": expected (" + exp_name + ", " + exp_value
                + ") got (" + entry[0] + ", " + entry[1] + ")"
            )
    print("  test_static_table_full_surface: PASS (61/61 entries verified)")


def test_lookup_out_of_range() raises:
    """Index 0 and 62+ must return empty tuples."""
    var table = StaticTable()
    var zero = table.lookup(0)
    if zero[0] != "" or zero[1] != "":
        raise Error("index 0 should return empty tuple")
    var oob = table.lookup(62)
    if oob[0] != "" or oob[1] != "":
        raise Error("index 62 should return empty tuple")
    var neg = table.lookup(-1)
    if neg[0] != "" or neg[1] != "":
        raise Error("index -1 should return empty tuple")
    print("  test_lookup_out_of_range: PASS")


def main() raises:
    print("=== test_hpack_static_table ===")
    test_static_table_full_surface()
    test_lookup_out_of_range()
    print("test_hpack_static_table: all tests passed")
