# tests/test_alt_svc.mojo
#
# Unit tests for Alt-Svc (RFC 7838, M2.5b §7.2).
from mojo_net.http.alt_svc import Origin, AltSvcEntry, parse_alt_svc, AltSvcCache
from tests._test_util import assert_true, assert_false, assert_equal_int, assert_equal_str


def test_origin_roundtrip() raises:
    var o = Origin(scheme=String("https"), host=String("example.com"), port=UInt16(443))
    assert_equal_str(o.scheme, String("https"), "origin.scheme")
    assert_equal_str(o.host, String("example.com"), "origin.host")
    assert_equal_int(Int(o.port), 443, "origin.port")


def test_origin_equality() raises:
    var a = Origin(scheme=String("https"), host=String("a.test"), port=UInt16(443))
    var b = Origin(scheme=String("https"), host=String("a.test"), port=UInt16(443))
    var c = Origin(scheme=String("https"), host=String("b.test"), port=UInt16(443))
    assert_true(a == b, "eq.ab")
    assert_false(a == c, "ne.ac")


def test_alt_svc_entry_construction() raises:
    var e = AltSvcEntry(
        protocol=String("h3"),
        host=String(""),
        port=UInt16(443),
        max_age_secs=UInt(3600),
        persist=False,
    )
    assert_equal_str(e.protocol, String("h3"), "entry.protocol")
    assert_equal_str(e.host, String(""), "entry.host_empty")
    assert_equal_int(Int(e.port), 443, "entry.port")
    assert_equal_int(Int(e.max_age_secs), 3600, "entry.ma")
    assert_false(e.persist, "entry.persist")


def test_parse_single_entry_h3_default_host() raises:
    var entries = parse_alt_svc(String("h3=\":443\"; ma=3600"))
    assert_equal_int(len(entries), 1, "single.count")
    assert_equal_str(entries[0].protocol, String("h3"), "single.protocol")
    assert_equal_str(entries[0].host, String(""), "single.host_default")
    assert_equal_int(Int(entries[0].port), 443, "single.port")
    assert_equal_int(Int(entries[0].max_age_secs), 3600, "single.ma")
    assert_false(entries[0].persist, "single.persist")


def test_parse_multi_entry() raises:
    var entries = parse_alt_svc(
        String("h2=\"alt.example.com:443\"; ma=86400, h3=\":443\"; ma=3600")
    )
    assert_equal_int(len(entries), 2, "multi.count")
    assert_equal_str(entries[0].protocol, String("h2"), "multi[0].proto")
    assert_equal_str(entries[0].host, String("alt.example.com"), "multi[0].host")
    assert_equal_int(Int(entries[0].port), 443, "multi[0].port")
    assert_equal_int(Int(entries[1].max_age_secs), 3600, "multi[1].ma")


def test_parse_clear_returns_empty_list() raises:
    var entries = parse_alt_svc(String("clear"))
    assert_equal_int(len(entries), 0, "clear.empty")


def test_parse_persist_flag() raises:
    var entries = parse_alt_svc(String("h3=\":443\"; ma=3600; persist=1"))
    assert_equal_int(len(entries), 1, "persist.count")
    assert_true(entries[0].persist, "persist.flag")


def test_cache_insert_and_lookup() raises:
    var cache = AltSvcCache()
    var origin = Origin(scheme=String("https"), host=String("example.com"), port=UInt16(443))
    var entries = parse_alt_svc(String("h3=\":443\"; ma=3600"))
    cache.insert(Origin(other=origin), entries^, UInt(1000))
    var found = cache.lookup(origin, UInt(2000))
    assert_equal_int(len(found), 1, "lookup.count")
    assert_equal_str(found[0].protocol, String("h3"), "lookup.proto")


def test_cache_lookup_expired_returns_empty() raises:
    var cache = AltSvcCache()
    var origin = Origin(scheme=String("https"), host=String("a.test"), port=UInt16(443))
    var entries = parse_alt_svc(String("h3=\":443\"; ma=10"))
    cache.insert(Origin(other=origin), entries^, UInt(1000))
    # now = 2000, received_at = 1000, ma = 10 → expired
    var found = cache.lookup(origin, UInt(2000))
    assert_equal_int(len(found), 0, "expired.empty")


def test_cache_clear() raises:
    var cache = AltSvcCache()
    var origin = Origin(scheme=String("https"), host=String("c.test"), port=UInt16(443))
    var entries = parse_alt_svc(String("h3=\":443\"; ma=3600"))
    cache.insert(Origin(other=origin), entries^, UInt(1000))
    cache.clear(origin)
    var found = cache.lookup(origin, UInt(1500))
    assert_equal_int(len(found), 0, "clear.empty")


def test_cache_clear_expired_prunes() raises:
    var cache = AltSvcCache()
    var fresh = Origin(scheme=String("https"), host=String("fresh.test"), port=UInt16(443))
    var stale = Origin(scheme=String("https"), host=String("stale.test"), port=UInt16(443))
    var fresh_entries = parse_alt_svc(String("h3=\":443\"; ma=3600"))
    var stale_entries = parse_alt_svc(String("h3=\":443\"; ma=10"))
    cache.insert(Origin(other=fresh), fresh_entries^, UInt(1000))
    cache.insert(Origin(other=stale), stale_entries^, UInt(1000))
    cache.clear_expired(UInt(2000))
    var fresh_found = cache.lookup(fresh, UInt(2000))
    var stale_found = cache.lookup(stale, UInt(2000))
    assert_equal_int(len(fresh_found), 1, "fresh.present")
    assert_equal_int(len(stale_found), 0, "stale.removed")


def main() raises:
    test_origin_roundtrip()
    test_origin_equality()
    test_alt_svc_entry_construction()
    test_parse_single_entry_h3_default_host()
    test_parse_multi_entry()
    test_parse_clear_returns_empty_list()
    test_parse_persist_flag()
    test_cache_insert_and_lookup()
    test_cache_lookup_expired_returns_empty()
    test_cache_clear()
    test_cache_clear_expired_prunes()
    print("test_alt_svc: all tests passed")
