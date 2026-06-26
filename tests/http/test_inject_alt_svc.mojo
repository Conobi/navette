"""test_inject_alt_svc.mojo — seed the Alt-Svc cache from a DNS-derived entry."""

from tests._test_util import assert_true, assert_equal_int, assert_equal_str

from navette.http.coro_client import HttpCoroClient
from navette.http.alt_svc import Origin, AltSvcEntry


def test_inject_seeds_h3_entry() raises:
    """Seeding an h3 entry makes it visible via lookup_alt_svc."""
    var client = HttpCoroClient()
    var origin = Origin(scheme=String("https"), host=String("example.com"), port=UInt16(443))
    var entries = List[AltSvcEntry]()
    entries.append(
        AltSvcEntry(
            protocol=String("h3"), host=String(""), port=UInt16(443),
            max_age_secs=UInt(3600), persist=False,
        )
    )
    client.inject_alt_svc_entries(Origin(other=origin), entries^, UInt(1000))
    var got = client.lookup_alt_svc(Origin(other=origin), UInt(1500))
    assert_equal_int(len(got), 1, "seeded entry count")
    assert_equal_str(got[0].protocol, String("h3"), "seeded entry protocol")
    # Verify at least one entry has protocol == "h3" (mirrors _cache_has_h3 check).
    var has_h3 = False
    for i in range(len(got)):
        if got[i].protocol == String("h3"):
            has_h3 = True
    assert_true(has_h3, "has_h3")


def test_inject_respects_expiry() raises:
    """An entry whose max-age has elapsed is not returned by lookup."""
    var client = HttpCoroClient()
    var origin = Origin(scheme=String("https"), host=String("a.test"), port=UInt16(443))
    var entries = List[AltSvcEntry]()
    entries.append(
        AltSvcEntry(
            protocol=String("h3"), host=String(""), port=UInt16(443),
            max_age_secs=UInt(30), persist=False,
        )
    )
    client.inject_alt_svc_entries(Origin(other=origin), entries^, UInt(1000))
    # received_at + max_age_secs = 1000 + 30 = 1030; 1030 > 1030 is False -> expired
    var got = client.lookup_alt_svc(Origin(other=origin), UInt(1030))
    assert_equal_int(len(got), 0, "expired entry count")


def main() raises:
    test_inject_seeds_h3_entry()
    test_inject_respects_expiry()
    print("All test_inject_alt_svc tests passed.")
