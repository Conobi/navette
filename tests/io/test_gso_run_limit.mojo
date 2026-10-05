"""GSO run sizing: one segmented send never carries more than the 65,507-byte UDP payload the kernel accepts.

Linux rejects a larger send with EMSGSIZE (the whole IP packet must fit
its 16-bit length), so 55+ segments of 1,200 B were lost at once.
"""

from navette.runtime.udp_socket_state import gso_run_limit
from tests._test_util import assert_true, assert_equal_int


def test_run_fits_ipv4_payload() raises:
    for seg in [1200, 1252, 1350, 1452, 1472]:
        var n = gso_run_limit(seg, 64)
        assert_true(n * seg <= 65507, "run within 65,507 B, seg=" + String(seg))
        assert_true((n + 1) * seg > 65507, "and no smaller than needed, seg=" + String(seg))
    assert_equal_int(gso_run_limit(1200, 64), 54, "54 x 1,200 B: 55 failed with EMSGSIZE")
    print("PASS: test_run_fits_ipv4_payload")


def test_segment_count_cap_still_applies() raises:
    assert_equal_int(gso_run_limit(100, 64), 64, "small segments stop at UDP_MAX_SEGMENTS")
    assert_equal_int(gso_run_limit(1200, 1), 1, "no GSO stays one per send")
    assert_equal_int(gso_run_limit(70000, 64), 1, "an oversized datagram still goes alone")
    print("PASS: test_segment_count_cap_still_applies")


def main() raises:
    test_run_fits_ipv4_payload()
    test_segment_count_cap_still_applies()
