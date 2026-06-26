"""test_svcb.mojo — DNS HTTPS/SVCB discovery unit tests."""

from std.testing import assert_equal, assert_true, assert_raises

from navette.net.svcb import _parse_resolv_conf, _first_nameserver, _encode_qname, _build_query, _decode_name, _read_u16


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    var b = s.as_bytes()
    for i in range(len(b)):
        out.append(b[i])
    return out^


def test_resolv_conf_first_ipv4_nameserver() raises:
    var conf = String(
        "# comment\n; also comment\n"
        "options edns0\n"
        "nameserver 9.9.9.9\n"
        "nameserver 1.1.1.1\n"
    )
    assert_equal(_parse_resolv_conf(_bytes(conf)), String("9.9.9.9"))


def test_resolv_conf_skips_ipv6_nameserver() raises:
    # IPv6 nameserver is ignored; the first *IPv4* line wins.
    var conf = String("nameserver 2001:4860:4860::8888\nnameserver 8.8.4.4\n")
    assert_equal(_parse_resolv_conf(_bytes(conf)), String("8.8.4.4"))


def test_resolv_conf_no_nameserver_returns_empty() raises:
    assert_equal(_parse_resolv_conf(_bytes(String("search lan\n"))), String(""))


def test_resolv_conf_crlf_lines_parsed_correctly() raises:
    # CRLF line endings must be stripped so the nameserver token is not
    # corrupted by a trailing CR byte.
    var conf = String("nameserver 1.2.3.4\r\nnameserver 5.6.7.8\r\n")
    assert_equal(_parse_resolv_conf(_bytes(conf)), String("1.2.3.4"))


def test_first_nameserver_missing_path_returns_default() raises:
    # When the given path does not exist, the fallback address is returned.
    var result = _first_nameserver("/no/such/resolv.conf")
    assert_equal(result, String("127.0.0.53"))


def test_query_golden_bytes() raises:
    # txn-id is the injected seam; the rest is asserted byte-for-byte.
    var q = _build_query(String("example.com"), UInt16(0x1234))
    # 12 header + 13 qname (3com:1+7+1+3+1 zero) + 4 qtype/class + 11 OPT = 40
    assert_equal(len(q), 40)
    assert_equal(q[0], UInt8(0x12))   # txn-id hi
    assert_equal(q[1], UInt8(0x34))   # txn-id lo
    assert_equal(q[2], UInt8(0x01))   # flags hi: RD=1
    assert_equal(q[3], UInt8(0x00))   # flags lo
    assert_equal(q[4], UInt8(0x00))   # QDCOUNT hi
    assert_equal(q[5], UInt8(0x01))   # QDCOUNT lo = 1
    assert_equal(q[10], UInt8(0x00))  # ARCOUNT hi
    assert_equal(q[11], UInt8(0x01))  # ARCOUNT lo = 1 (EDNS0 OPT)
    # question label run: 07 'example' 03 'com' 00
    assert_equal(q[12], UInt8(7))
    assert_equal(q[20], UInt8(3))
    assert_equal(q[24], UInt8(0))     # root label terminator
    assert_equal(q[25], UInt8(0x00))  # QTYPE hi
    assert_equal(q[26], UInt8(65))    # QTYPE lo = 65
    assert_equal(q[27], UInt8(0x00))  # QCLASS hi
    assert_equal(q[28], UInt8(1))     # QCLASS lo = IN
    # EDNS0 OPT (last 11 bytes): 00 | 00 29 | 04 D0 | 00 00 00 00 | 00 00
    var o = len(q) - 11
    assert_equal(q[o], UInt8(0x00))       # root name
    assert_equal(q[o + 1], UInt8(0x00))
    assert_equal(q[o + 2], UInt8(41))     # TYPE = 41 (OPT)
    assert_equal(q[o + 3], UInt8(0x04))   # CLASS = 1232 hi
    assert_equal(q[o + 4], UInt8(0xD0))   # CLASS = 1232 lo
    assert_equal(q[o + 5], UInt8(0x00))   # TTL byte 0 (extended-RCODE)
    assert_equal(q[o + 6], UInt8(0x00))   # TTL byte 1 (EDNS version)
    assert_equal(q[o + 7], UInt8(0x00))   # TTL byte 2 (DO=0 …)
    assert_equal(q[o + 8], UInt8(0x00))   # TTL byte 3
    assert_equal(q[o + 9], UInt8(0x00))   # RDLEN hi
    assert_equal(q[o + 10], UInt8(0x00))  # RDLEN lo = 0


def test_name_decompression_resolves_pointer() raises:
    # bytes: [0..]: 07 example 03 com 00 (offset 0), then a pointer 0xC000.
    var m = List[UInt8]()
    var qn = _encode_qname(String("example.com"))   # 13 bytes at offset 0
    for i in range(len(qn)):
        m.append(qn[i])
    m.append(UInt8(0xC0)); m.append(UInt8(0x00))     # pointer → offset 0
    var nm = _decode_name(m, len(qn))                # decode the pointer
    assert_equal(nm.value, String("example.com"))
    assert_equal(nm.next_off, len(qn) + 2)           # past the 2-byte pointer


def test_name_pointer_cycle_rejected() raises:
    # A self-pointer at offset 12 (→ 12) violates strictly-decreasing → raises.
    var m = List[UInt8]()
    for _k in range(12):
        m.append(UInt8(0))
    m.append(UInt8(0xC0)); m.append(UInt8(0x0C))     # pointer → 12 (itself)
    with assert_raises():
        _ = _decode_name(m, 12)


def test_name_forward_pointer_rejected() raises:
    # pointer at 0 → 4 (forward) must be rejected (kills cycles).
    var m = List[UInt8]()
    m.append(UInt8(0xC0)); m.append(UInt8(0x04))
    m.append(UInt8(0x00)); m.append(UInt8(0x00))
    m.append(UInt8(0x00))
    with assert_raises():
        _ = _decode_name(m, 0)


def test_name_label_pointer_ratchet_terminated_by_cap() raises:
    # Buffer: [0x01, 'A', 0xC0, 0x00] — a 1-byte label at offset 0 followed by
    # a pointer back to offset 0.  The pointer at offset 2 always targets
    # 0 < 2, so the strictly-decreasing guard passes on every iteration and
    # cannot stop the loop by itself.  It is the 255-octet cap that must
    # terminate the cycle.  Asserts it raises quickly (no hang).
    var m = List[UInt8]()
    m.append(UInt8(0x01))   # label length 1
    m.append(UInt8(65))     # 'A'
    m.append(UInt8(0xC0))   # pointer high byte (0b11xxxxxx)
    m.append(UInt8(0x00))   # pointer low byte → target offset 0
    with assert_raises():
        _ = _decode_name(m, 0)


def test_name_exceeds_255_octet_cap() raises:
    # Four 63-byte labels produce total = 4 × (63 + 1) = 256 > 255 → cap raises.
    # The root terminator is appended but never reached; the cap fires on the
    # fourth label.
    var m = List[UInt8]()
    for _i in range(4):
        m.append(UInt8(63))
        for _j in range(63):
            m.append(UInt8(65))   # 'A'
    m.append(UInt8(0))   # root terminator (unreachable; cap fires first)
    with assert_raises():
        _ = _decode_name(m, 0)


def test_name_label_over_read_rejected() raises:
    # Label length byte claims 5 octets of content but the buffer holds only 2
    # bytes after the length byte; label_end (= 0 + 1 + 5 = 6) exceeds len(m)
    # (= 3) → raises before any out-of-range read.
    var m = List[UInt8]()
    m.append(UInt8(5))    # label length 5
    m.append(UInt8(65))   # 'A' — only two content bytes present
    m.append(UInt8(66))   # 'B'
    with assert_raises():
        _ = _decode_name(m, 0)


def test_name_reserved_label_flags_rejected() raises:
    # High bits 0b10 (0x80) are reserved by RFC 1035; the decoder must raise
    # "bad label flags" rather than mis-parsing the byte as a label length.
    var m80 = List[UInt8]()
    m80.append(UInt8(0x80))
    m80.append(UInt8(0x00))
    with assert_raises():
        _ = _decode_name(m80, 0)
    # High bits 0b01 (0x40) are equally reserved and must be rejected.
    var m40 = List[UInt8]()
    m40.append(UInt8(0x40))
    m40.append(UInt8(0x00))
    with assert_raises():
        _ = _decode_name(m40, 0)


def test_name_edge_pointer_out_of_bounds_rejected() raises:
    # Pointer at offset 0 targeting offset 2 == len(m) — exactly one past the
    # last valid index.  ptr (2) >= pos (0) → rejected as non-decreasing before
    # any attempt to read at the out-of-range target.
    var m = List[UInt8]()
    m.append(UInt8(0xC0))   # pointer high byte
    m.append(UInt8(0x02))   # pointer low byte → offset 2 == len(m)
    with assert_raises():
        _ = _decode_name(m, 0)


def main() raises:
    test_resolv_conf_first_ipv4_nameserver()
    test_resolv_conf_skips_ipv6_nameserver()
    test_resolv_conf_no_nameserver_returns_empty()
    test_resolv_conf_crlf_lines_parsed_correctly()
    test_first_nameserver_missing_path_returns_default()
    test_query_golden_bytes()
    test_name_decompression_resolves_pointer()
    test_name_pointer_cycle_rejected()
    test_name_forward_pointer_rejected()
    test_name_label_pointer_ratchet_terminated_by_cap()
    test_name_exceeds_255_octet_cap()
    test_name_label_over_read_rejected()
    test_name_reserved_label_flags_rejected()
    test_name_edge_pointer_out_of_bounds_rejected()
    print("All test_svcb tests passed.")
