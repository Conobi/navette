# tests/h1/test_connection_compaction.mojo
#
# params-compaction (§7) + compaction-overlap/-full/-none (§5):
# _compact_forward left-shifts buf[cursor:len] to [0:keep] via an indexed
# forward copy (overlap-safe), reusing the backing allocation. >=1000 random
# iterations + pinned boundaries; asserts buf == original data[cursor:len].

from std.memory import Span
from std.random import random_ui64, seed
from navette.h1.connection import _compact_forward
from navette.http import StatusCode, Version, Headers, Response
from navette.h1.connection import H1Connection
from navette.h1 import ParseConfig
from tests._test_util import assert_true, assert_equal_int


def _check_compaction(len_in: Int, cursor: Int) raises:
    # Build a recognizable buffer, capture the expected tail, compact, compare.
    var buf = List[UInt8](capacity=len_in if len_in > 0 else 1)
    for i in range(len_in):
        buf.append(UInt8((i * 31 + 7) & 0xFF))
    var keep = len_in - cursor
    var expected = List[UInt8]()
    for i in range(keep):
        expected.append(buf[cursor + i])
    _compact_forward(buf, cursor)
    assert_equal_int(len(buf), keep, "compaction keep length")
    for i in range(keep):
        if buf[i] != expected[i]:
            raise "compaction byte mismatch at " + String(i) + " (len=" + String(len_in) + " cursor=" + String(cursor) + ")"


def test_compaction_boundaries() raises:
    # compaction-none, -overlap (cursor==1), near-end, -full.
    for L in [0, 1, 2, 10, 1000, 10000]:
        for c in [0, 1, L - 1 if L > 0 else 0, L]:
            if c < 0 or c > L:
                continue
            _check_compaction(L, c)


def test_compaction_random() raises:
    seed(0x1234)
    for _ in range(1000):
        var L = Int(random_ui64(0, 10000))
        var c = Int(random_ui64(0, UInt64(L)))
        _check_compaction(L, c)


def test_drain_into() raises:
    # drain_into appends the outbound buffer into the sink and clears it in
    # place (capacity preserved); a second response reuses the same backing.
    var conn = H1Connection(ParseConfig())
    var r1 = Response(status=StatusCode(200), reason="",
                      version=Version.http_1_1(), headers=Headers())
    conn.send_response(r1^)
    var sink = List[UInt8]()
    conn.drain_into(sink)
    assert_true(len(sink) > 0, "drain_into filled the sink")
    assert_true(not conn.wants_write(), "outbound empty after drain_into")
    # Second response appends after the first drained content.
    var prefix_len = len(sink)
    var r2 = Response(status=StatusCode(404), reason="",
                      version=Version.http_1_1(), headers=Headers())
    conn.send_response(r2^)
    conn.drain_into(sink)
    assert_true(len(sink) > prefix_len, "drain_into appended the second response")


def main() raises:
    test_compaction_boundaries()
    test_compaction_random()
    test_drain_into()
    print("test_connection_compaction: all tests passed")
