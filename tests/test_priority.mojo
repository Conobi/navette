# tests/test_priority.mojo
#
# Unit tests for Priority (RFC 9218, M2.5b §7.1).
from src.http.priority import Priority
from tests._test_util import assert_true, assert_false, assert_equal_int, assert_equal_str


def test_default_priority() raises:
    var p = Priority.default()
    assert_equal_int(p.urgency, 3, "default.urgency")
    assert_false(p.incremental, "default.incremental")


def test_parse_urgency_only() raises:
    var p = Priority.parse_header(String("u=1"))
    assert_equal_int(p.urgency, 1, "u=1.urgency")
    assert_false(p.incremental, "u=1.incremental")


def test_parse_urgency_with_incremental_bare() raises:
    var p = Priority.parse_header(String("u=5, i"))
    assert_equal_int(p.urgency, 5, "u=5,i.urgency")
    assert_true(p.incremental, "u=5,i.incremental")


def test_parse_explicit_incremental_false() raises:
    var p = Priority.parse_header(String("u=3, i=?0"))
    assert_equal_int(p.urgency, 3, "i=?0.urgency")
    assert_false(p.incremental, "i=?0.incremental")


def test_parse_explicit_incremental_true() raises:
    var p = Priority.parse_header(String("u=2, i=?1"))
    assert_equal_int(p.urgency, 2, "i=?1.urgency")
    assert_true(p.incremental, "i=?1.incremental")


def test_parse_empty_header_yields_defaults() raises:
    var p = Priority.parse_header(String(""))
    assert_equal_int(p.urgency, 3, "empty.urgency")
    assert_false(p.incremental, "empty.incremental")


def test_parse_out_of_range_urgency_raises() raises:
    var raised = False
    try:
        var _p = Priority.parse_header(String("u=9"))
    except:
        raised = True
    assert_true(raised, "out_of_range_raises")


def main() raises:
    test_default_priority()
    test_parse_urgency_only()
    test_parse_urgency_with_incremental_bare()
    test_parse_explicit_incremental_false()
    test_parse_explicit_incremental_true()
    test_parse_empty_header_yields_defaults()
    test_parse_out_of_range_urgency_raises()
    print("test_priority: all tests passed")
