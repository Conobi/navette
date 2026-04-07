# tests/test_priority.mojo
#
# Unit tests for Priority (RFC 9218, M2.5b §7.1).
from src.http.priority import Priority
from tests._test_util import assert_true, assert_false, assert_equal_int, assert_equal_str


def test_default_priority() raises:
    var p = Priority.default()
    assert_equal_int(p.urgency, 3, "default.urgency")
    assert_false(p.incremental, "default.incremental")


def main() raises:
    test_default_priority()
    print("test_priority: all tests passed")
