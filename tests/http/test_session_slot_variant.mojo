"""SessionSlot construction, move, and kind tests."""

from navette.http.session_slot import SessionSlot, SLOT_H1, SLOT_H2, SLOT_H3
from navette.h1.h1_session import H1Session
from navette.h2.h2_session import H2Session
from navette.h3.h3_session import H3Session
from tests._test_util import assert_true, assert_false


def test_session_slot_variant_construction() raises:
    """Verify each factory produces the correct kind tag."""
    var s1 = SessionSlot.from_h1(H1Session())
    assert_true(s1.kind == SLOT_H1, "from_h1 -> SLOT_H1")
    assert_true(Bool(s1.h1), "from_h1 has h1 value")
    assert_false(Bool(s1.h2), "from_h1 has no h2")
    assert_false(Bool(s1.h3), "from_h1 has no h3")
    print("  test_session_slot_variant_construction: PASS")


def test_session_slot_variant_move() raises:
    """Verify moved slot retains the correct kind tag."""
    var s1 = SessionSlot.from_h1(H1Session())
    var s2 = s1^
    assert_true(s2.kind == SLOT_H1, "moved slot is SLOT_H1")
    assert_true(Bool(s2.h1), "moved slot has h1")
    print("  test_session_slot_variant_move: PASS")


def main() raises:
    test_session_slot_variant_construction()
    test_session_slot_variant_move()
    print("test_session_slot_variant: 2/2 passed")
