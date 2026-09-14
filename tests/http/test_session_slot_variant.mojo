"""SessionSlot Variant construction, move, and predicate tests."""

from navette.http.session_slot import SessionSlot
from navette.h1.h1_session import H1Session
from navette.h2.h2_session import H2Session
from navette.h3.h3_session import H3Session
from tests._test_util import assert_true, assert_false


def test_session_slot_variant_construction() raises:
    """Verify each factory produces the correct Variant discriminant."""
    var s1 = SessionSlot.from_h1(H1Session())
    assert_true(s1.session.isa[H1Session](), "from_h1 -> H1")
    assert_false(s1.session.isa[H2Session](), "from_h1 != H2")
    assert_false(s1.session.isa[H3Session](), "from_h1 != H3")
    print("  test_session_slot_variant_construction: PASS")


def test_session_slot_variant_move() raises:
    """Verify moved slot retains the correct variant discriminant."""
    var s1 = SessionSlot.from_h1(H1Session())
    var s2 = s1^
    assert_true(s2.session.isa[H1Session](), "moved slot is H1")
    print("  test_session_slot_variant_move: PASS")


def test_session_slot_is_multiplexed() raises:
    """H1 is not multiplexed; H2/H3 would be (tested via the predicate contract)."""
    var h1 = SessionSlot.from_h1(H1Session())
    assert_false(h1.is_multiplexed(), "H1 is not multiplexed")
    print("  test_session_slot_is_multiplexed: PASS")


def main() raises:
    test_session_slot_variant_construction()
    test_session_slot_variant_move()
    test_session_slot_is_multiplexed()
    print("test_session_slot_variant: 3/3 passed")
