from navette.util.null_ptr import null_ptr
from std.memory import UnsafePointer
from std.testing import assert_equal


struct Param[x: Int](Copyable, Movable):
    var v: Int
    def __init__(out self):
        self.v = Self.x


def test_null_ptr_addr_zero() raises:
    assert_equal(Int(null_ptr[NoneType, MutAnyOrigin]()), 0)
    assert_equal(Int(null_ptr[UInt8, MutAnyOrigin]()), 0)
    assert_equal(Int(null_ptr[UInt64, MutAnyOrigin]()), 0)
    assert_equal(Int(null_ptr[NoneType, MutUntrackedOrigin]()), 0)
    assert_equal(Int(null_ptr[Int, MutAnyOrigin]()), 0)        # PtrBox Self.T stand-in
    assert_equal(Int(null_ptr[Param[3], MutAnyOrigin]()), 0)   # comptime-parameterized element


def main() raises:
    test_null_ptr_addr_zero()
    print("test_null_ptr: passed")
