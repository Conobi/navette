# probes/inplace_int_negative.mojo
#
# inplace-int-negative (§5): the debug-only ASSERT=all precondition on
# _append_decimal fires on a planted negative value. At default/release the
# assert is compiled out and the loop appends zero bytes (proven non-reachable
# by audit-int-nonneg; this probe documents the defense-in-depth behavior).

from navette.h1.serializer import _append_decimal

def main():
    var b = List[UInt8]()
    _append_decimal(b, -1)
    print("NO_ABORT len=", len(b))
