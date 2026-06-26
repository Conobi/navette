# probes/compact_cursor_oob.mojo
#
# audit-cursor-bounds (§7): the debug-only ASSERT=all precondition on
# _compact_forward fires when cursor > len(buf) (a state the audit proves
# unreachable). Compiled out at default/release.

from navette.h1.connection import _compact_forward

def main():
    var b = List[UInt8]()
    b.append(UInt8(1))
    b.append(UInt8(2))
    _compact_forward(b, 5)  # cursor 5 > len 2
    print("NO_ABORT len=", len(b))
