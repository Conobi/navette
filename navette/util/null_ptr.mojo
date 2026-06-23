"""null_ptr[T, o]() — a genuine NULL (address 0) UnsafePointer.

b2 added a compile-time non-null assertion on the IntLiteral
`unsafe_from_address` overload, rejecting a literal 0. Routing the address
through a runtime Int preserves the C-NULL/placeholder semantics navette
needs (e.g. PtrBox.null, decoder-state sentinels) without changing pointer
type or origin. @always_inline keeps the value identical (address 0).
"""

from std.memory import UnsafePointer


@always_inline
def null_ptr[T: AnyType, o: Origin]() -> UnsafePointer[T, o]:
    var addr: Int = 0
    return UnsafePointer[T, o](unsafe_from_address=addr)
