# conformance/oracle/http2/hpack_integer.mojo — re-exports from navette.h2.hpack_integer
from navette.h2.hpack_integer import decode_integer
from navette.quic.codec import hpack_encode_int_at


def encode_integer(value: Int, prefix_bits: Int) -> List[UInt8]:
    """List-returning view of navette's in-place HPACK prefix-integer encoder.

    The first byte carries only the low `prefix_bits` bits. 11 bytes cover
    any 64-bit value (1 prefix byte + 10 continuation bytes).
    """
    var wire = List[UInt8](length=11, fill=UInt8(0))
    var n = hpack_encode_int_at(wire, 0, value, prefix_bits)
    wire.resize(n, UInt8(0))
    return wire^
