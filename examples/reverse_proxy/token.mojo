# examples/reverse_proxy/token.mojo
#
# Token encoding scheme used by ProxyHandler to map io_uring completion
# tokens back to (connection_id, op_kind) pairs.
#
# Token layout (64 bits):
#   bits [63:8]  = connection_id (56 bits — up to 72 quadrillion connections)
#   bits [7:0]   = op_kind        (8 bits — up to 256 operation types)
#
# Encoding: token   = (conn_id << 8) | op_kind
# Decoding: conn_id = token >> 8
#           op_kind = token & 0xFF
#
# The ACCEPT op uses conn_id = 0 (reserved for the listener).

# --- Op kinds ---------------------------------------------------------------

comptime OP_ACCEPT: UInt8 = 0          # listener accept completion
comptime OP_CLIENT_RECV: UInt8 = 1     # recv from the client socket
comptime OP_CLIENT_SEND: UInt8 = 2     # send to the client socket
comptime OP_BACKEND_CONNECT: UInt8 = 3 # connect() to backend
comptime OP_BACKEND_RECV: UInt8 = 4    # recv from the backend socket
comptime OP_BACKEND_SEND: UInt8 = 5    # send to the backend socket

# Reserved listener connection id (the ACCEPT token uses this).
comptime LISTENER_CONN_ID: UInt64 = 0


# --- Encode / decode --------------------------------------------------------


def encode_token(conn_id: UInt64, op_kind: UInt8) -> UInt64:
    """Pack (conn_id, op_kind) into a single 64-bit io_uring user_data token.

    The connection id occupies the high 56 bits and the op kind the low 8.
    """
    return (conn_id << 8) | UInt64(op_kind)


def decode_conn_id(token: UInt64) -> UInt64:
    """Extract the connection id (high 56 bits) from a token."""
    return token >> 8


def decode_op_kind(token: UInt64) -> UInt8:
    """Extract the op kind (low 8 bits) from a token."""
    return UInt8(token & 0xFF)
