# tests/test_proxy_token.mojo
#
# Unit tests for the reverse proxy token encoding scheme.
#
# Token layout (64 bits):
#   bits [63:8] = connection_id (56 bits)
#   bits [7:0]  = op_kind (8 bits)

from token import (
    encode_token,
    decode_conn_id,
    decode_op_kind,
    OP_ACCEPT,
    OP_CLIENT_RECV,
    OP_CLIENT_SEND,
    OP_BACKEND_CONNECT,
    OP_BACKEND_RECV,
    OP_BACKEND_SEND,
    LISTENER_CONN_ID,
)
from tests._test_util import assert_true, assert_equal_int


def test_op_kind_constants() raises:
    """The op kind constants have the values the plan specifies."""
    assert_equal_int(Int(OP_ACCEPT), 0, "OP_ACCEPT == 0")
    assert_equal_int(Int(OP_CLIENT_RECV), 1, "OP_CLIENT_RECV == 1")
    assert_equal_int(Int(OP_CLIENT_SEND), 2, "OP_CLIENT_SEND == 2")
    assert_equal_int(Int(OP_BACKEND_CONNECT), 3, "OP_BACKEND_CONNECT == 3")
    assert_equal_int(Int(OP_BACKEND_RECV), 4, "OP_BACKEND_RECV == 4")
    assert_equal_int(Int(OP_BACKEND_SEND), 5, "OP_BACKEND_SEND == 5")
    assert_equal_int(Int(LISTENER_CONN_ID), 0, "LISTENER_CONN_ID == 0")


def test_encode_basic() raises:
    """Encode_token packs conn_id into the high 56 bits and op_kind into the low 8."""
    var tok = encode_token(1, OP_CLIENT_RECV)
    assert_equal_int(Int(tok), (1 << 8) | 1, "encode(1, CLIENT_RECV)")

    var tok2 = encode_token(42, OP_BACKEND_SEND)
    assert_equal_int(Int(tok2), (42 << 8) | 5, "encode(42, BACKEND_SEND)")


def test_decode_basic() raises:
    """Decode_conn_id / decode_op_kind recover the original fields."""
    var tok = encode_token(12345, OP_BACKEND_CONNECT)
    assert_equal_int(Int(decode_conn_id(tok)), 12345, "conn_id roundtrip")
    assert_equal_int(Int(decode_op_kind(tok)), 3, "op_kind roundtrip")


def test_listener_accept_token() raises:
    """The ACCEPT token uses conn_id = 0 (reserved for the listener)."""
    var tok = encode_token(LISTENER_CONN_ID, OP_ACCEPT)
    assert_equal_int(Int(tok), 0, "accept token == 0")
    assert_equal_int(Int(decode_conn_id(tok)), 0, "accept conn_id == 0")
    assert_equal_int(Int(decode_op_kind(tok)), 0, "accept op_kind == 0")


def test_roundtrip_all_ops() raises:
    """Every op kind round-trips through encode -> decode."""
    var ops = List[UInt8]()
    ops.append(OP_ACCEPT)
    ops.append(OP_CLIENT_RECV)
    ops.append(OP_CLIENT_SEND)
    ops.append(OP_BACKEND_CONNECT)
    ops.append(OP_BACKEND_RECV)
    ops.append(OP_BACKEND_SEND)

    var conn_id: UInt64 = 0xDEAD_BEEF
    for i in range(len(ops)):
        var op = ops[i]
        var tok = encode_token(conn_id, op)
        assert_equal_int(
            Int(decode_conn_id(tok)), Int(conn_id), "conn_id roundtrip"
        )
        assert_equal_int(
            Int(decode_op_kind(tok)), Int(op), "op_kind roundtrip"
        )


def test_max_conn_id() raises:
    """A 56-bit max connection id still round-trips cleanly."""
    var max_conn_id: UInt64 = (UInt64(1) << 56) - 1  # 2^56 - 1
    var tok = encode_token(max_conn_id, OP_CLIENT_SEND)
    assert_equal_int(
        Int(decode_conn_id(tok)), Int(max_conn_id), "max conn_id"
    )
    assert_equal_int(Int(decode_op_kind(tok)), 2, "op_kind with max conn_id")


def test_op_kind_independence() raises:
    """Different op kinds for the same conn_id produce distinct tokens."""
    var a = encode_token(7, OP_CLIENT_RECV)
    var b = encode_token(7, OP_CLIENT_SEND)
    assert_true(a != b, "same conn_id different ops differ")
    assert_equal_int(
        Int(decode_conn_id(a)), Int(decode_conn_id(b)), "same conn_id"
    )


def main() raises:
    test_op_kind_constants()
    test_encode_basic()
    test_decode_basic()
    test_listener_accept_token()
    test_roundtrip_all_ops()
    test_max_conn_id()
    test_op_kind_independence()
    print("test_proxy_token: all tests passed")
