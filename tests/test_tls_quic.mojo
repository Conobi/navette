# tests/test_tls_quic.mojo — FFI null-safety tests for QUIC handshake signatures.
#
# Q7 creates this file with +1 test. Q6 will ADD +2 tests later (do not
# duplicate file creation).
#
# Plan: 2026-05-04-q7-cold-handshake-cpu-utilization-decomposition §3 T3c.

from src.tls import RustlsLibrary
from tests._test_util import assert_equal_int
from std.memory import UnsafePointer


def test_quic_conn_read_hs_null_q7_out_params_do_not_crash() raises:
    """Call quic_conn_read_hs with NULL for all 4 out-params (legacy 3-arg defaults).

    Must not crash or segfault. Invalid handle returns -1 without panic — the
    Rust side's NULL-safe out-param writes are exercised here via Mojo's
    default-NULL pointer arguments on the wrapper.
    """
    var lib = RustlsLibrary()
    var rc = lib.quic_conn_read_hs(
        Int32(-1),
        UnsafePointer[UInt8, MutAnyOrigin](),
        Int32(0),
    )
    # Return code -1 = invalid handle (expected); not a panic.
    assert_equal_int(
        Int(rc), -1, "invalid handle returns -1, not a crash"
    )
    print("PASS: test_quic_conn_read_hs_null_q7_out_params_do_not_crash")


def main() raises:
    test_quic_conn_read_hs_null_q7_out_params_do_not_crash()
