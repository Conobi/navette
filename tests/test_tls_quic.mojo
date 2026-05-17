# tests/test_tls_quic.mojo — FFI null-safety tests for QUIC handshake signatures.

from navette.tls import RustlsLibrary
from tests._test_util import assert_equal_int
from std.memory import UnsafePointer


def test_quic_conn_read_hs_null_out_params_do_not_crash() raises:
    """Call quic_conn_read_hs with NULL for both out-params (3-arg defaults).

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
    assert_equal_int(
        Int(rc), -1, "invalid handle returns -1, not a crash"
    )
    print("PASS: test_quic_conn_read_hs_null_out_params_do_not_crash")


def test_quic_conn_read_hs_q6_profiled_form_null_safe() raises:
    """Q6: 5-arg profile-aware call form with both Q6 out-pointers wired.

    Mirrors the bracket-site call shape in connection.mojo's _drive_handshake
    under PROFILE_ACCEPT=True + profile_ptr != 0. Slot 1+2 are Q6 (state-machine,
    handle-lookup). Invalid handle returns -1 without writing to the out-pointers;
    this exercises the Rust-side early-return-before-out-param-write path.
    """
    var lib = RustlsLibrary()
    var out_sm_us: UInt64 = UInt64(0)
    var out_lookup_us: UInt64 = UInt64(0)
    var rc = lib.quic_conn_read_hs(
        Int32(-1),
        UnsafePointer[UInt8, MutAnyOrigin](),
        Int32(0),
        UnsafePointer(to=out_sm_us),
        UnsafePointer(to=out_lookup_us),
    )
    assert_equal_int(
        Int(rc), -1, "invalid handle returns -1 (profile-aware form)"
    )
    assert_equal_int(
        Int(out_sm_us), 0, "state-machine out-param untouched on invalid handle"
    )
    assert_equal_int(
        Int(out_lookup_us), 0, "handle-lookup out-param untouched on invalid handle"
    )
    print("PASS: test_quic_conn_read_hs_q6_profiled_form_null_safe")


def main() raises:
    test_quic_conn_read_hs_null_out_params_do_not_crash()
    test_quic_conn_read_hs_q6_profiled_form_null_safe()
