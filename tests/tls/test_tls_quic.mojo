# tests/test_tls_quic.mojo — FFI null-safety tests for QUIC handshake signatures.

from navette.tls import TlsBackend
from tests._test_util import assert_equal_int
from std.memory import Pointer


def test_quic_conn_read_hs_null_out_params_do_not_crash() raises:
    """Call quic_conn_read_hs with NULL for both out-params (3-arg defaults).

    Must not crash or segfault. Invalid handle returns -1 without panic — the
    Rust side's NULL-safe out-param writes are exercised here via Mojo's
    default-NULL pointer arguments on the wrapper.
    """
    var tls = TlsBackend()
    var shared = tls.shared()
    var rlib = shared.inner_ptr()
    var rc = rlib[].quic_conn_read_hs(
        Int32(-1),
        Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=Int(0)),
        Int32(0),
    )
    # Anchor: `inner_ptr()` hands back an untracked pointer, so the origin
    # checker cannot see that the call above depends on `shared`. Without a
    # later reference, ASAP destruction drops the last refcount at the `rlib`
    # binding -- closing the dylib -- and the FFI call runs through a null
    # handle. Same idiom as `QuicKeyStore.__deinit__` in packet_protect.mojo.
    _ = shared.inner_ptr()
    assert_equal_int(
        Int(rc), -1, "invalid handle returns -1, not a crash"
    )
    print("PASS: test_quic_conn_read_hs_null_out_params_do_not_crash")


def test_quic_conn_read_hs_q6_profiled_form_null_safe() raises:
    """5-arg call form with both timing out-pointers wired.

    Slots 1+2 are the state-machine and handle-lookup timings. Invalid
    handle returns -1 without writing to the out-pointers; this exercises
    the Rust-side early-return-before-out-param-write path.
    """
    var tls = TlsBackend()
    var shared = tls.shared()
    var rlib = shared.inner_ptr()
    var out_sm_us: UInt64 = UInt64(0)
    var out_lookup_us: UInt64 = UInt64(0)
    var rc = rlib[].quic_conn_read_hs(
        Int32(-1),
        Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=Int(0)),
        Int32(0),
        Pointer(to=out_sm_us),
        Pointer(to=out_lookup_us),
    )
    # Anchor `shared` past the FFI call -- see the note in the test above.
    _ = shared.inner_ptr()
    assert_equal_int(
        Int(rc), -1, "invalid handle returns -1 (timing out-param form)"
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
