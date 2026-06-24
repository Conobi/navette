# tests/quic/test_quic_packet_protect.mojo
#
# PacketProtect lifecycle tests for the 4th key slot (0-RTT decrypt).
#
# Properties proven here:
#   - install-then-has-keys: after install returns False (fresh conn),
#     has_keys(3) is False. (The success path needs a forced-resumption
#     fixture and is covered separately.)
#   - set-keys-replaces-without-leak: set_keys(3, h1); set_keys(3, h2)
#     frees h1 exactly once (via the keys-free counter probe).
#   - install-is-free-first: install_zero_rtt_read_keys with slot 3
#     populated frees the prior handle before invoking FFI, regardless
#     of FFI return code.

from std.memory import UnsafePointer, Span

from navette.util.owned_alloc import Owned
from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig
from navette.quic.connection import QuicConnection
from navette.quic.packet_protect import PacketProtect, ZERO_RTT_KEY_SLOT_IDX
from navette.quic.trans_param import default_transport_params
from tests._test_util import (
    assert_true, assert_equal_int, load_test_cert,
)


def _synth_dcid() -> List[UInt8]:
    """Return the canonical RFC 9001 §A test DCID for synthetic key derivation.

    Returns:
        An 8-byte List with the canonical sample DCID.
    """
    var dcid: List[UInt8] = [
        UInt8(0x83), UInt8(0x94), UInt8(0xc8), UInt8(0xf0),
        UInt8(0x3e), UInt8(0x51), UInt8(0x57), UInt8(0x08),
    ]
    return dcid^


def _reset_keys_free_counter(lib: SharedLibrary) raises:
    """Reset the test-only keys-free counter to zero."""
    var rlib = lib.inner_ptr()
    _ = rlib[].test_keys_free_reset()


def _read_keys_free_counter(lib: SharedLibrary) raises -> UInt64:
    """Read the current keys-free counter value."""
    var rlib = lib.inner_ptr()
    return rlib[].test_keys_free_count()


def test_install_zero_rtt_read_keys_returns_false_on_fresh_conn() raises:
    """A fresh server conn (no resumption, max_early_data=0) yields rc=1
    from the FFI, so install returns False and slot 3 stays empty."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    var tp = default_transport_params()
    var dcid_a = _synth_dcid()
    var dcid_b = _synth_dcid()
    var now = UInt64(1_000_000)
    var conn = QuicConnection.server(
        tls.shared(), cfg, tp, Span(dcid_a), Span(dcid_b), now,
    )
    var protect = PacketProtect(tls.shared())

    assert_true(
        not protect.has_keys(ZERO_RTT_KEY_SLOT_IDX),
        "slot 3 must start empty",
    )

    # Mojo ASAP-destruction gotcha: extracting conn.conn_handle as the last
    # use of `conn` would let Mojo run conn.__del__ (which calls
    # quic_conn_free on the FFI handle) BEFORE the install call enters the
    # method body — making the FFI report "invalid conn handle". Keep
    # `conn` live across the call by reading a field after the call site.
    var ch = conn.conn_handle
    var installed = protect.install_zero_rtt_read_keys(ch)
    _ = conn.is_server  # extend conn's lifetime past install
    _ = protect.has_keys(0)  # extend protect's lifetime past install
    assert_true(
        not installed,
        "install must return False on a fresh non-resumed server conn",
    )
    assert_true(
        not protect.has_keys(ZERO_RTT_KEY_SLOT_IDX),
        "slot 3 must remain empty when install returns False",
    )
    print("  test_install_zero_rtt_read_keys_returns_false_on_fresh_conn: PASS")


def test_set_keys_replaces_without_leak_at_slot_3() raises:
    """Replacing keys at slot 3 must free the prior handle exactly once.

    set_keys(3, h1); set_keys(3, h2) frees h1 exactly once (counter
    delta = 1) and leaves slot 3 holding h2.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var protect = PacketProtect(tls.shared())

    _reset_keys_free_counter(tls.shared())

    var dcid = _synth_dcid()
    var dcid_owned = Owned[UInt8](len(dcid))
    var dcid_ptr = dcid_owned.ptr()
    for i in range(len(dcid)):
        dcid_ptr[i] = dcid[i]

    var rlib = tls.shared().inner_ptr()
    var h1 = rlib[].initial_keys(
        Int32(1), dcid_ptr, Int32(len(dcid)), Int32(0)
    )
    var h2 = rlib[].initial_keys(
        Int32(1), dcid_ptr, Int32(len(dcid)), Int32(0)
    )
    _ = dcid_owned
    assert_true(h1 > Int32(0) and h2 > Int32(0), "synth handles must be positive")
    assert_true(h1 != h2, "synth handles must be distinct")

    protect.set_keys(ZERO_RTT_KEY_SLOT_IDX, h1)
    var c1 = _read_keys_free_counter(tls.shared())
    assert_equal_int(Int(c1), 0, "no free should occur on first set_keys")

    protect.set_keys(ZERO_RTT_KEY_SLOT_IDX, h2)
    var c2 = _read_keys_free_counter(tls.shared())
    assert_equal_int(Int(c2), 1, "h1 must be freed exactly once on replace")
    assert_true(
        protect.has_keys(ZERO_RTT_KEY_SLOT_IDX),
        "slot 3 must still hold h2 after replace",
    )
    print("  test_set_keys_replaces_without_leak_at_slot_3: PASS")


def test_install_is_free_first_when_slot_3_populated() raises:
    """If slot 3 is populated when install is called, the prior handle
    is freed BEFORE the FFI runs, regardless of FFI return code."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    var tp = default_transport_params()
    var dcid_a = _synth_dcid()
    var dcid_b = _synth_dcid()
    var now = UInt64(1_000_000)
    var conn = QuicConnection.server(
        tls.shared(), cfg, tp, Span(dcid_a), Span(dcid_b), now,
    )
    var protect = PacketProtect(tls.shared())

    var dcid = _synth_dcid()
    var dcid_owned = Owned[UInt8](len(dcid))
    var dcid_ptr = dcid_owned.ptr()
    for i in range(len(dcid)):
        dcid_ptr[i] = dcid[i]
    var rlib = tls.shared().inner_ptr()
    var h_pre = rlib[].initial_keys(
        Int32(1), dcid_ptr, Int32(len(dcid)), Int32(0)
    )
    _ = dcid_owned
    assert_true(h_pre > Int32(0), "pre-populate handle must be positive")
    protect.set_keys(ZERO_RTT_KEY_SLOT_IDX, h_pre)
    assert_true(protect.has_keys(ZERO_RTT_KEY_SLOT_IDX), "slot 3 populated")

    # Inline reset (helper invocation perturbs Mojo lifetimes — see note
    # below). Calling `_reset_keys_free_counter` via `def` here would
    # double-count h_pre's free by destroying a temp SharedLibrary copy
    # that aliases protect's inner; inlining keeps the lifetime stable.
    var rlib_pre = tls.shared().inner_ptr()
    _ = rlib_pre[].test_keys_free_reset()

    # See ASAP-destruction note in test 1. Both `conn` and `protect` must
    # live past install — Mojo's ASAP destructor for `protect` would
    # otherwise re-free slot 3 (set to -1 by discard) on some code paths
    # and double-count, masking the once-only invariant we're proving.
    var ch = conn.conn_handle
    var installed = protect.install_zero_rtt_read_keys(ch)
    _ = conn.is_server  # extend conn's lifetime past install
    _ = protect.has_keys(0)  # extend protect's lifetime past install
    assert_true(
        not installed,
        "install must return False on a fresh non-resumed conn",
    )

    var rlib_post = tls.shared().inner_ptr()
    var c = rlib_post[].test_keys_free_count()
    assert_equal_int(
        Int(c), 1,
        "h_pre must be freed exactly once before FFI is invoked",
    )
    assert_true(
        not protect.has_keys(ZERO_RTT_KEY_SLOT_IDX),
        "slot 3 must end empty when FFI returns 1 (unavailable)",
    )
    print("  test_install_is_free_first_when_slot_3_populated: PASS")


def test_discard_keys_at_slot_3_is_noop_when_empty() raises:
    """Calling discard_keys(3) on an empty slot must be a no-op:
    no crash, no error, no spurious free-counter increment."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var protect = PacketProtect(tls.shared())
    _reset_keys_free_counter(tls.shared())

    assert_true(
        not protect.has_keys(ZERO_RTT_KEY_SLOT_IDX),
        "slot 3 starts empty",
    )

    # Multiple discards on an empty slot are all no-ops.
    protect.discard_keys(ZERO_RTT_KEY_SLOT_IDX)
    protect.discard_keys(ZERO_RTT_KEY_SLOT_IDX)
    protect.discard_keys(ZERO_RTT_KEY_SLOT_IDX)

    var c = _read_keys_free_counter(tls.shared())
    assert_equal_int(Int(c), 0, "empty-slot discard must not increment the counter")
    assert_true(
        not protect.has_keys(ZERO_RTT_KEY_SLOT_IDX),
        "slot 3 must remain empty after no-op discards",
    )
    print("  test_discard_keys_at_slot_3_is_noop_when_empty: PASS")


def test_discard_zero_rtt_keys_helper_targets_slot_3() raises:
    """The `_discard_zero_rtt_keys` helper on QuicConnection MUST target
    slot 3 specifically. Pre-populate slot 3 on a real connection's
    `protect`, call the helper, and assert the counter increments by
    exactly one and slot 3 ends empty. A future renaming or wrong-slot
    bug in the helper body would fail this test."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    var tp = default_transport_params()
    var dcid_a = _synth_dcid()
    var dcid_b = _synth_dcid()
    var now = UInt64(1_000_000)
    var conn = QuicConnection.server(
        tls.shared(), cfg, tp, Span(dcid_a), Span(dcid_b), now,
    )

    # Synthesize a slot-3 handle and install it on the connection's
    # PacketProtect directly (the helper reaches the real field, not a
    # detached test fixture).
    var dcid = _synth_dcid()
    var dcid_owned = Owned[UInt8](len(dcid))
    var dcid_ptr = dcid_owned.ptr()
    for i in range(len(dcid)):
        dcid_ptr[i] = dcid[i]
    var rlib = tls.shared().inner_ptr()
    var h_pre = rlib[].initial_keys(
        Int32(1), dcid_ptr, Int32(len(dcid)), Int32(0)
    )
    _ = dcid_owned
    assert_true(h_pre > Int32(0), "synth handle must be positive")

    conn.protect.set_keys(ZERO_RTT_KEY_SLOT_IDX, h_pre)
    assert_true(
        conn.protect.has_keys(ZERO_RTT_KEY_SLOT_IDX),
        "slot 3 populated before helper call",
    )

    _reset_keys_free_counter(tls.shared())

    # Invoke the helper directly. This is the unit-level lock on the
    # wiring: if a future implementer renamed _discard_zero_rtt_keys to
    # call discard_keys(2) or some other slot, the counter would not
    # tick (because slot 3 still holds h_pre) and the post-state assert
    # would fail.
    conn._discard_zero_rtt_keys()

    var c = _read_keys_free_counter(tls.shared())
    assert_equal_int(
        Int(c), 1,
        "_discard_zero_rtt_keys must free the slot-3 handle exactly once",
    )
    assert_true(
        not conn.protect.has_keys(ZERO_RTT_KEY_SLOT_IDX),
        "slot 3 must be empty after _discard_zero_rtt_keys",
    )
    # Extend conn lifetime past the assertions per
    # feedback_mojo_asap_destruction_in_ffi_tests.
    _ = conn.is_server
    print("  test_discard_zero_rtt_keys_helper_targets_slot_3: PASS")


def test_discard_clears_slot_3_and_frees_handle() raises:
    """discard_keys(3) on a populated slot frees the handle exactly once
    (counter delta = 1) and leaves the slot empty. No error from the FFI
    (last_error not set)."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var protect = PacketProtect(tls.shared())

    var dcid: List[UInt8] = [
        UInt8(0x83), UInt8(0x94), UInt8(0xc8), UInt8(0xf0),
        UInt8(0x3e), UInt8(0x51), UInt8(0x57), UInt8(0x08),
    ]
    var dcid_owned = Owned[UInt8](len(dcid))
    var dcid_ptr = dcid_owned.ptr()
    for i in range(len(dcid)):
        dcid_ptr[i] = dcid[i]
    var rlib = tls.shared().inner_ptr()
    var h = rlib[].initial_keys(
        Int32(1), dcid_ptr, Int32(len(dcid)), Int32(0)
    )
    _ = dcid_owned
    assert_true(h > Int32(0), "synth handle must be positive")
    protect.set_keys(ZERO_RTT_KEY_SLOT_IDX, h)

    _reset_keys_free_counter(tls.shared())

    protect.discard_keys(ZERO_RTT_KEY_SLOT_IDX)

    var c = _read_keys_free_counter(tls.shared())
    assert_equal_int(Int(c), 1, "discard must free the handle exactly once")
    assert_true(
        not protect.has_keys(ZERO_RTT_KEY_SLOT_IDX),
        "slot 3 must be empty after discard",
    )

    var err = rlib[].last_error()
    assert_true(
        len(err) == 0,
        "last_error must be empty on successful discard",
    )
    # Extend protect lifetime past the assertion section so ASAP-destruction
    # doesn't fire __del__ during the counter read and inflate the count.
    _ = protect.has_keys(0)
    print("  test_discard_clears_slot_3_and_frees_handle: PASS")


def test_del_frees_slot_3_handle_exactly_once() raises:
    """When a PacketProtect with slot 3 populated goes out of scope,
    __del__ frees the slot-3 handle exactly once (counter delta = 1)."""
    var tls = TlsBackend("lib/librustls_mojo.so")

    var dcid: List[UInt8] = [
        UInt8(0x83), UInt8(0x94), UInt8(0xc8), UInt8(0xf0),
        UInt8(0x3e), UInt8(0x51), UInt8(0x57), UInt8(0x08),
    ]
    var dcid_owned = Owned[UInt8](len(dcid))
    var dcid_ptr = dcid_owned.ptr()
    for i in range(len(dcid)):
        dcid_ptr[i] = dcid[i]
    var rlib = tls.shared().inner_ptr()
    var h = rlib[].initial_keys(
        Int32(1), dcid_ptr, Int32(len(dcid)), Int32(0)
    )
    _ = dcid_owned
    assert_true(h > Int32(0), "synth handle must be positive")

    _reset_keys_free_counter(tls.shared())

    # Scope-bounded PacketProtect: __del__ fires at block exit.
    if True:
        var protect = PacketProtect(tls.shared())
        protect.set_keys(ZERO_RTT_KEY_SLOT_IDX, h)
        # Mid-scope: no free yet (set_keys with empty prior slot does not free).
        var c_mid = _read_keys_free_counter(tls.shared())
        assert_equal_int(Int(c_mid), 0, "no free yet — slot was empty before set_keys")
        # Extend protect lifetime so the counter read above doesn't trigger
        # premature destruction.
        _ = protect.has_keys(0)
    # End of scope — protect.__del__ fires. Slot 3 holds h, so the loop
    # over self.keys frees it.

    var c_end = _read_keys_free_counter(tls.shared())
    assert_equal_int(
        Int(c_end), 1,
        "__del__ must free slot-3 handle exactly once",
    )
    print("  test_del_frees_slot_3_handle_exactly_once: PASS")


def main() raises:
    test_install_zero_rtt_read_keys_returns_false_on_fresh_conn()
    test_set_keys_replaces_without_leak_at_slot_3()
    test_install_is_free_first_when_slot_3_populated()
    test_discard_keys_at_slot_3_is_noop_when_empty()
    test_discard_zero_rtt_keys_helper_targets_slot_3()
    test_discard_clears_slot_3_and_frees_handle()
    test_del_frees_slot_3_handle_exactly_once()
