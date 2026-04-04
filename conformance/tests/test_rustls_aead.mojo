# conformance/tests/test_rustls_aead.mojo
#
# AEAD encrypt/decrypt roundtrip via librustls_mojo.so.
# Tests: correctness, handle-after-free rejection, nonce reuse, rough throughput.
from lib.test_util import assert_true, assert_equal
from lib.rustls import RustlsLibrary
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.time import perf_counter_ns


def _alloc_dcid() -> UnsafePointer[UInt8, MutAnyOrigin]:
    """Allocate and fill the RFC 9001 A.1 DCID (8394c8f03e515708)."""
    var dcid = _heap_alloc[UInt8](8).as_any_origin()
    dcid[0] = 0x83
    dcid[1] = 0x94
    dcid[2] = 0xC8
    dcid[3] = 0xF0
    dcid[4] = 0x3E
    dcid[5] = 0x51
    dcid[6] = 0x57
    dcid[7] = 0x08
    return dcid


def _alloc_header() -> UnsafePointer[UInt8, MutAnyOrigin]:
    """Allocate a dummy 4-byte QUIC Long Header."""
    var header = _heap_alloc[UInt8](4).as_any_origin()
    header[0] = 0xC0
    header[1] = 0x00
    header[2] = 0x00
    header[3] = 0x01
    return header


def test_encrypt_decrypt_roundtrip(lib: RustlsLibrary) raises:
    """Client encrypts, server decrypts, plaintext matches."""
    var dcid = _alloc_dcid()

    var client_h = lib.initial_keys(Int32(1), dcid, Int32(8), Int32(1))
    assert_true(Int(client_h) > 0, "client handle should be positive, got " + String(Int(client_h)))

    var server_h = lib.initial_keys(Int32(1), dcid, Int32(8), Int32(0))
    assert_true(Int(server_h) > 0, "server handle should be positive, got " + String(Int(server_h)))

    var tag_len = lib.keys_tag_len(client_h)
    assert_equal(Int(tag_len), 16, "AES-128-GCM tag length")

    # Prepare plaintext "Hello QUIC!" (11 bytes)
    var pt_len = 11
    var pt = _heap_alloc[UInt8](pt_len).as_any_origin()
    pt[0] = 0x48  # H
    pt[1] = 0x65  # e
    pt[2] = 0x6C  # l
    pt[3] = 0x6C  # l
    pt[4] = 0x6F  # o
    pt[5] = 0x20  # (space)
    pt[6] = 0x51  # Q
    pt[7] = 0x55  # U
    pt[8] = 0x49  # I
    pt[9] = 0x43  # C
    pt[10] = 0x21  # !
    var header = _alloc_header()

    # Allocate buffer: plaintext + tag
    var buf_cap = pt_len + Int(tag_len)
    var buf = _heap_alloc[UInt8](buf_cap).as_any_origin()
    for i in range(pt_len):
        buf[i] = pt[i]

    # Encrypt with client's local keys (packet_number = 0)
    var ct_len = lib.keys_local_encrypt(
        client_h, UInt64(0),
        header, Int32(4),
        buf, Int32(pt_len), Int32(buf_cap),
    )
    assert_true(Int(ct_len) > 0, "encrypt failed: " + lib.last_error())
    assert_equal(Int(ct_len), buf_cap, "ciphertext length = plaintext + tag")

    # Verify ciphertext differs from plaintext
    var differs = False
    for i in range(pt_len):
        if buf[i] != pt[i]:
            differs = True
            break
    assert_true(differs, "ciphertext should differ from plaintext")

    # Decrypt with server's remote keys (packet_number = 0)
    var dec_len = lib.keys_remote_decrypt(
        server_h, UInt64(0),
        header, Int32(4),
        buf, ct_len,
    )
    assert_true(Int(dec_len) > 0, "decrypt failed: " + lib.last_error())
    assert_equal(Int(dec_len), pt_len, "decrypted plaintext length")

    # Verify plaintext matches original
    for i in range(pt_len):
        assert_true(buf[i] == pt[i], "plaintext mismatch at byte " + String(i))

    # Cleanup
    dcid.free()
    header.free()
    buf.free()
    pt.free()
    _ = lib.keys_free(client_h)
    _ = lib.keys_free(server_h)

    print("  roundtrip: OK")


def test_use_after_free(lib: RustlsLibrary) raises:
    """Freed handles must be rejected."""
    var dcid = _alloc_dcid()
    var h = lib.initial_keys(Int32(1), dcid, Int32(8), Int32(1))
    assert_true(Int(h) > 0, "handle should be positive")

    # Free it
    var rc = lib.keys_free(h)
    assert_equal(Int(rc), 0, "first free should succeed")

    # Use after free — must return -1
    var tag = lib.keys_tag_len(h)
    assert_true(Int(tag) < 0, "tag_len on freed handle should return -1")

    var rc2 = lib.keys_free(h)
    assert_true(Int(rc2) < 0, "double-free should return -1")

    dcid.free()
    print("  use-after-free rejected: OK")


def test_nonce_reuse_rejected(lib: RustlsLibrary) raises:
    """Encrypting twice with same packet_number must fail."""
    var dcid = _alloc_dcid()
    var h = lib.initial_keys(Int32(1), dcid, Int32(8), Int32(1))
    assert_true(Int(h) > 0, "handle should be positive")

    var tag_len = Int(lib.keys_tag_len(h))
    var header = _alloc_header()

    var pt_len = 4  # "ABCD"
    var buf_cap = pt_len + tag_len

    # First encrypt at pn=0 — should succeed
    var buf1 = _heap_alloc[UInt8](buf_cap).as_any_origin()
    buf1[0] = 0x41  # A
    buf1[1] = 0x42  # B
    buf1[2] = 0x43  # C
    buf1[3] = 0x44  # D
    var ct1 = lib.keys_local_encrypt(
        h, UInt64(0), header, Int32(4), buf1, Int32(pt_len), Int32(buf_cap),
    )
    assert_true(Int(ct1) > 0, "first encrypt should succeed")

    # Second encrypt at pn=0 (reuse) — must fail
    var buf2 = _heap_alloc[UInt8](buf_cap).as_any_origin()
    buf2[0] = 0x41
    buf2[1] = 0x42
    buf2[2] = 0x43
    buf2[3] = 0x44
    var ct2 = lib.keys_local_encrypt(
        h, UInt64(0), header, Int32(4), buf2, Int32(pt_len), Int32(buf_cap),
    )
    assert_true(Int(ct2) < 0, "nonce reuse must be rejected")

    _ = lib.keys_free(h)
    dcid.free()
    header.free()
    buf1.free()
    buf2.free()
    print("  nonce reuse rejected: OK")


def test_throughput(lib: RustlsLibrary) raises:
    """Rough throughput: 10k encrypt+decrypt cycles."""
    var dcid = _alloc_dcid()
    var client_h = lib.initial_keys(Int32(1), dcid, Int32(8), Int32(1))
    var server_h = lib.initial_keys(Int32(1), dcid, Int32(8), Int32(0))
    var tag_len = Int(lib.keys_tag_len(client_h))

    # 1200-byte payload (typical QUIC packet)
    var pt_len = 1200
    var buf_cap = pt_len + tag_len
    var buf = _heap_alloc[UInt8](buf_cap).as_any_origin()
    var header = _alloc_header()

    # Fill payload with a pattern
    for i in range(pt_len):
        buf[i] = UInt8(i % 256)

    var iterations = 10000
    var t0 = perf_counter_ns()

    for i in range(iterations):
        # Reset payload each iteration
        for j in range(pt_len):
            buf[j] = UInt8(j % 256)

        var ct_len = lib.keys_local_encrypt(
            client_h, UInt64(i),
            header, Int32(4),
            buf, Int32(pt_len), Int32(buf_cap),
        )
        assert_true(Int(ct_len) > 0, "encrypt failed at iteration " + String(i))

        var dec_len = lib.keys_remote_decrypt(
            server_h, UInt64(i),
            header, Int32(4),
            buf, ct_len,
        )
        assert_true(Int(dec_len) > 0, "decrypt failed at iteration " + String(i))

    var t1 = perf_counter_ns()
    var elapsed_ns = Int(t1 - t0)
    var elapsed_ms = elapsed_ns / 1_000_000
    var ns_per_op = elapsed_ns / iterations

    print(
        "  throughput: "
        + String(iterations)
        + " encrypt+decrypt cycles of "
        + String(pt_len)
        + "B in "
        + String(elapsed_ms)
        + "ms ("
        + String(ns_per_op)
        + " ns/op)"
    )

    _ = lib.keys_free(client_h)
    _ = lib.keys_free(server_h)
    dcid.free()
    header.free()
    buf.free()


def main() raises:
    # Verify assertions are working
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing — test infrastructure is broken")

    var lib = RustlsLibrary()

    print("test_rustls_aead:")
    test_encrypt_decrypt_roundtrip(lib)
    test_use_after_free(lib)
    test_nonce_reuse_rejected(lib)
    test_throughput(lib)
    print("test_rustls_aead: all passed")

    _ = lib^
