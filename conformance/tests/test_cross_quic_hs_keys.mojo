# conformance/tests/test_cross_quic_hs_keys.mojo
#
# QC-1 Category 1: Wave 2 FFI key-pair consistency.
# Runs a Wave 2 FFI client<->server TLS 1.3 handshake using a Python-generated
# self-signed cert, materialises Handshake (kc=1) and 1-RTT (kc=2) key handles,
# and performs four AEAD encrypt/decrypt cross-checks to verify the key pairs are
# correct complements.
from lib.test_util import assert_true, assert_equal
from lib.rustls import RustlsLibrary
from python import Python, PythonObject
from std.memory.unsafe_pointer import alloc as _heap_alloc


struct HandshakeKeys:
    """Holds the four key handles produced by the Wave 2 FFI handshake."""
    var client_hs:   Int32
    var server_hs:   Int32
    var client_1rtt: Int32
    var server_1rtt: Int32

    def __init__(out self):
        self.client_hs   = Int32(-1)
        self.server_hs   = Int32(-1)
        self.client_1rtt = Int32(-1)
        self.server_1rtt = Int32(-1)


def py_bytes_to_mojo(raw: PythonObject) raises -> List[UInt8]:
    """Convert Python bytes to Mojo List[UInt8]."""
    var builtins = Python.import_module("builtins")
    var result = List[UInt8]()
    for i in range(Int(py=builtins.len(raw))):
        result.append(UInt8(Int(py=raw[i])))
    return result^


def aead_cross_check(
    rl: RustlsLibrary,
    encrypt_handle: Int32,
    decrypt_handle: Int32,
    label: String,
) raises -> None:
    """Encrypt with encrypt_handle.local, decrypt with decrypt_handle.remote.
    Asserts the round-trip succeeds and produces the original plaintext.
    """
    # Use raw bytes to avoid null-terminator issues with .as_bytes()
    var payload_len   = 14  # "key-pair-check"
    var tag_len       = 16
    var buf_capacity  = payload_len + tag_len + 4

    var enc_buf = _heap_alloc[UInt8](buf_capacity).as_any_origin()
    # Fill "key-pair-check" (14 bytes)
    enc_buf[0]  = UInt8(ord("k"))
    enc_buf[1]  = UInt8(ord("e"))
    enc_buf[2]  = UInt8(ord("y"))
    enc_buf[3]  = UInt8(ord("-"))
    enc_buf[4]  = UInt8(ord("p"))
    enc_buf[5]  = UInt8(ord("a"))
    enc_buf[6]  = UInt8(ord("i"))
    enc_buf[7]  = UInt8(ord("r"))
    enc_buf[8]  = UInt8(ord("-"))
    enc_buf[9]  = UInt8(ord("c"))
    enc_buf[10] = UInt8(ord("h"))
    enc_buf[11] = UInt8(ord("e"))
    enc_buf[12] = UInt8(ord("c"))
    enc_buf[13] = UInt8(ord("k"))

    # Stash original plaintext for comparison
    var orig = _heap_alloc[UInt8](payload_len).as_any_origin()
    for i in range(payload_len):
        orig[i] = enc_buf[i]

    # AAD = "qc1" (3 bytes)
    var aad_ptr = _heap_alloc[UInt8](3).as_any_origin()
    aad_ptr[0] = UInt8(ord("q"))
    aad_ptr[1] = UInt8(ord("c"))
    aad_ptr[2] = UInt8(ord("1"))
    var aad_len = Int32(3)

    # Encrypt: local write key of encrypt_handle
    var ct_len = rl.keys_local_encrypt(
        encrypt_handle, UInt64(0),
        aad_ptr, aad_len,
        enc_buf, Int32(payload_len), Int32(buf_capacity),
    )
    assert_true(ct_len > 0, label + ": local_encrypt failed (ct_len=" + String(Int(ct_len)) + ")")

    # Decrypt: remote read key of decrypt_handle
    var pt_len = rl.keys_remote_decrypt(
        decrypt_handle, UInt64(0),
        aad_ptr, aad_len,
        enc_buf, ct_len,
    )
    assert_equal(Int(pt_len), payload_len, label + ": remote_decrypt length mismatch")
    for i in range(payload_len):
        assert_true(enc_buf[i] == orig[i], label + ": plaintext byte mismatch at " + String(i))

    enc_buf.free()
    orig.free()
    aad_ptr.free()
    print("  OK " + label)


def run_handshake(
    rl: RustlsLibrary,
    client_h: Int32,
    server_h: Int32,
    out keys: HandshakeKeys,
) raises:
    """Drive Wave 2 FFI handshake to completion.
    Fills keys with the four acquired key handles (all > 0 on success).
    """
    keys = HandshakeKeys()

    # Use 65536 bytes for server buffer to accommodate TLS cert in ServerHello
    var buf_c = _heap_alloc[UInt8](65536).as_any_origin()
    var buf_s = _heap_alloc[UInt8](65536).as_any_origin()
    var written_ptr = _heap_alloc[Int32](1).as_any_origin()
    var kc_ptr      = _heap_alloc[UInt8](1).as_any_origin()
    var kh_ptr      = _heap_alloc[Int32](1).as_any_origin()

    for _ in range(20):  # max rounds
        var progress = False

        # Client writes
        written_ptr[0] = 0
        kc_ptr[0] = 0
        assert_equal(
            Int(rl.quic_conn_write_hs(client_h, buf_c, Int32(65536), written_ptr, kc_ptr)),
            0, "client write_hs failed"
        )
        var kc = Int(kc_ptr[0])
        if kc != 0:
            kh_ptr[0] = 0
            assert_equal(Int(rl.quic_conn_take_keys(client_h, kh_ptr)), 0, "client take_keys failed")
            if kc == 2:
                keys.client_1rtt = kh_ptr[0]
            else:
                keys.client_hs = kh_ptr[0]
        var written = Int(written_ptr[0])
        if written > 0:
            progress = True
            assert_equal(
                Int(rl.quic_conn_read_hs(server_h, buf_c, Int32(written))),
                0, "server read_hs failed"
            )

        # Server writes
        written_ptr[0] = 0
        kc_ptr[0] = 0
        assert_equal(
            Int(rl.quic_conn_write_hs(server_h, buf_s, Int32(65536), written_ptr, kc_ptr)),
            0, "server write_hs failed"
        )
        kc = Int(kc_ptr[0])
        if kc != 0:
            kh_ptr[0] = 0
            assert_equal(Int(rl.quic_conn_take_keys(server_h, kh_ptr)), 0, "server take_keys failed")
            if kc == 2:
                keys.server_1rtt = kh_ptr[0]
            else:
                keys.server_hs = kh_ptr[0]
        written = Int(written_ptr[0])
        if written > 0:
            progress = True
            assert_equal(
                Int(rl.quic_conn_read_hs(client_h, buf_s, Int32(written))),
                0, "client read_hs failed"
            )

        var c_done = Int(rl.quic_conn_is_handshaking(client_h)) == 0
        var s_done = Int(rl.quic_conn_is_handshaking(server_h)) == 0
        if c_done and s_done:
            break

        assert_true(progress, "handshake stalled - no bytes exchanged")

    buf_c.free()
    buf_s.free()
    written_ptr.free()
    kc_ptr.free()
    kh_ptr.free()

    assert_true(keys.client_hs   > 0, "client Handshake key handle not acquired")
    assert_true(keys.server_hs   > 0, "server Handshake key handle not acquired")
    assert_true(keys.client_1rtt > 0, "client 1-RTT key handle not acquired")
    assert_true(keys.server_1rtt > 0, "server 1-RTT key handle not acquired")


def main() raises:
    # Sentinel
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing")

    var rl = RustlsLibrary()

    # Generate ephemeral self-signed cert for this run (inlined)
    var ec_mod   = Python.import_module("cryptography.hazmat.primitives.asymmetric.ec")
    var x509_mod = Python.import_module("cryptography.x509")
    var oid_mod  = Python.import_module("cryptography.x509.oid")
    var ser_mod  = Python.import_module("cryptography.hazmat.primitives.serialization")
    var hash_mod = Python.import_module("cryptography.hazmat.primitives.hashes")
    var dt_mod   = Python.import_module("datetime")
    var builtins = Python.import_module("builtins")

    var py_key = ec_mod.generate_private_key(ec_mod.SECP256R1())
    var name_attrs = builtins.list()
    name_attrs.append(x509_mod.NameAttribute(oid_mod.NameOID.COMMON_NAME, "qc1-test"))
    var subject = x509_mod.Name(name_attrs)
    var san_list = builtins.list()
    san_list.append(x509_mod.DNSName("localhost"))
    var py_cert = (
        x509_mod.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(py_key.public_key())
        .serial_number(x509_mod.random_serial_number())
        .not_valid_before(dt_mod.datetime(2024, 1, 1))
        .not_valid_after(dt_mod.datetime(2034, 1, 1))
        .add_extension(
            x509_mod.SubjectAlternativeName(san_list),
            critical=False,
        )
        .sign(py_key, hash_mod.SHA256())
    )
    var cert_pem_py = py_cert.public_bytes(ser_mod.Encoding.PEM)
    var key_pem_py  = py_key.private_bytes(
        ser_mod.Encoding.PEM,
        ser_mod.PrivateFormat.PKCS8,
        ser_mod.NoEncryption(),
    )

    var cert_bytes = py_bytes_to_mojo(cert_pem_py)
    var key_bytes  = py_bytes_to_mojo(key_pem_py)
    var cert_ptr = cert_bytes.unsafe_ptr().as_any_origin()
    var key_ptr  = key_bytes.unsafe_ptr().as_any_origin()
    var cert_len = Int32(len(cert_bytes))
    var key_len  = Int32(len(key_bytes))

    # ALPN = "test" (4 bytes, raw - no null terminator)
    var alpn_ptr = _heap_alloc[UInt8](4).as_any_origin()
    alpn_ptr[0] = UInt8(ord("t"))
    alpn_ptr[1] = UInt8(ord("e"))
    alpn_ptr[2] = UInt8(ord("s"))
    alpn_ptr[3] = UInt8(ord("t"))
    var alpn_len = Int32(4)

    # Server config
    var srv_cfg_h_ptr = _heap_alloc[Int32](1).as_any_origin()
    assert_equal(
        Int(rl.quic_server_config_new(cert_ptr, cert_len, key_ptr, key_len, alpn_ptr, alpn_len, srv_cfg_h_ptr)),
        0, "quic_server_config_new failed: " + rl.last_error()
    )
    var srv_cfg_h = srv_cfg_h_ptr[0]

    # Client config (trusts the server cert as CA)
    var cli_cfg_h_ptr = _heap_alloc[Int32](1).as_any_origin()
    assert_equal(
        Int(rl.quic_client_config_with_ca(cert_ptr, cert_len, alpn_ptr, alpn_len, cli_cfg_h_ptr)),
        0, "quic_client_config_with_ca failed: " + rl.last_error()
    )
    var cli_cfg_h = cli_cfg_h_ptr[0]

    # Transport params (empty - sufficient for handshake-only test)
    # Use a 1-byte alloc as sentinel for null-like pointer with len=0
    var tp_sentinel = _heap_alloc[UInt8](1).as_any_origin()

    # Server connection
    var srv_h_ptr = _heap_alloc[Int32](1).as_any_origin()
    assert_equal(
        Int(rl.quic_server_conn_new(srv_cfg_h, Int32(1), tp_sentinel, Int32(0), srv_h_ptr)),
        0, "quic_server_conn_new failed: " + rl.last_error()
    )
    var srv_h = srv_h_ptr[0]

    # Client connection - SNI = "localhost" (9 bytes, raw)
    var sni_ptr = _heap_alloc[UInt8](9).as_any_origin()
    sni_ptr[0] = UInt8(ord("l"))
    sni_ptr[1] = UInt8(ord("o"))
    sni_ptr[2] = UInt8(ord("c"))
    sni_ptr[3] = UInt8(ord("a"))
    sni_ptr[4] = UInt8(ord("l"))
    sni_ptr[5] = UInt8(ord("h"))
    sni_ptr[6] = UInt8(ord("o"))
    sni_ptr[7] = UInt8(ord("s"))
    sni_ptr[8] = UInt8(ord("t"))
    var sni_len = Int32(9)

    var cli_h_ptr = _heap_alloc[Int32](1).as_any_origin()
    assert_equal(
        Int(rl.quic_client_conn_new(cli_cfg_h, Int32(1), sni_ptr, sni_len, tp_sentinel, Int32(0), cli_h_ptr)),
        0, "quic_client_conn_new failed: " + rl.last_error()
    )
    var cli_h = cli_h_ptr[0]

    # Drive the handshake
    var keys = run_handshake(rl, cli_h, srv_h)

    # Free connections (keys stay in KEYS_TABLE)
    _ = rl.quic_conn_free(cli_h)
    _ = rl.quic_conn_free(srv_h)

    # Four AEAD cross-checks
    aead_cross_check(rl, keys.client_hs,   keys.server_hs,   "Handshake  client-write -> server-read")
    aead_cross_check(rl, keys.server_hs,   keys.client_hs,   "Handshake  server-write -> client-read")
    aead_cross_check(rl, keys.client_1rtt, keys.server_1rtt, "1-RTT      client-write -> server-read")
    aead_cross_check(rl, keys.server_1rtt, keys.client_1rtt, "1-RTT      server-write -> client-read")

    # Clean up key handles
    _ = rl.keys_free(keys.client_hs)
    _ = rl.keys_free(keys.server_hs)
    _ = rl.keys_free(keys.client_1rtt)
    _ = rl.keys_free(keys.server_1rtt)

    # Free heap allocs
    tp_sentinel.free()
    srv_cfg_h_ptr.free()
    cli_cfg_h_ptr.free()
    srv_h_ptr.free()
    cli_h_ptr.free()
    alpn_ptr.free()
    sni_ptr.free()

    print("test_cross_quic_hs_keys: all 4 cross-checks passed")
