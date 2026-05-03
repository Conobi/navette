# tests/test_quic_pacer_bypass.mojo
#
# Pacer-bypass unit tests for QuicConnection during handshake.
# See specs/2026-04-25-quic-pacer-bypass-handshake.md for the design.
#
# Run with:
#   cd ~/Projets/perso/mojo-net && LD_LIBRARY_PATH=lib uv run mojo run -I . -I conformance \
#     -D ASSERT=all tests/test_quic_pacer_bypass.mojo

from std.collections import Optional
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.python import Python, PythonObject

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection
from src.quic.trans_param import TransportParams, default_transport_params
from tests._test_util import assert_true, assert_false, assert_equal_int


# ── Helpers (copy/adapt from tests/test_quic_connection.mojo) ────────────


def py_bytes_to_mojo(raw: PythonObject) raises -> List[UInt8]:
    var builtins = Python.import_module("builtins")
    var result = List[UInt8]()
    for i in range(Int(py=builtins.len(raw))):
        result.append(UInt8(Int(py=raw[i])))
    return result^


def generate_ephemeral_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    var ec_mod = Python.import_module("cryptography.hazmat.primitives.asymmetric.ec")
    var x509_mod = Python.import_module("cryptography.x509")
    var oid_mod = Python.import_module("cryptography.x509.oid")
    var ser_mod = Python.import_module("cryptography.hazmat.primitives.serialization")
    var hash_mod = Python.import_module("cryptography.hazmat.primitives.hashes")
    var dt_mod = Python.import_module("datetime")
    var builtins = Python.import_module("builtins")

    var py_key = ec_mod.generate_private_key(ec_mod.SECP256R1())
    var name_attrs = builtins.list()
    name_attrs.append(x509_mod.NameAttribute(oid_mod.NameOID.COMMON_NAME, "localhost"))
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
    var pem_cert = py_cert.public_bytes(ser_mod.Encoding.PEM)
    var pem_key = py_key.private_bytes(
        ser_mod.Encoding.PEM,
        ser_mod.PrivateFormat.PKCS8,
        ser_mod.NoEncryption(),
    )
    return (py_bytes_to_mojo(pem_cert), py_bytes_to_mojo(pem_key))


def _create_configs_from_lib(
    lib_ptr: UnsafePointer[RustlsLibrary, MutAnyOrigin],
) raises -> Tuple[Int32, Int32]:
    var cert_key = generate_ephemeral_cert()
    var cert_bytes = cert_key[0].copy()
    var key_bytes = cert_key[1].copy()

    var cert_ptr = cert_bytes.unsafe_ptr().as_any_origin()
    var key_ptr = key_bytes.unsafe_ptr().as_any_origin()
    var cert_len = Int32(len(cert_bytes))
    var key_len = Int32(len(key_bytes))

    var alpn_ptr = _heap_alloc[UInt8](2).as_any_origin()
    alpn_ptr[0] = UInt8(ord("h"))
    alpn_ptr[1] = UInt8(ord("3"))
    var alpn_len = Int32(2)

    var srv_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    var rc = lib_ptr[].quic_server_config_new(
        cert_ptr, cert_len, key_ptr, key_len, alpn_ptr, alpn_len,
        Int32(0), srv_cfg_ptr,
    )
    assert_true(
        rc == Int32(0),
        "quic_server_config_new failed: " + lib_ptr[].last_error(),
    )
    var server_config = srv_cfg_ptr[0]
    srv_cfg_ptr.free()

    var cli_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    rc = lib_ptr[].quic_client_config_with_ca(
        cert_ptr, cert_len, alpn_ptr, alpn_len, cli_cfg_ptr,
    )
    assert_true(
        rc == Int32(0),
        "quic_client_config_with_ca failed: " + lib_ptr[].last_error(),
    )
    var client_config = cli_cfg_ptr[0]
    cli_cfg_ptr.free()

    alpn_ptr.free()

    return (server_config, client_config)


def _default_params() -> TransportParams:
    var params = default_transport_params()
    params.max_idle_timeout = UInt64(30_000)
    params.initial_max_data = UInt64(1_048_576)
    params.initial_max_stream_data_bidi_local = UInt64(65_536)
    params.initial_max_stream_data_bidi_remote = UInt64(65_536)
    params.initial_max_streams_bidi = UInt64(100)
    return params^


def _establish_handshake(
    mut client: QuicConnection,
    mut server: QuicConnection,
    mut now: UInt64,
) raises -> UInt64:
    var established = False
    for _ in range(20):
        now += UInt64(10_000)
        var c_dg = client.send(now)
        for i in range(len(c_dg)):
            try:
                server.recv(Span(c_dg[i]), now)
            except:
                pass
        var s_dg = server.send(now)
        for i in range(len(s_dg)):
            try:
                client.recv(Span(s_dg[i]), now)
            except:
                pass
        if client.is_established() and server.is_established():
            established = True
            break
    assert_true(established, "handshake did not complete")
    return now


# ── Tests ────────────────────────────────────────────────────────────────


def test_pacer_bypassed_during_handshake() raises:
    """_can_send returns True for non-established connections even when the
    pacer would otherwise block. The bypass is the surgical fix from
    specs/2026-04-25-quic-pacer-bypass-handshake.md."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        lib_addr, client_config, "localhost", params, now,
    )

    # Sanity: handshake has not completed.
    assert_false(client.is_established(), "fresh client must not be established")

    # Make anti-amp permissive: clients are unconditionally allowed to send by
    # _anti_amp_ok (the 3x check applies only to servers); set bytes_received
    # nonetheless so a server-side variant of this test would also pass.
    client.bytes_received = UInt64(2000)

    # Force the pacer into a "would-block" state. With tokens=0,
    # last_sched_time=now, and a finite pacing rate, refill produces 0
    # additional tokens (zero elapsed) and tokens_projected < MIN_DATAGRAM_SIZE
    # => next_send_time returns Some(deadline).
    client.recovery.pacer.tokens = UInt64(0)
    client.recovery.pacer.last_sched_time = now
    client.recovery.smoothed_rtt = UInt64(333_000)  # microseconds; INITIAL_RTT

    # Sanity: the pacer setup actually produces a deadline.
    var rate = client.recovery.cc.pacing_rate(client.recovery.smoothed_rtt)
    var deadline = client.recovery.pacer.next_send_time(rate, now)
    assert_true(
        Bool(deadline),
        "test setup wrong: pacer should produce a deadline with tokens=0 + elapsed=0",
    )

    # The actual assertion under test: bypass kicks in because the connection
    # is not yet established.
    assert_true(
        client._can_send(UInt64(1200), now),
        "_can_send must return True during handshake even when pacer would gate",
    )

    # Anti-amplification is independent of the bypass; this is server-side,
    # but we verify the order of checks is preserved by constructing a
    # server connection with bytes_received=0 and asserting _can_send is
    # False even though the pacer would now allow (server hasn't sent
    # anything yet).
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )
    server.bytes_received = UInt64(0)
    server.bytes_sent = UInt64(0)
    assert_false(
        server._can_send(UInt64(1500), now),
        "anti-amp must still gate non-established server with bytes_received=0",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_pacer_bypassed_during_handshake: PASS")


def test_pacer_active_after_handshake() raises:
    """After is_established(), the pacer continues to gate sends. Regression
    guard ensuring the bypass is scoped strictly to the handshake phase."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        lib_addr, client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )

    now = _establish_handshake(client, server, now)
    assert_true(client.is_established(), "client must be established")

    # Force the same pacer "would-block" setup as test 1.
    client.recovery.pacer.tokens = UInt64(0)
    client.recovery.pacer.last_sched_time = now
    client.recovery.smoothed_rtt = UInt64(333_000)

    # Now the pacer must gate because is_established() is True.
    assert_false(
        client._can_send(UInt64(1200), now),
        "_can_send must return False after handshake when pacer gates",
    )

    # Advance time past the deadline; the pacer must allow.
    var rate = client.recovery.cc.pacing_rate(client.recovery.smoothed_rtt)
    var deadline = client.recovery.pacer.next_send_time(rate, now)
    assert_true(Bool(deadline), "pacer setup must still produce a deadline")
    var advanced_now = deadline.value() + UInt64(1000)
    assert_true(
        client._can_send(UInt64(1200), advanced_now),
        "_can_send must return True after pacer deadline elapses",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_pacer_active_after_handshake: PASS")


def test_handshake_padding_still_works() raises:
    """A fresh client's first Initial flight is still padded to MIN_DATAGRAM_SIZE
    after the bypass change. Regression guard for the padding logic at
    src/quic/connection.mojo:1714-1728."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var client_config = configs[1]

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        lib_addr, client_config, "localhost", params, now,
    )

    # Drive one round of send: client should emit a padded Initial datagram.
    var dgrams = client.send(now)
    assert_true(len(dgrams) >= 1, "client must emit at least one datagram on first send")

    # The first datagram must be padded to >= MIN_DATAGRAM_SIZE (1200 bytes)
    # per RFC 9000 §14.1; the bypass must not affect the padding logic.
    var first_dg_len = len(dgrams[0])
    assert_true(
        first_dg_len >= 1200,
        "first Initial datagram must be padded to >= 1200 bytes; got " + String(first_dg_len),
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_handshake_padding_still_works: PASS")


def main() raises:
    print("test_quic_pacer_bypass:")
    test_pacer_bypassed_during_handshake()
    test_pacer_active_after_handshake()
    test_handshake_padding_still_works()
    print("All test_quic_pacer_bypass tests passed.")
