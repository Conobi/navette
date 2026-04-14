# tests/test_quic_connection.mojo
#
# Loopback handshake and connection lifecycle integration tests for
# QuicConnection. Exercises the full packet protection + handshake pipeline
# in memory (no real UDP).
#
# Run with:
#   cd ~/Projets/perso/mojo-net && uv run mojo run -I . -I conformance \
#     -D ASSERT=all tests/test_quic_connection.mojo

from std.collections import Optional
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.python import Python, PythonObject

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection, QuicEvent
from src.quic.trans_param import TransportParams, default_transport_params
from tests._test_util import assert_true, assert_false, assert_equal_int


# ── Helpers ──────────────────────────────────────────────────────────────


def py_bytes_to_mojo(raw: PythonObject) raises -> List[UInt8]:
    """Convert Python bytes to Mojo List[UInt8]."""
    var builtins = Python.import_module("builtins")
    var result = List[UInt8]()
    for i in range(Int(py=builtins.len(raw))):
        result.append(UInt8(Int(py=raw[i])))
    return result^


def generate_ephemeral_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    """Generate a self-signed EC cert+key via Python cryptography.

    Returns (cert_pem_bytes, key_pem_bytes).
    """
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
    var cert_pem_py = py_cert.public_bytes(ser_mod.Encoding.PEM)
    var key_pem_py = py_key.private_bytes(
        ser_mod.Encoding.PEM,
        ser_mod.PrivateFormat.PKCS8,
        ser_mod.NoEncryption(),
    )

    var cert_bytes = py_bytes_to_mojo(cert_pem_py)
    var key_bytes = py_bytes_to_mojo(key_pem_py)
    return (cert_bytes^, key_bytes^)


def _create_configs_from_lib(
    lib_ptr: UnsafePointer[RustlsLibrary, MutAnyOrigin],
) raises -> Tuple[Int32, Int32]:
    """Create QUIC server config + client config using an ephemeral cert.

    Returns (server_config_handle, client_config_handle).
    """
    var cert_key = generate_ephemeral_cert()
    var cert_bytes = cert_key[0].copy()
    var key_bytes = cert_key[1].copy()

    var cert_ptr = cert_bytes.unsafe_ptr().as_any_origin()
    var key_ptr = key_bytes.unsafe_ptr().as_any_origin()
    var cert_len = Int32(len(cert_bytes))
    var key_len = Int32(len(key_bytes))

    # ALPN = "h3" (2 bytes, raw).
    var alpn_ptr = _heap_alloc[UInt8](2).as_any_origin()
    alpn_ptr[0] = UInt8(ord("h"))
    alpn_ptr[1] = UInt8(ord("3"))
    var alpn_len = Int32(2)

    # Server config.
    var srv_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    var rc = lib_ptr[].quic_server_config_new(
        cert_ptr, cert_len, key_ptr, key_len, alpn_ptr, alpn_len, srv_cfg_ptr,
    )
    assert_true(
        rc == Int32(0),
        "quic_server_config_new failed: " + lib_ptr[].last_error(),
    )
    var server_config = srv_cfg_ptr[0]
    srv_cfg_ptr.free()

    # Client config (trusts the ephemeral cert as CA).
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
    """Return transport params suitable for integration tests."""
    var params = default_transport_params()
    params.max_idle_timeout = UInt64(30_000)  # 30 s in ms
    params.initial_max_data = UInt64(1_048_576)
    params.initial_max_stream_data_bidi_local = UInt64(65_536)
    params.initial_max_stream_data_bidi_remote = UInt64(65_536)
    params.initial_max_streams_bidi = UInt64(100)
    return params^


# ── Tests ────────────────────────────────────────────────────────────────


def test_loopback_handshake() raises:
    """Full client <-> server handshake in memory."""
    # Heap-allocate the library to avoid stack-pointer invalidation
    # when two QuicConnection objects coexist in the same frame.
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]

    var params = _default_params()
    var now = UInt64(1_000_000)

    # Create client -- generates initial DCID, drives ClientHello.
    var client = QuicConnection.client(
        lib_addr, client_config, "localhost", params, now,
    )

    # Two copies of DCID to avoid aliasing.
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)

    # Create server.
    var server = QuicConnection.server(
        lib_addr, server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )

    # Drive handshake to completion.
    var max_rounds = 20
    var established = False
    for round_idx in range(max_rounds):
        now += UInt64(10_000)
        var client_dgrams = client.send(now)
        for i in range(len(client_dgrams)):
            try:
                server.recv(Span(client_dgrams[i]), now)
            except e:
                print("  [round " + String(round_idx) + "] server.recv: " + String(e))
        var server_dgrams = server.send(now)
        for i in range(len(server_dgrams)):
            try:
                client.recv(Span(server_dgrams[i]), now)
            except e:
                print("  [round " + String(round_idx) + "] client.recv: " + String(e))
        if client.is_established() and server.is_established():
            established = True
            break

    assert_true(established, "handshake did not complete in " + String(max_rounds) + " rounds")
    assert_true(client.is_established(), "client not established after handshake")
    assert_true(server.is_established(), "server not established after handshake")

    # Drain events and verify.
    var client_got_hs = False
    var client_got_tp = False
    while True:
        var ev = client.poll()
        if not ev:
            break
        if ev.value().type_id == QuicEvent.HANDSHAKE_COMPLETE:
            client_got_hs = True
        if ev.value().type_id == QuicEvent.PEER_TRANSPORT_PARAMS:
            client_got_tp = True

    var server_got_hs = False
    var server_got_tp = False
    while True:
        var ev = server.poll()
        if not ev:
            break
        if ev.value().type_id == QuicEvent.HANDSHAKE_COMPLETE:
            server_got_hs = True
        if ev.value().type_id == QuicEvent.PEER_TRANSPORT_PARAMS:
            server_got_tp = True

    assert_true(client_got_hs, "client: missing HANDSHAKE_COMPLETE event")
    assert_true(client_got_tp, "client: missing PEER_TRANSPORT_PARAMS event")
    assert_true(server_got_hs, "server: missing HANDSHAKE_COMPLETE event")
    assert_true(server_got_tp, "server: missing PEER_TRANSPORT_PARAMS event")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_loopback_handshake: PASS")


def test_connection_close() raises:
    """After handshake, client closes; server transitions to draining."""
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

    # Complete handshake.
    for round_idx in range(20):
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
            break
    assert_true(client.is_established(), "client not established before close test")

    # Drain handshake events.
    while True:
        var ev = client.poll()
        if not ev:
            break
    while True:
        var ev = server.poll()
        if not ev:
            break

    # Client initiates close.
    now += UInt64(10_000)
    client.close(UInt64(0), String("done"), now)

    # Pump a few rounds so the server receives CONNECTION_CLOSE.
    for _ in range(5):
        now += UInt64(10_000)
        var client_dgrams = client.send(now)
        for i in range(len(client_dgrams)):
            try:
                server.recv(Span(client_dgrams[i]), now)
            except:
                pass
        var server_dgrams = server.send(now)
        for i in range(len(server_dgrams)):
            try:
                client.recv(Span(server_dgrams[i]), now)
            except:
                pass

    # Server should be draining.
    assert_true(server.is_draining(), "server not draining after client close")

    # Check server received CONNECTION_CLOSED event.
    var server_got_close = False
    while True:
        var ev = server.poll()
        if not ev:
            break
        if ev.value().type_id == QuicEvent.CONNECTION_CLOSED:
            server_got_close = True

    assert_true(server_got_close, "server: missing CONNECTION_CLOSED event")

    # Advance time past drain timer.
    now += UInt64(10_000_000)
    _ = server.send(now)
    assert_true(server.is_closed(), "server not closed after drain timeout")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_connection_close: PASS")


def test_idle_timeout() raises:
    """Idle timeout triggers connection closure after max_idle_timeout."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]

    var params = _default_params()
    params.max_idle_timeout = UInt64(5_000)  # 5 seconds for faster test

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

    # Complete handshake.
    for round_idx in range(20):
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
            break
    assert_true(client.is_established(), "client not established before idle test")

    # Drain events.
    while True:
        var ev = client.poll()
        if not ev:
            break

    # Verify timeout() returns a deadline.
    var deadline = client.timeout()
    assert_true(Bool(deadline), "client timeout() returned None after handshake")

    # Advance time well past idle timeout (5s = 5_000_000 us).
    now += UInt64(10_000_000)

    # Trigger idle timeout check.
    _ = client.send(now)

    assert_true(client.is_closed(), "client not closed after idle timeout")

    # Check for CONNECTION_CLOSED event.
    var got_idle_close = False
    while True:
        var ev = client.poll()
        if not ev:
            break
        if ev.value().type_id == QuicEvent.CONNECTION_CLOSED:
            got_idle_close = True

    assert_true(
        got_idle_close,
        "client: missing CONNECTION_CLOSED event from idle timeout",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_idle_timeout: PASS")


# ── Main ─────────────────────────────────────────────────────────────────


def main() raises:
    print("test_quic_connection:")
    test_loopback_handshake()
    test_connection_close()
    test_idle_timeout()
    print("All test_quic_connection tests passed.")
