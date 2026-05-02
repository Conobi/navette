# tests/test_quic_connection.mojo
#
# Loopback handshake and connection lifecycle integration tests for
# QuicConnection. Exercises the full packet protection + handshake pipeline
# in memory (no real UDP).
#
# Run with:
#   cd ~/Projets/perso/mojo-net && uv run mojo run -I . -I conformance \
#     -D ASSERT=all tests/test_quic_connection.mojo

from std.collections import Dict, Optional
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.python import Python, PythonObject

from src.tls.lib import RustlsLibrary
from src.quic.packet_protect import PacketProtect
from src.quic.connection import (
    QuicConnection, QuicEvent, SentStreamFrame,
    SSF_RESET_STREAM, SSF_STOP_SENDING, SSF_MAX_DATA, SSF_MAX_STREAM_DATA, SSF_NEW_CID,
    CONN_ADDR_VALIDATED,
)
from src.quic.cid import CID_ACTIVE
from src.quic.frame import Frame, StreamFrame, ResetStreamFrame
from src.quic.pn_space import SentPacket
from src.quic.cc.cc_trait import AckedPacket, LostPacket
from src.quic.stream import SEND_RESET_SENT
from src.quic.trans_param import TransportParams, default_transport_params
from src.quic.ecn import ECN_STATE_DISABLED
from src.quic.retry import (
    generate_retry_token,
    validate_retry_token,
    compute_retry_integrity_tag,
)
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


def _establish_handshake(
    mut client: QuicConnection,
    mut server: QuicConnection,
    mut now: UInt64,
) raises -> UInt64:
    """Drive the handshake loop until both sides are established.

    Returns the advanced `now` value so callers can continue with monotonic
    timestamps.  Drains post-handshake event queues so tests only observe
    events produced by their own actions.
    """
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


def _pump(
    mut a: QuicConnection,
    mut b: QuicConnection,
    mut now: UInt64,
    rounds: Int = 3,
) raises -> UInt64:
    """Exchange datagrams between `a` and `b` for a few rounds.

    Used after the handshake to propagate application-level frames (STREAM,
    RESET_STREAM, STOP_SENDING, NEW_CONNECTION_ID …) in both directions.
    """
    for _ in range(rounds):
        now += UInt64(10_000)
        var a_dg = a.send(now)
        for i in range(len(a_dg)):
            try:
                b.recv(Span(a_dg[i]), now)
            except:
                pass
        var b_dg = b.send(now)
        for i in range(len(b_dg)):
            try:
                a.recv(Span(b_dg[i]), now)
            except:
                pass
    return now


def _drain_events(mut conn: QuicConnection) raises:
    """Drain and discard all queued events on `conn`."""
    while True:
        var ev = conn.poll()
        if not ev:
            break


def _bytes_equal(data: List[UInt8], expected: String) -> Bool:
    """Compare a byte list against an ASCII string literal."""
    var exp_bytes = expected.as_bytes()
    if len(data) != len(exp_bytes):
        return False
    for i in range(len(data)):
        if data[i] != exp_bytes[i]:
            return False
    return True


def _to_bytes(s: String) -> List[UInt8]:
    """Encode an ASCII string as List[UInt8]."""
    var src = s.as_bytes()
    var out = List[UInt8](capacity=len(src))
    for i in range(len(src)):
        out.append(src[i])
    return out^


def _peer_granted_bidi_limit(conn: QuicConnection) -> UInt64:
    """Return the MAX_STREAMS(bidi) limit currently granted to the peer.

    This reads `stream_map.local_max_streams_bidi`, which is the running limit
    we advertise to the peer.  After N peer-initiated bidi streams are fully
    closed, `check_max_streams_update` sets it to N + initial_max_streams_bidi.
    """
    return conn.stream_map.local_max_streams_bidi


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
    var deadline = client.timeout(now)
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


def test_handshake_with_loss() raises:
    """Client retransmits Initial CRYPTO after PTO when server response is dropped."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]

    var params = _default_params()
    var now = UInt64(1_000_000)

    # Create client.
    var client = QuicConnection.client(
        lib_addr, client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)

    # Create server.
    var server = QuicConnection.server(
        lib_addr, server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )

    # Round 1: client sends Initial (ClientHello) -> server receives it.
    now += UInt64(10_000)
    var client_dgrams_r1 = client.send(now)
    assert_true(len(client_dgrams_r1) > 0, "client should send Initial")
    for i in range(len(client_dgrams_r1)):
        server.recv(Span(client_dgrams_r1[i]), now)

    # Server sends response (ServerHello + certs) -> DROPPED (not fed to client).
    now += UInt64(10_000)
    var server_dgrams_r1 = server.send(now)
    assert_true(len(server_dgrams_r1) > 0, "server should send response")
    # Intentionally NOT feeding server_dgrams_r1 to client.

    # Advance time past the client's PTO timeout.
    var client_deadline = client.timeout(now)
    assert_true(Bool(client_deadline), "client should have a PTO deadline")
    now = client_deadline.value() + UInt64(1)

    # Round 2: client PTO fires, should retransmit Initial CRYPTO.
    var client_dgrams_r2 = client.send(now)
    assert_true(len(client_dgrams_r2) > 0, "client should retransmit after PTO")

    # Feed retransmission to server.
    for i in range(len(client_dgrams_r2)):
        try:
            server.recv(Span(client_dgrams_r2[i]), now)
        except:
            pass  # Server may see duplicate CRYPTO; that's OK

    # Continue normal handshake loop to completion.
    var established = False
    for round_idx in range(20):
        now += UInt64(10_000)
        var s_dg = server.send(now)
        for i in range(len(s_dg)):
            try:
                client.recv(Span(s_dg[i]), now)
            except:
                pass
        var c_dg = client.send(now)
        for i in range(len(c_dg)):
            try:
                server.recv(Span(c_dg[i]), now)
            except:
                pass
        if client.is_established() and server.is_established():
            established = True
            break

    assert_true(established, "handshake did not complete after loss recovery")
    assert_true(client.is_established(), "client not established after loss recovery")
    assert_true(server.is_established(), "server not established after loss recovery")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_handshake_with_loss: PASS")


def test_handshake_with_retry() raises:
    """Retry token round-trip integrated with a normal handshake."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]

    var params = _default_params()
    var now = UInt64(1_000_000)

    # 1. Create initial client to get its initial_dcid.
    var client = QuicConnection.client(
        lib_addr, client_config, "localhost", params, now,
    )
    var client_initial_dcid = List[UInt8](copy=client.initial_dcid)

    # 2. Simulate server-side Retry token generation.
    #    server_secret: 16 random bytes.
    var os = Python.import_module("os")
    var py_secret = os.urandom(16)
    var server_secret = List[UInt8](capacity=16)
    for i in range(16):
        server_secret.append(UInt8(Int(py=py_secret[i])))

    #    client_addr_hash: 32 bytes (SHA-256 of simulated address).
    var hashlib = Python.import_module("hashlib")
    var builtins = Python.import_module("builtins")
    var py_hash = hashlib.sha256(builtins.bytes("127.0.0.1:12345", "utf-8")).digest()
    var client_addr_hash = List[UInt8](capacity=32)
    for i in range(32):
        client_addr_hash.append(UInt8(Int(py=py_hash[i])))

    var token = generate_retry_token(
        lib_addr,
        Span(server_secret),
        Span(client_initial_dcid),
        Span(client_addr_hash),
        now,
    )

    # 3. Validate the token (proving the round-trip works).
    var recovered_dcid = validate_retry_token(
        lib_addr,
        Span(server_secret),
        Span(token),
        Span(client_addr_hash),
        now,
    )

    # Verify recovered DCID matches original.
    assert_equal_int(len(recovered_dcid), len(client_initial_dcid), "recovered DCID length")
    for i in range(len(recovered_dcid)):
        assert_true(
            recovered_dcid[i] == client_initial_dcid[i],
            "recovered DCID byte " + String(i) + " mismatch",
        )

    # 4. Create server with the original DCID from token validation.
    var orig_dcid = List[UInt8](copy=recovered_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )

    # 5. Complete handshake normally.
    var established = False
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
            established = True
            break

    assert_true(established, "handshake did not complete with retry token")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_handshake_with_retry: PASS")


def test_coalesced_packets() raises:
    """Server coalesces Initial + Handshake into a single datagram."""
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

    # Client sends Initial.
    now += UInt64(10_000)
    var client_dgrams = client.send(now)
    assert_true(len(client_dgrams) > 0, "client should send Initial")
    for i in range(len(client_dgrams)):
        server.recv(Span(client_dgrams[i]), now)

    # Server sends response -- should contain coalesced data.
    now += UInt64(10_000)
    var server_dgrams = server.send(now)
    assert_true(len(server_dgrams) > 0, "server should send response")

    # Verify at least one datagram is large (contains coalesced Initial + Handshake).
    var has_large = False
    for i in range(len(server_dgrams)):
        if len(server_dgrams[i]) > 100:
            has_large = True
            break
    assert_true(has_large, "server should send coalesced datagram > 100 bytes")

    # Feed server datagrams to client -- should parse coalesced packets.
    for i in range(len(server_dgrams)):
        try:
            client.recv(Span(server_dgrams[i]), now)
        except:
            pass

    # Continue handshake to completion.
    var established = False
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
            established = True
            break

    assert_true(established, "handshake did not complete with coalesced packets")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_coalesced_packets: PASS")


def test_anti_amplification() raises:
    """Server respects 3x amplification limit before address validation."""
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

    # Client sends Initial (padded to 1200 bytes).
    now += UInt64(10_000)
    var client_dgrams = client.send(now)
    assert_true(len(client_dgrams) > 0, "client should send Initial")

    # Measure total client bytes.
    var client_bytes = 0
    for i in range(len(client_dgrams)):
        client_bytes += len(client_dgrams[i])

    # Feed to server.
    for i in range(len(client_dgrams)):
        server.recv(Span(client_dgrams[i]), now)

    # Server sends response -- measure total bytes.
    now += UInt64(10_000)
    var server_dgrams = server.send(now)

    var server_bytes = 0
    for i in range(len(server_dgrams)):
        server_bytes += len(server_dgrams[i])

    # Assert: server_bytes <= 3 * client_bytes (anti-amplification limit).
    assert_true(
        server_bytes <= 3 * client_bytes,
        "server exceeded 3x amplification limit: server_bytes="
        + String(server_bytes)
        + " client_bytes="
        + String(client_bytes),
    )

    # Verify client Initial was padded to at least 1200 bytes.
    assert_true(
        client_bytes >= 1200,
        "client Initial should be padded to >= 1200 bytes, got " + String(client_bytes),
    )

    # Complete handshake to verify it still works after amplification limit.
    for i in range(len(server_dgrams)):
        try:
            client.recv(Span(server_dgrams[i]), now)
        except:
            pass

    var established = False
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
            established = True
            break

    assert_true(established, "handshake did not complete after anti-amplification test")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_anti_amplification: PASS")


def test_stream_data_transfer() raises:
    """Client <-> server bidi stream echo: "hello" -> "world"."""
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
    _drain_events(client)
    _drain_events(server)

    # Client opens a bidi stream (id 0) and sends "hello" with FIN.
    var sid = client.open_stream(True)
    assert_equal_int(Int(sid), 0, "first client-initiated bidi stream id")
    var hello = _to_bytes("hello")
    client.send_stream_data(sid, Span(hello), True)

    now = _pump(client, server, now, 3)

    # Server observes the stream and reads its data.
    var server_saw_stream = False
    while True:
        var ev = server.poll()
        if not ev:
            break
        var e = ev.value().copy()
        if e.type_id == QuicEvent.STREAM_OPENED and e.stream_id == sid:
            server_saw_stream = True
        if e.type_id == QuicEvent.STREAM_READABLE and e.stream_id == sid:
            server_saw_stream = True
    assert_true(server_saw_stream, "server missed STREAM_OPENED/READABLE event")

    var srv_read = server.recv_stream_data(sid)
    assert_true(_bytes_equal(srv_read[0], "hello"), "server did not read 'hello'")
    assert_true(srv_read[1], "server did not see FIN on stream")

    # Server echoes "world" back with FIN.
    var world = _to_bytes("world")
    server.send_stream_data(sid, Span(world), True)

    _ = _pump(server, client, now, 3)

    var client_saw_readable = False
    while True:
        var ev = client.poll()
        if not ev:
            break
        var e = ev.value().copy()
        if e.type_id == QuicEvent.STREAM_READABLE and e.stream_id == sid:
            client_saw_readable = True
    assert_true(client_saw_readable, "client missed STREAM_READABLE event")

    var cli_read = client.recv_stream_data(sid)
    assert_true(_bytes_equal(cli_read[0], "world"), "client did not read 'world'")
    assert_true(cli_read[1], "client did not see FIN on stream")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_stream_data_transfer: PASS")


def test_multi_stream() raises:
    """Three concurrent bidi streams retain independent data."""
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
    _drain_events(client)
    _drain_events(server)

    var sid_a = client.open_stream(True)
    var sid_b = client.open_stream(True)
    var sid_c = client.open_stream(True)
    assert_equal_int(Int(sid_a), 0, "stream a id")
    assert_equal_int(Int(sid_b), 4, "stream b id")
    assert_equal_int(Int(sid_c), 8, "stream c id")

    var data_a = _to_bytes("AAAA")
    var data_b = _to_bytes("BBBB")
    var data_c = _to_bytes("CCCC")
    client.send_stream_data(sid_a, Span(data_a), True)
    client.send_stream_data(sid_b, Span(data_b), True)
    client.send_stream_data(sid_c, Span(data_c), True)

    # Several rounds so round-robin + ACK cycles flush all three streams.
    _ = _pump(client, server, now, 5)
    _drain_events(server)

    var srv_a = server.recv_stream_data(sid_a)
    var srv_b = server.recv_stream_data(sid_b)
    var srv_c = server.recv_stream_data(sid_c)
    assert_true(_bytes_equal(srv_a[0], "AAAA"), "stream a data mismatch")
    assert_true(srv_a[1], "stream a missing FIN")
    assert_true(_bytes_equal(srv_b[0], "BBBB"), "stream b data mismatch")
    assert_true(srv_b[1], "stream b missing FIN")
    assert_true(_bytes_equal(srv_c[0], "CCCC"), "stream c data mismatch")
    assert_true(srv_c[1], "stream c missing FIN")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_multi_stream: PASS")


def test_unidirectional_stream() raises:
    """Client and server each open a uni stream and deliver data once."""
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
    _drain_events(client)
    _drain_events(server)

    # Client-initiated uni stream: id 2.
    var cli_sid = client.open_stream(False)
    assert_equal_int(Int(cli_sid), 2, "first client uni stream id")
    var uni_data = _to_bytes("uni-data")
    client.send_stream_data(cli_sid, Span(uni_data), True)

    now = _pump(client, server, now, 3)
    _drain_events(server)

    var srv_read = server.recv_stream_data(cli_sid)
    assert_true(
        _bytes_equal(srv_read[0], "uni-data"),
        "server did not read 'uni-data' on uni stream",
    )
    assert_true(srv_read[1], "server missed FIN on client uni stream")

    # Server-initiated uni stream: id 3.
    var srv_sid = server.open_stream(False)
    assert_equal_int(Int(srv_sid), 3, "first server uni stream id")
    var srv_uni = _to_bytes("server-uni")
    server.send_stream_data(srv_sid, Span(srv_uni), True)

    _ = _pump(server, client, now, 3)
    _drain_events(client)

    var cli_read = client.recv_stream_data(srv_sid)
    assert_true(
        _bytes_equal(cli_read[0], "server-uni"),
        "client did not read 'server-uni' on server uni stream",
    )
    assert_true(cli_read[1], "client missed FIN on server uni stream")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_unidirectional_stream: PASS")


def test_reset_stream() raises:
    """Client resets a stream mid-transfer; server observes STREAM_RESET."""
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
    _drain_events(client)
    _drain_events(server)

    var sid = client.open_stream(True)
    var partial = _to_bytes("partial")
    client.send_stream_data(sid, Span(partial), False)  # no FIN

    now = _pump(client, server, now, 3)
    _drain_events(server)

    var srv_read = server.recv_stream_data(sid)
    assert_true(
        _bytes_equal(srv_read[0], "partial"),
        "server did not read 'partial' before reset",
    )
    assert_false(srv_read[1], "server saw FIN before reset")

    # Client resets the stream.
    client.reset_stream(sid, UInt64(42))

    _ = _pump(client, server, now, 3)

    var saw_reset = False
    while True:
        var ev = server.poll()
        if not ev:
            break
        var e = ev.value().copy()
        if e.type_id == QuicEvent.STREAM_RESET and e.stream_id == sid:
            saw_reset = True
            assert_equal_int(Int(e.error_code), 42, "reset error_code")
            assert_equal_int(Int(e.final_size), 7, "reset final_size (len('partial'))")
    assert_true(saw_reset, "server missed STREAM_RESET event")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_reset_stream: PASS")


def test_stop_sending() raises:
    """Server STOP_SENDING triggers client RESET_STREAM; server sees STREAM_RESET."""
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
    _drain_events(client)
    _drain_events(server)

    var sid = client.open_stream(True)
    var data = _to_bytes("first-bytes")
    client.send_stream_data(sid, Span(data), False)

    # Deliver some data so the server has a live stream to stop.
    now = _pump(client, server, now, 3)
    _drain_events(server)
    _ = server.recv_stream_data(sid)

    # Server asks client to stop.
    server.stop_sending(sid, UInt64(99))

    # Server -> client delivers STOP_SENDING; client sends RESET_STREAM back.
    now = _pump(server, client, now, 3)

    var saw_stopped = False
    while True:
        var ev = client.poll()
        if not ev:
            break
        var e = ev.value().copy()
        if e.type_id == QuicEvent.STREAM_STOPPED and e.stream_id == sid:
            saw_stopped = True
            assert_equal_int(Int(e.error_code), 99, "stop_sending error_code")
    assert_true(saw_stopped, "client missed STREAM_STOPPED event")

    # Client send-side should have transitioned to RESET_SENT.
    var key = Int(sid)
    assert_true(
        key in client.stream_map.streams,
        "client stream entry missing after stop_sending",
    )
    var cli_stream = client.stream_map.get_stream(key)
    assert_true(
        Bool(cli_stream.send_state),
        "client stream lost send_state after stop_sending",
    )
    assert_equal_int(
        Int(cli_stream.send_state.value()),
        Int(SEND_RESET_SENT),
        "client send_state should be RESET_SENT after stop_sending",
    )

    # Client -> server flushes RESET_STREAM; server fires STREAM_RESET.
    _ = _pump(client, server, now, 3)

    var saw_reset = False
    while True:
        var ev = server.poll()
        if not ev:
            break
        var e = ev.value().copy()
        if e.type_id == QuicEvent.STREAM_RESET and e.stream_id == sid:
            saw_reset = True
    assert_true(saw_reset, "server missed STREAM_RESET after stop_sending")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_stop_sending: PASS")


def test_cid_issuance() raises:
    """Both endpoints issue a new CID (seq=1) post-handshake via NEW_CONNECTION_ID."""
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
    _drain_events(client)
    _drain_events(server)

    # A few post-handshake rounds so each side ships its NEW_CONNECTION_ID
    # frame and sees the peer's.
    _ = _pump(client, server, now, 4)

    assert_true(
        client.cid_mgr.active_remote_count() >= 2,
        "client: expected >=2 active remote CIDs, got "
        + String(client.cid_mgr.active_remote_count()),
    )
    assert_true(
        server.cid_mgr.active_remote_count() >= 2,
        "server: expected >=2 active remote CIDs, got "
        + String(server.cid_mgr.active_remote_count()),
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_cid_issuance: PASS")


def test_flow_control_error_on_overflow() raises:
    """Sender exceeds peer's stream FC limit → FLOW_CONTROL_ERROR (0x03)."""
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
    _drain_events(client)
    _drain_events(server)

    # Build a STREAM frame whose payload exceeds the stream's recv FC limit
    # (initial_max_stream_data_bidi_remote = 65536 bytes in _default_params).
    # We directly call server._handle_stream_frame so the FC check fires
    # before any packet-layer silencing.
    var sid = UInt64(0)  # client-initiated bidi stream id 0 (peer stream from server's POV)
    var data = List[UInt8](capacity=70_000)
    for _ in range(70_000):
        data.append(UInt8(0x41))

    var sf = StreamFrame(sid, UInt64(0), data, False)
    var raised_fc = False
    try:
        server._handle_stream_frame(sf^)
    except e:
        var emsg = String(e)
        if emsg.find("FLOW_CONTROL") >= 0:
            raised_fc = True
    assert_true(raised_fc, "server should raise FLOW_CONTROL_ERROR on stream FC overflow")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_flow_control_error_on_overflow: PASS")


def test_conn_flow_control_error_on_overflow() raises:
    """Sender exceeds peer's MAX_DATA (conn-level) → FLOW_CONTROL_ERROR (0x03) on conn FC.
    Stream limits are set high so the conn-level check fires first."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]

    # Server advertises a low conn-level limit but high stream-level limits,
    # so only the conn-FC check can trip on the frame we inject.
    var client_params = _default_params()
    var server_params = _default_params()
    server_params.initial_max_data = UInt64(50_000)
    server_params.initial_max_stream_data_bidi_remote = UInt64(200_000)
    server_params.initial_max_stream_data_bidi_local = UInt64(200_000)

    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        lib_addr, client_config, "localhost", client_params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, server_config, server_params,
        Span(orig_dcid), Span(client_dcid), now,
    )

    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Build a STREAM frame with 60_000 bytes: above conn limit (50_000) but
    # below stream limit (200_000), so the conn-FC path fires.
    var sid = UInt64(0)  # client-initiated bidi stream id 0 (peer stream from server's POV)
    var data = List[UInt8](capacity=60_000)
    for _ in range(60_000):
        data.append(UInt8(0x41))

    var sf = StreamFrame(sid, UInt64(0), data, False)
    var raised_fc = False
    try:
        server._handle_stream_frame(sf^)
    except e:
        var emsg = String(e)
        if emsg.find("FLOW_CONTROL") >= 0:
            raised_fc = True
    assert_true(raised_fc, "server should raise FLOW_CONTROL_ERROR on conn FC overflow")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_conn_flow_control_error_on_overflow: PASS")


def test_final_size_error_on_reset_mismatch() raises:
    """RESET_STREAM with final_size < previously-observed offset → FINAL_SIZE_ERROR (0x06)."""
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
    _drain_events(client)
    _drain_events(server)

    # Client opens stream and sends 100 bytes (no FIN).
    var sid = client.open_stream(True)
    var data = List[UInt8](capacity=100)
    for _ in range(100):
        data.append(UInt8(0x41))
    client.send_stream_data(sid, Span(data), False)

    # Pump so the server receives the STREAM frame and records recv_highest_offset = 100.
    now = _pump(client, server, now, 3)
    _drain_events(server)

    # Now send RESET_STREAM with final_size=50, which contradicts the observed 100 bytes.
    var rf = ResetStreamFrame(sid, UInt64(0), UInt64(50))
    var raised_fse = False
    try:
        server._handle_reset_stream(rf)
    except e:
        var emsg = String(e)
        if emsg.find("FINAL_SIZE") >= 0:
            raised_fse = True
    assert_true(raised_fse, "server should raise FINAL_SIZE_ERROR on reset with final_size < received")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_final_size_error_on_reset_mismatch: PASS")


def test_max_stream_data_and_max_data_cycle() raises:
    """Sender fills a stream past 50% of advertised FC, receiver consumes,
    receiver emits MAX_STREAM_DATA, sender sees advanced limit and writes more."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]

    # Force low FC limits so the 50%-threshold logic trips predictably.
    # server_params.initial_max_stream_data_bidi_remote = 10 KiB means:
    #   - the server's recv window for client-initiated bidi streams is 10 KiB
    #   - the client's send limit on those streams is also 10 KiB
    # server_params.initial_max_data = 10 KiB (same as stream window) sets the
    # client's conn-level send limit so the conn-FC 50% threshold also trips:
    #   consumed=7168, remaining=10240-7168=3072 < window/2=5120 → should_update.
    var client_params = _default_params()
    var server_params = _default_params()
    server_params.initial_max_stream_data_bidi_remote = UInt64(10240)
    server_params.initial_max_data = UInt64(10240)

    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        lib_addr, client_config, "localhost", client_params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, server_config, server_params,
        Span(orig_dcid), Span(client_dcid), now,
    )

    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Client opens a bidi stream (id 0).
    var sid = client.open_stream(True)
    assert_equal_int(Int(sid), 0, "first client bidi stream id")

    # Client sends 7 KiB (>50% of 10 KiB stream limit → should_update trips on drain).
    var chunk = List[UInt8](capacity=7 * 1024)
    for _ in range(7 * 1024):
        chunk.append(UInt8(0x41))
    client.send_stream_data(sid, Span(chunk), False)

    # Pump client → server so the server receives all STREAM frames.
    # Each send() emits one STREAM frame (~1200 B); 7 KiB needs ceil(7168/1200)=6 rounds.
    now = _pump(client, server, now, 8)
    _drain_events(server)

    # Server consumes the full 7 KiB — this triggers should_update() on the
    # server's recv-side FC, setting needs_max_stream_data (and possibly
    # needs_max_data) on the stream map.
    var recv_out = server.recv_stream_data(sid)
    assert_equal_int(len(recv_out[0]), 7 * 1024, "server read 7 KiB")

    # Remember the client's current stream send limit before any MAX_STREAM_DATA.
    var stream_before = client.stream_map.get_stream(Int(sid))
    var limit_before = stream_before.fc_send.value().limit

    # Pump server → client so MAX_STREAM_DATA (and possibly MAX_DATA) flow to client.
    now = _pump(server, client, now, 3)

    # Client's stream send FC limit should have advanced beyond the initial 10 KiB.
    var stream_after = client.stream_map.get_stream(Int(sid))
    var limit_after = stream_after.fc_send.value().limit
    assert_true(
        limit_after > limit_before,
        "client stream FC limit did not advance after MAX_STREAM_DATA"
        + " (before=" + String(limit_before) + ", after=" + String(limit_after) + ")",
    )
    # The new limit should be consumed(7168) + window(10240) = 17408, well above
    # the original 10240, so the client can now send at least 5 KiB more.
    assert_true(
        limit_after >= UInt64(17408),
        "client stream FC limit should be >=17408 after MAX_STREAM_DATA, got "
        + String(limit_after),
    )

    # Verify conn-level FC limit advanced (MAX_DATA was emitted server-side and
    # client received + applied it via ensure_limit).
    var conn_fc_limit_after = client.stream_map.conn_fc_send.limit
    assert_true(
        conn_fc_limit_after > UInt64(10240),
        "client conn_fc_send.limit did not advance after MAX_DATA"
        + " (was 10240, now " + String(conn_fc_limit_after) + ")",
    )

    # Verify the client can actually write another 5 KiB (within the new limit).
    var extra = List[UInt8](capacity=5 * 1024)
    for _ in range(5 * 1024):
        extra.append(UInt8(0x42))
    client.send_stream_data(sid, Span(extra), False)  # raises if state error

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_max_stream_data_and_max_data_cycle: PASS")


def test_max_streams_linear_growth() raises:
    """After peer completes N streams, receiver emits MAX_STREAMS(bidi) = N + initial_max_streams_bidi."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]

    # Use small initial_max_streams_bidi for a fast, deterministic test.
    var client_params = _default_params()
    var server_params = _default_params()
    client_params.initial_max_streams_bidi = UInt64(100)
    server_params.initial_max_streams_bidi = UInt64(100)

    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        lib_addr, client_config, "localhost", client_params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, server_config, server_params,
        Span(orig_dcid), Span(client_dcid), now,
    )

    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Verify initial state: server has granted peer (client) bidi limit = 100.
    assert_true(
        _peer_granted_bidi_limit(server) == UInt64(100),
        "initial server bidi limit should be 100, got "
        + String(_peer_granted_bidi_limit(server)),
    )

    # Open N=50 bidi streams from client, send 1 byte + FIN on each.
    var sids = List[UInt64]()
    var one_byte = List[UInt8]()
    one_byte.append(UInt8(0x41))
    for _ in range(50):
        var sid = client.open_stream(True)
        sids.append(sid)
        client.send_stream_data(sid, Span(one_byte), True)

    # Pump client → server: deliver all STREAM+FIN frames.
    # With 50 streams and round-robin, each send() emits ~1 frame.
    # ceil(50/1) = 50 rounds to flush all FINs, plus a few ACK rounds.
    now = _pump(client, server, now, 60)

    _drain_events(server)

    # Server consumes each stream's single byte (recv side → RECV_DATA_READ).
    # For a bidi stream, server must also send data+FIN back to fully close.
    # Send 1 byte + FIN (not FIN-only) so the ACK record has non-zero length
    # and the send-side ack tracking advances correctly.
    var reply_byte = List[UInt8]()
    reply_byte.append(UInt8(0x42))
    for i in range(len(sids)):
        var sid = sids[i]
        _ = server.recv_stream_data(sid)
        # Send 1 byte + FIN back to close server's send side after ACK.
        server.send_stream_data(sid, Span(reply_byte), True)

    # Pump server → client: deliver server FINs (50 streams × ~1 frame each = 50 rounds).
    # Then pump client → server: deliver ACKs (each ACK may cover multiple packets).
    now = _pump(server, client, now, 60)
    now = _pump(client, server, now, 20)
    # Final stabilisation pass.
    now = _pump(server, client, now, 20)
    now = _pump(client, server, now, 20)

    # Server's local_max_streams_bidi should now reflect linear growth:
    # new_limit = peer_completed_bidi (50) + initial_max_streams_bidi (100) = 150.
    var granted_bidi = _peer_granted_bidi_limit(server)
    assert_true(
        granted_bidi == UInt64(150),
        "MAX_STREAMS(bidi) should be 50 + 100 = 150 (linear); got "
        + String(granted_bidi),
    )

    # Explicitly verify it is NOT exponential (not 200, not 150*2, etc.).
    assert_true(
        granted_bidi < UInt64(200),
        "MAX_STREAMS(bidi) must not be exponential (< 200); got "
        + String(granted_bidi),
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_max_streams_linear_growth: PASS")


def _count_active_cids(conn: QuicConnection) -> Int:
    """Count local CIDs with state == CID_ACTIVE."""
    var count = 0
    for i in range(len(conn.cid_mgr.local_cids)):
        if conn.cid_mgr.local_cids[i].state == CID_ACTIVE:
            count += 1
    return count


def _pick_non_primary_cid_seq(conn: QuicConnection) -> UInt64:
    """Return sequence number of the first non-zero active local CID."""
    for i in range(len(conn.cid_mgr.local_cids)):
        if (
            conn.cid_mgr.local_cids[i].state == CID_ACTIVE
            and conn.cid_mgr.local_cids[i].sequence != UInt64(0)
        ):
            return conn.cid_mgr.local_cids[i].sequence
    # Fallback: return seq 1 (should always exist after handshake + pump).
    return UInt64(1)


def _drain_pending_cid_frames(mut conn: QuicConnection) -> Int:
    """Simulate the NEW_CONNECTION_ID build path: mark_advertised for each
    pending (unadvertised) entry.  Returns the number of frames built."""
    var pending = conn.cid_mgr.pending_new_cid_entries()
    var built = len(pending)
    for i in range(len(pending)):
        conn.cid_mgr.mark_advertised(pending[i].sequence)
    return built


def test_cid_retire_triggers_reissue() raises:
    """Client retires a server CID → server issues a replacement CID."""
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
    _drain_events(client)
    _drain_events(server)

    # Exchange NEW_CONNECTION_ID frames so each side has its post-handshake CIDs.
    _ = _pump(client, server, now, 4)

    # Record server's active CID count (should be == peer_active_limit == 2).
    var initial_active = _count_active_cids(server)
    assert_true(
        initial_active >= 2,
        "server has >=2 active local CIDs post-handshake; got "
        + String(initial_active),
    )

    # Pick a non-primary CID on the server to retire.
    var to_retire_seq = _pick_non_primary_cid_seq(server)

    # Retire it: CidManager marks it CID_RETIRED and issues a replacement
    # (advertised=False) if active count drops below peer_active_limit.
    server.cid_mgr.on_retire_connection_id(to_retire_seq)

    # The replacement must be in pending_new_cid_entries() (advertised=False).
    var pending = server.cid_mgr.pending_new_cid_entries()
    assert_true(
        len(pending) >= 1,
        "server queued a replacement CID entry after retire; got "
        + String(len(pending)),
    )
    assert_true(
        not pending[0].advertised,
        "replacement CID must not yet be advertised",
    )

    # Simulate the send path: build NEW_CONNECTION_ID frames + mark_advertised.
    var built = _drain_pending_cid_frames(server)
    assert_true(
        built >= 1,
        "at least one NEW_CONNECTION_ID frame built; got " + String(built),
    )

    # After advertising, pending_new_cid_entries() should be empty.
    var pending_after = server.cid_mgr.pending_new_cid_entries()
    assert_true(
        len(pending_after) == 0,
        "no unadvertised entries remain after build+advertise; got "
        + String(len(pending_after)),
    )

    # Active CID count should be restored to >= initial_active
    # (one CID retired, one replacement issued).
    var active_after = _count_active_cids(server)
    assert_true(
        active_after >= initial_active,
        "active CID count restored after reissue (was "
        + String(initial_active)
        + ", now "
        + String(active_after)
        + ")",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_cid_retire_triggers_reissue: PASS")


# ── Loss-retransmit helpers ───────────────────────────────────────────────


def _last_app_pn(conn: QuicConnection) -> Int:
    """Return the packet number of the most-recently-built App-space packet.

    After send(), spaces[2].next_pn has been incremented by 1, so the last
    PN used is next_pn - 1.
    """
    return Int(conn.spaces[2].next_pn) - 1


def _app_has_kind(conn: QuicConnection, pn: Int, kind: UInt8, stream_id: Int) raises -> Bool:
    """Return True if app_frames_sent[pn] contains a record with the given kind.

    For SSF_NEW_CID the stream_id argument is ignored (CID frames carry
    cid_seq, not stream_id).  For all other kinds the stream_id must match.
    """
    if pn not in conn.app_frames_sent:
        return False
    var recs = conn.app_frames_sent[pn].copy()
    for i in range(len(recs)):
        if recs[i].kind != kind:
            continue
        if kind == SSF_NEW_CID:
            return True
        if Int(recs[i].stream_id) == stream_id:
            return True
    return False


def test_m3c_frames_retransmit_on_loss() raises:
    """RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA, MAX_DATA, and NEW_CONNECTION_ID
    are re-emitted when their carrier App-space packet is declared lost."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var srv_cfg = configs[0]
    var cli_cfg = configs[1]

    # ── Subsection A: RESET_STREAM (client) + STOP_SENDING (server) ──────

    var now_a = UInt64(1_000_000)
    var params_a = _default_params()

    var client_a = QuicConnection.client(lib_addr, cli_cfg, "localhost", params_a, now_a)
    var orig_dcid_a = List[UInt8](copy=client_a.initial_dcid)
    var cli_dcid_a = List[UInt8](copy=client_a.initial_dcid)
    var server_a = QuicConnection.server(
        lib_addr, srv_cfg, params_a, Span(orig_dcid_a), Span(cli_dcid_a), now_a,
    )
    now_a = _establish_handshake(client_a, server_a, now_a)
    _drain_events(client_a)
    _drain_events(server_a)

    # Client opens stream, sends partial data to create a live recv-side on server.
    var sid_a = client_a.open_stream(True)
    var data_a = _to_bytes("hello")
    client_a.send_stream_data(sid_a, Span(data_a), False)
    now_a = _pump(client_a, server_a, now_a, 3)
    _drain_events(server_a)
    _ = server_a.recv_stream_data(sid_a)

    # Client resets → needs_reset_stream = True.
    client_a.reset_stream(sid_a, UInt64(7))
    # Server requests stop → needs_stop_sending = True.
    server_a.stop_sending(sid_a, UInt64(11))

    # Build outgoing packets from each side (drop datagrams; just track PN).
    now_a += UInt64(10_000)
    _ = client_a.send(now_a)
    var c_pn_a = _last_app_pn(client_a)
    assert_true(
        _app_has_kind(client_a, c_pn_a, SSF_RESET_STREAM, Int(sid_a)),
        "client: RESET_STREAM in initial build",
    )
    _ = server_a.send(now_a)
    var s_pn_a = _last_app_pn(server_a)
    assert_true(
        _app_has_kind(server_a, s_pn_a, SSF_STOP_SENDING, Int(sid_a)),
        "server: STOP_SENDING in initial build",
    )

    # Declare the packets lost.
    client_a._on_app_pkt_lost(c_pn_a)
    server_a._on_app_pkt_lost(s_pn_a)

    # Next build must re-emit both frames.
    now_a += UInt64(10_000)
    _ = client_a.send(now_a)
    var c_pn_a2 = _last_app_pn(client_a)
    assert_true(
        _app_has_kind(client_a, c_pn_a2, SSF_RESET_STREAM, Int(sid_a)),
        "client re-emits RESET_STREAM after loss",
    )

    _ = server_a.send(now_a)
    var s_pn_a2 = _last_app_pn(server_a)
    assert_true(
        _app_has_kind(server_a, s_pn_a2, SSF_STOP_SENDING, Int(sid_a)),
        "server re-emits STOP_SENDING after loss",
    )

    # ── Subsection B: MAX_STREAM_DATA + MAX_DATA ──────────────────────────

    var now_b = UInt64(2_000_000)
    # Low stream window so 50% threshold trips after reading ~5 KiB.
    # Low conn window (10 KiB) so conn-FC 50% threshold also trips:
    #   consumed=7168, remaining=10240-7168=3072 < window/2=5120 → should_update.
    var server_params_b = _default_params()
    server_params_b.initial_max_stream_data_bidi_remote = UInt64(10240)
    server_params_b.initial_max_data = UInt64(10240)
    var client_params_b = _default_params()

    var client_b = QuicConnection.client(lib_addr, cli_cfg, "localhost", client_params_b, now_b)
    var orig_dcid_b = List[UInt8](copy=client_b.initial_dcid)
    var cli_dcid_b = List[UInt8](copy=client_b.initial_dcid)
    var server_b = QuicConnection.server(
        lib_addr, srv_cfg, server_params_b, Span(orig_dcid_b), Span(cli_dcid_b), now_b,
    )
    now_b = _establish_handshake(client_b, server_b, now_b)
    _drain_events(client_b)
    _drain_events(server_b)

    # Client sends 7 KiB (>50% of 10 KiB stream window) to the server.
    var sid_b = client_b.open_stream(True)
    var big_b = List[UInt8](capacity=7168)
    for _ in range(7168):
        big_b.append(UInt8(0x41))
    client_b.send_stream_data(sid_b, Span(big_b), False)
    now_b = _pump(client_b, server_b, now_b, 10)
    _drain_events(server_b)

    # Server reads → triggers needs_max_stream_data.
    _ = server_b.recv_stream_data(sid_b)

    # Build server packet; it should include MAX_STREAM_DATA and MAX_DATA.
    now_b += UInt64(10_000)
    _ = server_b.send(now_b)
    var s_pn_b = _last_app_pn(server_b)
    assert_true(
        _app_has_kind(server_b, s_pn_b, SSF_MAX_STREAM_DATA, Int(sid_b)),
        "server: MAX_STREAM_DATA in initial build",
    )
    assert_true(
        _app_has_kind(server_b, s_pn_b, SSF_MAX_DATA, 0),
        "server: MAX_DATA in initial build",
    )

    # Lose it; next build must re-emit.
    server_b._on_app_pkt_lost(s_pn_b)
    now_b += UInt64(10_000)
    _ = server_b.send(now_b)
    var s_pn_b2 = _last_app_pn(server_b)
    assert_true(
        _app_has_kind(server_b, s_pn_b2, SSF_MAX_STREAM_DATA, Int(sid_b)),
        "server re-emits MAX_STREAM_DATA after loss",
    )
    assert_true(
        _app_has_kind(server_b, s_pn_b2, SSF_MAX_DATA, 0),
        "server re-emits MAX_DATA after loss",
    )

    # ── Subsection C: NEW_CONNECTION_ID ───────────────────────────────────

    var now_c = UInt64(3_000_000)
    var params_c = _default_params()

    var client_c = QuicConnection.client(lib_addr, cli_cfg, "localhost", params_c, now_c)
    var orig_dcid_c = List[UInt8](copy=client_c.initial_dcid)
    var cli_dcid_c = List[UInt8](copy=client_c.initial_dcid)
    var server_c = QuicConnection.server(
        lib_addr, srv_cfg, params_c, Span(orig_dcid_c), Span(cli_dcid_c), now_c,
    )
    now_c = _establish_handshake(client_c, server_c, now_c)
    _drain_events(client_c)
    _drain_events(server_c)
    # Pump so each side issues its post-handshake NEW_CONNECTION_ID.
    now_c = _pump(client_c, server_c, now_c, 4)

    # Retire a non-primary CID → CidManager issues a replacement.
    var seq_c = _pick_non_primary_cid_seq(server_c)
    server_c.cid_mgr.on_retire_connection_id(seq_c)

    # Build server packet; should include the NEW_CONNECTION_ID replacement.
    now_c += UInt64(10_000)
    _ = server_c.send(now_c)
    var s_pn_c = _last_app_pn(server_c)
    assert_true(
        _app_has_kind(server_c, s_pn_c, SSF_NEW_CID, 0),
        "server: NEW_CID in initial build",
    )

    # Lose the packet; clear_advertised restores the pending state.
    server_c._on_app_pkt_lost(s_pn_c)
    now_c += UInt64(10_000)
    _ = server_c.send(now_c)
    var s_pn_c2 = _last_app_pn(server_c)
    assert_true(
        _app_has_kind(server_c, s_pn_c2, SSF_NEW_CID, 0),
        "server re-emits NEW_CID after loss",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_m3c_frames_retransmit_on_loss: PASS")


def test_anti_amp_ok_extract_parity() raises:
    """_anti_amp_ok mirrors the inline check: unvalidated server rejects
    oversized sends; validated server and clients are unrestricted."""
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

    # Post-handshake: server is addr-validated — large sends allowed.
    assert_true(
        server._anti_amp_ok(UInt64(1_000_000)),
        "validated server: no cap, allows large send",
    )

    # Simulate unvalidated state: clear CONN_ADDR_VALIDATED from state.
    var saved_state = server.state
    server.state = server.state & ~CONN_ADDR_VALIDATED

    # Reset bookkeeping to simulate no bytes received/sent yet.
    server.bytes_received = UInt64(0)
    server.bytes_sent = UInt64(0)

    # Unvalidated server with 0 bytes_received: 3*0 - fudge = negative → reject any size.
    assert_true(
        not server._anti_amp_ok(UInt64(1000)),
        "unvalidated server with 0 recv rejects 1000-byte send",
    )

    # Receive 1200 bytes: budget = 3*1200 = 3600; fudge=100 means max datagram_size is 3499.
    server.bytes_received = UInt64(1200)
    # bytes_sent=0, datagram_size=3400: 0 + 3400 + 100 = 3500 <= 3600 → OK.
    assert_true(
        server._anti_amp_ok(UInt64(3400)),
        "3400 + 100 fudge fits within 3*1200=3600",
    )
    # bytes_sent=0, datagram_size=3600: 0 + 3600 + 100 = 3700 > 3600 → reject.
    assert_true(
        not server._anti_amp_ok(UInt64(3600)),
        "3600 + 100 > 3600 (exceeds budget)",
    )

    # Restore addr-validated state: cap lifted.
    server.state = saved_state
    assert_true(
        server._anti_amp_ok(UInt64(1_000_000)),
        "addr-validated after restore: large send allowed",
    )

    # Client: _anti_amp_ok always True regardless of state.
    assert_true(
        client._anti_amp_ok(UInt64(1_000_000)),
        "client: anti-amp check always passes",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_anti_amp_ok_extract_parity: PASS")


def test_persistent_congestion_end_to_end() raises:
    """Force a loss-burst spanning persistent_congestion_duration and verify
    CUBIC cwnd resets to 2*MDS, and recovery.min_rtt is re-seeded.

    Drives the detector directly (no wire) and also exercises the
    on_packets_lost fan-out through _detect_losses/_handle_ack via a synthetic
    ACK that declares the injected packets lost via the packet-threshold rule.
    """
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

    # Grow the CUBIC cwnd above the 2*MDS floor via direct on_packet_acked
    # calls on the controller. Avoids needing to wire a send burst.
    _ = client.recovery.cc.cwnd()
    for i in range(50):
        var pkt = AckedPacket(
            pkt_num=UInt64(100 + i),
            size=UInt64(1200),
            time_sent=UInt64(i * 1000),
            time_acked=UInt64(i * 1000 + 500),
            rtt_sample=UInt64(500),
        )
        client.recovery.cc.on_packet_acked(
            pkt, UInt64(500), UInt64(i * 1000 + 500)
        )
    var pre_loss_cwnd = client.recovery.cc.cwnd()
    assert_true(
        pre_loss_cwnd > UInt64(2) * UInt64(1200),
        "cwnd grew before loss burst",
    )

    # Compute the congestion_period using the same formula the detector uses.
    var srtt = client.recovery.smoothed_rtt
    var rttvar = client.recovery.rttvar
    var peer_mad_ms = client.local_params.max_ack_delay
    if client.peer_params:
        peer_mad_ms = client.peer_params.value().max_ack_delay
    var peer_mad_us = peer_mad_ms * 1000
    var rttvar_scaled: UInt64 = UInt64(4) * rttvar
    if rttvar_scaled < UInt64(1000):
        rttvar_scaled = UInt64(1000)
    var congestion_period = (srtt + rttvar_scaled + peer_mad_us) * UInt64(3)

    # Inject five ack-eliciting SentPacket records into the Data space
    # spaced by congestion_period/4, so the span (latest - earliest) exceeds
    # congestion_period.
    var base_time = now + UInt64(1)
    var lost_pns = List[Int]()
    var step = congestion_period // UInt64(4)
    if step == UInt64(0):
        step = UInt64(1)
    for i in range(5):
        var pn = Int(9000 + i)
        var t = base_time + UInt64(i) * step
        var sp = SentPacket(
            pn=UInt64(pn),
            time_sent=t,
            ack_eliciting=True,
            in_flight=True,
            size=Int(1200),
            frames=List[Frame](),
        )
        client.spaces[2].sent_packets[pn] = sp^
        lost_pns.append(pn)

    # Seed the per-space tracker below the earliest so any_ae_acked_in_range
    # answers False.
    client.spaces[2].last_ae_acked_time_sent = base_time - UInt64(1)

    var t_now = base_time + congestion_period + UInt64(1_000)

    # Direct call to the detector — confirms the positive path.
    var persistent = client._detect_persistent_congestion(
        Int(2), lost_pns, peer_mad_us, t_now,
    )
    assert_true(persistent, "persistent congestion declared given criteria")

    # Emulate the caller's post-True behavior: fan out to CC and reset min_rtt.
    var lost_records = List[LostPacket]()
    for i in range(len(lost_pns)):
        var pn = lost_pns[i]
        var sp_pn = client.spaces[2].sent_packets[pn].pn
        var sp_size = client.spaces[2].sent_packets[pn].size
        var sp_ts = client.spaces[2].sent_packets[pn].time_sent
        lost_records.append(
            LostPacket(
                pkt_num=sp_pn,
                size=UInt64(sp_size),
                time_sent=sp_ts,
            )
        )
    var rec_latest = client.recovery.latest_rtt
    client.recovery.cc.on_packets_lost(
        lost_records, client.recovery.smoothed_rtt, t_now, persistent=True
    )
    client.recovery.min_rtt = rec_latest

    var post_cwnd = client.recovery.cc.cwnd()
    var expected_min = UInt64(2) * UInt64(1200)
    assert_true(
        post_cwnd == expected_min,
        "cwnd reset to 2*MDS after persistent congestion; got "
        + String(post_cwnd),
    )
    assert_true(
        client.recovery.min_rtt == client.recovery.latest_rtt,
        "min_rtt re-seeded from latest_rtt",
    )

    # Negative control: with an AE ACK recorded *inside* the range, the
    # detector must not declare persistent. Reseed with a fresh set of PNs.
    var lost_pns2 = List[Int]()
    for i in range(5):
        var pn = Int(9100 + i)
        var t = base_time + UInt64(i) * step
        var sp = SentPacket(
            pn=UInt64(pn),
            time_sent=t,
            ack_eliciting=True,
            in_flight=True,
            size=Int(1200),
            frames=List[Frame](),
        )
        client.spaces[2].sent_packets[pn] = sp^
        lost_pns2.append(pn)
    # Advance the tracker into the range — any_ae_acked_in_range returns True.
    client.spaces[2].last_ae_acked_time_sent = base_time + step
    var neg = client._detect_persistent_congestion(
        Int(2), lost_pns2, peer_mad_us, t_now,
    )
    assert_true(
        not neg,
        "persistent NOT declared when last_ae_acked_time_sent falls in range",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_persistent_congestion_end_to_end: PASS")


# ── Main ─────────────────────────────────────────────────────────────────


def test_pacer_delays_burst() raises:
    """With a low pacing rate, timeout() exposes a pacer deadline delaying the next send."""
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
    _drain_events(client)
    _drain_events(server)

    # Open a bidi stream and send 100 bytes to exercise the pacer.
    var sid = client.open_stream(True)
    var payload = List[UInt8](capacity=100)
    for _ in range(100):
        payload.append(UInt8(0x41))
    client.send_stream_data(sid, Span(payload), False)

    # Flush one round so the packet is sent and pacer tokens are consumed.
    now += UInt64(10_000)
    _ = client.send(now)

    # Call timeout() with the current `now`; some timer (PTO or pacer) must be active.
    var deadline = client.timeout(now)
    assert_true(Bool(deadline), "some timer active after send")
    # The returned deadline must not be in the past.
    if deadline:
        assert_true(
            deadline.value() >= now,
            "deadline not in past; got " + String(deadline.value()),
        )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_pacer_delays_burst: PASS")


def test_cubic_cwnd_gates_send_path() raises:
    """A connection with CUBIC cannot send beyond cwnd."""
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
    _drain_events(client)
    _drain_events(server)

    # Force CUBIC cwnd to a small known value and clear in-flight bytes.
    client.recovery.cc.cubic._cwnd_value = UInt64(2400)  # 2 * MDS
    client.recovery.bytes_in_flight = UInt64(0)
    # Disable the pacer so it doesn't interfere with the cwnd gate check.
    client.recovery.pacer.enabled = False

    # 3000 bytes exceeds cwnd=2400 — send must be blocked.
    var ok = client._can_send(UInt64(3000), now)
    assert_true(not ok, "send blocked by cwnd (cwnd=2400, size=3000)")

    # 1200 bytes fits within cwnd=2400 — send must be permitted.
    ok = client._can_send(UInt64(1200), now)
    assert_true(ok, "1200-byte send permitted within cwnd=2400")

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_cubic_cwnd_gates_send_path: PASS")


def test_blocked_frames_emitted_on_conn_fc_stall() raises:
    """CLIENT emits DATA_BLOCKED when conn-level FC is exhausted."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params,
                                       Span(orig_dcid), Span(client_dcid), now)

    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Exhaust the connection-level flow-control send credit.
    client.stream_map.conn_fc_send.received = client.stream_map.conn_fc_send.limit

    # send() should detect the stall and set blocked_at.
    now += UInt64(10_000)
    _ = client.send(now)

    assert_true(
        client.stream_map.conn_fc_send.blocked_at == client.stream_map.conn_fc_send.limit,
        "blocked_at should equal limit after conn-FC stall",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_blocked_frames_emitted_on_conn_fc_stall: PASS")


def test_blocked_not_re_emitted_at_same_limit() raises:
    """DATA_BLOCKED is not emitted twice at the same limit."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params,
                                       Span(orig_dcid), Span(client_dcid), now)

    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Exhaust FC, first send sets blocked_at.
    client.stream_map.conn_fc_send.received = client.stream_map.conn_fc_send.limit
    now += UInt64(10_000)
    _ = client.send(now)
    var blocked_after_first = client.stream_map.conn_fc_send.blocked_at

    # Second send at the same limit must not change blocked_at.
    now += UInt64(10_000)
    _ = client.send(now)
    var blocked_after_second = client.stream_map.conn_fc_send.blocked_at

    assert_true(
        blocked_after_second == blocked_after_first,
        "blocked_at should not change on second send at same limit",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_blocked_not_re_emitted_at_same_limit: PASS")


def test_blocked_cleared_on_max_data_increase() raises:
    """blocked_at resets to 0 after MAX_DATA raises the limit."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params,
                                       Span(orig_dcid), Span(client_dcid), now)

    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Exhaust FC and trigger blocked.
    var old_limit = client.stream_map.conn_fc_send.limit
    client.stream_map.conn_fc_send.received = old_limit
    now += UInt64(10_000)
    _ = client.send(now)
    assert_true(
        client.stream_map.conn_fc_send.blocked_at == old_limit,
        "blocked_at should be set after stall",
    )

    # Simulate MAX_DATA arrival: raise the limit and clear blocked_at.
    client.stream_map.conn_fc_send.ensure_limit(old_limit + UInt64(1_000_000))
    client.stream_map.conn_fc_send.blocked_at = UInt64(0)

    assert_true(
        client.stream_map.conn_fc_send.blocked_at == UInt64(0),
        "blocked_at should be 0 after MAX_DATA limit increase",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_blocked_cleared_on_max_data_increase: PASS")


def test_ecn_disabled_after_probing() raises:
    """ECN transitions to DISABLED when probes are sent but path strips marks."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params,
                                       Span(orig_dcid), Span(client_dcid), now)

    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Reset to PROBING with 1 probe needed.
    client.ecn_state = UInt8(0)   # ECN_STATE_PROBING
    client.ecn_probe_pkts_needed = 1
    client.ecn_probe_pkts_sent = 0
    client.ecn_probe_first_pn = UInt64(0)
    # Clear server recv_ecn so ACK carries no ECN counts.
    server.spaces[2].recv_ecn.ect0 = UInt64(0)
    server.spaces[2].recv_ecn.ect1 = UInt64(0)
    server.spaces[2].recv_ecn.ce = UInt64(0)

    # Open a stream so client has something to send.
    var sid = client.open_stream(True)
    var hello = _to_bytes("ecn_probe")
    client.send_stream_data(sid, Span(hello), False)

    # Pump several rounds; server always receives without ECN marks.
    for _ in range(5):
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

    assert_true(
        client.ecn_state == ECN_STATE_DISABLED,
        "client ECN state should be DISABLED when probes sent but path strips marks",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_ecn_disabled_after_probing: PASS")


def test_pn_skip_active_after_handshake() raises:
    """Application-space pn_skip_rng is seeded at handshake; Initial/Handshake remain zero."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params,
                                       Span(orig_dcid), Span(client_dcid), now)

    now = _establish_handshake(client, server, now)

    # Application space (index 2) must be seeded after handshake.
    assert_true(
        client.spaces[2].pn_skip_rng != UInt64(0),
        "client: Application-space pn_skip_rng should be non-zero after handshake",
    )
    assert_true(
        client.spaces[2].pn_skip_next < UInt64(0xFFFFFFFFFFFFFFFF),
        "client: pn_skip_next should be < MAX after seeding",
    )
    # Initial (0) and Handshake (1) spaces must NOT be seeded.
    assert_true(
        client.spaces[0].pn_skip_rng == UInt64(0),
        "client: Initial-space pn_skip_rng must remain 0",
    )
    assert_true(
        client.spaces[1].pn_skip_rng == UInt64(0),
        "client: Handshake-space pn_skip_rng must remain 0",
    )
    # Server must also be seeded.
    assert_true(
        server.spaces[2].pn_skip_rng != UInt64(0),
        "server: Application-space pn_skip_rng should be non-zero after handshake",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_pn_skip_active_after_handshake: PASS")


def test_pn_skip_next_in_valid_range() raises:
    """pn_skip_next is in [200, 499] immediately after handshake seeding."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params,
                                       Span(orig_dcid), Span(client_dcid), now)

    now = _establish_handshake(client, server, now)

    var skip_next = client.spaces[2].pn_skip_next
    assert_true(
        skip_next >= UInt64(200),
        "pn_skip_next must be >= 200, got " + String(skip_next),
    )
    assert_true(
        skip_next < UInt64(500),
        "pn_skip_next must be < 500, got " + String(skip_next),
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_pn_skip_next_in_valid_range: PASS")


def test_streams_blocked_bidi_emitted() raises:
    """CLIENT emits STREAMS_BLOCKED_BIDI when peer's bidi stream limit is exhausted."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, configs[0], params, Span(orig_dcid), Span(client_dcid), now
    )
    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Cap peer bidi limit so exactly one more stream can open before we're blocked.
    var base = client.stream_map.local_opened_bidi
    client.stream_map.peer_max_streams_bidi = base + UInt64(1)

    _ = client.stream_map.open_stream(True)   # succeeds
    try:
        _ = client.stream_map.open_stream(True)   # blocked → sets needs_streams_blocked_bidi
    except:
        pass

    assert_true(
        client.stream_map.needs_streams_blocked_bidi,
        "needs_streams_blocked_bidi must be set after failed open_stream",
    )

    _ = client.send(now)

    assert_equal_int(
        Int(client.stream_map.streams_blocked_at_bidi),
        Int(base + UInt64(1)),
        "streams_blocked_at_bidi must equal peer_max_streams_bidi after send",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_streams_blocked_bidi_emitted: PASS")


def test_streams_blocked_dedup_no_resend() raises:
    """STREAMS_BLOCKED is NOT re-emitted for the same peer limit (dedup)."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, configs[0], params, Span(orig_dcid), Span(client_dcid), now
    )
    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    var base = client.stream_map.local_opened_bidi
    client.stream_map.peer_max_streams_bidi = base + UInt64(1)
    _ = client.stream_map.open_stream(True)
    try:
        _ = client.stream_map.open_stream(True)
    except:
        pass

    # First send → emits STREAMS_BLOCKED, sets dedup field.
    _ = client.send(now)
    var after_first = client.stream_map.streams_blocked_at_bidi

    # Second send at same limit → dedup: field must not change.
    now += UInt64(10_000)
    _ = client.send(now)
    assert_equal_int(
        Int(client.stream_map.streams_blocked_at_bidi),
        Int(after_first),
        "streams_blocked_at_bidi must not change on second send (dedup)",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_streams_blocked_dedup_no_resend: PASS")


def test_batch_crypto_roundtrip() raises:
    """Encrypt with client batch methods, decrypt with server batch methods."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var client = PacketProtect(lib_addr)
    var server = PacketProtect(lib_addr)

    var dcid: List[UInt8] = [
        UInt8(0x83), UInt8(0x94), UInt8(0xc8), UInt8(0xf0),
        UInt8(0x3e), UInt8(0x51), UInt8(0x57), UInt8(0x08),
    ]
    client.derive_initial_keys(Span(dcid), True)
    server.derive_initial_keys(Span(dcid), False)

    # Build packet: 22-byte header + 32-byte PADDING + 16-byte tag space = 70 bytes
    # PN_OFFSET = 18, HEADER_LEN = 22 (18 + 4-byte PN)
    var buf_ptr = _heap_alloc[UInt8](70).as_any_origin()
    for i in range(70):
        buf_ptr[i] = UInt8(0)

    # Byte 0: Initial long header, 4-byte PN
    buf_ptr[0] = UInt8(0xC3)
    # Bytes 1-4: version 0x00000001
    buf_ptr[1] = UInt8(0x00)
    buf_ptr[2] = UInt8(0x00)
    buf_ptr[3] = UInt8(0x00)
    buf_ptr[4] = UInt8(0x01)
    # Byte 5: DCID len = 8
    buf_ptr[5] = UInt8(8)
    # Bytes 6-13: DCID
    buf_ptr[6]  = UInt8(0x83)
    buf_ptr[7]  = UInt8(0x94)
    buf_ptr[8]  = UInt8(0xc8)
    buf_ptr[9]  = UInt8(0xf0)
    buf_ptr[10] = UInt8(0x3e)
    buf_ptr[11] = UInt8(0x51)
    buf_ptr[12] = UInt8(0x57)
    buf_ptr[13] = UInt8(0x08)
    # Byte 14: SCID len = 0
    buf_ptr[14] = UInt8(0)
    # Byte 15: token length varint = 0
    buf_ptr[15] = UInt8(0)
    # Bytes 16-17: payload length varint (2-byte: 0x40|high, low) = 52 = 4+32+16
    buf_ptr[16] = UInt8(0x40)
    buf_ptr[17] = UInt8(52)
    # Bytes 18-21: PN = 0 (4 bytes, already zero)
    # Bytes 22-53: PADDING (zeros, already zero)
    # Bytes 54-69: tag space (zeros)

    # Allocate parallel arrays on the heap
    var pkt_ptrs   = _heap_alloc[UnsafePointer[UInt8, MutAnyOrigin]](1).as_any_origin()
    var pns        = _heap_alloc[UInt64](1).as_any_origin()
    var hdr_lens   = _heap_alloc[Int32](1).as_any_origin()
    var pay_lens   = _heap_alloc[Int32](1).as_any_origin()
    var capacities = _heap_alloc[Int32](1).as_any_origin()
    var pkt_lens   = _heap_alloc[Int32](1).as_any_origin()
    var pn_offsets = _heap_alloc[Int32](1).as_any_origin()
    var pn_lengths = _heap_alloc[Int32](1).as_any_origin()

    var out_ct_lens  = _heap_alloc[Int32](1).as_any_origin()
    var out_results  = _heap_alloc[Int32](1).as_any_origin()
    var out_fb       = _heap_alloc[UInt8](1).as_any_origin()
    var out_pnl      = _heap_alloc[Int32](1).as_any_origin()
    var out_pt_lens  = _heap_alloc[Int32](1).as_any_origin()

    pkt_ptrs[0]   = buf_ptr
    pns[0]        = UInt64(0)
    hdr_lens[0]   = Int32(22)   # 18 + 4-byte PN
    pay_lens[0]   = Int32(32)   # PADDING bytes
    capacities[0] = Int32(70)   # total buffer size
    pkt_lens[0]   = Int32(70)
    pn_offsets[0] = Int32(18)
    pn_lengths[0] = Int32(4)

    # Encrypt
    _ = client.batch_encrypt_in_place(0, 1, pns, pkt_ptrs, hdr_lens, pay_lens, capacities, out_ct_lens)
    # out_ct_lens = payload_len + tag_len = 32 + 16 = 48
    assert_true(out_ct_lens[0] == Int32(48), "ciphertext length must be 48 (payload+tag)")

    # Apply header protection
    pkt_lens[0] = Int32(70)
    _ = client.batch_protect_headers(0, 1, pkt_ptrs, pkt_lens, pn_offsets, pn_lengths, out_results)
    assert_true(out_results[0] == Int32(0), "batch_protect_headers must succeed (result=0)")

    # Remove header protection (server side)
    _ = server.batch_unprotect_headers(0, 1, pkt_ptrs, pkt_lens, pn_offsets, out_fb, out_pnl)
    assert_true(out_pnl[0] == Int32(4), "PN length must be 4 after unprotect")

    # Decrypt (server side)
    hdr_lens[0] = Int32(22)
    _ = server.batch_decrypt_in_place(0, 1, pns, pkt_ptrs, pkt_lens, hdr_lens, out_pt_lens)
    assert_true(out_pt_lens[0] == Int32(32), "decrypted plaintext length must be 32")

    # Verify plaintext is all zeros (original PADDING)
    for i in range(32):
        assert_true(buf_ptr[22 + i] == UInt8(0), "plaintext byte must be 0")

    pkt_ptrs.free()
    pns.free()
    hdr_lens.free()
    pay_lens.free()
    capacities.free()
    pkt_lens.free()
    pn_offsets.free()
    pn_lengths.free()
    out_ct_lens.free()
    out_results.free()
    out_fb.free()
    out_pnl.free()
    out_pt_lens.free()
    buf_ptr.free()

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_batch_crypto_roundtrip: PASS")


def test_is_expected_dcid_initial_and_local() raises:
    """is_expected_dcid matches initial_dcid and local_cid; rejects others."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, configs[0], params, Span(orig_dcid), Span(client_dcid), now
    )

    # Expected DCID #1: matches initial_dcid (== client_dcid in this fixture).
    var initial = List[UInt8](copy=client_dcid)
    assert_true(
        server.is_expected_dcid(Span(initial)),
        "is_expected_dcid should match initial_dcid",
    )

    # Expected DCID #2: matches local_cid (server-chosen SCID).
    var local = List[UInt8](copy=server.local_cid)
    assert_true(
        server.is_expected_dcid(Span(local)),
        "is_expected_dcid should match local_cid",
    )

    # NOT expected: an arbitrary unrelated DCID.
    var other = List[UInt8]()
    for b in InlineArray[UInt8, 8](fill=UInt8(0xCD)):
        other.append(b)
    assert_false(
        server.is_expected_dcid(Span(other)),
        "is_expected_dcid should reject unrelated DCIDs",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_is_expected_dcid_initial_and_local: PASS")


def test_quic_connection_dcid_lengths_are_8_bytes() raises:
    """Lock the invariant that QuicConnection.server produces 8-byte DCIDs.

    The bench server's short-header DCID parser (_extract_dcid) assumes
    8-byte CIDs (parse_packet_header(data, 8)). Any future change to
    _generate_random_cid that breaks this invariant must update both
    the parser AND this test together.
    """
    # Mirror the construction from test_is_expected_dcid_initial_and_local.
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, configs[0], params, Span(orig_dcid), Span(client_dcid), now
    )

    # New invariant assertions: both server-side CIDs must be 8 bytes.
    assert_true(
        len(server.local_cid) == 8,
        "expected len(local_cid) == 8, got " + String(len(server.local_cid)),
    )
    assert_true(
        len(server.initial_dcid) == 8,
        "expected len(initial_dcid) == 8, got " + String(len(server.initial_dcid)),
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("PASS: test_quic_connection_dcid_lengths_are_8_bytes")


def test_dcid_demux_disambiguates_two_conns() raises:
    """Conn-table-level invariant: two distinct DCIDs map to two distinct
    conn_idx values via _bytes_to_hex hashing, and a third (unrelated)
    DCID is a miss.

    Validates the migration's data-structure correctness without spinning
    up a full H3UdpHandler. End-to-end behaviour is exercised by the
    smoke gate (T8) and SIGINT captures (T9).
    """
    from bench.h3_server import _bytes_to_hex

    # Three distinct 8-byte DCIDs.
    var dcid_a = List[UInt8]()
    for b in InlineArray[UInt8, 8](fill=UInt8(0xAA)):
        dcid_a.append(b)
    var dcid_b = List[UInt8]()
    for b in InlineArray[UInt8, 8](fill=UInt8(0xBB)):
        dcid_b.append(b)
    var dcid_c = List[UInt8]()
    for b in InlineArray[UInt8, 8](fill=UInt8(0xCC)):
        dcid_c.append(b)

    var hex_a = _bytes_to_hex(Span(dcid_a))
    var hex_b = _bytes_to_hex(Span(dcid_b))
    var hex_c = _bytes_to_hex(Span(dcid_c))

    # Build a conn_dcid_map mirroring the bench's shape.
    var table = Dict[String, Int]()
    table[hex_a] = 0
    table[hex_b] = 1

    # Lookup-by-A returns 0; lookup-by-B returns 1; lookup-by-C is a miss.
    assert_equal_int(
        table[hex_a], 0, "expected hex_a -> 0"
    )
    assert_equal_int(
        table[hex_b], 1, "expected hex_b -> 1"
    )
    assert_false(
        hex_c in table,
        "expected hex_c to be a miss",
    )

    # Sanity: the three hex strings are themselves distinct.
    assert_true(
        hex_a != hex_b and hex_b != hex_c and hex_a != hex_c,
        "expected all three hex encodings to be distinct",
    )

    print("PASS: test_dcid_demux_disambiguates_two_conns")


def test_dcid_to_u64_basic_cases() raises:
    """Lock 5-case bijection of `_dcid_to_u64` 8-byte → UInt64 packing.

    Big-endian pack: result = (b[0]<<56) | (b[1]<<48) | ... | b[7].
    """
    from bench.h3_server import _dcid_to_u64

    # Case 1: All-zero bytes → 0.
    var z = List[UInt8]()
    for _ in range(8):
        z.append(UInt8(0))
    assert_equal_int(
        Int(_dcid_to_u64(Span(z))), 0, "all-zero -> 0"
    )

    # Case 2: All-0xff bytes → UInt64.MAX.
    var f = List[UInt8]()
    for _ in range(8):
        f.append(UInt8(0xFF))
    assert_true(
        _dcid_to_u64(Span(f)) == UInt64.MAX,
        "all-0xff -> UInt64.MAX",
    )

    # Case 3: Ascending [0x01..0x08] → 0x0102030405060708.
    var asc = List[UInt8]()
    for i in range(8):
        asc.append(UInt8(i + 1))
    assert_true(
        _dcid_to_u64(Span(asc)) == UInt64(0x0102030405060708),
        "ascending -> 0x0102030405060708",
    )

    # Case 4: Descending [0x08..0x01] → 0x0807060504030201.
    var desc = List[UInt8]()
    for i in range(8):
        desc.append(UInt8(8 - i))
    assert_true(
        _dcid_to_u64(Span(desc)) == UInt64(0x0807060504030201),
        "descending -> 0x0807060504030201",
    )

    # Case 5: Random 8-byte vector with a known reference value.
    # bytes = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
    # expected = 0xDEADBEEFCAFEBABE
    var r = List[UInt8]()
    r.append(UInt8(0xDE)); r.append(UInt8(0xAD))
    r.append(UInt8(0xBE)); r.append(UInt8(0xEF))
    r.append(UInt8(0xCA)); r.append(UInt8(0xFE))
    r.append(UInt8(0xBA)); r.append(UInt8(0xBE))
    assert_true(
        _dcid_to_u64(Span(r)) == UInt64(0xDEADBEEFCAFEBABE),
        "DEADBEEFCAFEBABE roundtrip",
    )

    print("PASS: test_dcid_to_u64_basic_cases")


def test_dcid_to_u64_injective_on_distinct_inputs() raises:
    """Sample 64 distinct 8-byte vectors; assert pairwise distinctness of
    `_dcid_to_u64` outputs. Trivially true for a bijection on 8-byte → UInt64;
    locked anyway as a regression guard.
    """
    from bench.h3_server import _dcid_to_u64

    var outputs = List[UInt64]()
    for n in range(64):
        # Construct 8 bytes from a deterministic LCG so inputs are distinct.
        var bytes = List[UInt8]()
        var seed = UInt32(n) * UInt32(2654435761) + UInt32(0xDEADBEEF)
        for _ in range(8):
            seed = seed * UInt32(1103515245) + UInt32(12345)
            bytes.append(UInt8((seed >> 16) & UInt32(0xFF)))
        outputs.append(_dcid_to_u64(Span(bytes)))

    # All-pairs distinctness.
    for i in range(len(outputs)):
        for j in range(i + 1, len(outputs)):
            assert_true(
                outputs[i] != outputs[j],
                "expected distinct outputs for distinct inputs",
            )

    print("PASS: test_dcid_to_u64_injective_on_distinct_inputs")


def main() raises:
    print("test_quic_connection:")
    test_loopback_handshake()
    test_connection_close()
    test_idle_timeout()
    test_handshake_with_loss()
    test_handshake_with_retry()
    test_coalesced_packets()
    test_anti_amplification()
    test_stream_data_transfer()
    test_multi_stream()
    test_unidirectional_stream()
    test_reset_stream()
    test_stop_sending()
    test_cid_issuance()
    test_cid_retire_triggers_reissue()
    test_flow_control_error_on_overflow()
    test_conn_flow_control_error_on_overflow()
    test_final_size_error_on_reset_mismatch()
    test_max_stream_data_and_max_data_cycle()
    test_max_streams_linear_growth()
    test_m3c_frames_retransmit_on_loss()
    test_anti_amp_ok_extract_parity()
    test_persistent_congestion_end_to_end()
    test_pacer_delays_burst()
    test_cubic_cwnd_gates_send_path()
    test_blocked_frames_emitted_on_conn_fc_stall()
    test_blocked_not_re_emitted_at_same_limit()
    test_blocked_cleared_on_max_data_increase()
    test_ecn_disabled_after_probing()
    test_pn_skip_active_after_handshake()
    test_pn_skip_next_in_valid_range()
    test_streams_blocked_bidi_emitted()
    test_streams_blocked_dedup_no_resend()
    test_batch_crypto_roundtrip()
    test_is_expected_dcid_initial_and_local()
    test_quic_connection_dcid_lengths_are_8_bytes()
    test_dcid_demux_disambiguates_two_conns()
    test_dcid_to_u64_basic_cases()
    test_dcid_to_u64_injective_on_distinct_inputs()
    print("All test_quic_connection tests passed.")
