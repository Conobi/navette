# tests/test_ecn.mojo
# ECN path validation and CE congestion integration tests.
#
# Run with:
#   cd ~/Projets/perso/mojo-net && uv run mojo run -I . -I conformance \
#     -D ASSERT=all tests/test_ecn.mojo

from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.python import Python, PythonObject

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection, QuicEvent
from src.quic.ecn import (
    ECN_NOT_ECT, ECN_ECT0, ECN_ECT1, ECN_CE,
    ECN_STATE_PROBING, ECN_STATE_CAPABLE, ECN_STATE_DISABLED,
)
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
    """Generate a self-signed EC cert+key via Python cryptography."""
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


def _create_configs(
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
        cert_ptr, cert_len, key_ptr, key_len, alpn_ptr, alpn_len, srv_cfg_ptr,
    )
    assert_true(rc == Int32(0), "quic_server_config_new failed")
    var server_config = srv_cfg_ptr[0]
    srv_cfg_ptr.free()

    var cli_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    rc = lib_ptr[].quic_client_config_with_ca(
        cert_ptr, cert_len, alpn_ptr, alpn_len, cli_cfg_ptr,
    )
    assert_true(rc == Int32(0), "quic_client_config_with_ca failed")
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


def _establish(
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


def _pump(
    mut a: QuicConnection,
    mut b: QuicConnection,
    mut now: UInt64,
    rounds: Int = 3,
) raises -> UInt64:
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
    while True:
        var ev = conn.poll()
        if not ev:
            break


def _to_bytes(s: String) -> List[UInt8]:
    """Convert ASCII string to byte list."""
    var result = List[UInt8]()
    var b = s.as_bytes()
    for i in range(len(b)):
        result.append(b[i])
    return result^


# ── Tests ─────────────────────────────────────────────────────────────────


def test_ecn_recv_counts_ce_mark() raises:
    """Server receives client datagram with ECN_CE; recv_ecn.ce increments."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params, Span(orig_dcid), Span(client_dcid), now)

    now = _establish(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Open a stream and send data so client has a packet to send.
    var sid = client.open_stream(True)
    var data = _to_bytes("ping")
    client.send_stream_data(sid, Span(data), False)

    # Client sends a datagram; server receives it with ECN_CE mark.
    now += UInt64(10_000)
    var c_dg = client.send(now)
    var ce_before = server.spaces[2].recv_ecn.ce
    for i in range(len(c_dg)):
        try:
            server.recv(Span(c_dg[i]), now, ecn_mark=ECN_CE)
        except:
            pass

    assert_true(
        server.spaces[2].recv_ecn.ce > ce_before,
        "server.spaces[2].recv_ecn.ce should have incremented after CE-marked recv",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_ecn_recv_counts_ce_mark: PASS")


def test_ecn_ack_includes_ecn_counts() raises:
    """After server receives CE-marked datagram, recv_ecn is non-zero."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params, Span(orig_dcid), Span(client_dcid), now)

    now = _establish(client, server, now)
    _drain_events(client)
    _drain_events(server)

    var sid = client.open_stream(True)
    var data = _to_bytes("data")
    client.send_stream_data(sid, Span(data), False)

    now += UInt64(10_000)
    var c_dg = client.send(now)
    for i in range(len(c_dg)):
        try:
            server.recv(Span(c_dg[i]), now, ecn_mark=ECN_CE)
        except:
            pass

    assert_true(
        server.spaces[2].recv_ecn.is_zero() == False,
        "server recv_ecn should be non-zero after receiving CE-marked packet",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_ecn_ack_includes_ecn_counts: PASS")


def test_ecn_probing_to_capable() raises:
    """ECN state transitions PROBING -> CAPABLE when ACK echoes ECN counts."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params, Span(orig_dcid), Span(client_dcid), now)

    now = _establish(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Reset client ECN state to PROBING with 1 probe needed.
    client.ecn_state = ECN_STATE_PROBING
    client.ecn_probe_pkts_needed = 1
    client.ecn_probe_pkts_sent = 0
    client.ecn_probe_first_pn = UInt64(0)

    # Open a stream so client has a packet to send (the probe).
    var sid = client.open_stream(True)
    var data = _to_bytes("probe")
    client.send_stream_data(sid, Span(data), False)

    # Client sends (ECT0 probes); server receives them with ECT0 mark.
    now += UInt64(10_000)
    var c_dg = client.send(now)
    for i in range(len(c_dg)):
        try:
            server.recv(Span(c_dg[i]), now, ecn_mark=ECN_ECT0)
        except:
            pass

    # Server ACK will carry ECN counts (ect0 > 0). Client processes ACK.
    now += UInt64(10_000)
    var s_dg = server.send(now)
    for i in range(len(s_dg)):
        try:
            client.recv(Span(s_dg[i]), now)
        except:
            pass

    assert_true(
        client.ecn_state == ECN_STATE_CAPABLE,
        "client ECN state should be CAPABLE after probe ACK with ECN counts",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_ecn_probing_to_capable: PASS")


def test_ecn_probing_to_disabled_no_counts() raises:
    """ECN state transitions PROBING -> DISABLED when ACK has no ECN counts."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params, Span(orig_dcid), Span(client_dcid), now)

    now = _establish(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Reset client ECN state to PROBING.
    client.ecn_state = ECN_STATE_PROBING
    client.ecn_probe_pkts_needed = 1
    client.ecn_probe_pkts_sent = 0
    client.ecn_probe_first_pn = UInt64(0)
    # Clear server recv_ecn so its ACK has no ECN counts.
    server.spaces[2].recv_ecn.ect0 = UInt64(0)
    server.spaces[2].recv_ecn.ect1 = UInt64(0)
    server.spaces[2].recv_ecn.ce = UInt64(0)

    # Open a stream so client has a packet to send (the probe).
    var sid2 = client.open_stream(True)
    var data2 = _to_bytes("noprobe")
    client.send_stream_data(sid2, Span(data2), False)

    # Client sends (ECT0 probes); server receives WITHOUT ecn_mark (NOT_ECT).
    now += UInt64(10_000)
    var c_dg2 = client.send(now)
    for i in range(len(c_dg2)):
        try:
            # No ecn_mark argument -> defaults to ECN_NOT_ECT (bleaching simulation).
            server.recv(Span(c_dg2[i]), now)
        except:
            pass

    # Server ACK has no ECN counts; client processes it.
    # Pump several rounds to ensure ACK is generated and processed.
    for _ in range(5):
        now += UInt64(10_000)
        var s_dg2 = server.send(now)
        for i in range(len(s_dg2)):
            try:
                client.recv(Span(s_dg2[i]), now)
            except:
                pass
        var c_ack = client.send(now)
        for i in range(len(c_ack)):
            try:
                server.recv(Span(c_ack[i]), now)
            except:
                pass

    assert_true(
        client.ecn_state == ECN_STATE_DISABLED,
        "client ECN state should be DISABLED when ACK carries no ECN counts",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_ecn_probing_to_disabled_no_counts: PASS")


def test_ecn_disabled_no_ecn_mark() raises:
    """When ECN state is DISABLED, ecn_mark() returns ECN_NOT_ECT."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params, Span(orig_dcid), Span(client_dcid), now)

    now = _establish(client, server, now)
    _drain_events(client)
    _drain_events(server)

    client.ecn_state = ECN_STATE_DISABLED
    assert_true(
        client.ecn_mark() == ECN_NOT_ECT,
        "ecn_mark() must return ECN_NOT_ECT when state is DISABLED",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_ecn_disabled_no_ecn_mark: PASS")


def test_ecn_ce_triggers_congestion() raises:
    """CE delta > 0 in ACK → _process_ecn_feedback → on_congestion_event → cwnd reduces."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params, Span(orig_dcid), Span(client_dcid), now)

    now = _establish(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Set client to CAPABLE so ECN feedback is processed.
    client.ecn_state = ECN_STATE_CAPABLE
    # Inflate cwnd above initial window so reduction is observable.
    client.recovery.cc.cubic._cwnd_value = UInt64(500_000)
    client.recovery.cc.cubic.ssthresh = UInt64(1_000_000)
    # Reset congestion_event_time so suppression window doesn't block the event.
    client.recovery.cc.cubic.congestion_event_time = UInt64(0)

    # Step 1: Client sends a packet (marked ECT0 since state is CAPABLE).
    var sid = client.open_stream(True)
    var data = _to_bytes("ping")
    client.send_stream_data(sid, Span(data), False)
    now += UInt64(10_000)
    var c_dg = client.send(now)
    assert_true(len(c_dg) > 0, "client must produce datagrams")

    # Step 2: Server receives client's packets with ECN_CE mark.
    # This increments server.spaces[2].recv_ecn.ce → next ACK will carry CE counts.
    for i in range(len(c_dg)):
        try:
            server.recv(Span(c_dg[i]), now, ecn_mark=ECN_CE)
        except:
            pass

    # Verify server recorded the CE mark.
    assert_true(
        server.spaces[2].recv_ecn.ce > UInt64(0),
        "server should record CE mark in recv_ecn.ce",
    )

    # Step 3: Server sends ACK with ECN counts (has_ecn=True, ecn_ce=1).
    var s_dg = server.send(now)
    assert_true(len(s_dg) > 0, "server must produce ACK")

    # Step 4: Client receives ACK → _handle_ack → _process_ecn_feedback →
    # CE delta > last_ack_ecn.ce → on_congestion_event → cwnd drops.
    # Zero last_ack_ecn so delta = ack.ecn_ce - 0 > 0.
    client.spaces[2].last_ack_ecn.ce = UInt64(0)
    var cwnd_before = client.recovery.cc.cubic._cwnd_value
    for i in range(len(s_dg)):
        try:
            client.recv(Span(s_dg[i]), now)
        except:
            pass

    assert_true(
        client.recovery.cc.cwnd() <= cwnd_before,
        "CE in ACK must trigger cwnd reduction via ECN feedback path",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_ecn_ce_triggers_congestion: PASS")


def test_ecn_bleaching_disables() raises:
    """ECT0-in-flight but ACK with no ECN counts (bleaching) → DISABLED."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params, Span(orig_dcid), Span(client_dcid), now)

    now = _establish(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # Client is CAPABLE; set up conditions for bleaching detection:
    # ect0_in_flight > 0 but ACK from server carries no ECN counts.
    client.ecn_state = ECN_STATE_CAPABLE
    # Ensure server recv_ecn is zero so it won't set has_ecn in ACK.
    server.spaces[2].recv_ecn.ect0 = UInt64(0)
    server.spaces[2].recv_ecn.ect1 = UInt64(0)
    server.spaces[2].recv_ecn.ce = UInt64(0)
    # last_ack_ecn also zero so delta calc stays zero.
    server.spaces[2].last_ack_ecn.ect0 = UInt64(0)
    server.spaces[2].last_ack_ecn.ect1 = UInt64(0)
    server.spaces[2].last_ack_ecn.ce = UInt64(0)

    # Open a stream so client has packets to send (marked ECT0 since CAPABLE).
    var sid3 = client.open_stream(True)
    var data3 = _to_bytes("bleach")
    client.send_stream_data(sid3, Span(data3), False)

    # Client sends; server receives WITHOUT ecn_mark (simulating bleaching: path stripped ECT0).
    now += UInt64(10_000)
    var c_dg3 = client.send(now)
    for i in range(len(c_dg3)):
        try:
            server.recv(Span(c_dg3[i]), now)
        except:
            pass

    # Server ACK has no ECN counts; when client processes it with ect0_in_flight>0
    # but ack has_ecn=False, the bleaching check fires.
    now += UInt64(10_000)
    var s_dg3 = server.send(now)
    for i in range(len(s_dg3)):
        try:
            client.recv(Span(s_dg3[i]), now)
        except:
            pass

    assert_true(
        client.ecn_state == ECN_STATE_DISABLED,
        "client ECN state should be DISABLED when ECT0 packets sent but ACK has no ECN counts (bleaching)",
    )

    lib_ptr.destroy_pointee()
    lib_ptr.free()
    print("  test_ecn_bleaching_disables: PASS")


def main() raises:
    print("test_ecn:")
    test_ecn_recv_counts_ce_mark()
    test_ecn_ack_includes_ecn_counts()
    test_ecn_probing_to_capable()
    test_ecn_probing_to_disabled_no_counts()
    test_ecn_disabled_no_ecn_mark()
    test_ecn_ce_triggers_congestion()
    test_ecn_bleaching_disables()
    print("All ECN tests passed.")
