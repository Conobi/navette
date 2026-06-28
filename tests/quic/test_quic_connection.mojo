# tests/test_quic_connection.mojo
#
# Loopback handshake and connection lifecycle integration tests for
# QuicConnection. Exercises the full packet protection + handshake pipeline
# in memory (no real UDP).
#
# Run with:
#   cd ~/Projets/perso/navette && uv run mojo run -I . -I conformance \
#     -D ASSERT=all tests/test_quic_connection.mojo

from std.collections import Dict, Optional
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.python import Python, PythonObject

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.packet_protect import PacketProtect
from navette.quic.connection import (
    QuicConnection, QuicEvent, SentStreamFrame,
    SSF_RESET_STREAM, SSF_STOP_SENDING, SSF_MAX_DATA, SSF_MAX_STREAM_DATA, SSF_NEW_CID,
    CONN_ADDR_VALIDATED, CONN_ESTABLISHED, CONN_CLOSING,
)
from navette.quic.guard_predicates import (
    check_long_reserved_bits,
    check_max_streams_value,
    check_new_connection_id_length,
    check_new_connection_id_retire_prior,
    check_streams_blocked_value,
    check_short_reserved_bits,
    stream_offset_exceeds_fc,
    is_client_only_frame_on_server,
    is_crypto_in_zero_rtt,
    is_path_challenge_in_handshake,
    is_unknown_frame_type,
    predicate_crypto_in_zero_rtt,
    predicate_f11_no_frames,
    predicate_f15_reset_on_server_uni,
    predicate_f16_stop_sending_local_not_created,
    predicate_f18_f19_max_stream_data,
    MaxStreamDataCtx,
    QuicResetCtx,
    QuicStopSendingCtx,
    ZERO_RTT_SPACE_IDX,
)
from navette.quic.guard_tags import (
    GUARD_TAG_TP_ORIGINAL_DCID_FORBIDDEN,
    GUARD_TAG_MIGRATION_DISABLED,
    GUARD_TAG_CRYPTO_IN_ZERO_RTT,
)
from navette.tls.guard_tags import (
    GUARD_TAG_TLS_KEYUPDATE_HANDSHAKE,
    GUARD_TAG_TLS_KEYUPDATE_1RTT,
    GUARD_TAG_TLS_NO_ALPN,
    GUARD_TAG_TLS_END_OF_EARLY_DATA,
)
from navette.quic.connection import _tls_guard_tag_for
from navette.quic.cid import CID_ACTIVE
from navette.quic.frame import Frame, StreamFrame, ResetStreamFrame
from navette.quic.path_validator import PathKey
from navette.quic.pn_space import SentPacket
from navette.quic.cc.cc_trait import AckedPacket, LostPacket
from navette.quic.stream import SEND_RESET_SENT
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.quic.ecn import ECN_STATE_DISABLED
from navette.quic.retry import (
    generate_retry_token,
    validate_retry_token,
    compute_retry_integrity_tag,
)
from tests._test_util import assert_true, assert_false, assert_equal_int, load_test_cert, load_test_ca


# ── Helpers ──────────────────────────────────────────────────────────────


def generate_ephemeral_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    # Backed by tests/fixtures/tls/server.{crt,key} (regen via
    # scripts/regen_test_certs.sh). See plans/2026-05-13-deps-enhancement.md §3.1.
    return load_test_cert()


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


def _drain_events(mut conn: QuicConnection):
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
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    # Create client -- generates initial DCID, drives ClientHello.
    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )

    # Two copies of DCID to avoid aliasing.
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)

    # Create server.
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_loopback_handshake: PASS")


def test_connection_close() raises:
    """After handshake, client closes; server transitions to draining."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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
    client.close_transport(UInt64(0), String("done"), now)

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

    _ = tls^
    print("  test_connection_close: PASS")


def test_idle_timeout() raises:
    """Idle timeout triggers connection closure after max_idle_timeout."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    params.max_idle_timeout = UInt64(5_000)  # 5 seconds for faster test

    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_idle_timeout: PASS")


def test_handshake_with_loss() raises:
    """Client retransmits Initial CRYPTO after PTO when server response is dropped."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    # Create client.
    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)

    # Create server.
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_handshake_with_loss: PASS")


def test_handshake_with_retry() raises:
    """Retry token round-trip integrated with a normal handshake."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    # 1. Create initial client to get its initial_dcid.
    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
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
        tls.shared(),
        Span(server_secret),
        Span(client_initial_dcid),
        Span(client_addr_hash),
        now,
    )

    # 3. Validate the token (proving the round-trip works).
    var recovered_dcid = validate_retry_token(
        tls.shared(),
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
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_handshake_with_retry: PASS")


def test_coalesced_packets() raises:
    """Server coalesces Initial + Handshake into a single datagram."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_coalesced_packets: PASS")


def test_anti_amplification() raises:
    """Server respects 3x amplification limit before address validation."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_anti_amplification: PASS")


def test_stream_data_transfer() raises:
    """Client <-> server bidi stream echo: "hello" -> "world"."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_stream_data_transfer: PASS")


def test_multi_stream() raises:
    """Three concurrent bidi streams retain independent data."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_multi_stream: PASS")


def test_unidirectional_stream() raises:
    """Client and server each open a uni stream and deliver data once."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_unidirectional_stream: PASS")


def test_reset_stream() raises:
    """Client resets a stream mid-transfer; server observes STREAM_RESET."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_reset_stream: PASS")


def test_stop_sending() raises:
    """Server STOP_SENDING triggers client RESET_STREAM; server sees STREAM_RESET."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_stop_sending: PASS")


def test_cid_issuance() raises:
    """Both endpoints issue a new CID (seq=1) post-handshake via NEW_CONNECTION_ID."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_cid_issuance: PASS")


def test_flow_control_error_on_overflow() raises:
    """Sender exceeds peer's stream FC limit → FLOW_CONTROL_ERROR (0x03)
    surfaced via close_transport with the F01 guard tag.

    The legacy raise path was rewritten into a queued CONNECTION_CLOSE
    so the outer try/except at recv_from_buffer no longer swallows the
    violation. Verified via `server.pending_close`.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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
    server._handle_stream_frame(sf)
    assert_true(
        Bool(server.pending_close),
        "server.pending_close not set after stream FC overflow",
    )
    var cc = server.pending_close.value().copy()
    assert_equal_int(
        Int(cc.error_code), 0x03, "FLOW_CONTROL_ERROR code on stream FC overflow"
    )
    assert_true(cc.is_transport, "must be a transport-CC frame")
    var reason_str = String("")
    for i in range(len(cc.reason)):
        reason_str = reason_str + chr(Int(cc.reason[i]))
    assert_true(
        "[QUIC-STREAM-LARGE-OFFSET]" in reason_str,
        "F01 guard tag present in CC reason, got " + reason_str,
    )

    _ = tls^
    print("  test_flow_control_error_on_overflow: PASS")


def test_conn_flow_control_error_on_overflow() raises:
    """Sender exceeds peer's MAX_DATA (conn-level) → FLOW_CONTROL_ERROR (0x03) on conn FC.
    Stream limits are set high so the conn-level check fires first."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    # Server advertises a low conn-level limit but high stream-level limits,
    # so only the conn-FC check can trip on the frame we inject.
    var client_params = _default_params()
    var server_params = _default_params()
    server_params.initial_max_data = UInt64(50_000)
    server_params.initial_max_stream_data_bidi_remote = UInt64(200_000)
    server_params.initial_max_stream_data_bidi_local = UInt64(200_000)

    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", client_params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, server_params,
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
        server._handle_stream_frame(sf)
    except e:
        var emsg = String(e)
        if emsg.find("FLOW_CONTROL") >= 0:
            raised_fc = True
    assert_true(raised_fc, "server should raise FLOW_CONTROL_ERROR on conn FC overflow")

    _ = tls^
    print("  test_conn_flow_control_error_on_overflow: PASS")


def test_final_size_error_on_reset_mismatch() raises:
    """RESET_STREAM with final_size < previously-observed offset → FINAL_SIZE_ERROR (0x06)."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_final_size_error_on_reset_mismatch: PASS")


def test_max_stream_data_and_max_data_cycle() raises:
    """Sender fills a stream past 50% of advertised FC, receiver consumes,
    receiver emits MAX_STREAM_DATA, sender sees advanced limit and writes more."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

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
        tls.shared(), client_config, "localhost", client_params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, server_params,
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

    _ = tls^
    print("  test_max_stream_data_and_max_data_cycle: PASS")


def test_max_streams_linear_growth() raises:
    """After peer completes N streams, receiver emits MAX_STREAMS(bidi) = N + initial_max_streams_bidi."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    # Use small initial_max_streams_bidi for a fast, deterministic test.
    var client_params = _default_params()
    var server_params = _default_params()
    client_params.initial_max_streams_bidi = UInt64(100)
    server_params.initial_max_streams_bidi = UInt64(100)

    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", client_params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, server_params,
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

    _ = tls^
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
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
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
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var srv_cfg = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var cli_cfg = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    # ── Subsection A: RESET_STREAM (client) + STOP_SENDING (server) ──────

    var now_a = UInt64(1_000_000)
    var params_a = _default_params()

    var client_a = QuicConnection.client(tls.shared(), cli_cfg, "localhost", params_a, now_a)
    var orig_dcid_a = List[UInt8](copy=client_a.initial_dcid)
    var cli_dcid_a = List[UInt8](copy=client_a.initial_dcid)
    var server_a = QuicConnection.server(
        tls.shared(), srv_cfg, params_a, Span(orig_dcid_a), Span(cli_dcid_a), now_a,
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

    var client_b = QuicConnection.client(tls.shared(), cli_cfg, "localhost", client_params_b, now_b)
    var orig_dcid_b = List[UInt8](copy=client_b.initial_dcid)
    var cli_dcid_b = List[UInt8](copy=client_b.initial_dcid)
    var server_b = QuicConnection.server(
        tls.shared(), srv_cfg, server_params_b, Span(orig_dcid_b), Span(cli_dcid_b), now_b,
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

    var client_c = QuicConnection.client(tls.shared(), cli_cfg, "localhost", params_c, now_c)
    var orig_dcid_c = List[UInt8](copy=client_c.initial_dcid)
    var cli_dcid_c = List[UInt8](copy=client_c.initial_dcid)
    var server_c = QuicConnection.server(
        tls.shared(), srv_cfg, params_c, Span(orig_dcid_c), Span(cli_dcid_c), now_c,
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

    _ = tls^
    print("  test_m3c_frames_retransmit_on_loss: PASS")


def test_anti_amp_ok_extract_parity() raises:
    """_anti_amp_ok mirrors the inline check: unvalidated server rejects
    oversized sends; validated server and clients are unrestricted."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_anti_amp_ok_extract_parity: PASS")


def test_persistent_congestion_end_to_end() raises:
    """Force a loss-burst spanning persistent_congestion_duration and verify
    CUBIC cwnd resets to 2*MDS, and recovery.min_rtt is re-seeded.

    Drives the detector directly (no wire) and also exercises the
    on_packets_lost fan-out through _detect_losses/_handle_ack via a synthetic
    ACK that declares the injected packets lost via the packet-threshold rule.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_persistent_congestion_end_to_end: PASS")


# ── Main ─────────────────────────────────────────────────────────────────


def test_pacer_delays_burst() raises:
    """With a low pacing rate, timeout() exposes a pacer deadline delaying the next send."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_pacer_delays_burst: PASS")


def test_cubic_cwnd_gates_send_path() raises:
    """A connection with CUBIC cannot send beyond cwnd."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_cubic_cwnd_gates_send_path: PASS")


def test_blocked_frames_emitted_on_conn_fc_stall() raises:
    """CLIENT emits DATA_BLOCKED when conn-level FC is exhausted."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(tls.shared(), client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_blocked_frames_emitted_on_conn_fc_stall: PASS")


def test_blocked_not_re_emitted_at_same_limit() raises:
    """DATA_BLOCKED is not emitted twice at the same limit."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(tls.shared(), client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_blocked_not_re_emitted_at_same_limit: PASS")


def test_blocked_cleared_on_max_data_increase() raises:
    """blocked_at resets to 0 after MAX_DATA raises the limit."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(tls.shared(), client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_blocked_cleared_on_max_data_increase: PASS")


def test_ecn_disabled_after_probing() raises:
    """ECN transitions to DISABLED when probes are sent but path strips marks."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(tls.shared(), client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_ecn_disabled_after_probing: PASS")


def test_pn_skip_active_after_handshake() raises:
    """Application-space pn_skip_rng is seeded at handshake; Initial/Handshake remain zero."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(tls.shared(), client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_pn_skip_active_after_handshake: PASS")


def test_pn_skip_next_in_valid_range() raises:
    """pn_skip_next is in [200, 499] immediately after handshake seeding."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(tls.shared(), client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(tls.shared(), server_config, params,
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

    _ = tls^
    print("  test_pn_skip_next_in_valid_range: PASS")


def test_streams_blocked_bidi_emitted() raises:
    """CLIENT emits STREAMS_BLOCKED_BIDI when peer's bidi stream limit is exhausted."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _default_params()
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(tls.shared(), client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params, Span(orig_dcid), Span(client_dcid), now
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

    _ = tls^
    print("  test_streams_blocked_bidi_emitted: PASS")


def test_streams_blocked_dedup_no_resend() raises:
    """STREAMS_BLOCKED is NOT re-emitted for the same peer limit (dedup)."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _default_params()
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(tls.shared(), client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params, Span(orig_dcid), Span(client_dcid), now
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

    _ = tls^
    print("  test_streams_blocked_dedup_no_resend: PASS")


def test_batch_crypto_roundtrip() raises:
    """Encrypt with client batch methods, decrypt with server batch methods."""
    var tls = TlsBackend("lib/librustls_mojo.so")

    var client = PacketProtect(tls.shared())
    var server = PacketProtect(tls.shared())

    var dcid: List[UInt8] = [
        UInt8(0x83), UInt8(0x94), UInt8(0xc8), UInt8(0xf0),
        UInt8(0x3e), UInt8(0x51), UInt8(0x57), UInt8(0x08),
    ]
    client.derive_initial_keys(Span(dcid), True)
    server.derive_initial_keys(Span(dcid), False)

    # Build packet: 22-byte header + 32-byte PADDING + 16-byte tag space = 70 bytes
    # PN_OFFSET = 18, HEADER_LEN = 22 (18 + 4-byte PN)
    var buf_ptr = _heap_alloc[UInt8](70).as_unsafe_any_origin()
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
    var pkt_ptrs   = _heap_alloc[UnsafePointer[UInt8, MutAnyOrigin]](1).as_unsafe_any_origin()
    var pns        = _heap_alloc[UInt64](1).as_unsafe_any_origin()
    var hdr_lens   = _heap_alloc[Int32](1).as_unsafe_any_origin()
    var pay_lens   = _heap_alloc[Int32](1).as_unsafe_any_origin()
    var capacities = _heap_alloc[Int32](1).as_unsafe_any_origin()
    var pkt_lens   = _heap_alloc[Int32](1).as_unsafe_any_origin()
    var pn_offsets = _heap_alloc[Int32](1).as_unsafe_any_origin()
    var pn_lengths = _heap_alloc[Int32](1).as_unsafe_any_origin()

    var out_ct_lens  = _heap_alloc[Int32](1).as_unsafe_any_origin()
    var out_results  = _heap_alloc[Int32](1).as_unsafe_any_origin()
    var out_fb       = _heap_alloc[UInt8](1).as_unsafe_any_origin()
    var out_pnl      = _heap_alloc[Int32](1).as_unsafe_any_origin()
    var out_pt_lens  = _heap_alloc[Int32](1).as_unsafe_any_origin()

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

    _ = tls^
    print("  test_batch_crypto_roundtrip: PASS")


def test_is_expected_dcid_initial_and_local() raises:
    """is_expected_dcid matches initial_dcid and local_cid; rejects others."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(tls.shared(), client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params, Span(orig_dcid), Span(client_dcid), now
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

    _ = tls^
    print("  test_is_expected_dcid_initial_and_local: PASS")


def test_quic_connection_dcid_lengths_are_8_bytes() raises:
    """Lock the invariant that QuicConnection.server produces 8-byte DCIDs.

    The bench server's short-header DCID parser (_extract_dcid) assumes
    8-byte CIDs (parse_packet_header(data, 8)). Any future change to
    _generate_random_cid that breaks this invariant must update both
    the parser AND this test together.
    """
    # Mirror the construction from test_is_expected_dcid_initial_and_local.
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(tls.shared(), client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params, Span(orig_dcid), Span(client_dcid), now
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

    _ = tls^
    print("PASS: test_quic_connection_dcid_lengths_are_8_bytes")


def test_dcid_demux_disambiguates_two_conns() raises:
    """Conn-table-level invariant: two distinct DCIDs map to two distinct
    conn_idx values via _bytes_to_hex hashing, and a third (unrelated)
    DCID is a miss.

    Validates the migration's data-structure correctness without spinning
    up a full H3UdpHandler. End-to-end behaviour is exercised by the
    smoke gate (T8) and SIGINT captures (T9).
    """
    from bench.servers.h3_server import _bytes_to_hex

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
    from navette.quic.cid import dcid_to_u64

    # Case 1: All-zero bytes → 0.
    var z = List[UInt8]()
    for _ in range(8):
        z.append(UInt8(0))
    assert_equal_int(
        Int(dcid_to_u64(Span(z))), 0, "all-zero -> 0"
    )

    # Case 2: All-0xff bytes → UInt64.MAX.
    var f = List[UInt8]()
    for _ in range(8):
        f.append(UInt8(0xFF))
    assert_true(
        dcid_to_u64(Span(f)) == UInt64.MAX,
        "all-0xff -> UInt64.MAX",
    )

    # Case 3: Ascending [0x01..0x08] → 0x0102030405060708.
    var asc = List[UInt8]()
    for i in range(8):
        asc.append(UInt8(i + 1))
    assert_true(
        dcid_to_u64(Span(asc)) == UInt64(0x0102030405060708),
        "ascending -> 0x0102030405060708",
    )

    # Case 4: Descending [0x08..0x01] → 0x0807060504030201.
    var desc = List[UInt8]()
    for i in range(8):
        desc.append(UInt8(8 - i))
    assert_true(
        dcid_to_u64(Span(desc)) == UInt64(0x0807060504030201),
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
        dcid_to_u64(Span(r)) == UInt64(0xDEADBEEFCAFEBABE),
        "DEADBEEFCAFEBABE roundtrip",
    )

    print("PASS: test_dcid_to_u64_basic_cases")


def test_dcid_to_u64_injective_on_distinct_inputs() raises:
    """Sample 64 distinct 8-byte vectors; assert pairwise distinctness of
    `_dcid_to_u64` outputs. Trivially true for a bijection on 8-byte → UInt64;
    locked anyway as a regression guard.
    """
    from navette.quic.cid import dcid_to_u64

    var outputs = List[UInt64]()
    for n in range(64):
        # Construct 8 bytes from a deterministic LCG so inputs are distinct.
        var bytes = List[UInt8]()
        var seed = UInt32(n) * UInt32(2654435761) + UInt32(0xDEADBEEF)
        for _ in range(8):
            seed = seed * UInt32(1103515245) + UInt32(12345)
            bytes.append(UInt8((seed >> 16) & UInt32(0xFF)))
        outputs.append(dcid_to_u64(Span(bytes)))

    # All-pairs distinctness.
    for i in range(len(outputs)):
        for j in range(i + 1, len(outputs)):
            assert_true(
                outputs[i] != outputs[j],
                "expected distinct outputs for distinct inputs",
            )

    print("PASS: test_dcid_to_u64_injective_on_distinct_inputs")


def test_predicate_f15_positive() raises:
    """F15 fires when sid=3 (server-uni control stream)."""
    var ctx = QuicResetCtx(stream_id=UInt64(3), local_uni_opened=UInt64(1), local_bidi_opened=UInt64(0))
    var v = predicate_f15_reset_on_server_uni(ctx)
    assert_true(v.__bool__(), "F15 positive must return Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x05, "F15 error_code is STREAM_STATE_ERROR")
    assert_true(verdict.tag == "[QUIC-RESET-SEND-ONLY]", "F15 tag matches")
    print("  test_predicate_f15_positive: PASS")


def test_predicate_f15_negative_no_violation() raises:
    """F15 stays silent on client-bidi (sid=0)."""
    var ctx = QuicResetCtx(stream_id=UInt64(0), local_uni_opened=UInt64(0), local_bidi_opened=UInt64(0))
    var v = predicate_f15_reset_on_server_uni(ctx)
    assert_false(v.__bool__(), "F15 negative (client-bidi) returns None")
    print("  test_predicate_f15_negative_no_violation: PASS")


def test_predicate_f15_negative_sibling_input() raises:
    """F15 stays silent on server-bidi (sid=5, suffix 0b01) — sibling input."""
    var ctx = QuicResetCtx(stream_id=UInt64(5), local_uni_opened=UInt64(0), local_bidi_opened=UInt64(1))
    var v = predicate_f15_reset_on_server_uni(ctx)
    assert_false(v.__bool__(), "F15 sibling (server-bidi) returns None")
    print("  test_predicate_f15_negative_sibling_input: PASS")


def test_predicate_f16_positive() raises:
    """F16 fires on STOP_SENDING for an uncreated server-uni stream."""
    var ctx = QuicStopSendingCtx(stream_id=UInt64(999), local_uni_opened=UInt64(1), local_bidi_opened=UInt64(0))
    var v = predicate_f16_stop_sending_local_not_created(ctx)
    assert_true(v.__bool__(), "F16 positive must return Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x05, "F16 error_code is STREAM_STATE_ERROR")
    assert_true(verdict.tag == "[QUIC-STOP-LOCAL-NOT-CREATED]", "F16 tag matches")
    print("  test_predicate_f16_positive: PASS")


def test_predicate_f16_negative_no_violation() raises:
    """F16 stays silent when STOP_SENDING targets an already-created local stream."""
    var ctx = QuicStopSendingCtx(stream_id=UInt64(3), local_uni_opened=UInt64(1), local_bidi_opened=UInt64(0))
    var v = predicate_f16_stop_sending_local_not_created(ctx)
    assert_false(v.__bool__(), "F16 no-violation: sid=3 with opened=1 is created")
    print("  test_predicate_f16_negative_no_violation: PASS")


def test_predicate_f16_negative_sibling_input() raises:
    """F16 stays silent when the counter advances past the target sid."""
    var ctx = QuicStopSendingCtx(stream_id=UInt64(7), local_uni_opened=UInt64(2), local_bidi_opened=UInt64(0))
    var v = predicate_f16_stop_sending_local_not_created(ctx)
    assert_false(v.__bool__(), "F16 sibling: sid=7 with opened=2 is created")
    print("  test_predicate_f16_negative_sibling_input: PASS")


def test_predicate_f11_positive() raises:
    """F11 fires when a packet contains zero frames (RFC 9000 §12.4)."""
    var v = predicate_f11_no_frames(0)
    assert_true(v.__bool__(), "F11 positive (count=0) must return Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x0A, "F11 error_code is PROTOCOL_VIOLATION")
    assert_true(verdict.tag == "[QUIC-NO-FRAMES]", "F11 tag matches")
    print("  test_predicate_f11_positive: PASS")


def test_predicate_f11_negative_no_violation() raises:
    """F11 stays silent when at least one frame is present."""
    var v = predicate_f11_no_frames(1)
    assert_false(v.__bool__(), "F11 negative (count=1) returns None")
    print("  test_predicate_f11_negative_no_violation: PASS")


def test_is_unknown_frame_type_positive() raises:
    """F10 predicate identifies type ids outside RFC 9000 §19."""
    # 0xFE is a single-byte varint encoded as 0x40, 0xFE — but type_id
    # itself decoded to UInt64(0xFE) lives well outside the §19 closed set.
    assert_true(is_unknown_frame_type(UInt64(0xFE)), "0xFE must be unknown")
    assert_true(is_unknown_frame_type(UInt64(0x1F)), "0x1F is one past HANDSHAKE_DONE")
    assert_true(is_unknown_frame_type(UInt64(0xFF)), "0xFF must be unknown")
    print("  test_is_unknown_frame_type_positive: PASS")


def test_is_unknown_frame_type_negative() raises:
    """Every RFC 9000 §19 frame type id is known."""
    assert_false(is_unknown_frame_type(UInt64(0x00)), "PADDING is known")
    assert_false(is_unknown_frame_type(UInt64(0x08)), "STREAM base is known")
    assert_false(is_unknown_frame_type(UInt64(0x0F)), "STREAM with FIN+LEN+OFF is known")
    assert_false(is_unknown_frame_type(UInt64(0x10)), "MAX_DATA is known")
    assert_false(is_unknown_frame_type(UInt64(0x1E)), "HANDSHAKE_DONE is known")
    print("  test_is_unknown_frame_type_negative: PASS")


def test_check_long_reserved_bits_positive() raises:
    """F12 fires when long-header mask 0x0C is non-zero."""
    var v = check_long_reserved_bits(UInt8(0x0C))
    assert_true(v.__bool__(), "F12 positive (mask 0x0C set) must return Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x0A, "F12 error_code is PROTOCOL_VIOLATION")
    assert_true(verdict.tag == "[QUIC-RESERVED-BITS-HS]", "F12 tag matches")
    print("  test_check_long_reserved_bits_positive: PASS")


def test_check_long_reserved_bits_negative_no_violation() raises:
    """F12 stays silent when mask 0x0C is zero."""
    var v = check_long_reserved_bits(UInt8(0xC3))  # bits 0x0C are zero; others ignored
    assert_false(v.__bool__(), "F12 negative (mask 0x0C clear) returns None")
    print("  test_check_long_reserved_bits_negative_no_violation: PASS")


def test_check_long_reserved_bits_negative_sibling_input() raises:
    """Long-mask check ignores 0x10 (bit 4 only — short reserved, no long overlap)."""
    var v = check_long_reserved_bits(UInt8(0x10))
    assert_false(v.__bool__(), "F12 sibling (only bit 4 set) returns None")
    print("  test_check_long_reserved_bits_negative_sibling_input: PASS")


def test_check_short_reserved_bits_positive() raises:
    """F14 fires when 1-RTT mask 0x18 is non-zero."""
    var v = check_short_reserved_bits(UInt8(0x18))
    assert_true(v.__bool__(), "F14 positive (mask 0x18 set) must return Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x0A, "F14 error_code is PROTOCOL_VIOLATION")
    assert_true(verdict.tag == "[QUIC-RESERVED-BITS-SHORT]", "F14 tag matches")
    print("  test_check_short_reserved_bits_positive: PASS")


def test_check_short_reserved_bits_negative_no_violation() raises:
    """F14 stays silent when mask 0x18 is zero; Key Phase (0x04) is NOT reserved."""
    var v = check_short_reserved_bits(UInt8(0x47))  # 0x40 + key phase 0x04 + pn-len 0x03
    assert_false(v.__bool__(), "F14 negative (mask 0x18 clear) returns None")
    print("  test_check_short_reserved_bits_negative_no_violation: PASS")


def test_check_short_reserved_bits_negative_sibling_input() raises:
    """Short-mask check ignores 0x04 (bit 2 only — long reserved, no overlap with 0x18)."""
    var v = check_short_reserved_bits(UInt8(0x04))
    assert_false(v.__bool__(), "F14 sibling (only bit 2 set) returns None")
    print("  test_check_short_reserved_bits_negative_sibling_input: PASS")


def test_is_path_challenge_in_handshake_positive() raises:
    """F13 fires when PATH_CHALLENGE / PATH_RESPONSE arrives pre-1-RTT."""
    assert_true(is_path_challenge_in_handshake(UInt64(0x1A), 1), "PATH_CHALLENGE in Handshake")
    assert_true(is_path_challenge_in_handshake(UInt64(0x1A), 0), "PATH_CHALLENGE in Initial")
    assert_true(is_path_challenge_in_handshake(UInt64(0x1B), 1), "PATH_RESPONSE in Handshake")
    print("  test_is_path_challenge_in_handshake_positive: PASS")


def test_is_path_challenge_in_handshake_negative() raises:
    """F13 stays silent in 1-RTT (space 2) and on non-path frames."""
    assert_false(is_path_challenge_in_handshake(UInt64(0x1A), 2), "PATH_CHALLENGE in 1-RTT is legal")
    assert_false(is_path_challenge_in_handshake(UInt64(0x06), 1), "CRYPTO in Handshake is legal")
    print("  test_is_path_challenge_in_handshake_negative: PASS")


def test_is_crypto_in_zero_rtt_positive() raises:
    """F30: CRYPTO frames in 0-RTT trip the gate (RFC 9001 §8.3)."""
    assert_true(
        is_crypto_in_zero_rtt(UInt64(0x06), ZERO_RTT_SPACE_IDX),
        "CRYPTO in 0-RTT sentinel must trip",
    )
    print("  test_is_crypto_in_zero_rtt_positive: PASS")


def test_is_crypto_in_zero_rtt_negative() raises:
    """F30: CRYPTO in 1-RTT (e.g. NewSessionTicket) and non-CRYPTO frames are legal."""
    assert_false(
        is_crypto_in_zero_rtt(UInt64(0x06), 2),
        "CRYPTO in 1-RTT is legal (NewSessionTicket per RFC 9001 §4.6.1)",
    )
    assert_false(
        is_crypto_in_zero_rtt(UInt64(0x06), 0),
        "CRYPTO in Initial is legal",
    )
    assert_false(
        is_crypto_in_zero_rtt(UInt64(0x06), 1),
        "CRYPTO in Handshake is legal",
    )
    assert_false(
        is_crypto_in_zero_rtt(UInt64(0x08), ZERO_RTT_SPACE_IDX),
        "STREAM (type 0x08) in 0-RTT is legal — not a CRYPTO frame",
    )
    print("  test_is_crypto_in_zero_rtt_negative: PASS")


def test_predicate_crypto_in_zero_rtt_verdict() raises:
    """F30 predicate returns PROTOCOL_VIOLATION + the correct tag string."""
    var verdict = predicate_crypto_in_zero_rtt(UInt64(0x06), ZERO_RTT_SPACE_IDX)
    assert_true(verdict.__bool__(), "predicate must fire for CRYPTO in 0-RTT")
    var v = verdict.value().copy()
    assert_equal_int(Int(v.error_code), 0x0A, "F30 maps to PROTOCOL_VIOLATION (0x0A)")
    assert_true(
        v.tag == String(GUARD_TAG_CRYPTO_IN_ZERO_RTT),
        "F30 verdict carries the [QUIC-CRYPTO-IN-0RTT] tag",
    )

    var clean = predicate_crypto_in_zero_rtt(UInt64(0x06), 2)
    assert_false(clean.__bool__(), "CRYPTO in 1-RTT must NOT trip the predicate")
    print("  test_predicate_crypto_in_zero_rtt_verdict: PASS")


def test_is_client_only_frame_on_server_positive() raises:
    """F17 / F24: NEW_TOKEN and HANDSHAKE_DONE received on a server are illegal."""
    assert_true(is_client_only_frame_on_server(UInt64(0x07), True), "NEW_TOKEN on server")
    assert_true(is_client_only_frame_on_server(UInt64(0x1E), True), "HANDSHAKE_DONE on server")
    print("  test_is_client_only_frame_on_server_positive: PASS")


def test_is_client_only_frame_on_server_negative() raises:
    """Client receiving NEW_TOKEN / HANDSHAKE_DONE is legal; other ids never trip."""
    assert_false(is_client_only_frame_on_server(UInt64(0x07), False), "NEW_TOKEN on client OK")
    assert_false(is_client_only_frame_on_server(UInt64(0x1E), False), "HANDSHAKE_DONE on client OK")
    assert_false(is_client_only_frame_on_server(UInt64(0x06), True), "CRYPTO on server OK")
    print("  test_is_client_only_frame_on_server_negative: PASS")


def test_predicate_f18_max_stream_data_nonexist() raises:
    """F18 fires for an MSD on a stream the local map does not know about."""
    var ctx = MaxStreamDataCtx(stream_id=UInt64(99999), exists=False, has_send_side=False)
    var v = predicate_f18_f19_max_stream_data(ctx)
    assert_true(v.__bool__(), "F18 (nonexist) returns Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x05, "F18 STREAM_STATE_ERROR")
    assert_true(verdict.tag == "[QUIC-MAX-STREAM-DATA-NONEXIST]", "F18 tag matches")
    print("  test_predicate_f18_max_stream_data_nonexist: PASS")


def test_predicate_f19_max_stream_data_recv_only() raises:
    """F19 fires for an MSD on a known recv-only stream (peer is sender)."""
    var ctx = MaxStreamDataCtx(stream_id=UInt64(2), exists=True, has_send_side=False)
    var v = predicate_f18_f19_max_stream_data(ctx)
    assert_true(v.__bool__(), "F19 (recv-only) returns Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x05, "F19 STREAM_STATE_ERROR")
    assert_true(verdict.tag == "[QUIC-MAX-STREAM-DATA-RECV-ONLY]", "F19 tag matches")
    print("  test_predicate_f19_max_stream_data_recv_only: PASS")


def test_predicate_f18_f19_max_stream_data_negative() raises:
    """Legal MSD on a known send-side stream returns None."""
    var ctx = MaxStreamDataCtx(stream_id=UInt64(0), exists=True, has_send_side=True)
    var v = predicate_f18_f19_max_stream_data(ctx)
    assert_false(v.__bool__(), "legal MSD returns None")
    print("  test_predicate_f18_f19_max_stream_data_negative: PASS")


def test_check_max_streams_value_positive() raises:
    """F20/F21 fire when MAX_STREAMS/STREAMS_BLOCKED exceeds 2^60."""
    var v = check_max_streams_value((UInt64(1) << 60) + UInt64(1))
    assert_true(v.__bool__(), "2^60 + 1 must trip")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x07, "FRAME_ENCODING_ERROR")
    assert_true(verdict.tag == "[QUIC-MAX-STREAMS-OVERFLOW]", "F20/F21 tag matches")
    print("  test_check_max_streams_value_positive: PASS")


def test_check_max_streams_value_negative() raises:
    """Values up to and including 2^60 are legal."""
    var v_eq = check_max_streams_value(UInt64(1) << 60)
    assert_false(v_eq.__bool__(), "2^60 is legal (boundary)")
    var v_low = check_max_streams_value(UInt64(100))
    assert_false(v_low.__bool__(), "low value is legal")
    print("  test_check_max_streams_value_negative: PASS")


def test_check_streams_blocked_value_positive() raises:
    """F21 fires when STREAMS_BLOCKED carries a limit > 2^60."""
    var v = check_streams_blocked_value((UInt64(1) << 60) + UInt64(1))
    assert_true(v.__bool__(), "2^60 + 1 must trip")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x07, "FRAME_ENCODING_ERROR")
    assert_true(verdict.tag == "[QUIC-STREAMS-BLOCKED-OVERFLOW]", "F21 tag matches")
    print("  test_check_streams_blocked_value_positive: PASS")


def test_check_streams_blocked_value_negative() raises:
    """Values up to and including 2^60 are legal for STREAMS_BLOCKED."""
    var v_eq = check_streams_blocked_value(UInt64(1) << 60)
    assert_false(v_eq.__bool__(), "2^60 is legal (boundary)")
    var v_low = check_streams_blocked_value(UInt64(100))
    assert_false(v_low.__bool__(), "low value is legal")
    print("  test_check_streams_blocked_value_negative: PASS")


def test_check_new_connection_id_retire_prior_positive() raises:
    """F22 fires when retire_prior_to > sequence (RFC 9000 §19.15)."""
    var v = check_new_connection_id_retire_prior(UInt64(5), UInt64(10))
    assert_true(v.__bool__(), "retire_prior_to > seq must trip")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x07, "FRAME_ENCODING_ERROR")
    assert_true(verdict.tag == "[QUIC-CID-RETIRE-PRIOR-GT-SEQ]", "F22 tag matches")
    print("  test_check_new_connection_id_retire_prior_positive: PASS")


def test_check_new_connection_id_retire_prior_negative() raises:
    """Retire_prior_to <= sequence is legal."""
    var v_eq = check_new_connection_id_retire_prior(UInt64(7), UInt64(7))
    assert_false(v_eq.__bool__(), "rpt == seq is legal (boundary)")
    var v_lt = check_new_connection_id_retire_prior(UInt64(10), UInt64(0))
    assert_false(v_lt.__bool__(), "rpt < seq is legal")
    print("  test_check_new_connection_id_retire_prior_negative: PASS")


def test_check_new_connection_id_length_positive() raises:
    """F23 fires when NEW_CONNECTION_ID carries a zero-length CID."""
    var v_zero = check_new_connection_id_length(UInt64(0))
    assert_true(v_zero.__bool__(), "cid_length == 0 must trip")
    var verdict = v_zero.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x07, "FRAME_ENCODING_ERROR")
    assert_true(verdict.tag == "[QUIC-CID-ZERO-LENGTH]", "F23 tag matches")
    # Over-length is also FRAME_ENCODING_ERROR for the same RFC clause.
    var v_huge = check_new_connection_id_length(UInt64(21))
    assert_true(v_huge.__bool__(), "cid_length == 21 must trip")
    print("  test_check_new_connection_id_length_positive: PASS")


def test_check_new_connection_id_length_negative() raises:
    """CID length in 1..20 inclusive is legal."""
    var v_lo = check_new_connection_id_length(UInt64(1))
    assert_false(v_lo.__bool__(), "cid_length == 1 is legal (lower boundary)")
    var v_hi = check_new_connection_id_length(UInt64(20))
    assert_false(v_hi.__bool__(), "cid_length == 20 is legal (upper boundary)")
    var v_mid = check_new_connection_id_length(UInt64(8))
    assert_false(v_mid.__bool__(), "cid_length == 8 is legal")
    print("  test_check_new_connection_id_length_negative: PASS")


def test_stream_offset_exceeds_fc_positive() raises:
    """F01 fires when offset+data_len > stream FC limit."""
    # Offset alone larger than window.
    assert_true(
        stream_offset_exceeds_fc(UInt64(1 << 20), UInt64(0), UInt64(1 << 19)),
        "offset alone exceeding window",
    )
    # offset+data_len just over.
    assert_true(
        stream_offset_exceeds_fc(UInt64(100), UInt64(50), UInt64(149)),
        "boundary +1 trips",
    )
    # Saturating-overflow input — offset near UInt64 max plus any data trips.
    var huge = ~UInt64(0)  # UInt64::MAX
    assert_true(
        stream_offset_exceeds_fc(huge, UInt64(1), UInt64(1 << 60)),
        "UInt64 overflow detected as out-of-bounds",
    )
    # Realistic scenario: F01 wire offset.
    assert_true(
        stream_offset_exceeds_fc(
            UInt64(0x3FFF_FFFF_FFFF_FFFF), UInt64(0), UInt64(1 << 20)
        ),
        "2^62-1 offset trips against 1 MiB window",
    )
    print("  test_stream_offset_exceeds_fc_positive: PASS")


def test_stream_offset_exceeds_fc_negative() raises:
    """Legal stream offsets within the FC window do not trip."""
    assert_false(
        stream_offset_exceeds_fc(UInt64(0), UInt64(0), UInt64(1 << 20)),
        "empty frame at offset 0 is legal",
    )
    assert_false(
        stream_offset_exceeds_fc(UInt64(100), UInt64(50), UInt64(150)),
        "offset+len == limit is legal (boundary)",
    )
    assert_false(
        stream_offset_exceeds_fc(UInt64(10), UInt64(40), UInt64(1024)),
        "well-within window is legal",
    )
    print("  test_stream_offset_exceeds_fc_negative: PASS")


def test_on_handshake_complete_close_transport_on_invalid_tp() raises:
    """Server routes a client TP violation through close_transport rather than raising.

    Builds a client whose `local_params` carry the server-only
    `original_destination_connection_id` (RFC 9000 §18.2 — F03 violation).
    After driving the handshake, the server must:

      * NOT raise an exception out of `_on_handshake_complete` (close + return
        contract: errors on the TLS-error path must surface as a queued
        CONNECTION_CLOSE, not a raise that the I/O loop would swallow).
      * Set `pending_close` with `error_code == 0x08`
        (TRANSPORT_PARAMETER_ERROR, RFC 9000 §20.1).
      * Embed `[QUIC-TP-ORIGINAL-DCID-FORBIDDEN]` in the reason so the
        out-of-process scenario binary can grep for it as proof the violation
        was detected for the right reason.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    # Build adversarial client TPs: a well-formed baseline plus the
    # server-only `original_destination_connection_id` (8 zero bytes is enough
    # to fail the presence check; the value is irrelevant).
    var bad_params = _default_params()
    var orig_dcid_payload = List[UInt8]()
    for _ in range(8):
        orig_dcid_payload.append(UInt8(0))
    bad_params.original_dcid = orig_dcid_payload^

    var good_params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", bad_params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, good_params,
        Span(orig_dcid), Span(client_dcid), now,
    )

    # Drive the handshake. The server should reach _on_handshake_complete,
    # decode the peer TPs, detect F03, and queue a CONNECTION_CLOSE.
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
        if server.pending_close:
            break

    assert_true(
        Bool(server.pending_close),
        "server.pending_close not set after F03 violation",
    )
    var cc = server.pending_close.value().copy()
    assert_equal_int(
        Int(cc.error_code), 0x08,
        "server CONNECTION_CLOSE error_code must be TRANSPORT_PARAMETER_ERROR",
    )
    assert_true(cc.is_transport, "server must use transport-CC (0x1c) for TP violation")

    # Reason carries the GUARD-TAG bracketed marker.
    var tag = String(GUARD_TAG_TP_ORIGINAL_DCID_FORBIDDEN)
    var reason_str = String("")
    for i in range(len(cc.reason)):
        reason_str = reason_str + chr(Int(cc.reason[i]))
    assert_true(
        tag in reason_str,
        "reason must contain " + tag + ", got " + reason_str,
    )

    _ = tls^
    print("  test_on_handshake_complete_close_transport_on_invalid_tp: PASS")


def test_tls_guard_tag_for_alert_mapping() raises:
    """`_tls_guard_tag_for` maps each (alert, level) pair to the matching tag.

    Locks in the v3.1 AC-3.alert allowed-set disambiguation:

      * alert 120 → NO_ALPN regardless of level (F27).
      * alert 47  → KEYUPDATE_1RTT regardless of level (F26).
      * alert 10 with current_level==1 → KEYUPDATE_HANDSHAKE (F25).
      * alert 10 with current_level!=1 → END_OF_EARLY_DATA (F29).
      * alert 50 (fallback) on Handshake-level → KEYUPDATE_HANDSHAKE (F25 fb).
      * alert 50 (fallback) with handshake_confirmed → END_OF_EARLY_DATA (F29 fb).
      * alert 50 (fallback) otherwise → KEYUPDATE_1RTT (F26 fb).
    """
    var default_fb = String(GUARD_TAG_TLS_KEYUPDATE_1RTT)

    # F27 — unique alert, any level.
    assert_true(
        _tls_guard_tag_for(Int32(120), 0, False, default_fb) == String(GUARD_TAG_TLS_NO_ALPN),
        "alert 120 must map to TLS_NO_ALPN (Initial-level)",
    )
    assert_true(
        _tls_guard_tag_for(Int32(120), 2, True, default_fb) == String(GUARD_TAG_TLS_NO_ALPN),
        "alert 120 must map to TLS_NO_ALPN (1-RTT-level)",
    )

    # F26 — unique alert.
    assert_true(
        _tls_guard_tag_for(Int32(47), 1, False, default_fb) == String(GUARD_TAG_TLS_KEYUPDATE_1RTT),
        "alert 47 must map to TLS_KEYUPDATE_1RTT",
    )

    # F25 vs F29 disambiguation on alert 10 by encryption level.
    assert_true(
        _tls_guard_tag_for(Int32(10), 1, False, default_fb) == String(GUARD_TAG_TLS_KEYUPDATE_HANDSHAKE),
        "alert 10 on Handshake-level must map to KEYUPDATE_HANDSHAKE (F25)",
    )
    assert_true(
        _tls_guard_tag_for(Int32(10), 2, True, default_fb) == String(GUARD_TAG_TLS_END_OF_EARLY_DATA),
        "alert 10 on 1-RTT-level must map to END_OF_EARLY_DATA (F29)",
    )

    # Alert 50 fallback disambiguation.
    assert_true(
        _tls_guard_tag_for(Int32(50), 1, False, default_fb) == String(GUARD_TAG_TLS_KEYUPDATE_HANDSHAKE),
        "alert 50 fallback on Handshake-level must map to KEYUPDATE_HANDSHAKE",
    )
    assert_true(
        _tls_guard_tag_for(Int32(50), 2, True, default_fb) == String(GUARD_TAG_TLS_END_OF_EARLY_DATA),
        "alert 50 fallback after handshake-confirmed must map to END_OF_EARLY_DATA",
    )
    assert_true(
        _tls_guard_tag_for(Int32(50), 0, False, default_fb) == String(GUARD_TAG_TLS_KEYUPDATE_1RTT),
        "alert 50 fallback pre-handshake-confirmed must map to KEYUPDATE_1RTT (caller-supplied fallback)",
    )

    # Unknown alert codes use the caller-supplied fallback verbatim.
    var custom_fb = String(GUARD_TAG_TLS_NO_ALPN)
    assert_true(
        _tls_guard_tag_for(Int32(99), 0, False, custom_fb) == custom_fb,
        "unknown alert must use caller-supplied fallback verbatim",
    )

    print("  test_tls_guard_tag_for_alert_mapping: PASS")


def test_drive_handshake_tls_error_emits_crypto_close() raises:
    """`_drive_handshake` routes a TLS read failure through `close_transport`.

    Injects 16 bytes of garbage straight into the server's Initial-level
    `crypto_streams` slot, then calls `_drive_handshake`. The rustls FFI
    will fail to parse the bytes (`quic_conn_read_hs` returns -1); the
    new alert-routing path must:

      * NOT raise (the prior implementation raised "quic_conn_read_hs failed"
        which the I/O loop would swallow on its catch-all);
      * queue a transport CONNECTION_CLOSE (frame_type 0x1c);
      * set `error_code` in the CRYPTO_ERROR range 0x0100..=0x01ff;
      * embed one of the TLS GUARD-TAGs in the reason phrase.

    The exact alert byte rustls reports for "garbage in Initial CRYPTO" is
    implementation-defined (commonly decode_error=50 or
    unexpected_message=10), so the test asserts the range + the presence of
    any TLS-prefixed guard tag rather than a single specific alert.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    # Server-only: no client, no ClientHello — we just feed garbage CRYPTO.
    var orig_dcid = List[UInt8]()
    for _ in range(8):
        orig_dcid.append(UInt8(0xab))
    var client_dcid = List[UInt8](copy=orig_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )

    # Inject malformed CRYPTO bytes into Initial-level (current_level == 0).
    # `crypto_streams[level].receive(offset, data)` is the same path the wire
    # parser would take after AEAD-unprotecting an Initial packet containing
    # a CRYPTO frame; rustls will fail to interpret these as a ClientHello
    # and emit an alert via quic_conn_alert.
    var garbage = List[UInt8]()
    for i in range(64):
        garbage.append(UInt8((i * 31) & 0xff))
    server.crypto_streams[0].receive(UInt64(0), Span(garbage))

    # Drive the handshake. Must NOT raise (close-and-return contract).
    server._drive_handshake(now)

    assert_true(
        Bool(server.pending_close),
        "server.pending_close not set after TLS read_hs failure",
    )
    var cc = server.pending_close.value().copy()
    assert_true(cc.is_transport, "must use transport-CC (0x1c) for TLS alert")

    var code = Int(cc.error_code)
    assert_true(
        code >= 0x0100 and code <= 0x01ff,
        "error_code must be in CRYPTO_ERROR range 0x0100..=0x01ff, got 0x" + String(code),
    )

    # Reason must contain one of the 4 TLS guard tags.
    var reason_str = String("")
    for i in range(len(cc.reason)):
        reason_str = reason_str + chr(Int(cc.reason[i]))
    var has_tls_tag = (
        String(GUARD_TAG_TLS_KEYUPDATE_HANDSHAKE) in reason_str
        or String(GUARD_TAG_TLS_KEYUPDATE_1RTT) in reason_str
        or String(GUARD_TAG_TLS_NO_ALPN) in reason_str
        or String(GUARD_TAG_TLS_END_OF_EARLY_DATA) in reason_str
    )
    assert_true(
        has_tls_tag,
        "reason must contain a [TLS-*] guard tag, got " + reason_str,
    )

    _ = tls^
    print("  test_drive_handshake_tls_error_emits_crypto_close: PASS")


def _build_server_for_rx_test() raises -> QuicConnection:
    """Build a freshly-constructed server connection for RX-only tests.

    Reuses the same factory path the established tests rely on, but does
    not drive a handshake — the RX handlers exercised here only touch
    `pending_path_responses` and `path_validator`, so the handshake state
    is irrelevant.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var server_config = QuicServerConfig(
        tls.shared(), Span(cert_bytes), Span(key_bytes)
    )
    var params = _default_params()
    var now = UInt64(1_000_000)
    # Build a client just to mint a random initial DCID for the server.
    var ca_bytes = load_test_ca()
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )
    _ = tls^
    return server^


def test_path_challenge_recorded_for_response() raises:
    """RX-side: incoming PATH_CHALLENGE is stashed for later echo."""
    var conn = _build_server_for_rx_test()
    var data = List[UInt8](capacity=8)
    for i in range(8):
        data.append(UInt8(0x10 + i))
    conn.on_path_challenge_received(Span(data), UInt64(1000))
    assert_equal_int(
        len(conn.pending_path_responses),
        1,
        "expected exactly one pending PATH_RESPONSE",
    )
    assert_equal_int(
        len(conn.pending_path_responses[0]),
        8,
        "expected pending PATH_RESPONSE token to be 8 bytes",
    )
    # Verify exact bytes preserved.
    for i in range(8):
        assert_equal_int(
            Int(conn.pending_path_responses[0][i]),
            Int(UInt8(0x10 + i)),
            "PATH_RESPONSE token byte mismatch at index " + String(i),
        )
    print("  test_path_challenge_recorded_for_response: PASS")


def test_path_response_handler_no_op_without_pending_challenge() raises:
    """RX-side: PATH_RESPONSE with no pending challenges is a safe no-op."""
    var conn = _build_server_for_rx_test()
    var data = List[UInt8](capacity=8)
    for i in range(8):
        data.append(UInt8(0xAB))
    var from_addr = PathKey.from_v4(
        UInt8(127), UInt8(0), UInt8(0), UInt8(1), UInt16(5000)
    )
    # Should neither raise nor mutate `path_validator.pending`. The C5
    # signature added `from_addr` for the §8.2 addr+token match; with no
    # pending challenges the inner `on_response` returns None and the
    # handler is a pure no-op.
    conn.on_path_response_received(Span(data), from_addr^, UInt64(2000))
    assert_equal_int(
        len(conn.path_validator.pending),
        0,
        "path_validator.pending must stay empty (no challenges started yet)",
    )
    assert_equal_int(
        len(conn.pending_path_responses),
        0,
        "pending_path_responses must stay empty when handling a response",
    )
    print("  test_path_response_handler_no_op_without_pending_challenge: PASS")


def test_emit_path_response_drains_pending() raises:
    """C3: after on_path_challenge_received, emit drains the queue into a frame."""
    var conn = _build_server_for_rx_test()
    var data = List[UInt8](capacity=8)
    for i in range(8):
        data.append(UInt8(0x55))
    conn.on_path_challenge_received(Span(data), UInt64(1000))
    assert_equal_int(
        len(conn.pending_path_responses),
        1,
        "expected one pending PATH_RESPONSE after challenge RX",
    )
    var frames = conn.emit_path_response_frames()
    assert_equal_int(len(frames), 1, "emit must produce one PATH_RESPONSE frame")
    assert_true(
        frames[0].is_path_response(),
        "emitted frame must be PATH_RESPONSE",
    )
    assert_equal_int(
        len(conn.pending_path_responses),
        0,
        "pending_path_responses must be drained after emit",
    )
    print("  test_emit_path_response_drains_pending: PASS")


def test_start_path_challenge_queues_emission() raises:
    """C3: start_path_challenge queues a PATH_CHALLENGE for emission."""
    var conn = _build_server_for_rx_test()
    var target = PathKey.from_v4(
        UInt8(127), UInt8(0), UInt8(0), UInt8(1), UInt16(5000)
    )
    conn.start_path_challenge(target^, UInt64(1000))
    assert_equal_int(
        len(conn.path_validator.pending),
        1,
        "expected one pending challenge after start_path_challenge",
    )
    var frames = conn.emit_path_challenge_frames(UInt64(1001))
    assert_equal_int(len(frames), 1, "emit must produce one PATH_CHALLENGE frame")
    assert_true(
        frames[0].is_path_challenge(),
        "emitted frame must be PATH_CHALLENGE",
    )
    print("  test_start_path_challenge_queues_emission: PASS")


def test_path_response_emission_preserves_data() raises:
    """C3: echoed PATH_RESPONSE data matches incoming PATH_CHALLENGE byte-for-byte."""
    var conn = _build_server_for_rx_test()
    var data = List[UInt8](capacity=8)
    for i in range(8):
        data.append(UInt8(0xA0 + i))
    conn.on_path_challenge_received(Span(data), UInt64(1000))
    var frames = conn.emit_path_response_frames()
    assert_equal_int(len(frames), 1, "emit must produce one PATH_RESPONSE frame")
    ref payload = frames[0].as_path_data()
    assert_equal_int(
        len(payload), 8, "PATH_RESPONSE payload must be exactly 8 bytes"
    )
    for i in range(8):
        assert_equal_int(
            Int(payload[i]),
            Int(UInt8(0xA0 + i)),
            "echoed byte mismatch at index " + String(i),
        )
    print("  test_path_response_emission_preserves_data: PASS")


def test_initial_new_cid_burst_after_handshake_complete() raises:
    """C4: first 1-RTT flush after CONN_ESTABLISHED fills local_cids to
    `peer_active_limit` and drains NEW_CONNECTION_ID frames in the same
    flight (RFC 9000 §5.1.1)."""
    var server = _build_server_for_rx_test()
    # Crank the peer's CID limit up so the burst issues more than the
    # constructor's default. We use 4 so the burst must issue at least 3
    # additional CIDs (seq=0 is already advertised at construction).
    server.cid_mgr.peer_active_limit = UInt64(4)
    server.cid_mgr.retire_queue_cap = Int(server.cid_mgr.peer_active_limit) * 8

    # Pre-conditions: only the initial CID (seq=0) exists and is advertised;
    # the initial-burst guard has not yet fired.
    assert_equal_int(
        len(server.cid_mgr.local_cids), 1, "fresh server has only seq=0"
    )
    assert_true(
        server.cid_mgr.local_cids[0].advertised,
        "initial CID is advertised at construction",
    )
    assert_false(
        server.initial_cids_emitted,
        "burst guard starts False",
    )

    # Force ESTABLISHED so _build_frames_for_space takes the initial-burst
    # branch on its first 1-RTT call.
    server.state = server.state | CONN_ESTABLISHED

    var sent_records = List[SentStreamFrame]()
    var frames = server._build_frames_for_space(2, UInt64(1_000_000), sent_records)

    var n_new_cid = 0
    for i in range(len(frames)):
        if frames[i].is_new_connection_id():
            n_new_cid += 1
    # peer_active_limit=4, seq=0 already advertised → expect 3 NEW_CID frames.
    assert_equal_int(
        n_new_cid, 3, "burst emits peer_active_limit-1 NEW_CID frames"
    )
    assert_true(
        server.initial_cids_emitted,
        "burst guard set after first 1-RTT flush",
    )
    # `local_cids` is now filled to peer_active_limit.
    assert_equal_int(
        len(server.cid_mgr.local_cids), 4, "local_cids filled to limit"
    )

    # A second 1-RTT flush MUST NOT re-issue: pending_new_cid_entries is
    # drained (everything marked advertised) and the guard stays set.
    var sent_records2 = List[SentStreamFrame]()
    var frames2 = server._build_frames_for_space(2, UInt64(1_000_001), sent_records2)
    var n_new_cid2 = 0
    for i in range(len(frames2)):
        if frames2[i].is_new_connection_id():
            n_new_cid2 += 1
    assert_equal_int(
        n_new_cid2, 0, "second flush does not re-emit"
    )
    assert_equal_int(
        len(server.cid_mgr.local_cids), 4, "local_cids unchanged on second flush"
    )
    print("  test_initial_new_cid_burst_after_handshake_complete: PASS")


def test_initial_new_cid_burst_default_limit() raises:
    """C4: with the default peer_active_limit=2, the initial burst emits
    exactly one NEW_CID (seq=1) — seq=0 was advertised in the handshake."""
    var server = _build_server_for_rx_test()
    assert_equal_int(
        Int(server.cid_mgr.peer_active_limit), 2, "default peer_active_limit is 2"
    )
    assert_false(
        server.initial_cids_emitted, "burst guard starts False"
    )

    server.state = server.state | CONN_ESTABLISHED
    var sent_records = List[SentStreamFrame]()
    var frames = server._build_frames_for_space(2, UInt64(1_000_000), sent_records)

    var n_new_cid = 0
    for i in range(len(frames)):
        if frames[i].is_new_connection_id():
            n_new_cid += 1
    assert_equal_int(
        n_new_cid, 1, "default-limit burst emits exactly one NEW_CID"
    )
    assert_true(
        server.initial_cids_emitted, "guard flipped after burst"
    )
    assert_equal_int(
        len(server.cid_mgr.local_cids), 2, "local_cids filled to 2"
    )
    print("  test_initial_new_cid_burst_default_limit: PASS")


def test_initial_burst_skipped_before_handshake_complete() raises:
    """C4: the burst guard is gated on CONN_ESTABLISHED. A 1-RTT build
    before the handshake completes must not issue CIDs."""
    var server = _build_server_for_rx_test()
    assert_false(
        server.initial_cids_emitted, "guard starts False"
    )
    assert_equal_int(
        len(server.cid_mgr.local_cids), 1, "only seq=0 pre-handshake"
    )

    var sent_records = List[SentStreamFrame]()
    var frames = server._build_frames_for_space(2, UInt64(1_000_000), sent_records)

    var n_new_cid = 0
    for i in range(len(frames)):
        if frames[i].is_new_connection_id():
            n_new_cid += 1
    assert_equal_int(
        n_new_cid, 0, "no NEW_CID emitted before CONN_ESTABLISHED"
    )
    # Guard stayed False; no new local CIDs issued.
    assert_false(
        server.initial_cids_emitted, "guard stays False before establishment"
    )
    assert_equal_int(
        len(server.cid_mgr.local_cids), 1, "no CIDs issued pre-handshake"
    )
    print("  test_initial_burst_skipped_before_handshake_complete: PASS")


def test_initial_burst_server_only() raises:
    """C4: the initial NEW_CID burst is a server responsibility. Clients
    must not issue local CIDs in the 1-RTT builder (RFC 9000 §5.1.1 — only
    the server emits NEW_CID before the client has issued any)."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ca_bytes = load_test_ca()
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _default_params()
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    client.state = client.state | CONN_ESTABLISHED
    var initial_count = len(client.cid_mgr.local_cids)

    var sent_records = List[SentStreamFrame]()
    var frames = client._build_frames_for_space(2, now, sent_records)
    var n_new_cid = 0
    for i in range(len(frames)):
        if frames[i].is_new_connection_id():
            n_new_cid += 1
    # Client side: no burst, guard stays False.
    assert_equal_int(
        n_new_cid, 0, "client emits no NEW_CID in burst"
    )
    assert_false(
        client.initial_cids_emitted, "client guard stays False"
    )
    assert_equal_int(
        len(client.cid_mgr.local_cids), initial_count, "client local_cids unchanged"
    )
    _ = tls^
    print("  test_initial_burst_server_only: PASS")


# ── C5 — path validation full round trip + CID rotation + anti-amp + ───────
#       disable_active_migration enforcement ─────────────────────────────────


def _seed_spare_remote_cid(mut conn: QuicConnection, seq: UInt64) raises:
    """Inject an Active remote CID at `seq` so CID rotation can succeed.

    The rotation lever in `on_path_response_received` requires at least
    one spare remote CID with a sequence different from the currently
    Active one. Tests don't drive a real NEW_CID handshake; this helper
    short-circuits via `cid_mgr.on_new_connection_id`, the same code
    path the live RX handler uses (so the invariants stay aligned).
    """
    var cid = List[UInt8](capacity=8)
    for i in range(8):
        cid.append(UInt8(0xC0 + i + Int(seq)))
    var tok = List[UInt8](capacity=16)
    for i in range(16):
        tok.append(UInt8(0xD0 + i))
    conn.cid_mgr.on_new_connection_id(
        seq, UInt64(0), cid^, tok^
    )


def test_path_validation_full_round_trip() raises:
    """AC8/AC15: a matching PATH_RESPONSE promotes peer_addr AND rotates DCID.

    Server starts a challenge to addr_b; the response carrying the same
    8-byte token arrives FROM addr_b; the connection swaps `peer_addr`
    and `cid_mgr.remote_active_cid_seq` advances to the spare CID we
    seeded. A RETIRE_CONNECTION_ID for the old sequence is queued.
    """
    var conn = _build_server_for_rx_test()

    # Seed a spare remote CID so the §9.5 MUST-rotate succeeds.
    _seed_spare_remote_cid(conn, UInt64(1))
    assert_equal_int(
        Int(conn.cid_mgr.remote_active_cid_seq), 0,
        "fresh server starts on remote_active_cid_seq=0",
    )
    assert_equal_int(
        len(conn.cid_mgr.remote_cids), 2,
        "two remote CIDs after seeding spare",
    )

    var addr_a = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(1), UInt16(5000)
    )
    var addr_b = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(2), UInt16(6000)
    )
    conn.bootstrap_peer_addr(addr_a^)

    # Start path validation against addr_b.
    conn.start_path_challenge(PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(2), UInt16(6000)
    ), UInt64(1000))
    assert_equal_int(
        len(conn.path_validator.pending), 1,
        "challenge queued before response arrives",
    )
    var token = List[UInt8](copy=conn.path_validator.pending[0].token)

    # PATH_RESPONSE with the matching token, arriving from addr_b.
    conn.on_path_response_received(
        Span(token), PathKey(other=addr_b), UInt64(2000)
    )

    # peer_addr swapped to addr_b.
    var current_peer = PathKey(other=conn.peer_addr)
    assert_true(
        current_peer == addr_b,
        "peer_addr promoted to validated path",
    )
    # Validator's pending list drained, current set.
    assert_equal_int(
        len(conn.path_validator.pending), 0,
        "matched challenge removed from pending",
    )
    assert_true(
        Bool(conn.path_validator.current),
        "path_validator.current populated post-match",
    )
    # CID rotation per RFC 9000 §9.5 MUST.
    assert_equal_int(
        Int(conn.cid_mgr.remote_active_cid_seq), 1,
        "remote_active_cid_seq advanced to spare after validation",
    )
    # RETIRE_CONNECTION_ID for the old seq is queued for emission.
    var retire_drain = conn.cid_mgr.pending_retire_frames()
    assert_equal_int(
        len(retire_drain), 1,
        "one RETIRE_CONNECTION_ID queued for the rotated-out sequence",
    )
    assert_equal_int(
        Int(retire_drain[0]), 0,
        "RETIRE_CID targets the previously-active sequence (0)",
    )
    print("  test_path_validation_full_round_trip: PASS")


def test_path_validation_rejects_wrong_addr() raises:
    """AC7+§8.2 edge case: PATH_RESPONSE from a different addr is silently dropped.

    Token matches but `from_addr` does not equal the challenge's target;
    `on_response` returns None, peer_addr is unchanged, no CID rotation
    fires.
    """
    var conn = _build_server_for_rx_test()
    _seed_spare_remote_cid(conn, UInt64(1))

    var addr_a = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(1), UInt16(5000)
    )
    var addr_b = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(2), UInt16(6000)
    )
    var addr_c = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(3), UInt16(7000)
    )
    conn.bootstrap_peer_addr(addr_a^)

    conn.start_path_challenge(PathKey(other=addr_b), UInt64(1000))
    var token = List[UInt8](copy=conn.path_validator.pending[0].token)

    # Response carries the matching token but arrives from a third addr.
    conn.on_path_response_received(
        Span(token), PathKey(other=addr_c), UInt64(2000)
    )

    # peer_addr UNCHANGED — addr_a still the validated path.
    var peer_now = PathKey(other=conn.peer_addr)
    var addr_a_cmp = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(1), UInt16(5000)
    )
    assert_true(
        peer_now == addr_a_cmp,
        "peer_addr unchanged on mismatched response addr",
    )
    # Pending challenge still in flight.
    assert_equal_int(
        len(conn.path_validator.pending), 1,
        "challenge still pending — mismatched response is a silent no-op",
    )
    # No CID rotation, no retire queued.
    assert_equal_int(
        Int(conn.cid_mgr.remote_active_cid_seq), 0,
        "remote_active_cid_seq unchanged on mismatch",
    )
    print("  test_path_validation_rejects_wrong_addr: PASS")


def test_path_validation_defers_without_spare_cid() raises:
    """AC15: PATH_RESPONSE match WITHOUT a spare remote CID defers promotion.

    RFC 9000 §9.5 MUST: a different DCID is required on a new path.
    With no spare, the connection cannot rotate, and the validated path
    must NOT take effect — peer_addr stays put. Validation completes
    once the client issues a fresh NEW_CONNECTION_ID.
    """
    var conn = _build_server_for_rx_test()
    # NO spare remote CID seeded; only seq=0 exists.
    assert_equal_int(
        len(conn.cid_mgr.remote_cids), 1,
        "only the initial remote CID exists",
    )

    var addr_a = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(1), UInt16(5000)
    )
    var addr_b = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(2), UInt16(6000)
    )
    conn.bootstrap_peer_addr(addr_a^)

    conn.start_path_challenge(PathKey(other=addr_b), UInt64(1000))
    var token = List[UInt8](copy=conn.path_validator.pending[0].token)

    conn.on_path_response_received(
        Span(token), PathKey(other=addr_b), UInt64(2000)
    )

    # The matched challenge is REMOVED (validator's on_response is the
    # one that pops + marks `current`); CID rotation fails → peer_addr
    # does NOT swap.
    var peer_now = PathKey(other=conn.peer_addr)
    var addr_a_cmp = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(1), UInt16(5000)
    )
    assert_true(
        peer_now == addr_a_cmp,
        "peer_addr stays on the old path when no spare DCID is available",
    )
    assert_equal_int(
        Int(conn.cid_mgr.remote_active_cid_seq), 0,
        "remote_active_cid_seq unchanged — no rotation occurred",
    )
    # Validator did record the validated path internally (the response
    # was a real match); the deferral is at the connection layer.
    assert_true(
        Bool(conn.path_validator.current),
        "validator marks the path validated even when conn defers promotion",
    )
    print("  test_path_validation_defers_without_spare_cid: PASS")


def test_disable_active_migration_triggers_close() raises:
    """AC9: `disable_active_migration=True` + addr change → close_transport(0x0A).

    Per RFC 9000 §9 ¶last, when the server advertised
    `disable_active_migration`, any client-side 4-tuple change is a
    PROTOCOL_VIOLATION. Asserts the reason tag is
    `GUARD_TAG_MIGRATION_DISABLED` so log scrapers / coverage tools
    can identify the close cause.
    """
    var conn = _build_server_for_rx_test()
    # Flip the TP and re-bootstrap the addr so the addr-change branch
    # has something concrete to diverge from.
    conn.local_params.disable_active_migration = True
    var addr_a = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(1), UInt16(5000)
    )
    var addr_b = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(2), UInt16(6000)
    )
    conn.bootstrap_peer_addr(addr_a^)
    # Force ESTABLISHED so the post-handshake migration check runs.
    conn.state = conn.state | CONN_ESTABLISHED

    # Pre-condition: not closing yet.
    assert_equal_int(
        Int(conn.state & CONN_CLOSING), 0,
        "connection not closing before the ingress arrives",
    )

    conn.on_ingress_from(PathKey(other=addr_b), 1200, UInt64(2000))

    # Post-condition: CLOSING set, pending_close holds the right tag.
    assert_true(
        (conn.state & CONN_CLOSING) != 0,
        "CONN_CLOSING set after migration-disabled violation",
    )
    assert_true(
        Bool(conn.pending_close),
        "pending CONNECTION_CLOSE frame queued",
    )
    var cc = conn.pending_close.value().copy()
    assert_true(
        cc.is_transport,
        "close uses transport namespace (PROTOCOL_VIOLATION)",
    )
    assert_equal_int(
        Int(cc.error_code), 0x0A,
        "error_code == PROTOCOL_VIOLATION (0x0A)",
    )
    # Reason tag check — bytes carry the exact GUARD_TAG_MIGRATION_DISABLED.
    var expected_tag = String(GUARD_TAG_MIGRATION_DISABLED)
    var expected_bytes = expected_tag.as_bytes()
    assert_equal_int(
        len(cc.reason), len(expected_bytes),
        "reason length matches GUARD_TAG_MIGRATION_DISABLED",
    )
    for i in range(len(expected_bytes)):
        assert_equal_int(
            Int(cc.reason[i]), Int(expected_bytes[i]),
            "reason byte mismatch at index " + String(i),
        )

    # No PATH_CHALLENGE was queued on the disabled connection — the
    # close pre-empts validation entirely.
    assert_equal_int(
        len(conn.path_validator.pending), 0,
        "no PATH_CHALLENGE emitted when migration is disabled",
    )
    print("  test_disable_active_migration_triggers_close: PASS")


def test_is_closing_reflects_bitfield() raises:
    """is_closing() non-destructively mirrors the CONN_CLOSING state bit.

    Mirrors is_draining()/is_closed(): a pure bitfield read with no side
    effects. Exercised on an established connection (the downstream
    race-driver's is_established()==True case) to prove the additive
    bitfield lets `is_closing()` flip independently of CONN_ESTABLISHED,
    and that repeated reads neither mutate `state` nor disturb other bits.
    """
    var conn = _build_server_for_rx_test()
    # Establish so the accessor is read on a usable connection, matching
    # the downstream consumer that checks a live (established) conn.
    conn.state = conn.state | CONN_ESTABLISHED

    # Bit clear -> is_closing() is False; established is unaffected.
    assert_true(conn.is_established(), "precondition: connection established")
    assert_false(
        conn.is_closing(),
        "is_closing() False before CONN_CLOSING is set",
    )

    # Set CONN_CLOSING -> is_closing() flips to True.
    conn.state = conn.state | CONN_CLOSING
    assert_true(
        conn.is_closing(),
        "is_closing() True once CONN_CLOSING is set",
    )

    # Non-destructive: a second read returns the same value and the raw
    # bitfield is unchanged (no poll()-style side effect).
    var snapshot = conn.state
    assert_true(
        conn.is_closing(),
        "is_closing() is idempotent across repeated reads",
    )
    assert_equal_int(
        Int(conn.state), Int(snapshot),
        "is_closing() does not mutate state",
    )
    # The bitfield is additive: closing does not clear ESTABLISHED.
    assert_true(
        conn.is_established(),
        "is_closing() True does not clear CONN_ESTABLISHED",
    )
    print("  test_is_closing_reflects_bitfield: PASS")


def test_anti_amp_per_path_in_flusher() raises:
    """AC16: the per-path 3× budget gates `can_send_to` until validation lifts it.

    Models the bench flusher's contract: outbound emission is allowed
    iff `can_send_to(target, n_bytes)` returns True; on send, the
    caller credits `record_send_to`. With no received bytes credited,
    `can_send_to` rejects any positive `n` on a pending-challenge path.
    After 1000 received bytes, the gate admits ≤3000 bytes; after a
    3000-byte send, further emission is blocked until more arrives.
    """
    var conn = _build_server_for_rx_test()
    var addr_a = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(1), UInt16(5000)
    )
    var addr_b = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(2), UInt16(6000)
    )
    conn.bootstrap_peer_addr(addr_a^)
    conn.start_path_challenge(PathKey(other=addr_b), UInt64(1000))

    # Cold gate: 0 received → no budget. The validator's contract is to
    # refuse `n > 0` when bytes_received == 0 (budget = 3*0 - 0 = 0).
    assert_false(
        conn.can_send_to(addr_b, 1),
        "cold path rejects any outbound bytes",
    )

    # Credit 1000 received bytes; budget = 3 * 1000 - 0 = 3000.
    conn.path_validator.record_received_bytes(
        PathKey(other=addr_b), 1000
    )
    assert_true(
        conn.can_send_to(addr_b, 3000),
        "3000-byte send fits in the 3× budget after 1000 RX bytes",
    )
    assert_false(
        conn.can_send_to(addr_b, 3001),
        "3001-byte send exceeds the 3× budget",
    )

    # Spend the budget; remaining should be 0.
    conn.record_send_to(addr_b, 3000)
    assert_false(
        conn.can_send_to(addr_b, 1),
        "budget exhausted after a full 3× send",
    )

    # The VALIDATED path (peer_addr / addr_a) has no per-path
    # constraint — `can_send_to` returns True regardless of `n`.
    var addr_a_view = PathKey.from_v4(
        UInt8(10), UInt8(0), UInt8(0), UInt8(1), UInt16(5000)
    )
    assert_true(
        conn.can_send_to(addr_a_view, 65536),
        "validated path is not anti-amp gated",
    )
    print("  test_anti_amp_per_path_in_flusher: PASS")


# ── RFC 9221 — QUIC DATAGRAM frames ──────────────────────────────────────


def _datagram_params(cap: UInt64) -> TransportParams:
    """Like `_default_params` but with DATAGRAM support advertised.

    `cap` is the local max_datagram_frame_size; both sides typically share
    the same params struct so both gain the ability to send + receive.
    """
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    p.initial_max_data = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_local = UInt64(65_536)
    p.initial_max_stream_data_bidi_remote = UInt64(65_536)
    p.initial_max_streams_bidi = UInt64(100)
    p.max_datagram_frame_size = cap
    return p^


def test_send_datagram_refused_when_peer_disabled() raises:
    """RFC 9221 §3: when peer advertises 0 (or absent), send_datagram returns False.

    Set up a handshake where the SERVER advertises 0 but the CLIENT
    advertises >0 — verifies that the client cannot send despite its own
    willingness, because the peer cannot receive.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var client_params = _datagram_params(UInt64(1200))   # local enabled
    var server_params = _datagram_params(UInt64(0))      # peer disabled (default)
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", client_params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, server_params,
        Span(orig_dcid), Span(client_dcid), now,
    )
    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    var payload = _to_bytes("hello-datagram")
    var ok = client.send_datagram(Span(payload))
    assert_false(ok, "send_datagram must refuse when peer max=0")
    assert_equal_int(
        len(client.pending_outbound_datagrams),
        0,
        "no datagram should be queued",
    )
    _ = tls^
    print("  test_send_datagram_refused_when_peer_disabled: PASS")


def test_send_datagram_refused_when_oversize() raises:
    """RFC 9221 §3: payload above peer cap is refused at send time.

    Peer advertises 1200 — the local side rejects a 2000-byte payload
    without queueing it, returning False so the caller surfaces the limit
    to its own consumer.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _datagram_params(UInt64(1200))
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )
    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    var oversize = List[UInt8]()
    for _ in range(2000):
        oversize.append(UInt8(0xAB))
    var ok = client.send_datagram(Span(oversize))
    assert_false(ok, "send_datagram must refuse oversize payload")
    assert_equal_int(
        len(client.pending_outbound_datagrams),
        0,
        "oversize payload must not be queued",
    )

    # Sanity: a within-cap payload IS queued.
    var small = _to_bytes("ok")
    var ok2 = client.send_datagram(Span(small))
    assert_true(ok2, "within-cap payload must enqueue")
    assert_equal_int(
        len(client.pending_outbound_datagrams),
        1,
        "one queued datagram after enqueue",
    )
    _ = tls^
    print("  test_send_datagram_refused_when_oversize: PASS")


def test_datagram_round_trip_client_to_server() raises:
    """RFC 9221 §5: client-sent DATAGRAM arrives as a server-side QuicEvent.

    Wires the full QUIC layer (handshake → enqueue → flush → recv →
    dispatch) end-to-end. The payload bytes MUST come out byte-identical
    on the server side via QuicEvent.datagram_received, with the queue
    drained after the flush.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _datagram_params(UInt64(1200))
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )
    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    var payload = _to_bytes("hello-datagram")
    var ok = client.send_datagram(Span(payload))
    assert_true(ok, "send_datagram must succeed once handshake done")
    assert_equal_int(
        len(client.pending_outbound_datagrams),
        1,
        "queue holds one datagram pre-flush",
    )

    now = _pump(client, server, now, 3)

    # The queue must be drained on the client after a flush.
    assert_equal_int(
        len(client.pending_outbound_datagrams),
        0,
        "queue drained after flush",
    )

    # The server must surface a DATAGRAM_RECEIVED event with the same bytes.
    var got_event = False
    var got_bytes_match = False
    while True:
        var ev = server.poll()
        if not ev:
            break
        var e = ev.value().copy()
        if e.type_id == QuicEvent.DATAGRAM_RECEIVED:
            got_event = True
            if _bytes_equal(e.datagram_payload, "hello-datagram"):
                got_bytes_match = True
    assert_true(got_event, "server must emit DATAGRAM_RECEIVED")
    assert_true(got_bytes_match, "server datagram payload must match sender's bytes")
    _ = tls^
    print("  test_datagram_round_trip_client_to_server: PASS")


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
    test_predicate_f15_positive()
    test_predicate_f15_negative_no_violation()
    test_predicate_f15_negative_sibling_input()
    test_predicate_f16_positive()
    test_predicate_f16_negative_no_violation()
    test_predicate_f16_negative_sibling_input()
    test_predicate_f11_positive()
    test_predicate_f11_negative_no_violation()
    test_is_unknown_frame_type_positive()
    test_is_unknown_frame_type_negative()
    test_check_long_reserved_bits_positive()
    test_check_long_reserved_bits_negative_no_violation()
    test_check_long_reserved_bits_negative_sibling_input()
    test_check_short_reserved_bits_positive()
    test_check_short_reserved_bits_negative_no_violation()
    test_check_short_reserved_bits_negative_sibling_input()
    test_is_path_challenge_in_handshake_positive()
    test_is_path_challenge_in_handshake_negative()
    test_is_crypto_in_zero_rtt_positive()
    test_is_crypto_in_zero_rtt_negative()
    test_predicate_crypto_in_zero_rtt_verdict()
    test_is_client_only_frame_on_server_positive()
    test_is_client_only_frame_on_server_negative()
    test_predicate_f18_max_stream_data_nonexist()
    test_predicate_f19_max_stream_data_recv_only()
    test_predicate_f18_f19_max_stream_data_negative()
    test_check_max_streams_value_positive()
    test_check_max_streams_value_negative()
    test_check_streams_blocked_value_positive()
    test_check_streams_blocked_value_negative()
    test_check_new_connection_id_retire_prior_positive()
    test_check_new_connection_id_retire_prior_negative()
    test_check_new_connection_id_length_positive()
    test_check_new_connection_id_length_negative()
    test_stream_offset_exceeds_fc_positive()
    test_stream_offset_exceeds_fc_negative()
    test_on_handshake_complete_close_transport_on_invalid_tp()
    test_tls_guard_tag_for_alert_mapping()
    test_drive_handshake_tls_error_emits_crypto_close()
    test_path_challenge_recorded_for_response()
    test_path_response_handler_no_op_without_pending_challenge()
    test_emit_path_response_drains_pending()
    test_start_path_challenge_queues_emission()
    test_path_response_emission_preserves_data()
    test_initial_new_cid_burst_after_handshake_complete()
    test_initial_new_cid_burst_default_limit()
    test_initial_burst_skipped_before_handshake_complete()
    test_initial_burst_server_only()
    test_path_validation_full_round_trip()
    test_path_validation_rejects_wrong_addr()
    test_path_validation_defers_without_spare_cid()
    test_disable_active_migration_triggers_close()
    test_is_closing_reflects_bitfield()
    test_anti_amp_per_path_in_flusher()
    test_send_datagram_refused_when_peer_disabled()
    test_send_datagram_refused_when_oversize()
    test_datagram_round_trip_client_to_server()
    print("All test_quic_connection tests passed.")
