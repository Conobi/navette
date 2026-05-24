# tests/test_quic_pacer_bypass.mojo
#
# Pacer-bypass unit tests for QuicConnection during handshake.
# See specs/2026-04-25-quic-pacer-bypass-handshake.md for the design.
#
# Run with:
#   cd ~/Projets/perso/navette && LD_LIBRARY_PATH=lib uv run mojo run -I . -I conformance \
#     -D ASSERT=all tests/test_quic_pacer_bypass.mojo

from std.collections import Optional
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import TransportParams, default_transport_params
from tests._test_util import assert_true, assert_false, assert_equal_int, load_test_cert, load_test_ca


# ── Helpers (copy/adapt from tests/test_quic_connection.mojo) ────────────


def generate_ephemeral_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    # Backed by tests/fixtures/tls/server.{crt,key} (regen via
    # scripts/regen_test_certs.sh). See plans/2026-05-13-deps-enhancement.md §3.1.
    return load_test_cert()


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
        tls.shared(), server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )
    server.bytes_received = UInt64(0)
    server.bytes_sent = UInt64(0)
    assert_false(
        server._can_send(UInt64(1500), now),
        "anti-amp must still gate non-established server with bytes_received=0",
    )

    _ = tls^
    print("  test_pacer_bypassed_during_handshake: PASS")


def test_pacer_active_after_handshake() raises:
    """After is_established(), the pacer continues to gate sends. Regression
    guard ensuring the bypass is scoped strictly to the handshake phase."""
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

    _ = tls^
    print("  test_pacer_active_after_handshake: PASS")


def test_handshake_padding_still_works() raises:
    """A fresh client's first Initial flight is still padded to MIN_DATAGRAM_SIZE
    after the bypass change. Regression guard for the padding logic at
    src/quic/connection.mojo:1714-1728."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var ca_bytes = load_test_ca()
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
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

    _ = tls^
    print("  test_handshake_padding_still_works: PASS")


def main() raises:
    print("test_quic_pacer_bypass:")
    test_pacer_bypassed_during_handshake()
    test_pacer_active_after_handshake()
    test_handshake_padding_still_works()
    print("All test_quic_pacer_bypass tests passed.")
