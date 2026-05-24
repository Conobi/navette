# tests/test_interop_http09.mojo
#
# HTTP/0.9 over QUIC integration tests.
#
# Run with:
#   cd ~/Projets/perso/navette && uv run mojo run -I . tests/test_interop_http09.mojo

from std.collections import Optional
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection, QuicEvent
from navette.quic.trans_param import TransportParams, default_transport_params
from tests._test_util import assert_true, assert_equal_str, assert_equal_int, load_test_cert, load_test_ca
from interop.http09 import http09_request, http09_collect, http09_parse_path, http09_serve
from interop.file_io import read_file, write_file, mkdir_p


# ── Helpers (mirrors test_quic_connection.mojo) ───────────────────────────


def generate_ephemeral_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    # Backed by tests/fixtures/tls/server.{crt,key} (regen via
    # scripts/regen_test_certs.sh). See plans/2026-05-13-deps-enhancement.md §3.1.
    return load_test_cert()


    # _create_configs removed — use QuicServerConfig / QuicClientConfig directly.


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


def _drain_events(mut conn: QuicConnection):
    while True:
        var ev = conn.poll()
        if not ev:
            break


# ── Tests ──────────────────────────────────────────────────────────────────


def test_parse_path() raises:
    """Parse path with subdirectory."""
    var req = String("GET /path/to/file.txt\r\n")
    var req_bytes = req.as_bytes()
    var result = http09_parse_path(Span(req_bytes))
    assert_equal_str(result, "path/to/file.txt", "parse_path with subdirectory")
    print("  PASS test_parse_path")


def test_parse_path_root() raises:
    """Parse path for root-level file."""
    var req = String("GET /file.bin\r\n")
    var req_bytes = req.as_bytes()
    var result = http09_parse_path(Span(req_bytes))
    assert_equal_str(result, "file.bin", "parse_path root file")
    print("  PASS test_parse_path_root")


def test_http09_loopback() raises:
    """Full QUIC loopback: client GET -> server serve file -> client collects."""
    # ── Set up the test file ──────────────────────────────────────────────
    var www_dir = "/tmp/interop_test_www"
    mkdir_p(www_dir)
    var test_data = List[UInt8](capacity=1024)
    for i in range(1024):
        test_data.append(UInt8(i % 256))
    write_file(www_dir + "/test1k.bin", Span(test_data))

    # ── Create QUIC loopback pair ─────────────────────────────────────────
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var server_config = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes), alpn="hq-interop")
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes), alpn="hq-interop")

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(tls.shared(), client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        tls.shared(), server_config, params, Span(orig_dcid), Span(client_dcid), now,
    )

    now = _establish_handshake(client, server, now)
    _drain_events(client)
    _drain_events(server)

    # ── Client sends HTTP/0.9 GET request ─────────────────────────────────
    var stream_id = http09_request(client, "/test1k.bin")

    # Pump client -> server so the request arrives
    now = _pump(client, server, now, rounds=3)

    # ── Server: poll for STREAM events, read request, serve file ──────────
    var server_saw_stream = False
    var server_stream_id = UInt64(0)
    while True:
        var ev = server.poll()
        if not ev:
            break
        var e = ev.value().copy()
        # STREAM_OPENED=9 or STREAM_READABLE=5
        if e.type_id == QuicEvent.STREAM_OPENED or e.type_id == QuicEvent.STREAM_READABLE:
            server_saw_stream = True
            server_stream_id = e.stream_id
    assert_true(server_saw_stream, "server missed STREAM event")

    var srv_read = server.recv_stream_data(server_stream_id)
    var req_data = srv_read[0].copy()
    assert_true(len(req_data) > 0, "server got empty request")
    http09_serve(server, server_stream_id, Span(req_data), www_dir)

    # Pump server -> client so the response arrives
    _ = _pump(server, client, now, rounds=5)

    # ── Client: collect response ──────────────────────────────────────────
    # Drain events to trigger STREAM_READABLE on client side.
    _drain_events(client)

    var result = http09_collect(client, stream_id)
    var response_data = result[0].copy()
    _ = result[1]  # fin flag

    assert_equal_int(len(response_data), 1024, "response length should be 1024")
    # Verify contents match.
    var data_ok = True
    for i in range(1024):
        if response_data[i] != UInt8(i % 256):
            data_ok = False
            break
    assert_true(data_ok, "response data does not match test file")

    print("  PASS test_http09_loopback")


# ── Main ───────────────────────────────────────────────────────────────────


def main() raises:
    print("test_interop_http09")
    test_parse_path()
    test_parse_path_root()
    test_http09_loopback()
    print("All interop/http09 tests passed.")
