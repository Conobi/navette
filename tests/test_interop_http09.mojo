# tests/test_interop_http09.mojo
#
# HTTP/0.9 over QUIC integration tests.
#
# Run with:
#   cd ~/Projets/perso/mojo-net && uv run mojo run -I . tests/test_interop_http09.mojo

from std.collections import Optional
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.python import Python, PythonObject

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection, QuicEvent
from src.quic.trans_param import TransportParams, default_transport_params
from tests._test_util import assert_true, assert_equal_str, assert_equal_int
from interop.http09 import http09_request, http09_collect, http09_parse_path, http09_serve
from interop.file_io import read_file, write_file, mkdir_p


# ── Helpers (mirrors test_quic_connection.mojo) ───────────────────────────


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

    # ALPN = "hq-interop" for HTTP/0.9 interop
    var alpn_str = String("hq-interop")
    var alpn_bytes = alpn_str.as_bytes()
    var alpn_ptr = _heap_alloc[UInt8](len(alpn_bytes)).as_any_origin()
    for i in range(len(alpn_bytes)):
        alpn_ptr[i] = alpn_bytes[i]
    var alpn_len = Int32(len(alpn_bytes))

    var srv_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    var rc = lib_ptr[].quic_server_config_new(
        cert_ptr, cert_len, key_ptr, key_len, alpn_ptr, alpn_len, srv_cfg_ptr,
    )
    assert_true(rc == Int32(0), "quic_server_config_new failed: " + lib_ptr[].last_error())
    var server_config = srv_cfg_ptr[0]
    srv_cfg_ptr.free()

    var cli_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    rc = lib_ptr[].quic_client_config_with_ca(
        cert_ptr, cert_len, alpn_ptr, alpn_len, cli_cfg_ptr,
    )
    assert_true(rc == Int32(0), "quic_client_config_with_ca failed: " + lib_ptr[].last_error())
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
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))

    var configs = _create_configs(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]

    var params = _default_params()
    var now = UInt64(1_000_000)

    var client = QuicConnection.client(lib_addr, client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(
        lib_addr, server_config, params, Span(orig_dcid), Span(client_dcid), now,
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
