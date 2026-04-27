# tests/test_h3_sync_server.mojo
#
# Tests for H3CoroServer (Sprint 2A Path A — sync handler).
# Ports the two REWRITE-classified tests from test_h3_coro_server.mojo:
#   test_h3_sync_simple_get  (was test_h3_coro_simple_get)
#   test_h3_sync_goaway      (was test_h3_coro_goaway)
#
# Run with:
#   uv run mojo run -I . -I conformance tests/test_h3_sync_server.mojo

from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.python import Python, PythonObject

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection
from src.quic.trans_param import TransportParams, default_transport_params
from src.h3.connection import H3Connection, H3Event
from src.h3.h3_sync_server import H3CoroServer, CoroStreamCtx, H3BodyFn
from src.h3.qpack import QpackHeaderField
from src.http.handler import RecvBody, ResponseWriter, StreamError, Capabilities
from src.http.headers import Headers
from src.http.body import BodyFrame
from src.http.status import StatusCode
from tests._test_util import assert_true, assert_equal_int


# ── Shared loopback helpers ──────────────────────────────────────────────────


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
    var cert_bytes = py_bytes_to_mojo(py_cert.public_bytes(ser_mod.Encoding.PEM))
    var key_bytes = py_bytes_to_mojo(
        py_key.private_bytes(ser_mod.Encoding.PEM, ser_mod.PrivateFormat.PKCS8, ser_mod.NoEncryption())
    )
    return (cert_bytes^, key_bytes^)


def _h3_default_params() -> TransportParams:
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    p.initial_max_data = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_local = UInt64(65_536)
    p.initial_max_stream_data_bidi_remote = UInt64(65_536)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


def _make_lib_and_configs() raises -> Tuple[UInt64, Int32, Int32]:
    """Return (lib_addr, server_config_handle, client_config_handle)."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var cert_ptr = cert_bytes.unsafe_ptr().as_any_origin()
    var key_ptr = key_bytes.unsafe_ptr().as_any_origin()
    var cert_len = Int32(len(cert_bytes))
    var key_len = Int32(len(key_bytes))
    var alpn_ptr = _heap_alloc[UInt8](2).as_any_origin()
    alpn_ptr[0] = UInt8(ord("h"))
    alpn_ptr[1] = UInt8(ord("3"))
    var alpn_len = Int32(2)
    var srv_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    _ = lib_ptr[].quic_server_config_new(cert_ptr, cert_len, key_ptr, key_len, alpn_ptr, alpn_len, srv_cfg_ptr)
    var srv_cfg = srv_cfg_ptr[0]
    srv_cfg_ptr.free()
    var cli_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    _ = lib_ptr[].quic_client_config_with_ca(cert_ptr, cert_len, alpn_ptr, alpn_len, cli_cfg_ptr)
    var cli_cfg = cli_cfg_ptr[0]
    cli_cfg_ptr.free()
    alpn_ptr.free()
    return (lib_addr, srv_cfg, cli_cfg)


def _pump_sync_client(
    mut server: H3CoroServer,
    mut client: H3Connection,
    mut now: UInt64,
    rounds: Int = 5,
) raises -> UInt64:
    """Exchange QUIC datagrams between H3CoroServer (sync) and client H3Connection."""
    for _ in range(rounds):
        now += UInt64(10_000)
        var s_dgs = server.drain()
        for i in range(len(s_dgs)):
            try:
                client.feed_datagram(Span(s_dgs[i]), now)
            except:
                pass
        var c_dgs = client.drain_datagrams(now)
        for i in range(len(c_dgs)):
            try:
                server.feed_datagram(Span(c_dgs[i]), now)
            except:
                pass
    return now


# ── Sync body functions ──────────────────────────────────────────────────────


fn _simple_get_body(
    ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]
) raises:
    """Respond immediately with 200 OK + 'hello' body."""
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), Headers())
    var body = List[UInt8]()
    var src = String("hello").as_bytes()
    for i in range(len(src)):
        body.append(src[i])
    _ = ctx_ptr[].resp_writer.try_send_body(BodyFrame.data(body^))
    ctx_ptr[].resp_writer.end()


# ── Tests ────────────────────────────────────────────────────────────────────


def test_h3_sync_simple_get() raises:
    """GET / → sync handler responds immediately with 200 OK + 'hello'."""
    var configs = _make_lib_and_configs()
    var lib_addr = configs[0]
    var srv_cfg = configs[1]
    var cli_cfg = configs[2]
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(lib_addr, cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        lib_addr, srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3CoroServer(quic=server_quic^, body_fn=_simple_get_body)
    var client = H3Connection.client(client_quic^)

    # Handshake + H3 bootstrap
    now = _pump_sync_client(server, client, now, 50)

    # Send GET / with fin=True (no body)
    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "GET"))
    req_fields.append(QpackHeaderField(":path", "/"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, True)  # fin=True

    now = _pump_sync_client(server, client, now, 20)

    # Collect response events
    var got_200 = False
    var body_bytes = List[UInt8]()
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.HEADERS_RECEIVED:
            for i in range(len(e.fields)):
                if e.fields[i].name == ":status" and e.fields[i].value == "200":
                    got_200 = True
        elif e.kind == H3Event.DATA_RECEIVED:
            for i in range(len(e.data)):
                body_bytes.append(e.data[i])

    assert_true(got_200, "client did not receive 200 OK")
    var body_str = String(unsafe_from_utf8=body_bytes)
    assert_true(body_str == "hello", "response body expected 'hello', got: " + body_str)
    print("  test_h3_sync_simple_get: PASS")


def test_h3_sync_goaway() raises:
    """Server sends GOAWAY → client receives GOAWAY_RECEIVED event."""
    var configs = _make_lib_and_configs()
    var lib_addr = configs[0]
    var srv_cfg = configs[1]
    var cli_cfg = configs[2]
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(lib_addr, cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        lib_addr, srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3CoroServer(quic=server_quic^, body_fn=_simple_get_body)
    var client = H3Connection.client(client_quic^)

    now = _pump_sync_client(server, client, now, 50)

    # Server sends GOAWAY before any request
    server.send_goaway(UInt64(0))
    now = _pump_sync_client(server, client, now, 20)

    # Client should receive GOAWAY_RECEIVED event
    var got_goaway = False
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.GOAWAY_RECEIVED:
            got_goaway = True

    assert_true(got_goaway, "client did not receive GOAWAY from server")
    print("  test_h3_sync_goaway: PASS")


def main() raises:
    print("=== test_h3_sync_server ===")
    test_h3_sync_simple_get()
    test_h3_sync_goaway()
    print("All H3SyncServer tests passed.")
    print("ok")
