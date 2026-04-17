# tests/test_h3_e2e.mojo
#
# Full QUIC loopback E2E tests for H3HandlerServer and H3Session.
# Run with:
#   uv run mojo run -I . -I conformance -D ASSERT=all tests/test_h3_e2e.mojo

from std.collections.deque import Deque
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.python import Python, PythonObject

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection
from src.quic.trans_param import TransportParams, default_transport_params
from src.h3.connection import H3Connection, H3Event
from src.h3.h3_handler_server import H3HandlerServer
from src.h3.h3_session import H3Session
from src.h3.qpack import QpackHeaderField, QpackEncoder
from src.http.handler import StreamHandler, RecvBody, ResponseWriter, Capabilities, StreamError
from src.http.request import Request, RequestBody
from src.http.response import Response
from src.http.headers import Headers
from src.http.status import StatusCode
from src.http.body import BodyFrame
from src.http.method import Method
from src.http.version import Version
from src.http.session import RequestHandle
from tests._test_util import assert_true, assert_equal_int


# ── Helpers ─────────────────────────────────────────────────────────────


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


def _pump_server_client[H: StreamHandler](
    mut server: H3HandlerServer[H],
    mut client: H3Connection,
    mut now: UInt64,
    rounds: Int = 5,
) raises -> UInt64:
    """Exchange datagrams between server adapter and raw client H3Connection."""
    for _ in range(rounds):
        now += UInt64(10_000)
        var s_dgs = server.drain_datagrams(now)
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


# ── Test handler ─────────────────────────────────────────────────────────


struct _FixedResponseHandler(StreamHandler):
    """Handler that always sends a fixed status + body, ignoring the request."""
    var _body: String

    def __init__(out self, body: String):
        self._body = body

    def __init__(out self, *, deinit take: Self):
        self._body = take._body^

    def on_request(
        mut self, var req: Request, mut body: RecvBody, mut resp: ResponseWriter, caps: Capabilities
    ) raises:
        resp.send_status(StatusCode.ok(), Headers())
        var body_bytes = List[UInt8]()
        var src = self._body.as_bytes()
        for i in range(len(src)):
            body_bytes.append(src[i])
        _ = resp.try_send_body(BodyFrame.data(body_bytes^))
        resp.end()

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


# ── Tests ────────────────────────────────────────────────────────────────


def test_h3_simple_get() raises:
    """GET / → 200 OK with body 'hello'."""
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
    var server = H3HandlerServer[_FixedResponseHandler](
        quic=server_quic^, handler=_FixedResponseHandler("hello")
    )
    var client = H3Connection.client(client_quic^)

    # Pump handshake + bootstrap (50 rounds max)
    now = _pump_server_client(server, client, now, 50)

    # Client opens bidi stream and sends GET /
    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "GET"))
    req_fields.append(QpackHeaderField(":path", "/"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, True)  # fin=True (no body)

    # Pump 20 more rounds for request/response
    now = _pump_server_client(server, client, now, 20)

    # Collect client events: expect HEADERS_RECEIVED + DATA_RECEIVED
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
    print("  test_h3_simple_get: PASS")


def test_h3_post_with_body() raises:
    """POST /upload with body 'data' → server responds 200."""
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
    var server = H3HandlerServer[_FixedResponseHandler](
        quic=server_quic^, handler=_FixedResponseHandler("data")
    )
    var client = H3Connection.client(client_quic^)

    now = _pump_server_client(server, client, now, 50)

    # Client sends POST /upload with body
    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "POST"))
    req_fields.append(QpackHeaderField(":path", "/upload"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, False)
    var body_bytes = List[UInt8]()
    var src = "data".as_bytes()
    for i in range(len(src)):
        body_bytes.append(src[i])
    client.send_data(stream_id, body_bytes, True)

    now = _pump_server_client(server, client, now, 20)

    # Verify response
    var got_200 = False
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.HEADERS_RECEIVED:
            for i in range(len(e.fields)):
                if e.fields[i].name == ":status" and e.fields[i].value == "200":
                    got_200 = True

    assert_true(got_200, "POST: client did not receive 200 OK")
    print("  test_h3_post_with_body: PASS")


def _pump_e2e[H: StreamHandler](
    mut server: H3HandlerServer[H],
    mut client: H3Session,
    mut now: UInt64,
    rounds: Int = 5,
) raises -> UInt64:
    """Exchange datagrams between HandlerServer and H3Session."""
    for _ in range(rounds):
        now += UInt64(10_000)
        var s_dgs = server.drain_datagrams(now)
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


def test_h3_session_get() raises:
    """H3Session.submit(GET /) → response 200 with body 'hello'."""
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
    var server = H3HandlerServer[_FixedResponseHandler](
        quic=server_quic^, handler=_FixedResponseHandler("hello")
    )
    var client = H3Session(quic=client_quic^)

    # Pump handshake
    now = _pump_e2e(server, client, now, 50)

    # Submit GET /
    var req = Request(
        method=Method.get(),
        target=String("/"),
        version=Version.http_3(),
        headers=Headers(),
    )
    var handle = client.submit(req^)

    # Pump until complete
    var complete = False
    for _ in range(30):
        now = _pump_e2e(server, client, now, 3)
        client.run_one(handle)
        if handle.is_complete():
            complete = True
            break

    assert_true(complete, "H3Session GET: handle did not complete")
    assert_true(handle.has_headers(), "H3Session GET: no response headers")
    var resp_opt = handle.try_take_response()
    assert_true(Bool(resp_opt), "H3Session GET: try_take_response returned none")
    var resp = resp_opt.take()
    assert_equal_int(Int(resp.status.code()), 200, "status 200")
    print("  test_h3_session_get: PASS")


def test_h3_multi_request() raises:
    """Three concurrent GET requests all complete successfully."""
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
    var server = H3HandlerServer[_FixedResponseHandler](
        quic=server_quic^, handler=_FixedResponseHandler("ok")
    )
    var client = H3Session(quic=client_quic^)

    now = _pump_e2e(server, client, now, 50)

    # Submit three requests — RequestHandle is Movable but not Copyable,
    # so keep them as individual named variables.
    var req0 = Request(method=Method.get(), target=String("/"), version=Version.http_3(), headers=Headers())
    var req1 = Request(method=Method.get(), target=String("/"), version=Version.http_3(), headers=Headers())
    var req2 = Request(method=Method.get(), target=String("/"), version=Version.http_3(), headers=Headers())
    var h0 = client.submit(req0^)
    var h1 = client.submit(req1^)
    var h2 = client.submit(req2^)

    for _ in range(60):
        now = _pump_e2e(server, client, now, 3)
        client.run_one(h0)
        client.run_one(h1)
        client.run_one(h2)
        if h0.is_complete() and h1.is_complete() and h2.is_complete():
            break

    assert_true(h0.is_complete(), "handle 0 not complete")
    assert_true(h1.is_complete(), "handle 1 not complete")
    assert_true(h2.is_complete(), "handle 2 not complete")
    assert_true(h0.has_headers(), "handle 0 no headers")
    assert_true(h1.has_headers(), "handle 1 no headers")
    assert_true(h2.has_headers(), "handle 2 no headers")
    print("  test_h3_multi_request: PASS")


def test_h3_goaway() raises:
    """Server sends GOAWAY; client receives GOAWAY_RECEIVED event."""
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
    var server = H3HandlerServer[_FixedResponseHandler](
        quic=server_quic^, handler=_FixedResponseHandler("bye")
    )
    var client = H3Session(quic=client_quic^)

    now = _pump_e2e(server, client, now, 50)

    # Server sends GOAWAY
    server.send_goaway(UInt64(0))

    # Pump so client receives it
    now = _pump_e2e(server, client, now, 10)

    # H3Session.feed_datagram dispatches events internally and sets
    # received_goaway when a GOAWAY_RECEIVED event is observed.
    assert_true(client.received_goaway, "client did not receive GOAWAY_RECEIVED")
    print("  test_h3_goaway: PASS")


def main() raises:
    print("=== test_h3_e2e ===")
    test_h3_simple_get()
    test_h3_post_with_body()
    test_h3_session_get()
    test_h3_multi_request()
    test_h3_goaway()
    print("All H3 E2E tests passed.")
