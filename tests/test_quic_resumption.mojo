# tests/test_quic_resumption.mojo
#
# P2 — server-side TLS 1.3 session resumption (Plan: 2026-05-03-short-conn-resumption).
#
# T2 tests:
#   - handshake_kind FFI: invalid handle -> -1 with last_error set
#   - handshake_kind FFI: client connection -> -2 (not applicable)

from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from src.tls.lib import RustlsLibrary
from tests._test_util import assert_true, assert_equal_int


def test_quic_handshake_kind_invalid_handle_returns_minus_one() raises:
    """An invalid conn handle must yield -1 with last_error set."""
    var lib = RustlsLibrary()
    var rc = lib.quic_conn_handshake_kind(Int32(-99))
    assert_equal_int(Int(rc), -1, "invalid handle must return -1")
    var err = lib.last_error()
    assert_true(len(err) > 0, "last_error must be set on invalid handle")


def test_quic_handshake_kind_client_returns_minus_two() raises:
    """Client connections must always return -2 (not applicable)."""
    var lib = RustlsLibrary()

    var alpn_bytes = String("h3").as_bytes()
    var alpn_len = len(alpn_bytes)
    var alpn_buf = _heap_alloc[UInt8](alpn_len).as_any_origin()
    for i in range(alpn_len):
        alpn_buf[i] = alpn_bytes[i]

    var cfg_handle = _heap_alloc[Int32](1).as_any_origin()
    cfg_handle[0] = Int32(-1)
    var rc_cfg = lib.quic_client_config_new(
        alpn_buf, Int32(alpn_len), cfg_handle
    )
    assert_equal_int(Int(rc_cfg), 0, "quic_client_config_new must succeed")
    assert_true(cfg_handle[0] >= Int32(0), "cfg handle must be non-negative")

    var sni_bytes = String("example.com").as_bytes()
    var sni_len = len(sni_bytes)
    var sni_buf = _heap_alloc[UInt8](sni_len).as_any_origin()
    for i in range(sni_len):
        sni_buf[i] = sni_bytes[i]

    # Empty transport-params buffer is acceptable for this test.
    var tp_buf = _heap_alloc[UInt8](1).as_any_origin()
    tp_buf[0] = UInt8(0)

    var conn_handle = _heap_alloc[Int32](1).as_any_origin()
    conn_handle[0] = Int32(-1)
    var rc_conn = lib.quic_client_conn_new(
        cfg_handle[0], Int32(1),  # version=1 (QUIC v1)
        sni_buf, Int32(sni_len),
        tp_buf, Int32(0),
        conn_handle,
    )
    assert_equal_int(Int(rc_conn), 0, "quic_client_conn_new must succeed")
    assert_true(conn_handle[0] >= Int32(0), "conn handle must be non-negative")

    var k = lib.quic_conn_handshake_kind(conn_handle[0])
    assert_equal_int(Int(k), -2, "client conn must return -2 from handshake_kind")

    _ = lib.quic_conn_free(conn_handle[0])
    alpn_buf.free()
    sni_buf.free()
    tp_buf.free()
    cfg_handle.free()
    conn_handle.free()


def _read_file_bytes(path: String) raises -> List[UInt8]:
    """Local helper: read a small text file (PEM) into List[UInt8].
    Mirrors patterns in existing tests under tests/ — keep self-contained."""
    var f = open(path, "r")
    var s = f.read()
    f.close()
    var bytes = s.as_bytes()
    var out = List[UInt8](capacity=len(bytes))
    for i in range(len(bytes)):
        out.append(bytes[i])
    return out^


def test_quic_server_config_new_accepts_max_early_data_param() raises:
    """Smoke test: rlsm_quic_server_config_new accepts the new max_early_data
    8th param (passed as 0). Direct read of ticketer is not exposed via FFI;
    success is signaled by rc == 0 and a non-negative handle."""
    var lib = RustlsLibrary()

    # Use the bench's self-signed test fixtures.
    var cert_pem = _read_file_bytes("certs/server.crt")
    var key_pem  = _read_file_bytes("certs/server.key")

    var alpn_bytes = String("h3").as_bytes()
    var alpn_len = len(alpn_bytes)

    var cert_buf = _heap_alloc[UInt8](len(cert_pem)).as_any_origin()
    for i in range(len(cert_pem)):
        cert_buf[i] = cert_pem[i]
    var key_buf = _heap_alloc[UInt8](len(key_pem)).as_any_origin()
    for i in range(len(key_pem)):
        key_buf[i] = key_pem[i]
    var alpn_buf = _heap_alloc[UInt8](alpn_len).as_any_origin()
    for i in range(alpn_len):
        alpn_buf[i] = alpn_bytes[i]
    var out_handle = _heap_alloc[Int32](1).as_any_origin()
    out_handle[0] = Int32(-1)

    var rc = lib.quic_server_config_new(
        cert_buf, Int32(len(cert_pem)),
        key_buf,  Int32(len(key_pem)),
        alpn_buf, Int32(alpn_len),
        Int32(0),                # max_early_data: 0 = 0-RTT disabled
        out_handle,
    )
    assert_equal_int(Int(rc), 0, "rc==0")
    assert_true(out_handle[0] >= Int32(0), "handle must be non-negative")

    cert_buf.free(); key_buf.free(); alpn_buf.free(); out_handle.free()


def main() raises:
    test_quic_handshake_kind_invalid_handle_returns_minus_one()
    test_quic_handshake_kind_client_returns_minus_two()
    test_quic_server_config_new_accepts_max_early_data_param()
