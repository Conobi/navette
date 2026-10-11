# tests/tls/test_tls_boundaries_existing_api.mojo
"""Red Gate (existing API): large TLS transfers at any split must arrive intact.

On main, `receive_data` raises "received plaintext buffer full" once more
than 16 KiB of plaintext is pending, and `send_data` drops everything past
rustls's 64 KiB send buffer. Failures surface as assertions, never raises.
"""
from std.collections import Span
from navette.tls import TlsBackend, TlsClientConfig, TlsServerConfig, TlsConnection
from tests._test_util import assert_true, load_test_cert
from tests._split_harness import (
    SplitPlan, split_plans, payload, boundary_sizes, assert_bytes_equal,
    tls_probe_layout,
)
from tests.tls._tls_pair import tls_handshake, sealed, sealed_records


def _transfer_case(
    tls: TlsBackend, cli_cfg: TlsClientConfig, srv_cfg: TlsServerConfig,
    size: Int, plan: SplitPlan, server_to_client: Bool, lazy: Bool, seed: UInt64,
    ct_len: Int,
) raises:
    """Fresh pair (shared backend and configs); seal `size` bytes on one side;
    feed per `plan` on the other."""
    var client = TlsConnection.new_client(tls.shared(), cli_cfg, "localhost")
    var server = TlsConnection.new_server(tls.shared(), srv_cfg)
    tls_handshake(client, server)
    var data = payload(size, seed)
    var label = (
        "size=" + String(size) + (" s->c" if server_to_client else " c->s")
        + (" lazy" if lazy else " eager") + " plan=" + plan.label
    )
    var ct = sealed(server, data) if server_to_client else sealed(client, data)
    assert_true(len(ct) == ct_len, label + ": ciphertext length changed between pairs")
    var got = List[Byte]()
    var off = 0
    for i in range(len(plan.chunks)):
        var n = plan.chunks[i]
        try:
            if server_to_client:
                client.receive_data(Span(ct)[off:off + n])
                if not lazy:
                    client.drain_plaintext_into(got)
            else:
                server.receive_data(Span(ct)[off:off + n])
                if not lazy:
                    server.drain_plaintext_into(got)
        except e:
            assert_true(False, label + ": receive_data raised: " + String(e))
        off += n
    try:
        if server_to_client:
            client.drain_plaintext_into(got)
        else:
            server.drain_plaintext_into(got)
    except e:
        assert_true(False, label + ": drain raised: " + String(e))
    assert_bytes_equal(got, data, label)
    _ = client^
    _ = server^


def _ct_len(
    tls: TlsBackend, cli_cfg: TlsClientConfig, srv_cfg: TlsServerConfig,
    size: Int, server_to_client: Bool, seed: UInt64,
) raises -> Int:
    """Ciphertext length for `size` bytes (record overhead is deterministic)."""
    var client = TlsConnection.new_client(tls.shared(), cli_cfg, "localhost")
    var server = TlsConnection.new_server(tls.shared(), srv_cfg)
    tls_handshake(client, server)
    var data = payload(size, seed)
    var n = len(sealed(server, data)) if server_to_client else len(sealed(client, data))
    _ = client^
    _ = server^
    return n


def _probe_layout_case() raises:
    """The probe's failing record layout, fed whole and drained lazily."""
    var tls = TlsBackend()
    var pem = load_test_cert()
    var cert_pem = pem[0].copy()
    var key_pem = pem[1].copy()
    var cli_cfg = TlsClientConfig(tls.shared(), insecure=True)
    var srv_cfg = TlsServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    var client = TlsConnection.new_client(tls.shared(), cli_cfg, "localhost")
    var server = TlsConnection.new_server(tls.shared(), srv_cfg)
    tls_handshake(client, server)
    var layout = tls_probe_layout()
    var size = 0
    for i in range(len(layout)):
        size += layout[i]
    var data = payload(size, UInt64(size))
    var ct = sealed_records(server, data, layout)
    var label = "probe layout size=" + String(size) + " s->c lazy plan=whole"
    var got = List[Byte]()
    try:
        client.receive_data(Span(ct))
        client.drain_plaintext_into(got)
    except e:
        assert_true(False, label + ": receive_data raised: " + String(e))
    assert_bytes_equal(got, data, label)
    _ = client^
    _ = server^
    _ = cli_cfg^
    _ = srv_cfg^
    _ = tls^


def test_receive_sizes_and_splits() raises:
    """One backend and config pair for the whole sweep (setup dominated the
    run time); every case still gets a fresh connection pair."""
    _probe_layout_case()
    var tls = TlsBackend()
    var pem = load_test_cert()
    var cert_pem = pem[0].copy()
    var key_pem = pem[1].copy()
    var cli_cfg = TlsClientConfig(tls.shared(), insecure=True)
    var srv_cfg = TlsServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    var sizes = boundary_sizes()
    for si in range(len(sizes)):
        var size = sizes[si]
        if size == 0:
            continue
        for d in range(2):
            var s2c = d == 0
            var seed = UInt64(size * 2 + d)
            var ct_len = _ct_len(tls, cli_cfg, srv_cfg, size, s2c, seed)
            var plans = split_plans(ct_len, seed, sampled=8, randoms=4)
            for p in range(len(plans)):
                _transfer_case(tls, cli_cfg, srv_cfg, size, plans[p], s2c, False, seed, ct_len)
                _transfer_case(tls, cli_cfg, srv_cfg, size, plans[p], s2c, True, seed, ct_len)
    _ = cli_cfg^
    _ = srv_cfg^
    _ = tls^


def test_send_sizes_complete() raises:
    """One `send_data` call of 64 KiB + 1 and 1 MiB must deliver every byte."""
    var sizes: List[Int] = [65537, 1 << 20]
    for si in range(len(sizes)):
        var size = sizes[si]
        var tls = TlsBackend()
        var pem = load_test_cert()
        var cert_pem = pem[0].copy()
        var key_pem = pem[1].copy()
        var cli_cfg = TlsClientConfig(tls.shared(), insecure=True)
        var srv_cfg = TlsServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
        var client = TlsConnection.new_client(tls.shared(), cli_cfg, "localhost")
        var server = TlsConnection.new_server(tls.shared(), srv_cfg)
        tls_handshake(client, server)
        var data = payload(size, UInt64(size))
        var label = "send size=" + String(size)
        try:
            server.send_data(Span(data))
        except e:
            assert_true(False, label + ": send_data raised: " + String(e))
        var ct = server.drain_ciphertext()
        var got = List[Byte]()
        var off = 0
        while off < len(ct):
            var end = min(off + 4096, len(ct))
            try:
                client.receive_data(Span(ct)[off:end])
                client.drain_plaintext_into(got)
            except e:
                assert_true(False, label + ": receive raised: " + String(e))
            off = end
        assert_bytes_equal(got, data, label)
        _ = client^
        _ = server^
        _ = cli_cfg^
        _ = srv_cfg^
        _ = tls^


def main() raises:
    var passed = 0
    var names: List[String] = ["test_receive_sizes_and_splits", "test_send_sizes_complete"]
    for i in range(len(names)):
        try:
            if i == 0:
                test_receive_sizes_and_splits()
            else:
                test_send_sizes_complete()
            print("PASS: " + names[i])
            passed += 1
        except e:
            print("FAIL: " + names[i] + ": " + String(e))
    print("test_tls_boundaries_existing_api: " + String(passed) + "/2 passed")
    if passed != 2:
        raise "some tls boundary tests failed"
