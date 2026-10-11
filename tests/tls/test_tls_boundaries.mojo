# tests/tls/test_tls_boundaries.mojo
"""Step API, end-of-stream and empty-input contract of TlsConnection."""
from std.collections import Span
from navette.tls import (
    TlsBackend, TlsClientConfig, TlsServerConfig, TlsConnection,
    TlsStep, TlsStepStatus, TlsEof,
)
from tests._test_util import assert_true, assert_equal_int, load_test_cert
from tests._split_harness import payload, assert_bytes_equal, TLS_PROBE_MIN_A, MAX_DRIVE_ITERS
from tests.tls._tls_pair import tls_handshake, sealed


def _recv_step(mut conn: TlsConnection, ct: Span[Byte, _], label: String) raises -> TlsStep:
    """`receive_data_step` whose raise becomes an assertion failure: the step
    must never raise for backpressure."""
    try:
        return conn.receive_data_step(ct)
    except e:
        assert_true(False, label + ": step raised: " + String(e))
        return TlsStep(consumed=0, status=TlsStepStatus.COMPLETE)


def _recv_all(mut conn: TlsConnection, ct: Span[Byte, _], label: String) raises:
    """`receive_data` whose raise becomes an assertion failure."""
    try:
        conn.receive_data(ct)
    except e:
        assert_true(False, label + ": receive_data raised: " + String(e))


def test_step_priority_close_notify_last_and_drain_pending() raises:
    """NEEDS_DRAIN half (close_notify half lives in test_read_tls_stops.rs):
    a step that consumes everything but leaves > 16 KiB pending says NEEDS_DRAIN."""
    var tls = TlsBackend()
    var pem = load_test_cert()
    var cc = TlsClientConfig(tls.shared(), insecure=True)
    var cert_pem = pem[0].copy()
    var key_pem = pem[1].copy()
    var sc = TlsServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    var client = TlsConnection.new_client(tls.shared(), cc, "localhost")
    var server = TlsConnection.new_server(tls.shared(), sc)
    tls_handshake(client, server)
    var data = payload(16384 + 100, UInt64(9))
    var ct = sealed(server, data)
    var off = 0
    var saw_drain = False
    for _ in range(MAX_DRIVE_ITERS):
        if off >= len(ct):
            break
        var step = _recv_step(client, Span(ct)[off:], "drain-pending step")
        off += step.consumed
        if step.status == TlsStepStatus.NEEDS_DRAIN:
            saw_drain = True
            break
    assert_true(saw_drain, "no NEEDS_DRAIN with > 16 KiB pending")
    _ = client^
    _ = server^
    _ = cc^
    _ = sc^
    _ = tls^


def test_lazy_drain_across_calls_returns_needs_drain() raises:
    """After a call that left > 16 KiB pending, the next step stops on entry."""
    var tls = TlsBackend()
    var pem = load_test_cert()
    var cc = TlsClientConfig(tls.shared(), insecure=True)
    var cert_pem = pem[0].copy()
    var key_pem = pem[1].copy()
    var sc = TlsServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    var client = TlsConnection.new_client(tls.shared(), cc, "localhost")
    var server = TlsConnection.new_server(tls.shared(), sc)
    tls_handshake(client, server)
    var first = sealed(server, payload(16384 + 200, UInt64(1)))
    var second = sealed(server, payload(1000, UInt64(2)))
    var s1 = _recv_step(client, Span(first), "first step")
    assert_equal_int(s1.consumed, len(first), "first chunk fully consumed")
    assert_true(s1.status == TlsStepStatus.NEEDS_DRAIN, "first step must report NEEDS_DRAIN")
    var s2 = _recv_step(client, Span(second), "second step")
    assert_equal_int(s2.consumed, 0, "entry check must consume nothing")
    assert_true(s2.status == TlsStepStatus.NEEDS_DRAIN, "entry check must report NEEDS_DRAIN")
    _ = client^
    _ = server^
    _ = cc^
    _ = sc^
    _ = tls^


def test_send_step_64k_boundaries() raises:
    var sizes: List[Int] = [65535, 65536, 65537]
    for i in range(len(sizes)):
        var tls = TlsBackend()
        var pem = load_test_cert()
        var cc = TlsClientConfig(tls.shared(), insecure=True)
        var cert_pem = pem[0].copy()
        var key_pem = pem[1].copy()
        var sc = TlsServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
        var client = TlsConnection.new_client(tls.shared(), cc, "localhost")
        var server = TlsConnection.new_server(tls.shared(), sc)
        tls_handshake(client, server)
        var data = payload(sizes[i], UInt64(sizes[i]))
        var step = server.send_data_step(Span(data))
        var label = "send_data_step size=" + String(sizes[i])
        if sizes[i] > 65536:
            assert_true(step.status == TlsStepStatus.NEEDS_FLUSH, label + ": expected NEEDS_FLUSH")
            assert_true(step.consumed < sizes[i] and step.consumed > 0, label + ": partial acceptance")
        else:
            assert_true(step.status == TlsStepStatus.COMPLETE, label + ": expected COMPLETE")
            assert_equal_int(step.consumed, sizes[i], label + ": all accepted")
        _ = client^
        _ = server^
        _ = cc^
        _ = sc^
        _ = tls^


def test_send_zero_length() raises:
    var tls = TlsBackend()
    var pem = load_test_cert()
    var cc = TlsClientConfig(tls.shared(), insecure=True)
    var cert_pem = pem[0].copy()
    var key_pem = pem[1].copy()
    var sc = TlsServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    var client = TlsConnection.new_client(tls.shared(), cc, "localhost")
    var server = TlsConnection.new_server(tls.shared(), sc)
    tls_handshake(client, server)
    var empty = List[Byte]()
    var step = server.send_data_step(Span(empty))
    assert_equal_int(step.consumed, 0, "zero-length step consumes nothing")
    assert_true(step.status == TlsStepStatus.COMPLETE, "zero-length step is COMPLETE")
    server.send_data(Span(empty))
    assert_true(not server.wants_write(), "zero-length send produces no ciphertext")
    _ = client^
    _ = server^
    _ = cc^
    _ = sc^
    _ = tls^


def test_send_while_handshaking() raises:
    """<= 64 KiB is buffered until the handshake ends; > 64 KiB: the step
    takes nothing once rustls's pre-handshake buffer is full and the wrapper raises."""
    var tls = TlsBackend()
    var pem = load_test_cert()
    var cc = TlsClientConfig(tls.shared(), insecure=True)
    var cert_pem = pem[0].copy()
    var key_pem = pem[1].copy()
    var sc = TlsServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    var client = TlsConnection.new_client(tls.shared(), cc, "localhost")
    var server = TlsConnection.new_server(tls.shared(), sc)
    var small = payload(1000, UInt64(3))
    client.send_data(Span(small))
    tls_handshake(client, server)
    var ct = client.drain_ciphertext()
    server.receive_data(Span(ct))
    var got = server.drain_plaintext()
    assert_bytes_equal(got, small, "pre-handshake send delivered after handshake")
    var client2 = TlsConnection.new_client(tls.shared(), cc, "localhost")
    var big = payload(65536 * 2, UInt64(4))
    var first = client2.send_data_step(Span(big))
    assert_true(first.consumed < len(big), "pre-handshake step must stop short of 128 KiB")
    assert_true(first.status == TlsStepStatus.NEEDS_FLUSH, "first pre-handshake step is NEEDS_FLUSH")
    var rest = Span(big)[first.consumed:]
    var second = client2.send_data_step(rest)
    assert_equal_int(second.consumed, 0, "full pre-handshake buffer takes nothing")
    assert_true(second.status == TlsStepStatus.NEEDS_FLUSH, "full pre-handshake buffer is NEEDS_FLUSH")
    var raised = False
    try:
        client2.send_data(rest)
    except e:
        raised = "no progress" in String(e)
    assert_true(raised, "wrapper must raise on a full pre-handshake buffer")
    _ = client2^
    _ = client^
    _ = server^
    _ = cc^
    _ = sc^
    _ = tls^


def _eof_case(size: Int) raises:
    """`size` bytes pending at a bare EOF survive; later input raises."""
    var label = "pending=" + String(size)
    var tls = TlsBackend()
    var pem = load_test_cert()
    var cc = TlsClientConfig(tls.shared(), insecure=True)
    var cert_pem = pem[0].copy()
    var key_pem = pem[1].copy()
    var sc = TlsServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    var client = TlsConnection.new_client(tls.shared(), cc, "localhost")
    var server = TlsConnection.new_server(tls.shared(), sc)
    tls_handshake(client, server)
    var data = payload(size, UInt64(5))
    var ct = sealed(server, data)
    _recv_all(client, Span(ct), label + " receive")
    client.receive_eof()
    client.receive_eof()
    assert_true(client.eof_state() == TlsEof.UNCLEAN, label + ": bare EOF is UNCLEAN")
    var got = client.drain_plaintext()
    assert_bytes_equal(got, data, label + ": plaintext pending at EOF survives")
    var raised = False
    try:
        client.receive_data(Span(data))
    except e:
        raised = "data after EOF" in String(e)
    assert_true(raised, label + ": receive_data after receive_eof must raise")
    var step_raised = False
    try:
        _ = client.receive_data_step(Span(data))
    except e:
        step_raised = "data after EOF" in String(e)
    assert_true(step_raised, label + ": receive_data_step after receive_eof must raise")
    _ = client^
    _ = server^
    _ = cc^
    _ = sc^
    _ = tls^


def test_receive_eof_pending_and_idempotent() raises:
    """Under 16 KiB pending isolates the EOF contract; 40000 adds the stash."""
    _eof_case(10000)
    _eof_case(40000)


def test_tcp_eof_during_handshake() raises:
    var tls = TlsBackend()
    var cc = TlsClientConfig(tls.shared(), insecure=True)
    var client = TlsConnection.new_client(tls.shared(), cc, "localhost")
    client.receive_eof()
    assert_true(client.eof_state() == TlsEof.UNCLEAN, "EOF during handshake is UNCLEAN")
    assert_true(client.is_handshaking(), "handshake never completes")
    _ = client^
    _ = cc^
    _ = tls^


def test_close_and_alert_edges() raises:
    """A corrupted record after valid data: data kept, step raises, alert queued."""
    var tls = TlsBackend()
    var pem = load_test_cert()
    var cc = TlsClientConfig(tls.shared(), insecure=True)
    var cert_pem = pem[0].copy()
    var key_pem = pem[1].copy()
    var sc = TlsServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    var client = TlsConnection.new_client(tls.shared(), cc, "localhost")
    var server = TlsConnection.new_server(tls.shared(), sc)
    tls_handshake(client, server)
    var good = payload(500, UInt64(6))
    var ct = sealed(server, good)
    var bad = sealed(server, payload(500, UInt64(7)))
    bad[len(bad) - 1] = bad[len(bad) - 1] ^ 0xFF
    ct.extend(Span(bad))
    var raised = False
    try:
        _ = client.receive_data_step(Span(ct))
    except:
        raised = True
    assert_true(raised, "corrupted record must raise")
    assert_true(client.wants_write(), "fatal alert queued for the peer")
    var got = client.drain_plaintext()
    assert_bytes_equal(got, good, "data before the bad record kept")
    _ = client^
    _ = server^
    _ = cc^
    _ = sc^
    _ = tls^


def test_empty_inputs() raises:
    var tls = TlsBackend()
    var pem = load_test_cert()
    var cc = TlsClientConfig(tls.shared(), insecure=True)
    var cert_pem = pem[0].copy()
    var key_pem = pem[1].copy()
    var sc = TlsServerConfig(tls.shared(), Span(cert_pem), Span(key_pem))
    var client = TlsConnection.new_client(tls.shared(), cc, "localhost")
    var server = TlsConnection.new_server(tls.shared(), sc)
    tls_handshake(client, server)
    var empty = List[Byte]()
    var step = client.receive_data_step(Span(empty))
    assert_equal_int(step.consumed, 0, "empty step consumes nothing")
    assert_true(step.status == TlsStepStatus.COMPLETE, "empty step is COMPLETE")
    client.receive_data(Span(empty))
    assert_equal_int(len(client.drain_plaintext()), 0, "no plaintext from empty input")
    _ = client^
    _ = server^
    _ = cc^
    _ = sc^
    _ = tls^


def main() raises:
    var passed = 0
    var total = 9
    var names: List[String] = [
        "test_step_priority_close_notify_last_and_drain_pending",
        "test_lazy_drain_across_calls_returns_needs_drain",
        "test_send_step_64k_boundaries", "test_send_zero_length",
        "test_send_while_handshaking", "test_receive_eof_pending_and_idempotent",
        "test_tcp_eof_during_handshake", "test_close_and_alert_edges", "test_empty_inputs",
    ]
    for i in range(total):
        try:
            if i == 0: test_step_priority_close_notify_last_and_drain_pending()
            elif i == 1: test_lazy_drain_across_calls_returns_needs_drain()
            elif i == 2: test_send_step_64k_boundaries()
            elif i == 3: test_send_zero_length()
            elif i == 4: test_send_while_handshaking()
            elif i == 5: test_receive_eof_pending_and_idempotent()
            elif i == 6: test_tcp_eof_during_handshake()
            elif i == 7: test_close_and_alert_edges()
            else: test_empty_inputs()
            print("PASS: " + names[i])
            passed += 1
        except e:
            print("FAIL: " + names[i] + ": " + String(e))
    print("test_tls_boundaries: " + String(passed) + "/" + String(total) + " passed")
    if passed != total:
        raise "some tls step tests failed"
