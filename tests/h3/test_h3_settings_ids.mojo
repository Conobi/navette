"""SETTINGS identifiers a peer is not allowed to send close the connection (RFC 9114 Sections 7.2.4, 7.2.4.1).

Each case writes the client's control stream straight into a server
H3Connection and reads the close it queued.
"""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.frame import StreamFrame
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.h3.connection import H3Connection, H3_MAX_FIELD_SECTION_SIZE
from navette.h3.frame import (
    SettingsFrame,
    SettingsPair,
    SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    SETTINGS_MAX_FIELD_SECTION_SIZE,
    SETTINGS_H3_DATAGRAM,
)
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca


def _params() -> TransportParams:
    var p = default_transport_params()
    p.initial_max_data = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_remote = UInt64(65_536)
    p.initial_max_stream_data_uni = UInt64(65_536)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


def _server(tls: TlsBackend) raises -> H3Connection:
    var ck = load_test_cert()
    var cert = ck[0].copy()
    var key = ck[1].copy()
    var ca = load_test_ca()
    var scfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
    var ccfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(tls.shared(), ccfg, "localhost", _params(), now)
    var orig = List[Byte](client.initial_dcid.as_span())
    var orig2 = orig.copy()
    return H3Connection.server(QuicConnection.server(tls.shared(), scfg, _params(), Span(orig), Span(orig2), now))


def _settings(ids_values: List[UInt8]) -> List[Byte]:
    """A SETTINGS frame of 1-byte varint (id, value) pairs."""
    var f = List[Byte]()
    f.append(0x04)
    f.append(UInt8(len(ids_values)))
    f.extend(Span(ids_values))
    return f^


def _control_close_code(var frames: List[Byte]) raises -> Int:
    """Feed a client control stream (type 0x00 then `frames`) to a fresh server; the close code it queued, -1 if none."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var h3 = _server(tls)
    var stream = List[Byte]()
    stream.append(0x00)  # control stream type
    stream.extend(Span(frames))
    h3._quic._handle_stream_frame(StreamFrame(UInt64(2), UInt64(0), List[Byte](), False), Span(stream))
    h3._poll_quic_events(UInt64(1_000_000))
    var code = -1
    if h3._quic.close.pending:
        code = Int(h3._quic.close.pending.value().error_code)
    _ = tls^
    return code


def test_normal_settings_pass() raises:
    assert_equal_int(_control_close_code(_settings([0x01, 0x00, 0x06, 0x20, 0x21, 0x07])), -1, "known and unknown ids accepted")
    print("  test_normal_settings_pass: PASS")


def test_duplicate_id_is_settings_error() raises:
    assert_equal_int(_control_close_code(_settings([0x06, 0x20, 0x06, 0x21])), 0x0109, "duplicate id")
    print("  test_duplicate_id_is_settings_error: PASS")


def test_http2_ids_are_settings_error() raises:
    for id in [0x00, 0x02, 0x03, 0x04, 0x05]:
        assert_equal_int(
            _control_close_code(_settings([UInt8(id), 0x01])), 0x0109, "HTTP/2 id " + String(id)
        )
    print("  test_http2_ids_are_settings_error: PASS")


def _local_control_bytes(datagrams: Bool) raises -> List[Byte]:
    """Bytes a fresh server queues on its control stream; checks the QPACK stream types too."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var h3 = _server(tls)
    if datagrams:
        h3.enable_h3_datagrams()
    h3._quic.stream_map.peer_max_streams_uni = UInt64(3)
    h3._bootstrap_local_streams(UInt64(1_000_000))
    var sids = [h3._local_ctrl_sid.value(), h3._local_qenc_sid.value(), h3._local_qdec_sid.value()]
    for i in range(1, 3):
        var p = h3._quic.stream_map.stream_ptr(Int(sids[i]))
        ref d = p[].send_buf.value().data
        assert_true(len(d) == 1 and d[0] == UInt8(i + 1), "QPACK stream type byte")
    var p = h3._quic.stream_map.stream_ptr(Int(sids[0]))
    var out = p[].send_buf.value().data.copy()
    _ = h3._quic.stream_map.streams
    _ = tls^
    return out^


def test_local_settings_bytes() raises:
    """The control stream carries type 0x00 then the same SETTINGS frame SettingsFrame encodes."""
    for dg in range(2):
        var pairs = List[SettingsPair]()
        pairs.append(SettingsPair(SETTINGS_QPACK_MAX_TABLE_CAPACITY, UInt64(0)))
        pairs.append(SettingsPair(SETTINGS_MAX_FIELD_SECTION_SIZE, UInt64(H3_MAX_FIELD_SECTION_SIZE)))
        if dg == 1:
            pairs.append(SettingsPair(SETTINGS_H3_DATAGRAM, UInt64(1)))
        var want: List[Byte] = [0x00]
        SettingsFrame(pairs^).encode(want)
        var got = _local_control_bytes(dg == 1)
        assert_equal_int(len(got), len(want), "control stream length")
        for i in range(len(want)):
            assert_equal_int(Int(got[i]), Int(want[i]), "control stream byte " + String(i))
    print("  test_local_settings_bytes: PASS")


def main() raises:
    print("test_h3_settings_ids:")
    test_normal_settings_pass()
    test_duplicate_id_is_settings_error()
    test_http2_ids_are_settings_error()
    test_local_settings_bytes()
    print("All test_h3_settings_ids tests passed.")
