# conformance/tests/test_h2_connection_cross.mojo
#
# HC-4a: Cross-validation of H2Connection against Python h2.
#
# As of §3.3 of the dependency-enhancement plan, Python h2 is no longer
# imported at test runtime. Oracle outputs (h2 server preface, PING ACK
# bytes, expected event sequence) are pre-materialized into
# conformance/vectors/rfc9113/h2_states.json by
# conformance/scripts/oracle_h1_h2_states.py.
from lib.test_util import assert_true, assert_equal, hex_encode
from lib.http2.connection import (
    H2Connection,
    H2Config,
    H2Event,
    H2_EVT_SETTINGS_CHANGED,
    H2_EVT_SETTINGS_ACKNOWLEDGED,
    H2_EVT_PING_RECEIVED,
    H2_EVT_PING_ACKNOWLEDGED,
    H2_EVT_GOAWAY_RECEIVED,
    H2_EVT_CONNECTION_TERMINATED,
    H2_EVT_WINDOW_UPDATED,
)
from lib.http2.frame import (
    Frame,
    encode_frame,
    FRAME_SETTINGS,
    FRAME_PING,
    FRAME_GOAWAY,
    FLAG_ACK,
)
from lib.stateful_vectors import load_states, py_field_str, py_has_key
from std.python import Python, PythonObject


def _hex_val(b: UInt8) -> Int:
    var v = Int(b)
    if v >= 48 and v <= 57:
        return v - 48
    if v >= 97 and v <= 102:
        return v - 87
    if v >= 65 and v <= 70:
        return v - 55
    return 0


def _hex_to_bytes(hex_str: String) -> List[UInt8]:
    var result = List[UInt8]()
    var b = hex_str.as_bytes()
    var i = 0
    while i < len(hex_str):
        var hi = _hex_val(b[i])
        var lo = _hex_val(b[i + 1])
        result.append(UInt8(hi * 16 + lo))
        i += 2
    return result^


def test_cross_client_preface_accepted(states: PythonObject) raises:
    """h2 server accepts an HTTP/2 client preface (pre-materialized oracle).

    The oracle JSON contains the event sequence h2 emitted when fed the
    canonical client preface (24-byte magic + a SETTINGS frame). We assert
    only structural properties: >= 1 event, first event is
    RemoteSettingsChanged. The byte-level preface is not compared here
    since Mojo's H2Connection emits its own SETTINGS values; the
    `cross_server_preface_accepted` test below covers Mojo<-h2 byte parity.
    """
    var oracle = states["h2_server_receive_client_preface"]
    var err_field = py_field_str(oracle, "error")
    assert_true(len(err_field) == 0, "oracle has no error: " + err_field)

    var builtins = Python.import_module("builtins")
    var events = oracle["events"]
    var count = Int(py=builtins.len(events))
    assert_true(count >= 1, "h2 emitted >= 1 event for client preface, got " + String(count))
    var first_type = String(events[0]["type"])
    assert_true(
        first_type == String("RemoteSettingsChanged"),
        "first event type: " + first_type,
    )

    # Also sanity-check that our own H2Connection emits a non-empty client
    # preface — the oracle assumption.
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()
    assert_true(len(client_preface) > 0, "our client preface non-empty")
    print("  PASS: cross_client_preface_accepted")


def test_cross_server_preface_accepted(states: PythonObject) raises:
    """Our client accepts Python h2's server preface (pre-materialized)."""
    var preface_hex = py_field_str(states, "server_preface_after_empty_recv_hex")
    assert_true(len(preface_hex) > 0, "server preface present in oracle JSON")
    var h2_preface = _hex_to_bytes(preface_hex)

    var client = H2Connection(client_side=True)
    client.initiate_connection()
    _ = client.data_to_send()
    var events = client.receive_data(h2_preface)
    assert_true(len(events) >= 1, "our client got events from h2 preface")
    assert_equal(events[0].kind, H2_EVT_SETTINGS_CHANGED, "SETTINGS_CHANGED")
    print("  PASS: cross_server_preface_accepted")


def test_cross_ping(states: PythonObject) raises:
    """PING ACK bytes from our server match the pre-materialized h2 PING ACK.

    The PING ACK byte sequence is deterministic: 9-byte header (length=8,
    type=0x06, flags=0x01, stream_id=0) + the 8-byte payload echoed back.
    Whether h2 is fed our Mojo client preface or h2's own preface, the
    ACK bytes for the same PING payload are identical.
    """
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()

    var server = H2Connection(client_side=False)
    server.initiate_connection()
    _ = server.data_to_send()
    _ = server.receive_data(client_preface)
    _ = server.data_to_send()

    var ping_payload = List[UInt8]()
    ping_payload.append(UInt8(0x10))
    ping_payload.append(UInt8(0x20))
    ping_payload.append(UInt8(0x30))
    ping_payload.append(UInt8(0x40))
    ping_payload.append(UInt8(0x50))
    ping_payload.append(UInt8(0x60))
    ping_payload.append(UInt8(0x70))
    ping_payload.append(UInt8(0x80))
    var ping_frame = Frame(8, FRAME_PING, 0, 0, ping_payload)
    var ping_wire = encode_frame(ping_frame)

    var our_events = server.receive_data(ping_wire)
    var our_response = server.data_to_send()

    var oracle = states["ping_oracle"]
    var err_field = py_field_str(oracle, "error")
    assert_true(len(err_field) == 0, "oracle ping has no error: " + err_field)

    assert_true(len(our_events) >= 1, "our server got event")
    assert_equal(our_events[0].kind, H2_EVT_PING_RECEIVED, "our PingReceived")

    var builtins = Python.import_module("builtins")
    var oracle_events = oracle["events"]
    var oracle_count = Int(py=builtins.len(oracle_events))
    assert_true(oracle_count >= 1, "oracle got event")
    var oracle_type = String(oracle_events[0]["type"])
    assert_true(oracle_type == String("PingReceived"), "oracle PingReceived: " + oracle_type)

    var our_hex = hex_encode(our_response)
    var oracle_hex = py_field_str(oracle, "data_to_send_hex")
    assert_true(
        our_hex == oracle_hex,
        "PING ACK bytes match: our=" + our_hex + " oracle=" + oracle_hex,
    )
    print("  PASS: cross_ping")


def main() raises:
    var states = load_states("vectors/rfc9113/h2_states.json")
    test_cross_client_preface_accepted(states)
    test_cross_server_preface_accepted(states)
    test_cross_ping(states)
    print("test_h2_connection_cross: 3 tests passed")
