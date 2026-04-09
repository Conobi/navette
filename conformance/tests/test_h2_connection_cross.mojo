# conformance/tests/test_h2_connection_cross.mojo
#
# HC-4a: Cross-validation of H2Connection against Python h2.
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
from lib.http2.oracles import h2_server_receive, h2_client_receive, h2_ping_scenario
from std.python import Python, PythonObject


def _has_key(obj: PythonObject, key: String) -> Bool:
    try:
        var builtins = Python.import_module("builtins")
        return Bool(builtins.bool(key in obj))
    except:
        return False


def _oracle_error(result: PythonObject) -> String:
    try:
        if _has_key(result, "error"):
            var err = result["error"]
            var builtins = Python.import_module("builtins")
            if Bool(builtins.bool(err is builtins.None)):
                return String("")
            return String(err)
        return String("")
    except:
        return String("(failed to read oracle error)")


def _hex_val(b: UInt8) -> Int:
    """Convert hex ASCII byte to value."""
    var v = Int(b)
    if v >= 48 and v <= 57:
        return v - 48
    if v >= 97 and v <= 102:
        return v - 87
    if v >= 65 and v <= 70:
        return v - 55
    return 0


def _hex_to_bytes(hex_str: String) -> List[UInt8]:
    """Convert hex string to byte list."""
    var result = List[UInt8]()
    var b = hex_str.as_bytes()
    var i = 0
    while i < len(hex_str):
        var hi = _hex_val(b[i])
        var lo = _hex_val(b[i + 1])
        result.append(UInt8(hi * 16 + lo))
        i += 2
    return result^


def test_cross_client_preface_accepted() raises:
    """Python h2 server accepts our client preface."""
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()

    var oracle = h2_server_receive(client_preface)
    var err = _oracle_error(oracle)
    assert_true(len(err) == 0, "h2 server accepted our client preface: " + err)

    # h2 should emit RemoteSettingsChanged
    var builtins = Python.import_module("builtins")
    var events = oracle["events"]
    var count = Int(py=builtins.len(events))
    assert_true(count >= 1, "h2 emitted >= 1 event, got " + String(count))
    var first_type = String(events[0]["type"])
    assert_true(first_type == String("RemoteSettingsChanged"), "first event type: " + first_type)
    print("  PASS: cross_client_preface_accepted")


def test_cross_server_preface_accepted() raises:
    """Our client accepts Python h2's server preface."""
    # Get h2's server preface via oracle (feed empty bytes, just get the preface)
    var oracle = h2_server_receive(List[UInt8]())
    var preface_hex = String(oracle["preface_hex"])
    var h2_preface = _hex_to_bytes(preface_hex)

    # Feed to our client
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    _ = client.data_to_send()
    var events = client.receive_data(h2_preface)
    assert_true(len(events) >= 1, "our client got events from h2 preface")
    assert_equal(events[0].kind, H2_EVT_SETTINGS_CHANGED, "SETTINGS_CHANGED")
    print("  PASS: cross_server_preface_accepted")


def test_cross_ping() raises:
    """PING frame produces matching responses from our server and h2."""
    # Get our client preface for establishing both connections
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()

    # Establish our server
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    _ = server.data_to_send()
    _ = server.receive_data(client_preface)
    _ = server.data_to_send()

    # Build PING frame
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

    # Feed to our server
    var our_events = server.receive_data(ping_wire)
    var our_response = server.data_to_send()

    # Feed to h2 server via oracle (need fresh client preface for the oracle)
    var client2 = H2Connection(client_side=True)
    client2.initiate_connection()
    var cp2 = client2.data_to_send()
    # Rebuild PING wire for oracle (can't reuse — it was consumed)
    var ping_payload2 = List[UInt8]()
    ping_payload2.append(UInt8(0x10))
    ping_payload2.append(UInt8(0x20))
    ping_payload2.append(UInt8(0x30))
    ping_payload2.append(UInt8(0x40))
    ping_payload2.append(UInt8(0x50))
    ping_payload2.append(UInt8(0x60))
    ping_payload2.append(UInt8(0x70))
    ping_payload2.append(UInt8(0x80))
    var ping_frame2 = Frame(8, FRAME_PING, 0, 0, ping_payload2)
    var ping_wire2 = encode_frame(ping_frame2)
    var oracle = h2_ping_scenario(cp2, ping_wire2)
    var err = _oracle_error(oracle)
    assert_true(len(err) == 0, "h2 accepted PING: " + err)

    # Compare events: both should have PingReceived
    assert_true(len(our_events) >= 1, "our server got event")
    assert_equal(our_events[0].kind, H2_EVT_PING_RECEIVED, "our PingReceived")

    var builtins = Python.import_module("builtins")
    var oracle_events = oracle["events"]
    var oracle_count = Int(py=builtins.len(oracle_events))
    assert_true(oracle_count >= 1, "oracle got event")
    var oracle_type = String(oracle_events[0]["type"])
    assert_true(oracle_type == String("PingReceived"), "oracle PingReceived: " + oracle_type)

    # Compare PING ACK response bytes (should be identical)
    var our_hex = hex_encode(our_response)
    var oracle_hex = String(oracle["data_to_send_hex"])
    assert_true(our_hex == oracle_hex, "PING ACK bytes match: our=" + our_hex + " oracle=" + oracle_hex)
    print("  PASS: cross_ping")


def main() raises:
    test_cross_client_preface_accepted()
    test_cross_server_preface_accepted()
    test_cross_ping()
    print("test_h2_connection_cross: 3 tests passed")
