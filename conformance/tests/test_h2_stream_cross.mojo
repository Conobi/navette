# conformance/tests/test_h2_stream_cross.mojo
#
# HC-4b: Stream-level cross-validation against Python h2.
#
# As of §3.3 of the dependency-enhancement plan, Python h2 is no longer
# imported at test runtime. Oracle outputs (request headers, DataReceived
# flow_controlled_length) are pre-materialized into
# conformance/vectors/rfc9113/h2_states.json by
# conformance/scripts/oracle_h1_h2_states.py.
from lib.test_util import assert_true, assert_equal
from lib.http2.connection import (
    H2Config,
    H2Event,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_RESPONSE_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
    H2_EVT_SETTINGS_CHANGED,
    H2_EVT_SETTINGS_ACKNOWLEDGED,
    STREAM_CLOSED,
    H2Connection,
)
from lib.http2.frame import H2_NO_ERROR, H2_CANCEL
from lib.stateful_vectors import load_states, py_field_str
from lib.http1.types import Header
from std.python import Python, PythonObject


def test_cross_roundtrip_headers_match(states: PythonObject) raises:
    """Our H2Connection and Python h2 produce matching request headers."""
    var oracle = states["roundtrip"]
    var err = py_field_str(oracle, "error")
    assert_true(len(err) == 0, "oracle no error: " + err)

    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    var server_preface = server.data_to_send()
    _ = client.receive_data(server_preface)
    var client_ack = client.data_to_send()
    _ = server.receive_data(client_preface)
    var server_ack = server.data_to_send()
    _ = client.receive_data(server_ack)
    _ = client.data_to_send()
    _ = server.receive_data(client_ack)
    _ = server.data_to_send()

    var req_headers = List[Header]()
    req_headers.append(Header(":method", "GET"))
    req_headers.append(Header(":path", "/"))
    req_headers.append(Header(":scheme", "https"))
    req_headers.append(Header(":authority", "example.com"))
    client.send_headers(UInt32(1), req_headers^, end_stream=True)
    var request_wire = client.data_to_send()
    var srv_events = server.receive_data(request_wire)
    _ = server.data_to_send()

    # Compare: both should have RequestReceived with matching headers
    var oracle_srv_events = oracle["server_events"]
    var builtins = Python.import_module("builtins")
    var our_req_found = False
    for i in range(len(srv_events)):
        if srv_events[i].kind == H2_EVT_REQUEST_RECEIVED:
            our_req_found = True
            for j in range(Int(py=builtins.len(oracle_srv_events))):
                if String(oracle_srv_events[j]["type"]) == "RequestReceived":
                    var oracle_headers = oracle_srv_events[j]["headers"]
                    assert_equal(
                        len(srv_events[i].headers),
                        Int(py=builtins.len(oracle_headers)),
                        "header count match",
                    )
                    for k in range(len(srv_events[i].headers)):
                        assert_true(
                            srv_events[i].headers[k].name == String(oracle_headers[k][0]),
                            "header name " + String(k),
                        )
                        assert_true(
                            srv_events[i].headers[k].value == String(oracle_headers[k][1]),
                            "header value " + String(k),
                        )
    assert_true(our_req_found, "our server emitted RequestReceived")


def test_cross_data_flow_controlled_length(states: PythonObject) raises:
    """DataReceived flow_controlled_length matches Python h2."""
    var oracle = states["stream_data_100_A"]
    var err = py_field_str(oracle, "error")
    assert_true(len(err) == 0, "oracle no error: " + err)

    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    var server_preface = server.data_to_send()
    _ = client.receive_data(server_preface)
    var client_ack = client.data_to_send()
    _ = server.receive_data(client_preface)
    var server_ack = server.data_to_send()
    _ = client.receive_data(server_ack)
    _ = client.data_to_send()
    _ = server.receive_data(client_ack)
    _ = server.data_to_send()

    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "example.com"))
    client.send_headers(UInt32(1), headers^, end_stream=False)
    _ = client.data_to_send()
    var body = List[UInt8]()
    for _ in range(100):
        body.append(UInt8(0x41))
    client.send_data(UInt32(1), body, end_stream=True)
    var request_wire = client.data_to_send()
    var srv_events = server.receive_data(request_wire)

    var oracle_events = oracle["events"]
    var builtins = Python.import_module("builtins")
    for i in range(len(srv_events)):
        if srv_events[i].kind == H2_EVT_DATA_RECEIVED:
            for j in range(Int(py=builtins.len(oracle_events))):
                if String(oracle_events[j]["type"]) == "DataReceived":
                    assert_equal(
                        srv_events[i].flow_controlled_length,
                        Int(py=oracle_events[j]["flow_controlled_length"]),
                        "flow_controlled_length match",
                    )
                    assert_equal(len(srv_events[i].data), 100, "our data length")


def test_cross_response_round_trip(states: PythonObject) raises:
    """Full request/response round-trip: our client receives matching response.

    The oracle confirms a successful round-trip happened (no error). The
    assertions below verify our Mojo client emits the expected
    ResponseReceived + DataReceived events and reaches STREAM_CLOSED.
    """
    var oracle = states["roundtrip"]
    var err = py_field_str(oracle, "error")
    assert_true(len(err) == 0, "oracle no error: " + err)

    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    var server_preface = server.data_to_send()
    _ = client.receive_data(server_preface)
    var client_ack = client.data_to_send()
    _ = server.receive_data(client_preface)
    var server_ack = server.data_to_send()
    _ = client.receive_data(server_ack)
    _ = client.data_to_send()
    _ = server.receive_data(client_ack)
    _ = server.data_to_send()

    var req_headers = List[Header]()
    req_headers.append(Header(":method", "GET"))
    req_headers.append(Header(":path", "/"))
    req_headers.append(Header(":scheme", "https"))
    req_headers.append(Header(":authority", "example.com"))
    client.send_headers(UInt32(1), req_headers^, end_stream=True)
    var req_wire = client.data_to_send()
    _ = server.receive_data(req_wire)
    _ = server.data_to_send()

    var resp_headers = List[Header]()
    resp_headers.append(Header(":status", "200"))
    resp_headers.append(Header("content-type", "text/plain"))
    server.send_headers(UInt32(1), resp_headers^, end_stream=False)
    var resp_body = List[UInt8]()
    resp_body.append(UInt8(0x68))
    resp_body.append(UInt8(0x65))
    resp_body.append(UInt8(0x6C))
    resp_body.append(UInt8(0x6C))
    resp_body.append(UInt8(0x6F))
    server.send_data(UInt32(1), resp_body, end_stream=True)
    var resp_wire = server.data_to_send()
    var cli_events = client.receive_data(resp_wire)

    var resp_found = False
    for i in range(len(cli_events)):
        if cli_events[i].kind == H2_EVT_RESPONSE_RECEIVED:
            resp_found = True
            assert_true(cli_events[i].headers[0].name == ":status", "status header")
            assert_true(cli_events[i].headers[0].value == "200", "200 status")
    assert_true(resp_found, "ResponseReceived emitted")
    var data_found = False
    for i in range(len(cli_events)):
        if cli_events[i].kind == H2_EVT_DATA_RECEIVED:
            data_found = True
            assert_equal(len(cli_events[i].data), 5, "body length")
    assert_true(data_found, "DataReceived emitted")
    var state = client.stream_state(UInt32(1))
    assert_equal(state, STREAM_CLOSED, "stream closed after full round-trip")


def main() raises:
    var states = load_states("vectors/rfc9113/h2_states.json")
    test_cross_roundtrip_headers_match(states)
    test_cross_data_flow_controlled_length(states)
    test_cross_response_round_trip(states)
    print("All tests passed.")
