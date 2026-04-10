# conformance/tests/test_h2_stream_cross.mojo
#
# HC-4b: Stream-level cross-validation against Python h2.
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
from lib.http2.oracles import h2_roundtrip, h2_stream_data_scenario
from lib.http1.types import Header
from std.python import Python


def test_cross_roundtrip_headers_match() raises:
    """Our H2Connection and Python h2 produce matching request headers."""
    var oracle = h2_roundtrip()
    assert_true(String(oracle["error"]) == "None", "oracle no error")

    # Our implementation: same scenario
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
    var our_req_found = False
    for i in range(len(srv_events)):
        if srv_events[i].kind == H2_EVT_REQUEST_RECEIVED:
            our_req_found = True
            for j in range(Int(py=len(oracle_srv_events))):
                if String(oracle_srv_events[j]["type"]) == "RequestReceived":
                    var oracle_headers = oracle_srv_events[j]["headers"]
                    assert_equal(len(srv_events[i].headers), Int(py=len(oracle_headers)), "header count match")
                    for k in range(len(srv_events[i].headers)):
                        assert_true(srv_events[i].headers[k].name == String(oracle_headers[k][0]), "header name " + String(k))
                        assert_true(srv_events[i].headers[k].value == String(oracle_headers[k][1]), "header value " + String(k))
    assert_true(our_req_found, "our server emitted RequestReceived")


def test_cross_data_flow_controlled_length() raises:
    """DataReceived flow_controlled_length matches Python h2."""
    var oracle_hdrs = List[Header]()
    oracle_hdrs.append(Header(":method", "POST"))
    oracle_hdrs.append(Header(":path", "/"))
    oracle_hdrs.append(Header(":scheme", "https"))
    oracle_hdrs.append(Header(":authority", "example.com"))
    var body = List[UInt8]()
    for _ in range(100):
        body.append(UInt8(0x41))
    var oracle = h2_stream_data_scenario(oracle_hdrs, body, end_stream=True)
    assert_true(String(oracle["error"]) == "None", "oracle no error")

    # Our implementation
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
    client.send_data(UInt32(1), body, end_stream=True)
    var request_wire = client.data_to_send()
    var srv_events = server.receive_data(request_wire)

    var oracle_events = oracle["events"]
    for i in range(len(srv_events)):
        if srv_events[i].kind == H2_EVT_DATA_RECEIVED:
            for j in range(Int(py=len(oracle_events))):
                if String(oracle_events[j]["type"]) == "DataReceived":
                    assert_equal(
                        srv_events[i].flow_controlled_length,
                        Int(py=oracle_events[j]["flow_controlled_length"]),
                        "flow_controlled_length match"
                    )
                    assert_equal(len(srv_events[i].data), 100, "our data length")


def test_cross_response_round_trip() raises:
    """Full request/response round-trip: our client receives matching response."""
    var oracle = h2_roundtrip()
    assert_true(String(oracle["error"]) == "None", "oracle no error")

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
    resp_body.append(UInt8(0x68))  # h
    resp_body.append(UInt8(0x65))  # e
    resp_body.append(UInt8(0x6C))  # l
    resp_body.append(UInt8(0x6C))  # l
    resp_body.append(UInt8(0x6F))  # o
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
    test_cross_roundtrip_headers_match()
    test_cross_data_flow_controlled_length()
    test_cross_response_round_trip()
    print("All tests passed.")
