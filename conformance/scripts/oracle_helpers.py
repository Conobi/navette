"""Oracle helpers for HTTP/1.1 and HTTP/2 cross-validation.

Wraps h11, httptools, and hyperframe to provide structured parse results
for cross-validation with our Mojo parsers.
"""
import h11
import httptools


def parse_with_h11(wire_bytes: bytes) -> dict:
    """Parse request bytes with h11, return structured result."""
    try:
        conn = h11.Connection(h11.SERVER)
        conn.receive_data(wire_bytes)
        event = conn.next_event()
        if isinstance(event, h11.Request):
            headers = [
                [
                    h[0].decode("ascii", errors="replace"),
                    h[1].decode("ascii", errors="replace"),
                ]
                for h in event.headers
            ]
            # Try to get body
            body = b""
            while True:
                ev = conn.next_event()
                if isinstance(ev, h11.Data):
                    body += ev.data
                elif isinstance(ev, h11.EndOfMessage):
                    break
                elif ev is h11.NEED_DATA:
                    break
                else:
                    break
            return {
                "method": event.method.decode("ascii", errors="replace"),
                "target": event.target.decode("ascii", errors="replace"),
                "version": event.http_version.decode("ascii", errors="replace"),
                "headers": headers,
                "body": body,
                "error": None,
            }
        else:
            return {"error": f"unexpected event: {type(event).__name__}"}
    except Exception as e:
        return {"error": str(e)}


class _HttpToolsCollector:
    """Callback collector for httptools parser."""

    def __init__(self):
        self.method = None
        self.target = None
        self.version = None
        self.headers = []
        self.body = b""
        self.complete = False

    def on_url(self, url: bytes):
        self.target = url.decode("ascii", errors="replace")

    def on_header(self, name: bytes, value: bytes):
        self.headers.append(
            [
                name.decode("ascii", errors="replace"),
                value.decode("ascii", errors="replace"),
            ]
        )

    def on_body(self, body: bytes):
        self.body += body

    def on_message_complete(self):
        self.complete = True


def parse_with_httptools(wire_bytes: bytes) -> dict:
    """Parse request bytes with httptools, return structured result."""
    try:
        c = _HttpToolsCollector()
        parser = httptools.HttpRequestParser(c)
        parser.feed_data(wire_bytes)

        # httptools exposes method via get_method()
        method = parser.get_method()
        if method:
            c.method = method.decode("ascii", errors="replace")

        # httptools exposes HTTP version
        ver = parser.get_http_version()
        if ver:
            c.version = ver

        return {
            "method": c.method,
            "target": c.target,
            "version": c.version,
            "headers": c.headers,
            "body": c.body,
            "error": None,
        }
    except httptools.HttpParserError as e:
        return {"error": str(e)}
    except httptools.HttpParserCallbackError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


# ---- Response oracles ----


def parse_response_with_h11(wire_bytes: bytes, request_method: str = "GET") -> dict:
    """Parse response with h11. Needs request_method for HEAD/CONNECT."""
    try:
        conn = h11.Connection(h11.CLIENT)
        # Send synthetic request to set connection state
        req = h11.Request(
            method=request_method.encode("ascii"),
            target=b"/",
            headers=[(b"Host", b"x")],
        )
        conn.send(req)
        conn.receive_data(wire_bytes)

        event = conn.next_event()
        if isinstance(event, h11.InformationalResponse):
            headers = [
                [
                    h[0].decode("ascii", errors="replace"),
                    h[1].decode("ascii", errors="replace"),
                ]
                for h in event.headers
            ]
            return {
                "status_code": event.status_code,
                "reason": event.reason.decode("ascii", errors="replace")
                if event.reason
                else "",
                "version": event.http_version.decode("ascii", errors="replace"),
                "headers": headers,
                "body": b"",
                "error": None,
            }
        elif isinstance(event, h11.Response):
            headers = [
                [
                    h[0].decode("ascii", errors="replace"),
                    h[1].decode("ascii", errors="replace"),
                ]
                for h in event.headers
            ]
            body = b""
            while True:
                ev = conn.next_event()
                if isinstance(ev, h11.Data):
                    body += ev.data
                elif isinstance(ev, h11.EndOfMessage):
                    break
                elif ev is h11.NEED_DATA:
                    break
                else:
                    break
            return {
                "status_code": event.status_code,
                "reason": event.reason.decode("ascii", errors="replace")
                if event.reason
                else "",
                "version": event.http_version.decode("ascii", errors="replace"),
                "headers": headers,
                "body": body,
                "error": None,
            }
        else:
            return {"error": f"unexpected event: {type(event).__name__}"}
    except Exception as e:
        return {"error": str(e)}


class _HttpResponseCollector:
    """Callback collector for httptools response parser."""

    def __init__(self):
        self.status_code = None
        self.reason = None
        self.version = None
        self.headers = []
        self.body = b""

    def on_status(self, status: bytes):
        self.reason = status.decode("ascii", errors="replace")

    def on_header(self, name: bytes, value: bytes):
        self.headers.append(
            [
                name.decode("ascii", errors="replace"),
                value.decode("ascii", errors="replace"),
            ]
        )

    def on_body(self, body: bytes):
        self.body += body


def parse_response_with_httptools(
    wire_bytes: bytes, request_method: str = "GET"
) -> dict:
    """Parse response with httptools. Cannot model HEAD/CONNECT context."""
    try:
        c = _HttpResponseCollector()
        parser = httptools.HttpResponseParser(c)
        parser.feed_data(wire_bytes)
        c.status_code = parser.get_status_code()
        c.version = parser.get_http_version()
        return {
            "status_code": c.status_code,
            "reason": c.reason or "",
            "version": c.version or "",
            "headers": c.headers,
            "body": c.body,
            "error": None,
        }
    except Exception as e:
        return {"error": str(e)}


# ---- Connection oracle ----


def parse_connection_with_h11(
    wire_bytes: bytes, direction: str, request_methods: list = None
) -> dict:
    """Parse multi-message wire with h11's connection state machine.

    h11 models the full HTTP/1.1 connection lifecycle. For requests (SERVER
    role), after each request EndOfMessage we must send a synthetic response
    and call start_next_cycle() so h11 transitions back to IDLE to accept
    the next pipelined request.  For responses (CLIENT role), we send all
    synthetic requests up front, then after each final-response EndOfMessage
    we call start_next_cycle() and send the next synthetic request.

    Returns: {
        "messages": [{"type": "request"/"response", ...}],
        "phase": "IDLE"/"MUST_CLOSE"/"UPGRADED"/"ERROR",
        "error": None or str
    }
    """
    if request_methods is None:
        request_methods = []

    try:
        role = h11.SERVER if direction == "request" else h11.CLIENT
        conn = h11.Connection(role)

        if direction == "response":
            # Send first synthetic request so h11 enters SEND_RESPONSE
            if request_methods:
                req = h11.Request(
                    method=request_methods[0].encode("ascii"),
                    target=b"/",
                    headers=[(b"Host", b"x")],
                )
                conn.send(req)

        conn.receive_data(wire_bytes)

        messages = []
        max_iterations = 500
        iterations = 0
        method_idx = 0  # tracks next request_methods index for responses

        while iterations < max_iterations:
            iterations += 1
            event = conn.next_event()

            if event is h11.NEED_DATA:
                break
            if isinstance(event, h11.ConnectionClosed):
                break

            # h11.PAUSED means both sides are DONE but not recycled yet
            if type(event).__name__ == "Sentinel":
                # NEED_DATA and PAUSED are sentinels
                event_str = str(event)
                if "PAUSED" in event_str:
                    break
                if "NEED_DATA" in event_str:
                    break
                break

            if isinstance(event, h11.Request):
                headers = [
                    [
                        h[0].decode("ascii", errors="replace"),
                        h[1].decode("ascii", errors="replace"),
                    ]
                    for h in event.headers
                ]
                messages.append(
                    {
                        "type": "request",
                        "method": event.method.decode("ascii", errors="replace"),
                        "target": event.target.decode("ascii", errors="replace"),
                        "version": event.http_version.decode(
                            "ascii", errors="replace"
                        ),
                        "headers": headers,
                        "body": b"",
                    }
                )
            elif isinstance(event, (h11.Response, h11.InformationalResponse)):
                headers = [
                    [
                        h[0].decode("ascii", errors="replace"),
                        h[1].decode("ascii", errors="replace"),
                    ]
                    for h in event.headers
                ]
                messages.append(
                    {
                        "type": "response",
                        "status_code": event.status_code,
                        "reason": event.reason.decode("ascii", errors="replace")
                        if event.reason
                        else "",
                        "version": event.http_version.decode(
                            "ascii", errors="replace"
                        ),
                        "headers": headers,
                        "body": b"",
                    }
                )
            elif isinstance(event, h11.Data):
                if messages:
                    messages[-1]["body"] = messages[-1].get("body", b"") + event.data
            elif isinstance(event, h11.EndOfMessage):
                if direction == "request":
                    # Server role: send synthetic response, cycle, to parse
                    # next pipelined request
                    try:
                        conn.send(
                            h11.Response(
                                status_code=200,
                                headers=[(b"Content-Length", b"0")],
                            )
                        )
                        conn.send(h11.EndOfMessage())
                        conn.start_next_cycle()
                    except Exception:
                        # Connection may be closing or in error
                        break
                else:
                    # Client role: after final response, cycle and send next
                    # synthetic request
                    final_count = sum(
                        1
                        for m in messages
                        if m["type"] == "response"
                        and m.get("status_code", 0) >= 200
                    )
                    if final_count < len(request_methods):
                        try:
                            conn.start_next_cycle()
                            method = request_methods[final_count]
                            req = h11.Request(
                                method=method.encode("ascii"),
                                target=b"/",
                                headers=[(b"Host", b"x")],
                            )
                            conn.send(req)
                        except Exception:
                            break
                    else:
                        break
            else:
                # Unknown event type — stop
                break

        # Map h11 state to our phase names
        if direction == "request":
            state = conn.their_state
        else:
            state = conn.our_state

        state_str = str(state)
        phase = "IDLE"
        if "IDLE" in state_str or "DONE" in state_str:
            phase = "IDLE"
        elif "CLOSED" in state_str:
            phase = "MUST_CLOSE"
        elif "SWITCHED" in state_str:
            phase = "UPGRADED"
        elif "ERROR" in state_str:
            phase = "ERROR"

        return {"messages": messages, "phase": phase, "error": None}
    except Exception as e:
        return {"messages": [], "phase": "ERROR", "error": str(e)}


# ---- HPACK oracles ----


def hpack_decode_with_python(wire_bytes: bytes) -> dict:
    """Decode HPACK wire with Python hpack (stateless -- fresh decoder)."""
    try:
        import hpack as hpack_lib

        decoder = hpack_lib.Decoder()
        headers = decoder.decode(wire_bytes)
        return {
            "headers": [
                [
                    h[0].decode("ascii", errors="replace")
                    if isinstance(h[0], bytes)
                    else str(h[0]),
                    h[1].decode("ascii", errors="replace")
                    if isinstance(h[1], bytes)
                    else str(h[1]),
                ]
                for h in headers
            ],
            "error": None,
        }
    except Exception as e:
        return {"error": str(e)}


def hpack_encode_with_python(headers_list: list) -> dict:
    """Encode headers with Python hpack (stateless -- fresh encoder)."""
    try:
        import hpack as hpack_lib

        encoder = hpack_lib.Encoder()
        wire = encoder.encode([(h[0], h[1]) for h in headers_list])
        return {"wire_hex": wire.hex(), "error": None}
    except Exception as e:
        return {"error": str(e)}


def hpack_story_decode_with_python(wire_hex_list: list) -> dict:
    """Decode multiple HPACK blocks statefully with Python hpack."""
    try:
        import hpack as hpack_lib

        decoder = hpack_lib.Decoder()
        all_results = []
        for wire_hex in wire_hex_list:
            wire = bytes.fromhex(wire_hex)
            headers = decoder.decode(wire)
            all_results.append(
                [
                    [
                        h[0].decode("ascii", errors="replace")
                        if isinstance(h[0], bytes)
                        else str(h[0]),
                        h[1].decode("ascii", errors="replace")
                        if isinstance(h[1], bytes)
                        else str(h[1]),
                    ]
                    for h in headers
                ]
            )
        return {"results": all_results, "error": None}
    except Exception as e:
        return {"results": [], "error": str(e)}


def hpack_story_encode_with_python(headers_lists: list) -> dict:
    """Encode multiple header blocks statefully with Python hpack."""
    try:
        import hpack as hpack_lib

        encoder = hpack_lib.Encoder()
        wire_hex_list = []
        for headers in headers_lists:
            wire = encoder.encode([(h[0], h[1]) for h in headers])
            wire_hex_list.append(wire.hex())
        return {"wire_hex_list": wire_hex_list, "error": None}
    except Exception as e:
        return {"wire_hex_list": [], "error": str(e)}


# ---- HTTP/2 frame oracle ----



def decode_frame_with_hyperframe(wire_bytes: bytes) -> dict:
    """Decode one HTTP/2 frame with hyperframe. Returns structured dict.

    The flags integer is read directly from wire byte 4 (the flags byte in
    the 9-byte frame header) to avoid any mapping inconsistencies between
    hyperframe's string-based flag names and our integer representation.
    """
    try:
        import hyperframe.frame as hf

        if len(wire_bytes) < 9:
            return {"error": "wire too short for frame header"}

        f, length = hf.Frame.parse_frame_header(memoryview(wire_bytes[:9]))
        f.parse_body(memoryview(wire_bytes[9 : 9 + length]))

        # Read flags directly from the wire header byte for exact comparison
        flags_int = wire_bytes[4]

        return {
            "length": length,
            "type": f.type if hasattr(f, "type") else -1,
            "flags": flags_int,
            "stream_id": f.stream_id,
            "payload_hex": wire_bytes[9 : 9 + length].hex(),
            "error": None,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# HTTP/2 connection oracle (Python h2)
# ---------------------------------------------------------------------------

def _h2_event_to_dict(event):
    """Convert h2 event to a serializable dict."""
    import h2.events
    result = {"type": type(event).__name__}
    if isinstance(event, h2.events.RemoteSettingsChanged):
        result["changed_settings"] = {
            int(k): {"original_value": v.original_value, "new_value": v.new_value}
            for k, v in event.changed_settings.items()
        }
    elif isinstance(event, h2.events.SettingsAcknowledged):
        result["changed_settings"] = {}
    elif isinstance(event, h2.events.PingReceived):
        result["ping_data"] = event.ping_data.hex()
    elif isinstance(event, h2.events.PingAckReceived):
        result["ping_data"] = event.ping_data.hex() if hasattr(event, "ping_data") else ""
    elif isinstance(event, h2.events.ConnectionTerminated):
        result["error_code"] = event.error_code
        result["last_stream_id"] = event.last_stream_id
        result["additional_data"] = (
            event.additional_data.hex() if event.additional_data else ""
        )
    elif isinstance(event, h2.events.WindowUpdated):
        result["stream_id"] = event.stream_id
        result["delta"] = event.delta
    elif isinstance(event, h2.events.StreamReset):
        result["stream_id"] = event.stream_id
        result["error_code"] = event.error_code
    elif isinstance(event, h2.events.RequestReceived):
        result["stream_id"] = event.stream_id
        result["headers"] = [[h[0] if isinstance(h[0], str) else h[0].decode("ascii", errors="replace"),
                               h[1] if isinstance(h[1], str) else h[1].decode("ascii", errors="replace")]
                              for h in event.headers]
    elif isinstance(event, h2.events.ResponseReceived):
        result["stream_id"] = event.stream_id
        result["headers"] = [[h[0] if isinstance(h[0], str) else h[0].decode("ascii", errors="replace"),
                               h[1] if isinstance(h[1], str) else h[1].decode("ascii", errors="replace")]
                              for h in event.headers]
    elif isinstance(event, h2.events.DataReceived):
        result["stream_id"] = event.stream_id
        result["data_hex"] = event.data.hex()
        result["flow_controlled_length"] = event.flow_controlled_length
    elif isinstance(event, h2.events.TrailersReceived):
        result["stream_id"] = event.stream_id
        result["headers"] = [[h[0] if isinstance(h[0], str) else h[0].decode("ascii", errors="replace"),
                               h[1] if isinstance(h[1], str) else h[1].decode("ascii", errors="replace")]
                              for h in event.headers]
    elif isinstance(event, h2.events.StreamEnded):
        result["stream_id"] = event.stream_id
    return result


def h2_server_receive(wire_bytes):
    """Create h2 server, initiate, feed wire_bytes, return result dict."""
    import h2.connection, h2.config
    config = h2.config.H2Configuration(client_side=False)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    preface = conn.data_to_send()
    try:
        events = conn.receive_data(wire_bytes)
        response = conn.data_to_send()
        return {
            "preface_hex": preface.hex(),
            "events": [_h2_event_to_dict(e) for e in events],
            "response_hex": response.hex(),
            "error": None,
        }
    except Exception as e:
        return {
            "preface_hex": preface.hex(),
            "events": [],
            "response_hex": "",
            "error": str(e),
        }


def h2_client_receive(wire_bytes):
    """Create h2 client, initiate, feed wire_bytes, return result dict."""
    import h2.connection, h2.config
    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    preface = conn.data_to_send()
    try:
        events = conn.receive_data(wire_bytes)
        response = conn.data_to_send()
        return {
            "preface_hex": preface.hex(),
            "events": [_h2_event_to_dict(e) for e in events],
            "response_hex": response.hex(),
            "error": None,
        }
    except Exception as e:
        return {
            "preface_hex": preface.hex(),
            "events": [],
            "response_hex": "",
            "error": str(e),
        }


def h2_ping_scenario(client_preface_bytes, ping_frame_bytes):
    """Establish h2 server with client preface, then feed PING frame."""
    import h2.connection, h2.config
    config = h2.config.H2Configuration(client_side=False)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    _ = conn.data_to_send()
    conn.receive_data(client_preface_bytes)
    _ = conn.data_to_send()
    try:
        events = conn.receive_data(ping_frame_bytes)
        data = conn.data_to_send()
        return {
            "events": [_h2_event_to_dict(e) for e in events],
            "data_to_send_hex": data.hex(),
            "error": None,
        }
    except Exception as e:
        return {"events": [], "data_to_send_hex": "", "error": str(e)}


def h2_roundtrip():
    """Full request/response round-trip through Python h2.
    Client sends GET /, server responds with 200 + "hello".
    Returns dict with server_events, client_events.
    """
    import h2.connection, h2.config, h2.events

    client_config = h2.config.H2Configuration(client_side=True)
    client = h2.connection.H2Connection(config=client_config)
    client.initiate_connection()
    client_preface = client.data_to_send()

    server_config = h2.config.H2Configuration(client_side=False)
    server = h2.connection.H2Connection(config=server_config)
    server.initiate_connection()
    server_preface = server.data_to_send()

    try:
        client.receive_data(server_preface)
        client_ack = client.data_to_send()
        server.receive_data(client_preface)
        server_ack = server.data_to_send()
        client.receive_data(server_ack)
        _ = client.data_to_send()
        server.receive_data(client_ack)
        _ = server.data_to_send()

        client.send_headers(1, [
            (":method", "GET"), (":path", "/"),
            (":scheme", "https"), (":authority", "example.com"),
        ], end_stream=True)
        request_wire = client.data_to_send()

        server_events = server.receive_data(request_wire)
        _ = server.data_to_send()

        server.send_headers(1, [
            (":status", "200"), ("content-type", "text/plain"),
        ], end_stream=False)
        server.send_data(1, b"hello", end_stream=True)
        response_wire = server.data_to_send()

        client_events = client.receive_data(response_wire)
        _ = client.data_to_send()

        return {
            "server_events": [_h2_event_to_dict(e) for e in server_events],
            "client_events": [_h2_event_to_dict(e) for e in client_events],
            "request_wire_hex": request_wire.hex(),
            "response_wire_hex": response_wire.hex(),
            "error": None,
        }
    except Exception as e:
        return {"server_events": [], "client_events": [],
                "request_wire_hex": "", "response_wire_hex": "", "error": str(e)}


def h2_stream_data_scenario(headers_list, body_bytes, end_stream=True):
    """Client sends HEADERS + DATA, server receives. Returns events."""
    import h2.connection, h2.config

    client_config = h2.config.H2Configuration(client_side=True)
    client = h2.connection.H2Connection(config=client_config)
    client.initiate_connection()
    client_preface = client.data_to_send()

    server_config = h2.config.H2Configuration(client_side=False)
    server = h2.connection.H2Connection(config=server_config)
    server.initiate_connection()
    server_preface = server.data_to_send()

    try:
        client.receive_data(server_preface)
        client_ack = client.data_to_send()
        server.receive_data(client_preface)
        server_ack = server.data_to_send()
        client.receive_data(server_ack)
        _ = client.data_to_send()
        server.receive_data(client_ack)
        _ = server.data_to_send()

        client.send_headers(1, headers_list, end_stream=False)
        client.send_data(1, body_bytes, end_stream=end_stream)
        wire = client.data_to_send()

        events = server.receive_data(wire)
        _ = server.data_to_send()

        return {
            "events": [_h2_event_to_dict(e) for e in events],
            "wire_hex": wire.hex(),
            "error": None,
        }
    except Exception as e:
        return {"events": [], "wire_hex": "", "error": str(e)}
