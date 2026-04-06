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
