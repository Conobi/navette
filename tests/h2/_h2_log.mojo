"""Request and event-log helpers shared by the H2 coroutine-server tests (sync and streaming)."""

from oracle.http1.types import Header
from oracle.http2.connection import (
    H2Connection,
    H2Event,
    H2_EVT_RESPONSE_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
)


def send_request(mut client: H2Connection, sid: Int, method: String, path: String, end: Bool) raises:
    var headers = List[Header]()
    headers.append(Header(":method", method))
    headers.append(Header(":path", path))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "localhost"))
    client.send_headers(UInt32(sid), headers^, end_stream=end)


def _field(evt: H2Event, name: String) -> String:
    for ref h in evt.headers:
        if h.name == name:
            return h.value
    return ""


def event_log(events: List[H2Event], sid: Int) -> String:
    """One token per event on `sid`: H<status><link>[/cl<n>][!] (! = END_STREAM), D<bytes>[!], E (ended), R<code>."""
    var out = String("")
    for ref e in events:
        if Int(e.stream_id) != sid:
            continue
        var end = String("!") if e.stream_ended else String("")
        if e.kind == H2_EVT_RESPONSE_RECEIVED:
            var cl = _field(e, "content-length")
            out += "H" + _field(e, ":status") + _field(e, "link") + ("/cl" + cl if cl else "") + end + " "
        elif e.kind == H2_EVT_DATA_RECEIVED:
            out += "D" + String(unsafe_from_utf8=e.data.copy()) + end + " "
        elif e.kind == H2_EVT_STREAM_ENDED:
            out += "E "
        elif e.kind == H2_EVT_STREAM_RESET:
            out += "R" + String(Int(e.error_code)) + " "
    return out
