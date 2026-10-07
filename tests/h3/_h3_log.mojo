"""Event-log helpers shared by the H3 coroutine-server tests (sync and streaming)."""

from std.collections import Dict

from navette.h3.connection import H3Connection, H3Event


def log_events(mut client: H3Connection, mut log: Dict[Int, String]) raises:
    """Append one token per pending client event to its stream's entry: H<status><link>[/cl<n>], D<bytes>, E, R<code>."""
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.take()
        var tok: String
        if e.kind == H3Event.HEADERS_RECEIVED:
            var cl = e.section.headers.get("content-length")
            tok = "H" + e.section.status + e.section.headers.get("link") + ("/cl" + cl if cl else "")
        elif e.kind == H3Event.DATA_RECEIVED:
            tok = "D" + String(unsafe_from_utf8=e.data.copy())
        elif e.kind == H3Event.STREAM_ENDED:
            tok = "E"
        elif e.kind == H3Event.STREAM_RESET:
            tok = "R" + String(Int(e.error_code))
        else:
            continue
        log[Int(e.stream_id)] = logged(log, e.stream_id) + tok + " "


def logged(log: Dict[Int, String], sid: UInt64) -> String:
    var v = log.find(Int(sid))
    return v.value() if v else String("")


def stop_code(h3: H3Connection, sid: UInt64) -> Int:
    """The STOP_SENDING code queued on `sid` and not yet flushed, or -1."""
    var p = h3._quic.stream_map.try_stream_ptr(Int(sid))
    if not p or not p.value()[].needs_stop_sending:
        return -1
    return Int(p.value()[].stop_sending_error)
