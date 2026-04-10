# src/h2/h2_handler_server.mojo
#
# HTTP/2 server-side handler adapter.  Sans-I/O: feed inbound wire bytes,
# drain outbound bytes.  Translates H2Connection events into StreamHandler
# lifecycle callbacks.  (M5.5 Task 4)

from std.collections import Dict
from std.memory import Span, UnsafePointer

from lib.http2.connection import (
    H2Connection,
    H2Config,
    H2Event,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_TRAILERS_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
)
from src.http.handler import (
    StreamHandler,
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
    ALPN_H2,
)
from src.http.body import BodyFrame
from src.http.headers import Headers
from src.http.request import Request
from src.h2.config import h2_production_config
from src.h2.pseudo_headers import (
    request_from_h2_headers,
    response_to_h2_headers,
    headers_from_h2,
)


# ---------------------------------------------------------------------------
# _StreamCtx — per-stream context (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct _StreamCtx(Movable):
    """Per-stream state that lives on the heap.  RecvBody and ResponseWriter
    are move-only, so this struct cannot go in a Dict directly."""

    var recv_body: RecvBody
    var resp_writer: ResponseWriter
    var detached: Bool
    var request_ended: Bool
    var response_ended: Bool
    var headers_sent: Bool
    var unacked_bytes: Int

    def __init__(out self):
        self.recv_body = RecvBody()
        self.resp_writer = ResponseWriter()
        self.detached = False
        self.request_ended = False
        self.response_ended = False
        self.headers_sent = False
        self.unacked_bytes = 0

    def __init__(out self, *, deinit take: Self):
        self.recv_body = take.recv_body^
        self.resp_writer = take.resp_writer^
        self.detached = take.detached
        self.request_ended = take.request_ended
        self.response_ended = take.response_ended
        self.headers_sent = take.headers_sent
        self.unacked_bytes = take.unacked_bytes


# ---------------------------------------------------------------------------
# _StreamPtr — thin wrapper so Dict[Int, _StreamPtr] satisfies
# CollectionElement (Copyable + Movable) even if UnsafePointer does not.
# ---------------------------------------------------------------------------


struct _StreamPtr(Copyable, Movable):
    """Holds the address of a heap-allocated _StreamCtx as a UInt64."""

    var addr: UInt64

    def __init__(out self, addr: UInt64):
        self.addr = addr

    def __init__(out self, *, other: Self):
        self.addr = other.addr

    def __init__(out self, *, deinit take: Self):
        self.addr = take.addr

    def ptr(self) -> UnsafePointer[_StreamCtx, MutAnyOrigin]:
        return UnsafePointer[_StreamCtx, MutAnyOrigin](
            unsafe_from_address=Int(self.addr)
        )


# ---------------------------------------------------------------------------
# H2HandlerServer — server adapter
# ---------------------------------------------------------------------------


struct H2HandlerServer[H: StreamHandler](Movable):
    """Drive a StreamHandler from an HTTP/2 H2Connection.  Sans-I/O:
    the caller feeds inbound bytes via `feed()` and drains outbound bytes
    via `drain()`.  Multiplexed streams are tracked in a Dict keyed by
    stream ID."""

    var _conn: H2Connection
    var handler: Self.H
    var _outbuf: List[UInt8]
    var _streams: Dict[Int, _StreamPtr]

    # --- Constructors -------------------------------------------------------

    def __init__(out self, *, var handler: Self.H) raises:
        """Create with default production config (server-side)."""
        self._conn = H2Connection(
            client_side=False,
            config=h2_production_config(client_side=False),
        )
        self._conn.initiate_connection()
        self.handler = handler^
        self._outbuf = List[UInt8]()
        self._streams = Dict[Int, _StreamPtr]()
        self._flush_outbound()

    def __init__(out self, *, var handler: Self.H, config: H2Config) raises:
        """Create with a custom H2Config (server-side)."""
        self._conn = H2Connection(client_side=False, config=config)
        self._conn.initiate_connection()
        self.handler = handler^
        self._outbuf = List[UInt8]()
        self._streams = Dict[Int, _StreamPtr]()
        self._flush_outbound()

    def __init__(out self, *, deinit take: Self):
        self._conn = take._conn^
        self.handler = take.handler^
        self._outbuf = take._outbuf^
        self._streams = take._streams^

    fn __del__(deinit self):
        """Destroy and free all heap-allocated stream contexts."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            try:
                var p = self._streams[keys[i]].ptr()
                p.destroy_pointee()
                p.free()
            except:
                pass

    # --- Transport bridging API ---------------------------------------------

    def feed(mut self, data: Span[UInt8, _]) raises:
        """Feed inbound transport bytes, dispatch events, drain responses."""
        var data_list = List[UInt8]()
        for i in range(len(data)):
            data_list.append(data[i])
        var events = self._conn.receive_data(data_list)
        self._dispatch_events(events)
        self._drain_responses()
        self._flush_outbound()

    def drain(mut self) -> List[UInt8]:
        """Drain queued outbound bytes for the transport to write."""
        var out = self._outbuf^
        self._outbuf = List[UInt8]()
        return out^

    def should_close(self) -> Bool:
        """True when the H2 connection has reached terminal state."""
        return self._conn.is_closed()

    # --- Internal -----------------------------------------------------------

    def _flush_outbound(mut self):
        """Move pending outbound bytes from the H2Connection into our buffer."""
        var pending = self._conn.data_to_send()
        for i in range(len(pending)):
            self._outbuf.append(pending[i])

    def _dispatch_events(mut self, mut events: List[H2Event]) raises:
        """Dispatch H2 events to handler callbacks (stub — loops but does
        nothing).  Will be filled in by later tasks."""
        for i in range(len(events)):
            var _evt = events[i]
            pass

    def _drain_responses(mut self) raises:
        """Drain pending response data from stream contexts into the H2
        connection (stub — does nothing).  Will be filled in by later tasks."""
        pass
