# src/h2/h2_handler_server.mojo
#
# HTTP/2 server-side handler adapter.  Sans-I/O: feed inbound wire bytes,
# drain outbound bytes.  Translates H2Connection events into calls on the
# shared handler driver.

from std.collections import Span

from .connection import (
    H2Connection,
    H2Config,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_TRAILERS_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
)
from .frame import H2_PROTOCOL_ERROR
from navette.http.body import BodyFrame
from navette.http.handler import StreamHandler, Capabilities
from navette.http.handler_driver import HandlerDriver
from .config import h2_production_config
from .pseudo_headers import request_from_h2_headers, headers_from_h2


struct H2HandlerServer[H: StreamHandler](Movable):
    """Drive a StreamHandler from an HTTP/2 H2Connection.  Sans-I/O:
    the caller feeds inbound bytes via `feed()` and drains outbound bytes
    via `drain()`.  A handler that raises fails only its own stream."""

    var _conn: H2Connection
    var driver: HandlerDriver[Self.H]
    var _outbuf: List[Byte]
    var _peer_addr: String

    def __init__(
        out self,
        *,
        var handler: Self.H,
        config: H2Config = h2_production_config(client_side=False),
        var peer_addr: String = "",
    ) raises:
        self._conn = H2Connection(client_side=False, config=config)
        self._conn.initiate_connection()
        self.driver = HandlerDriver[Self.H](handler^)
        self._outbuf = List[Byte]()
        self._peer_addr = peer_addr^
        self._conn.data_to_send_into(self._outbuf)

    # --- Transport bridging API ---------------------------------------------

    def feed(mut self, data: Span[Byte, _]) raises:
        """Feed inbound transport bytes, run the handler callbacks they trigger, and stage the responses.

        A malformed request head resets its stream with PROTOCOL_ERROR
        (RFC 9113 Section 8.1.1); it never reaches the handler.
        """
        var events = self._conn.receive_data(List[Byte](data))
        for ref evt in events:
            var sid = Int(evt.stream_id)
            if evt.kind == H2_EVT_REQUEST_RECEIVED:
                try:
                    var req = request_from_h2_headers(evt.stream_id, evt.headers)
                    self.driver.on_request(sid, req^, Capabilities.for_h2(peer_addr=self._peer_addr), evt.stream_ended)
                except:
                    self._conn.send_rst_stream(evt.stream_id, UInt32(H2_PROTOCOL_ERROR))
            elif evt.kind == H2_EVT_DATA_RECEIVED:
                var chunk = List[Byte]()
                swap(chunk, evt.data)
                var credit = self.driver.on_body(sid, BodyFrame.data(chunk^), evt.flow_controlled_length)
                if credit > 0:
                    self._conn.acknowledge_received_data(credit, evt.stream_id)
                if evt.stream_ended:
                    self.driver.on_end(sid)
            elif evt.kind == H2_EVT_TRAILERS_RECEIVED:
                # Trailers always carry END_STREAM (enforced by H2Connection).
                _ = self.driver.on_body(sid, BodyFrame.trailers(headers_from_h2(evt.headers)))
                self.driver.on_end(sid)
            elif evt.kind == H2_EVT_STREAM_ENDED:
                self.driver.on_end(sid)
            elif evt.kind == H2_EVT_STREAM_RESET:
                _ = self.driver.on_reset(sid, evt.error_code)
        if not self._conn.is_closed():
            self.driver.drain(self._conn)
        self._conn.data_to_send_into(self._outbuf)

    def drain(mut self) -> List[Byte]:
        """Drain queued outbound bytes for the transport to write. Delegates to drain_into."""
        var out = List[Byte]()
        self.drain_into(out)
        return out^

    def drain_into(mut self, mut sink: List[Byte]):
        """Append queued outbound bytes into sink and clear the buffer in place,
        preserving its backing allocation across drains."""
        sink.extend(Span(self._outbuf))
        self._outbuf.clear()

    def should_close(self) -> Bool:
        """True when the H2 connection has reached terminal state."""
        return self._conn.is_closed()
