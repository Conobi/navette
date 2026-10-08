"""The stream driver shared by the H2 and H3 handler servers.

Each adapter decodes its protocol's events, builds the `Request`, and
calls the driver; the driver runs the `StreamHandler` callbacks and sends
what they staged through the protocol's `ResponseSink`. Callbacks only
mark a stream ready: `drain` is the one place that writes, because a
method borrowing both the adapter and a stream record inside it is
rejected as aliasing.
"""

from std.collections import Dict, Optional
from std.memory import OwnedPointer

from navette.http.body import BodyFrame
from navette.http.handler import (
    Capabilities, RecvBody, ResponseWriter, StreamError, StreamHandler, _BODY_DETACHED,
)
from navette.http.headers import Headers
from navette.http.request import Request
from navette.http.status import StatusCode


trait ResponseSink:
    """What a protocol provides to put one stream's response on the wire."""

    def send_head(mut self, sid: Int, status: StatusCode, var headers: Headers, end: Bool) raises:
        """A response head: interim (1xx) or final."""
        ...

    def send_body(mut self, sid: Int, data: Span[Byte, _], end: Bool) raises:
        """Body bytes; empty `data` with `end` only ends the stream."""
        ...

    def send_trailers(mut self, sid: Int, var trailers: Headers) raises:
        """Trailers, which end the stream."""
        ...

    def stop_request(mut self, sid: Int):
        """Refuse the rest of the request body once the response is complete (H2 RST_STREAM NO_ERROR, H3 STOP_SENDING H3_NO_ERROR)."""
        ...

    def abort(mut self, sid: Int):
        """Abandon a partly sent response with an internal error in both directions; never a clean end."""
        ...


def pump_response[S: ResponseSink](mut sink: S, sid: Int, mut resp: ResponseWriter, mut head_sent: Bool) raises -> Bool:
    """Send what `resp` has staged: 1xx heads in order, the final head, then body frames. True once the response ended."""
    if not head_sent:
        var info = resp._take_informational()
        var info_headers = resp._take_informational_headers()
        for i in range(len(info)):
            sink.send_head(sid, info[i], info_headers[i].copy(), False)
        if not resp._has_status():
            return False
        var status = resp._take_status()
        var headers = resp._take_headers()
        sink.send_head(sid, status.take(), headers.take() if headers else Headers(), False)
        head_sent = True
    while True:
        var f_opt = resp._pop_body_frame()
        if not f_opt:
            return False
        var f = f_opt.take()
        if f.is_data():
            sink.send_body(sid, f.data(), False)
        elif f.is_end():
            sink.send_body(sid, List[Byte](), True)
            return True
        elif f.is_trailers():
            sink.send_trailers(sid, f.trailers().copy())
            return True


def fail_response[S: ResponseSink](mut sink: S, sid: Int, msg: String, head_sent: Bool, response_ended: Bool, request_open: Bool) -> Bool:
    """Log a failed stream once and apply the failure policy; True when it had to be aborted, so the handler gets `on_reset`.

    Before any head is on the wire the exchange completes as a 500 with an
    empty body (the request body, if still open, is refused without
    error). After the head, the response is aborted, never ended cleanly.
    A response that already ended is kept and only the request is refused.
    """
    print("navette: stream", sid, "failed:", msg)
    if not response_ended:
        if head_sent:
            sink.abort(sid)
            return True
        var headers = Headers()
        headers.add_lowercase("content-length", "0")
        try:
            sink.send_head(sid, StatusCode.internal_server_error(), headers^, True)
        except:
            sink.abort(sid)
            return True
    if request_open:
        sink.stop_request(sid)
    return False


def pump_or_fail[S: ResponseSink](
    mut sink: S, sid: Int, mut resp: ResponseWriter, mut head_sent: Bool, mut response_ended: Bool,
    mut failure: Optional[String], request_ended: Bool,
) -> Bool:
    """`pump_response`, then `fail_response` if the stream failed (a recorded handler raise or a send error). True once it can be freed.

    For the coroutine servers, which keep their own per-stream record and
    have no `on_reset` to call. Resolving a failure here, not at the raise,
    lets an H3 request's FIN arrive first, so no needless STOP_SENDING.
    """
    if not failure and not response_ended:
        try:
            response_ended = pump_response(sink, sid, resp, head_sent)
        except e:
            failure = String(e)
    if failure:
        _ = fail_response(sink, sid, failure.value(), head_sent, response_ended, not request_ended)
        return True
    return response_ended and request_ended


def _mark_ready(mut ready: List[Int], mut st: DriverStream, sid: Int):
    """Queue `sid` for the next `drain`, once."""
    if not st.queued:
        st.queued = True
        ready.append(sid)


def _wake[H: StreamHandler](mut handler: H, mut st: DriverStream, end: Bool):
    """Run `on_request_end` (`end`) or `on_body_available`, unless the body is detached or the stream already failed; a raise fails it."""
    if st.detached or st.failure:
        return
    try:
        if end:
            handler.on_request_end(st.body, st.resp)
        else:
            handler.on_body_available(st.body, st.resp)
    except e:
        st.failure = String(e)


struct DriverStream(Movable):
    """One open request, boxed in `HandlerDriver.streams`.

    Boxed because a Dict reserves 16 entries on its first insert: by value
    each short connection would touch 6 KB of fresh memory (cache misses,
    measured in cycles); boxed it is 16 x 24 B plus one record.

    `failure` holds a handler or send error the next `drain` resolves;
    `unacked` is H2 flow-control credit held while the body is paused.
    """

    var body: RecvBody
    var resp: ResponseWriter
    var detached: Bool
    var request_ended: Bool
    var response_ended: Bool
    var head_sent: Bool
    var queued: Bool
    var failure: Optional[String]
    var unacked: Int

    def __init__(out self):
        self.body = RecvBody()
        self.resp = ResponseWriter()
        self.detached = False
        self.request_ended = False
        self.response_ended = False
        self.head_sent = False
        self.queued = False
        self.failure = None
        self.unacked = 0


struct HandlerDriver[H: StreamHandler](Movable):
    """Runs one connection's handler callbacks per stream and drains their responses.

    `ready` lists the streams a callback touched since the last `drain`;
    `detached` counts open streams whose handler detached the body (the H3
    governor's long-lived streams); `completed` counts streams freed with
    both sides ended (the H2 transport's proof of progress). Lookups probe
    twice (`in`, then `[]`): `Dict.find` needs a copyable value.
    """

    var handler: Self.H
    var streams: Dict[Int, OwnedPointer[DriverStream]]
    var ready: List[Int]
    var detached: UInt64
    var completed: Int

    def __init__(out self, var handler: Self.H):
        self.handler = handler^
        self.streams = Dict[Int, OwnedPointer[DriverStream]]()
        self.ready = List[Int]()
        self.detached = 0
        self.completed = 0

    def on_request(mut self, sid: Int, var req: Request, caps: Capabilities, ended: Bool) raises:
        """Open the stream and run `on_request` (then `on_request_end` when `ended`). A repeated id is ignored."""
        if sid in self.streams:
            return
        self.streams[sid] = OwnedPointer(DriverStream())
        ref st = self.streams[sid][]
        if ended:
            st.request_ended = True
            st.body._set_end()
        try:
            self.handler.on_request(req^, st.body, st.resp, caps)
            st.detached = st.body._state == _BODY_DETACHED
            if st.detached:
                self.detached += 1
        except e:
            st.failure = String(e)
        if ended:
            _wake(self.handler, st, True)
        _mark_ready(self.ready, st, sid)

    def on_body(mut self, sid: Int, var frame: BodyFrame, credit: Int = 0) raises -> Int:
        """Queue a DATA chunk or the trailers and wake the handler.

        Returns the H2 flow-control credit to give back now: none while the
        body is paused. The caller still ends the request after trailers.
        """
        if sid not in self.streams:
            return credit
        ref st = self.streams[sid][]
        st.unacked += credit
        if not frame.is_data() or len(frame.data()) > 0:
            st.body._push(frame^)
        _wake(self.handler, st, False)
        _mark_ready(self.ready, st, sid)
        if st.body.is_paused():
            return 0
        var ack = st.unacked
        st.unacked = 0
        return ack

    def on_end(mut self, sid: Int) raises:
        """End the request body and run `on_request_end`, once."""
        if sid not in self.streams:
            return
        ref st = self.streams[sid][]
        if st.request_ended:
            return
        st.request_ended = True
        st.body._set_end()
        _wake(self.handler, st, True)
        _mark_ready(self.ready, st, sid)

    def on_reset(mut self, sid: Int, code: UInt32) raises -> Bool:
        """The peer reset the stream: free it and tell the handler. False for a stream already gone."""
        if sid not in self.streams:
            return False
        if self.streams.pop(sid)[].detached:
            self.detached -= 1
        self.handler.on_reset(StreamError.rst_stream(code))
        return True

    def respond(mut self, sid: Int, var status: StatusCode, var headers: Headers, var body: List[Byte], end: Bool) raises:
        """Stage a whole response from outside a handler callback; a no-op for a stream already gone, and staging errors are dropped."""
        if sid not in self.streams:
            return
        ref st = self.streams[sid][]
        try:
            st.resp.send_status(status^, headers^)
            if len(body) > 0:
                _ = st.resp.try_send_body(BodyFrame.data(body^))
            if end:
                st.resp.end()
        except:
            pass
        _mark_ready(self.ready, st, sid)

    def drain[S: ResponseSink](mut self, mut sink: S) raises:
        """Send what the ready streams staged; resolve failures; free streams whose both sides ended.

        A failed stream gets `fail_response` and, when aborted,
        `on_reset(local_abort)`; it is freed. Other streams
        on the connection are unaffected.
        """
        for i in range(len(self.ready)):
            var sid = self.ready[i]
            if sid not in self.streams:
                continue
            ref st = self.streams[sid][]
            st.queued = False
            if not st.failure and not st.response_ended:
                try:
                    st.response_ended = pump_response(sink, sid, st.resp, st.head_sent)
                except e:
                    st.failure = String(e)
            var done = st.request_ended and st.response_ended
            if st.failure:
                var msg = st.failure.take()
                if fail_response(sink, sid, msg, st.head_sent, st.response_ended, not st.request_ended):
                    self.handler.on_reset(StreamError.local_abort(msg^))
                done = True
            elif done:
                self.completed += 1
            if done:
                if self.streams.pop(sid)[].detached:
                    self.detached -= 1
        self.ready.clear()
