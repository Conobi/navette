"""A scripted `StreamHandler` for the H2 and H3 handler-server tests of the shared driver.

By request target: `/info` sends two 103s before the final response;
`/boom` raises in `on_request`; `/late` answers 200 plus a chunk in
`on_request`, then raises on the first body data; anything else answers
200 "ok" at request end. Every final response also tries one 1xx after
the final status, which must raise.
"""

from navette.http.body import BodyFrame
from navette.http.handler import Capabilities, RecvBody, ResponseWriter, StreamError, StreamHandler
from navette.http.headers import Headers
from navette.http.request import Request
from navette.http.status import StatusCode


def _bytes(s: String) -> List[Byte]:
    return List[Byte](s.as_bytes())


def _link(target: String) -> Headers:
    var h = Headers()
    h.add("link", target)
    return h^


struct ScriptHandler(StreamHandler):
    var requests: Int
    var late_armed: Bool
    var resets: Int
    var reset_kind: Int
    var reset_code: UInt32
    var info_after_final_raised: Bool
    var trailers: Int

    def __init__(out self):
        self.requests, self.late_armed, self.resets, self.reset_kind = 0, False, 0, -1
        self.reset_code, self.info_after_final_raised, self.trailers = 0, False, 0

    def on_request(mut self, var req: Request, mut body: RecvBody, mut resp: ResponseWriter, caps: Capabilities) raises:
        self.requests += 1
        if req.target == "/boom":
            raise "boom"
        if req.target == "/info":
            resp.send_informational(StatusCode(103), _link("</a>"))
            resp.send_informational(StatusCode(103), _link("</b>"))
        elif req.target == "/late":
            self.late_armed = True
            resp.send_status(StatusCode(200), Headers())
            _ = resp.try_send_body(BodyFrame.data(_bytes("part")))

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        if self.late_armed:
            raise "late failure"
        while True:
            var f = body.try_read()
            if not f:
                break
            if f.value().is_trailers():
                self.trailers += 1

    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        resp.send_status(StatusCode(200), Headers())
        try:
            resp.send_informational(StatusCode(103), Headers())
        except:
            self.info_after_final_raised = True
        _ = resp.try_send_body(BodyFrame.data(_bytes("ok")))
        resp.end()

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        self.resets += 1
        self.reset_kind, self.reset_code = error.kind, error.code
