# src/http/sse.mojo
#
# Server-Sent Events (text/event-stream) — M2.5b §7.3.
#
# WHATWG HTML Living Standard §9.2 "Server-sent events" subset:
#   https://html.spec.whatwg.org/multipage/server-sent-events.html
#
# Not implemented in v1: UTF-8 BOM stripping (assume UTF-8 input),
# cross-field UTF-8 validation (the reader treats input as bytes),
# reconnection policy (that lives in M6's HttpClient).

from std.collections.optional import Optional


struct ServerSentEvent(Copyable, Movable):
    """One dispatched Server-Sent Event. Matches the WHATWG `event` dispatch
    step output: a UTF-8 `data` string, an optional type, optional last-event
    id, and an optional reconnection-time hint."""

    var event: Optional[String]
    var data: String
    var id: Optional[String]
    var retry: Optional[UInt]

    def __init__(out self):
        self.event = Optional[String]()
        self.data = String("")
        self.id = Optional[String]()
        self.retry = Optional[UInt]()

    def __init__(out self, *, other: Self):
        self.event = other.event
        self.data = other.data.copy()
        self.id = other.id
        self.retry = other.retry

    def __init__(out self, *, deinit take: Self):
        self.event = take.event^
        self.data = take.data^
        self.id = take.id^
        self.retry = take.retry^
