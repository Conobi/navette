# navette/quic/event.mojo
#
# QuicEvent and Variant-based payload types.
#
# Extracted from connection.mojo for module cohesion. QuicEvent is
# the flat-tag event emitted by QuicConnection; the payload is a
# 6-element Variant indexed by type_id.

from std.utils import Variant


# ── QuicEvent payload structs ────────────────────────────────────────


struct ConnectionClosedPayload(Copyable, Movable):
    """Payload for QuicEvent.CONNECTION_CLOSED."""

    var error_code: UInt64
    var reason: String

    def __init__(out self, error_code: UInt64, var reason: String):
        """Construct with error code and reason phrase."""
        self.error_code = error_code
        self.reason = reason^


@fieldwise_init
struct StreamResetPayload(Copyable, Movable):
    """Payload for QuicEvent.STREAM_RESET."""

    var stream_id: UInt64
    var error_code: UInt64
    var final_size: UInt64


@fieldwise_init
struct StreamStoppedPayload(Copyable, Movable):
    """Payload for QuicEvent.STREAM_STOPPED."""

    var stream_id: UInt64
    var error_code: UInt64


comptime QuicEventPayload = Variant[
    NoneType,                  # HANDSHAKE_COMPLETE
    ConnectionClosedPayload,   # CONNECTION_CLOSED
    UInt64,                    # STREAM_READABLE, STREAM_WRITABLE, STREAM_OPENED (stream_id)
    StreamResetPayload,        # STREAM_RESET
    StreamStoppedPayload,      # STREAM_STOPPED
    List[Byte],               # DATAGRAM_RECEIVED
]


# ── QuicEvent ────────────────────────────────────────────────────────


struct QuicEvent(Copyable, Movable):
    """Event emitted by QuicConnection for the application layer.

    `type_id` identifies the event kind; `payload` holds the
    event-specific data via a 6-element Variant.
    """

    comptime HANDSHAKE_COMPLETE: UInt8 = 1
    comptime CONNECTION_CLOSED: UInt8 = 2
    comptime STREAM_READABLE: UInt8 = 5
    comptime STREAM_WRITABLE: UInt8 = 6
    comptime STREAM_RESET: UInt8 = 7
    comptime STREAM_STOPPED: UInt8 = 8
    comptime STREAM_OPENED: UInt8 = 9
    comptime DATAGRAM_RECEIVED: UInt8 = 10

    var type_id: UInt8
    var payload: QuicEventPayload

    def __init__(out self, type_id: UInt8, var payload: QuicEventPayload):
        """Construct with event type and payload variant."""
        self.type_id = type_id
        self.payload = payload^

    @staticmethod
    def handshake_complete() -> QuicEvent:
        return QuicEvent(QuicEvent.HANDSHAKE_COMPLETE, QuicEventPayload(NoneType()))

    @staticmethod
    def connection_closed(error_code: UInt64, var reason: String) -> QuicEvent:
        return QuicEvent(
            QuicEvent.CONNECTION_CLOSED,
            QuicEventPayload(ConnectionClosedPayload(error_code, reason^)),
        )

    @staticmethod
    def stream_readable(stream_id: UInt64) -> QuicEvent:
        return QuicEvent(QuicEvent.STREAM_READABLE, QuicEventPayload(stream_id))

    @staticmethod
    def stream_writable(stream_id: UInt64) -> QuicEvent:
        return QuicEvent(QuicEvent.STREAM_WRITABLE, QuicEventPayload(stream_id))

    @staticmethod
    def stream_reset(stream_id: UInt64, error_code: UInt64, final_size: UInt64) -> QuicEvent:
        return QuicEvent(
            QuicEvent.STREAM_RESET,
            QuicEventPayload(StreamResetPayload(stream_id, error_code, final_size)),
        )

    @staticmethod
    def stream_stopped(stream_id: UInt64, error_code: UInt64) -> QuicEvent:
        return QuicEvent(
            QuicEvent.STREAM_STOPPED,
            QuicEventPayload(StreamStoppedPayload(stream_id, error_code)),
        )

    @staticmethod
    def stream_opened(stream_id: UInt64) -> QuicEvent:
        return QuicEvent(QuicEvent.STREAM_OPENED, QuicEventPayload(stream_id))

    @staticmethod
    def datagram_received(var payload: List[Byte]) -> QuicEvent:
        """Surface a received DATAGRAM to the application (RFC 9221)."""
        return QuicEvent(QuicEvent.DATAGRAM_RECEIVED, QuicEventPayload(payload^))
