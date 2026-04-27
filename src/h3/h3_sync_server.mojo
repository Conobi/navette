# src/h3/h3_sync_server.mojo
#
# HTTP/3 server-side adapter — sans-IO codec wrapper. Feed inbound QUIC
# datagrams via `feed_datagram_from_buffer()`; drain outbound datagrams via
# `drain()`. Translates H3Connection events into a per-stream hand-written
# state machine, NOT stackful coroutines (Sprint 2A Path A — mirrors
# Sprint 1's H2CoroServer over QUIC).
#
# The "Coro" in `CoroStreamCtx` is preserved to mirror the H2 sister-file's
# naming (Sprint 1 chose to leave it that way to minimise churn). A future
# rename pass can unify both names — out of scope here.
#
# See plans/2026-04-27-sprint-2a-h1h3-sync.md.

from std.collections import Dict, Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.sys.info import size_of

from src.quic.connection import QuicConnection
from src.h3.connection import H3Connection, H3Event
from src.h3.error import H3_REQUEST_CANCELLED
from src.h3.qpack import QpackHeaderField
from src.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from src.http.body import BodyFrame
from src.http.headers import Headers
from src.http.method import Method
from src.http.request import Request
from src.http.status import StatusCode
from src.http.version import Version
