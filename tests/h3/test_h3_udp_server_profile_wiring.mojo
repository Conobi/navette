"""Accept-profile wiring through the library UDP server's per-connection
construction (`test_h3_udp_server_profile_wiring.mojo`).

The headline defect this guards: `H3UdpServer.profile` was declared and
initialized but never handed to `QuicConnection.server` or the
per-connection `H3HandlerServer`, so every accept-profile counter family
stayed DEAD in the library server (the bench server wired both pointers;
the library server wired neither).

Construction is now extracted into `H3UdpServer._construct_conn_handler`
so these tests can exercise the REAL wiring without standing up an
io_uring loop:

  * `test_udp_construction_wires_profile` — both `profile_ptr` slots
    (`H3HandlerServer.profile_ptr` and the inner
    `H3Connection._quic.profile_ptr`) are non-None after construction, and
    the policy-on config also wires the early-data filter pointer.
  * `test_http_filter_counters_live_through_udp_construction` — a 1-RTT
    request driven through the constructed handler bumps
    `server.profile.zero_rtt_http_filter_1rtt_bypassed` by exactly one,
    proving the counter reached `server.profile` THROUGH the wired pointer
    chain (the defect-demonstration: pre-fix construction never passed
    `profile_ptr`, so this counter would stay at 0).

The 1-RTT counter only fires when 0-RTT is ENABLED (the `zero_rtt_enabled`
gate, Task 9), so the server is built with
`EarlyDataPolicy.idempotent_only()` — a policy-ON config that also
populates `_early_data_filter`.

The synthetic-event drive mirrors `test_h3_adapter_early_data_filter.mojo`:
toggle `_current_space_idx` to bookend a stream into the QUIC stream_map at
a chosen packet space, then invoke `_on_request` directly — no TLS/QPACK
handshake.
"""

from std.collections import Optional
from std.memory import Span, UnsafePointer

from navette.h3.connection import H3Event
from navette.h3.h3_udp_server import H3UdpServer
from navette.h3.qpack import QpackHeaderField
from navette.http.handler import (
    Capabilities,
    RecvBody,
    Request,
    ResponseWriter,
    StreamError,
    StreamHandler,
)
from navette.quic.frame import StreamFrame
from navette.quic.trans_param import default_transport_params
from navette.runtime.socket_helpers import udp_listener
from navette.tls.config import QuicServerConfig
from navette.tls.early_data_policy import EarlyDataPolicy
from navette.tls.lib import TlsBackend

from interop.file_io import read_file


# ---------------------------------------------------------------------------
# StubHandler — no-op StreamHandler (synthetic drive never reaches a body)
# ---------------------------------------------------------------------------


struct StubHandler(StreamHandler):
    """No-op handler. The synthetic-event drive feeds exactly one
    HEADERS_RECEIVED per test; none of the body/end/drain/reset callbacks
    are reached, so all five are `pass`."""

    def __init__(out self):
        pass

    def __init__(out self, *, deinit take: Self):
        pass

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        pass

    def on_body_available(
        mut self, mut body: RecvBody, mut resp: ResponseWriter
    ) raises:
        pass

    def on_request_end(
        mut self, mut body: RecvBody, mut resp: ResponseWriter
    ) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


def make_stub_handler() raises -> StubHandler:
    """Per-conn factory handed to `H3UdpServer`."""
    return StubHandler()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_policy_on_server() raises -> H3UdpServer[StubHandler]:
    """Build an `H3UdpServer[StubHandler]` on an ephemeral UDP port with
    `EarlyDataPolicy.idempotent_only()`.

    The policy-on config sets `max_early_data = u32::MAX`
    (`zero_rtt_enabled = True` at conn creation) AND populates
    `_early_data_filter`, so construction wires the early-data filter
    pointer as well as both profile pointers.
    """
    var cert = read_file(String("certs/server.crt"))
    var key = read_file(String("certs/server.key"))
    var tls = TlsBackend()
    var config = QuicServerConfig(
        tls.shared(),
        Span(cert),
        Span(key),
        policy=EarlyDataPolicy.idempotent_only(),
    )
    var sock = udp_listener(0)  # kernel picks a free port
    var tp = default_transport_params()
    return H3UdpServer[StubHandler](
        sock^,
        tls^,
        config^,
        tp^,
        make_stub_handler,
    )


def _synth_dcid() -> List[UInt8]:
    """An 8-byte synthetic client Initial DCID (all 0xAB)."""
    var dcid = List[UInt8]()
    for _ in range(8):
        dcid.append(UInt8(0xAB))
    return dcid^


def _build_get_event(stream_id: UInt64) raises -> H3Event:
    """Synthesise a finished `HEADERS_RECEIVED` GET event with the four
    pseudo-headers the adapter's QPACK walk requires."""
    var ev = H3Event(H3Event.HEADERS_RECEIVED)
    ev.stream_id = stream_id
    ev.fin = True
    ev.fields.append(QpackHeaderField(String(":method"), String("GET")))
    ev.fields.append(QpackHeaderField(String(":scheme"), String("https")))
    ev.fields.append(QpackHeaderField(String(":path"), String("/")))
    ev.fields.append(
        QpackHeaderField(String(":authority"), String("localhost"))
    )
    return ev^


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_udp_construction_wires_profile() raises:
    """The extracted constructor wires BOTH profile pointers (the H3
    adapter's and the inner QUIC connection's) plus the early-data filter
    pointer for a policy-on config."""
    var server = _make_policy_on_server()
    var dcid = _synth_dcid()
    var h3_ptr = server._construct_conn_handler(Span(dcid), UInt64(1_000_000))

    if h3_ptr[].profile_ptr is None:
        raise Error("H3HandlerServer.profile_ptr must be wired (got None)")
    if h3_ptr[]._h3._quic.profile_ptr is None:
        raise Error(
            "inner QuicConnection.profile_ptr must be wired (got None)"
        )
    if h3_ptr[]._early_data_filter_ptr is None:
        raise Error(
            "policy-on config must wire the early-data filter pointer"
            " (got None)"
        )

    h3_ptr.destroy_pointee()
    h3_ptr.free()
    # Extend the server's lifetime past the FFI-dependent reads above so
    # ASAP-destruction does not free `server.profile` mid-assertion.
    _ = server.profile
    print("PASS: test_udp_construction_wires_profile")


def test_http_filter_counters_live_through_udp_construction() raises:
    """A 1-RTT request driven through the constructed handler bumps
    `server.profile.zero_rtt_http_filter_1rtt_bypassed` by exactly one —
    proving the counter reached `server.profile` THROUGH the wired pointer
    chain. Pre-fix (no `profile_ptr`), the counter would stay at 0."""
    var server = _make_policy_on_server()
    var dcid = _synth_dcid()
    var h3_ptr = server._construct_conn_handler(Span(dcid), UInt64(1_000_000))

    # Precondition: the counter starts at zero.
    if server.profile.zero_rtt_http_filter_1rtt_bypassed != 0:
        raise Error("precondition: 1rtt_bypassed must start at 0")

    # Force a 1-RTT (Application-space) stream into the QUIC stream_map via
    # the `_current_space_idx` bookend, exactly like the production
    # per-packet dispatch loop. Application space (2) leaves the stream's
    # is_zero_rtt tag False -> the filter takes the 1-RTT bypass row.
    var APPLICATION_SPACE_IDX: Int = 2
    var stream_id: UInt64 = 0
    h3_ptr[]._h3._quic._current_space_idx = APPLICATION_SPACE_IDX
    var payload = List[UInt8]()
    payload.append(UInt8(0x00))
    var sf = StreamFrame(stream_id, UInt64(0), payload^, False)
    try:
        h3_ptr[]._h3._quic._handle_stream_frame(sf)
    except:
        pass
    h3_ptr[]._h3._quic._current_space_idx = -1

    var ev = _build_get_event(stream_id)
    h3_ptr[]._on_request(ev, UInt64(1_000_001))

    if server.profile.zero_rtt_http_filter_1rtt_bypassed != 1:
        raise Error(
            "1rtt_bypassed must be 1 after a 1-RTT request flows through"
            " the wired profile pointer (got "
            + String(Int(server.profile.zero_rtt_http_filter_1rtt_bypassed))
            + ")"
        )

    h3_ptr.destroy_pointee()
    h3_ptr.free()
    # ASAP-destruction bookend: keep `server` (and thus `server.profile`)
    # alive past the final counter read.
    _ = server.profile
    print("PASS: test_http_filter_counters_live_through_udp_construction")


def main() raises:
    """Driver for `scripts/run_tests.sh`."""
    print("=== test_h3_udp_server_profile_wiring ===")
    test_udp_construction_wires_profile()
    test_http_filter_counters_live_through_udp_construction()
    print("test_h3_udp_server_profile_wiring: PASS")
