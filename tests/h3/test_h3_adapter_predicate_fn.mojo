"""Structural tests for the per-adapter `_early_data_predicate_fn` field.

Each of the three H3 server adapters (`H3HandlerServer`, `H3CoroServer`,
`H3StreamingServer`) must accept a `predicate_fn` kwarg on its main
constructor and store the supplied `Optional[EarlyDataPredicateFn]` on
its `_early_data_predicate_fn` field. The dispatch helper consults this
field at request time, in preference to `_early_data_filter_ptr`, per
the truth-table that backs the predicate variant of the 0-RTT policy.

Coverage scope:
  - Per-adapter ctor: passing `predicate_fn=Some(fn)` sets the field
    to a populated Optional; defaulting (no kwarg) leaves it as None.
  - The `H3UdpServer` -> `H3HandlerServer` propagation of the
    predicate-fn is covered by source inspection plus the continuing
    pass of `tests/h3/test_h3_adapter_early_data_filter.mojo` (the
    existing `early_data_filter_ptr` threading is unchanged; the new
    kwarg defaults to None at every legacy call site). Spinning up a
    real listener here would re-invent the wire-level test family;
    the QuicServerConfig-side field is independently covered by
    `tests/tls/test_quic_server_config_predicate.mojo`.
"""

from std.collections import Optional
from std.memory import Span, UnsafePointer

from boucle.stackful import CoroYielder

from navette.h3.h3_handler_server import H3HandlerServer
from navette.h3.h3_streaming_server import H3StreamingServer
from navette.h3.h3_sync_server import H3CoroServer, CoroStreamCtx
from navette.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
    StreamHandler,
)
from navette.http.headers import Headers
from navette.http.request import Request
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import default_transport_params
from navette.tls.config import QuicServerConfig
from navette.tls.early_data_filter import EarlyDataPredicateFn, FilterDecision
from navette.tls.lib import TlsBackend
from tests._test_util import assert_false, assert_true, load_test_cert


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


struct _NoopHandler(StreamHandler):
    """Minimal StreamHandler — never invoked in these structural tests."""

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

    def on_reset(self, error: StreamError):
        pass


def _accept_all_predicate(
    method: String, path: String, headers: Headers
) raises -> FilterDecision:
    """Test predicate — always returns accept. Used purely to obtain a
    non-null `EarlyDataPredicateFn` value the ctor stores; the
    dispatch helper itself is exercised by
    `tests/h3/test_early_data_filter_dispatch_widened.mojo`."""
    return FilterDecision.accept()


def _make_server_quic(
    lib: TlsBackend, ref cfg: QuicServerConfig
) raises -> QuicConnection:
    """Construct a server-side `QuicConnection` with synthetic DCID/SCID.

    The caller owns `lib` and `cfg`; both MUST outlive the returned
    `QuicConnection` (the QUIC layer borrows shared TLS state via the
    config handle). The handshake is NOT driven — these structural
    tests only exercise the H3 adapter ctor's field assignment.
    """
    var tp = default_transport_params()
    var dcid_a = List[UInt8]()
    var dcid_b = List[UInt8]()
    for _ in range(8):
        dcid_a.append(UInt8(0xab))
        dcid_b.append(UInt8(0xcd))
    var now = UInt64(1_000_000)
    return QuicConnection.server(
        lib.shared(), cfg, tp, Span(dcid_a), Span(dcid_b), now,
    )


def _make_cfg(lib: TlsBackend) raises -> QuicServerConfig:
    """Build a `QuicServerConfig` from the bundled test cert/key."""
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    return QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )


# ---------------------------------------------------------------------------
# H3BodyFn for H3CoroServer — required by the ctor; never invoked here.
# ---------------------------------------------------------------------------


def _noop_body_fn(
    ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]
) raises:
    pass


def _noop_streaming_handler(mut yld: CoroYielder) raises:
    pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_h3_handler_server_stores_predicate_fn() raises:
    """H3HandlerServer ctor accepts `predicate_fn=` and stores it."""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var cfg = _make_cfg(lib)
    var quic = _make_server_quic(lib, cfg)

    var server = H3HandlerServer[_NoopHandler](
        quic=quic^,
        handler=_NoopHandler(),
        predicate_fn=Optional[EarlyDataPredicateFn](_accept_all_predicate),
    )

    assert_true(
        server._early_data_predicate_fn is not None,
        String("predicate_fn=Some must populate _early_data_predicate_fn"),
    )
    _ = server._h3._quic.conn_handle
    _ = cfg._handle


def test_h3_handler_server_default_predicate_fn_is_none() raises:
    """H3HandlerServer ctor without `predicate_fn=` defaults to None."""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var cfg = _make_cfg(lib)
    var quic = _make_server_quic(lib, cfg)

    var server = H3HandlerServer[_NoopHandler](
        quic=quic^,
        handler=_NoopHandler(),
    )

    assert_false(
        server._early_data_predicate_fn is not None,
        String("default predicate_fn kwarg must leave field=None"),
    )
    _ = server._h3._quic.conn_handle
    _ = cfg._handle


def test_h3_sync_server_stores_predicate_fn() raises:
    """H3CoroServer (the sync adapter) accepts `predicate_fn=` and stores it."""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var cfg = _make_cfg(lib)
    var quic = _make_server_quic(lib, cfg)

    var server = H3CoroServer(
        quic=quic^,
        body_fn=_noop_body_fn,
        predicate_fn=Optional[EarlyDataPredicateFn](_accept_all_predicate),
    )

    assert_true(
        server._early_data_predicate_fn is not None,
        String("predicate_fn=Some must populate _early_data_predicate_fn"),
    )
    _ = server._h3._quic.conn_handle
    _ = cfg._handle


def test_h3_streaming_server_stores_predicate_fn() raises:
    """H3StreamingServer accepts `predicate_fn=` and stores it."""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var cfg = _make_cfg(lib)
    var quic = _make_server_quic(lib, cfg)

    var server = H3StreamingServer(
        quic=quic^,
        handler_fn=_noop_streaming_handler,
        predicate_fn=Optional[EarlyDataPredicateFn](_accept_all_predicate),
    )

    assert_true(
        server._early_data_predicate_fn is not None,
        String("predicate_fn=Some must populate _early_data_predicate_fn"),
    )
    _ = server._h3._quic.conn_handle
    _ = cfg._handle


def main() raises:
    """Driver for `scripts/run_tests.sh`: each test must be invoked here."""
    print("=== test_h3_adapter_predicate_fn ===")
    test_h3_handler_server_stores_predicate_fn()
    print("  test_h3_handler_server_stores_predicate_fn: PASS")
    test_h3_handler_server_default_predicate_fn_is_none()
    print("  test_h3_handler_server_default_predicate_fn_is_none: PASS")
    test_h3_sync_server_stores_predicate_fn()
    print("  test_h3_sync_server_stores_predicate_fn: PASS")
    test_h3_streaming_server_stores_predicate_fn()
    print("  test_h3_streaming_server_stores_predicate_fn: PASS")
    print("test_h3_adapter_predicate_fn: all tests passed")
    print("ok")
