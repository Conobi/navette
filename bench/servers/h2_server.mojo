# bench/servers/h2_server.mojo
#
# HTTP/2 TLS benchmark server on port 8443 (TCP).
#
# Uses navette's H2TcpServer[BenchHandler] with bouclette's WatchLoop for
# all I/O (accept, recv, send). The library server handles TLS negotiation,
# HTTP/2 framing, per-connection lifecycle, and buffer management internally.
#
# BenchHandler (StreamHandler impl) dispatches requests to the benchmark
# endpoints. A thin function pointer factory reads the shared BenchState
# pointer from a fixed mmap'd address, since Mojo thin fn ptrs cannot
# capture runtime values.

from std.ffi import external_call
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc

from navette.h2.h2_tcp_server import H2TcpServer
from navette.tls import TlsServerConfig
from navette.tls.lib import TlsBackend
from navette.runtime.socket_helpers import tcp_listener
from bench.lib.handler import (
    BenchHandler,
    BenchState,
    _load_static_files,
    _load_dataset,
)

from bouclette import WatchLoop

from interop.file_io import read_file, getenv_opt


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
comptime _SQ_ENTRIES: Int = 4096
comptime _LISTEN_PORT: UInt16 = 8443
comptime _STATE_PTR_ADDR: Int = 0x60001000


# ---------------------------------------------------------------------------
# Handler factory — reads BenchState pointer from mmap'd page
# ---------------------------------------------------------------------------


def _make_bench_handler() raises -> BenchHandler:
    """Factory called once per accepted connection by H2TcpServer."""
    var p = Pointer[Pointer[BenchState, MutUntrackedOrigin], MutUntrackedOrigin](
        unsafe_from_address=_STATE_PTR_ADDR
    )
    return BenchHandler(p[unsafe_offset=0])


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
    """Run the HTTP/2-over-TLS benchmark server until killed."""
    # Load certs
    var certs_dir_opt = getenv_opt("CERTS_DIR")
    var certs_dir: String
    if Bool(certs_dir_opt):
        certs_dir = certs_dir_opt.unsafe_take()
    else:
        certs_dir = String("/certs")

    var static_dir_opt = getenv_opt("STATIC_DIR")
    var static_dir: String
    if Bool(static_dir_opt):
        static_dir = static_dir_opt.unsafe_take()
    else:
        static_dir = String("/data/static")

    var cert_pem = read_file(certs_dir + "/server.crt")
    var key_pem = read_file(certs_dir + "/server.key")

    # TLS setup
    var tls = TlsBackend()
    var shared = tls.shared()
    var server_config = TlsServerConfig(
        shared, Span(cert_pem), Span(key_pem)
    )
    var server_alpn = List[String]()
    server_alpn.append("h2")
    server_config.set_alpn_protocols(server_alpn)

    # Load static files
    var cache = _load_static_files(static_dir)

    # Load dataset for the /json profile from DATA_DIR (default /data).
    var data_dir_opt = getenv_opt("DATA_DIR")
    var data_dir: String
    if data_dir_opt.__bool__():
        data_dir = data_dir_opt.value()
    else:
        data_dir = String("/data")
    var dataset = _load_dataset(data_dir + "/dataset.json")

    # Heap-allocate combined bench state.
    var bstate = BenchState(static_cache=cache^, dataset=dataset^)
    var state_ptr = _heap_alloc[BenchState](1)
    state_ptr.unsafe_write(bstate^)

    # Map state pointer page so the handler factory can reach it.
    var hint = Pointer[NoneType, MutUntrackedOrigin](
        unsafe_from_address=_STATE_PTR_ADDR
    )
    var mapped = external_call["mmap", Pointer[NoneType, MutUntrackedOrigin]](
        hint,
        Int(4096),
        Int32(3),
        Int32(2) | Int32(0x20) | Int32(0x110),
        Int32(-1),
        Int(0),
    )
    if Int(mapped) != _STATE_PTR_ADDR:
        raise "h2-bench: mmap failed for state pointer page"
    var sp = Pointer[Pointer[BenchState, MutUntrackedOrigin], MutUntrackedOrigin](
        unsafe_from_address=_STATE_PTR_ADDR
    )
    sp[unsafe_offset=0] = state_ptr

    # Listening socket (dual-stack, SO_REUSEPORT via tcp_listener).
    var listener = tcp_listener(Int(_LISTEN_PORT))

    var worker_id_opt = getenv_opt("BENCH_WORKER_ID")
    var prefix: String
    if worker_id_opt.__bool__():
        prefix = "[h2-w" + worker_id_opt.value() + "] "
    else:
        prefix = ""
    print(prefix + "h2-bench: listening on https://[::]:8443")

    # Build H2TcpServer[BenchHandler].
    var server = H2TcpServer[BenchHandler](
        listener^,
        _make_bench_handler,
        TlsBackend(copy=tls),
        server_config^,
    )
    var srv_ptr = _heap_alloc[H2TcpServer[BenchHandler]](1)
    srv_ptr.unsafe_write(server^)

    # WatchLoop event loop.
    var loop = WatchLoop(capacity=_SQ_ENTRIES)
    srv_ptr[].start(loop)

    while True:
        _ = loop.step(timeout_ms=-1)
        srv_ptr[].poll_accept()
        srv_ptr[].poll_connections()
        srv_ptr[].reap_closed()
