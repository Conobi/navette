# bench/servers/h3_server.mojo
#
# HTTP/3 QUIC benchmark server for HttpArena on port 8443 (UDP).
#
# Uses navette's H3UdpServer[BenchHandler] driven by boucle's WatchLoop.
# H3UdpServer handles multishot recvmsg via DatagramStream, fire-and-forget
# sendmsg via WatchLoop.send_msg, and periodic timeout via TimerFuture.
# All io_uring details are hidden behind the WatchLoop abstraction.
#
# The event loop is: step the WatchLoop, flush the server (drain ingress,
# route packets, submit egress, poll timer). Profile instrumentation lives
# on H3UdpServer.profile (AcceptProfile); a SIGINT/SIGTERM handler triggers
# a text + JSON dump and clean exit.

from std.ffi import external_call
from std.memory import Pointer
from std.collections import Span, InlineArray
from std.memory.alloc import unsafe_alloc as _heap_alloc

from navette.h3.h3_udp_server import H3UdpServer
from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.quic.profile import AcceptProfile, PROFILE_ACCEPT, monotonic_us as profile_monotonic_us
from navette.runtime.socket_helpers import udp_listener
from bench.lib.handler import (
    BenchHandler,
    BenchState,
    _load_static_files,
    _load_dataset,
)
from interop.file_io import read_file, getenv_opt, write_file, mkdir_p
from boucle import WatchLoop


# ── constants ──────────────────────────────────────────────────────────

comptime _SQ_ENTRIES: Int = 4096

# Fixed-address page for the BenchState pointer, readable by the thin
# handler factory function that cannot capture runtime state.
comptime _STATE_PTR_ADDR: Int = 0x60001000


# ── Plan B SIGINT plumbing ────────────────────────────────────────────
#
# Mojo 0.26.2 forbids module-level `var`, so we cannot declare a global
# `Atomic[Int32]` flag. `comptime _heap_alloc(...)` is also unusable
# because each function captures its own copy of the comptime value
# (verified empirically — the address differs across `main` and
# `_profile_signal_handler`).
#
# Workaround: mmap a one-page anonymous mapping at a fixed low address.
# Both `main` and the signal handler agree on the literal `Int` constant
# `PROFILE_FLAG_ADDR`, so they read/write the same word. This is the
# simplest async-signal-safe state-sharing scheme available in 0.26.2.
# The signal handler itself does no allocation, no Mojo runtime calls,
# and no I/O — it just stores `1` to that word.
#
# `signal(2)` FFI signature: signal(int signum, void (*handler)(int))
# returns void (*)(int). We cast our `thin` fn pointer through Int and
# pass it as an opaque pointer. Empirically validated against libc.
comptime PROFILE_FLAG_ADDR: Int = 0x60000000  # 1.5 GiB — well below any heap
comptime PROFILE_MAP_PRIVATE: Int32 = 2
comptime PROFILE_MAP_ANON: Int32 = 0x20
comptime PROFILE_MAP_FIXED: Int32 = 0x110  # MAP_FIXED | MAP_FIXED_NOREPLACE (Linux 4.17+)
comptime PROFILE_PROT_RW: Int32 = 3
comptime PROFILE_SIGINT: Int32 = 2
comptime PROFILE_SIGTERM: Int32 = 15


def _profile_signal_handler(signo: Int32):
    # Async-signal-safe: store `1` to the fixed-address flag word. No
    # allocation, no print, no Mojo runtime.
    var p = Pointer[Int32, MutUntrackedOrigin](
        unsafe_from_address=PROFILE_FLAG_ADDR
    )
    p[unsafe_offset=0] = Int32(1)


def _profile_install_signal_handlers() raises:
    """Map the flag page and install SIGINT/SIGTERM handlers."""
    var hint = Pointer[NoneType, MutUntrackedOrigin](
        unsafe_from_address=PROFILE_FLAG_ADDR
    )
    var mapped = external_call["mmap", Pointer[NoneType, MutUntrackedOrigin]](
        hint,
        Int(4096),
        PROFILE_PROT_RW,
        PROFILE_MAP_PRIVATE | PROFILE_MAP_ANON | PROFILE_MAP_FIXED,
        Int32(-1),
        Int(0),
    )
    if Int(mapped) != PROFILE_FLAG_ADDR:
        raise "_profile_install_signal_handlers: mmap failed (address already in use or out of memory)"
    var p = Pointer[Int32, MutUntrackedOrigin](
        unsafe_from_address=PROFILE_FLAG_ADDR
    )
    p[unsafe_offset=0] = Int32(0)

    var fn_ptr: def(Int32) thin -> None = _profile_signal_handler
    var fp_value = Pointer(to=fn_ptr).unsafe_bitcast[UInt64]()[]
    var handler_ptr = Pointer[NoneType, MutUntrackedOrigin](
        unsafe_from_address=Int(fp_value)
    )
    _ = external_call["signal", Pointer[NoneType, MutUntrackedOrigin]](
        PROFILE_SIGINT, handler_ptr
    )
    _ = external_call["signal", Pointer[NoneType, MutUntrackedOrigin]](
        PROFILE_SIGTERM, handler_ptr
    )


@always_inline
def _profile_dump_pending() -> Bool:
    var p = Pointer[Int32, MutUntrackedOrigin](
        unsafe_from_address=PROFILE_FLAG_ADDR
    )
    return p[unsafe_offset=0] != Int32(0)


# ── Handler factory ───────────────────────────────────────────────────


def _make_bench_handler() raises -> BenchHandler:
    """Factory for BenchHandler, reads state_ptr from mmap'd page."""
    var p = Pointer[Pointer[BenchState, MutUntrackedOrigin], MutUntrackedOrigin](
        unsafe_from_address=_STATE_PTR_ADDR
    )
    return BenchHandler(p[unsafe_offset=0])


# ── Profile sidecar helpers ──────────────────────────────────────────


def _zpad2_int(n: Int) -> String:
    """Zero-pad an Int to 2 digits (used for UTC timestamp formatting)."""
    if n < 10:
        return String("0") + String(n)
    return String(n)


def _write_profile_json_sidecar(ref profile: AcceptProfile) raises:
    """Write profile JSON sidecar to bench/quic_perf/results/profile/.

    Dump-pending writes
    ``bench/quic_perf/results/profile/INSTRUMENTATION-<UTC ts>.json``
    containing ``profile.report_json()``. Creates the directory
    with mkdir -p semantics if absent.

    Args:
        profile: The AcceptProfile to serialize.
    """
    # 1. Compute UTC timestamp via time(2) + gmtime_r(3).
    var now_t = external_call["time", Int64](
        Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=Int(0))
    )
    var t_buf = InlineArray[Int64, 1](fill=now_t)
    var tm_buf = InlineArray[UInt8, 56](fill=0)
    var tm_ptr = Pointer(to=tm_buf).unsafe_bitcast[UInt8]()
    var t_ptr = Pointer(to=t_buf).unsafe_bitcast[Int64]()
    _ = external_call[
        "gmtime_r", Pointer[UInt8, MutUntrackedOrigin]
    ](t_ptr, tm_ptr)
    var tm_i32 = Pointer(to=tm_buf).unsafe_bitcast[Int32]()
    var sec = Int(tm_i32[unsafe_offset=0])
    var minu = Int(tm_i32[unsafe_offset=1])
    var hour = Int(tm_i32[unsafe_offset=2])
    var mday = Int(tm_i32[unsafe_offset=3])
    var mon = Int(tm_i32[unsafe_offset=4]) + 1
    var year = Int(tm_i32[unsafe_offset=5]) + 1900

    # 2. Format yyyymmdd-hhmmss with zero-padding.
    var ts = (
        String(year)
        + _zpad2_int(mon)
        + _zpad2_int(mday)
        + "-"
        + _zpad2_int(hour)
        + _zpad2_int(minu)
        + _zpad2_int(sec)
    )

    # 3. mkdir -p the sidecar directory (ignores EEXIST).
    var dir_path = String("bench/quic_perf/results/profile")
    try:
        mkdir_p(dir_path)
    except e:
        print("h3-bench: profile sidecar mkdir_p failed:", e)
        return

    # 4. Write JSON via interop.file_io.write_file (open/pwrite64/close).
    var path = dir_path + "/INSTRUMENTATION-" + ts + ".json"
    var json_text = profile.report_json()
    try:
        write_file(path, json_text.as_bytes())
    except e:
        print("h3-bench: profile sidecar write failed:", path, "err=", e)
        return
    print("h3-bench: profile sidecar written:", path)


# ── main ─────────────────────────────────────────────────────────────


def main() raises:
    """Run the HTTP/3-over-QUIC benchmark server until killed."""
    # Load static files from STATIC_DIR env var (default /data/static).
    var static_dir_opt = getenv_opt("STATIC_DIR")
    var static_dir: String
    if static_dir_opt.__bool__():
        static_dir = static_dir_opt.value()
    else:
        static_dir = String("/data/static")
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

    # Map state pointer page for the thin handler factory.
    var state_hint = Pointer[NoneType, MutUntrackedOrigin](
        unsafe_from_address=_STATE_PTR_ADDR
    )
    var state_mapped = external_call["mmap", Pointer[NoneType, MutUntrackedOrigin]](
        state_hint,
        Int(4096),
        PROFILE_PROT_RW,
        PROFILE_MAP_PRIVATE | PROFILE_MAP_ANON | PROFILE_MAP_FIXED,
        Int32(-1),
        Int(0),
    )
    if Int(state_mapped) != _STATE_PTR_ADDR:
        raise "h3-bench: mmap failed for state pointer page"
    var sp = Pointer[Pointer[BenchState, MutUntrackedOrigin], MutUntrackedOrigin](
        unsafe_from_address=_STATE_PTR_ADDR
    )
    sp[unsafe_offset=0] = state_ptr

    # Load TLS library and create server config.
    var certs_dir_opt = getenv_opt("CERTS_DIR")
    var certs_dir: String
    if certs_dir_opt.__bool__():
        certs_dir = certs_dir_opt.value()
    else:
        certs_dir = String("certs")

    var tls = TlsBackend()
    var cert = read_file(certs_dir + "/server.crt")
    var key = read_file(certs_dir + "/server.key")
    var server_config = QuicServerConfig(tls.shared(), Span(cert), Span(key))

    # Create UDP socket via the library factory.
    var port = 8443
    var sock = udp_listener(port)

    var worker_id_opt = getenv_opt("BENCH_WORKER_ID")
    var prefix: String
    if worker_id_opt.__bool__():
        prefix = "[h3-w" + worker_id_opt.value() + "] "
    else:
        prefix = ""

    # BENCH_WAIT_NR was an io_uring-specific knob (submit_and_wait floor).
    # WatchLoop hides that detail; report and move on.
    var wait_nr_opt = getenv_opt("BENCH_WAIT_NR")
    if wait_nr_opt.__bool__():
        var requested: Int
        try:
            requested = Int(wait_nr_opt.value())
        except:
            print(prefix + "h3-bench: BENCH_WAIT_NR parse failed, ignoring")
            requested = 1
        if requested != 1:
            print(
                prefix
                + "h3-bench: BENCH_WAIT_NR="
                + String(requested)
                + " unsupported (WatchLoop manages wait internally); ignoring"
            )

    # Install SIGINT/SIGTERM handler for profile dump + clean exit.
    comptime if PROFILE_ACCEPT:
        _profile_install_signal_handlers()

    # Build H3UdpServer[BenchHandler] and heap-allocate for pointer stability.
    var tp = default_transport_params()
    var server = H3UdpServer[BenchHandler](
        sock^, TlsBackend(copy=tls), server_config^, tp^, _make_bench_handler,
    )
    var srv_ptr = _heap_alloc[H3UdpServer[BenchHandler]](1)
    srv_ptr.unsafe_write(server^)
    srv_ptr[].wire_context()

    # WatchLoop event loop — step dispatches completions, flush drains
    # ingress / routes packets / submits egress / polls timer.
    var loop_ptr = _heap_alloc[WatchLoop](1)
    loop_ptr.unsafe_write(WatchLoop(capacity=_SQ_ENTRIES))
    srv_ptr[].start(loop_ptr[])

    print(prefix + "h3-bench: listening on https://[::]:" + String(port) + " (UDP/QUIC/H3)")

    while True:
        _ = loop_ptr[].step()
        srv_ptr[].flush()

        comptime if PROFILE_ACCEPT:
            if _profile_dump_pending():
                print(srv_ptr[].profile.report_text(), end="")
                _write_profile_json_sidecar(srv_ptr[].profile)
                _ = external_call["exit", NoneType](Int32(0))
