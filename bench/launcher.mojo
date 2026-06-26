# bench/launcher.mojo
#
# Multi-process benchmark launcher. Spawns N copies of each bench
# server binary with SO_REUSEPORT. Same model as nginx workers.
#
# Signal handling: SIGTERM/SIGINT are blocked via sigprocmask at startup,
# then checked synchronously each loop iteration via sigtimedwait with a
# 500ms timeout. No module-level mutable vars needed.

from std.ffi import external_call
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from navette.util.owned_alloc import Owned


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

comptime MAX_RESTARTS: Int = 3

comptime SIGTERM: Int32 = 15
comptime SIGINT: Int32 = 2
comptime SIGKILL: Int32 = 9
comptime WNOHANG: Int32 = 1

# sigprocmask "how" constants
comptime SIG_BLOCK: Int32 = 0

# sigset_t size on Linux x86_64: 128 bytes (1024 bits / 8)
comptime SIGSET_SIZE: Int = 128

# kernel_timespec: 16 bytes (tv_sec i64 + tv_nsec i64)
comptime TIMESPEC_SIZE: Int = 16


# ---------------------------------------------------------------------------
# ProcessInfo
# ---------------------------------------------------------------------------


struct ProcessInfo(Copyable, Movable):
    """Tracks a spawned worker process."""
    var pid: Int32
    var server_type: String
    var worker_id: Int
    var restart_count: Int
    var dead: Bool

    def __init__(out self, pid: Int32, var server_type: String, worker_id: Int):
        self.pid = pid
        self.server_type = server_type^
        self.worker_id = worker_id
        self.restart_count = 0
        self.dead = False

    def __init__(out self, *, other: Self):
        self.pid = other.pid
        self.server_type = String(copy=other.server_type)
        self.worker_id = other.worker_id
        self.restart_count = other.restart_count
        self.dead = other.dead

    def __init__(out self, *, deinit take: Self):
        self.pid = take.pid
        self.server_type = take.server_type^
        self.worker_id = take.worker_id
        self.restart_count = take.restart_count
        self.dead = take.dead


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_cpu_count() -> Int:
    """Get number of online CPUs via sysconf(_SC_NPROCESSORS_ONLN)."""
    var n = external_call["sysconf", Int64](Int32(84))  # _SC_NPROCESSORS_ONLN = 84
    if n <= 0:
        return 1
    return Int(n)


def _setenv(name: String, value: String):
    """Set an environment variable via setenv(3)."""
    var name_bytes = name.as_bytes()
    var val_bytes = value.as_bytes()

    var name_buf_buf = Owned[UInt8](len(name_bytes) + 1)
    var name_buf = name_buf_buf.ptr()
    for i in range(len(name_bytes)):
        name_buf[i] = name_bytes[i]
    name_buf[len(name_bytes)] = 0

    var val_buf_buf = Owned[UInt8](len(val_bytes) + 1)
    var val_buf = val_buf_buf.ptr()
    for i in range(len(val_bytes)):
        val_buf[i] = val_bytes[i]
    val_buf[len(val_bytes)] = 0

    _ = external_call["setenv", Int32](name_buf, val_buf, Int32(1))
    # Keep buffers alive across the setenv FFI call above.
    _ = name_buf_buf
    _ = val_buf_buf


def _find_binary(name: String) raises -> String:
    """Find a server binary: check /usr/local/bin first (Docker), then bench/."""
    var docker_path = "/usr/local/bin/" + name
    var local_path = "bench/" + name

    # Try Docker path first via access(2), X_OK = 1
    var docker_bytes = docker_path.as_bytes()
    var path_buf_buf = Owned[UInt8](len(docker_bytes) + 1)
    var path_buf = path_buf_buf.ptr()
    for i in range(len(docker_bytes)):
        path_buf[i] = docker_bytes[i]
    path_buf[len(docker_bytes)] = 0

    var rc = external_call["access", Int32](path_buf, Int32(1))
    # Keep path_buf alive across the access FFI call above.
    _ = path_buf_buf

    if rc == 0:
        return docker_path

    # Try local path
    var local_bytes = local_path.as_bytes()
    var path_buf2_buf = Owned[UInt8](len(local_bytes) + 1)
    var path_buf2 = path_buf2_buf.ptr()
    for i in range(len(local_bytes)):
        path_buf2[i] = local_bytes[i]
    path_buf2[len(local_bytes)] = 0

    var rc2 = external_call["access", Int32](path_buf2, Int32(1))
    # Keep path_buf2 alive across the access FFI call above.
    _ = path_buf2_buf

    if rc2 == 0:
        return local_path

    raise "binary not found: " + name


def _spawn_worker(binary_path: String, server_type: String, worker_id: Int) raises -> Int32:
    """Fork and exec a server binary. Returns child PID.

    Role-specific env (BENCH_H1_TLS for the h1tls sidecar) is set inside
    the child between fork and execv so it doesn't leak into siblings.
    """
    _setenv("BENCH_WORKER_ID", String(worker_id))

    var pid = external_call["fork", Int32]()
    if pid < 0:
        raise "fork() failed"

    if pid == 0:
        # Child process — apply role-specific env, then exec.
        if server_type == "h1tls":
            _setenv("BENCH_H1_TLS", String("1"))
            _setenv("BENCH_H1_PORT", String("8081"))
            _setenv("BENCH_H1_ROLE", String("h1tls"))
        elif server_type == "h1":
            _setenv("BENCH_H1_TLS", String("0"))
            _setenv("BENCH_H1_PORT", String("8080"))
            _setenv("BENCH_H1_ROLE", String("h1"))

        var path_bytes = binary_path.as_bytes()
        var path_buf_buf = Owned[UInt8](len(path_bytes) + 1)
        var path_buf = path_buf_buf.ptr()
        for i in range(len(path_bytes)):
            path_buf[i] = path_bytes[i]
        path_buf[len(path_bytes)] = 0

        # Build argv: [path, NULL]
        var argv_buf = Owned[UnsafePointer[UInt8, MutAnyOrigin]](2)
        var argv = argv_buf.ptr()
        argv[0] = path_buf.as_unsafe_any_origin()
        argv[1] = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=Int(0))

        _ = external_call["execv", Int32](path_buf, argv)

        # Keep buffers alive across the execv FFI call above (no return on
        # success — the child image is replaced; on failure we _exit below).
        _ = path_buf_buf
        _ = argv_buf

        # If execv failed, exit child.
        _ = external_call["_exit", Int32](Int32(127))

    return pid


def _binary_for_type(server_type: String) -> String:
    """Map a server role to its binary basename.

    h1 and h1tls share the same binary (TLS toggled via env).
    """
    if server_type == "h1tls":
        return String("h1_server")
    return server_type + "_server"


def _kill_children(children: List[ProcessInfo], sig: Int32):
    """Send a signal to all non-dead children."""
    for i in range(len(children)):
        if not children[i].dead:
            _ = external_call["kill", Int32](children[i].pid, sig)


def _make_sigset(sig1: Int32, sig2: Int32) -> UnsafePointer[UInt8, MutAnyOrigin]:
    """Create a sigset_t with sig1 and sig2 added."""
    var ss = _heap_alloc[UInt8](SIGSET_SIZE).as_any_origin()
    # sigemptyset: zero all 128 bytes
    for i in range(SIGSET_SIZE):
        ss[i] = 0
    # sigaddset: set bit (sig - 1) in the bitmask
    # Signal N is bit (N-1) in the 1024-bit set.
    var bit1 = Int(sig1) - 1
    ss[bit1 // 8] = ss[bit1 // 8] | UInt8(1 << (bit1 % 8))
    var bit2 = Int(sig2) - 1
    ss[bit2 // 8] = ss[bit2 // 8] | UInt8(1 << (bit2 % 8))
    return ss


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
    # Block SIGTERM and SIGINT so they can be caught by sigtimedwait.
    var sigset = _make_sigset(SIGTERM, SIGINT)
    var null_set = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=Int(0))
    _ = external_call["sigprocmask", Int32](SIG_BLOCK, sigset, null_set)

    # Read worker count from BENCH_WORKERS env (default: CPU count).
    var workers_per_server: Int

    var env_name = "BENCH_WORKERS"
    var env_bytes = env_name.as_bytes()
    var env_buf_buf = Owned[UInt8](len(env_bytes) + 1)
    var env_buf = env_buf_buf.ptr()
    for i in range(len(env_bytes)):
        env_buf[i] = env_bytes[i]
    env_buf[len(env_bytes)] = 0

    var env_ptr = external_call["getenv", UnsafePointer[UInt8, MutAnyOrigin]](env_buf)
    # Keep env_buf alive across the getenv FFI call above.
    _ = env_buf_buf

    if Int(env_ptr) != 0:
        var val = 0
        var j = 0
        while env_ptr[j] != 0 and j < 10:
            var digit = Int(env_ptr[j]) - 48
            if digit >= 0 and digit <= 9:
                val = val * 10 + digit
            j += 1
        if val > 0:
            workers_per_server = val
        else:
            workers_per_server = _get_cpu_count()
    else:
        workers_per_server = _get_cpu_count()

    print("[launcher] workers per server: " + String(workers_per_server))

    # Read optional BENCH_PROTOCOL filter (e.g. "h1", "h2", "h3").
    # If unset or empty, all protocols are launched.
    var proto_env_name = "BENCH_PROTOCOL"
    var proto_env_bytes = proto_env_name.as_bytes()
    var proto_env_buf_buf = Owned[UInt8](len(proto_env_bytes) + 1)
    var proto_env_buf = proto_env_buf_buf.ptr()
    for i in range(len(proto_env_bytes)):
        proto_env_buf[i] = proto_env_bytes[i]
    proto_env_buf[len(proto_env_bytes)] = 0

    var proto_ptr = external_call["getenv", UnsafePointer[UInt8, MutAnyOrigin]](proto_env_buf)
    # Keep proto_env_buf alive across the getenv FFI call above.
    _ = proto_env_buf_buf

    var protocol_filter = String("")
    if Int(proto_ptr) != 0:
        var pf_len = 0
        while proto_ptr[pf_len] != 0 and pf_len < 10:
            pf_len += 1
        if pf_len > 0:
            var pf_bytes = List[UInt8]()
            for i in range(pf_len):
                pf_bytes.append(proto_ptr[i])
            protocol_filter = String(from_utf8=pf_bytes^)

    if protocol_filter:
        print("[launcher] protocol filter: " + protocol_filter)

    # Find server binaries and build filtered lists.
    var server_types = List[String]()
    var server_bins = List[String]()

    var all_types = List[String]()
    all_types.append("h1")
    all_types.append("h1tls")
    all_types.append("h2")
    all_types.append("h3")

    for i in range(len(all_types)):
        if not protocol_filter or all_types[i] == protocol_filter:
            var bin = _find_binary(_binary_for_type(all_types[i]))
            print("[launcher] " + all_types[i] + "=" + bin)
            server_types.append(String(copy=all_types[i]))
            server_bins.append(bin)

    if len(server_types) == 0:
        raise "no matching protocol for BENCH_PROTOCOL=" + protocol_filter

    # Spawn workers.
    var children = List[ProcessInfo]()

    for s in range(len(server_types)):
        for w in range(workers_per_server):
            var pid = _spawn_worker(server_bins[s], server_types[s], w)
            print(
                "[launcher] spawned "
                + server_types[s]
                + " worker "
                + String(w)
                + " pid="
                + String(pid)
            )
            children.append(ProcessInfo(pid, String(copy=server_types[s]), w))

    # Monitor loop: use sigtimedwait with 500ms timeout.
    # Returns signal number if caught, -1 with errno=EAGAIN on timeout.
    var status_buf_buf = Owned[Int32](1)
    var status_buf = status_buf_buf.ptr()
    var ts_buf = Owned[UInt8](TIMESPEC_SIZE)
    var ts = ts_buf.ptr()
    for i in range(TIMESPEC_SIZE):
        ts[i] = 0
    # tv_sec = 0, tv_nsec = 500_000_000 (500ms) = 0x1DCD6500 LE
    ts[8] = 0x00
    ts[9] = 0x65
    ts[10] = 0xCD
    ts[11] = 0x1D

    var null_info = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=Int(0))
    var shutdown = False

    while not shutdown:
        # Check for SIGTERM/SIGINT with 500ms timeout.
        var sig = external_call["sigtimedwait", Int32](sigset, null_info, ts)
        if sig == SIGTERM or sig == SIGINT:
            shutdown = True

        # Check children via waitpid(WNOHANG).
        var i = 0
        while i < len(children):
            if children[i].dead:
                i += 1
                continue

            status_buf[0] = 0
            var wpid = external_call["waitpid", Int32](
                children[i].pid, status_buf, WNOHANG
            )

            if wpid > 0:
                var exit_status = Int(status_buf[0])
                print(
                    "[launcher] "
                    + children[i].server_type
                    + " worker "
                    + String(children[i].worker_id)
                    + " (pid="
                    + String(children[i].pid)
                    + ") exited with status "
                    + String(exit_status)
                )

                if children[i].restart_count < MAX_RESTARTS and not shutdown:
                    children[i].restart_count += 1
                    var bin_path = _find_binary(_binary_for_type(children[i].server_type))

                    try:
                        var new_pid = _spawn_worker(
                            bin_path,
                            children[i].server_type,
                            children[i].worker_id,
                        )
                        children[i].pid = new_pid
                        print(
                            "[launcher] restarted "
                            + children[i].server_type
                            + " worker "
                            + String(children[i].worker_id)
                            + " pid="
                            + String(new_pid)
                            + " (restart "
                            + String(children[i].restart_count)
                            + "/"
                            + String(MAX_RESTARTS)
                            + ")"
                        )
                    except e:
                        print("[launcher] respawn failed: " + String(e))
                        children[i].dead = True
                else:
                    if not shutdown:
                        print(
                            "[launcher] "
                            + children[i].server_type
                            + " worker "
                            + String(children[i].worker_id)
                            + " exceeded max restarts, marking dead"
                        )
                    children[i].dead = True

            i += 1

    # Graceful shutdown: SIGTERM to all children.
    print("[launcher] shutdown requested, sending SIGTERM to children...")
    _kill_children(children, SIGTERM)

    # Wait up to 5 seconds for children to exit.
    _ = external_call["usleep", Int32](UInt32(5000000))

    # SIGKILL any survivors.
    for i in range(len(children)):
        if children[i].dead:
            continue
        status_buf[0] = 0
        var wpid = external_call["waitpid", Int32](
            children[i].pid, status_buf, WNOHANG
        )
        if wpid == 0:
            # Still alive — force kill.
            print(
                "[launcher] SIGKILL "
                + children[i].server_type
                + " worker "
                + String(children[i].worker_id)
            )
            _ = external_call["kill", Int32](children[i].pid, SIGKILL)
            _ = external_call["waitpid", Int32](
                children[i].pid, status_buf, Int32(0)
            )

    sigset.free()
    # Keep Owned buffers alive across the monitor loop's FFI calls above.
    _ = ts_buf
    _ = status_buf_buf
    print("[launcher] all children reaped, exiting")
