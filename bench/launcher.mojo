# bench/launcher.mojo
#
# Multi-process benchmark launcher. Spawns N copies of each bench
# server binary with SO_REUSEPORT. Same model as nginx workers.
#
# Signal handling: we cannot use a C-style signal handler with a
# module-level mutable pointer (Mojo forbids module-level mutable vars).
# Instead children set PR_SET_PDEATHSIG = SIGTERM so they die automatically
# when the launcher exits, and the launcher's main loop simply runs until
# interrupted (SIGINT/SIGTERM kills the process via default disposition).
# A pipe-based self-wakeup is used: the monitor loop polls with usleep.

from std.ffi import external_call
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

comptime MAX_RESTARTS: Int = 3
comptime POLL_INTERVAL_US: UInt32 = 500000  # 500 ms

comptime SIGTERM: Int32 = 15
comptime SIGKILL: Int32 = 9
comptime WNOHANG: Int32 = 1

# prctl constants
comptime PR_SET_PDEATHSIG: Int32 = 1


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

    var name_buf = _heap_alloc[UInt8](len(name_bytes) + 1).as_any_origin()
    for i in range(len(name_bytes)):
        name_buf[i] = name_bytes[i]
    name_buf[len(name_bytes)] = 0

    var val_buf = _heap_alloc[UInt8](len(val_bytes) + 1).as_any_origin()
    for i in range(len(val_bytes)):
        val_buf[i] = val_bytes[i]
    val_buf[len(val_bytes)] = 0

    _ = external_call["setenv", Int32](name_buf, val_buf, Int32(1))
    name_buf.free()
    val_buf.free()


def _find_binary(name: String) raises -> String:
    """Find a server binary: check /usr/local/bin first (Docker), then bench/."""
    var docker_path = "/usr/local/bin/" + name
    var local_path = "bench/" + name

    # Try Docker path first via access(2), X_OK = 1
    var docker_bytes = docker_path.as_bytes()
    var path_buf = _heap_alloc[UInt8](len(docker_bytes) + 1).as_any_origin()
    for i in range(len(docker_bytes)):
        path_buf[i] = docker_bytes[i]
    path_buf[len(docker_bytes)] = 0

    var rc = external_call["access", Int32](path_buf, Int32(1))
    path_buf.free()

    if rc == 0:
        return docker_path

    # Try local path
    var local_bytes = local_path.as_bytes()
    var path_buf2 = _heap_alloc[UInt8](len(local_bytes) + 1).as_any_origin()
    for i in range(len(local_bytes)):
        path_buf2[i] = local_bytes[i]
    path_buf2[len(local_bytes)] = 0

    var rc2 = external_call["access", Int32](path_buf2, Int32(1))
    path_buf2.free()

    if rc2 == 0:
        return local_path

    raise "binary not found: " + name


def _spawn_worker(binary_path: String, server_type: String, worker_id: Int) raises -> Int32:
    """Fork and exec a server binary. Returns child PID."""
    _setenv("BENCH_WORKER_ID", String(worker_id))

    var pid = external_call["fork", Int32]()
    if pid < 0:
        raise "fork() failed"

    if pid == 0:
        # Child process: ask the kernel to send us SIGTERM when the parent exits.
        _ = external_call["prctl", Int32](PR_SET_PDEATHSIG, SIGTERM, Int32(0), Int32(0), Int32(0))

        # exec the server binary.
        var path_bytes = binary_path.as_bytes()
        var path_buf = _heap_alloc[UInt8](len(path_bytes) + 1).as_any_origin()
        for i in range(len(path_bytes)):
            path_buf[i] = path_bytes[i]
        path_buf[len(path_bytes)] = 0

        # Build argv: [path, NULL]
        var argv = _heap_alloc[UnsafePointer[UInt8, MutAnyOrigin]](2).as_any_origin()
        argv[0] = path_buf
        argv[1] = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=0)

        # envp = NULL (inherit parent environment)
        var envp = UnsafePointer[UnsafePointer[UInt8, MutAnyOrigin], MutAnyOrigin](
            unsafe_from_address=0
        )

        _ = external_call["execve", Int32](path_buf, argv, envp)

        # If execve failed, exit child.
        _ = external_call["_exit", Int32](Int32(127))

    return pid


def _kill_children(children: List[ProcessInfo], sig: Int32):
    """Send a signal to all non-dead children."""
    for i in range(len(children)):
        if not children[i].dead:
            _ = external_call["kill", Int32](children[i].pid, sig)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
    # Read worker count from BENCH_WORKERS env (default: CPU count).
    var workers_per_server: Int

    var env_name = "BENCH_WORKERS"
    var env_bytes = env_name.as_bytes()
    var env_buf = _heap_alloc[UInt8](len(env_bytes) + 1).as_any_origin()
    for i in range(len(env_bytes)):
        env_buf[i] = env_bytes[i]
    env_buf[len(env_bytes)] = 0

    var env_ptr = external_call["getenv", UnsafePointer[UInt8, MutAnyOrigin]](env_buf)
    env_buf.free()

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

    # Find server binaries.
    var h1_bin = _find_binary("h1_server")
    var h2_bin = _find_binary("h2_server")
    var h3_bin = _find_binary("h3_server")

    print("[launcher] h1=" + h1_bin + " h2=" + h2_bin + " h3=" + h3_bin)

    # Spawn workers.
    var children = List[ProcessInfo]()

    var server_types = List[String]()
    server_types.append("h1")
    server_types.append("h2")
    server_types.append("h3")

    var server_bins = List[String]()
    server_bins.append(h1_bin)
    server_bins.append(h2_bin)
    server_bins.append(h3_bin)

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

    # Monitor loop: check children every 500 ms.
    # The loop runs until the process receives SIGTERM/SIGINT (default
    # disposition terminates us) — children survive via PR_SET_PDEATHSIG
    # and will themselves receive SIGTERM when we die.
    var status_buf = _heap_alloc[Int32](1).as_any_origin()

    while True:
        _ = external_call["usleep", Int32](POLL_INTERVAL_US)

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

                if children[i].restart_count < MAX_RESTARTS:
                    children[i].restart_count += 1
                    var bin_path: String
                    if children[i].server_type == "h1":
                        bin_path = h1_bin
                    elif children[i].server_type == "h2":
                        bin_path = h2_bin
                    else:
                        bin_path = h3_bin

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
                    print(
                        "[launcher] "
                        + children[i].server_type
                        + " worker "
                        + String(children[i].worker_id)
                        + " exceeded max restarts, marking dead"
                    )
                    children[i].dead = True

            i += 1

    status_buf.free()
    print("[launcher] all children reaped, exiting")
