# interop/file_io.mojo
#
# Syscall-based file I/O and environment variable helpers for the QUIC
# Interop Runner test infrastructure.  Isolated from src/ — no production
# code imports.
#
# Syscall numbers (x86_64 Linux):
#   SYS_read       =   0
#   SYS_write      =   1
#   SYS_open       =   2
#   SYS_close      =   3
#   SYS_fstat      =   5
#   SYS_mkdir      =  83
#   SYS_getdents64 = 217

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc
from std.collections import Optional

# ── open flags (x86_64 Linux) ─────────────────────────────────────────────────

comptime O_RDONLY: Int32 = 0
comptime O_WRONLY: Int32 = 1
comptime O_CREAT: Int32 = 64
comptime O_TRUNC: Int32 = 512
comptime O_DIRECTORY: Int32 = 65536

# Mode 0644 = 420, mode 0755 = 493
comptime MODE_644: Int32 = 420
comptime MODE_755: Int32 = 493


# ── internal helpers ──────────────────────────────────────────────────────────


def _to_cstr(s: String) -> UnsafePointer[UInt8, MutAnyOrigin]:
    """Allocate a null-terminated C string from a Mojo String.
    Caller must call .free() on the returned pointer."""
    var slen = len(s)
    var buf = alloc[UInt8](slen + 1).as_any_origin()
    var bytes = s.as_bytes()
    for i in range(slen):
        buf[i] = bytes[i]
    buf[slen] = 0
    return buf


def _ptr_to_string(ptr: UnsafePointer[UInt8, MutAnyOrigin]) -> String:
    """Read a null-terminated C string into a Mojo String."""
    var result = String()
    var i = 0
    while ptr[i] != 0:
        result += chr(Int(ptr[i]))
        i += 1
    return result^


# ── public API ────────────────────────────────────────────────────────────────


def read_file(path: String) raises -> List[UInt8]:
    """Read entire file via open/fstat/read/close."""
    var pbuf = _to_cstr(path)
    var fd = external_call["open", Int32](pbuf, O_RDONLY, Int32(0))
    pbuf.free()
    if fd < 0:
        raise "read_file: open failed for " + path

    # fstat64 — struct stat on x86_64 is 144 bytes; st_size is 8 bytes at offset 48
    var statbuf = alloc[UInt8](144).as_any_origin()
    var fstat_rc = external_call["fstat64", Int32](fd, statbuf)
    if fstat_rc < 0:
        _ = external_call["close", Int32](fd)
        statbuf.free()
        raise "read_file: fstat64 failed"

    var file_size: Int = 0
    for i in range(8):
        file_size |= Int(statbuf[48 + i]) << (i * 8)
    statbuf.free()

    # Read in 65536-byte chunks via pread64
    var result = List[UInt8](capacity=file_size)
    var chunk_size = 65536
    var buf = alloc[UInt8](chunk_size).as_any_origin()
    var offset = 0
    while offset < file_size:
        var to_read = min(chunk_size, file_size - offset)
        var n = external_call["pread64", Int](Int32(fd), buf, to_read, offset)
        if n < 0:
            buf.free()
            _ = external_call["close", Int32](fd)
            raise "read_file: pread64 failed"
        if n == 0:
            break
        for i in range(n):
            result.append(buf[i])
        offset += n
    buf.free()
    _ = external_call["close", Int32](fd)
    return result^


def write_file(path: String, data: Span[UInt8, _]) raises:
    """Write data to file via open/write/close."""
    var pbuf = _to_cstr(path)
    # O_WRONLY | O_CREAT | O_TRUNC = 1 | 64 | 512 = 577
    var fd = external_call["open", Int32](pbuf, Int32(577), MODE_644)
    pbuf.free()
    if fd < 0:
        raise "write_file: open failed for " + path

    var total = len(data)
    var chunk_size = 65536
    var buf = alloc[UInt8](chunk_size).as_any_origin()
    var offset = 0
    while offset < total:
        var to_write = min(chunk_size, total - offset)
        for i in range(to_write):
            buf[i] = data[offset + i]
        var n = external_call["pwrite64", Int](Int32(fd), buf, to_write, offset)
        if n < 0:
            buf.free()
            _ = external_call["close", Int32](fd)
            raise "write_file: pwrite64 failed"
        offset += n
    buf.free()
    _ = external_call["close", Int32](fd)


def _bytes_to_string(data: Span[UInt8, _], start: Int, end: Int) -> String:
    """Build a String from a byte span slice."""
    var result = String()
    for i in range(start, end):
        result += chr(Int(data[i]))
    return result^


def mkdir_p(path: String) raises:
    """Create directory and parents. Ignores EEXIST."""
    var n = len(path)
    var path_bytes = path.as_bytes()
    # Walk through each '/' separator and create partial paths
    var i = 1  # skip leading '/'
    while i <= n:
        if i == n or path_bytes[i] == UInt8(ord("/")):
            var partial = _bytes_to_string(path_bytes, 0, i)
            var pbuf = _to_cstr(partial)
            # mkdir syscall = 83; ignore errors (EEXIST etc.)
            _ = external_call["mkdir", Int32](pbuf, MODE_755)
            pbuf.free()
        i += 1


def list_dir(path: String) raises -> List[String]:
    """List filenames in directory via getdents64 syscall (217 on x86_64).
    Skips '.' and '..'."""
    var pbuf = _to_cstr(path)
    # O_RDONLY | O_DIRECTORY = 0 | 65536 = 65536
    var fd = external_call["open", Int32](pbuf, O_DIRECTORY, Int32(0))
    pbuf.free()
    if fd < 0:
        raise "list_dir: open failed for " + path

    var buf = alloc[UInt8](4096).as_any_origin()
    var names = List[String]()

    while True:
        var nread = external_call["getdents64", Int](Int32(fd), buf, Int(4096))
        if nread < 0:
            buf.free()
            _ = external_call["close", Int32](fd)
            raise "list_dir: getdents64 failed"
        if nread == 0:
            break
        var off = 0
        while off < nread:
            # struct linux_dirent64:
            #   u64 d_ino     @ 0
            #   i64 d_off     @ 8
            #   u16 d_reclen  @ 16
            #   u8  d_type    @ 18
            #   char d_name[] @ 19
            var reclen = Int(buf[off + 16]) | (Int(buf[off + 17]) << 8)
            var name = String()
            var j = 0
            while buf[off + 19 + j] != 0:
                name += chr(Int(buf[off + 19 + j]))
                j += 1
            if name != "." and name != "..":
                names.append(name)
            off += reclen

    buf.free()
    _ = external_call["close", Int32](fd)
    return names^


def getenv(name: String) raises -> String:
    """Read environment variable. Raises if not set."""
    var nbuf = _to_cstr(name)
    var ptr_int = external_call["getenv", Int](nbuf)
    nbuf.free()
    if ptr_int == 0:
        raise "getenv: variable not set: " + name
    var ptr = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=ptr_int)
    return _ptr_to_string(ptr)


def getenv_opt(name: String) -> Optional[String]:
    """Read environment variable. Returns None if not set."""
    var nbuf = _to_cstr(name)
    var ptr_int = external_call["getenv", Int](nbuf)
    nbuf.free()
    if ptr_int == 0:
        return None
    var ptr = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=ptr_int)
    return Optional(_ptr_to_string(ptr))


def setenv(name: String, value: String) raises:
    """Set environment variable via setenv(3)."""
    var nbuf = _to_cstr(name)
    var vbuf = _to_cstr(value)
    var rc = external_call["setenv", Int32](nbuf, vbuf, Int32(1))
    nbuf.free()
    vbuf.free()
    if rc != 0:
        raise "setenv: failed to set variable: " + name


def basename(url_path: String) -> String:
    """Extract filename from URL path (last component after '/')."""
    var n = len(url_path)
    var path_bytes = url_path.as_bytes()
    var last_slash = -1
    for i in range(n):
        if path_bytes[i] == UInt8(ord("/")):
            last_slash = i
    if last_slash == -1:
        return url_path
    return _bytes_to_string(path_bytes, last_slash + 1, n)
