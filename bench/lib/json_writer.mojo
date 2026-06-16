# bench/json_writer.mojo
#
# Hand-rolled JSON byte writer for the HttpArena bench /json endpoint.
# jsonette ships only a parser; serialisation is on us. The writer
# appends raw bytes into a caller-owned List[UInt8] so the same scratch
# buffer can be reused across requests without per-call allocation.


def write_bytes(mut buf: List[UInt8], b: Span[UInt8, _]):
    """Append raw bytes (used for pre-escaped fragments)."""
    var i = 0
    while i < len(b):
        buf.append(b[i])
        i += 1


def write_uint(mut buf: List[UInt8], v: UInt64):
    """ASCII decimal of *v* into *buf*, no allocations beyond a 20-byte scratch."""
    if v == 0:
        buf.append(UInt8(ord("0")))
        return
    var tmp = List[UInt8]()
    var n = v
    while n > 0:
        tmp.append(UInt8(ord("0")) + UInt8(n % 10))
        n //= 10
    var i = len(tmp) - 1
    while i >= 0:
        buf.append(tmp[i])
        i -= 1


def write_int(mut buf: List[UInt8], v: Int64):
    """Signed ASCII decimal of *v* into *buf*."""
    if v < 0:
        buf.append(UInt8(ord("-")))
        write_uint(buf, UInt64(-v))
    else:
        write_uint(buf, UInt64(v))


def write_str_escaped(mut buf: List[UInt8], s: Span[UInt8, _]):
    """Write a JSON string literal: opening ", RFC8259-escaped contents, closing ".

    Used at boot time to build per-item pre-escaped fragments. Hot-path code
    writes those fragments verbatim with write_bytes.
    """
    buf.append(UInt8(ord("\"")))
    var i = 0
    while i < len(s):
        var c = s[i]
        if c == UInt8(ord("\"")):
            buf.append(UInt8(ord("\\")))
            buf.append(UInt8(ord("\"")))
        elif c == UInt8(ord("\\")):
            buf.append(UInt8(ord("\\")))
            buf.append(UInt8(ord("\\")))
        elif c == UInt8(0x08):
            buf.append(UInt8(ord("\\")))
            buf.append(UInt8(ord("b")))
        elif c == UInt8(0x09):
            buf.append(UInt8(ord("\\")))
            buf.append(UInt8(ord("t")))
        elif c == UInt8(0x0A):
            buf.append(UInt8(ord("\\")))
            buf.append(UInt8(ord("n")))
        elif c == UInt8(0x0C):
            buf.append(UInt8(ord("\\")))
            buf.append(UInt8(ord("f")))
        elif c == UInt8(0x0D):
            buf.append(UInt8(ord("\\")))
            buf.append(UInt8(ord("r")))
        elif c < UInt8(0x20):
            buf.append(UInt8(ord("\\")))
            buf.append(UInt8(ord("u")))
            buf.append(UInt8(ord("0")))
            buf.append(UInt8(ord("0")))
            var hi = (c >> 4) & UInt8(0x0F)
            var lo = c & UInt8(0x0F)
            if hi < UInt8(10):
                buf.append(UInt8(ord("0")) + hi)
            else:
                buf.append(UInt8(ord("a")) + hi - UInt8(10))
            if lo < UInt8(10):
                buf.append(UInt8(ord("0")) + lo)
            else:
                buf.append(UInt8(ord("a")) + lo - UInt8(10))
        else:
            buf.append(c)
        i += 1
    buf.append(UInt8(ord("\"")))
