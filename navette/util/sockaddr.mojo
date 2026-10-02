"""Locate the peer IP inside a raw Linux `sockaddr_in` / `sockaddr_in6` blob.

Decides which bytes identify a peer (Retry tokens bind to them), so a
dual-stack socket's two views of one IPv4 peer agree. Pure byte
inspection: no syscalls, no allocation.
"""

from std.collections import Span

comptime AF_INET: Int = 2
comptime AF_INET6: Int = 10
comptime SOCKADDR_PORT_OFFSET: Int = 2
"""Offset of the big-endian port in both layouts; valid whenever `sockaddr_ip` found an address."""


def sockaddr_ip(sa: Span[Byte, _]) -> Tuple[Int, Int]:
    """Offset and length of the peer IP bytes in `sa`, or `(0, 0)` when malformed.

    The family is read little-endian (Linux host order). Length is 4 for
    `sockaddr_in` and for IPv4-mapped IPv6 (`::ffff:a.b.c.d`, as a
    dual-stack socket reports IPv4 peers), so both views of one IPv4 peer
    point at the same 4 bytes; 16 for any other `sockaddr_in6`.
    `flowinfo` and `scope_id` are never part of the range. A blob too
    short for its family, or any other family, yields length 0.
    """
    if len(sa) < 2:
        return (0, 0)
    var family = Int(sa[0]) | (Int(sa[1]) << 8)
    if family == AF_INET:
        if len(sa) < 8:
            return (0, 0)
        return (4, 4)
    if family != AF_INET6 or len(sa) < 24:
        return (0, 0)
    var mapped = sa[18] == 0xFF and sa[19] == 0xFF
    for i in range(8, 18):
        if sa[i] != 0:
            mapped = False
    if mapped:
        return (20, 4)
    return (8, 16)
