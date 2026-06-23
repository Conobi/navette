"""resolver.mojo — DNS resolution via getaddrinfo(3).

`resolve_host(host, port)` returns a list of `ResolvedAddr` — a small
tagged union over `SocketAddrV4` / `SocketAddrV6` — for `host:port`,
using `AF_UNSPEC` so both IPv4 (A) and IPv6 (AAAA) records are returned.
The order matches glibc's RFC 6724 destination-address selection
(typically IPv6-global first, then IPv4, then link-local).

`Resolver` wraps `resolve_host` with an optional TTL cache for clients
that issue many requests to the same host. Set `ttl_secs=0` to disable
the cache.

# Fast paths

* `host == ""` raises.
* `host` matching `IpAddrV4.parse` skips `getaddrinfo` entirely and
  returns a single AF_INET `ResolvedAddr`.
* `host == "localhost"` is NOT special-cased here — `getaddrinfo` will
  honour `/etc/hosts` and the system resolver, typically returning
  `[::1, 127.0.0.1]` on Linux. Both reach a dual-stack listener bound
  to `[::]:port` thanks to `IPV6_V6ONLY=0`.
"""

from std.ffi import external_call
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.collections.dict import Dict
from std.collections.optional import Optional

from boucle.net.addr import SocketAddrV4, SocketAddrV6
from boucle.net.ip import IpAddrV4

from navette.util.null_ptr import null_ptr


comptime _AF_INET: Int32 = 2
comptime _AF_INET6: Int32 = 10
comptime _AF_UNSPEC: Int32 = 0
comptime _CLOCK_MONOTONIC: Int32 = 1


def _monotonic_secs() -> Int:
    """clock_gettime(CLOCK_MONOTONIC) → seconds (drops nsec)."""
    var ts = _heap_alloc[UInt8](16).as_unsafe_any_origin()
    _ = external_call["clock_gettime", Int32](_CLOCK_MONOTONIC, ts)
    var sec_ptr = ts.bitcast[Int64]()
    var sec = Int(sec_ptr[])
    ts.free()
    return sec


@always_inline
def _read_u64_le(p: UnsafePointer[UInt8, MutAnyOrigin], offset: Int) -> UInt64:
    """Read 8 bytes little-endian from `p[offset..offset+8]`."""
    var v = UInt64(0)
    for i in range(8):
        v = v | (UInt64(p[offset + i]) << UInt64(i * 8))
    return v


# ── ResolvedAddr — tagged union over SocketAddrV4 / SocketAddrV6 ─────


struct ResolvedAddr(Copyable, Movable):
    """A resolved address — either AF_INET or AF_INET6.

    `family` is `_AF_INET` (2) or `_AF_INET6` (10), matching the kernel
    constants. Use `is_ipv4()` / `is_ipv6()` to dispatch.

    Both `v4` and `v6` are populated as defaults; only the field
    matching `family` carries valid data. This avoids `Variant`, which
    has compile-time gotchas under Mojo 0.26.x when used in loops.
    """

    var family: Int32
    var v4: SocketAddrV4
    var v6: SocketAddrV6

    def __init__(out self, family: Int32, v4: SocketAddrV4, v6: SocketAddrV6):
        self.family = family
        self.v4 = v4
        self.v6 = v6

    def __init__(out self, *, deinit take: Self):
        self.family = take.family
        self.v4 = take.v4
        self.v6 = take.v6

    @staticmethod
    def from_v4(v4: SocketAddrV4) -> Self:
        return Self(
            family=_AF_INET,
            v4=v4,
            v6=SocketAddrV6(0, 0, 0, 0, 0, 0, 0, 0, port=0),
        )

    @staticmethod
    def from_v6(v6: SocketAddrV6) -> Self:
        return Self(
            family=_AF_INET6,
            v4=SocketAddrV4(0, 0, 0, 0, port=0),
            v6=v6,
        )

    @always_inline
    def is_ipv4(self) -> Bool:
        return self.family == _AF_INET

    @always_inline
    def is_ipv6(self) -> Bool:
        return self.family == _AF_INET6


def resolve_host(host: String, port: Int) raises -> List[ResolvedAddr]:
    """Resolve `host` to a list of `ResolvedAddr` via getaddrinfo(3) AF_UNSPEC.

    Returns at least one address on success. Addresses appear in glibc's
    RFC 6724 preference order — typically IPv6 first, then IPv4. Raises
    on empty host, getaddrinfo failure, or zero AF_INET/AF_INET6 nodes.
    """
    if len(host) == 0:
        raise "resolve_host: empty host"

    var dotted = IpAddrV4.parse(host)
    if dotted:
        var ip = dotted.value()
        var sa = SocketAddrV4(
            ip.octets[0], ip.octets[1], ip.octets[2], ip.octets[3],
            port=UInt16(port),
        )
        var out = List[ResolvedAddr](capacity=1)
        out.append(ResolvedAddr.from_v4(sa))
        return out^

    # `struct addrinfo` on Linux x86_64 is 48 bytes:
    #   ai_flags(4)  ai_family(4)  ai_socktype(4)  ai_protocol(4)
    #   ai_addrlen(4)  pad(4)  ai_addr(8)  ai_canonname(8)  ai_next(8)
    var hints = _heap_alloc[UInt8](48).as_unsafe_any_origin()
    for i in range(48):
        hints[i] = UInt8(0)
    # ai_family = AF_UNSPEC (0) — leave hints[4..8] as zero.
    # ai_socktype = SOCK_STREAM (1) at offset 8 so glibc returns ONE entry
    # per address rather than one-per-socktype. The packed bytes are the
    # same for SOCK_STREAM/SOCK_DGRAM/SOCK_RAW, so this dedupe is free for
    # both TCP and UDP callers.
    hints[8] = UInt8(1)

    var host_bytes = host.as_bytes()
    var host_cstr = _heap_alloc[UInt8](len(host_bytes) + 1).as_unsafe_any_origin()
    for i in range(len(host_bytes)):
        host_cstr[i] = host_bytes[i]
    host_cstr[len(host_bytes)] = UInt8(0)

    var out_res = _heap_alloc[UInt64](1).as_unsafe_any_origin()
    out_res[0] = UInt64(0)
    var rc = external_call["getaddrinfo", Int32](
        host_cstr,
        null_ptr[UInt8, MutAnyOrigin](),  # service = NULL
        hints,
        out_res,
    )
    host_cstr.free()
    hints.free()

    if rc != 0:
        out_res.free()
        raise "getaddrinfo(" + host + ") failed: rc=" + String(Int(rc))

    var head = out_res[0]
    out_res.free()
    if head == UInt64(0):
        raise "getaddrinfo(" + host + "): empty result"

    var results = List[ResolvedAddr]()
    var node = head
    while node != UInt64(0):
        var np = UnsafePointer[UInt8, MutAnyOrigin](
            unsafe_from_address=Int(node)
        )
        # addrinfo offsets (Linux x86_64):
        #   ai_family at 4    (i32, AF_INET or AF_INET6 fits in one byte)
        #   ai_addr  at 24    (sockaddr *)
        #   ai_next  at 40    (addrinfo *)
        var fam = Int32(np[4])
        var ai_addr = _read_u64_le(np, 24)
        var ai_next = _read_u64_le(np, 40)

        if ai_addr != UInt64(0) and (fam == _AF_INET or fam == _AF_INET6):
            var sa = UnsafePointer[UInt8, MutAnyOrigin](
                unsafe_from_address=Int(ai_addr)
            )
            if fam == _AF_INET:
                var o1 = UInt8(sa[4])
                var o2 = UInt8(sa[5])
                var o3 = UInt8(sa[6])
                var o4 = UInt8(sa[7])
                results.append(
                    ResolvedAddr.from_v4(
                        SocketAddrV4(o1, o2, o3, o4, port=UInt16(port))
                    )
                )
            else:
                # sockaddr_in6: family(2) port(2 BE) flowinfo(4) addr(16) scope_id(4)
                # Read 8 segments of 16 bits in network order from offset 8.
                var seg0 = (UInt16(sa[8]) << 8) | UInt16(sa[9])
                var seg1 = (UInt16(sa[10]) << 8) | UInt16(sa[11])
                var seg2 = (UInt16(sa[12]) << 8) | UInt16(sa[13])
                var seg3 = (UInt16(sa[14]) << 8) | UInt16(sa[15])
                var seg4 = (UInt16(sa[16]) << 8) | UInt16(sa[17])
                var seg5 = (UInt16(sa[18]) << 8) | UInt16(sa[19])
                var seg6 = (UInt16(sa[20]) << 8) | UInt16(sa[21])
                var seg7 = (UInt16(sa[22]) << 8) | UInt16(sa[23])
                var scope_id = (
                    UInt32(sa[24])
                    | (UInt32(sa[25]) << 8)
                    | (UInt32(sa[26]) << 16)
                    | (UInt32(sa[27]) << 24)
                )
                results.append(
                    ResolvedAddr.from_v6(
                        SocketAddrV6(
                            seg0, seg1, seg2, seg3,
                            seg4, seg5, seg6, seg7,
                            port=UInt16(port),
                            scope_id=scope_id,
                        )
                    )
                )

        node = ai_next

    _ = external_call["freeaddrinfo", Int32](head)

    if len(results) == 0:
        raise "getaddrinfo(" + host + "): no AF_INET/AF_INET6 nodes"

    return results^


struct _CacheEntry(Copyable, Movable):
    var addrs: List[ResolvedAddr]
    var expires_secs: Int

    def __init__(out self, var addrs: List[ResolvedAddr], expires_secs: Int):
        self.addrs = addrs^
        self.expires_secs = expires_secs

    def __init__(out self, *, deinit take: Self):
        self.addrs = take.addrs^
        self.expires_secs = take.expires_secs


struct Resolver(Movable):
    """A name resolver with an optional TTL cache.

    With `ttl_secs == 0`, every call is a fresh `getaddrinfo`. With a
    positive TTL, results are cached per `(host, port)` pair until the
    monotonic-clock deadline expires. Reasonable default: 60 s.

    The cache is process-local and not thread-safe — wrap in a mutex
    or shard per-thread if you share a `Resolver` across workers.
    """

    var ttl_secs: Int
    var cache: Dict[String, _CacheEntry]

    def __init__(out self, ttl_secs: Int = 60):
        self.ttl_secs = ttl_secs
        self.cache = Dict[String, _CacheEntry]()

    def __init__(out self, *, deinit take: Self):
        self.ttl_secs = take.ttl_secs
        self.cache = take.cache^

    def resolve(mut self, host: String, port: Int) raises -> List[ResolvedAddr]:
        """Resolve `host:port`, consulting + populating the TTL cache."""
        if self.ttl_secs <= 0:
            return resolve_host(host, port)
        var key = host + ":" + String(port)
        var now = _monotonic_secs()
        if key in self.cache:
            ref entry = self.cache[key]
            if entry.expires_secs > now:
                var out = List[ResolvedAddr](capacity=len(entry.addrs))
                for i in range(len(entry.addrs)):
                    out.append(entry.addrs[i].copy())
                return out^
        var fresh = resolve_host(host, port)
        var cached = List[ResolvedAddr](capacity=len(fresh))
        for i in range(len(fresh)):
            cached.append(fresh[i].copy())
        self.cache[key] = _CacheEntry(cached^, now + self.ttl_secs)
        return fresh^

    def invalidate(mut self, host: String, port: Int):
        """Drop any cached entry for `host:port`."""
        var key = host + ":" + String(port)
        if key in self.cache:
            try:
                _ = self.cache.pop(key)
            except:
                pass

    def clear(mut self):
        """Drop the entire cache."""
        self.cache.clear()
