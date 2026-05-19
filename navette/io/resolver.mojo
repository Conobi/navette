"""resolver.mojo — DNS resolution via getaddrinfo(3).

`resolve_host(host, port)` returns a list of `SockAddr` for `host:port`,
using `AF_UNSPEC` so both IPv4 (A) and IPv6 (AAAA) records are returned.
The order matches glibc's RFC 6724 destination-address selection
(typically IPv6-global first, then IPv4, then link-local).

`Resolver` wraps `resolve_host` with an optional TTL cache for clients
that issue many requests to the same host. Set `ttl_secs=0` to disable
the cache.

# Fast paths

* `host == ""` raises.
* `host` matching `parse_dotted_ipv4` skips `getaddrinfo` entirely and
  returns a single AF_INET SockAddr.
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

from .sockaddr import SockAddr, sockaddr_ipv4, sockaddr_ipv6, parse_dotted_ipv4


comptime _AF_INET: Int32 = 2
comptime _AF_INET6: Int32 = 10
comptime _AF_UNSPEC: Int32 = 0
comptime _CLOCK_MONOTONIC: Int32 = 1


def _monotonic_secs() -> Int:
    """clock_gettime(CLOCK_MONOTONIC) → seconds (drops nsec)."""
    var ts = _heap_alloc[UInt8](16).as_any_origin()
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


def resolve_host(host: String, port: Int) raises -> List[SockAddr]:
    """Resolve `host` to a list of SockAddr via getaddrinfo(3) AF_UNSPEC.

    Returns at least one address on success. Addresses appear in glibc's
    RFC 6724 preference order — typically IPv6 first, then IPv4. Raises
    on empty host, getaddrinfo failure, or zero AF_INET/AF_INET6 nodes.
    """
    if len(host) == 0:
        raise "resolve_host: empty host"

    var dotted = parse_dotted_ipv4(host, port)
    if dotted:
        var out = List[SockAddr](capacity=1)
        out.append(dotted.value().copy())
        return out^

    # `struct addrinfo` on Linux x86_64 is 48 bytes:
    #   ai_flags(4)  ai_family(4)  ai_socktype(4)  ai_protocol(4)
    #   ai_addrlen(4)  pad(4)  ai_addr(8)  ai_canonname(8)  ai_next(8)
    var hints = _heap_alloc[UInt8](48).as_any_origin()
    for i in range(48):
        hints[i] = UInt8(0)
    # ai_family = AF_UNSPEC (0) — leave hints[4..8] as zero.
    # ai_socktype = SOCK_STREAM (1) at offset 8 so glibc returns ONE entry
    # per address rather than one-per-socktype. The packed bytes are the
    # same for SOCK_STREAM/SOCK_DGRAM/SOCK_RAW, so this dedupe is free for
    # both TCP and UDP callers.
    hints[8] = UInt8(1)

    var host_bytes = host.as_bytes()
    var host_cstr = _heap_alloc[UInt8](len(host_bytes) + 1).as_any_origin()
    for i in range(len(host_bytes)):
        host_cstr[i] = host_bytes[i]
    host_cstr[len(host_bytes)] = UInt8(0)

    var out_res = _heap_alloc[UInt64](1).as_any_origin()
    out_res[0] = UInt64(0)
    var rc = external_call["getaddrinfo", Int32](
        host_cstr,
        UnsafePointer[UInt8, MutAnyOrigin](),  # service = NULL
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

    var results = List[SockAddr]()
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
                var o1 = Int(sa[4])
                var o2 = Int(sa[5])
                var o3 = Int(sa[6])
                var o4 = Int(sa[7])
                results.append(sockaddr_ipv4(o1, o2, o3, o4, port))
            else:
                var addr16 = List[UInt8](capacity=16)
                for i in range(16):
                    addr16.append(sa[8 + i])
                var scope_id = (
                    Int(sa[24])
                    | (Int(sa[25]) << 8)
                    | (Int(sa[26]) << 16)
                    | (Int(sa[27]) << 24)
                )
                results.append(sockaddr_ipv6(addr16^, port, scope_id))

        node = ai_next

    _ = external_call["freeaddrinfo", Int32](head)

    if len(results) == 0:
        raise "getaddrinfo(" + host + "): no AF_INET/AF_INET6 nodes"

    return results^


struct _CacheEntry(Copyable, Movable):
    var addrs: List[SockAddr]
    var expires_secs: Int

    def __init__(out self, var addrs: List[SockAddr], expires_secs: Int):
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

    def resolve(mut self, host: String, port: Int) raises -> List[SockAddr]:
        """Resolve `host:port`, consulting + populating the TTL cache."""
        if self.ttl_secs <= 0:
            return resolve_host(host, port)
        var key = host + ":" + String(port)
        var now = _monotonic_secs()
        if key in self.cache:
            ref entry = self.cache[key]
            if entry.expires_secs > now:
                var out = List[SockAddr](capacity=len(entry.addrs))
                for i in range(len(entry.addrs)):
                    out.append(entry.addrs[i].copy())
                return out^
        var fresh = resolve_host(host, port)
        var cached = List[SockAddr](capacity=len(fresh))
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
