"""navette network helpers — DNS resolution and other host-language
concerns that don't belong in Boucle.

Boucle owns transport-level types (`Socket`, `SocketAddrV4/V6`,
`IpAddrV4/V6`). Navette owns the layer above: `getaddrinfo`-backed
host resolution with an optional TTL cache, and a deadline-bounded
A/AAAA resolver for callers that need timeout guarantees.
"""

from .resolver import resolve_host, Resolver, ResolvedAddr
from .resolver_bounded import resolve_host_bounded
