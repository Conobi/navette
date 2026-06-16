"""navette runtime — socket setup helpers.

Thin wrappers over the Linux socket syscalls the example servers use to
create listeners and client connections (`tcp_listener`, `udp_listener`,
`tcp_connect`, `udp_connect`, `tcp_v4_nonblocking`).

The event loop itself is boucle's `CompletionLoop` / `BatchCompletionLoop`,
which the H1/H2/H3 server runtimes drive directly.
"""

from .socket_helpers import (
    tcp_listener,
    udp_listener,
    tcp_connect,
    udp_connect,
    tcp_v4_nonblocking,
)
