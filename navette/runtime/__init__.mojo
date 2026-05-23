"""navette runtime — submission-side I/O capability layer.

The `Io` and `UdpIo` traits abstract the H1/H2/H3 servers' I/O calls
behind a small set of submission verbs. `IoUring` and `IoUringUdp`
are the io_uring-backed impls today. Future impls (KTlsIo, AsyncIo,
epoll-based fallbacks) plug in behind the same trait.

This lives in navette (not Boucle) because the trait is a swap point
for navette's executor strategy — see the structured-async direction.
Boucle stays neutral on which executor seam a consumer adopts.
"""

from .io_trait import Io
from .io_uring import IoUring
from .udp_io_trait import UdpIo
from .io_uring_udp import IoUringUdp
from .socket_helpers import (
    tcp_listener,
    udp_listener,
    tcp_connect,
    udp_connect,
    tcp_v4_nonblocking,
)
