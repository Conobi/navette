"""mojo-net I/O capability layer.

The `Io` trait abstracts the H1/H2/H3 servers' I/O calls behind a
small set of submission verbs, so that the runtime backend can be
swapped without touching protocol code.

Today's only impl: `IoUring` (Sprint 1 Step 2). Future impls:
KTlsIo (Sprint 5), AsyncIo (post-Mojo-async).

See plans/2026-04-27-h2-perf-roadmap-sprint-sequence.md § Sprint 1.
"""

from .io_trait import Io
from .io_uring import IoUring
from .udp_io import UdpIo
from .io_uring_udp import IoUringUdp
