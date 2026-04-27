"""IoUring — io_uring backend for the Io capability trait.

Wraps `boucle.completion.CompletionLoop[H]` and exposes the `Io`
trait surface. Method bodies delegate 1:1 to the loop, so swapping
`CompletionLoop` callsites for `IoUring` callsites is mechanical
and semantically a no-op.

Step 2 of Sprint 1 — ships the wrapper. Step 3 rewires
`bench/h2_server.mojo` and `src/h2/h2_sync_server.mojo` to use it
(co-located with the StreamState replacement, since both touch the
same hot paths).

# Why parameterise over the handler?

`CompletionLoop` is parameterised by a `CompletionHandler` impl —
that's how CQE dispatch stays type-safe and inlined. `IoUring[H]`
preserves that, so callers retain direct access to their handler's
state via `io.loop._handler.<field>`. Future Io impls (`KTlsIo`,
`AsyncIo`) will not need this parameter; `Io` is the stable seam,
the parametrisation is an io_uring-specific detail.

See plans/2026-04-27-h2-perf-roadmap-sprint-sequence.md § Sprint 1.
"""

from std.memory import UnsafePointer
from boucle.handle import RawHandle
from boucle.completion import (
    CompletionLoop,
    CompletionHandler,
    BufRing,
)
from .io_trait import Io


struct IoUring[H: CompletionHandler](Io):
    """Thin wrapper around `CompletionLoop[H]` that conforms to `Io`.

    Field `loop` is intentionally public so callers can reach
    `io.loop._handler.<field>` without proxy methods. This is fine
    here — the io_uring impl is the only one that exposes a handler
    of this exact shape, and pretending otherwise via private fields
    would be a YAGNI violation (R5, R9 in the sprint roadmap).

    `IoUring` is not Movable because `CompletionLoop` isn't (the
    underlying io_uring fd + mmap'd queues pin the struct). This is
    fine: `IoUring` is constructed once at server boot and lives
    until shutdown.
    """

    var loop: CompletionLoop[Self.H]

    fn __init__(out self, var handler: Self.H, sq_entries: UInt32 = 64) raises:
        self.loop = CompletionLoop[Self.H](handler^, sq_entries=sq_entries)

    # ── Io trait verbs ────────────────────────────────────────────

    fn submit_accept_multishot(
        mut self, fd: RawHandle, token: UInt64
    ) raises:
        self.loop.submit_accept_multishot(fd, token)

    fn submit_recv_multishot(
        mut self, fd: RawHandle, buf_group: UInt16, token: UInt64
    ) raises:
        self.loop.submit_recv_multishot(fd, buf_group, token)

    fn submit_send(
        mut self,
        fd: RawHandle,
        buf: UnsafePointer[Int8, StaticConstantOrigin],
        len: UInt,
        token: UInt64,
    ) raises:
        self.loop.submit_send(fd, buf, len, token)

    fn register_buf_ring(
        mut self,
        buf_base: UnsafePointer[UInt8, MutAnyOrigin],
        buf_size: UInt32,
        count: Int,
        group_id: UInt16,
    ) raises -> BufRing:
        return self.loop.register_buf_ring(
            buf_base, buf_size, count, group_id
        )

    fn tick(mut self, *, wait_nr: UInt32 = 1) raises:
        self.loop.poll(wait_nr=wait_nr)

    fn now_us(self) -> UInt64:
        # Defer to boucle's monotonic clock when we have one wired.
        # Today the bench server reads it directly via `monotonic_us()`;
        # IoUring keeps the trait satisfied with a stub returning 0
        # until callers route through this verb. Step 3 wires it up.
        return UInt64(0)
