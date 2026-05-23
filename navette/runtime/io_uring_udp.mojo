"""IoUringUdp — io_uring-batch backend for the `UdpIo` capability.

Wraps `boucle.completion.BatchCompletionLoop[H]` and conforms to
`UdpIo`. `BatchCompletionLoop` extends `CompletionLoop` with an
`on_flush()` callback fired once after all CQEs in a poll cycle are
dispatched — the H3 server uses this to batch egress after ingress
fan-in.

`H` is parameterised over `BatchCompletionHandler`; the H3UdpServer
struct in `src/h3/` fills this role.

Field `loop` is intentionally public so callers can reach
`io.loop._handler.<field>` without proxy methods — same pattern as
`IoUring` in `src/io/io_uring.mojo`. `IoUringUdp` is not `Movable`
because `BatchCompletionLoop` isn't (mmap'd io_uring queues pin the
struct).
"""

from std.memory import UnsafePointer
from boucle.handle import RawHandle
from boucle.completion import BatchCompletionLoop, BatchCompletionHandler
from boucle.ctypes import c_void

from .udp_io_trait import UdpIo


struct IoUringUdp[H: BatchCompletionHandler](UdpIo):
    """`UdpIo` impl wrapping `BatchCompletionLoop[H]`.

    Construct with an owned handler — the loop takes ownership and
    parameterises CQE dispatch on the handler's `on_complete` /
    `on_flush` methods. Tickle the loop by calling `tick(wait_nr=...)`
    from the outer driver; after each `tick` returns, the driver
    consumes the handler's pending-submits queue and routes them
    back through `submit_*` here.
    """

    var loop: BatchCompletionLoop[Self.H]

    def __init__(out self, var handler: Self.H, sq_entries: UInt32 = 4096) raises:
        self.loop = BatchCompletionLoop[Self.H](handler^, sq_entries=sq_entries)

    # ── UdpIo trait verbs ─────────────────────────────────────────

    def submit_recvmsg_multishot(
        mut self,
        fd: RawHandle,
        msghdr_ptr: UnsafePointer[c_void, StaticConstantOrigin],
        buf_group: UInt16,
        token: UInt64,
    ) raises:
        self.loop.submit_recvmsg_multishot(fd, msghdr_ptr, buf_group, token)

    def submit_sendmsg(
        mut self,
        fd: RawHandle,
        msghdr_ptr: UnsafePointer[c_void, StaticConstantOrigin],
        token: UInt64,
        flags: UInt32 = 0,
    ) raises:
        self.loop.submit_sendmsg(fd, msghdr_ptr, token, flags)

    def submit_timeout(
        mut self,
        ts_ptr: UnsafePointer[c_void, StaticConstantOrigin],
        token: UInt64,
    ) raises:
        self.loop.submit_timeout(ts_ptr, token)

    def provide_buffers(
        mut self,
        buf_base: UnsafePointer[UInt8, MutAnyOrigin],
        buf_size: Int,
        count: Int,
        group_id: UInt16,
        base_buf_id: UInt16,
        token: UInt64 = 0,
    ) raises:
        self.loop.provide_buffers(
            buf_base, buf_size, count, group_id, base_buf_id, token,
        )

    def reprovide_buffer(
        mut self,
        buf_ptr: UnsafePointer[UInt8, MutAnyOrigin],
        buf_size: Int,
        group_id: UInt16,
        buf_id: UInt16,
        token: UInt64 = 0,
    ) raises:
        self.loop.reprovide_buffer(
            buf_ptr, buf_size, group_id, buf_id, token,
        )

    def tick(mut self, *, wait_nr: UInt32 = 1) raises:
        self.loop.poll(wait_nr=wait_nr)
