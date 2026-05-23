"""UdpIo capability trait — UDP-specific submission verbs.

Separate from `Io` (TCP/stream-shaped) because UDP-via-io_uring uses
different SQE shapes: recvmsg/sendmsg with msghdr/iovec, provided-buffer
rings, and per-datagram completions. Pulling these into the `Io` trait
would bloat it for TCP-only consumers (H1, H2).

Implementations:

  * `IoUringUdp` — wraps `boucle.completion.BatchCompletionLoop`.
  * Future epoll/kqueue/macOS backends can implement this trait without
    touching `Io`.

# Completion dispatch

Same split as `Io`: submission verbs live here, CQE delivery flows
through `boucle.completion.BatchCompletionHandler`. The handler emits
"pending submits" from `on_complete`, and an outer drain loop calls
back into `UdpIo.submit_*` after `tick()` returns. This decouples
submission re-entry (which can't happen inside `on_complete` due to
the loop's mutable borrow on itself).

# c_void in signatures

`UnsafePointer[c_void, StaticConstantOrigin]` matches the io_uring SQE
ABI exactly: `msghdr*`, `__kernel_timespec*`, etc. are kernel-typed
buffers whose lifetime the caller manages outside this trait. Callers
build the msghdr template in their handler's struct and pass a cast
pointer; the trait passes it through untouched.
"""

from std.memory import UnsafePointer
from boucle.handle import RawHandle
from boucle.ctypes import c_void


trait UdpIo:
    """Submission-side I/O surface for UDP / H3 servers.

    All `submit_*` methods raise on submission-queue overflow; callers
    must defer via a pending-submits queue (the existing
    `_drain_pending_submits` pattern in `bench/h3_server.mojo` is the
    reference).

    Method names mirror `BatchCompletionLoop` 1:1 so the underlying
    backend can be replaced without rewriting consumers.
    """

    def submit_recvmsg_multishot(
        mut self,
        fd: RawHandle,
        msghdr_ptr: UnsafePointer[c_void, StaticConstantOrigin],
        buf_group: UInt16,
        token: UInt64,
    ) raises:
        """Register a multishot recvmsg on `fd` using buffers from
        `buf_group`. Each datagram produces one CQE with the kernel-
        selected buf_id encoded in `flags >> IORING_CQE_BUFFER_SHIFT`
        when `IORING_CQE_F_BUFFER` is set. Re-submit when the CQE flags
        lack `IORING_CQE_F_MORE`."""
        ...

    def submit_sendmsg(
        mut self,
        fd: RawHandle,
        msghdr_ptr: UnsafePointer[c_void, StaticConstantOrigin],
        token: UInt64,
        flags: UInt32 = 0,
    ) raises:
        """Submit a one-shot sendmsg. Caller owns the msghdr / iovec /
        payload storage until the CQE arrives. Partial sends complete
        with `result < bytes_queued` and must be re-submitted by the
        caller for the remaining bytes."""
        ...

    def submit_timeout(
        mut self,
        ts_ptr: UnsafePointer[c_void, StaticConstantOrigin],
        token: UInt64,
    ) raises:
        """Submit a one-shot timeout. `ts_ptr` must point at a
        kernel-shaped `__kernel_timespec`. The CQE fires either when
        the timeout elapses or when the loop's `wait_nr` quota is
        otherwise satisfied — see the io_uring docs for cancellation
        semantics."""
        ...

    def provide_buffers(
        mut self,
        buf_base: UnsafePointer[UInt8, MutAnyOrigin],
        buf_size: Int,
        count: Int,
        group_id: UInt16,
        base_buf_id: UInt16,
        token: UInt64 = 0,
    ) raises:
        """Provide `count` buffers of `buf_size` starting at `buf_base`
        to the kernel, tagged with `group_id` and sequential buf IDs
        `base_buf_id .. base_buf_id + count`. Uses
        `IORING_OP_PROVIDE_BUFFERS` semantics (kernel pulls a buf per
        datagram; consumer reprovides via `reprovide_buffer`)."""
        ...

    def reprovide_buffer(
        mut self,
        buf_ptr: UnsafePointer[UInt8, MutAnyOrigin],
        buf_size: Int,
        group_id: UInt16,
        buf_id: UInt16,
        token: UInt64 = 0,
    ) raises:
        """Return a single buffer to its group after the consumer is
        done with the payload. Mirrors `provide_buffers` with `count=1`
        and a specific `buf_id`."""
        ...

    def tick(mut self, *, wait_nr: UInt32 = 1) raises:
        """Drive the loop until at least `wait_nr` CQEs arrive, then
        dispatch them via `on_complete` and call `on_flush` once.
        Equivalent to `BatchCompletionLoop.poll`."""
        ...
