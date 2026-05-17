"""Io capability trait — abstract submission-side I/O verbs.

The navette server loops (H1/H2/H3) call methods on an `Io` impl
rather than touching `boucle.completion.CompletionLoop` directly.
This dependency-inversion seam is the swap point for backend impls:

  * `IoUring`  (Sprint 1, Step 2)         — wraps boucle's CompletionLoop
  * `KTlsIo`   (Sprint 5)                 — kernel TLS over io_uring
  * `AsyncIo`  (post-Mojo-async, Phase 2) — Mojo's native async runtime

# Why a trait, not direct CompletionLoop calls?

The architectural commitment in
`plans/2026-04-27-mojo-async-direction-and-server-architecture.md`
is to keep all language-version-bound machinery (keywords, runtime
handles, future shapes) at one well-defined seam, so that when Mojo's
async story stabilises, only this seam moves.

Per the survival patterns from Rust/Swift/Zig transitions, the shape
that consistently survived is "caller-injected I/O capability,
Allocator-shaped." This trait is that capability for navette.

# Scope (YAGNI)

This trait covers exactly the submission verbs that
`bench/h2_server.mojo` + `bench/h3_server.mojo` use today. No
speculative additions. New verbs land only when a concrete consumer
demands them (R4 in the sprint roadmap).

# Completion dispatch

CQE delivery stays on the existing `boucle.completion.CompletionHandler`
trait, which the H2/H3 server handlers already implement. `Io.tick`
drives the underlying loop; completions invoke `on_complete(token,
result, flags)` on the server's handler. Splitting submission (`Io`)
from dispatch (`CompletionHandler`) keeps the new trait minimal and
lets us swap submission backends without rewriting every CQE handler.

See `plans/2026-04-27-h2-perf-roadmap-sprint-sequence.md` § Sprint 1.
"""

from std.memory import UnsafePointer
from boucle.handle import RawHandle
from boucle.completion import BufRing


trait Io:
    """Submission-side I/O surface for navette servers.

    All `submit_*` methods raise on submission-queue overflow; callers
    must be prepared to defer via a pending-submits queue (the
    existing `_drain_pending_submits` loop in `bench/h2_server.mojo`
    is the reference pattern).

    Method names mirror `boucle.completion.CompletionLoop` 1:1 to make
    the Step-2 routing change a no-op semantic-wise.
    """

    fn submit_accept_multishot(
        mut self, fd: RawHandle, token: UInt64
    ) raises:
        """Register multishot accept on a listener fd. Each new
        connection produces one CQE with the accepted fd in `result`.
        Re-submit when CQE flags lack `IORING_CQE_F_MORE`."""
        ...

    fn submit_recv_multishot(
        mut self, fd: RawHandle, buf_group: UInt16, token: UInt64
    ) raises:
        """Register multishot recv via a registered buffer ring. Each
        readable event produces one CQE; the kernel selects a buffer
        ID encoded in `flags >> IORING_CQE_BUFFER_SHIFT` when
        `IORING_CQE_F_BUFFER` is set. Re-arm on multishot end."""
        ...

    fn submit_recv(
        mut self,
        fd: RawHandle,
        buf: UnsafePointer[Int8, StaticConstantOrigin],
        len: UInt,
        token: UInt64,
    ) raises:
        """Submit a one-shot recv. Caller owns `buf` until the CQE
        arrives with a byte count in `result`. Equivalent to a single
        read(2). Use this for simple per-conn buffers; for
        high-throughput workloads, prefer `submit_recv_multishot`
        with a buf-ring."""
        ...

    fn submit_send(
        mut self,
        fd: RawHandle,
        buf: UnsafePointer[Int8, StaticConstantOrigin],
        len: UInt,
        token: UInt64,
    ) raises:
        """Submit a one-shot send. Caller owns `buf` until the CQE
        arrives. Partial sends complete with `result < len` and must
        be re-submitted by the caller for the remaining bytes."""
        ...

    fn register_buf_ring(
        mut self,
        buf_base: UnsafePointer[UInt8, MutAnyOrigin],
        buf_size: UInt32,
        count: Int,
        group_id: UInt16,
    ) raises -> BufRing:
        """Register a kernel-shared buffer ring (io_uring 5.19+).
        Backends without an equivalent primitive may raise
        `NotImplementedError` — non-uring impls will define their
        own buffer-provisioning verb when they exist."""
        ...

    fn tick(mut self, *, wait_nr: UInt32 = 1) raises:
        """Drive the loop until at least `wait_nr` CQEs arrive, then
        dispatch them via the server's `CompletionHandler`. Equivalent
        to `boucle.CompletionLoop.poll`."""
        ...

    fn now_us(self) -> UInt64:
        """Monotonic microseconds. Used for timeouts, RTT estimation,
        and `bench.profile.AcceptProfile` telemetry."""
        ...
