"""Fixed-size slab pool for UDP sendmsg operations.

Each slot pre-allocates a contiguous buffer for the complete sendmsg
wire layout (msghdr + iovec + sockaddr + packet data) plus a Completion
token for proactor-based io_uring submission. Slots are recycled by
the sendmsg CQE callback without any heap allocation in the hot path.

Buffer layout per slot (offsets from buf start):
    [0..56)    msghdr       (56 bytes)
    [56..72)   iovec        (16 bytes)
    [72..100)  sockaddr     (28 bytes, sockaddr_in6 size)
    [100..)    packet data  (buf_size bytes)
"""

from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from boucle.proactor.completion import Completion


# Wire layout constants.
comptime _MSGHDR_SIZE: Int = 56
comptime _IOVEC_SIZE: Int = 16
comptime _ADDR_SIZE: Int = 28
comptime _HEADER_SIZE: Int = 100  # msghdr + iovec + sockaddr


struct SendSlab(Movable):
    """One pre-allocated sendmsg slot.

    Owns a contiguous heap buffer laid out as:
        [msghdr(56)] [iovec(16)] [sockaddr(28)] [data(buf_size)]

    The Completion token is embedded for zero-alloc io_uring submission.
    `pool_ptr` is a type-erased backpointer to the owning SendSlabPool,
    used by the static CQE callback to release the slot.

    Fields:
        pool_ptr: Type-erased backpointer to the owning SendSlabPool.
        slot_idx: This slot's index within the pool.
        completion: Embedded Completion token for io_uring.
        buf: Heap-allocated contiguous buffer for the wire layout.
        buf_size: Maximum packet data capacity (bytes after the header).
    """

    var pool_ptr: UnsafePointer[NoneType, MutAnyOrigin]
    var slot_idx: Int
    var completion: Completion
    var buf: UnsafePointer[UInt8, MutAnyOrigin]
    var buf_size: Int

    def __init__(out self, slot_idx: Int, buf_size: Int):
        """Allocate a new slab with the given data capacity.

        Args:
            slot_idx: Index of this slot within its owning pool.
            buf_size: Maximum packet data size in bytes.
        """
        var zero: Int = 0
        self.pool_ptr = UnsafePointer[NoneType, MutAnyOrigin](
            unsafe_from_address=zero
        )
        self.slot_idx = slot_idx
        self.completion = Completion()

        var total = _HEADER_SIZE + buf_size
        self.buf = _heap_alloc[UInt8](total).as_unsafe_any_origin()
        for i in range(total):
            self.buf[i] = 0
        self.buf_size = buf_size

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self.pool_ptr = take.pool_ptr
        self.slot_idx = take.slot_idx
        self.completion = take.completion^
        self.buf = take.buf
        self.buf_size = take.buf_size

    def msghdr_ptr(self) -> UnsafePointer[UInt8, MutAnyOrigin]:
        """Return a pointer to the msghdr region (offset 0)."""
        return self.buf

    def iov_ptr(self) -> UnsafePointer[UInt8, MutAnyOrigin]:
        """Return a pointer to the iovec region (offset 56)."""
        return self.buf + _MSGHDR_SIZE

    def addr_ptr(self) -> UnsafePointer[UInt8, MutAnyOrigin]:
        """Return a pointer to the sockaddr region (offset 72)."""
        return self.buf + _MSGHDR_SIZE + _IOVEC_SIZE

    def data_ptr(self) -> UnsafePointer[UInt8, MutAnyOrigin]:
        """Return a pointer to the packet data region (offset 100)."""
        return self.buf + _HEADER_SIZE

    def fill(mut self, data: List[UInt8], addr: List[UInt8]):
        """Fill the buffer with packet data and peer address, then wire
        msghdr and iovec fields to point at the correct regions.

        All pointer fields are written as little-endian u64 (native on
        x86_64). msg_namelen is fixed at 28 (sockaddr_in6 size). The
        addr is zero-padded to 28 bytes if shorter.

        Args:
            data: Packet payload bytes.
            addr: Peer sockaddr bytes (up to 28 bytes, padded if shorter).
        """
        var data_len = len(data)
        var addr_len = len(addr)

        # Copy payload into the data region.
        var data_p = self.data_ptr()
        for i in range(data_len):
            data_p[i] = data[i]

        # Copy peer address into the sockaddr region, zero-padded.
        var addr_p = self.addr_ptr()
        for i in range(_ADDR_SIZE):
            if i < addr_len:
                addr_p[i] = addr[i]
            else:
                addr_p[i] = 0

        # Zero msghdr and iovec regions before wiring.
        var msghdr = self.msghdr_ptr()
        for i in range(_MSGHDR_SIZE):
            msghdr[i] = 0
        var iov = self.iov_ptr()
        for i in range(_IOVEC_SIZE):
            iov[i] = 0

        # msghdr offset 0 -- msg_name = pointer to addr region.
        var addr_ptr_val = UInt64(Int(addr_p))
        var addr_ptr_bytes = UnsafePointer(to=addr_ptr_val).bitcast[UInt8]()
        for i in range(8):
            msghdr[i] = addr_ptr_bytes[i]

        # msghdr offset 8 -- msg_namelen = 28 (sockaddr_in6 size).
        var namelen = UInt32(_ADDR_SIZE)
        var namelen_bytes = UnsafePointer(to=namelen).bitcast[UInt8]()
        for i in range(4):
            msghdr[8 + i] = namelen_bytes[i]

        # msghdr offset 16 -- msg_iov = pointer to iovec region.
        var iov_ptr_val = UInt64(Int(iov))
        var iov_ptr_bytes = UnsafePointer(to=iov_ptr_val).bitcast[UInt8]()
        for i in range(8):
            msghdr[16 + i] = iov_ptr_bytes[i]

        # msghdr offset 24 -- msg_iovlen = 1.
        var iovlen = UInt64(1)
        var iovlen_bytes = UnsafePointer(to=iovlen).bitcast[UInt8]()
        for i in range(8):
            msghdr[24 + i] = iovlen_bytes[i]

        # iov[0].iov_base = pointer to data region.
        var data_ptr_val = UInt64(Int(data_p))
        var data_ptr_bytes = UnsafePointer(to=data_ptr_val).bitcast[UInt8]()
        for i in range(8):
            iov[i] = data_ptr_bytes[i]

        # iov[0].iov_len = data_len.
        var iov_len = UInt64(data_len)
        var iov_len_bytes = UnsafePointer(to=iov_len).bitcast[UInt8]()
        for i in range(8):
            iov[8 + i] = iov_len_bytes[i]

    @staticmethod
    def _on_sendmsg_complete(
        ctx: UnsafePointer[NoneType, MutAnyOrigin],
        result: Int32,
        flags: UInt32,
    ):
        """Static CQE callback for sendmsg completion.

        Recovers the SendSlab from the context pointer, reads the
        pool backpointer, and calls pool.release(slot_idx) to return
        the slot to the free list.

        Args:
            ctx: Type-erased pointer to the SendSlab that completed.
            result: io_uring CQE result (bytes sent or negative errno).
            flags: io_uring CQE flags (unused for sendmsg).
        """
        var slab_ptr = UnsafePointer[SendSlab, MutAnyOrigin](
            unsafe_from_address=Int(ctx)
        )
        var pool_ptr = UnsafePointer[SendSlabPool, MutAnyOrigin](
            unsafe_from_address=Int(slab_ptr[].pool_ptr)
        )
        pool_ptr[].release(slab_ptr[].slot_idx)

    def free_buf(mut self):
        """Free the contiguous buffer. Called during pool teardown."""
        self.buf.free()


struct SendSlabPool(Movable):
    """Fixed-size pool of pre-allocated sendmsg slots.

    Pre-allocates `capacity` SendSlab instances on the heap at
    construction. Slots are acquired for outbound sendmsg operations
    and released by the CQE callback. No heap allocation occurs in
    the acquire/release hot path.

    Fields:
        _slots: Heap-allocated SendSlab pointers.
        _free: Stack of free slot indices.
        capacity: Total number of slots.
        in_flight: Number of currently acquired (in-use) slots.
    """

    var _slots: List[UnsafePointer[SendSlab, MutAnyOrigin]]
    var _free: List[Int]
    var capacity: Int
    var in_flight: Int

    def __init__(out self, capacity: Int, buf_size: Int = 1500):
        """Pre-allocate `capacity` SendSlab instances on the heap.

        Args:
            capacity: Number of slots in the pool.
            buf_size: Maximum packet data size per slot (default 1500,
                     typical MTU for UDP datagrams).
        """
        self._slots = List[UnsafePointer[SendSlab, MutAnyOrigin]]()
        self._free = List[Int]()
        self.capacity = capacity
        self.in_flight = 0

        for i in range(capacity):
            var slab = SendSlab(slot_idx=i, buf_size=buf_size)
            var slab_ptr = _heap_alloc[SendSlab](1).as_unsafe_any_origin()
            slab_ptr.init_pointee_move(slab^)
            self._slots.append(slab_ptr)
            self._free.append(i)

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self._slots = take._slots^
        self._free = take._free^
        self.capacity = take.capacity
        self.in_flight = take.in_flight

    def wire_completions(mut self):
        """Wire each slot's pool_ptr backpointer and Completion.context.

        Must be called after the pool is at its final heap address
        (i.e. after any moves that relocate the pool). Sets each
        slot's pool_ptr to point at this pool instance, and sets
        each slot's Completion.context to the slot's own heap address
        with the static callback wired in.
        """
        var pool_addr = Int(UnsafePointer(to=self))
        var pool_none_ptr = UnsafePointer[NoneType, MutAnyOrigin](
            unsafe_from_address=pool_addr
        )

        for i in range(self.capacity):
            var slab_ptr = self._slots[i]
            slab_ptr[].pool_ptr = pool_none_ptr

            var slab_none_ptr = UnsafePointer[NoneType, MutAnyOrigin](
                unsafe_from_address=Int(slab_ptr)
            )
            slab_ptr[].completion = Completion(
                invoke=SendSlab._on_sendmsg_complete,
                context=slab_none_ptr,
            )

    def acquire(mut self) -> Int:
        """Acquire a free slot from the pool.

        Returns the slot index, or -1 if all slots are in flight.
        """
        if len(self._free) == 0:
            return -1
        var idx = self._free.pop()
        self.in_flight += 1
        return idx

    def release(mut self, idx: Int):
        """Return a slot to the free list.

        Args:
            idx: The slot index to release (must be currently acquired).
        """
        self._free.append(idx)
        self.in_flight -= 1

    def has_available(self) -> Bool:
        """Return True if at least one slot is free."""
        return len(self._free) > 0

    def slot_ptr(self, idx: Int) -> UnsafePointer[SendSlab, MutAnyOrigin]:
        """Return the heap pointer for slot `idx`.

        Args:
            idx: Slot index (0 <= idx < capacity).
        """
        return self._slots[idx]

    def completion_ptr(
        self, idx: Int
    ) -> UnsafePointer[Completion, MutAnyOrigin]:
        """Return a pointer to the Completion token for slot `idx`.

        Used by the proactor driver's submit_sendmsg call.

        Args:
            idx: Slot index (0 <= idx < capacity).
        """
        return UnsafePointer[Completion, MutAnyOrigin](
            unsafe_from_address=Int(
                UnsafePointer(to=self._slots[idx][].completion)
            )
        )

    def msghdr_for_submit(
        self, idx: Int
    ) -> UnsafePointer[UInt8, MutAnyOrigin]:
        """Return the msghdr pointer for slot `idx`, for submit_sendmsg.

        Args:
            idx: Slot index (0 <= idx < capacity).
        """
        return self._slots[idx][].msghdr_ptr()

    def teardown(mut self):
        """Free all slot memory. Call during server shutdown.

        Frees each slot's contiguous buffer and the slot struct itself.
        After teardown the pool is in an invalid state and must not be
        used.
        """
        for i in range(len(self._slots)):
            var ptr = self._slots[i]
            ptr[].free_buf()
            ptr.free()
        self._slots.clear()
        self._free.clear()
