# src/tls/connection.mojo
#
# Sans-I/O TLS connection wrapper.
#
# A TlsConnection wraps a rustls connection handle and exposes a feed/drain
# API. Callers shovel ciphertext in (`receive_data`) and pull plaintext out
# (`drain_plaintext`); they push plaintext in (`send_data`) and pull
# ciphertext out (`drain_ciphertext`). No sockets, no I/O.
#
# After construction (especially for clients) and after every `receive_data`
# / `send_data` call, any pending outbound ciphertext is automatically
# drained from rustls into the internal `_ciphertext_out` buffer so the
# handshake loop stays trivial:
#
#     while tls.is_handshaking():
#         tls.receive_data(network_in)
#         if tls.wants_write():
#             network_out = tls.drain_ciphertext()
#             ... send to peer ...
from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc
from std.collections.optional import Optional
from std.collections import Span

from .lib import SharedLibrary
from .config import TlsClientConfig, TlsServerConfig


comptime _IO_BUF_SIZE = 16384
# Ciphertext drain buffer must hold a full TLS record: up to 16384 bytes of
# plaintext payload plus record header (5 B), AEAD tag (16 B), content type
# (1 B), and a margin for any record-layer padding rustls may emit. We use
# 18432 (16 KiB + 2 KiB headroom) so a single `write_tls` call can always
# extract a full record without short-writing into the SliceWriter (which
# would surface as a rustls WriteZero error).
comptime _CIPHERTEXT_DRAIN_BUF_SIZE = 18432
comptime _ALPN_BUF_SIZE = 256


@fieldwise_init
struct TlsStepStatus(Equatable, ImplicitlyCopyable):
    """Why a TLS step stopped. Receive statuses equal the shim's `stop_out` codes."""

    var _value: UInt8

    comptime COMPLETE = TlsStepStatus(0)  # all input consumed / accepted
    comptime NEEDS_DRAIN = TlsStepStatus(1)  # > 16 KiB plaintext pending: drain first
    comptime NEEDS_FLUSH = TlsStepStatus(2)  # send: rustls full, ciphertext moved out; call again
    comptime PEER_CLOSED = TlsStepStatus(3)  # close_notify received; later input ignored

    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value


@fieldwise_init
struct TlsStep(ImplicitlyCopyable):
    """Bytes taken before stopping; any ciphertext produced is already in
    ciphertext-out."""

    var consumed: Int
    var status: TlsStepStatus


@fieldwise_init
struct TlsEof(Equatable, ImplicitlyCopyable):
    """How the peer's stream ended."""

    var _value: UInt8

    comptime NONE = TlsEof(0)
    comptime CLEAN = TlsEof(1)  # close_notify received
    comptime UNCLEAN = TlsEof(2)  # `receive_eof` without close_notify

    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value


struct TlsConnection(Movable):
    """Sans-I/O TLS connection wrapping a rustls connection handle.

    Inbound flow:  receive_data(ciphertext) -> drain_plaintext() -> bytes
    Outbound flow: send_data(plaintext)     -> drain_ciphertext() -> bytes
    """

    var _lib: SharedLibrary
    var _handle: Int32
    var _ciphertext_out: List[Byte]
    var _ct_drain_buf: Pointer[UInt8, MutUntrackedOrigin]
    var _pt_drain_buf: Pointer[UInt8, MutUntrackedOrigin]
    var _handshake_complete: Bool
    var _pt_stash: List[Byte]  # plaintext pulled out of rustls so it accepts more
    var _eof_received: Bool
    var _peer_closed: Bool

    # -- Private constructor (used by factory methods) ------------------------

    def __init__(
        out self,
        *,
        _lib: SharedLibrary,
        _handle: Int32,
        var _ciphertext_out: List[Byte],
        _ct_drain_buf: Pointer[UInt8, MutUntrackedOrigin],
        _pt_drain_buf: Pointer[UInt8, MutUntrackedOrigin],
        _handshake_complete: Bool,
    ):
        self._lib = SharedLibrary(copy=_lib)
        self._handle = _handle
        self._ciphertext_out = _ciphertext_out^
        self._ct_drain_buf = _ct_drain_buf
        self._pt_drain_buf = _pt_drain_buf
        self._handshake_complete = _handshake_complete
        self._pt_stash = List[Byte]()
        self._eof_received = False
        self._peer_closed = False

    # -- Move / Destroy --------------------------------------------------------

    def __deinit__(deinit self):
        """Free the rustls connection handle and the two drain buffers.

        A destructor may not raise. `tls_conn_free` can, but only from
        the symbol lookup — the Rust side answers an unknown handle with
        -1, a status already discarded here. A lookup failure means the
        loaded librustls_mojo.so does not export `rlsm_tls_conn_free`,
        so the connection this object owns cannot be reached at all;
        swallowing it leaks one entry in the Rust CONN_TABLE rather than
        killing the process mid-teardown. `deinit self` consumes the
        connection, so this runs once per handle and cannot double free.

        The two `unsafe_free` calls sit outside the guarded region on
        purpose: they are Mojo-side allocations owned outright by this
        struct, they cannot fail, and they must happen even when the FFI
        handle could not be released.
        """
        if self._handle >= 0:
            try:
                _ = self._lib.inner_ptr()[].tls_conn_free(self._handle)
            except:
                pass
        self._ct_drain_buf.unsafe_free()
        self._pt_drain_buf.unsafe_free()
        # Anchor: `inner_ptr()` returns an untracked pointer, so the checker
        # cannot see that the call above depends on `_lib`. Without a later
        # reference, ASAP destruction frees `_lib` at that line -- closing the
        # dylib -- and the FFI call runs through a null handle.
        _ = self._lib.inner_ptr()

    # -- Construction ----------------------------------------------------------

    @staticmethod
    def new_client(
        lib: SharedLibrary,
        ref config: TlsClientConfig,
        server_name: String,
    ) raises -> Self:
        """Create a TLS client connection.

        Immediately drains the initial ClientHello into the internal
        ciphertext-out buffer so the caller can grab it via
        `drain_ciphertext()` right after construction.

        Args:
            lib: SharedLibrary handle (refcount is incremented).
            config: Client config (must outlive the connection).
            server_name: SNI hostname (e.g. "localhost").
        """
        var rlib = lib.inner_ptr()
        var name_bytes = server_name.as_bytes()
        var name_len = len(name_bytes)
        var name_buf = _heap_alloc[UInt8](name_len)
        for i in range(name_len):
            name_buf[unsafe_offset=i] = name_bytes[i]

        var handle = rlib[].tls_client_new(
            config.handle(),
            name_buf,
            Int32(name_len),
        )
        name_buf.unsafe_free()

        if handle < 0:
            raise "rlsm_tls_client_new failed: " + rlib[].last_error()

        # Drain the ClientHello immediately so the caller can send it.
        # We allocate the ciphertext drain buffer here and reuse it as the
        # struct's pre-allocated buffer (no double allocation).
        var ct_out = List[Byte]()
        var init_ct_buf = _heap_alloc[UInt8](_CIPHERTEXT_DRAIN_BUF_SIZE)
        try:
            while True:
                var dn = rlib[].tls_conn_write_tls(
                    handle, init_ct_buf, Int32(_CIPHERTEXT_DRAIN_BUF_SIZE)
                )
                if dn < 0:
                    raise "rlsm_tls_conn_write_tls failed: " + rlib[].last_error()
                if dn == 0:
                    break
                for di in range(Int(dn)):
                    ct_out.append(init_ct_buf[unsafe_offset=di])
        except e:
            init_ct_buf.unsafe_free()
            _ = rlib[].tls_conn_free(handle)
            raise e.copy()

        return Self(
            _lib=lib,
            _handle=handle,
            _ciphertext_out=ct_out^,
            _ct_drain_buf=init_ct_buf,
            _pt_drain_buf=_heap_alloc[UInt8](_IO_BUF_SIZE),
            _handshake_complete=False,
        )

    @staticmethod
    def new_server(
        lib: SharedLibrary,
        ref config: TlsServerConfig,
    ) raises -> Self:
        """Create a TLS server connection.

        The server has nothing to send until it has received a ClientHello,
        so the internal ciphertext-out buffer starts empty.
        """
        var rlib = lib.inner_ptr()
        var handle = rlib[].tls_server_new(config.handle())
        if handle < 0:
            raise "rlsm_tls_server_new failed: " + rlib[].last_error()

        return Self(
            _lib=lib,
            _handle=handle,
            _ciphertext_out=List[Byte](),
            _ct_drain_buf=_heap_alloc[UInt8](_CIPHERTEXT_DRAIN_BUF_SIZE),
            _pt_drain_buf=_heap_alloc[UInt8](_IO_BUF_SIZE),
            _handshake_complete=False,
        )

    # -- Inbound: ciphertext -> plaintext --------------------------------------

    def receive_data(mut self, ciphertext: Span[Byte, _]) raises:
        """Feed all of `ciphertext`, moving plaintext rustls cannot hold to a stash.

        Stops early only at close_notify (later bytes are ignored, RFC 8446
        Section 6.1). The stash grows until the next drain; callers that need
        bounded memory use `receive_data_step`. Handshake replies and alerts
        land in ciphertext-out. Raises "data after EOF" after `receive_eof`.
        """
        if self._eof_received:
            raise "TlsConnection.receive_data: data after EOF"
        var off = 0
        while off < len(ciphertext):
            var step = self.receive_data_step(ciphertext[off:])
            off += step.consumed
            if step.status == TlsStepStatus.PEER_CLOSED:
                return
            var stashed = 0
            if step.status == TlsStepStatus.NEEDS_DRAIN:
                stashed = self._stash_plaintext()
            if step.consumed == 0 and stashed == 0:
                raise "TlsConnection.receive_data: no progress"

    def drain_plaintext_into(mut self, mut sink: List[Byte]) raises:
        """Append all decrypted plaintext (stash first, then rustls) into `sink`.

        A clean close, "no data yet" and an unclean EOF all end the drain
        without raising; `eof_state()` tells them apart.
        """
        if len(self._pt_stash) > 0:
            sink.extend(Span(self._pt_stash))
            self._pt_stash.clear()
        self._read_rustls_plaintext(sink)

    def drain_plaintext(mut self) raises -> List[Byte]:
        """Return any decrypted plaintext available after `receive_data`.

        Convenience wrapper around `drain_plaintext_into` for callers that
        don't retain a reusable buffer across calls.
        """
        var result = List[Byte]()
        self.drain_plaintext_into(result)
        return result^

    def receive_data_step(mut self, ciphertext: Span[Byte, _]) raises -> TlsStep:
        """Feed ciphertext until done or rustls needs the caller; never raises
        for backpressure.

        Status priority, independent of `consumed == len`: PEER_CLOSED >
        NEEDS_DRAIN > COMPLETE. With more than 16 KiB of plaintext pending on
        entry, returns `consumed=0, NEEDS_DRAIN` without feeding rustls. On a
        fatal error, any alert rustls queued is moved to ciphertext-out before
        raising. Raises "data after EOF" after `receive_eof`.
        """
        if self._eof_received:
            raise "TlsConnection.receive_data: data after EOF"
        if len(ciphertext) == 0:
            return TlsStep(consumed=0, status=TlsStepStatus.COMPLETE)
        var stop = Int32(0)
        var rc = self._lib.inner_ptr()[].tls_conn_read_tls(
            self._handle,
            ciphertext.unsafe_ptr().unsafe_mut_cast[True]().as_unsafe_any_origin(),
            Int32(len(ciphertext)),
            Pointer(to=stop),
        )
        if rc < 0:
            var err = self._lib.inner_ptr()[].last_error()
            try:
                self._drain_write_tls()
            except:
                pass
            raise "rlsm_tls_conn_read_tls failed: " + err
        self._drain_write_tls()
        self._refresh_handshake()
        var status = TlsStepStatus(UInt8(stop))
        if status == TlsStepStatus.PEER_CLOSED:
            self._peer_closed = True
        return TlsStep(consumed=Int(rc), status=status)

    def receive_eof(mut self) raises:
        """Record the transport's end-of-stream (idempotent).

        Pending plaintext stays drainable. Afterwards `receive_data` and
        `receive_data_step` raise "data after EOF". Call only after feeding
        everything the transport delivered.
        """
        if self._eof_received:
            return
        # rustls refuses EOF while its plaintext buffer is full.
        _ = self._stash_plaintext()
        var stop = Int32(0)
        if self._lib.inner_ptr()[].tls_conn_read_eof(self._handle, Pointer(to=stop)) < 0:
            var err = self._lib.inner_ptr()[].last_error()
            try:
                self._drain_write_tls()
            except:
                pass
            raise "rlsm_tls_conn_read_eof failed: " + err
        self._eof_received = True
        if TlsStepStatus(UInt8(stop)) == TlsStepStatus.PEER_CLOSED:
            self._peer_closed = True
        self._drain_write_tls()

    def eof_state(self) -> TlsEof:
        """CLEAN once close_notify was seen, else UNCLEAN after `receive_eof`,
        else NONE. Unclean EOF never raises from the drain; check it here."""
        if self._peer_closed:
            return TlsEof.CLEAN
        if self._eof_received:
            return TlsEof.UNCLEAN
        return TlsEof.NONE

    # -- Outbound: plaintext -> ciphertext -------------------------------------

    def send_data(mut self, plaintext: Span[Byte, _]) raises:
        """Encrypt all of `plaintext` into ciphertext-out (`drain_ciphertext`).

        Raises if rustls stops accepting without producing ciphertext (its
        pre-handshake buffer is full); bytes accepted before that may already
        be ciphertext, so the connection is then unusable.
        """
        var off = 0
        while off < len(plaintext):
            var before = len(self._ciphertext_out)
            var step = self.send_data_step(plaintext[off:])
            off += step.consumed
            if step.consumed == 0 and len(self._ciphertext_out) == before:
                raise "TLS send made no progress (pre-handshake buffer full?)"

    def send_data_step(mut self, plaintext: Span[Byte, _]) raises -> TlsStep:
        """Offer plaintext; `consumed` is what rustls accepted.

        Produced ciphertext is moved to ciphertext-out within the call.
        COMPLETE iff everything was accepted, else NEEDS_FLUSH. While
        handshaking with the 64 KiB pre-handshake buffer full, returns
        `consumed=0, NEEDS_FLUSH`.
        """
        if len(plaintext) == 0:
            return TlsStep(consumed=0, status=TlsStepStatus.COMPLETE)
        var rc = self._lib.inner_ptr()[].tls_conn_write_plaintext(
            self._handle,
            plaintext.unsafe_ptr().unsafe_mut_cast[True]().as_unsafe_any_origin(),
            Int32(len(plaintext)),
        )
        if rc < 0:
            raise (
                "rlsm_tls_conn_write_plaintext failed: "
                + self._lib.inner_ptr()[].last_error()
            )
        self._drain_write_tls()
        var n = Int(rc)
        if n == len(plaintext):
            return TlsStep(consumed=n, status=TlsStepStatus.COMPLETE)
        return TlsStep(consumed=n, status=TlsStepStatus.NEEDS_FLUSH)

    def drain_ciphertext_into(mut self, mut sink: List[Byte]):
        """Append all buffered ciphertext into `sink` and clear it in place.

        Unlike `drain_ciphertext` (which moves the buffer out and
        reallocates a fresh one), `drain_ciphertext_into` preserves the
        internal buffer's backing allocation across `send_data` /
        `receive_data` cycles (`clear()` keeps capacity) -- this is the
        steady-state zero-churn drain for long-lived connections.
        """
        sink.extend(Span(self._ciphertext_out))
        self._ciphertext_out.clear()

    def drain_ciphertext(mut self) -> List[Byte]:
        """Return all buffered ciphertext, clearing the internal buffer.

        This is the data that must be sent to the peer over the network.
        Convenience wrapper around `drain_ciphertext_into` for callers that
        don't retain a reusable buffer across calls.
        """
        var out = List[Byte]()
        self.drain_ciphertext_into(out)
        return out^

    # -- State -----------------------------------------------------------------

    def is_handshaking(self) -> Bool:
        """True if the TLS handshake is still in progress."""
        return not self._handshake_complete

    def wants_write(self) -> Bool:
        """True if there is buffered ciphertext waiting to be sent."""
        return len(self._ciphertext_out) > 0

    def alpn(self) raises -> Optional[String]:
        """Return the negotiated ALPN protocol identifier, or None.

        The buffer is sized to fit any realistic ALPN identifier (256 B —
        ALPN strings in practice are short tokens like "h2", "http/1.1",
        "h3"). The Rust FFI returns -1 if it would have to truncate, so
        any -1 here is a real error rather than silent data loss.
        """
        var buf = _heap_alloc[UInt8](_ALPN_BUF_SIZE)
        var n = self._lib.inner_ptr()[].tls_conn_alpn(
            self._handle, buf, Int32(_ALPN_BUF_SIZE)
        )
        if n < 0:
            var err = self._lib.inner_ptr()[].last_error()
            buf.unsafe_free()
            raise "rlsm_tls_conn_alpn failed: " + err
        if n == 0:
            buf.unsafe_free()
            return Optional[String](None)
        var s = String()
        for i in range(Int(n)):
            s += chr(Int(buf[unsafe_offset=i]))
        buf.unsafe_free()
        return Optional[String](s^)

    # -- Internal --------------------------------------------------------------

    def _read_rustls_plaintext(mut self, mut sink: List[Byte]) raises:
        """Move everything rustls has decrypted into `sink`."""
        while True:
            var n = self._lib.inner_ptr()[].tls_conn_read_plaintext(
                self._handle, self._pt_drain_buf, Int32(_IO_BUF_SIZE)
            )
            if n < 0:
                raise (
                    "rlsm_tls_conn_read_plaintext failed: "
                    + self._lib.inner_ptr()[].last_error()
                )
            if n == 0:
                return
            sink.extend(Span(unsafe_ptr=self._pt_drain_buf, length=Int(n)))

    def _stash_plaintext(mut self) raises -> Int:
        """Move rustls's plaintext to the stash; returns the bytes moved."""
        var stash = self._pt_stash^
        self._pt_stash = List[Byte]()
        var before = len(stash)
        try:
            self._read_rustls_plaintext(stash)
        finally:
            self._pt_stash = stash^
        return len(self._pt_stash) - before

    def _refresh_handshake(mut self) raises:
        """Latch handshake completion from rustls."""
        if not self._handshake_complete:
            if self._lib.inner_ptr()[].tls_conn_is_handshaking(self._handle) == Int32(0):
                self._handshake_complete = True

    def _drain_write_tls(mut self) raises:
        """Drain all pending ciphertext from rustls into `_ciphertext_out`."""
        while True:
            var n = self._lib.inner_ptr()[].tls_conn_write_tls(
                self._handle,
                self._ct_drain_buf,
                Int32(_CIPHERTEXT_DRAIN_BUF_SIZE),
            )
            if n < 0:
                raise (
                    "rlsm_tls_conn_write_tls failed: "
                    + self._lib.inner_ptr()[].last_error()
                )
            if n == 0:
                break
            self._ciphertext_out.extend(Span(unsafe_ptr=self._ct_drain_buf, length=Int(n)))

