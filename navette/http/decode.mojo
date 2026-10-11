# src/http/decode.mojo
#
# ContentDecoder — streaming gzip / brotli / identity decoder backed by
# libcompress_mojo.so FFI (lcm_gzip_* / lcm_br_*). Previously lived in
# librustls_mojo.so; split into its own shim
# so a future zlib/brotli CVE is a `apt upgrade` away, not a Navette release.
from std.collections import Span
from std.ffi import OwnedDLHandle
from std.memory import Pointer

# Typed FFI loaders auto-generated from crates/libcompress-mojo/symbols.toml
# by scripts/gen_ffi_bindings.py — signature drift between C and Mojo
# produces a compile error.
from navette.compress._lcm_bindings import (
    call_lcm_br_free,
    call_lcm_br_init,
    call_lcm_br_trailing_seen,
    call_lcm_gzip_free,
    call_lcm_gzip_init,
    call_lcm_gzip_trailing_seen,
    load_lcm_br_finish_step,
    load_lcm_br_step,
    load_lcm_gzip_finish_step,
    load_lcm_gzip_step,
    lcm_br_finish_step_fn,
    lcm_br_step_fn,
    lcm_gzip_finish_step_fn,
    lcm_gzip_step_fn,
)
from navette.compress.lib import DecoderLimits, _open_libcompress
from navette.util.null_ptr import null_ptr


comptime _STEP_OUT = 65536  # wrapper step size: bounds each FFI call's output
comptime _LCM_TRUNCATED = Int32(-5)
comptime _LCM_AFTER_FINISH = Int32(-6)
comptime _LCM_FAILED = Int32(-7)
comptime _BAD_COUNTS = Int32(-100)  # Mojo-side: shim counts exceed the buffers

comptime _ENC_IDENTITY: UInt8 = 0
comptime _ENC_GZIP: UInt8 = 1
comptime _ENC_BROTLI: UInt8 = 2


struct ContentEncoding(Copyable, Movable):
    """Identifies the wire encoding of a response body."""

    var _tag: UInt8

    def __init__(out self, tag: UInt8):
        self._tag = tag

    def __init__(out self, *, copy_from: Self):
        self._tag = copy_from._tag

    @staticmethod
    def identity() -> ContentEncoding:
        return ContentEncoding(_ENC_IDENTITY)

    @staticmethod
    def gzip() -> ContentEncoding:
        return ContentEncoding(_ENC_GZIP)

    @staticmethod
    def brotli() -> ContentEncoding:
        return ContentEncoding(_ENC_BROTLI)

    @staticmethod
    def from_header(value: String) -> ContentEncoding:
        """Parse a Content-Encoding header value."""
        if value == "gzip" or value == "x-gzip":
            return ContentEncoding(_ENC_GZIP)
        if value == "br":
            return ContentEncoding(_ENC_BROTLI)
        return ContentEncoding(_ENC_IDENTITY)


@fieldwise_init
struct DecodeStatus(Equatable, ImplicitlyCopyable):
    """Why a decode step stopped."""

    var _value: UInt8

    comptime NEED_INPUT = DecodeStatus(0)  # input consumed, no output pending
    comptime NEED_OUTPUT = DecodeStatus(1)  # max_out reached or output pending; call again
    # step_into: end of the current gzip member / brotli stream (provisional);
    # finish_step_into: stream complete, decoder closed.
    comptime DONE = DecodeStatus(2)

    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value


@fieldwise_init
struct DecodeStep(ImplicitlyCopyable):
    """`produced` bytes were appended to `out`; `consumed` includes discarded
    trailing bytes."""

    var consumed: Int
    var produced: Int
    var status: DecodeStatus


def _init_decoder_state(
    ref lib: OwnedDLHandle, encoding: ContentEncoding, limits: DecoderLimits,
) raises -> Pointer[NoneType, MutUntrackedOrigin]:
    """Initialize C-side decoder state for the given encoding."""
    if encoding._tag == _ENC_GZIP:
        return call_lcm_gzip_init(
            lib,
            limits.input_cap, limits.output_cap, limits.ratio_x100,
        )
    elif encoding._tag == _ENC_BROTLI:
        return call_lcm_br_init(
            lib,
            limits.input_cap, limits.output_cap, limits.ratio_x100,
        )
    return null_ptr[NoneType, MutUntrackedOrigin]()


def _call_step(
    step_fn: lcm_gzip_step_fn,
    state: Pointer[NoneType, MutUntrackedOrigin],
    input: Span[Byte, _],
    dest: Span[mut=True, Byte, _],
    consumed: Pointer[mut=True, T=UInt, origin=_],
    produced: Pointer[mut=True, T=UInt, origin=_],
) -> Int32:
    """Call a C step function with out-params whose origins reach this frame.

    Erasing an out-param's origin at the caller hides the write from the
    compiler, and optimized builds then read the local's initial value.
    Counts larger than the buffers return `_BAD_COUNTS`.
    """
    var rc = step_fn(
        state,
        input.unsafe_ptr().unsafe_mut_cast[True]().unsafe_origin_cast[MutUntrackedOrigin](), len(input),
        consumed.unsafe_origin_cast[MutUntrackedOrigin](),
        dest.unsafe_ptr().unsafe_origin_cast[MutUntrackedOrigin](), len(dest),
        produced.unsafe_origin_cast[MutUntrackedOrigin](),
    )
    if rc >= 0 and (Int(consumed[]) > len(input) or Int(produced[]) > len(dest)):
        return _BAD_COUNTS
    return rc


def _call_finish(
    finish_fn: lcm_gzip_finish_step_fn,
    state: Pointer[NoneType, MutUntrackedOrigin],
    dest: Span[mut=True, Byte, _],
    produced: Pointer[mut=True, T=UInt, origin=_],
) -> Int32:
    """`_call_step` for the finish functions (same origin and count rules)."""
    var rc = finish_fn(
        state, dest.unsafe_ptr().unsafe_origin_cast[MutUntrackedOrigin](), len(dest),
        produced.unsafe_origin_cast[MutUntrackedOrigin](),
    )
    if rc >= 0 and Int(produced[]) > len(dest):
        return _BAD_COUNTS
    return rc


def _decode_error(phase: String, rc: Int32, gzip: Bool) -> Error:
    """Message for a negative shim code; numeric codes keep the "(<code>)" form."""
    var head = "ContentDecoder." + phase + ": "
    if rc == _LCM_AFTER_FINISH:
        return Error(head + "feed after finish")
    if rc == _LCM_FAILED:
        return Error(head + "decoder failed")
    if rc == _BAD_COUNTS:
        return Error(head + "shim reported counts beyond its buffers")
    var msg = head + "decompression error (" + String(rc) + ")"
    if rc == _LCM_TRUNCATED:
        msg += ": truncated " + ("gzip" if gzip else "brotli") + " stream"
    return Error(msg)


struct ContentDecoder(Movable):
    """Streaming content decoder (gzip, brotli, or identity passthrough).

    Wraps the stateful C FFI in libcompress_mojo.so. Typical usage:

        var dec = ContentDecoder(ContentEncoding.gzip())
        var chunk = dec.feed(compressed_bytes)
        var tail  = dec.finish()

    Decompression caps are configurable per decoder via the optional
    `limits` parameter — see DecoderLimits.default() for the ship
    defaults (64 MiB input / 256 MiB output / 100:1 ratio). Each wrapper
    call works in 64 KiB steps; caps hold on every step.
    """

    var _encoding: ContentEncoding
    var _lib: OwnedDLHandle
    var _state: Pointer[NoneType, MutUntrackedOrigin]
    # Cached FFI pointers for hot-path feed/finish, resolved once at init.
    var _gzip_step: lcm_gzip_step_fn
    var _gzip_finish_step: lcm_gzip_finish_step_fn
    var _br_step: lcm_br_step_fn
    var _br_finish_step: lcm_br_finish_step_fn

    # -- lifecycle -------------------------------------------------------------

    def __init__(out self, encoding: ContentEncoding) raises:
        """Create a decoder for the given encoding, with default caps."""
        self._encoding = ContentEncoding(copy_from=encoding)
        self._lib = _open_libcompress()
        self._gzip_step = load_lcm_gzip_step(self._lib)
        self._gzip_finish_step = load_lcm_gzip_finish_step(self._lib)
        self._br_step = load_lcm_br_step(self._lib)
        self._br_finish_step = load_lcm_br_finish_step(self._lib)
        self._state = _init_decoder_state(self._lib, encoding, DecoderLimits.default())

    def __init__(out self, encoding: ContentEncoding, limits: DecoderLimits) raises:
        """Create a decoder with explicit decompression caps."""
        self._encoding = ContentEncoding(copy_from=encoding)
        self._lib = _open_libcompress()
        self._gzip_step = load_lcm_gzip_step(self._lib)
        self._gzip_finish_step = load_lcm_gzip_finish_step(self._lib)
        self._br_step = load_lcm_br_step(self._lib)
        self._br_finish_step = load_lcm_br_finish_step(self._lib)
        self._state = _init_decoder_state(self._lib, encoding, limits)

    def __init__(out self, encoding: ContentEncoding, lib_path: String) raises:
        """Create a decoder with an explicit libcompress_mojo.so path."""
        self._encoding = ContentEncoding(copy_from=encoding)
        self._lib = OwnedDLHandle(lib_path)
        self._gzip_step = load_lcm_gzip_step(self._lib)
        self._gzip_finish_step = load_lcm_gzip_finish_step(self._lib)
        self._br_step = load_lcm_br_step(self._lib)
        self._br_finish_step = load_lcm_br_finish_step(self._lib)
        self._state = _init_decoder_state(self._lib, encoding, DecoderLimits.default())

    def __init__(out self, encoding: ContentEncoding, lib_path: String, limits: DecoderLimits) raises:
        """Create a decoder with explicit lib path and caps."""
        self._encoding = ContentEncoding(copy_from=encoding)
        self._lib = OwnedDLHandle(lib_path)
        self._gzip_step = load_lcm_gzip_step(self._lib)
        self._gzip_finish_step = load_lcm_gzip_finish_step(self._lib)
        self._br_step = load_lcm_br_step(self._lib)
        self._br_finish_step = load_lcm_br_finish_step(self._lib)
        self._state = _init_decoder_state(self._lib, encoding, limits)

    def __init__(out self, *, deinit move: Self):
        self._encoding = ContentEncoding(copy_from=move._encoding)
        self._lib = move._lib^
        self._state = move._state
        self._gzip_step = move._gzip_step
        self._gzip_finish_step = move._gzip_finish_step
        self._br_step = move._br_step
        self._br_finish_step = move._br_finish_step

    def __deinit__(deinit self):
        """Release the C-side decoder state.

        A destructor may not raise, but resolving `lcm_*_free` can: the
        symbol lookup is what raises, never the C call, which returns
        `void`. A failure therefore means the loaded .so does not export
        the matching `free` for the `init` that succeeded at construction
        — an inconsistent library, not a recoverable condition.

        The failure is swallowed, and the cost is bounded: one zlib or
        brotli stream plus its buffers leak, once, for a decoder whose
        library was already broken. Killing the process mid-teardown of a
        single HTTP response body is the worse trade for a server. There
        is no double-free risk in either direction — `deinit self`
        consumes the decoder, so this runs exactly once per state, and a
        state that fails to free is simply never freed.
        """
        # `Pointer` is non-null by design in Mojo 1.0.0, so it has no
        # truthiness; the identity encoding parks a `null_ptr` sentinel in
        # `_state` and this is the repo's address test for it (see
        # `navette.util.ptrbox.PtrBox.is_valid`).
        if Int(self._state) != 0:
            try:
                if self._encoding._tag == _ENC_GZIP:
                    call_lcm_gzip_free(self._lib, self._state)
                elif self._encoding._tag == _ENC_BROTLI:
                    call_lcm_br_free(self._lib, self._state)
            except:
                pass

    # -- public API ------------------------------------------------------------

    def feed(self, data: List[Byte]) raises -> List[Byte]:
        """Feed compressed bytes and return whatever can be decompressed now.

        For identity encoding, returns a copy of the input. Delegates to
        feed_into.
        """
        var result = List[Byte]()
        self.feed_into(result, data)
        return result^

    def finish(self) raises -> List[Byte]:
        """Flush any remaining decompressed bytes.

        Must be called once after all data has been fed. For identity
        encoding, returns an empty list. Delegates to finish_into.
        """
        var result = List[Byte]()
        self.finish_into(result)
        return result^

    def feed_into(self, mut buf: List[Byte], data: List[Byte]) raises:
        """Decode all of `data`, appending to `buf` in 64 KiB steps.

        May have appended output from earlier steps before raising. Peak
        memory is bounded only by `DecoderLimits.output_cap`; use
        `step_into` to bound it per call.
        """
        var off = 0
        while True:
            var step = self.step_into(buf, Span(data)[off:], _STEP_OUT)
            off += step.consumed
            if off == len(data) and step.status != DecodeStatus.NEED_OUTPUT:
                return
            if step.consumed == 0 and step.produced == 0:
                raise "ContentDecoder.feed: decoder made no progress"

    def finish_into(self, mut buf: List[Byte]) raises:
        """Flush the rest after the last `feed`; raises if the stream was cut off.

        A no-op for identity encoding and for a closed decoder.
        """
        while True:
            var step = self.finish_step_into(buf, _STEP_OUT)
            if step.status == DecodeStatus.DONE:
                return
            if step.produced == 0:
                raise "ContentDecoder.finish: decoder made no progress"

    def step_into(
        self, mut out: List[Byte], input: Span[Byte, _], max_out: Int
    ) raises -> DecodeStep:
        """Decode a prefix of `input`, appending at most `max_out` bytes to `out`.

        `max_out < 1` raises. Input, output and ratio caps are checked on every
        step. On raise, `len(out)` is unchanged and the decoder is poisoned:
        later steps raise "decoder failed". Bytes after the last complete
        gzip member / brotli stream are consumed, discarded and flagged via
        `trailing_garbage_seen()`. DONE is provisional: keep feeding the rest
        of the body.
        """
        if max_out < 1:
            raise "ContentDecoder.feed: max_out must be at least 1"
        if self._encoding._tag == _ENC_IDENTITY:
            var n = min(len(input), max_out)
            out.extend(input[:n])
            var st = DecodeStatus.NEED_INPUT if n == len(input) else DecodeStatus.NEED_OUTPUT
            return DecodeStep(consumed=n, produced=n, status=st)
        var gzip = self._encoding._tag == _ENC_GZIP
        var step_fn = self._gzip_step if gzip else self._br_step
        var base = len(out)
        out.resize(unsafe_uninit_length=base + max_out)
        var consumed = UInt(0)
        var produced = UInt(0)
        var rc = _call_step(
            step_fn, self._state, input, Span(out)[base:],
            Pointer(to=consumed), Pointer(to=produced),
        )
        out.resize(unsafe_uninit_length=base + (0 if rc < 0 else Int(produced)))
        if rc < 0:
            raise _decode_error("feed", rc, gzip)
        return DecodeStep(consumed=Int(consumed), produced=Int(produced), status=DecodeStatus(UInt8(rc)))

    def finish_step_into(
        self, mut out: List[Byte], max_out: Int
    ) raises -> DecodeStep:
        """Drain pending output under the same caps; call until DONE.

        Raises "truncated gzip stream" / "truncated brotli stream" when the
        stream end was never reached. A body with zero input bytes is DONE.
        Once DONE or raised, the decoder is closed: later steps raise "feed
        after finish" and further finishes return nothing. On raise,
        `len(out)` is unchanged.
        """
        if max_out < 1:
            raise "ContentDecoder.finish: max_out must be at least 1"
        if self._encoding._tag == _ENC_IDENTITY:
            return DecodeStep(consumed=0, produced=0, status=DecodeStatus.DONE)
        var gzip = self._encoding._tag == _ENC_GZIP
        var finish_fn = self._gzip_finish_step if gzip else self._br_finish_step
        var base = len(out)
        out.resize(unsafe_uninit_length=base + max_out)
        var produced = UInt(0)
        var rc = _call_finish(finish_fn, self._state, Span(out)[base:], Pointer(to=produced))
        out.resize(unsafe_uninit_length=base + (0 if rc < 0 else Int(produced)))
        if rc < 0:
            raise _decode_error("finish", rc, gzip)
        return DecodeStep(consumed=0, produced=Int(produced), status=DecodeStatus(UInt8(rc)))

    def trailing_garbage_seen(self) -> Bool:
        """True once bytes after the last complete member were discarded."""
        if Int(self._state) == 0:
            return False
        try:
            if self._encoding._tag == _ENC_GZIP:
                return call_lcm_gzip_trailing_seen(self._lib, self._state) != 0
            return call_lcm_br_trailing_seen(self._lib, self._state) != 0
        except:
            return False
