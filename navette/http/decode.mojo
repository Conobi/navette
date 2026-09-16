# src/http/decode.mojo
#
# ContentDecoder — streaming gzip / brotli / identity decoder backed by
# libcompress_mojo.so FFI (lcm_gzip_* / lcm_br_*). Previously lived in
# librustls_mojo.so; split into its own shim
# so a future zlib/brotli CVE is a `apt upgrade` away, not a Navette release.
from std.ffi import OwnedDLHandle
from std.memory import Pointer
from navette.util.owned_alloc import Owned

# Typed FFI loaders auto-generated from crates/libcompress-mojo/symbols.toml
# by scripts/gen_ffi_bindings.py — signature drift between C and Mojo
# produces a compile error.
from navette.compress._lcm_bindings import (
    call_lcm_br_feed,
    call_lcm_br_finish,
    call_lcm_br_free,
    call_lcm_br_init,
    call_lcm_gzip_feed,
    call_lcm_gzip_finish,
    call_lcm_gzip_free,
    call_lcm_gzip_init,
)
from navette.compress.lib import DecoderLimits, _open_libcompress
from navette.util.null_ptr import null_ptr


comptime _OUT_CAP = 262144  # 256 KiB per-call output buffer

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


struct ContentDecoder(Movable):
    """Streaming content decoder (gzip, brotli, or identity passthrough).

    Wraps the stateful C FFI in libcompress_mojo.so. Typical usage:

        var dec = ContentDecoder(ContentEncoding.gzip())
        var chunk = dec.feed(compressed_bytes)
        var tail  = dec.finish()

    Decompression caps are configurable per decoder via the optional
    `limits` parameter — see DecoderLimits.default() for the ship
    defaults (64 MiB input / 256 MiB output / 100:1 ratio).
    """

    var _encoding: ContentEncoding
    var _lib: OwnedDLHandle
    var _state: Pointer[NoneType, MutUntrackedOrigin]

    # -- lifecycle -------------------------------------------------------------

    def __init__(out self, encoding: ContentEncoding) raises:
        """Create a decoder for the given encoding, with default caps."""
        var limits = DecoderLimits.default()
        self._encoding = ContentEncoding(copy_from=encoding)
        self._lib = _open_libcompress()
        if encoding._tag == _ENC_GZIP:
            self._state = call_lcm_gzip_init(
                self._lib,
                limits.input_cap, limits.output_cap, limits.ratio_x100,
            )
        elif encoding._tag == _ENC_BROTLI:
            self._state = call_lcm_br_init(
                self._lib,
                limits.input_cap, limits.output_cap, limits.ratio_x100,
            )
        else:
            self._state = null_ptr[NoneType, MutUntrackedOrigin]()

    def __init__(out self, encoding: ContentEncoding, limits: DecoderLimits) raises:
        """Create a decoder with explicit decompression caps.

        Resolves libcompress_mojo.so via the shared loader
        (`navette.compress.lib._open_libcompress`); same RPATH /
        env-var / CWD-relative fallback as `RustlsLibrary`.
        """
        self._encoding = ContentEncoding(copy_from=encoding)
        self._lib = _open_libcompress()
        if encoding._tag == _ENC_GZIP:
            self._state = call_lcm_gzip_init(
                self._lib,
                limits.input_cap, limits.output_cap, limits.ratio_x100,
            )
        elif encoding._tag == _ENC_BROTLI:
            self._state = call_lcm_br_init(
                self._lib,
                limits.input_cap, limits.output_cap, limits.ratio_x100,
            )
        else:
            self._state = null_ptr[NoneType, MutUntrackedOrigin]()

    def __init__(out self, encoding: ContentEncoding, lib_path: String) raises:
        """Create a decoder with an explicit libcompress_mojo.so path."""
        var limits = DecoderLimits.default()
        self._encoding = ContentEncoding(copy_from=encoding)
        self._lib = OwnedDLHandle(lib_path)
        if encoding._tag == _ENC_GZIP:
            self._state = call_lcm_gzip_init(
                self._lib,
                limits.input_cap, limits.output_cap, limits.ratio_x100,
            )
        elif encoding._tag == _ENC_BROTLI:
            self._state = call_lcm_br_init(
                self._lib,
                limits.input_cap, limits.output_cap, limits.ratio_x100,
            )
        else:
            self._state = null_ptr[NoneType, MutUntrackedOrigin]()

    def __init__(out self, encoding: ContentEncoding, lib_path: String, limits: DecoderLimits) raises:
        """Create a decoder with explicit lib path and caps."""
        self._encoding = ContentEncoding(copy_from=encoding)
        self._lib = OwnedDLHandle(lib_path)
        if encoding._tag == _ENC_GZIP:
            self._state = call_lcm_gzip_init(
                self._lib,
                limits.input_cap, limits.output_cap, limits.ratio_x100,
            )
        elif encoding._tag == _ENC_BROTLI:
            self._state = call_lcm_br_init(
                self._lib,
                limits.input_cap, limits.output_cap, limits.ratio_x100,
            )
        else:
            self._state = null_ptr[NoneType, MutUntrackedOrigin]()

    def __init__(out self, *, deinit move: Self):
        self._encoding = ContentEncoding(copy_from=move._encoding)
        self._lib = move._lib^
        self._state = move._state

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

    def feed(self, data: List[UInt8]) raises -> List[UInt8]:
        """Feed compressed bytes and return whatever can be decompressed now.

        For identity encoding, returns a copy of the input.
        """
        if self._encoding._tag == _ENC_IDENTITY:
            var out = List[UInt8]()
            for ref byte in data:
                out.append(byte)
            return out^

        # Keeps `data`'s origin: the wrapper's `origin=_` parameter borrows
        # it for the duration of the FFI call, so the list cannot be freed
        # while C is reading from it.
        var in_ptr = data.unsafe_ptr().unsafe_bitcast[UInt8]().unsafe_mut_cast[True]()
        var out_buf_owner = Owned[UInt8](_OUT_CAP)
        var out_buf = out_buf_owner.ptr()
        var n: Int64

        if self._encoding._tag == _ENC_GZIP:
            n = call_lcm_gzip_feed(
                self._lib,
                self._state, in_ptr, len(data), out_buf, _OUT_CAP,
            )
        else:
            n = call_lcm_br_feed(
                self._lib,
                self._state, in_ptr, len(data), out_buf, _OUT_CAP,
            )

        if n < 0:
            raise "ContentDecoder.feed: decompression error (" + String(n) + ")"

        var result = List[UInt8]()
        for i in range(Int(n)):
            result.append(out_buf[unsafe_offset=i])
        return result^

    def finish(self) raises -> List[UInt8]:
        """Flush any remaining decompressed bytes.

        Must be called once after all data has been fed. For identity
        encoding, returns an empty list.
        """
        if self._encoding._tag == _ENC_IDENTITY:
            return List[UInt8]()

        var out_buf_owner = Owned[UInt8](_OUT_CAP)
        var out_buf = out_buf_owner.ptr()
        var n: Int64

        if self._encoding._tag == _ENC_GZIP:
            n = call_lcm_gzip_finish(
                self._lib,
                self._state, out_buf, _OUT_CAP,
            )
        else:
            n = call_lcm_br_finish(
                self._lib,
                self._state, out_buf, _OUT_CAP,
            )

        if n < 0:
            raise "ContentDecoder.finish: decompression error (" + String(n) + ")"

        var result = List[UInt8]()
        for i in range(Int(n)):
            result.append(out_buf[unsafe_offset=i])
        return result^
