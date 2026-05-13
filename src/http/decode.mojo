# src/http/decode.mojo
#
# ContentDecoder — streaming gzip / brotli / identity decoder backed by
# librustls_mojo.so FFI (rlsm_gzip_* / rlsm_br_*).
from std.ffi import OwnedDLHandle
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

# Typed FFI loaders auto-generated from crates/librustls-mojo/symbols.toml.
# §2.3 deps-enhancement: rlsm_* symbols resolve through the generated module
# so signature drift between Rust and Mojo produces a compile error.
from src.tls._rlsm_bindings import (
    load_rlsm_br_feed,
    load_rlsm_br_finish,
    load_rlsm_br_free,
    load_rlsm_br_init,
    load_rlsm_gzip_feed,
    load_rlsm_gzip_finish,
    load_rlsm_gzip_free,
    load_rlsm_gzip_init,
)


comptime _OUT_CAP = 262144  # 256 KiB decompression output buffer

comptime _ENC_IDENTITY: UInt8 = 0
comptime _ENC_GZIP: UInt8 = 1
comptime _ENC_BROTLI: UInt8 = 2


struct ContentEncoding:
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

    Wraps the stateful C FFI in librustls_mojo.so.  Typical usage:

        var dec = ContentDecoder(ContentEncoding.gzip())
        var chunk = dec.feed(compressed_bytes)
        var tail  = dec.finish()
    """

    var _encoding: ContentEncoding
    var _lib: OwnedDLHandle
    var _state: UnsafePointer[NoneType, MutAnyOrigin]

    # -- lifecycle -------------------------------------------------------------

    def __init__(
        out self,
        encoding: ContentEncoding,
        lib_path: String = "lib/librustls_mojo.so",
    ) raises:
        """Create a decoder for the given encoding."""
        self._encoding = ContentEncoding(copy_from=encoding)
        self._lib = OwnedDLHandle(lib_path)
        if encoding._tag == _ENC_GZIP:
            self._state = load_rlsm_gzip_init(self._lib)()
        elif encoding._tag == _ENC_BROTLI:
            self._state = load_rlsm_br_init(self._lib)()
        else:
            self._state = UnsafePointer[NoneType, MutAnyOrigin]()

    def __init__(out self, *, deinit take: Self):
        self._encoding = ContentEncoding(copy_from=take._encoding)
        self._lib = take._lib^
        self._state = take._state

    def __del__(deinit self):
        if self._state:
            if self._encoding._tag == _ENC_GZIP:
                load_rlsm_gzip_free(self._lib)(self._state)
            elif self._encoding._tag == _ENC_BROTLI:
                load_rlsm_br_free(self._lib)(self._state)

    # -- public API ------------------------------------------------------------

    def feed(self, data: List[UInt8]) raises -> List[UInt8]:
        """Feed compressed bytes and return whatever can be decompressed now.

        For identity encoding, returns a copy of the input.
        """
        if self._encoding._tag == _ENC_IDENTITY:
            var out = List[UInt8]()
            for i in range(len(data)):
                out.append(data[i])
            return out^

        var in_ptr = data.unsafe_ptr().bitcast[UInt8]().as_any_origin()
        var out_buf = _heap_alloc[UInt8](_OUT_CAP).as_any_origin()
        var n: Int64

        if self._encoding._tag == _ENC_GZIP:
            n = load_rlsm_gzip_feed(self._lib)(
                self._state, in_ptr, len(data), out_buf, _OUT_CAP,
            )
        else:
            n = load_rlsm_br_feed(self._lib)(
                self._state, in_ptr, len(data), out_buf, _OUT_CAP,
            )

        if n < 0:
            out_buf.free()
            raise "ContentDecoder.feed: decompression error"

        var result = List[UInt8]()
        for i in range(Int(n)):
            result.append(out_buf[i])
        out_buf.free()
        return result^

    def finish(self) raises -> List[UInt8]:
        """Flush any remaining decompressed bytes.

        Must be called once after all data has been fed.  For identity
        encoding, returns an empty list.
        """
        if self._encoding._tag == _ENC_IDENTITY:
            return List[UInt8]()

        var out_buf = _heap_alloc[UInt8](_OUT_CAP).as_any_origin()
        var n: Int64

        if self._encoding._tag == _ENC_GZIP:
            n = load_rlsm_gzip_finish(self._lib)(
                self._state, out_buf, _OUT_CAP,
            )
        else:
            n = load_rlsm_br_finish(self._lib)(
                self._state, out_buf, _OUT_CAP,
            )

        if n < 0:
            out_buf.free()
            raise "ContentDecoder.finish: decompression error"

        var result = List[UInt8]()
        for i in range(Int(n)):
            result.append(out_buf[i])
        out_buf.free()
        return result^
