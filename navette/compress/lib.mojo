# navette/compress/lib.mojo
#
# CompressLibrary — dynamically loaded libcompress_mojo.so. Mirrors the
# RustlsLibrary dlopen pattern in navette/tls/lib.mojo so deployment
# rules are consistent across the two native shims.
#
# DecoderLimits — runtime decompression caps. The defaults sit here
# rather than in the C wrapper so a CLI or library user can override
# without rebuilding the .so. See spec §4.3.
from std.ffi import OwnedDLHandle
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.compress._lcm_bindings import (
    load_lcm_last_error,
)


fn _open_libcompress() raises -> OwnedDLHandle:
    """Locate and dlopen libcompress_mojo.so across deployment modes.

    Search order mirrors `_open_librustls`:
      1. Bare soname `libcompress_mojo.so` — resolves via RUNPATH
         (mojox-build injects $ORIGIN-relative paths to the venv's
         mojo_packages/lib for installed scripts) or LD_LIBRARY_PATH
         / ld.so.cache.
      2. CWD-relative `lib/libcompress_mojo.so` — for `mojo run` from
         example directories that carry a committed `lib/` symlink.
    """
    try:
        return OwnedDLHandle("libcompress_mojo.so")
    except:
        return OwnedDLHandle("lib/libcompress_mojo.so")


struct DecoderLimits:
    """Runtime caps for streaming decompression.

    Limits are explicit knobs on the Mojo side, not magic constants in
    the C wrapper (spec §4.3). A cap of 0 disables the corresponding
    check.

    - input_cap:  total compressed bytes that may be fed via successive
                  `feed` calls before the wrapper returns -2.
    - output_cap: total decompressed bytes that may be emitted before
                  the wrapper returns -3.
    - ratio_x100: max output/input ratio × 100; check kicks in once
                  cumulative input ≥ 1024 (no divide-by-zero for tiny
                  prefixes). Returns -4 on violation.
    """

    var input_cap: UInt64
    var output_cap: UInt64
    var ratio_x100: UInt32

    def __init__(out self, input_cap: UInt64, output_cap: UInt64, ratio_x100: UInt32):
        self.input_cap  = input_cap
        self.output_cap = output_cap
        self.ratio_x100 = ratio_x100

    def __init__(out self, *, copy_from: Self):
        self.input_cap  = copy_from.input_cap
        self.output_cap = copy_from.output_cap
        self.ratio_x100 = copy_from.ratio_x100

    @staticmethod
    def default() -> DecoderLimits:
        """64 MiB input, 256 MiB output, 100:1 ratio.

        Chosen to fit the dominant HTTP-response shape (well under
        100 MB) while bounding decompression-bomb amplification at
        100×, which is more than enough headroom for gzip text but
        an order of magnitude under typical zip-bomb ratios (1000×+).
        """
        return DecoderLimits(64 << 20, 256 << 20, 10_000)

    @staticmethod
    def unlimited() -> DecoderLimits:
        """No caps. Use only in trusted contexts (test fixtures, etc.)."""
        return DecoderLimits(0, 0, 0)


struct CompressLibrary(Movable):
    """Dynamically loaded libcompress_mojo.so handle.

    Owners of the handle can retrieve the last error string via
    `last_error()`. ContentDecoder consumes a `CompressLibrary` via
    `_open_libcompress()`; tests that want a non-default search path
    can construct one explicitly with `CompressLibrary(path=...)`.
    """

    var _handle: OwnedDLHandle

    def __init__(out self) raises:
        self._handle = _open_libcompress()

    def __init__(out self, path: String) raises:
        self._handle = OwnedDLHandle(path)

    def __init__(out self, *, deinit take: Self):
        self._handle = take._handle^

    def last_error(self) -> String:
        """Retrieve the last libcompress-mojo error message.

        Returns an empty string if no error is set.
        """
        var buf = _heap_alloc[UInt8](512).as_any_origin()
        var n = load_lcm_last_error(self._handle)(buf, Int32(512))
        if n <= 0:
            buf.free()
            return String("")
        var msg = String()
        for i in range(Int(n - 1)):
            msg += chr(Int(buf[i]))
        buf.free()
        return msg^
