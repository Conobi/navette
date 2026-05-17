# navette.compress — system zlib + brotli, dlopen'd via libcompress_mojo.so.
#
# Public surface:
#   CompressLibrary: dlopen handle owner; mirrors navette.tls.lib.RustlsLibrary.
#   DecoderLimits:   decompression caps (input/output/ratio) — explicit knobs
#                    rather than #define magic in the C wrapper (spec
#                    2026-05-17-compress-shim-split §4.3).

from .lib import CompressLibrary, DecoderLimits, _open_libcompress
