#!/usr/bin/env python3
"""Back-compat shim: gen_ffi_bindings.py with the rlsm defaults baked in.

Original behaviour: emit src/tls/_rlsm_bindings.mojo from
crates/librustls-mojo/symbols.toml. Now generalized by gen_ffi_bindings.py
(spec 2026-05-17-compress-shim-split). This shim preserves the historical
invocation so any external scripts / docs still work.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import gen_ffi_bindings  # noqa: E402


def main(argv: list[str]) -> int:
    import os
    # Run from repo root so the schema path is captured relative in the
    # generated header, not as an absolute path that depends on whoever
    # ran the script.
    repo_root = HERE.parent
    os.chdir(repo_root)
    forwarded = ["--schema", "crates/librustls-mojo/symbols.toml"]
    forwarded += argv  # forwards --out etc. verbatim
    return gen_ffi_bindings.main(forwarded)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
