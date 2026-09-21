#!/bin/bash
# Remove the editable-install source symlink for navette from site-packages.
#
# When both navette.mojoc (.mojox/build/pkg/) and the navette/ source
# directory (site-packages/mojo_packages/, created by the editable install)
# are on the -I path, the Mojo compiler sometimes resolves through the
# source instead of the precompiled .mojoc — recompiling the entire package
# per test file.  Removing the symlink forces resolution through the .mojoc.
#
# Impact: 6-9× faster test compilation (972s → ~150s for 16 target files).
#
# Run after any `uv sync` that recreates the symlink.  Idempotent.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_PYTHON="$PROJECT_DIR/.venv/bin/python3"

SITE_MOJO="$("$VENV_PYTHON" -c 'import sysconfig; print(sysconfig.get_path("platlib"))')/mojo_packages"

target="$SITE_MOJO/navette"
if [ -L "$target" ]; then
    rm "$target"
    echo "Removed source symlink: $target"
elif [ -d "$target" ]; then
    echo "WARNING: $target is a real directory, not a symlink — not touching it"
    exit 1
elif [ ! -e "$target" ]; then
    echo "Already removed: $target"
fi

# Ensure bouclette.mojoc is available alongside navette.mojoc so tests that
# directly import bouclette resolve without the site-packages path.
pkg_dir="$(dirname "$(dirname "$0")")/.mojox/build/pkg"
bouclette_src="$SITE_MOJO/bouclette.mojoc"
bouclette_dst="$pkg_dir/bouclette.mojoc"
if [ -f "$bouclette_src" ] && [ ! -e "$bouclette_dst" ]; then
    ln -s "$bouclette_src" "$bouclette_dst"
    echo "Symlinked bouclette.mojoc into $pkg_dir"
fi
