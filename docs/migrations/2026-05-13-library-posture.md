# §1.2 — library posture for mojo-net (research, deferred execution)

**Status:** research complete; execution deferred pending posture choice. 2026-05-13.

The v2 deps-enhancement plan (`plans/2026-05-13-deps-enhancement.md` §1.2) called for adding a `[build-system]` block to `pyproject.toml` so mojo-net itself can be consumed via `uv add mojo-net @ git+ssh://…`. That requires deciding how the `src/` tree maps onto a published Mojo package.

This doc captures what `mojox-build` 0.2 actually supports, the three viable reshuffle paths, and a recommendation. Nothing under `src/` has been moved yet.

## What mojox-build expects

Verified by reading `mojox-build/src/mojox_build/_config.py` + `_build.py` (PyPI 0.2.0). `[tool.mojox-build]` `BackendConfig`:

| Field            | Default | Purpose                                                              |
|------------------|---------|----------------------------------------------------------------------|
| `package-root`   | `"src"` | Directory mojox-build scans when `packages` is unset.                |
| `packages`       | (auto)  | Explicit list of package dirs. Each entry resolves as `<root>/<entry>`. |
| `native-libs`    | `[]`    | Native .so files to ship.                                            |
| `source-include` | (auto)  | sdist glob include.                                                   |
| `source-exclude` | `[]`    | sdist glob exclude.                                                  |
| `wheel-exclude`  | `[]`    | wheel-time exclude.                                                  |

Discovery logic in `_resolve_package_dirs(root, cfg)`:

```python
if cfg.packages:
    return [root / name for name in cfg.packages]
pkg_root = root / cfg.package_root
return [p for p in sorted(pkg_root.iterdir()) if p.is_dir()]
```

Each resolved dir is then compiled as a separate `.mojopkg` named after its leaf path component.

## Current state of mojo-net

- `src/` contains 7 top-level subdirs: `h1`, `h2`, `h3`, `http`, `io`, `quic`, `tls`.
- 154 `.mojo` files import via the `from src.<module>...` prefix (`grep -rln 'from src\.' --include='*.mojo'`).
- No `mojo_net/` directory exists at the repo root.

## Stdlib-name-collision constraint

Per `boucle/CLAUDE.md` and the existing src/ naming: Mojo 0.26.2's implicit stdlib imports cause local packages named `io`, `http`, `json` etc. to collide with `std.io`, `std.http`, `std.json`. **Auto-discovery under `package-root = "src"` would publish `io.mojopkg`, `http.mojopkg`, etc., which consumers cannot import without colliding with stdlib.** That option is dead.

## Three viable paths

### Path A — single `mojo_net/` package at repo root (clean, big diff)

```toml
[build-system]
requires      = ["mojox-build>=0.2", "mojo-compiler==0.26.2.0"]
build-backend = "mojox_build"

[tool.mojox-build]
packages = ["mojo_net"]
```

**Layout:** `src/` is deleted; everything moves to `mojo_net/{h1,h2,h3,http,io,quic,tls}/`.

**Diff:** 154 `from src.X` imports become `from mojo_net.X`. A `git mv src mojo_net` plus a single `sed -i 's/from src\./from mojo_net./g'` (or Python script with proper Mojo awareness) across all `.mojo` files in `tests/`, `conformance/`, `bench/`, `examples/`.

**Consumer experience:** `uv add mojo-net && from mojo_net.quic.connection import QuicConnection`. Clean.

**Risk:** big mechanical PR; merge-conflict surface against any concurrent branch touching `src/` is huge.

### Path B — keep `src/`, set `packages = ["src/mojo_net"]` (clean, medium diff)

Possible because `cfg.packages` entries are joined with `root` as `Path` segments, so `"src/mojo_net"` resolves to `<root>/src/mojo_net/`. The resulting `.mojopkg` is named after the leaf path component, so it would still be `mojo_net.mojopkg` and importable as `from mojo_net.X`.

```toml
[tool.mojox-build]
packages = ["src/mojo_net"]
```

**Layout:** `src/{h1,h2,...}` → `src/mojo_net/{h1,h2,...}`.

**Diff:** Same 154 imports need rewriting — there's no way to keep `from src.X import Y` since the import resolution after install is `from mojo_net.X` (the `src` prefix never appears in the wheel-installed package).

**Comparison to A:** identical import diff; only difference is whether the `src/` directory survives at the repo root. Path A is cleaner because `src/` was just a Python convention that doesn't earn its keep here.

**Verdict:** dominated by Path A. No reason to keep `src/`.

### Path C — defer indefinitely (current state)

Keep `[tool.uv] package = false`, no `[build-system]`, no library posture. mojo-net stays a top-level workspace consumable only by being cloned. Acceptable while:

- No external repo wants to `uv add mojo-net`
- The lift to do 154-import migration isn't worth the optionality gain

**Verdict:** fine for today. Revisit when a consumer materializes.

## Recommendation

**Adopt Path A when there's a concrete consumer.** Today, no repo `uv add`s mojo-net, so the migration would be code churn for no immediate user benefit. The work itself is mostly mechanical and can be one PR.

When ready:
1. `git mv src mojo_net` in a clean working tree.
2. Run a migration script:
   ```bash
   find mojo_net tests conformance bench examples \
        -type f -name '*.mojo' \
        -exec sed -i 's|from src\.|from mojo_net.|g' {} +
   ```
3. Update every `-I` flag and `include_paths` site:
   - `scripts/run_tests.sh`, `conformance/scripts/run_tests.sh`, `bench/Dockerfile`, etc.
   - `mcp__mojo-mcp__execute(include_paths=[...])` callers.
4. Add to `pyproject.toml`:
   ```toml
   [build-system]
   requires      = ["mojox-build>=0.2", "mojo-compiler==0.26.2.0"]
   build-backend = "mojox_build"

   [tool.mojox-build]
   packages = ["mojo_net"]
   ```
5. Remove `[tool.uv] package = false`.
6. `uv build` should produce `mojo_net-0.1.0-…whl` containing `mojo_net.mojopkg`.
7. Run `bash scripts/check_integrations.sh` — §1.1 + §1.4 still pass; add a `[build-system]` presence check.
8. Smoke-test the wheel install per the §1.6 pattern (see `/tmp/sibling-import-test/` from earlier sessions).

Estimated effort: ½ day (the import rewrite is mechanical; the validation surface is non-trivial because every test/bench/example needs to compile).

## Why this doc exists rather than the actual reshuffle

Per the dispatch instruction "research + spike (defer execution)", the goal here is to record findings so the actual move is a one-shot mechanical PR rather than a discovery-during-execution affair. The risk of an in-progress 154-file reshuffle conflicting with the §3.2 / §3.3 oracle-vector work was high enough that landing it here would have churned three subagents' deliveries.

When the user wants the reshuffle: spin up a fresh subagent in a worktree with this doc as the brief.
