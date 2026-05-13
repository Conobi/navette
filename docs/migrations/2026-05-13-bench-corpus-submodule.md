# §4.2 — move `.research/tquic/` + `bench/.httparena/` to a corpus submodule

**Status:** scripted ops drafted; submodule repo creation is user-owned. 2026-05-13.

The v2 deps-enhancement plan §4.2 called for moving bench/research corpora out of the main repo into a sibling `mojo-net-bench-corpus` submodule, so a default clone stays lean and the corpora are only fetched when running bench sweeps.

This doc lists what to move, the rationale, and the one-shot git operations.

## What's in scope

Verified by `du -sh` on 2026-05-13:

| Path                     | Size  | Purpose                                                          |
|--------------------------|-------|------------------------------------------------------------------|
| `.research/tquic/`       | 4.0 MB  | TQUIC vendored source for perf comparison; not linked into mojo-net runtime. |
| `bench/.httparena/`      | 245 MB  | httparena vendor: ~50 framework Dockerfiles + wrk/ghz/gcannon helper scripts. Comparison sweep only. |

Together: **~249 MB** added to every `git clone`. Neither path is consumed by `cargo build`, `uv sync`, `mojo build`, or `scripts/check_integrations.sh`.

## Why submodule, not subtree or branch

- **Submodule**: clone is opt-in via `git submodule update --init bench/corpus`. Default clone stays lean. Refs survive in their own history. ✓
- **Subtree**: keeps everything in the main repo; defeats the goal.
- **Separate branch**: `.git`-history-isolated but adds friction (developer needs to know to checkout a different branch for bench work).

Submodule wins.

## One-shot scripted move

When the corpus repo exists (e.g., `github.com/Conobi/mojo-net-bench-corpus`):

```bash
#!/usr/bin/env bash
# scripts/migrations/move_bench_corpus_to_submodule.sh — run ONCE on a clean working tree.
set -euo pipefail
CORPUS_REPO="${1:-git@github.com:Conobi/mojo-net-bench-corpus.git}"

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Sanity: clean tree.
if [ -n "$(git status --porcelain)" ]; then
    echo "working tree dirty; commit or stash first" >&2
    exit 1
fi

# 1) Stage 1 commit: move existing dirs to corpus/ subdir locally
#    (this is the dir layout the submodule repo will mirror).
mkdir -p _corpus_staging
git mv .research/tquic _corpus_staging/tquic
git mv bench/.httparena _corpus_staging/httparena
git commit -m "chore(bench): stage tquic + httparena for corpus extraction"

# 2) Use git-filter-repo to extract a new repo with only these paths.
#    git-filter-repo is faster than filter-branch and recommended by git docs.
#    If unavailable: `pip install --user git-filter-repo`.
git clone . /tmp/mojo-net-corpus-staging
cd /tmp/mojo-net-corpus-staging
git filter-repo --path _corpus_staging --path-rename _corpus_staging/:
# Result: a new repo whose contents are tquic/ + httparena/ at the root.
# History preserved for those paths only.

# 3) Push to the new GitHub repo.
git remote add origin "$CORPUS_REPO"
git push -u origin main

# 4) Back in mojo-net main repo: delete the staging dir, add submodule.
cd "$REPO_ROOT"
git rm -r _corpus_staging
git commit -m "chore(bench): remove staged corpus (will be re-added as submodule)"
git submodule add "$CORPUS_REPO" bench/corpus
git commit -m "chore(bench): add bench/corpus submodule (formerly .research/tquic + bench/.httparena)"
```

## Path updates after the move

Anything referencing `.research/tquic` or `bench/.httparena` needs its path updated to `bench/corpus/tquic` or `bench/corpus/httparena` respectively. Grep the tree:

```bash
grep -rln -E '\.research/tquic|bench/\.httparena' \
     bench/ scripts/ conformance/ docs/ \
     --exclude-dir=.git --exclude-dir=.worktrees
```

Substitute via sed.

## `.gitignore` updates

After the move, ensure `.gitignore` does not exclude `bench/corpus` (submodules are explicit — git tracks the gitlink even without removing matching patterns, but stay tidy).

## Acceptance

Done when:
- `bench/corpus/tquic` and `bench/corpus/httparena` are submodules.
- `git clone` of mojo-net no longer pulls 249 MB by default.
- `git submodule update --init bench/corpus` pulls the corpus.
- All affected bench scripts/Dockerfiles updated to new paths.
- A bench sweep still runs end-to-end.

## Prerequisites (user-owned)

1. Create `mojo-net-bench-corpus` repo on GitHub.
2. Run the migration script above.
3. Update README / CONTRIBUTING (if any) to note the `--recurse-submodules` clone flag for users running benches.

## Risk

This is a destructive history rewrite for the corpus paths. Anyone with an in-flight branch touching `.research/tquic/` or `bench/.httparena/` would have their work invalidated. Coordinate timing.

## Why deferred

User-side infra (the new GitHub repo) needs to exist before the migration runs. The script is ready to invoke once `mojo-net-bench-corpus` is created.
