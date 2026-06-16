# §4.1 — mirror frozen-fork upstreams (REJECTED — YAGNI, 2026-05-13)

**Decision: do not implement.** The ongoing cost of maintaining 7 mirror repos and a sync workflow exceeds the expected cost of reactive remediation if an upstream disappears. Specifically:

- **Mirror cost is certain and continuous**: 7 GitHub repos to keep in sync, a weekly Action whose failures we have to triage, naming/transfer hygiene if we ever consolidate accounts.
- **Outage cost is uncertain and one-shot**: if e.g. `quictls/openssl` is deleted, the recovery options are (a) vendor a snapshot into navette once, (b) swap to mainline OpenSSL 3.5+ which now ships the QUIC API natively, or (c) point at any successor fork. Each is hours of work, not days, and only paid once.

The risk is real but tail-shaped; the maintenance is certain. YAGNI wins.

If a future upstream deletion forces our hand, the analysis and substitution script below still apply — point them at a freshly-created mirror at that time. There's no value in standing up the mirror infrastructure pre-emptively.

---

**Original analysis preserved below for reference.**

The v2 deps-enhancement plan §4.1 called for mirroring upstream repos that lack guaranteed availability so a bench / interop image build doesn't break the day they're deleted. This doc lists every upstream URL embedded in the repo, the proposed mirror strategy, and the substitution script.

## Upstreams to mirror

Verified by `grep -rnE 'quictls/openssl|Tencent/tquic|axboe/liburing|nghttp2/nghttp2|ngtcp2/nghttp3|ngtcp2/ngtcp2|http2jp/'` across Dockerfiles, scripts, and Cargo manifests.

| Upstream                              | Pin / branch                  | Used by                                                     | Risk           |
|---------------------------------------|-------------------------------|-------------------------------------------------------------|----------------|
| `quictls/openssl`                     | `openssl-3.1.4+quic`          | `bench/Dockerfile.h2load-h3` L54                            | **High** — fork effectively unmaintained, GitHub deletion would break the h2load HTTP/3 bench image. |
| `Tencent/tquic`                       | `4dcec0f2fcd6fd4a49366e2c759a169e4e81c48e` (v1.0.0) | `bench/quic_perf/Dockerfile.tquic` L38         | Medium — active repo today, but commit-pinned bench artifacts disappear if the repo is renamed/transferred. |
| `ngtcp2/nghttp3`                      | `v1.5.0`                      | `bench/Dockerfile.h2load-h3` L61                            | Low — actively maintained. Mirror is cheap insurance. |
| `ngtcp2/ngtcp2`                       | `v1.5.0`                      | `bench/Dockerfile.h2load-h3` L69                            | Low — same as above. |
| `nghttp2/nghttp2`                     | `v1.60.0`                     | `bench/Dockerfile.h2load-h3` L80                            | Low — actively maintained. |
| `http2jp/hpack-test-case`             | (latest)                      | `conformance/scripts/download_hpack_stories.py` L17         | Medium — corpus is small but irreplaceable test vectors. |
| `http2jp/http2-frame-test-case`       | (latest)                      | `conformance/scripts/convert_h2_vectors.py` L22             | Medium — same. |

Not in scope (already reproducible from package indexes): cargo crates (rustls, aws-lc-rs, etc.), Python packages (h2, hpack, etc.), Mojo siblings (boucle, jsonette — both publishable via mojox-build).

## Recommended approach

A single private GitHub org `Conobi-mirror` (or similar) holding read-only forks/mirrors of each upstream above. Replace `https://github.com/<upstream>` with `https://github.com/Conobi-mirror/<upstream>` in every Dockerfile and script.

**Why a GitHub org and not a different mirror service:**

- All upstream consumers in this repo use `git clone` over HTTPS; mirroring as plain GitHub repos minimises tooling changes (no S3 tarballs, no submodule indirection).
- GitHub's "mirror" mode (`git push --mirror`) keeps the mirror's refs in sync with upstream via a cron/Action.
- Resync stays under your account control.

**Why not `git submodule` for these:**

- Submodules pull at git-clone time, but these are needed at Docker build time (inside the image, post `git clone`). Each Dockerfile would need refactoring to consume submodule state — much more invasive than URL substitution.

## One-shot scripted substitution

When the mirror org exists, the URL swap is mechanical:

```bash
#!/usr/bin/env bash
# scripts/migrations/swap_to_mirrors.sh — run once after Conobi-mirror is set up.
set -euo pipefail
MIRROR_ORG="Conobi-mirror"   # change to your org name

declare -A SWAPS=(
    ["github.com/quictls/openssl"]="github.com/${MIRROR_ORG}/quictls-openssl"
    ["github.com/Tencent/tquic"]="github.com/${MIRROR_ORG}/Tencent-tquic"
    ["github.com/ngtcp2/nghttp3"]="github.com/${MIRROR_ORG}/ngtcp2-nghttp3"
    ["github.com/ngtcp2/ngtcp2"]="github.com/${MIRROR_ORG}/ngtcp2-ngtcp2"
    ["github.com/nghttp2/nghttp2"]="github.com/${MIRROR_ORG}/nghttp2-nghttp2"
    ["github.com/http2jp/hpack-test-case"]="github.com/${MIRROR_ORG}/http2jp-hpack-test-case"
    ["github.com/http2jp/http2-frame-test-case"]="github.com/${MIRROR_ORG}/http2jp-http2-frame-test-case"
)

# Mojo-net repo root, excluding vendored research artefacts.
GLOBS=(
    'bench/**/Dockerfile*'
    'interop/Dockerfile*'
    'conformance/scripts/*.py'
    'scripts/*.sh'
)

for src in "${!SWAPS[@]}"; do
    dst="${SWAPS[$src]}"
    for glob in "${GLOBS[@]}"; do
        for f in $(find . -path "./$glob" -not -path '*/.git/*' -not -path '*/.worktrees/*' 2>/dev/null); do
            if grep -q "$src" "$f"; then
                echo "  $f: $src → $dst"
                sed -i "s|$src|$dst|g" "$f"
            fi
        done
    done
done

# Audit: confirm no upstream URLs remain.
remaining=$(grep -rE 'github.com/(quictls|Tencent|ngtcp2|nghttp2|http2jp)' \
            bench/ conformance/ scripts/ interop/ 2>/dev/null \
            | grep -v "${MIRROR_ORG}" || true)
if [ -n "$remaining" ]; then
    echo "FAIL: upstream URLs still present:"
    echo "$remaining"
    exit 1
fi
echo "all upstream URLs swapped to ${MIRROR_ORG}"
```

This script is **not committed** yet because it depends on user-side decisions (org name, repo naming convention). Save the body to `scripts/migrations/swap_to_mirrors.sh` when ready.

## Prerequisites (user-owned)

1. Create GitHub org or use an existing one (e.g., `Conobi-mirror`).
2. For each upstream, create a mirrored repo. Easiest path:
   ```bash
   gh repo create Conobi-mirror/quictls-openssl --private --description "Mirror of github.com/quictls/openssl"
   git clone --mirror https://github.com/quictls/openssl
   cd openssl.git
   git remote set-url --push origin git@github.com:Conobi-mirror/quictls-openssl.git
   git push --mirror
   ```
3. Set up a GitHub Action (or cron) to `git fetch --tags` upstream and `git push --mirror` to the fork weekly. Optional but keeps the mirror current.
4. Run `scripts/migrations/swap_to_mirrors.sh`.
5. Rebuild affected Docker images to confirm the new URLs work.

## Acceptance

Done when:
- Every Dockerfile and script in the table above clones from `Conobi-mirror/*` rather than upstream.
- `bash scripts/check_integrations.sh` passes (it doesn't currently assert mirror state, but could be extended).
- A Docker bench rebuild succeeds end-to-end.
