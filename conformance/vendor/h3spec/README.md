# Pinned h3spec checksum

Source: https://github.com/kazu-yamamoto/h3spec/releases/tag/v0.1.0
Linux x86_64 prebuilt.

The binary itself is NOT committed. `conformance/scripts/run_h3spec.sh`
downloads it on first use from the release URL above, caches it at
`conformance/vendor/h3spec/h3spec` (gitignored), and verifies it against
`SHA256SUMS` here on every invocation.

To refresh the pin (new upstream release):
1. Download the new release asset somewhere temporary.
2. Run `sha256sum <asset> > SHA256SUMS` (in this directory).
3. Bump `VERSION` to the new tag.
4. Update `RELEASE_URL` in `conformance/scripts/run_h3spec.sh` if the
   asset name changed.
5. Re-run `conformance/scripts/run_h3spec.sh` against the current
   `examples/hello_h3_server` to confirm the new pin's pass count
   matches expectations; if not, `conformance/h3spec_min_pass.txt`
   may need adjustment.
