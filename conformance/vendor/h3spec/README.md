# Pinned h3spec checksum (legacy probe)

Source: https://github.com/kazu-yamamoto/h3spec/releases/tag/v0.1.0
Linux x86_64 prebuilt.

> **NOTE:** h3spec is no longer the active conformance gate. The
> active gate is `conformance/scripts/run_h3i.sh` (driven by
> `conformance/h3i_min_pass.txt`). h3spec is kept here as a
> diagnostic probe: its Haskell QUIC client cannot complete a
> handshake with navette's rustls server, so it produces no
> per-test signal in its current form. Re-pin and try a fresh
> release if you want to verify whether the interop bug has been
> fixed upstream.

The binary itself is NOT committed. `conformance/scripts/run_h3spec.sh`
downloads it on first use from the release URL above, caches it at
`conformance/vendor/h3spec/h3spec` (gitignored), and verifies it
against `SHA256SUMS` here on every invocation. The script is no
longer wired into `conformance/scripts/run_tests.sh`; invoke it
directly if you want to probe.

To refresh the pin (new upstream release):
1. Download the new release asset somewhere temporary.
2. Run `sha256sum <asset> > SHA256SUMS` (in this directory).
3. Bump `VERSION` to the new tag.
4. Update `RELEASE_URL` in `conformance/scripts/run_h3spec.sh` if
   the asset name changed.
5. Invoke `conformance/scripts/run_h3spec.sh` directly against the
   current `examples/hello_h3_server` and check whether any tests
   pass. If h3spec now handshakes cleanly (a non-zero pass count
   with no early `MissingQuicTransportParameters` in the server
   stderr), the interop bug is fixed upstream and the gate could
   be re-wired by restoring the `H3SPEC=1` block in
   `conformance/scripts/run_tests.sh`.
