# Vendor Patch — quiche 0.24.9 (raw-frame conformance)

upstream-commit:   bbfe6205b8af2e6fadbb6d7818de463fbe123342 (cloudflare/quiche@0.24.9)
fork-branch:       https://github.com/Conobi/quiche/tree/navette-patches-0.24
fork-branch-tip:   ee0bf250 (Patches 1-5; the Patch 3 fix is its own commit, after Patch 4)
vendor-target:     conformance/vendor/quiche-raw-frame/

The fork-branch is the canonical source of truth for the patches: each commit
on `navette-patches-0.24` corresponds to one of the patches below, in order.
When adding a fifth patch, commit it to the fork branch FIRST (and open an
upstream PR for the change if appropriate per the hard-cap policy), then
re-sync the vendored tree below from that branch.

This vendored quiche tree carries five changes from upstream needed for the
raw-frame conformance harness. The harness needs to inject hand-crafted QUIC
frames at the wire level — quiche's public API does not expose this. The
following patches expose the required internals.

## Patch 1 — Expose `quiche::frame::Frame`

In `src/lib.rs`:

  -mod frame;
  +pub mod frame;

This lets the harness construct `Frame::*` variants by name (ResetStream,
StopSending, MaxStreamData, ...) and pass them to `test_utils::encode_pkt`.

## Patch 2 — Expose `quiche::range_buf`

In `src/lib.rs`:

  -mod range_buf;
  +pub mod range_buf;

`Frame::Stream { data: RangeBuf }` requires `RangeBuf` to be constructible from
the harness side; `RangeBuf::from(&[u8], offset, fin)` is the relevant
constructor.

## Patch 3 — `encode_pkt_reserved_bits` helper

In `src/test_utils.rs`, immediately after `encode_pkt`, add a helper that
mirrors `encode_pkt` but sets the reserved bits of the cleartext first header
byte before the packet is sealed. Used by scenario binaries F12 (long-header
reserved bits, mask 0x0c) and F14 (short-header reserved bits, mask 0x18, per
RFC 9000 Section 17.3.1).

### Implementation note — set the bits before sealing

The first header byte is part of the AEAD's associated data (RFC 9001
Section 5.3). The helper therefore writes the header, ORs `reserved_mask` into
the first byte, then encrypts and applies header protection as `encode_pkt`
does. Flipping the bits in the wire byte after sealing does reach the receiver
in cleartext, since header protection is a plain XOR, but the packet then
fails authentication and is dropped before the bits are ever checked. The
first version of this patch did that, and F12/F14 only passed while navette
checked reserved bits before authentication.

## Patch 4 — `encode_pkt_with_payload` helper

In `src/test_utils.rs`, immediately after `encode_pkt_reserved_bits`, add a
helper that mirrors `encode_pkt` but takes the QUIC payload as a raw byte
slice. The harness needs this for scenario F10
(`s_f10_unknown_frame`) — an unknown frame type byte (e.g. `0xFE`) has no
matching `frame::Frame` variant, so the standard `encode_pkt` path cannot
inject it. The helper uses the same packet-number / header-construction /
AEAD / header-protection routines as `encode_pkt`; only the payload-writing
step differs (`b.put_bytes(payload)` instead of `frame.to_bytes(&mut b)`).

The function body is ~40 lines. Wire-level behaviour is identical to
`encode_pkt` for the subset of frames expressible via `Frame`; the helper
is strictly additive — it does not alter `encode_pkt`.

## Patch 5 — `Connection::has_application_crypto_seal` accessor

In `src/lib.rs`, on the public `impl<F: BufFactory> Connection<F>` block,
add a cfg-gated read-only accessor that returns whether the Application
(1-RTT) `crypto_seal` slot is populated:

  ```rust
  #[cfg(any(test, feature = "raw-frame-fixtures"))]
  #[inline]
  pub fn has_application_crypto_seal(&self) -> bool {
      self.crypto_ctx[packet::Epoch::Application]
          .crypto_seal
          .is_some()
  }
  ```

A new feature `raw-frame-fixtures` is declared in `Cargo.toml` (and the
sibling `Cargo.toml.orig`) to gate the accessor. The scenarios crate
enables this feature unconditionally; downstream consumers of the
vendored crate do not pick it up.

The 0-RTT scenario harness (`s_f30_zero_rtt_crypto`) needs this signal
to detect when quiche has derived the early-data keys after
`set_session()`, which is the precondition for invoking
`test_utils::encode_pkt(Type::ZeroRTT, ...)`. quiche's public surface
exposes `is_in_early_data()` only after the *client* writes its first
0-RTT byte; the harness drives the keys-only handshake without writing
any 0-RTT application data, so it needs a key-state predicate that does
not depend on the Boring SSL early-data writer state.

The accessor is read-only and borrows `&self`; no mutation, no panic
paths, no AEAD material exposed.
