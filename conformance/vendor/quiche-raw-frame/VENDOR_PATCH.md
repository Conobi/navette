# Vendor Patch — quiche 0.24.9 (raw-frame conformance)

upstream-commit:   bbfe6205b8af2e6fadbb6d7818de463fbe123342 (cloudflare/quiche@0.24.9)
fork-branch:       https://github.com/Conobi/quiche/tree/navette-patches-0.24
fork-branch-tip:   6d15774b (post-Patch-4)
vendor-target:     conformance/vendor/quiche-raw-frame/

The fork-branch is the canonical source of truth for the patches: each commit
on `navette-patches-0.24` corresponds to one of the patches below, in order.
When adding a fifth patch, commit it to the fork branch FIRST (and open an
upstream PR for the change if appropriate per the hard-cap policy), then
re-sync the vendored tree below from that branch.

This vendored quiche tree carries four changes from upstream needed for the
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

In `src/test_utils.rs`, immediately after `encode_pkt`, add a helper that wraps
`encode_pkt` and XORs the cleartext first-byte reserved bits BEFORE HP. Used
by scenario binaries F12 (long-header reserved-bits = 0x0c) and F14
(short-header reserved-bit = 0x18 per RFC 9000 §17.3.1).

### Implementation note — XOR commutativity

Header protection (RFC 9001 §5.4) applies a per-packet XOR mask to the first
header byte: `wire[0] = cleartext[0] ^ (hp_mask[0] & protection_bits)`. Since
XOR is self-inverse and commutative, flipping reserved bits in the cleartext is
equivalent to flipping them in the HP-protected wire byte:

  `wire'[0] = wire[0] ^ reserved_mask`

The receiver un-applies HP and recovers `cleartext[0] ^ reserved_mask` — the
exact modified reserved-bits value navette's QUIC parser validates (RFC 9000
§17.2 for long headers, §17.3.1 for short headers). This means the
implementation is a single `buf[0] ^= reserved_mask` after calling `encode_pkt`,
with no need to re-derive the HP mask. The function body is 3 effective lines.

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
