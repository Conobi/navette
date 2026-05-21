# Known fuzz-harness divergences (deferred triage)

Each entry is a documented disagreement between the production parser and the
oracle that has been triaged but not yet root-caused — usually because the
oracle is a simpler/stricter reference implementation that diverges from
production on an under-specified RFC point or on an edge case where both
implementations are defensible.

The fuzz harness skips these patterns (matched by oracle error-message prefix)
so the harness can continue running and catch *new* disagreements.

## fuzz_hpack

### "invalid name index 62" (oracle) vs production accept

**Observed:** at FUZZ_SEED=0xC0FFEE, ~2 occurrences per 5000 iters of random byte input.

**Hypothesis:** the divergence centres on the timing of dynamic-table insertion
across a literal-with-indexing followed by an indexed-reference to the
just-added entry, OR on a max-table-size-update boundary case. Both stacks
implement the RFC 7541 §6.2.1 semantic ("add to dynamic table, then return the
indexed value") but production's insertion path may evict differently when the
new entry plus existing entries cross the max-size boundary mid-decode.

**Triage status:** open. Pending offline reproduction via the saved-disagreement
corpus file (next session). The production behaviour appears correct on a
first read of `navette/h2/hpack.mojo`; the oracle is the more likely suspect.

**Skip-by-prefix:** `"invalid name index 62"`.

## fuzz_h1_parser

No known divergences as of seed=0xC0FFEE, iters=5000.

## fuzz_varint

No known divergences as of seed=0xC0FFEE, iters=5000.

## (Other harnesses)

To be populated as they land.

## Triage workflow

1. When a harness reports a disagreement, the harness has (or should have) saved
   the input bytes to `conformance/fuzz/corpus/<harness>/<seed>-<hash>.bin`.
2. Open the `.txt` sidecar to read both observations.
3. Decide whether the production stack is wrong (file a regression test + fix
   in `navette/`), the oracle is wrong (fix in `conformance/lib/`), or the RFC
   is ambiguous (extend this file's entry with the spec citation, leave both
   stacks as-is).
4. Once triaged, remove the skip-by-prefix entry and re-run the harness to
   confirm the fix.
