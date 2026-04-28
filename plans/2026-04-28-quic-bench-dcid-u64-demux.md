# QUIC bench DCID demux Dict[UInt64,Int] migration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the bench-server's per-connection DCID demux table in `bench/h3_server.mojo` from `Dict[String, Int]` (16-char hex-string keyed) to `Dict[UInt64, Int]` (packed-u64 keyed) via a new `_dcid_to_u64` helper, eliminating per-packet hex-encode + String-hash overhead on the hot path.

**Architecture:** Bench-local change (no `src/`). New `_dcid_to_u64(Span[UInt8, _]) -> UInt64` 8-iter shift-pack helper. Type migration of `H3UdpHandler.conn_dcid_map` (`Dict[String, Int]` → `Dict[UInt64, Int]`) and `H3UdpHandler.conn_dcids` (`List[List[String]]` → `List[List[UInt64]]`). 5 call-site updates (hot-path lookup + cold-create insert + `_find_conn_by_dcid` signature + teardown remap). 8-byte SCID invariant locked upstream by `test_quic_connection_dcid_lengths_are_8_bytes`. Validation gate: sub-leg observed-drop on `loop_pop_dispatch.total` (≥8% on n=5+5 SIGINT sidecars, escalates to n=10+10), long-conn RPS non-regression on/off-build (≥−2.0% drift, n=10), `dcid_mismatch_pkts == 0` correctness check.

**Tech Stack:** Mojo 0.26.2; bench docker (`bench/Dockerfile`); `bench/quic_perf/scripts/{bench.sh,start-server.sh}` for capture; `src/quic/profile.mojo:16` `comptime PROFILE_ACCEPT` flag for instrumentation.

---

## File structure

| File | Status | Single responsibility |
|---|---|---|
| `bench/h3_server.mojo` | modify | Add `_dcid_to_u64` helper; type-migrate `conn_dcid_map` + `conn_dcids` fields; update 5 call sites (hot-path lookup, cold-create insert, `_find_conn_by_dcid` signature, teardown remap, retained-helper comment on `_bytes_to_hex`). |
| `tests/test_quic_connection.mojo` | modify | Add 2 new test functions (`test_dcid_to_u64_basic_cases`, `test_dcid_to_u64_injective_on_distinct_inputs`) + register both in `main()`. Existing `test_dcid_demux_disambiguates_two_conns` carries over unmodified (still imports `_bytes_to_hex` which is retained per spec D4). |
| `bench/quic_perf/results/REFERENCE.md` | modify | Append a new shipped-pass row at T5 with median `loop_pop_dispatch.total` deltas, RPS deltas, and verdict. |
| `bench/quic_perf/results/profile/Q3_pre_baselines_2026-04-28.md` | create | T0 evidence file: pre-migration off-build + on-build baselines (long-conn 10-iter median + short-conn 10-iter median + n=5 short-conn sidecar `loop_pop_dispatch.total` per-iter raw values). |
| `bench/quic_perf/results/profile/Q3_post_evidence_2026-04-28.md` | create | T3+T4 evidence file: post-migration captures + per-AC verdict + escalation log if needed. |
| `bench/quic_perf/results/profile/INSTRUMENTATION-<UTC ts>-q3-pre-shortconn-iter[1-5].json` | create (×5) | T0 SIGINT sidecars (pre-migration). |
| `bench/quic_perf/results/profile/INSTRUMENTATION-<UTC ts>-q3-post-shortconn-iter[1-5].json` | create (×5) | T4 SIGINT sidecars (post-migration). |
| `docs/project-context.md` | modify | T5: phase advance to `spec-quic-bench-dcid-u64-demux-reviewing`; spec status from `pending` to `done`; session-history entry. |

---

## Task list

### Task 0: Branch + pre-spec test count anchor + pre-migration baselines

**Tag:** parent
**Estimated time:** ~60 min (most of it bench-running time)

**Files:**
- Create: `bench/quic_perf/results/profile/Q3_pre_baselines_2026-04-28.md`
- Create: `bench/quic_perf/results/profile/INSTRUMENTATION-<UTC ts>-q3-pre-shortconn-iter[1-5].json` (×5)

- [ ] **Step 1: Commit any uncommitted project-context.md edits from the planning phase**

```bash
cd /home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main
git status -sb
# If docs/project-context.md is dirty, commit it:
git add docs/project-context.md research/2026-04-28-q3-RESEARCH-PLAN.md research/2026-04-28-q3-codebase-verification.md research/2026-04-28-q3-mojo-dict-internals.md research/2026-04-28-q3-reference-stacks-cid-keys.md research/2026-04-28-q3-bench-gate-design.md specs/2026-04-28-quic-bench-dcid-u64-demux.md
git commit -m "docs+specs+research: Q3 brainstorm → spec for Dict[UInt64,Int] DCID demux"
```

Expected: clean working tree after commit.

- [ ] **Step 2: Branch off main (current HEAD)**

```bash
MAIN_HEAD=$(git rev-parse main)
echo "Branching off main at: $MAIN_HEAD"
git checkout -b feat/quic-bench-dcid-u64-demux main
```

Expected: switched to new branch off main. Save `$MAIN_HEAD` for the retrospective.

- [ ] **Step 3: Pre-spec test count anchor**

```bash
TESTS_FILTER=test_quic_connection bash scripts/run_tests.sh 2>&1 | tee /tmp/q3_t0_pre_tests.log | tail -5
PRE_PASS=$(grep -c "^PASS:" /tmp/q3_t0_pre_tests.log || echo 0)
echo "Pre-spec PASS count (filtered to test_quic_connection): $PRE_PASS"
```

Expected: prints a non-zero PASS count and the line `All 30/30 src tests passed.` (or similar — current tree has 72/72 unfiltered; filtered to `test_quic_connection` should be ~30+ tests).

Record `$PRE_PASS` for the AC#1 delta verification at T1.

- [ ] **Step 4: Verify off-build flag is False (sanity)**

```bash
grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo
```

Expected output: `comptime PROFILE_ACCEPT: Bool = False`

If this prints `True`, abort and report — main is contaminated and the pre-baseline would be misleading.

- [ ] **Step 5: Build pre-migration off-build image**

```bash
bash bench/build.sh 2>&1 | tail -5
docker tag httparena-mojo-net mojo-net-bench:q3-pre-off
docker images | grep mojo-net-bench
```

Expected: `mojo-net-bench:q3-pre-off` listed.

- [ ] **Step 6: Capture pre-migration off-build baseline (long-conn + short-conn)**

```bash
# Ensure no other bench is running (CPU gate per feedback_bench_iter_count.md):
bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
# (script blocks until 5-min loadavg < 0.5; if not present, fall back to:)
#   while [ "$(awk '{print int($1*100)}' /proc/loadavg)" -gt 50 ]; do sleep 30; done

MOJO_NET_IMAGE=mojo-net-bench:q3-pre-off bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 10
MOJO_NET_IMAGE=mojo-net-bench:q3-pre-off bash bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 10
```

Expected: two `bench/quic_perf/results/<timestamp>-mojo-net-1k-{long,short}-conn-tquic_client-iter[1-10].json` directories.

Compute median + IQR + stdev:

```bash
python3 bench/quic_perf/scripts/summarize.py bench/quic_perf/results/<latest-long-dir> | tee /tmp/q3_pre_offbuild_long.txt
python3 bench/quic_perf/scripts/summarize.py bench/quic_perf/results/<latest-short-dir> | tee /tmp/q3_pre_offbuild_short.txt
```

Record medians for T3 AC#5 comparison.

- [ ] **Step 7: Flip PROFILE_ACCEPT to True (uncommitted edit) + build pre-migration on-build image**

```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = False/comptime PROFILE_ACCEPT: Bool = True/' src/quic/profile.mojo
grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo  # confirm = True
bash bench/build.sh 2>&1 | tee /tmp/q3_t0_build_on.log | tail -5
grep -E "Successfully built|^ERROR" /tmp/q3_t0_build_on.log
docker tag httparena-mojo-net mojo-net-bench:q3-pre-on
docker images | grep q3-pre-on
```

Expected: `Successfully built <sha>` line; `mojo-net-bench:q3-pre-on` listed.

- [ ] **Step 8: Capture pre-migration on-build long-conn 10-iter (Hard Gate 1 baseline)**

```bash
MOJO_NET_IMAGE=mojo-net-bench:q3-pre-on bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 10
python3 bench/quic_perf/scripts/summarize.py bench/quic_perf/results/<latest-long-dir> | tee /tmp/q3_pre_onbuild_long.txt
```

Record median for T3 AC#2.

- [ ] **Step 9: Capture pre-migration on-build short-conn n=5 SIGINT sidecars (Hard Gate 2 baseline)**

For each of 5 iters:
```bash
for i in 1 2 3 4 5; do
    bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
    MOJO_NET_IMAGE=mojo-net-bench:q3-pre-on bash bench/quic_perf/scripts/start-server.sh &
    SERVER_PID=$!
    bash bench/quic_perf/scripts/wait-ready.sh
    bash bench/quic_perf/scripts/run-tquic-client.sh 1k short-conn 30 &
    CLIENT_PID=$!
    wait $CLIENT_PID
    docker kill --signal=SIGINT bench-h3
    sleep 2
    docker cp bench-h3:/app/bench/quic_perf/results/profile/. bench/quic_perf/results/profile/
    bash bench/quic_perf/scripts/stop-server.sh
    # Rename the just-dropped sidecar:
    LATEST=$(ls -t bench/quic_perf/results/profile/INSTRUMENTATION-*.json | head -1)
    mv "$LATEST" "${LATEST%.json}-q3-pre-shortconn-iter${i}.json"
done
```

Expected: 5 files matching `bench/quic_perf/results/profile/INSTRUMENTATION-*-q3-pre-shortconn-iter[1-5].json`.

Extract `loop_pop_dispatch.total` per iter:
```bash
for f in bench/quic_perf/results/profile/INSTRUMENTATION-*-q3-pre-shortconn-iter[1-5].json; do
    python3 -c "import json,sys; d=json.load(open('$f')); print('${f}', d['loop_phases_us']['pop_dispatch']['total'])"
done | tee /tmp/q3_pre_pop_dispatch.txt
```

Record the 5 values + median for T4 AC#3.

- [ ] **Step 10: Revert the PROFILE_ACCEPT flag (must NOT be committed at T0)**

```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = True/comptime PROFILE_ACCEPT: Bool = False/' src/quic/profile.mojo
grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo  # confirm back to False
git status src/quic/profile.mojo  # should show clean (no diff)
```

Expected: `comptime PROFILE_ACCEPT: Bool = False` and `git status` shows the file unchanged from main.

- [ ] **Step 11: Write T0 evidence file**

Write `bench/quic_perf/results/profile/Q3_pre_baselines_2026-04-28.md` with:
- Branch + main `$MAIN_HEAD`
- Pre-spec test count anchor `$PRE_PASS`
- Off-build long-conn median + IQR + stdev (5 values from /tmp/q3_pre_offbuild_long.txt)
- Off-build short-conn median + IQR + stdev
- On-build long-conn median + IQR + stdev
- On-build short-conn `loop_pop_dispatch.total` per-iter (5 values) + median + stdev
- Image SHAs for `q3-pre-off` and `q3-pre-on` (`docker inspect mojo-net-bench:q3-pre-off --format '{{.Id}}'`)

- [ ] **Step 12: Commit T0 evidence**

```bash
git add bench/quic_perf/results/profile/Q3_pre_baselines_2026-04-28.md \
        bench/quic_perf/results/profile/INSTRUMENTATION-*-q3-pre-shortconn-iter*.json
```

Use the `commit-smart` skill. Message format: `bench: T0 pre-migration baselines (off+on build, 5x sidecars)`.

---

### Task 1: `_dcid_to_u64` helper + 2 unit tests (TDD)

**Tag:** subagent
**Estimated time:** ~15 min

**Files:**
- Modify: `bench/h3_server.mojo:164` (add helper)
- Modify: `tests/test_quic_connection.mojo` (add 2 test functions + register in `main()`)

- [ ] **Step 1: Write failing tests**

In `tests/test_quic_connection.mojo`, after the existing `test_dcid_demux_disambiguates_two_conns` function (around line 2905), add:

```mojo
def test_dcid_to_u64_basic_cases() raises:
    """Lock 5-case bijection of `_dcid_to_u64` 8-byte → UInt64 packing.

    Big-endian pack: result = (b[0]<<56) | (b[1]<<48) | ... | b[7].
    """
    from bench.h3_server import _dcid_to_u64

    # Case 1: All-zero bytes → 0.
    var z = List[UInt8]()
    for _ in range(8):
        z.append(UInt8(0))
    assert_equal_int(
        Int(_dcid_to_u64(Span(z))), 0, "all-zero -> 0"
    )

    # Case 2: All-0xff bytes → UInt64.MAX.
    var f = List[UInt8]()
    for _ in range(8):
        f.append(UInt8(0xFF))
    # UInt64.MAX = 0xFFFFFFFFFFFFFFFF; assert via signed-Int round-trip
    # avoids cross-rep equality issues.
    assert_true(
        _dcid_to_u64(Span(f)) == UInt64.MAX,
        "all-0xff -> UInt64.MAX",
    )

    # Case 3: Ascending [0x01..0x08] → 0x0102030405060708.
    var asc = List[UInt8]()
    for i in range(8):
        asc.append(UInt8(i + 1))
    assert_true(
        _dcid_to_u64(Span(asc)) == UInt64(0x0102030405060708),
        "ascending -> 0x0102030405060708",
    )

    # Case 4: Descending [0x08..0x01] → 0x0807060504030201.
    var desc = List[UInt8]()
    for i in range(8):
        desc.append(UInt8(8 - i))
    assert_true(
        _dcid_to_u64(Span(desc)) == UInt64(0x0807060504030201),
        "descending -> 0x0807060504030201",
    )

    # Case 5: Random 8-byte vector with a known reference value.
    # bytes = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
    # expected = 0xDEADBEEFCAFEBABE
    var r = List[UInt8]()
    r.append(UInt8(0xDE)); r.append(UInt8(0xAD))
    r.append(UInt8(0xBE)); r.append(UInt8(0xEF))
    r.append(UInt8(0xCA)); r.append(UInt8(0xFE))
    r.append(UInt8(0xBA)); r.append(UInt8(0xBE))
    assert_true(
        _dcid_to_u64(Span(r)) == UInt64(0xDEADBEEFCAFEBABE),
        "DEADBEEFCAFEBABE roundtrip",
    )

    print("PASS: test_dcid_to_u64_basic_cases")


def test_dcid_to_u64_injective_on_distinct_inputs() raises:
    """Sample 64 distinct 8-byte vectors; assert pairwise distinctness of
    `_dcid_to_u64` outputs. Trivially true for a bijection on 8-byte → UInt64;
    locked anyway as a regression guard.
    """
    from bench.h3_server import _dcid_to_u64

    var outputs = List[UInt64]()
    for n in range(64):
        # Construct 8 bytes from a deterministic LCG so inputs are distinct.
        var bytes = List[UInt8]()
        var seed = UInt32(n) * UInt32(2654435761) + UInt32(0xDEADBEEF)
        for _ in range(8):
            seed = seed * UInt32(1103515245) + UInt32(12345)
            bytes.append(UInt8((seed >> 16) & UInt32(0xFF)))
        outputs.append(_dcid_to_u64(Span(bytes)))

    # All-pairs distinctness.
    for i in range(len(outputs)):
        for j in range(i + 1, len(outputs)):
            assert_true(
                outputs[i] != outputs[j],
                "expected distinct outputs for distinct inputs",
            )

    print("PASS: test_dcid_to_u64_injective_on_distinct_inputs")
```

Then in `main()` (around line 2933), register both new tests:

```mojo
    test_dcid_demux_disambiguates_two_conns()
    test_dcid_to_u64_basic_cases()
    test_dcid_to_u64_injective_on_distinct_inputs()
```

- [ ] **Step 2: Verify they fail (helper not yet defined)**

```bash
TESTS_FILTER=test_quic_connection bash scripts/run_tests.sh 2>&1 | tail -20
```

Expected: FAIL — `error: cannot import '_dcid_to_u64' from 'bench.h3_server'` or similar import error in the test.

- [ ] **Step 3: Add the `_dcid_to_u64` helper**

In `bench/h3_server.mojo`, after the existing `_bytes_to_hex` function (around line 179, immediately after the closing of `_bytes_to_hex`'s body), add:

```mojo
fn _dcid_to_u64(bytes: Span[UInt8, _]) -> UInt64:
    """Pack 8 bytes (big-endian) into a UInt64 for use as a Dict[UInt64, Int]
    key. Replaces `_bytes_to_hex` on the bench's hot DCID-demux path.

    Precondition: `len(bytes) == 8` (locked by upstream
    `test_quic_connection_dcid_lengths_are_8_bytes` and by debug_assert at
    the conn-create site). When ASSERT mode is `none` (the bench's
    measurement-build configuration), the assert below is compiled out and
    the function is a pure 8-iter shift loop (~20 ns).
    """
    debug_assert(len(bytes) == 8, "DCID must be 8 bytes")
    var result: UInt64 = 0
    for i in range(8):
        result = (result << 8) | UInt64(bytes[i])
    return result
```

- [ ] **Step 4: Verify tests pass**

```bash
TESTS_FILTER=test_quic_connection bash scripts/run_tests.sh 2>&1 | tail -10
```

Expected: PASS — `PASS: test_dcid_to_u64_basic_cases` and `PASS: test_dcid_to_u64_injective_on_distinct_inputs` both printed; PASS count is `$PRE_PASS + 2`.

- [ ] **Step 5: Commit**

Use the `commit-smart` skill. Message format: `feat: add _dcid_to_u64 helper + unit tests`.

---

### Task 2: Field type migration + call-site updates

**Tag:** subagent
**Estimated time:** ~30 min

**Files:**
- Modify: `bench/h3_server.mojo`
  - Field declarations: line 466 (`conn_dcid_map`), line 473 (`conn_dcids`)
  - Constructor inits: lines 508, 511
  - Move ctor: lines 558, 561
  - `_find_conn_by_dcid`: lines 587–593
  - Hot-path lookup: lines 742–743
  - Cold-create: lines 813–850
  - Teardown remap: lines 1014–1039
  - `_bytes_to_hex` retention comment: line 164 (above the existing `fn _bytes_to_hex`)

This task is mechanical type substitution across 8 sites. Steps below are atomic edits; run the bench src-test gate after the full set lands.

- [ ] **Step 1: Update field declarations**

In `bench/h3_server.mojo`, line 466:
```mojo
# before:
#     var conn_dcid_map: Dict[String, Int]
# after:
    var conn_dcid_map: Dict[UInt64, Int]
```

Line 473 (the `conn_dcids` field):
```mojo
# before:
#     var conn_dcids: List[List[String]]
# after:
    var conn_dcids: List[List[UInt64]]
```

Also update the docstring comment at line 469 if it references "DCID-hex" — replace with "DCID-u64".

- [ ] **Step 2: Update constructor inits**

Line 508:
```mojo
# before: self.conn_dcid_map = Dict[String, Int]()
# after:
        self.conn_dcid_map = Dict[UInt64, Int]()
```

Line 511:
```mojo
# before: self.conn_dcids = List[List[String]]()
# after:
        self.conn_dcids = List[List[UInt64]]()
```

(Move ctor at lines 558/561 uses `^` move and does not name the type — no change needed there. Verify by reading; if the move-ctor lines DO name the type, update them similarly.)

- [ ] **Step 3: Update `_find_conn_by_dcid` signature**

Lines 587–593, replace:
```mojo
# before:
#     def _find_conn_by_dcid(self, dcid_hex: String) -> Int:
#         if dcid_hex in self.conn_dcid_map:
#             ...
#                 return self.conn_dcid_map[dcid_hex]
# after:
    def _find_conn_by_dcid(self, dcid_u64: UInt64) -> Int:
        if dcid_u64 in self.conn_dcid_map:
            try:
                return self.conn_dcid_map[dcid_u64]
            except:
                pass
        return -1
```

(Preserve whatever the existing body shape was — only the parameter type and name change. If the body deviates from the snippet above, retain the existing body.)

- [ ] **Step 4: Update hot-path lookup site**

Lines 742–743, replace:
```mojo
# before:
#     var dcid_hex = _bytes_to_hex(Span(pd.dcid))
#     var conn_idx = self._find_conn_by_dcid(dcid_hex)
# after:
            var dcid_u64 = _dcid_to_u64(Span(pd.dcid))
            var conn_idx = self._find_conn_by_dcid(dcid_u64)
```

- [ ] **Step 5: Update cold conn-create site**

Lines 813–850. The 8-byte invariant `debug_assert` at lines 813–814 is preserved unchanged. Replace the encoding + insert + per-conn-list block:

```mojo
# Lines 816-817 — replace:
#     var icid_hex = _bytes_to_hex(Span(quic.initial_dcid))
#     var lcid_hex = _bytes_to_hex(Span(quic.local_cid))
# with:
                var icid_u64 = _dcid_to_u64(Span(quic.initial_dcid))
                var lcid_u64 = _dcid_to_u64(Span(quic.local_cid))

# Lines 842-843 — replace `icid_hex` / `lcid_hex` with `icid_u64` / `lcid_u64`:
                self.conn_dcid_map[icid_u64] = conn_idx
                self.conn_dcid_map[lcid_u64] = conn_idx

# Lines 847-850 — replace `List[String]()` + `String` appends with `List[UInt64]()` + `UInt64` appends:
                var dcids = List[UInt64]()
                dcids.append(icid_u64)
                dcids.append(lcid_u64)
                self.conn_dcids.append(dcids^)
```

(Note: `icid_u64` / `lcid_u64` are `UInt64` (Copyable + Movable + AnyType-equivalent) — no `^` move needed on the appends.)

- [ ] **Step 6: Update teardown remap (lines 1014–1039)**

Replace the swap-and-pop block. The structure (loop, swap, remap, pops, no-increment + continue) is unchanged; ONLY the element-type-bearing identifiers change.

```mojo
                # Existing pre-swap free is unchanged:
                var ptr = self.conn_h3s[i]
                ptr.destroy_pointee()
                ptr.free()

                # B-permissive teardown: pop ALL of dying conn's DCID entries
                # (typically 2: initial_dcid + local_cid). The pre-migration
                # single-DCID single-pop with first-match-break is incorrect
                # for the dual-key shape.
                for dcid_u64 in self.conn_dcids[i]:
                    _ = self.conn_dcid_map.pop(dcid_u64)

                var last = len(self.conn_h3s) - 1
                if i != last:
                    # Swap the last element into position i in all parallel
                    # lists (conn_h3s, conn_addrs, conn_dcids).
                    self.conn_h3s[i] = self.conn_h3s[last]
                    self.conn_addrs[i] = List[UInt8](copy=self.conn_addrs[last])
                    self.conn_dcids[i] = List[UInt64](copy=self.conn_dcids[last])

                    # Remap ALL of the swapped-in conn's DCID entries from
                    # `last` → `i`. CRITICAL: do NOT break after first match
                    # (the survivor has 2 entries; both must be remapped).
                    for dcid_u64 in self.conn_dcids[i]:
                        self.conn_dcid_map[dcid_u64] = i

                _ = self.conn_h3s.pop()
                _ = self.conn_addrs.pop()
                _ = self.conn_dcids.pop()
                # Don't increment i — the swapped-in element needs checking.
                continue
```

The trailing `continue` + missing `i += 1` are load-bearing — preserve verbatim.

- [ ] **Step 7: Add retention comment to `_bytes_to_hex`**

At line 164 (immediately above the `fn _bytes_to_hex(...)` definition), add the retention comment so a future code-cleanup pass does not inadvertently delete this now-unused-by-default helper:

```mojo
# unused at hot-path post-2026-04-28-quic-bench-dcid-u64-demux; retained
# for ad-hoc debug rendering and for `tests/test_quic_connection.mojo`'s
# `test_dcid_demux_disambiguates_two_conns`. Do not delete without
# re-grepping across the repo.
fn _bytes_to_hex(bytes: Span[UInt8, _]) -> String:
    ...
```

- [ ] **Step 8: Verify build (Mojo MCP — fast feedback before src test gate)**

```bash
mcp__mojo-mcp__validate bench/h3_server.mojo
```

Expected: no syntax errors. (If `validate` flags issues, fix before continuing.)

- [ ] **Step 9: Verify src tests pass**

```bash
TESTS_FILTER=test_quic_connection bash scripts/run_tests.sh 2>&1 | tail -10
```

Expected: PASS count is `$PRE_PASS + 2` (the helper + 2 new tests; `test_dcid_demux_disambiguates_two_conns` continues to pass on the retained `_bytes_to_hex` per spec D4).

If `test_dcid_demux_disambiguates_two_conns` fails: investigate — it should not be affected (it imports `_bytes_to_hex` which is retained). If it does fail, the retention path is broken and needs the same fix as in Step 7.

- [ ] **Step 10: Verify full src test suite still green (regression guard)**

```bash
bash scripts/run_tests.sh 2>&1 | tail -3
```

Expected: `All N/N src tests passed.` where N = (pre-migration count) + 2.

- [ ] **Step 11: Commit**

Use the `commit-smart` skill. Message format: `refactor(bench): migrate DCID demux to Dict[UInt64,Int]`.

---

### Task 3: Hard Gate 1 (long-conn RPS non-regression on-build) + AC#5 (off-build sanity)

**Tag:** parent
**Estimated time:** ~30 min

**Files:** none modified; results captured to `bench/quic_perf/results/`.

- [ ] **Step 1: Build post-migration off-build image**

```bash
grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo  # confirm = False
bash bench/build.sh 2>&1 | tee /tmp/q3_t3_build_off.log | tail -5
grep -E "Successfully built|^ERROR" /tmp/q3_t3_build_off.log
docker tag httparena-mojo-net mojo-net-bench:q3-post-off
```

- [ ] **Step 2: Capture post-migration off-build long-conn 10-iter (AC#5)**

```bash
bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
MOJO_NET_IMAGE=mojo-net-bench:q3-post-off bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 10
python3 bench/quic_perf/scripts/summarize.py bench/quic_perf/results/<latest-long-dir> | tee /tmp/q3_post_offbuild_long.txt
```

Compute drift vs `/tmp/q3_pre_offbuild_long.txt` median.

Expected: drift ≥ −2.0% (AC#5 PASS).

If drift < −2.0%: investigate the type change for unexpected codegen overhead in the no-instrumentation build before proceeding.

- [ ] **Step 3: Capture post-migration off-build short-conn 10-iter (reporting only)**

```bash
bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
MOJO_NET_IMAGE=mojo-net-bench:q3-post-off bash bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 10
python3 bench/quic_perf/scripts/summarize.py bench/quic_perf/results/<latest-short-dir> | tee /tmp/q3_post_offbuild_short.txt
```

Soft Gate / Soft AC#5 short-conn — capture for the REFERENCE.md row at T5; not a pass/fail.

- [ ] **Step 4: Flip PROFILE_ACCEPT to True + build post-migration on-build image**

```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = False/comptime PROFILE_ACCEPT: Bool = True/' src/quic/profile.mojo
bash bench/build.sh 2>&1 | tee /tmp/q3_t3_build_on.log | tail -5
grep -E "Successfully built|^ERROR" /tmp/q3_t3_build_on.log
docker tag httparena-mojo-net mojo-net-bench:q3-post-on
```

- [ ] **Step 5: Capture post-migration on-build long-conn 10-iter (AC#2)**

```bash
bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
MOJO_NET_IMAGE=mojo-net-bench:q3-post-on bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 10
python3 bench/quic_perf/scripts/summarize.py bench/quic_perf/results/<latest-long-dir> | tee /tmp/q3_post_onbuild_long.txt
```

Compute drift vs `/tmp/q3_pre_onbuild_long.txt` median.

Expected: drift ≥ −2.0% (AC#2 / Hard Gate 1 PASS).

If FAIL: stop and investigate before T4. The migration intent does not predict any long-conn impact (long-conn `conn_dcid_map` has <10 entries; perpetually L1-hot pre-migration). A drift below −2.0% indicates an unexpected interaction and must be diagnosed.

- [ ] **Step 6: Revert the PROFILE_ACCEPT flag (uncommitted, will re-flip in T4 if needed)**

```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = True/comptime PROFILE_ACCEPT: Bool = False/' src/quic/profile.mojo
git status src/quic/profile.mojo  # should show clean
```

(If T4 needs to rebuild on-build image, re-flip then revert again.)

- [ ] **Step 7: No commit at this step.** T4 captures the sub-leg evidence and T5 commits the combined evidence + REFERENCE.md row.

---

### Task 4: Hard Gate 2 (sub-leg observed drop) + Hard Gate 3 (demux correctness)

**Tag:** parent
**Estimated time:** ~30 min (60 min if escalation triggers)

**Files:**
- Create: `bench/quic_perf/results/profile/INSTRUMENTATION-<UTC ts>-q3-post-shortconn-iter[1-5].json` (×5; or ×10 if escalation triggers).
- Create: `bench/quic_perf/results/profile/Q3_post_evidence_2026-04-28.md`

- [ ] **Step 1: Re-flip PROFILE_ACCEPT to True (uncommitted)**

The image `mojo-net-bench:q3-post-on` from T3 is still tagged and contains the on-build code. We just need the source flag flipped if Step 5 below decides to rebuild for any reason. For the standard path where the image is reused, the flag state in source does not matter. (Verify image exists before reuse.)

```bash
docker images | grep q3-post-on
```

If the image is missing, flip + rebuild + re-tag:
```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = False/comptime PROFILE_ACCEPT: Bool = True/' src/quic/profile.mojo
bash bench/build.sh
docker tag httparena-mojo-net mojo-net-bench:q3-post-on
sed -i 's/comptime PROFILE_ACCEPT: Bool = True/comptime PROFILE_ACCEPT: Bool = False/' src/quic/profile.mojo
```

- [ ] **Step 2: Capture n=5 post-migration short-conn SIGINT sidecars**

```bash
for i in 1 2 3 4 5; do
    bash ~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh
    MOJO_NET_IMAGE=mojo-net-bench:q3-post-on bash bench/quic_perf/scripts/start-server.sh &
    bash bench/quic_perf/scripts/wait-ready.sh
    bash bench/quic_perf/scripts/run-tquic-client.sh 1k short-conn 30 &
    CLIENT_PID=$!
    wait $CLIENT_PID
    docker kill --signal=SIGINT bench-h3
    sleep 2
    docker cp bench-h3:/app/bench/quic_perf/results/profile/. bench/quic_perf/results/profile/
    bash bench/quic_perf/scripts/stop-server.sh
    LATEST=$(ls -t bench/quic_perf/results/profile/INSTRUMENTATION-*.json | head -1)
    mv "$LATEST" "${LATEST%.json}-q3-post-shortconn-iter${i}.json"
done
```

Expected: 5 files matching `bench/quic_perf/results/profile/INSTRUMENTATION-*-q3-post-shortconn-iter[1-5].json`.

- [ ] **Step 3: Compute median + stdev for both pre and post `loop_pop_dispatch.total`**

```bash
PRE_VALS=$(for f in bench/quic_perf/results/profile/INSTRUMENTATION-*-q3-pre-shortconn-iter[1-5].json; do
    python3 -c "import json; print(json.load(open('$f'))['loop_phases_us']['pop_dispatch']['total'])"
done | tr '\n' ',')
POST_VALS=$(for f in bench/quic_perf/results/profile/INSTRUMENTATION-*-q3-post-shortconn-iter[1-5].json; do
    python3 -c "import json; print(json.load(open('$f'))['loop_phases_us']['pop_dispatch']['total'])"
done | tr '\n' ',')

python3 - <<EOF
import statistics
pre = [int(x) for x in "$PRE_VALS".rstrip(',').split(',')]
post = [int(x) for x in "$POST_VALS".rstrip(',').split(',')]
mp = statistics.median(pre)
mq = statistics.median(post)
sp = statistics.stdev(pre)
sq = statistics.stdev(post)
drop = (mp - mq) / mp * 100
print(f"pre  median={mp}  stdev={sp:.0f}  ({sp/mp*100:.2f}%)")
print(f"post median={mq}  stdev={sq:.0f}  ({sq/mq*100:.2f}%)")
print(f"drop = {drop:.2f}%")
EOF
```

Expected: drop ≥ 8% (Hard Gate 2 / AC#3 PASS).

- [ ] **Step 4: Apply decision rule from spec §7 Hard Gate 2**

Decision rule (precedence — applied in order):
1. If treatment stdev > 5% of median OR drop ∈ [6%, 10%], escalate to n=10+10:
   - Repeat Step 2 with iters 6–10 for both pre (re-using `mojo-net-bench:q3-pre-on`) and post (`mojo-net-bench:q3-post-on`); rename outputs to `iter[6-10]`.
   - Recompute medians + stdevs at n=10+10; re-apply ≥8% gate.
2. Otherwise n=5+5 medians decide pass/fail directly.

Record the decision path explicitly in the evidence file (Step 7 below).

- [ ] **Step 5: Verify Hard Gate 3 (`dcid_mismatch_pkts == 0` in all sidecars)**

```bash
for f in bench/quic_perf/results/profile/INSTRUMENTATION-*-q3-{pre,post}-shortconn-iter*.json; do
    DM=$(python3 -c "import json; print(json.load(open('$f')).get('addr_key_dcid_mismatch', {}).get('dcid_mismatch_pkts', 'MISSING'))")
    echo "$f: dcid_mismatch_pkts=$DM"
done
```

Expected: every file shows `dcid_mismatch_pkts=0` (AC#4 PASS).

If any file shows non-zero: STOP. Demux is broken. Investigate the type change at the lookup or insert sites for missed remap.

- [ ] **Step 6: Open-question optional sanity — AHash distribution check**

(Only if treatment Step 4 passes; if it fails, the AHash check is moot.)

Sample N=100 distinct DCIDs from the post sidecar(s) and check Dict load factor. The just-shipped sub-leg sidecar should record per-conn DCID samples in `per_conn_pkt_counts` or similar; if not, dump from a docker-exec'd debug build instead.

```bash
python3 - <<'EOF'
import json, os
keys = set()
for f in sorted([x for x in os.listdir("bench/quic_perf/results/profile/")
                 if "q3-post-shortconn" in x and x.endswith(".json")])[:1]:
    d = json.load(open(f"bench/quic_perf/results/profile/{f}"))
    # per_conn_pkt_counts is a Dict[String, UInt64] — keys are addr_keys not DCIDs
    # but we can grep the underlying server logs in /tmp/h3-bench-stderr.log if a
    # debug DCID dump was instrumented. For Q3 this check is OPTIONAL — the goal
    # is just to confirm 36k entries don't cluster.
    print("conn_count_post (addr_key keys):", len(d.get("per_conn_pkt_counts", {})))
EOF
```

Document either "Sanity-check skipped — DCIDs are random by construction" or "Sanity-check confirms expected distribution." in the evidence file.

- [ ] **Step 7: Write T4 evidence file**

Write `bench/quic_perf/results/profile/Q3_post_evidence_2026-04-28.md` with:
- Image SHAs for `q3-post-off` and `q3-post-on`.
- AC#2 result: pre on-build median, post on-build median, drift %, PASS/FAIL.
- AC#3 result: pre/post `loop_pop_dispatch.total` medians, stdevs, drop %, decision-rule outcome (n=5+5 OR escalated to n=10+10), PASS/FAIL.
- AC#4 result: `dcid_mismatch_pkts` for all 10–20 sidecars, PASS/FAIL.
- AC#5 result: pre/post off-build long-conn medians, drift %, PASS/FAIL.
- Soft gate: pre/post short-conn RPS medians + delta (informational).
- AHash sanity check outcome.

- [ ] **Step 8: Revert PROFILE_ACCEPT to False (one last time)**

```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = True/comptime PROFILE_ACCEPT: Bool = False/' src/quic/profile.mojo
grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo  # confirm = False
git status src/quic/profile.mojo  # should show clean
```

- [ ] **Step 9: Commit T4 evidence**

```bash
git add bench/quic_perf/results/profile/INSTRUMENTATION-*-q3-post-shortconn-iter*.json \
        bench/quic_perf/results/profile/Q3_post_evidence_2026-04-28.md
```

Use the `commit-smart` skill. Message format: `bench: T4 post-migration sub-leg evidence + AC verdicts`.

---

### Task 5: REFERENCE.md row + flag revert verification + project-context advance

**Tag:** parent
**Estimated time:** ~15 min

**Files:**
- Modify: `bench/quic_perf/results/REFERENCE.md`
- Modify: `docs/project-context.md`

- [ ] **Step 1: Verify flag revert (AC#7)**

```bash
grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo
```

Expected: `comptime PROFILE_ACCEPT: Bool = False`.

- [ ] **Step 2: Append REFERENCE.md row (AC#6)**

In `bench/quic_perf/results/REFERENCE.md`, append a new row at the bottom (consult the previous "shipped" row in the sub-leg pass for layout — the row should include columns the existing schema defines: branch / verdict / `loop_pop_dispatch.total` pre-median / post-median / drop% / long-conn RPS pre/post/drift / short-conn RPS pre/post/drift / AC#1-#7 PASS|FAIL summary).

The exact layout to copy is the row that ends in `subleg-pass` from the previous spec; replace its values with Q3 numbers from `Q3_post_evidence_2026-04-28.md`.

- [ ] **Step 3: Update `docs/project-context.md`**

Phase: `spec-quic-bench-dcid-u64-demux-planning` → `spec-quic-bench-dcid-u64-demux-reviewing`.

Active-specs row for this spec: status `pending` → `done`; notes append `**SHIPPED.** loop_pop_dispatch.total drop = X.X%; long-conn drift = +/-X.X%; short-conn RPS delta = +/-X.X%. AC#1-#7 all PASS. <Branch SHA range>.`

Session-history entry (top-of-list per convention):
```
- 2026-04-28 — `~/.claude/projects/-home-donokami-Projets-perso-mojo-net/<session>.jsonl` (continued) — **Q3 plan executed via subagent-driven-development on branch `feat/quic-bench-dcid-u64-demux` off main `<MAIN_HEAD>`.** All 6 plan tasks (T0-T5) complete; <N> commits. T0 captured pre-migration off-build + on-build baselines. T1 added `_dcid_to_u64` helper + 2 unit tests (TDD). T2 migrated `Dict[String,Int]→Dict[UInt64,Int]` across 8 sites in `bench/h3_server.mojo`. T3 captured post-migration on/off-build long-conn 10-iter — AC#2/#5 verdict <PASS/FAIL>. T4 captured n=5+5 short-conn SIGINT sidecars — AC#3 `loop_pop_dispatch.total` drop = X.X% (decision rule: <n=5+5 direct | escalated to n=10+10>); AC#4 `dcid_mismatch_pkts == 0` in all sidecars. T5 REFERENCE.md row appended; flag revert verified. Final phase: spec-quic-bench-dcid-u64-demux-reviewing. Ready for finishing-a-development-branch.
```

- [ ] **Step 4: Commit T5**

```bash
git add bench/quic_perf/results/REFERENCE.md docs/project-context.md
```

Use the `commit-smart` skill. Message format: `docs: T5 REFERENCE.md entry + project-context advance`.

- [ ] **Step 5: Final cross-cutting review**

Per subagent-driven-development skill: dispatch a final combined reviewer covering all commits since the plan started (full BASE..HEAD range from `$MAIN_HEAD` to T5 commit).

If the reviewer returns ✅ CLEAN, the plan is done — invoke `atelier:finishing-a-development-branch`.

If ISSUES: fix per the reviewer's findings, re-run the reviewer, repeat until ✅ CLEAN.

---

## Pre-save scan

- [x] **Spec coverage** — every spec acceptance criterion (AC#1–#7) maps to a step:
  - AC#1 (test count delta) → T1 Step 4 + T1 Step 5
  - AC#2 (Hard Gate 1, on-build long-conn drift ≥ −2.0%) → T3 Step 5
  - AC#3 (Hard Gate 2, sub-leg ≥8% drop) → T4 Step 4
  - AC#4 (Hard Gate 3, `dcid_mismatch_pkts == 0`) → T4 Step 5
  - AC#5 (off-build long-conn drift ≥ −2.0%) → T3 Step 2
  - AC#6 (REFERENCE.md row) → T5 Step 2
  - AC#7 (flag revert) → T5 Step 1
- [x] **No forbidden placeholders** — every step has complete code or exact commands.
- [x] **Names + signatures consistent across tasks** — `_dcid_to_u64`, `dcid_u64`, `icid_u64`, `lcid_u64`, `Dict[UInt64, Int]`, `List[List[UInt64]]` used uniformly.
- [x] **Test count locked at +2** across §6 (spec) and T1 Steps 1+5 (this plan).
- [x] **8-byte invariant precondition** — surfaced at T1 docstring + retained at T2 cold-create `debug_assert`s + locked upstream by `test_quic_connection_dcid_lengths_are_8_bytes`.
- [x] **Image hygiene** — every bench step uses tag-isolated `mojo-net-bench:q3-{pre,post}-{off,on}` images per `feedback_bench_offbuild_image_hygiene.md`.
- [x] **CPU gate** — every bench step gates on `~/.claude/projects/-home-donokami-Projets-perso-mojo-net/cpu_gate.sh` per `feedback_bench_iter_count.md`.
- [x] **Decision rule** — T4 Step 4 reproduces the spec's precedence-ordered decision rule verbatim.

---

## Branch precondition

- New branch `feat/quic-bench-dcid-u64-demux` off `main` (HEAD captured at T0 Step 2).
- Pre-spec PASS count anchor captured at T0 Step 3.
- `comptime PROFILE_ACCEPT: Bool = False` in `src/quic/profile.mojo` at T0 Step 4 (verified) and at T5 Step 1 (verified one final time).
