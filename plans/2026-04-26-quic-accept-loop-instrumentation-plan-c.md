# QUIC Accept-Loop Instrumentation — Plan C Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-capture profile data under cold-start saturating-handshake load to fix Plan B's mistake (B14 captured steady-state long-conn — only 5 handshakes — instead of the saturating-handshake regime that produced the calibrated 412/1 rps + 99% timeout floor).

**Architecture:** Operational data-collection pass. NO code changes — uses Plan B's instrumentation as-is on branch `feat/quic-accept-loop-instrumentation`. C1 is a hard gate: verify the calibrated baseline reproduces off-build before spending time on profile-build captures. If yes, capture two on-build sidecars (`short-conn` and `long-conn --max-concurrent-conns 100`), apply spec's ≥2× signal table for dominant-cost identification, append REFERENCE.md hypothesis-pass log entry.

**Tech Stack:** Bash + Docker + bench harness (`start-server.sh`, `run-tquic-client.sh`, `stop-server.sh`) + manual SIGINT + `docker cp` + `python3 -m json.tool`.

**Branch:** `feat/quic-accept-loop-instrumentation` at HEAD `58a1729` (Plan B + user's h2 follow-on; instrumentation already in place).

---

## Spec coverage

This plan covers `specs/2026-04-25-quic-accept-loop-instrumentation.md` §Validation deliverable 3 (full bench-mvp matrix → adapted to two single-cell saturating-handshake captures per user choice in B14 streamline) AND the required-later trigger documented in Plan B's retrospective (`plans/2026-04-26-quic-accept-loop-instrumentation-plan-b-retrospective.md` §Open questions, "Re-capture under saturating-handshake load").

**No deviations from spec; no code changes.** Pure operational follow-through.

---

## File structure

| File | Op | Responsibility |
|---|---|---|
| `src/quic/profile.mojo:15` | Modify (twice — flip then restore) | Toggle `comptime PROFILE_ACCEPT` for on-build capture; restore to False at end |
| `bench/quic_perf/results/profile/INSTRUMENTATION-<utc>-short-conn.json` | Create (via SIGINT capture) | C3 sidecar artifact |
| `bench/quic_perf/results/profile/INSTRUMENTATION-<utc>-long-conn-c100.json` | Create (via SIGINT capture) | C4 sidecar artifact |
| `bench/quic_perf/results/REFERENCE.md` | Modify (append) | Hypothesis-pass log entry with both captures + dominant-cost finding |
| `docs/project-context.md` | Modify | Phase advance to `plan-c-done`; session-history entry |
| `/tmp/c1_off_long.log`, `/tmp/c1_off_short.log` | Create (transient) | C1 baseline-verification logs |
| `/tmp/c3_text_report.log`, `/tmp/c4_text_report.log` | Create (transient) | On-build text reports for the retrospective |

---

## Task list

### Task C1: GATE — Off-build baseline reproducibility verification

**Files:**
- Read: `bench/quic_perf/results/REFERENCE.md` (calibrated baseline)
- Output: `/tmp/c1_off_long.log`, `/tmp/c1_off_short.log`
- No commit (gate produces console evidence; numbers go in C6's REFERENCE.md entry)

**Why:** B14's 30s long-conn capture only saw 5 handshakes (100% success), which is incompatible with the calibrated 412 rps + 99% timeout pattern. Either the calibrated baseline drifted or the load pattern doesn't reproduce on this hardware/config combo. C1 gates Plan C: verify at least one of `long-conn` or `short-conn` reproduces the saturating-handshake regime before spending time on on-build captures.

- [ ] **Step 1: Confirm off-build flag**

```bash
cd /home/donokami/Projets/perso/mojo-net
grep -n "comptime PROFILE_ACCEPT" src/quic/profile.mojo
```
Expected: `15:comptime PROFILE_ACCEPT: Bool = False`

If anything else, set to False before proceeding (this should already be the case post-Plan-B).

- [ ] **Step 2: Ensure off-build Docker image is fresh**

```bash
docker images --format '{{.Repository}}:{{.Tag}}' | grep '^mojo-net-bench:latest$' && \
    docker rmi mojo-net-bench:latest
make -C bench/quic_perf setup 2>&1 | tail -10
```
Expected: clean Docker rebuild (~5-10 min). The image will be built off-build because the flag is False.

- [ ] **Step 3: Run off-build long-conn baseline**

```bash
./bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 3 2>&1 | tee /tmp/c1_off_long.log
```
Expected: 3 result JSONs written to `bench/quic_perf/results/`. Capture median rps + handshake counts.

Extract metrics:
```bash
ls -t bench/quic_perf/results/*-mojo-net-1k-long-conn-tquic_client-iter*.json | head -3 | while read f; do
    python3 -c "
import json
d = json.load(open('$f'))
print(f\"{'$f':70} rps={d.get('req_per_sec', '?')} successful={d.get('successful', '?')} failed={d.get('failed', '?')}\")
"
done
```

(Adjust JSON keys based on actual sidecar structure — try `req_per_sec`, `requests_per_sec`, `rps`. Inspect with `python3 -m json.tool $f | head -30` to find the right key.)

- [ ] **Step 4: Run off-build short-conn baseline**

```bash
./bench/quic_perf/scripts/bench.sh mojo-net 1k short-conn tquic_client --iters 3 2>&1 | tee /tmp/c1_off_short.log
```
Expected: 3 result JSONs. Capture median rps + handshake counts the same way.

- [ ] **Step 5: GATE — apply reproducibility test**

Compare today's medians against REFERENCE.md (line 19-20):
- Calibrated long-conn: **mojo-net 412 req/s** (~3-10 successful handshakes per 30s, ~390 timeouts)
- Calibrated short-conn: **mojo-net 1 req/s** (massive timeout rate)

PASS if EITHER:
- Long-conn median ≤ 600 rps (allows generous noise) AND failed/timed-out count ≥ 100 in at least one iter, OR
- Short-conn median ≤ 5 rps AND failed/timed-out count ≥ 100 in at least one iter.

FAIL if BOTH:
- Long-conn median > 600 rps OR shows the 5-handshake/100%-success pattern from B14, AND
- Short-conn median > 5 rps OR shows similar steady-state.

**On FAIL — ABORT Plan C.** Escalate to user with these diagnostics:
- Today's long-conn median + handshake stats vs calibrated 412/3-10/390.
- Today's short-conn median + handshake stats vs calibrated 1/?/many.
- Suggest: bench harness drift (compare `bench/quic_perf/scripts/run-tquic-client.sh` and `bench/quic_perf/configs/*.env` against git log since 2026-04-25), tquic-bench:latest image version drift (`docker images --filter reference=tquic-bench:latest --format '{{.CreatedAt}}'`), or cross-stack impact from `82905d5` (h2-bench register_buf_ring perf — h2 and QUIC share the rustls library; unlikely but worth checking with `git log -- src/tls/`).

If gate FAILs, stop here and switch to debugging the harness; do NOT proceed to C2-C7.

- [ ] **Step 6: Document gate result**

Print a one-line summary to stdout:
```
[C1] GATE: PASS|FAIL — long-conn median=<X> rps (<succ>/<fail>); short-conn median=<Y> rps (<succ>/<fail>)
```

Save this summary; it goes verbatim into C6's REFERENCE.md entry.

- [ ] **Step 7: No commit**

C1 is a measurement gate. Result JSONs in `bench/quic_perf/results/*.json` are gitignored (`bench/quic_perf/.gitignore`). The gate's output goes into C6's REFERENCE.md commit. Do NOT commit anything in C1.

---

### Task C2: Switch to on-build profile build

**Files:**
- Modify: `src/quic/profile.mojo:15` (`False` → `True`)
- No commit yet (flag will be restored to False before final commit in C6).

**Why:** Plan B's instrumentation is gated by `comptime PROFILE_ACCEPT`; C3-C4 captures need on-build. Force a Docker rebuild to pick up the new flag.

- [ ] **Step 1: Flip the comptime flag**

```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = False/comptime PROFILE_ACCEPT: Bool = True/' src/quic/profile.mojo
grep -n "comptime PROFILE_ACCEPT" src/quic/profile.mojo
```
Expected: `15:comptime PROFILE_ACCEPT: Bool = True`

- [ ] **Step 2: Force Docker rebuild**

```bash
docker rmi mojo-net-bench:latest 2>&1 | tail -3
make -C bench/quic_perf setup 2>&1 | tail -10
```
Expected: clean rebuild (~5-10 min). The new image bakes in `PROFILE_ACCEPT=True`.

- [ ] **Step 3: Verify rebuild succeeded**

```bash
docker images --format '{{.Repository}}:{{.Tag}} {{.Size}} {{.CreatedAt}}' | grep '^mojo-net-bench:latest'
```
Expected: an image with a `CreatedAt` timestamp within the last few minutes.

- [ ] **Step 4: No commit**

The flag flip is temporary; restored in C6.

---

### Task C3: Capture sidecar under SHORT-CONN saturating-handshake load

**Files:**
- Create: `bench/quic_perf/results/profile/INSTRUMENTATION-<utc>-short-conn.json` (copied from container)
- Create: `/tmp/c3_text_report.log` (text report from `docker logs`)

**Why:** Spec §Validation deliverable 3. Short-conn is the retro-recommended primary load pattern (1 request per QUIC conn — `MAX_REQUESTS_PER_CONN=1` from `bench/quic_perf/configs/short-conn.env`). At `tquic_client --threads 4 --max-concurrent-conns 25` with each conn closing after 1 request, the harness should produce ~100 connection attempts / 30s — the saturating-handshake regime.

- [ ] **Step 1: Start the bench server**

```bash
bash bench/quic_perf/scripts/start-server.sh mojo-net 2>&1 | tee /tmp/c3_start.log
```
Expected: `[start-server] mojo-net container: bench-h3` + `[wait-ready] server responded on attempt N` + `bench-h3` (echoed name).

If `start-server.sh` fails: inspect `/tmp/start-server.log` (the docker run output) and `docker logs bench-h3 2>&1 | tail -30`.

- [ ] **Step 2: Drive 30s of short-conn load**

```bash
bash bench/quic_perf/scripts/run-tquic-client.sh 1k short-conn 30 2>&1 | tail -10
```
Expected: `[run-tquic-client] 1k/short-conn/30s: stdout in /tmp/client-stdout.log`. The client may exit non-zero; that's normal for `--duration`.

While the client is running (30s), the bench server is processing the saturating-handshake load. The instrumentation accumulates per-packet decomposition + idle/busy/fan-out into `H3UdpHandler.profile`.

- [ ] **Step 3: SIGINT the server to flush the report**

```bash
docker kill --signal=SIGINT bench-h3 2>&1
sleep 4
```
Expected: `bench-h3` (echoed). The 4s sleep gives the main-loop check time to run the timeout sweep + flush.

- [ ] **Step 4: Capture the text report from container logs**

```bash
docker logs bench-h3 2>&1 | grep -A 80 "=== mojo-net QUIC accept-loop profile" | tee /tmp/c3_text_report.log
```
Expected: the full text report block ending with `=== end ===` plus `h3-bench: profile sidecar written: bench/quic_perf/results/profile/INSTRUMENTATION-...json`.

If the text report is missing: check `docker logs bench-h3 2>&1 | tail -60`. Possible causes:
- The SIGINT main-loop check didn't fire because the loop was idle in `io_uring_enter` (documented latency caveat in `bench/quic_perf/README.md`). Send another datagram by re-running `run-tquic-client.sh 1k short-conn 5` briefly, then SIGINT again.
- Server crashed: `docker logs bench-h3 2>&1 | tail -100` to see panic/abort message.

- [ ] **Step 5: Copy the sidecar JSON out of the container**

```bash
mkdir -p bench/quic_perf/results/profile
docker cp bench-h3:/app/bench/quic_perf/results/profile/. ./bench/quic_perf/results/profile/ 2>&1
SIDECAR_SHORT=$(ls -t bench/quic_perf/results/profile/INSTRUMENTATION-*.json | head -1)
echo "Short-conn sidecar: $SIDECAR_SHORT"
```
Expected: a JSON file named `INSTRUMENTATION-<yyyymmdd-hhmmss>.json` (UTC). Save the path; you'll rename it in Step 6.

- [ ] **Step 6: Tag the sidecar with the load-pattern suffix**

The harness's UTC timestamp doesn't distinguish short-conn from long-conn. Rename:

```bash
SIDECAR_SHORT_TAGGED="${SIDECAR_SHORT%.json}-short-conn.json"
mv "$SIDECAR_SHORT" "$SIDECAR_SHORT_TAGGED"
echo "Renamed to: $SIDECAR_SHORT_TAGGED"
```

- [ ] **Step 7: Verify JSON well-formedness**

```bash
python3 -m json.tool "$SIDECAR_SHORT_TAGGED" > /dev/null && echo "[C3] JSON OK"
```
Expected: `[C3] JSON OK`. If parse error, the report-write path has a bug — escalate.

- [ ] **Step 8: Stop the server**

```bash
bash bench/quic_perf/scripts/stop-server.sh 2>&1 | tail -3
```
Expected: `[stop-server] removed bench-h3`.

- [ ] **Step 9: No commit yet**

C6 will commit the sidecar JSON + REFERENCE.md update + project-context update together.

---

### Task C4: Capture sidecar under LONG-CONN with `--max-concurrent-conns 100`

**Files:**
- Create: `bench/quic_perf/results/profile/INSTRUMENTATION-<utc>-long-conn-c100.json` (copied from container)
- Create: `/tmp/c4_text_report.log`

**Why:** Plan B retro called for a comparison cell. The harness's standard long-conn config uses `--max-concurrent-conns 25` (B14's setup that produced only 5 handshakes). Raising to 100 explicitly stresses the cold-start path even with persistent connections. Disambiguates whether the cold-start floor is short-conn-specific or simply concurrency-driven.

The harness's `run-tquic-client.sh` reads `--max-concurrent-conns 25` from a hardcoded line in the script (not from `configs/*.env`). To override, drive `tquic_client` directly via `docker run` rather than the wrapper.

- [ ] **Step 1: Start the bench server (still on-build)**

```bash
bash bench/quic_perf/scripts/start-server.sh mojo-net 2>&1 | tee /tmp/c4_start.log
```
Expected: `bench-h3` is up.

- [ ] **Step 2: Drive 30s of long-conn-c100 load**

Inspect `bench/quic_perf/scripts/run-tquic-client.sh` for the exact docker invocation, then replicate with `--max-concurrent-conns 100`. The harness invocation is:

```
docker run --rm --network host --cpuset-cpus=2-5 \
    --entrypoint /usr/local/bin/tquic_client tquic-bench:latest \
    --threads 4 \
    --max-concurrent-conns 25 \
    --max-requests-per-conn $MAX_REQUESTS_PER_CONN \
    --max-concurrent-requests $MAX_CONCURRENT_REQUESTS \
    --total-requests-per-thread 0 \
    --send-udp-payload-size 1350 \
    --duration $DURATION \
    --connect-to 127.0.0.1:8443 \
    "https://127.0.0.1:8443/static/${PAYLOAD}.bin"
```

For long-conn (`MAX_REQUESTS_PER_CONN=0`, `MAX_CONCURRENT_REQUESTS=10`) with c100 override:

```bash
docker run --rm --network host --cpuset-cpus=2-5 \
    --entrypoint /usr/local/bin/tquic_client tquic-bench:latest \
    --threads 4 \
    --max-concurrent-conns 100 \
    --max-requests-per-conn 0 \
    --max-concurrent-requests 10 \
    --total-requests-per-thread 0 \
    --send-udp-payload-size 1350 \
    --duration 30 \
    --connect-to 127.0.0.1:8443 \
    https://127.0.0.1:8443/static/1k.bin \
    > /tmp/c4_client_stdout.log 2>&1 || true
echo "[C4] tquic_client done; stdout in /tmp/c4_client_stdout.log"
```

(`|| true` because `tquic_client` may exit non-zero on `--duration` end.)

- [ ] **Step 3: SIGINT + capture text report**

```bash
docker kill --signal=SIGINT bench-h3 2>&1
sleep 4
docker logs bench-h3 2>&1 | grep -A 80 "=== mojo-net QUIC accept-loop profile" | tail -82 | tee /tmp/c4_text_report.log
```

(`tail -82` because both C3 and C4 reports are in the same container's logs; `tail -82` picks the most recent block. If `bench-h3` was restarted between C3 and C4 by `start-server.sh`, this isn't necessary — `start-server.sh` removes the previous container first per its `stop-server.sh` call.)

Expected: full text report ending with `=== end ===`.

- [ ] **Step 4: Copy + tag the sidecar**

```bash
docker cp bench-h3:/app/bench/quic_perf/results/profile/. ./bench/quic_perf/results/profile/ 2>&1
SIDECAR_C100=$(ls -t bench/quic_perf/results/profile/INSTRUMENTATION-*.json | grep -v -- '-short-conn\|-long-conn-c100' | head -1)
SIDECAR_C100_TAGGED="${SIDECAR_C100%.json}-long-conn-c100.json"
mv "$SIDECAR_C100" "$SIDECAR_C100_TAGGED"
echo "Long-conn-c100 sidecar: $SIDECAR_C100_TAGGED"
```

- [ ] **Step 5: Verify JSON well-formedness**

```bash
python3 -m json.tool "$SIDECAR_C100_TAGGED" > /dev/null && echo "[C4] JSON OK"
```
Expected: `[C4] JSON OK`.

- [ ] **Step 6: Stop the server**

```bash
bash bench/quic_perf/scripts/stop-server.sh 2>&1 | tail -3
```
Expected: `[stop-server] removed bench-h3`.

- [ ] **Step 7: No commit yet**

---

### Task C5: Analyse both sidecars; identify dominant cost

**Files:**
- Output: console summary; numbers go into C6's REFERENCE.md entry.

**Why:** Spec §Validation deliverable 3. Apply the ≥2× signal table to each sidecar; compare short-conn vs long-conn-c100 to identify whether cold-start dominance is short-conn-specific or concurrency-driven.

- [ ] **Step 1: Define the analyser**

```bash
cat > /tmp/c5_analyse.py <<'EOF'
import json
import sys

def analyse(path, label):
    d = json.load(open(path))
    print(f"=== {label} ({path}) ===")

    # Run summary
    run_us = d["run_wall_clock_us"]
    on_flush = d["on_flush_events"]
    idle = d["idle_us_total"]
    busy = d["busy_us_total"]
    print(f"Run:           {run_us/1_000_000:.2f}s, on_flush={on_flush}, idle={idle/run_us*100:.1f}%, busy={busy/run_us*100:.1f}%")

    # Fan-out
    hist = d["pkts_per_flush_histogram"]
    midpoints = {"1":1, "2-3":2.5, "4-7":5.5, "8-15":11.5, "16-31":23.5, "32-63":47.5, "64-127":95.5, "128+":192}
    total = sum(hist.values())
    fanout_mean = sum(hist[k] * midpoints[k] for k in hist) / total if total else 0
    print(f"pkts_per_flush: weighted-mean={fanout_mean:.2f}, dist={hist}")

    # Per-packet legs
    pp = d["per_pkt_us"]
    legs = {
        "header_parse": pp["header_parse"]["avg"],
        "hp": pp["hp"]["avg"],
        "aead": pp["aead"]["avg"],
        "frame_parse": pp["frame_parse"]["avg"],
        "sm": pp["sm"]["avg"],
        "residual": pp["residual"]["avg"],
        "shim_ffi": pp["shim_ffi"]["avg"],
        "drain": pp["drain"]["avg"],
    }
    total_p = pp["total"]
    print(f"per_pkt total: p50={total_p['p50']} p90={total_p['p90']} p99={total_p['p99']} (n={total_p['n']}, overflow={total_p['overflow']})")
    for k, v in legs.items():
        print(f"  {k:14s} avg={v} us")

    # Apply 2x rule (in-recv legs only; sm excludes shim_ffi as overlap)
    candidates = ["shim_ffi", "aead", "sm"]
    dominant = []
    for c in candidates:
        others = {k: v for k, v in legs.items() if k != c}
        if c == "sm":
            others = {k: v for k, v in others.items() if k != "shim_ffi"}
        # exclude drain (bench-side TX) from the in-recv comparison
        in_recv_others = {k: v for k, v in others.items() if k != "drain"}
        max_other = max(in_recv_others.values()) if in_recv_others else 0
        if legs[c] >= 2 * max_other and legs[c] > 0:
            dominant.append(f"{c} (avg={legs[c]} >= 2x next-in-recv={max_other})")

    # Fan-out dominance
    if fanout_mean >= 8:
        dominant.append(f"fan-out (mean={fanout_mean:.2f} >= 8)")

    # Drain dominance (separate; bench-side TX)
    drain_v = legs["drain"]
    in_recv = {k: v for k, v in legs.items() if k != "drain"}
    if drain_v >= 2 * max(in_recv.values()) and drain_v > 0:
        dominant.append(f"drain (avg={drain_v} >= 2x in-recv legs={max(in_recv.values())}) — bench TX path")

    if dominant:
        print(f"DOMINANT: {'; '.join(dominant)}")
    else:
        print(f"NO SINGLE DOMINANT — combination effect")

    # Handshake
    hs = d["handshake"]
    print(f"Handshake: arrivals={hs['arrivals']} successful={hs['successful']} timed_out={hs['timed_out']}")
    lat = hs["latency_us"]
    print(f"Handshake latency: p50={lat['p50']} p90={lat['p90']} p99={lat['p99']} max={lat['max']} (n={lat['count']})")
    print()

if __name__ == "__main__":
    for label, path in [("short-conn", sys.argv[1]), ("long-conn-c100", sys.argv[2])]:
        analyse(path, label)
EOF
echo "Analyser at /tmp/c5_analyse.py"
```

- [ ] **Step 2: Run the analyser on both sidecars**

```bash
SIDECAR_SHORT=$(ls -t bench/quic_perf/results/profile/INSTRUMENTATION-*-short-conn.json | head -1)
SIDECAR_C100=$(ls -t bench/quic_perf/results/profile/INSTRUMENTATION-*-long-conn-c100.json | head -1)
python3 /tmp/c5_analyse.py "$SIDECAR_SHORT" "$SIDECAR_C100" | tee /tmp/c5_analysis.log
```
Expected: two summary blocks, each with run/fanout/per-pkt-legs/dominant-cost/handshake stats. Note the dominant-cost line(s) per cell.

- [ ] **Step 3: Compare and synthesise**

Print a one-line conclusion:

```bash
echo "[C5] Conclusion: <DOMINANT_COST_NAME> | short-conn:<short_dominant> | c100:<c100_dominant>" | tee -a /tmp/c5_analysis.log
```

(Replace `<DOMINANT_COST_NAME>` with your reasoned synthesis. Possible values: "FFI dominance (consistent across both cells)", "fan-out dominance (c100 only)", "no single dominant — combination effect", etc.)

This conclusion goes verbatim into C6's REFERENCE.md entry.

- [ ] **Step 4: No commit**

---

### Task C6: Append REFERENCE.md hypothesis-pass log entry; restore flag; commit

**Files:**
- Modify: `bench/quic_perf/results/REFERENCE.md` (append hypothesis-pass log entry)
- Modify: `src/quic/profile.mojo:15` (restore `False`)
- Modify: `docs/project-context.md` (phase advance + session entry)
- Stage: the two sidecar JSONs (`*-short-conn.json` and `*-long-conn-c100.json`)

**Why:** Persists C1-C5 findings as the documented data artifact. Restores off-build state for any subsequent build.

- [ ] **Step 1: Restore off-build flag**

```bash
sed -i 's/comptime PROFILE_ACCEPT: Bool = True/comptime PROFILE_ACCEPT: Bool = False/' src/quic/profile.mojo
grep -n "comptime PROFILE_ACCEPT" src/quic/profile.mojo
```
Expected: `15:comptime PROFILE_ACCEPT: Bool = False`

- [ ] **Step 2: Append REFERENCE.md hypothesis-pass log entry**

Open `bench/quic_perf/results/REFERENCE.md`, find the existing hypothesis-pass log section (the most recent entry is `2026-04-26 — accept-loop-instrumentation-data-collection — DATA (steady-state only)`). Append a new entry directly after it:

```markdown

### 2026-04-26 — accept-loop-instrumentation-saturating-handshake — DATA

**Spec:** `specs/2026-04-25-quic-accept-loop-instrumentation.md`. Plan: `plans/2026-04-26-quic-accept-loop-instrumentation-plan-c.md`. Goal: re-capture the missing cold-start data after Plan B's long-conn capture only saw 5 handshakes (steady-state).

**C1 baseline reproducibility gate (off-build, 3 iters each):**

| Cell | Median rps | Successful / Failed |
|---|---|---|
| 1k long-conn | <X> rps | <succ> / <fail> |
| 1k short-conn | <Y> rps | <succ> / <fail> |

vs calibrated 2026-04-25 baseline: long-conn 412 rps (3-10/390 timeouts), short-conn 1 rps. **Gate: PASS / FAIL.**

**On-build single-cell captures (30 s window each, manual SIGINT-driven sidecar):**

| Cell | pkts_per_flush mean | per_pkt p50/p90/p99 (us) | shim_ffi | aead | sm | drain | arrivals/succ/timeout | hs lat p50/p99 (us) |
|---|---|---|---|---|---|---|---|---|
| short-conn (`MAX_REQUESTS_PER_CONN=1`) | <X> | <p50>/<p90>/<p99> | <us> | <us> | <us> | <us> | <a>/<s>/<t> | <p50>/<p99> |
| long-conn-c100 (`--max-concurrent-conns 100`) | <X> | <p50>/<p90>/<p99> | <us> | <us> | <us> | <us> | <a>/<s>/<t> | <p50>/<p99> |

(All `header_parse` / `hp` / `aead` / `residual` legs were sub-microsecond in B14's steady-state capture; if they remain sub-microsecond here too, that's preserved — fast RX continues to be a non-bottleneck.)

**Dominant cost (≥2× signal table):** <FFI / AEAD / SM / fan-out / drain (bench TX) / no single dominant>.

Per-cell breakdown: short-conn → <X dominant or "none">; long-conn-c100 → <Y dominant or "none">.

**Sidecars committed:**
- `bench/quic_perf/results/profile/INSTRUMENTATION-<utc>-short-conn.json`
- `bench/quic_perf/results/profile/INSTRUMENTATION-<utc>-long-conn-c100.json`

**On-build overhead drift:** Inferred from on-build run wall-clock vs off-build (C1) — if C3/C4 sidecar shows degraded effective rps (compared to the C1 long-conn or short-conn off-build cell of the same load pattern), document the drift here. If the saturating-handshake regime makes the overhead more visible than B13's -0.40% on long-conn (5 conns), note it.

**Methodology:** Plan C's two captures replace what B14 should have produced. C1 verified the off-build calibrated baseline is still reproducible (gate PASS). Both captures used the harness's `start-server.sh` + `run-tquic-client.sh` (or direct `docker run` for c100 override) + manual `docker kill --signal=SIGINT bench-h3` + `docker cp` exfiltration pattern from Plan B.

**Next hypothesis (synthesis):** <derive from dominant cost in both cells — concrete, actionable. Examples:
- If FFI dominates in both → spec a Rust-side counters pass to disambiguate FFI-roundtrip from rustls work.
- If fan-out ≥8 in c100 only → spec a multi-fiber accept fan-out pass (the original suspect from the pacer-bypass falsification log).
- If sm dominates → spec a state-machine dispatch pass.
- If drain (bench TX) dominates in both → instrument the TX path more finely (response generation, outgoing AEAD, sendmsg queue depth).
- If no single dominant → spec broader investigation (multiple medium-cost legs; combination effect).>
```

Replace ALL `<X>`, `<Y>`, `<succ>`, `<fail>`, etc. placeholders with actual numbers from C1 and C5's analysis output.

- [ ] **Step 3: Update docs/project-context.md**

Edit `docs/project-context.md`:

a) Update phase line:
```markdown
**Last updated:** 2026-04-26
**Current phase:** spec-quic-accept-loop-instrumentation-plan-c-done — Plan C captured saturating-handshake data on branch `feat/quic-accept-loop-instrumentation`. C1 baseline gate <PASS/FAIL>. Dominant cost: <synthesis>. Next hypothesis: <next>. Branch HEAD <new-sha>; Plan B + Plan C will FF-merge to main together.
```

b) Update the active-specs row from `in-progress` to `done`:

Find: `| in-progress | \`specs/2026-04-25-quic-accept-loop-instrumentation.md\` → ...`

Change `in-progress` → `done`. Update the description to mention Plan C's findings (one-line summary).

c) Add a session-history entry at the top of the "Session history" section:

```markdown
- 2026-04-26 — `~/.claude/projects/-home-donokami-Projets-perso-mojo-net/682f3d4b-5bc9-454e-afd2-f045e6edca1c.jsonl` (continued) — Plan C executed via subagent-driven-development on branch `feat/quic-accept-loop-instrumentation` (renamed from `feat/quic-accept-loop-profile-b`). 7 operational tasks; no code changes. C1 off-build baseline reproducibility gate: <PASS/FAIL — values>. C2-C4 captured two on-build sidecars (short-conn primary; long-conn --max-concurrent-conns 100 comparison). C5 analysis: <dominant cost synthesis>. C6 REFERENCE.md hypothesis-pass log + project-context updated. C7 test baseline confirmed no regression. Sidecars committed:
  - `bench/quic_perf/results/profile/INSTRUMENTATION-<utc>-short-conn.json`
  - `bench/quic_perf/results/profile/INSTRUMENTATION-<utc>-long-conn-c100.json`
Branch HEAD <new-sha>. Off-build flag restored to False. Phase: spec-quic-accept-loop-instrumentation-plan-c-done. Ready for finishing-a-development-branch.
```

- [ ] **Step 4: Commit**

```bash
git status -- bench/quic_perf/results/profile/ src/quic/profile.mojo bench/quic_perf/results/REFERENCE.md docs/project-context.md
```

Stage:
- `bench/quic_perf/results/profile/INSTRUMENTATION-*-short-conn.json`
- `bench/quic_perf/results/profile/INSTRUMENTATION-*-long-conn-c100.json`
- `bench/quic_perf/results/REFERENCE.md`
- `docs/project-context.md`
- `src/quic/profile.mojo` (only if the False restore left a diff — should NOT, since we flipped → ran → flipped back, net zero)

Use the `commit-smart` skill. Message: `bench: capture saturating-handshake profile data (plan c)`.

- [ ] **Step 5: Verify final state**

```bash
git status && grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo
```
Expected: clean working tree (relative to Plan C scope; ignored files like `.gitignore`, `bench/h2_server` binary may still appear) AND `comptime PROFILE_ACCEPT: Bool = False`.

---

### Task C7: Test baseline + acceptance

**Files:**
- No changes; verification only.

**Why:** Confirm Plan C operations didn't regress anything (e.g., a stray sed in C2/C6 didn't corrupt `src/quic/profile.mojo`).

- [ ] **Step 1: Run the full test suite**

```bash
cd /home/donokami/Projets/perso/mojo-net
bash scripts/run_tests.sh 2>&1 | tail -30
```
Expected: same baseline as Plan B's final state (33 loopback tests pass, `test_quic_profile`/`test_quic_profile_wiring` pass, pre-existing `test_tls_connection` failure is the only failure — out-of-scope FFI symbol).

If a NEW failure appears: inspect the diff, particularly `src/quic/profile.mojo`. Most likely cause: an extra newline or sed-induced corruption from the toggle steps. Restore via `git checkout src/quic/profile.mojo` (only if the diff is purely the flag flip leftover; verify with `git diff src/quic/profile.mojo` first).

- [ ] **Step 2: Print acceptance summary**

```bash
cat <<EOF
=== Plan C Acceptance ===
Branch: feat/quic-accept-loop-instrumentation
HEAD: $(git rev-parse --short HEAD)
Off-build flag: $(grep "comptime PROFILE_ACCEPT" src/quic/profile.mojo | awk '{print $NF}')
C1 gate: <PASS/FAIL with values>
Sidecars: $(ls bench/quic_perf/results/profile/INSTRUMENTATION-*.json 2>/dev/null | wc -l) total
Dominant cost (synthesis): <one-line>
Next hypothesis: <one-line>
Tests: <PASS / FAIL listing>
EOF
```

- [ ] **Step 3: No commit**

C7 is acceptance only.

---

## Acceptance summary

After all 7 tasks complete:

- [x] C1 GATE PASSed — at least one of long-conn or short-conn off-build reproduces the calibrated saturating-handshake regime. (If C1 FAILed, Plan C aborts at C1 and the rest of the plan is N/A.)
- [x] C2 on-build profile build was rebuilt successfully.
- [x] C3 short-conn sidecar captured + verified well-formed JSON.
- [x] C4 long-conn-c100 sidecar captured + verified well-formed JSON.
- [x] C5 analysis run; dominant-cost synthesis named.
- [x] C6 REFERENCE.md updated with both captures + dominant cost; off-build flag restored; commit landed.
- [x] C7 baseline test suite green (modulo pre-existing `test_tls_connection`); acceptance summary printed.

## Open questions (severity / trigger)

- **What:** If both captures show drain (bench TX) dominates and no in-recv leg exceeds 2× threshold, the next hypothesis is bench-side TX path investigation, not QUIC stack.
  **Severity:** required-later (high) — this would shift the perf-investigation focus from QUIC to bench infrastructure.
  **Trigger:** C5 conclusion line names "drain dominance in both cells".

- **What:** If C1 FAILs (neither off-build cell reproduces the calibrated baseline), the bench harness has drifted and Plan C aborts.
  **Severity:** required-later (critical)
  **Trigger:** C1's gate evaluation. Likely diagnostics:
    - `git log -- bench/quic_perf/scripts/run-tquic-client.sh bench/quic_perf/configs/`: any change since 2026-04-25?
    - `docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedAt}}' | grep tquic-bench`: same image as 2026-04-25?
    - `git log -- src/tls/`: any change to the rustls FFI path since 2026-04-25 that could have cross-stack impact?

- **What:** On-build overhead in saturating-handshake mode could exceed 10% (vs B13's -0.40% on long-conn 5-conn steady-state).
  **Severity:** optional
  **Trigger:** C5/C6 — if the on-build run's effective rps is materially below C1's off-build short-conn rps, document the drift in REFERENCE.md and note that the captured numbers may be biased.

- **What:** SIGINT-flush latency caveat may cause C3/C4 to miss the report window.
  **Severity:** optional
  **Trigger:** if `docker logs` shows no `=== mojo-net QUIC accept-loop profile ===` block after Step 3 of C3 or C4. Mitigation: send another small client load to wake the loop, then SIGINT again.

---

## Pre-save checklist

- [x] Every spec requirement (saturating-handshake re-capture per Plan B retro) maps to a task.
- [x] No forbidden placeholders (TBD/TODO/"add appropriate error handling"/"similar to Task N").
- [x] Names + paths consistent across tasks (`bench-h3` container, `bench/quic_perf/results/profile/INSTRUMENTATION-*-{short-conn,long-conn-c100}.json` artifact paths).
- [x] Mojo 0.26.2 considerations: NO code changes in Plan C; B13 already validated Docker build with `PROFILE_ACCEPT=True`. The flag-flip pattern is mechanical.
