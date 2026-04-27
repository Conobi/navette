## Host

- Kernel: `Linux 6.19.12-lqx1-1-lqx`
- CPU: `11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz`
- Cores: `8`
- Docker: `29.3.0`
- Date: `2026-04-25`

## Reference numbers

`make bench-mvp` on the host above. Each cell is the median of 3 iterations of
a 30 s measurement window after a 5 s warmup, with `--cpuset-cpus=0` for the
server and `--cpuset-cpus=2-5` for the client. CPU% is sampled at the cgroup
level via `docker stats --no-stream` once per second.

### tquic_client (4 threads, 25 conns/thread, saturating)

| Payload | Scenario   | mojo-net req/s (n) | TQUIC req/s (n) | mojo-net CPU% | mojo-net / TQUIC |
|---------|------------|--------------------|-----------------|---------------|------------------|
| 1k      | long-conn  | 412 (3)            | 87,113 (3)      | 5.6           | 0.0047× |
| 1k      | short-conn | 1 (3)              | 2,535 (3)       | 0.2           | 0.0004× |

### h2load-h3 (single-threaded, regression-tracking)

| Payload | Scenario   | mojo-net req/s (n) | TQUIC req/s (n) | mojo-net CPU% | mojo-net / TQUIC |
|---------|------------|--------------------|-----------------|---------------|------------------|
| 1k      | long-conn  | 125 (3)            | 32,625 (3)      | 2.9           | 0.0038× |
| 1k      | short-conn | 11 (3)             | 66,023 (3)      | 0.6           | 0.0002× |

## How to read this

- **TQUIC's tquic_server hits 87K req/s with `tquic_client` and saturates core 0
  at 88% CPU** — server-side bottleneck reached, the hardware envelope on this
  laptop. This is the calibration anchor.
- **mojo-net hits 412 req/s long-conn / 1 req/s short-conn while using <6% of
  one CPU core.** Mojo-net is *not* CPU-bound on core 0 — there is huge headroom
  the server isn't using. The bottleneck is **per-connection cost**: under
  saturating load (400 attempted connections in 30 s) only ~3–10 complete the
  QUIC handshake, the rest time out. The successful handshakes then drive
  thousands of requests, but the throughput is gated by the trickle of
  conns the server can actually accept.
- **h2load → mojo-net is single-threaded at the client** — those numbers are
  for regression tracking against prior runs, not absolute comparisons.

## Known limitations of these numbers

- **2 MB / 5K / 15K payloads not in the MVP matrix.** The 1 KB cells are the
  ones run by `make bench-mvp`. Run `make bench-full` for all 32 cells.
- **`tquic_client` knob ceiling** — 4 threads × 25 conns × 10 streams = 1,000
  in-flight requests. On a 48-core EPYC the ceiling would be higher; here we
  are likely under-saturating `tquic_server` slightly. The 87K rps is a lower
  bound on TQUIC's achievable throughput.
- **No CI integration / no commit-to-commit tracking yet** — REFERENCE.md is
  a manual snapshot. Numbers will drift with kernel updates, thermals, and
  parallel host load.
- **Single-worker mojo-net** (`--workers 1`). Multi-process via SO_REUSEPORT
  is out of scope for this harness.

## Where the work goes from here

The honest read: mojo-net is ~210× slower than TQUIC long-conn, ~2,500× slower
short-conn, while using essentially zero CPU. The next optimisation pass should
target **connection-establishment throughput** — handshake latency, accept
loop, packet decryption pipelining — rather than steady-state stream throughput.

## Hypothesis-pass log

### 2026-04-25 — pacer-bypass-during-handshake — FALSIFIED

**Spec:** `specs/2026-04-25-quic-pacer-bypass-handshake.md`. Hypothesis: the
M4a universal `_can_send` gate paces Initial+Handshake-space packets;
cold-start pacing rate (`2 × cwnd × 1e6 / smoothed_rtt ≈ 60 KiB/s`) blocks
each subsequent datagram for ~20 ms in a multishot recvmsg burst, pushing
~100 concurrent client handshakes past their handshake timeout. Fix: gate
the pacer (and post-send token commit + timer-deadline branch) on
`is_established()`; preserve anti-amp and CC cwnd unchanged.

**Single-cell gate** (`bench.sh mojo-net 1k long-conn tquic_client --iters 3`):

| iter | rps | CPU% | success | fail |
|---|---|---|---|---|
| 1 | 415.08 | 5.5% | 12,870 | 40 |
| 2 | 432.81 | 4.4% | 13,420 | 40 |
| 3 | 411.20 | 4.5% | 12,750 | 40 |

**Median: 415 rps.** Threshold for confirmation was ≥ 4,000 rps (≥ 10× the
412 pre-fix baseline). Result: 1.01× — within noise. **Hypothesis
falsified: the pacer was not the cold-start handshake-throughput floor.**
CPU% remains ~5%, same idle-waiting symptom. Something else gates accept /
handshake throughput under concurrency.

**Code shipped anyway as a code-quality improvement.** The fix is
RFC-compatible (RFC 9002 §7's only normative MUST is "pace OR limit bursts
to the initial congestion window"; retained anti-amp + cwnd checks satisfy
the burst-limit clause). picoquic ships this exact design; quinn / TQUIC /
ngtcp2 / quiche pace every encryption level. mojo-net is now in the
picoquic camp on this point. Commits: `911601e..ba3c254` on
`fix/quic-pacer-bypass-handshake`.

**Next hypothesis (open question, severity: required-later, trigger:
before any further QUIC perf work):** the multi-fiber accept fan-out / the
serial single-fiber `on_flush` loop in `bench/h3_server.mojo:523-600`. The
recvmsg burst delivers N Initial packets into one CQ wakeup; today they
are processed strictly serially in one fiber. Even with the pacer out of
the way, the serial nature plus per-packet FFI roundtrips through the
rustls global lock would explain the symptom (low CPU + high handshake
timeout rate under concurrency).

### 2026-04-26 — accept-loop-instrumentation-saturating-handshake — DATA (REVISED: buffer-ring exhaustion, not FFI dominance)

**Post-capture independent investigation revealed the on-server "FFI dominance" finding below is a red herring.** A subagent traced the actual cold-start path and identified buffer-ring reprovision delay as the rate-limiter. Summary at end of this entry; the original analysis is preserved verbatim for audit.

---


**Spec:** `specs/2026-04-25-quic-accept-loop-instrumentation.md`. Plan: `plans/2026-04-26-quic-accept-loop-instrumentation-plan-c.md`. Goal: re-capture the missing cold-start data after Plan B's long-conn capture only saw 5 handshakes (steady-state).

**C1 baseline reproducibility gate (off-build, 3 iters each):**

| Cell | Median rps | Failed (handshake timeouts per 30s) |
|---|---|---|
| 1k long-conn | 405.07 rps | 40 |
| 1k short-conn | 0.42 rps | 0 (only 13 succeeded — saturating-handshake regime confirmed) |

vs calibrated 2026-04-25 baseline: long-conn 412 rps, short-conn 1 rps. **Gate: PASS.** The B14 anomaly (only 5 handshakes in long-conn) was a one-off; today's runs reproduce the calibrated saturating-handshake regime cleanly.

**On-build single-cell captures (30 s window each, manual SIGINT-driven sidecar):**

| Cell | pkts_per_flush mean | per_pkt p50/p90/p99 (us) | shim_ffi | aead | sm | drain | arrivals/succ/timeout | hs lat p50/p99 (us) |
|---|---|---|---|---|---|---|---|---|
| short-conn (saturating-handshake; n=233 pkts) | 2.07 | 6/101/246 | **127** | 0 | **129** | 47 | 17/17/0 | 879/26,272 |
| long-conn-c100 (mostly steady-state; n=3571 pkts) | 3.83 | 15/30/60 | 8 | 0 | 8 | 52 | 5/5/0 | 2,628/27,951 |

`header_parse` / `hp` / `aead` / `residual` legs were sub-microsecond in both cells — fast RX continues to be a non-bottleneck.

**Dominant cost (≥2× signal table):**

- **short-conn → SM (state machine) dominates by 64.5×** (avg 129us vs next-in-recv frame_parse 2us). Critically, `shim_ffi` (127us) ≈ `sm` (129us) — almost ALL of the state-machine time IS FFI roundtrip into `librustls-mojo` (`quic_conn_read_hs` / `quic_conn_write_hs` / `quic_conn_take_keys`). **The cold-start bottleneck is per-packet rustls FFI on the handshake CRYPTO path.**
- **long-conn-c100 → drain (bench TX) dominates by 4.7×** (avg 52us). Expected steady-state pattern (response generation + outgoing AEAD + sendmsg queue); not actionable as a hypothesis — see Plan B retro for the same finding.

**Sidecars committed:**
- `bench/quic_perf/results/profile/INSTRUMENTATION-20260426-203147-short-conn.json`
- `bench/quic_perf/results/profile/INSTRUMENTATION-20260426-203304-long-conn-c100.json`

**Methodology:** Plan C's two captures replace B14's single steady-state capture. C1 verified the off-build calibrated baseline still reproduces (within 2% on long-conn rps; short-conn slower than calibrated 1 rps, ~0.5 rps median — even more saturating-handshake-bottlenecked). Both on-build captures used the harness's `start-server.sh` + `run-tquic-client.sh` (or direct `docker run` for `--max-concurrent-conns 100` override) + manual `docker kill --signal=SIGINT bench-h3` + `docker cp` exfiltration pattern.

**Next hypothesis (synthesis — original, NOW SUPERSEDED — see corrected diagnosis below):**

~~The cold-start floor is the per-packet rustls FFI roundtrip through `_drive_handshake`. At saturating-handshake load with serialized single-fiber `_flush_impl`, a 127us-per-packet FFI cost multiplies into the observed timeout floor.~~

This synthesis is wrong. The FFI cost is real but it's measured on the 233 packets that arrived; it cannot be the rate-limiter when those 233 packets accrue at only ~7/sec. Something upstream throttles arrival.

---

## Corrected diagnosis (post-investigation, 2026-04-26) — SUPERSEDED, see TRUE diagnosis below

The buffer-ring exhaustion hypothesis was tested with diagnostic counters and **falsified**. See "TRUE diagnosis" section below. The original investigation was directionally right (look upstream of FFI) but landed on the wrong layer.

---

### Buffer-ring exhaustion theory (FALSIFIED 2026-04-26)

**Original claim:** the cold-start floor is buffer-ring exhaustion in `bench/h3_server.mojo`'s io_uring provided-buffer pool, not FFI cost.

**Root cause** (traced in `bench/h3_server.mojo:main()` lines ~894-919 and `boucle/boucle/completion.mojo:774-789`): the bench's main loop reprovisions consumed buffers AFTER `loop.poll()` returns and queues `reprovide_buffer` SQEs in the next iteration's submission batch. Those SQEs do not reach the kernel until the next `submit_and_wait()` call. During that gap, the kernel has no buffers; new multishot recvmsg completions arrive with `result <= 0` (ENOBUFS) and terminate the multishot. The `_handle_recvmsg` early-return on `result <= 0` means no packet processed, no buffer consumed, no signal that anything was dropped.

Under saturating-handshake load (4×25=100 clients sending Initial packets simultaneously):
- First poll cycle: kernel drains all ~1024 pool buffers
- `on_flush()` processes them serially with FFI cost (this is where the 127us number comes from — it's REAL but only for these few packets)
- Returns to main; consumed_bufs queued for reprovision
- Multishot terminates; main re-arms it but pool is empty → tight ENOBUFS loop
- The 50ms `submit_timeout` tick is the only thing that breaks the loop: each tick fires a fresh `poll()`, which submits queued reprovides via `submit_and_wait`, kernel sees buffers, brief acceptance window before re-exhaustion
- Effective handshake accept rate is gated by the 50ms cycle (~20 windows/sec)

**This explains every observed paradox:**

| Observed | Real cause |
|---|---|
| Server 99.8% idle | Blocked in `poll()` waiting for CQEs that can't arrive (no kernel buffers) |
| Only 17 arrivals in 32s | Most Initials dropped at kernel-recvmsg layer before reaching pending_rx |
| Server-side timeout count = 0 | Server only sees the connections that DID arrive; the 80+ that didn't never registered |
| FFI dominance (127us shim_ffi) | Measured cost on the few packets that escaped buffer starvation |
| Successful handshake p50=879us | Fast when packets do get through |

**What "batch FFI" would NOT fix:** the dropped Initials. FFI cost is invisible to packets the server never sees. Batching FFI helps steady-state throughput (long-conn) but doesn't lift the short-conn floor.

**What WILL fix it (two options, ranked):**

1. **Port h3 to `BufRing.add_buffer()`** (Recommended). The user's commit `82905d5 perf(bench/h2): drop per-conn recv_buf, use boucle register_buf_ring` ports h2 to boucle's `BufRing` API — userspace store + atomic tail update, zero SQE, zero syscall, kernel sees buffer immediately. h3 currently uses the legacy `IORING_OP_PROVIDE_BUFFERS` SQE path. Mirror the h2 work for h3.

2. **Move reprovision into `on_flush()`** (alternative, smaller change). Currently the consumed_bufs loop runs in `main()` after `poll()` returns. Move it to the top or bottom of `on_flush` so reprovides are queued before `poll()` returns, and they get submitted in the same `submit_and_wait` cycle. Doesn't fix the syscall round-trip but eliminates the one-poll-cycle delay.

**Concrete verification step (next):** add a `-ENOBUFS` counter to `_handle_recvmsg` (`if result <= 0: enobufs_count += 1`) and a getter to expose it via the SIGINT-driven sidecar. Re-run short-conn capture; if the counter shows hundreds-thousands per second, hypothesis confirmed conclusively.

**Original FFI-dominance synthesis stays valid for steady-state (long-conn) regime** — that's still the next target after the buffer-ring fix lands. But it's a secondary optimization, not the rate-limiter for the 412/1 rps cold-start floor.

**Investigation source (buffer-ring theory):** see Plan C retrospective revised section.

---

## TRUE diagnosis (verified 2026-04-26) — SUPERSEDED, see CORRECTED diagnosis below

The "harness is the bottleneck" claim below ignored cross-client data already in this file (rows 16-28). Both `tquic_client` AND `h2load --h3` drive `tquic_server` to 5-digit rps on the same hardware; both bring `mojo-net` to its knees. The harness *can* saturate. The bottleneck IS in mojo-net. Section preserved verbatim for audit.

---

**The bench harness's calibrated 412 rps long-conn / 1 rps short-conn floor is set by the test harness, NOT by mojo-net's server.**

**Verification:** added six diagnostic counters to `bench/h3_server.mojo` covering every layer where packets could be silently dropped:

```
recvmsg drops (result<=0):       0
multishot terminations:          0
QuicConnection.server errors:    0
H3HandlerServer ctor errors:     0
feed_datagram_from_buffer errs:  0
UdpRcvbufErrors delta over run:  0   (via nstat -az before/after)
```

**Every counter is zero across multiple runs.** The server processes every packet it sees, successfully. No silent drops at any layer.

**What we saw:**
- `tquic_client` reports: 392 conns attempted, 13-21 successful, 277-285 timed out, sent 3228 packets, recv 73
- Server profile reports: 13-21 handshake arrivals (matching tquic_client's success count exactly), n=194-283 packets recorded in `record_pkt`, ~3500-7000 packets entering `pending_rx` (per `pkts_per_flush_histogram` × `on_flush_count`)
- **The discrepancy** between "3228 packets sent by client" and "13-21 distinct conns seen by server" cannot be a server bug — every packet the server sees is processed without error.

**Likely true cause:** `tquic_client` reports "conns attempted" but those conns share a small set of source ports (4 threads × 25 concurrent slots = 100 slots, but ports may be recycled). The server's `addr_key` (src_ip:src_port) demuxes packets correctly per slot, but only 13-21 of the 100 slots manage to complete a handshake within `tquic_client`'s per-slot timeout. The other slots cycle through "open conn → send Initial → wait → timeout → open new conn" multiple times during the 30s window. The "392 conns" count is total attempts across all cycles, but only 100 distinct ports → 100 distinct server-side conns. Of those 100, many never have their Initial fully processed (server queues them in `pending_rx` but processes serially with 50ms timeout-driven cycles between flushes).

**This means:**

1. **mojo-net's per-packet FFI cost (~127us) is NOT the rate-limiter** at the rates this bench tests. At 13-21 conn arrivals / 30s = 0.4-0.7/sec, the server is loafing.
2. **Buffer-ring exhaustion is NOT happening.** io_uring is fine. Kernel UDP buffer is fine.
3. **The calibrated 412/1 rps numbers are test-harness floors, not server-stack floors.** Optimizing the server (batch FFI, multi-fiber fan-out, BufRing port) won't lift these numbers because the harness can't supply the load needed to reveal a server bottleneck.

**To find the actual server limit, the bench harness needs replacing or augmenting.** Options:
- Run multiple parallel `tquic_client` containers (4 × current → ~1600 conn attempts / 30s).
- Switch to a load generator that doesn't have per-slot timeout cycling (e.g., a custom UDP packet replayer that just floods Initials without waiting for responses).
- Profile in production-style traffic (real clients, recorded traces).

**Open question for the next investigation:** is `tquic_client`'s "conns: total 392" really 392 distinct (src_port) values, or does it count each timeout-and-retry cycle? Inspect tquic source. If it's the latter, the server actually saw all 392 distinct source ports and only 21 of them progressed past Initial — which would point at a different (and real) bottleneck. If it's the former, the harness genuinely can't saturate.

**Diagnostic instrumentation committed** (gated as compile-time additions under PROFILE_ACCEPT for now; the `enobufs_count` / `multishot_term_count` / 3 error counters in `_flush_impl` add ~6 UInt64 fields and ~5 increment sites — minimal overhead, useful for future re-investigation).

**Investigation source:** see this session's transcript and `plans/2026-04-26-quic-accept-loop-instrumentation-plan-c-retrospective.md` (re-revised). The diagnostic counters' raw values are inlined in this entry above; the sidecar JSON from the diagnostic run was not exfiltrated separately.

---

## CORRECTED diagnosis (post-debate, 2026-04-26)

**The 412 long-conn / 1 short-conn rps floors are REAL server-side bottlenecks. The harness is fine.**

A multi-subagent debate over which next investigation to pursue surfaced a fact that had been in this file unread: rows 16-28 above already contain N=2 cross-client validation. Same hardware, same network path, same harness orchestration:

| Client | mojo-net long-conn | tquic_server long-conn | mojo-net short-conn | tquic_server short-conn |
|---|---|---|---|---|
| `tquic_client` (4 threads, 25 conns) | 412 | 87,113 (88% CPU on core 0) | 1 | 2,535 |
| `h2load --h3` (single-threaded) | 125 | 32,625 | 11 | 66,023 |

**Both clients drive `tquic_server` into 5-digit rps. Both bring mojo-net to <1% of that.** A harness that can saturate one server but not another is not the bottleneck — the slower server is. The "harness limit" diagnosis was a misread of the data.

**What the 6 zero counters DO and DO NOT prove:**
- They prove: **packets that arrive at the server are processed without error.** No `-ENOBUFS`, no multishot termination, no kernel UDP drops, no QuicConnection construction failure.
- They do NOT prove: that all packets sent by the client arrive in a *timely* manner. The 5-phase per-packet profiler only times packets that successfully reached `record_pkt`. Packets queued in `pending_rx` but processed *after* tquic_client's per-conn timeout fires never accrue an error counter — tquic_client's conn is gone, the packet is processed normally on the server side, and nothing fails.

**Most-likely mechanism (re-instated from the pacer-bypass falsification's deferred next-hypothesis):**

Serial single-fiber `_flush_impl` (`bench/h3_server.mojo:523-600`) processes Initial packets one at a time with ~127us FFI cost per packet on the handshake CRYPTO path. Under saturating-handshake load:
- 100 client slots simultaneously send Initial packets → ~100 packets land in `pending_rx` per CQ wake
- Serial drain at 127us/packet → tail packets wait 100 × 127us = ~12.7 ms before processing
- Layered on top of the 50 ms `submit_timeout` tick cycle and TCP-style RTT estimation in tquic_client, queue tail packets blow past tquic_client's per-conn handshake timeout
- Server eventually processes every packet (zero drops, zero errors); tquic_client has already moved on
- Net: 13-21 of 100 simultaneous handshakes complete; the rest contribute zero rps

This is consistent with every observation: low CPU% (server is blocked on rustls FFI calls, not computing); zero drop counters (every packet IS processed); tquic_server is fine under the same harness (it has a different — likely batched / parallel — accept-loop architecture); h2load shows the same shape with different absolute numbers (single-threaded h2load has a smaller concurrent-handshake burst, so it gets 11 short-conn rps vs tquic_client's 1 — fewer packets contend the serial drain).

**What the existing 5-phase profiler can NOT see:**
- **Per-packet arrival-to-processing latency.** The instrumentation starts the clock at `record_pkt`, not at packet arrival in `pending_rx`. The 127us avg is the *processing* cost; the queueing wait is invisible.
- **Per-conn-id packet counts.** No way to see "this conn-id sent 8 Initials; server processed only 3 before tquic_client timed out."

**Real next investigation (replaces all three previous "next steps"):**

1. **Add arrival-to-processing-latency instrumentation.** In `_handle_recvmsg` / pending_rx queue insertion, stamp each datagram with arrival monotonic_us. In `record_pkt`, record `now - stamp` into a new histogram. Expected signal: under saturating-handshake load, queueing tail >> 12.7 ms.
2. **Add per-conn-id packet counters.** Cheap: a Dict[ConnID, UInt64] incremented at packet-routing time; dump to sidecar on SIGINT. Expected signal: many conn-ids with N≥3 packets but no handshake completion.
3. **THEN** decide between: (a) batch FFI for `quic_conn_read_hs/write_hs/take_keys` to amortize per-call cost across N packets, (b) multi-fiber accept fan-out to parallelize the serial drain, (c) BufRing migration for h3 (lower priority — buffer-ring exhaustion ruled out, but the legacy `IORING_OP_PROVIDE_BUFFERS` path's syscall cost is still real).

**What this debate cost:**
- Three diagnoses committed and superseded: FFI dominance (Plan C C5) → buffer-ring exhaustion (post-Plan-C investigation) → harness limits (commit `8c5325e`).
- Each diagnosis was internally consistent with the data the previous investigation gathered. Each missed data the *previous* one had collected: FFI dominance ignored "99.8% idle"; buffer-ring exhaustion ignored that diagnostic counters disprove kernel-side drops; harness-limits ignored that h2load row 28 already provided cross-client validation.

**Lesson — methodology, not technology:** before each new "TRUE diagnosis" entry, re-read the entire REFERENCE.md and check if the new claim contradicts any *existing* row. Cross-client data, kernel counters, and CPU% measurements live in different sections of the file and were each missed by exactly one investigation. A diagnosis is only as good as the data it integrates.

**Open question (final, this iteration) — required-later, HIGH severity:**

- **What:** Add arrival-to-processing-latency stamps + per-conn-id packet counts to the SIGINT sidecar. Re-run short-conn capture. Expected output: queueing-tail histogram showing P99 ≥ tquic_client's per-conn handshake timeout; per-conn-id counts showing 80+ conn-ids with N≥3 packets but no handshake-complete event.
  **Severity:** required-later (HIGH) — this is the prerequisite for choosing the right cold-start fix.
  **Trigger:** anyone returning to the QUIC perf push.

---

### 2026-04-27 — queueing-tail-instrumentation — DATA — FALSIFIED (queueing-tail) + NEW HYPOTHESIS (addr_key demux collapse)

**Spec:** `specs/2026-04-27-quic-queueing-tail-instrumentation.md`. Plan: `plans/2026-04-27-quic-queueing-tail-instrumentation.md`. Goal: test the queueing-tail hypothesis (most-plausible mechanism after the 4-diagnosis chain on `feat/quic-accept-loop-instrumentation`). Branch: `feat/quic-queueing-tail-instrumentation` off main `3919f7d`.

**Methodology gate satisfied:** re-read all 348 lines of `REFERENCE.md` (rows 1-279 from prior context + rows 280-348 just before drafting). Flagged contradictions: **none** — the "5 distinct addr_keys vs ~392 logical conns" asymmetry seen in this capture is consistent with prior CORRECTED-diagnosis section's note that the server saw "13-21 distinct conns" while tquic_client reported 392 attempts. The new data does not contradict any prior row; it gives the asymmetry quantitative bounds.

**Capture cell:** 1k short-conn, tquic_client (4 threads × 25 max-concurrent-conns × max-requests-per-conn=1), 30s, on-build (PROFILE_ACCEPT=True), manual SIGINT-driven sidecar via `start-server.sh + run-tquic-client.sh + docker kill --signal=SIGINT bench-h3 + docker cp + stop-server.sh`. Smoke gate (T11 long-conn / T12 short-conn) PASS at -2.12% / within-noise drift before this capture.

**Sidecar:** `bench/quic_perf/results/profile/INSTRUMENTATION-20260427-001113-queueing-tail.json`

**tquic_client report (client-side POV):** `conns: total 392, finish 296, success 8, failure 288`.

**Server-side (sidecar):**
- Run wall-clock: 44.94s, 99.9% idle / 0.1% busy (~57ms total work)
- `pkts_per_flush_histogram`: 1=75% / 2-3=14% / 4-7=7% / 8-15=3% / 16-31=1% / 32-63=0.3% / 64-127=0% / 128+=0%
- Per-packet processing (n=163 records, only counts records that hit `record_pkt`): p50=6 p90=92 p99=512us. Drain avg=71us. **shim_ffi avg=187us, sm avg=190us** — FFI/SM still dominate per-packet *processing* cost on the few packets that get processed (consistent with prior FFI-dominance OBSERVATION; not the rate-limiter for the calibrated 1 rps short-conn floor).
- **Handshake accounting: 10 arrivals, 10 successful (100%), 0 timed out.** Latency p50=778us p90=1023us p99/max=29.7ms.
- Plan C diagnostic counters all zero (recvmsg drops, multishot terms, 3 server-side error counters).

**NEW INSTRUMENT 1 — Arrival-to-processing latency (n=3369, overflow=0):**
- `arrival_lat_us_total`: 20,005us (sum across all observations)
- `arrival_lat_us_buckets`: [855, 596, 615, 593, 438, 205, 37, 9, 21, 0, 0, ...0] (24 buckets; non-zero only in buckets 0-8)
- **p50=2us, p90=14us, p99=61us** (computed: bucket 6 [32,64) holds rank 3336/3369; linear-interp at 0.92 of span → 61us).
- Wider distribution: bucket 0 (zero-wait) holds 25% of observations; buckets 0-3 (wait ≤8us) hold 79%.

**NEW INSTRUMENT 2 — Per-conn packet trajectory:**
- `conns_total`: 5 (distinct addr_keys = src_ip:src_port tuples)
- `conns_with_pkts_no_hs_complete`: **0** (every conn the server saw completed its handshake)
- `per_conn_pkts_buckets`: [0, 0, 1, 0, 0, 0, 0, 4] (1 conn in 4-7 pkt range, 4 conns in 128+ range)
- `worst_conns`: `[]` (no non-complete entries to report)

**3-verdict signal table — applied to queueing-tail hypothesis:**
- CONFIRMED if P99 ≥ 1,000,000us (1s) OR overflow ≥ 50% of pkt_count: **NO** (P99=61us; overflow=0)
- FALSIFIED if P99 ≤ 100,000us (100ms): **YES** (61us is 1638× below the FALSIFIED threshold)
- INCONCLUSIVE if 100,000 < P99 < 1,000,000: NO
- Corroboration: `conns_with_pkts_no_hs_complete = 0 ≤ 5` → **weakens hypothesis** (no "received N packets but never completed handshake" population at all)

**Verdict: FALSIFIED for queueing-tail hypothesis.** Server-side serial single-fiber `_flush_impl` queueing is NOT the rate-limiter. Of the packets the server sees, queueing wait is ≤61us at p99 — well within tquic_client's per-conn handshake timeout budget (≥1s).

**NEW HYPOTHESIS surfaced by Instrument 2 — `addr_key` demux collapse via kernel port reuse:**

The striking finding is the asymmetry between client-side and server-side conn counts:

| Side | Count |
|---|---|
| tquic_client logical conn attempts | 392 |
| tquic_client successful (client POV) | 8 |
| tquic_client failed/timed-out | 288 |
| Server distinct addr_keys (`conns_total`) | **5** |
| Server hs_complete (`conns_total - conns_with_pkts_no_hs_complete`) | 5 |
| Server `record_handshake_arrival` count | 10 |

The server saw only 5 distinct (src_ip, src_port) tuples despite the client attempting 392 logical conns. Most logical conns reuse a small set of source ports (kernel ephemeral-port allocation pinning under loopback + Docker network namespace + tquic_client's 4×25 socket pool). When a "new logical conn" arrives at a src_port already mapped in `conn_map` to an existing established `QuicConnection`, the server's `_find_conn(addr_key)` returns the OLD conn. The new Initial gets fed to the wrong connection, which silently rejects it (DCID/SCID mismatch, no server-side error since `feed_datagram_from_buffer_err_count = 0` in this run). The new logical conn never receives an Initial-ACK and times out client-side. From the server's POV everything is fine; from the client's POV, 288 attempts fail.

This explains:
- Why tquic_server (REFERENCE.md row 20) gets 87K rps under the same harness — it has different demux logic (per-CID rather than per-addr_key, presumably).
- Why the server's CPU usage is microscopic (~0.1% busy) — most of those 288 "logical conn" Initials are absorbed by 4-5 active connections that discard them in microseconds.
- Why the "FFI dominance" observation in Plan C C3 (sm avg=129us, shim_ffi avg=127us on 233 packets) was real but irrelevant: those costs apply to the few packets that reach successful processing; the overwhelming majority of "failed" client conns never trigger meaningful server work.

**Caveat:** this captured arrival pattern is `tquic_client`-specific. `h2load --h3` (REFERENCE.md row 28) drives different absolute numbers (mojo-net 11 short-conn rps vs tquic_client's 1) — could indicate h2load uses different source-port allocation strategy and would expose the demux-collapse problem differently. A follow-up h2load capture is warranted before assuming the addr_key-collapse is universal.

**Next hypothesis (post-FALSIFIED verdict — required-later, HIGH severity):**

- **What:** Verify the `addr_key` demux collapse hypothesis. Two sub-questions:
  1. **Diagnostic:** Add a per-flush counter tracking how often `_find_conn(pd.addr_key)` returns an existing `conn_idx` whose state is `is_established()=True` AND the incoming packet is an Initial (long-header type 0). Each such "Initial-on-established-addr_key" event is a logical conn that the server is silently absorbing into a wrong destination. Expected: hundreds/thousands per 30s short-conn run.
  2. **Mechanistic:** Switch the demux from `addr_key` (src_ip:src_port) to `dcid` (destination connection ID, already extracted at `_handle_recvmsg`). DCIDs are minted per-conn by the client and don't collide on port reuse. This is the change tquic_server presumably has. Estimated scope: ~50-100 LoC in `bench/h3_server.mojo` `conn_map` + `_find_conn` + `_handle_recvmsg`. Not in scope for any current spec — would need its own brainstorm + plan.
  **Severity:** required-later (HIGH) — this is the prerequisite for choosing whether mojo-net's bottleneck is fundamentally architectural (demux design) vs micro-optimizable (FFI batching, multi-fiber).
  **Trigger:** anyone returning to the QUIC perf push.

**Off-build flag confirmed:** `comptime PROFILE_ACCEPT: Bool = False` at `src/quic/profile.mojo:16` post-capture. Smoke gate doc at `bench/quic_perf/results/profile/T11_T12_smoke_gate_2026-04-27.md`.

**Diagnostic counters left in place** (all six, plus the new arrival-latency + per-conn instruments). Off-build cost: zero (PROFILE_ACCEPT-gated everywhere).

---

### 2026-04-26 — accept-loop-instrumentation-data-collection — DATA (steady-state only, B14)

**Spec:** `specs/2026-04-25-quic-accept-loop-instrumentation.md`. Goal:
distinguish three suspects (fan-out / per-packet cost / FFI-AEAD-SM
decomposition) for the 412 req/s cold-start floor on
`bench.sh mojo-net 1k long-conn tquic_client`.

**On-build single-cell capture (1k long-conn, 30s window, SIGINT-driven sidecar):**

| Metric | Value |
|---|---|
| pkts_per_flush weighted-mean | 2.47 |
| pkts_per_flush bucket dist | size=1: 59.3% / size=2-3: 30.0% / size=4-7: 7.0% / size=8-15: 2.1% / size=16-31: 1.4% / size=32-63: 0.3% / size=64-127: 0.1% / size=128+: 0% |
| per_pkt_us.total p50 / p90 / p99 | 15 / 29 / 57 |
| shim_ffi avg | 7 us |
| aead avg | 0 us (sub-us — bucket=0) |
| header_parse avg | 0 us (sub-us) |
| hp avg | 0 us (sub-us) |
| frame_parse avg | 11 us |
| sm avg | 8 us (overlaps shim_ffi as inner sub-budget) |
| residual avg | 0 us (sub-us) |
| drain avg (bench TX path) | 31 us |
| arrivals / successful / timed_out | 5 / 5 / 0 (100% success) |
| handshake latency p50 / p90 / p99 / max | 1,348 / 29,477 / 29,477 / 29,477 us |
| Run wall-clock / on_flush events | 38.37 s / 3,504 |
| Idle vs busy | 97.5% idle / 2.5% busy |

**Spec ≥2× signal table — applied:**
- `shim_ffi.avg=7 ≥ 2 × frame_parse.avg=11`? **NO** (0.6×). FFI dominance NOT confirmed.
- `aead.avg=0 ≥ 2 × frame_parse.avg=11`? **NO**. AEAD dominance NOT confirmed.
- `sm.avg=8 ≥ 2 × frame_parse.avg=11` (excluding shim_ffi as overlap)? **NO** (0.7×). SM dominance NOT confirmed.
- `pkts_per_flush weighted-mean=2.47 ≥ 8`? **NO** (0.31×). Fan-out dominance NOT confirmed.

**No single in-recv leg dominates.** The bench-side `drain` leg (31 us avg, 2.8× frame_parse) is the largest per-packet wall-clock contributor, but `drain` covers the full TX path (response generation + outgoing AEAD + io_uring sendmsg queue) and is expected to dominate steady-state.

**Critical caveat — this run did NOT reproduce the cold-start floor.**
Only **5** handshakes arrived in 30 s (vs the calibrated baseline's "~400 attempts → 3-10 successes" pattern with 99% timeouts). With `tquic_client --max-concurrent-conns=25 --duration=30` in long-conn mode, the client opened 5 long-lived connections and pumped streams through them rather than constantly reconnecting. Steady-state stream serving dominates; the saturating-handshake load that produced the 412 req/s + 99% timeout floor in `2026-04-25 — pacer-bypass-during-handshake — FALSIFIED` did not manifest here.

The handshake-latency tail IS suggestive: `p50=1.3ms` vs `p99/max=29ms` (n=5) — the first arriving connection paid the Initial-key-derivation bleed-in cost (Plan B's `profile_first_iter_done` semantic harvesting it on iter 1). But n=5 is too small to draw conclusions.

**Sidecar JSON:** `bench/quic_perf/results/profile/INSTRUMENTATION-20260426-183256.json` (committed).

**On-build overhead drift (B13 single-cell smoke gate, separate run):** −0.40% (on-build 413.46 rps median vs off-build 411.83 rps median; within run-to-run noise — the spec's ≤10% budget is satisfied with ~25× headroom).

**Methodology note:** Full bench-mvp matrix (~50 min, 24 cells) skipped per Plan B option B. B13 already validated the overhead budget on the load-bearing cell at −0.40%; the 7 other matrix cells re-confirm the same drift property without new diagnostic value. The dominant-cost identification was meant to come from the sidecar's per-packet decomposition, but **the single 30 s long-conn capture does not exercise the cold-start path** that motivated the spec.

**Next hypothesis (revised — required-later, severity: high):**
1. **Re-capture under cold-start saturation.** Run `tquic_client` with `short-conn` scenario (forces frequent reconnect) AND/OR raise `--max-concurrent-conns` from 25 to 100+ to force the saturating-handshake regime. The resulting sidecar should show much higher `arrivals` (closer to 100/s) and lower `successful` rate — that's the regime the spec was designed to characterise. Trigger: anyone returning to the QUIC perf push.
2. **In the meantime,** the steady-state data above stands as a baseline: per-packet RX is fast (~15 us p50 total), fan-out is low (~2.5 mean), no in-recv leg dominates. If saturating-handshake re-runs ALSO show no in-recv dominance, the bottleneck is elsewhere — most plausibly in `_drain_and_send` or downstream of it (response generation, outgoing AEAD throughput, or sendmsg queue depth).
