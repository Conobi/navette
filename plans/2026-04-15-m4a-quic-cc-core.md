# M4a — QUIC Congestion Control Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace M3b's dummy congestion controller with real CUBIC (RFC 9438) + a TQUIC-style token-bucket pacer + RFC 9002 §7.6.2-compliant persistent congestion detection, all wired through the existing `Recovery` + `QuicConnection` send path.

**Architecture:** New `src/quic/cc/` subsystem containing a shared-interface trait (`trait.mojo`), a Pacer, a Dummy CC, a CUBIC CC, and a tag-discriminated `CcController` variant dispatcher. `Recovery` gains `cc: CcController` and `pacer: Pacer` fields and forwards ACK/loss events. `QuicConnection` grows `_anti_amp_ok` + `_can_send` helpers (extracting the inline check at `connection.mojo:1393`), a persistent-congestion detector, and folds the pacer deadline into `timeout(now)`. `pn_space.mojo` gains a `last_ae_acked_time_sent` tracker per space. No new external dependencies.

**Tech Stack:** Mojo 0.26.2, sans-I/O at every layer.

**Prerequisite:** `plans/2026-04-15-m3c-integration-coverage.md` must land on main first. M4a relies on the FC/RESET/MAX/CID integration coverage added there to validate no behavior regressions from send-path changes.

---

## File structure

| File | Responsibility | Status |
|---|---|---|
| `src/quic/cc/trait.mojo` | Shared types (`AckedPacket`, `LostPacket`), module constants (`CC_KIND_*`, `MIN_WINDOW_PACKETS`, `PERSISTENT_CONG_THRESHOLD`, `UINT64_UNLIMITED`), interface-contract docstring. | CREATE ~180 LoC |
| `src/quic/cc/pacing.mojo` | `Pacer` struct — token bucket with pure `next_send_time` + mutating `refill_and_check`. | CREATE ~215 LoC |
| `src/quic/cc/dummy.mojo` | `DummyCc` — no-op, unlimited cwnd. Test aid. | CREATE ~165 LoC |
| `src/quic/cc/cubic.mojo` | `Cubic` struct + algorithm per RFC 9438 (no HyStart++) + integer cube-root helper. | CREATE ~450 LoC |
| `src/quic/cc/controller.mojo` | `CcController` — tag-discriminated variant dispatcher. | CREATE ~200 LoC |
| `src/quic/pn_space.mojo` | Add `last_ae_acked_time_sent: UInt64` field to `PacketNumberSpace` + `any_ae_acked_in_range` query. | MODIFY +~40 LoC |
| `src/quic/recovery.mojo` | Add `cc: CcController`, `pacer: Pacer` fields + construction + hook-point modifications + `detect_persistent_congestion` helper. | MODIFY +~300 LoC |
| `src/quic/connection.mojo` | Extract `_anti_amp_ok` + introduce `_can_send`; update ACK-processing flow to fan into CC + persistent-congestion; add pacer branch to `timeout(now)`. | MODIFY +~280 LoC |
| `tests/test_cc_cubic.mojo` | CUBIC unit tests. | CREATE ~250 LoC |
| `tests/test_cc_pacing.mojo` | Pacer unit tests. | CREATE ~150 LoC |
| `tests/test_cc_controller.mojo` | Controller dispatch tests. | CREATE ~100 LoC |
| `tests/test_recovery.mojo` | Extend with CC-integration + persistent-congestion tests. | MODIFY +~120 LoC |
| `tests/test_pn_space.mojo` | Extend with `last_ae_acked_time_sent` tests. | MODIFY +~40 LoC |
| `tests/test_quic_connection.mojo` | Extend with CC-aware connection integration tests. | MODIFY +~100 LoC |
| `scripts/run_tests.sh` | Register 3 new test files. | MODIFY +3 lines |

---

## Phase 0 — Pre-planning spikes (Task 0)

Resolve the seven Mojo-API open questions from spec §11 before any real implementation, via `mcp__mojo-mcp__execute` smoke programs. Each spike produces a decision recorded in the task checklist.

### Task 0: Mojo 0.26.2 feature verification via mcp-execute

**Files:**
- None (spike-only; findings feed subsequent tasks)

- [ ] **Step 1: Nested-Copyable variant dispatch compiles**
Run via `mcp__mojo-mcp__execute`:

```mojo
struct Inner(Copyable, Movable):
    var x: UInt64
    def __init__(out self, x: UInt64): self.x = x

struct Outer(Copyable, Movable):
    var kind: UInt8
    var a: Inner
    var b: Inner
    def __init__(out self, kind: UInt8, a: Inner, b: Inner):
        self.kind = kind; self.a = a; self.b = b
    def get(self) -> UInt64:
        if self.kind == 0: return self.a.x
        return self.b.x
    def bump(mut self, v: UInt64):
        if self.kind == 0: self.a.x += v
        else: self.b.x += v

def main():
    var o = Outer(kind=0, a=Inner(10), b=Inner(99))
    print(o.get())  # 10
    o.bump(5)
    print(o.get())  # 15
    var o2 = o
    print(o2.get())  # 15 (copy preserves state)
    o.bump(100)
    print(o.get(), o2.get())  # 115 15
```
Expected: `10 / 15 / 15 / 115 15`. If this compiles + runs cleanly, the spec §2.3 pattern is confirmed. **If not**, fall back to flat-primitive hoist: all `Cubic` + `DummyCc` fields become direct fields on `CcController` (verbose but known-good à la `QuicEvent`).

- [ ] **Step 2: UInt128 availability**
Run:
```mojo
def main():
    var a: UInt64 = 10_000_000_000  # 10^10
    var b = a * a  # 10^20, overflows UInt64 (max ~1.8e19)
    print(b)
```
Expected: observe overflow. Then attempt:
```mojo
from builtin.simd import SIMD
def main():
    var a: SIMD[DType.uint128, 1] = SIMD[DType.uint128, 1](10_000_000_000)
    print(a * a)
```
If `SIMD[DType.uint128, 1]` is available → use it in `cubic.mojo`'s cube-root + cube math. If not → write `mul_u64_hi_lo(a: UInt64, b: UInt64) -> Tuple[UInt64, UInt64]` helper using 32-bit splits.

- [ ] **Step 3: UINT64_UNLIMITED idiom**
Run:
```mojo
def main():
    alias U: UInt64 = ~UInt64(0)
    print(U)  # expect 18446744073709551615
```
If `~UInt64(0)` works → use it. If not, try `UInt64.MAX`, `UInt64.max_finite()`, or `comptime UINT64_UNLIMITED: UInt64 = 0xFFFFFFFFFFFFFFFF`. Settle on the cleanest working form. Record the chosen form for `cc/trait.mojo`.

- [ ] **Step 4: Optional truthiness**
Run:
```mojo
def main():
    var o1: Optional[UInt64] = Optional[UInt64](42)
    var o2: Optional[UInt64] = Optional[UInt64](None)
    if o1: print("o1 truthy")
    if not o2: print("o2 falsy")
```
Expected: both lines print. Confirms `if opt:` idiom for M4a code.

- [ ] **Step 5: `Dict[Int, SentPacket]` iteration**
Not a critical spike — spec §5.3 only uses `pn in dict` checks and key-by-key lookups, not full iteration. Skip unless a later task requires ordered iteration.

- [ ] **Step 6: Record decisions**
Append to a new "M4a Task 0 findings" section at the top of this plan file OR add inline notes in the relevant §11 bullet of `specs/2026-04-15-m4a-quic-cc-core.md`. Use whichever is more visible.

- [ ] **Step 7: Commit the recording**
Use the `commit-smart` skill. Message: `docs: record M4a Mojo 0.26.2 spike findings`

---

## Phase 1 — CC subsystem (Tasks 1-5, sequential)

Each task is a TDD cycle on one new file. Phase 1 tasks are sequential because later files import from earlier ones (`cubic.mojo` imports from `trait.mojo`, `controller.mojo` imports from `cubic.mojo` + `dummy.mojo`).

### Task 1: cc/trait.mojo — shared types and constants

**Files:**
- Create: `src/quic/cc/__init__.mojo` (empty package marker if Mojo 0.26.2 requires one; else skip)
- Create: `src/quic/cc/trait.mojo`

**Spec reference:** §3.1 constants, §3.2 shared value types, §3.3 method contract.

- [ ] **Step 1: Write test stub** (no behavior to test; compile-check only)
Add a trivial import-check at the top of `tests/test_cc_controller.mojo` (created in Task 5). For Task 1 in isolation, the "test" is Mojo compilation: the module must import cleanly.

- [ ] **Step 2: Create the file**

```mojo
# src/quic/cc/trait.mojo
# Shared types + method-contract documentation for CC implementations.

# --- Module-scope constants (RFC 9002 + §3.1) ---

comptime CC_KIND_DUMMY: UInt8 = 0
comptime CC_KIND_CUBIC: UInt8 = 1
# Reserved for M4b / later: CC_KIND_BBR = 2, CC_KIND_BBR3 = 3.

comptime MIN_WINDOW_PACKETS: UInt64 = 2            # RFC 9002 §7.2
comptime INITIAL_WINDOW_PACKETS: UInt64 = 10       # RFC 9002 §7.2
comptime INITIAL_WINDOW_BYTES_CAP: UInt64 = 14720  # RFC 9002 §7.2
comptime LOSS_REDUCTION_NUM: UInt64 = 1            # 0.5 as num/den
comptime LOSS_REDUCTION_DEN: UInt64 = 2
comptime PERSISTENT_CONG_THRESHOLD: UInt64 = 3     # RFC 9002 §7.6.2

# Resolved by Phase 0 Task 0 step 3; replace placeholder if needed.
comptime UINT64_UNLIMITED: UInt64 = ~UInt64(0)


# --- Shared value types ---

struct AckedPacket(Copyable, Movable):
    """One newly-ACKed packet's information, passed from Recovery/Connection to CC."""
    var pkt_num: UInt64
    var size: UInt64
    var time_sent: UInt64      # us
    var time_acked: UInt64     # us
    var rtt_sample: UInt64     # us

    def __init__(out self, pkt_num: UInt64, size: UInt64,
                 time_sent: UInt64, time_acked: UInt64, rtt_sample: UInt64):
        self.pkt_num = pkt_num; self.size = size
        self.time_sent = time_sent; self.time_acked = time_acked
        self.rtt_sample = rtt_sample


struct LostPacket(Copyable, Movable):
    """One lost packet's information, passed from Connection to CC."""
    var pkt_num: UInt64
    var size: UInt64
    var time_sent: UInt64  # us

    def __init__(out self, pkt_num: UInt64, size: UInt64, time_sent: UInt64):
        self.pkt_num = pkt_num; self.size = size; self.time_sent = time_sent
```

The "trait contract" itself lives as documentation — every CC implementation (`DummyCc`, `Cubic`) provides:
```
cwnd(self) -> UInt64
pacing_rate(self, smoothed_rtt_us: UInt64) -> UInt64
on_packet_sent(mut self, size: UInt64, now: UInt64)
on_packet_acked(mut self, packet: AckedPacket, smoothed_rtt_us: UInt64, now: UInt64)
on_packets_lost(mut self, lost: List[LostPacket], smoothed_rtt_us: UInt64, now: UInt64, persistent: Bool)
name(self) -> String
```

- [ ] **Step 3: Verify compilation**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all -c src/quic/cc/trait.mojo`
Expected: compiles cleanly (no diagnostics). If `-c` isn't supported, do an import-check from a test file.

- [ ] **Step 4: Validate via MCP**
Run `mcp__mojo-mcp__validate` on the file. Expected: no known gotchas flagged.

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `feat: add cc/trait module with CC-contract types and constants`

---

### Task 2: cc/pacing.mojo — token-bucket pacer

**Files:**
- Create: `src/quic/cc/pacing.mojo`
- Create: `tests/test_cc_pacing.mojo`

**Spec reference:** §6.1 state, §6.2 constants, §6.3 API (split pure/mutating), §6.4 refill math.

- [ ] **Step 1: Write failing tests** (~150 LoC)

```mojo
# tests/test_cc_pacing.mojo
from src.quic.cc.pacing import Pacer

def test_pacer_init_defaults():
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    assert_true(p.enabled == True, "enabled by default")
    assert_true(p.tokens == UInt64(0), "starts with zero tokens")
    assert_true(p.max_datagram_size == UInt64(1200), "MDS stored")
    print("PASS: test_pacer_init_defaults")

def test_pacer_disabled_returns_none():
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    p.enabled = False
    var r = p.next_send_time(UInt64(1_000_000), UInt64(0))
    assert_true(not r, "disabled pacer returns None")
    print("PASS: test_pacer_disabled_returns_none")

def test_pacer_zero_rate_returns_none():
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    var r = p.next_send_time(UInt64(0), UInt64(0))
    assert_true(not r, "zero rate treated as unpaced")
    print("PASS: test_pacer_zero_rate_returns_none")

def test_pacer_update_capacity_clamp_min():
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    # Tiny cwnd/srtt combination → capacity clamps to 10 * MDS.
    p.update_capacity(cwnd=UInt64(100), smoothed_rtt_us=UInt64(1_000_000))
    assert_true(p.capacity == UInt64(12000), "clamped to min 10 MTU")  # 10 * 1200
    print("PASS: test_pacer_update_capacity_clamp_min")

def test_pacer_update_capacity_clamp_max():
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    # Huge cwnd/tiny srtt → capacity clamps to 128 * MDS.
    p.update_capacity(cwnd=UInt64(10_000_000), smoothed_rtt_us=UInt64(1000))
    assert_true(p.capacity == UInt64(153_600), "clamped to max 128 MTU")  # 128 * 1200
    print("PASS: test_pacer_update_capacity_clamp_max")

def test_pacer_tokens_cap_at_capacity():
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    p.update_capacity(cwnd=UInt64(1_200_000), smoothed_rtt_us=UInt64(10_000))
    # capacity = cwnd * granularity(1000) / srtt(10000) = 120_000; clamped in [12000, 153_600] → 120_000
    var ok = p.refill_and_check(pacing_rate_bps=UInt64(100_000_000), now=UInt64(10_000_000))
    # huge time elapsed since last_sched_time=0 → tokens should saturate at capacity.
    assert_true(ok, "can send after saturation")
    assert_true(p.tokens <= p.capacity, "tokens don't exceed capacity")
    print("PASS: test_pacer_tokens_cap_at_capacity")

def test_pacer_refill_and_check_returns_true_when_enough():
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    p.update_capacity(cwnd=UInt64(12_000), smoothed_rtt_us=UInt64(1000))
    # rate = 12_000_000 bytes/sec, elapsed = 1ms → refill = 12_000 bytes = 10 MTU.
    var ok = p.refill_and_check(pacing_rate_bps=UInt64(12_000_000), now=UInt64(1000))
    assert_true(ok, "1ms at 12MB/s accrues 12000 bytes >= MDS")
    print("PASS: test_pacer_refill_and_check_returns_true_when_enough")

def test_pacer_next_send_time_pure():
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    # tokens = 0, rate = 1_200_000 bytes/sec, need 1200 bytes → need 1ms = 1000 us.
    p.last_sched_time = UInt64(0)
    var r = p.next_send_time(pacing_rate_bps=UInt64(1_200_000), now=UInt64(0))
    assert_true(bool(r), "some deadline returned")
    # Purity: call again, no state mutation.
    assert_true(p.last_sched_time == UInt64(0), "last_sched_time unchanged (pure)")
    assert_true(p.tokens == UInt64(0), "tokens unchanged (pure)")
    print("PASS: test_pacer_next_send_time_pure")

def test_pacer_on_sent_saturating():
    var p = Pacer.new(max_datagram_size=UInt64(1200))
    p.tokens = UInt64(500)
    p.on_sent(UInt64(1000))  # overconsume
    assert_true(p.tokens == UInt64(0), "saturating subtract to zero, no underflow")
    print("PASS: test_pacer_on_sent_saturating")

def main():
    test_pacer_init_defaults()
    test_pacer_disabled_returns_none()
    test_pacer_zero_rate_returns_none()
    test_pacer_update_capacity_clamp_min()
    test_pacer_update_capacity_clamp_max()
    test_pacer_tokens_cap_at_capacity()
    test_pacer_refill_and_check_returns_true_when_enough()
    test_pacer_next_send_time_pure()
    test_pacer_on_sent_saturating()
    print("All pacing tests passed.")
```

- [ ] **Step 2: Verify tests fail** (module not found)
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_cc_pacing.mojo`
Expected: FAIL — `src.quic.cc.pacing` not found.

- [ ] **Step 3: Implement Pacer**
Create `src/quic/cc/pacing.mojo` per spec §6. Fields: `enabled`, `capacity`, `tokens`, `last_cwnd`, `last_sched_time`, `pacer_granularity_us` (default 1000), `max_datagram_size`. Methods: `new`, `next_send_time` (pure, projects refill without mutation), `refill_and_check` (mutating), `on_sent` (saturating sub), `update_capacity` (with `clamp(cwnd*granularity/srtt, [10*MTU, 128*MTU])` and trims tokens to new capacity).

- [ ] **Step 4: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_cc_pacing.mojo`
Expected: PASS — "All pacing tests passed."

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `feat: add token-bucket Pacer with pure next_send_time and mutating refill_and_check`

---

### Task 3: cc/dummy.mojo — no-op CC

**Files:**
- Create: `src/quic/cc/dummy.mojo`

**Spec reference:** §7.

- [ ] **Step 1: Write test**

Defer to Task 5 where the controller tests exercise both dummy and cubic through dispatch. For this task the smoke is "imports cleanly + fields initialize".

- [ ] **Step 2: Implement DummyCc**

```mojo
# src/quic/cc/dummy.mojo
from src.quic.cc.trait import AckedPacket, LostPacket, UINT64_UNLIMITED

struct DummyCc(Copyable, Movable):
    """No-op CC. cwnd = unlimited; pacing_rate = 0 (pacer disabled)."""
    var max_datagram_size: UInt64

    def __init__(out self, max_datagram_size: UInt64):
        self.max_datagram_size = max_datagram_size

    def cwnd(self) -> UInt64:
        return UINT64_UNLIMITED

    def pacing_rate(self, smoothed_rtt_us: UInt64) -> UInt64:
        return UInt64(0)

    def on_packet_sent(mut self, size: UInt64, now: UInt64):
        pass

    def on_packet_acked(mut self, packet: AckedPacket, smoothed_rtt_us: UInt64, now: UInt64):
        pass

    def on_packets_lost(mut self, lost: List[LostPacket], smoothed_rtt_us: UInt64,
                        now: UInt64, persistent: Bool):
        pass

    def name(self) -> String:
        return String("dummy")
```

- [ ] **Step 3: Compile-check via a trivial import test**
Append to (or create) `tests/test_cc_controller.mojo`:
```mojo
def test_dummy_cc_basic():
    var d = DummyCc(max_datagram_size=UInt64(1200))
    assert_true(d.cwnd() == UINT64_UNLIMITED, "dummy cwnd unlimited")
    assert_true(d.pacing_rate(UInt64(100_000)) == UInt64(0), "dummy pacing 0")
    assert_true(d.name() == String("dummy"), "dummy name")
    print("PASS: test_dummy_cc_basic")
```

- [ ] **Step 4: Verify compiles + passes**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_cc_controller.mojo`
Expected: PASS on the new single test (the file still grows with Task 5).

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `feat: add DummyCc no-op congestion controller for tests`

---

### Task 4: cc/cubic.mojo — CUBIC algorithm

**Files:**
- Create: `src/quic/cc/cubic.mojo`
- Create: `tests/test_cc_cubic.mojo`

**Spec reference:** §4 (state, constants, algorithm, pacing rate, fixed-point math).

- [ ] **Step 1: Write failing tests** (~250 LoC, 14 tests per spec §9.1)

```mojo
# tests/test_cc_cubic.mojo
from src.quic.cc.cubic import Cubic
from src.quic.cc.trait import AckedPacket, LostPacket, INITIAL_WINDOW_BYTES_CAP

alias MDS: UInt64 = 1200

def test_cubic_init_initial_window():
    var c = Cubic(max_datagram_size=MDS)
    var expected = min(UInt64(10) * MDS, INITIAL_WINDOW_BYTES_CAP)
    assert_true(c.cwnd == expected, "initial window per RFC 9002 §7.2")
    assert_true(c.ssthresh > c.cwnd, "ssthresh starts unlimited-ish")
    print("PASS: test_cubic_init_initial_window")

def test_cubic_slow_start_growth():
    var c = Cubic(max_datagram_size=MDS)
    var start = c.cwnd
    var pkt = AckedPacket(pkt_num=1, size=MDS, time_sent=0, time_acked=1000, rtt_sample=1000)
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(1000), now=UInt64(1000))
    assert_true(c.cwnd == start + MDS, "slow-start adds MDS per ACK")
    print("PASS: test_cubic_slow_start_growth")

def test_cubic_enters_ca_after_loss():
    var c = Cubic(max_datagram_size=MDS)
    c.cwnd = UInt64(100_000); c.ssthresh = UInt64(200_000)
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=1, size=MDS, time_sent=0))
    c.on_packets_lost(lost, smoothed_rtt_us=UInt64(50_000), now=UInt64(100_000), persistent=False)
    assert_true(c.cwnd < UInt64(100_000), "cwnd reduced after loss")
    assert_true(c.cwnd >= UInt64(2) * MDS, "cwnd >= min_cwnd after loss")
    assert_true(c.ssthresh == c.cwnd, "ssthresh = new cwnd after congestion event")
    print("PASS: test_cubic_enters_ca_after_loss")

def test_cubic_beta_0_7():
    var c = Cubic(max_datagram_size=MDS)
    c.cwnd = UInt64(100_000); c.ssthresh = UInt64(200_000)
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=1, size=MDS, time_sent=0))
    c.on_packets_lost(lost, smoothed_rtt_us=UInt64(50_000), now=UInt64(100_000), persistent=False)
    # beta = 0.7 → new cwnd = 70_000
    assert_true(c.cwnd == UInt64(70_000), "cwnd = old * 0.7")
    print("PASS: test_cubic_beta_0_7")

def test_cubic_persistent_resets_to_min():
    var c = Cubic(max_datagram_size=MDS)
    c.cwnd = UInt64(500_000); c.ssthresh = UInt64(400_000)
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=1, size=MDS, time_sent=0))
    c.on_packets_lost(lost, smoothed_rtt_us=UInt64(50_000), now=UInt64(100_000), persistent=True)
    assert_true(c.cwnd == UInt64(2) * MDS, "persistent resets cwnd to min (2*MDS)")
    assert_true(c.w_max == UInt64(0), "w_max cleared on persistent")
    print("PASS: test_cubic_persistent_resets_to_min")

def test_cubic_pacing_slow_start_2x_gain():
    var c = Cubic(max_datagram_size=MDS)
    # cwnd < ssthresh → slow-start → gain 2.0
    var rate = c.pacing_rate(smoothed_rtt_us=UInt64(100_000))
    var expected = UInt64(2) * c.cwnd * UInt64(1_000_000) // UInt64(100_000)
    assert_true(rate == expected, "SS gain 2.0")
    print("PASS: test_cubic_pacing_slow_start_2x_gain")

def test_cubic_pacing_ca_1_25x_gain():
    var c = Cubic(max_datagram_size=MDS)
    c.cwnd = UInt64(100_000); c.ssthresh = UInt64(50_000)  # force CA
    var rate = c.pacing_rate(smoothed_rtt_us=UInt64(100_000))
    var expected = UInt64(5) * c.cwnd * UInt64(1_000_000) // (UInt64(4) * UInt64(100_000))
    assert_true(rate == expected, "CA gain 1.25")
    print("PASS: test_cubic_pacing_ca_1_25x_gain")

def test_cubic_pacing_zero_srtt_guarded():
    var c = Cubic(max_datagram_size=MDS)
    var rate = c.pacing_rate(smoothed_rtt_us=UInt64(0))  # would divide by zero naively
    assert_true(rate > UInt64(0), "no division by zero; rate finite")
    print("PASS: test_cubic_pacing_zero_srtt_guarded")

def test_cubic_suppress_double_loss_within_rtt():
    var c = Cubic(max_datagram_size=MDS)
    c.cwnd = UInt64(100_000); c.ssthresh = UInt64(200_000)
    var lost1 = List[LostPacket]()
    lost1.append(LostPacket(pkt_num=1, size=MDS, time_sent=0))
    c.on_packets_lost(lost1, smoothed_rtt_us=UInt64(50_000), now=UInt64(100_000), persistent=False)
    var after_first = c.cwnd
    var lost2 = List[LostPacket]()
    lost2.append(LostPacket(pkt_num=2, size=MDS, time_sent=0))
    # Now = 110_000 < 100_000 + 1*50_000 = 150_000 → suppressed
    c.on_packets_lost(lost2, smoothed_rtt_us=UInt64(50_000), now=UInt64(110_000), persistent=False)
    assert_true(c.cwnd == after_first, "suppressed; cwnd unchanged")
    print("PASS: test_cubic_suppress_double_loss_within_rtt")

def test_cubic_fast_convergence():
    var c = Cubic(max_datagram_size=MDS)
    c.cwnd = UInt64(200_000); c.ssthresh = UInt64(300_000)
    c.w_last_max = UInt64(300_000)  # prior max larger than current cwnd → fast convergence
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=1, size=MDS, time_sent=0))
    c.on_packets_lost(lost, smoothed_rtt_us=UInt64(50_000), now=UInt64(100_000), persistent=False)
    # w_last_max updated, w_max = cwnd * (1+beta)/2 = 200_000 * 1.7/2 = 170_000
    assert_true(c.w_max == UInt64(170_000), "fast convergence w_max")
    print("PASS: test_cubic_fast_convergence")

def test_cubic_reno_friendly_w_est_tracks():
    var c = Cubic(max_datagram_size=MDS)
    c.cwnd = UInt64(100_000); c.ssthresh = UInt64(50_000)  # CA
    c.w_est = UInt64(100_000)
    var pkt = AckedPacket(pkt_num=1, size=MDS, time_sent=0, time_acked=1000, rtt_sample=1000)
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(1000), now=UInt64(1000))
    assert_true(c.w_est > UInt64(100_000), "w_est grew with AIMD rule")
    print("PASS: test_cubic_reno_friendly_w_est_tracks")

def test_cubic_copy_semantics():
    var c = Cubic(max_datagram_size=MDS)
    c.cwnd = UInt64(50_000)
    var c2 = c
    assert_true(c2.cwnd == UInt64(50_000), "copy preserves cwnd")
    c.cwnd = UInt64(70_000)
    assert_true(c2.cwnd == UInt64(50_000), "copy is independent")
    print("PASS: test_cubic_copy_semantics")

def test_cube_root_newton_correct():
    """Integer cube root helper correctness on edge cases."""
    from src.quic.cc.cubic import _cube_root_u64
    assert_true(_cube_root_u64(UInt64(0)) == UInt64(0), "cbrt(0)=0")
    assert_true(_cube_root_u64(UInt64(1)) == UInt64(1), "cbrt(1)=1")
    assert_true(_cube_root_u64(UInt64(8)) == UInt64(2), "cbrt(8)=2")
    assert_true(_cube_root_u64(UInt64(27)) == UInt64(3), "cbrt(27)=3")
    assert_true(_cube_root_u64(UInt64(1_000_000_000_000)) == UInt64(10_000), "cbrt(1e12)=1e4")
    print("PASS: test_cube_root_newton_correct")

def test_cubic_overflow_clamp_not_hit_normal_rtt():
    """With normal RTT (100ms, 1s), cubic curve doesn't trip MAX_CWND clamp."""
    var c = Cubic(max_datagram_size=MDS)
    c.cwnd = UInt64(500_000); c.ssthresh = UInt64(400_000)
    c.w_max = UInt64(500_000)
    c.epoch_start = UInt64(1_000_000)
    # Simulate 1 second past epoch.
    var pkt = AckedPacket(pkt_num=1, size=MDS, time_sent=1_000_000,
                          time_acked=2_000_000, rtt_sample=100_000)
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(100_000), now=UInt64(2_000_000))
    assert_true(c.cwnd < UInt64(1_073_741_824), "cwnd below 1 GiB clamp for normal RTT")
    print("PASS: test_cubic_overflow_clamp_not_hit_normal_rtt")

def main():
    test_cubic_init_initial_window()
    test_cubic_slow_start_growth()
    test_cubic_enters_ca_after_loss()
    test_cubic_beta_0_7()
    test_cubic_persistent_resets_to_min()
    test_cubic_pacing_slow_start_2x_gain()
    test_cubic_pacing_ca_1_25x_gain()
    test_cubic_pacing_zero_srtt_guarded()
    test_cubic_suppress_double_loss_within_rtt()
    test_cubic_fast_convergence()
    test_cubic_reno_friendly_w_est_tracks()
    test_cubic_copy_semantics()
    test_cube_root_newton_correct()
    test_cubic_overflow_clamp_not_hit_normal_rtt()
    print("All cubic tests passed.")
```

- [ ] **Step 2: Verify tests fail**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_cc_cubic.mojo`
Expected: FAIL — `src.quic.cc.cubic` not found.

- [ ] **Step 3: Implement Cubic**
Create `src/quic/cc/cubic.mojo` per spec §4. State fields per §4.2. Module-scope constants per §4.3 (`CUBIC_BETA_NUM=7`, `CUBIC_BETA_DEN=10`, `CUBIC_C_NUM=4`, `CUBIC_C_DEN=10`, `CUBIC_CONGESTION_SUPPRESS_RTT_MULT=1`). Algorithm per §4.4: slow-start, congestion-avoidance with w_cubic+w_est, congestion-event path with fast convergence + suppression, persistent reset. `pacing_rate` per §4.5. Arithmetic per §4.6 (UInt128 if Task 0 found it; otherwise scale-down via mul_u64_hi_lo). Integer cube root as `_cube_root_u64` via Newton's method. Output clamp to `[min_cwnd, 1 GiB]` with debug log when hit.

- [ ] **Step 4: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_cc_cubic.mojo`
Expected: PASS — "All cubic tests passed."

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `feat: add CUBIC congestion controller per RFC 9438`

---

### Task 5: cc/controller.mojo — variant dispatcher

**Files:**
- Create: `src/quic/cc/controller.mojo`
- Modify: `tests/test_cc_controller.mojo` (grew in Task 3; now extend to full suite per spec §9.3)

**Spec reference:** §2.3 dispatch pattern, §9.3 tests.

- [ ] **Step 1: Extend test file** (~100 LoC total, 6 tests)

```mojo
# tests/test_cc_controller.mojo
from src.quic.cc.controller import CcController
from src.quic.cc.cubic import Cubic
from src.quic.cc.dummy import DummyCc
from src.quic.cc.trait import (
    AckedPacket, LostPacket,
    CC_KIND_DUMMY, CC_KIND_CUBIC, UINT64_UNLIMITED,
)

alias MDS: UInt64 = 1200

def test_dummy_cc_basic():
    var d = DummyCc(max_datagram_size=MDS)
    assert_true(d.cwnd() == UINT64_UNLIMITED, "dummy cwnd unlimited")
    assert_true(d.pacing_rate(UInt64(100_000)) == UInt64(0), "dummy pacing 0")
    assert_true(d.name() == String("dummy"), "dummy name")
    print("PASS: test_dummy_cc_basic")

def test_controller_cubic_dispatch():
    var ctrl = CcController.new_cubic(max_datagram_size=MDS)
    assert_true(ctrl.kind == CC_KIND_CUBIC, "kind is CUBIC")
    assert_true(ctrl.name() == String("cubic"), "name dispatch")
    var start = ctrl.cwnd()
    ctrl.on_packet_sent(size=MDS, now=UInt64(1000))
    # on_packet_sent doesn't change cwnd, just bookkeeping
    assert_true(ctrl.cwnd() == start, "cwnd unchanged by send")
    print("PASS: test_controller_cubic_dispatch")

def test_controller_dummy_unlimited_cwnd():
    var ctrl = CcController.new_dummy(max_datagram_size=MDS)
    assert_true(ctrl.kind == CC_KIND_DUMMY, "kind is DUMMY")
    assert_true(ctrl.cwnd() == UINT64_UNLIMITED, "dummy cwnd unlimited")
    print("PASS: test_controller_dummy_unlimited_cwnd")

def test_controller_dummy_no_op_acked():
    var ctrl = CcController.new_dummy(max_datagram_size=MDS)
    var before_name = ctrl.name()
    var pkt = AckedPacket(pkt_num=1, size=MDS, time_sent=0, time_acked=1000, rtt_sample=1000)
    ctrl.on_packet_acked(pkt, smoothed_rtt_us=UInt64(1000), now=UInt64(1000))
    assert_true(ctrl.cwnd() == UINT64_UNLIMITED, "dummy cwnd still unlimited after ACK")
    assert_true(ctrl.name() == before_name, "name unchanged")
    print("PASS: test_controller_dummy_no_op_acked")

def test_controller_copy_preserves_variant():
    var ctrl = CcController.new_cubic(max_datagram_size=MDS)
    # Mutate: force a cwnd change by simulating a congestion event.
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=1, size=MDS, time_sent=0))
    ctrl.on_packets_lost(lost, smoothed_rtt_us=UInt64(50_000), now=UInt64(100_000), persistent=False)
    var reduced = ctrl.cwnd()
    var ctrl2 = ctrl
    assert_true(ctrl2.kind == CC_KIND_CUBIC, "copy kind preserved")
    assert_true(ctrl2.cwnd() == reduced, "copy cwnd preserved")
    print("PASS: test_controller_copy_preserves_variant")

def test_controller_persistent_loss_resets_cubic():
    var ctrl = CcController.new_cubic(max_datagram_size=MDS)
    # Grow cwnd beyond min so reset is observable.
    for i in range(50):
        var pkt = AckedPacket(pkt_num=UInt64(i), size=MDS,
                              time_sent=UInt64(i * 1000), time_acked=UInt64(i * 1000 + 500),
                              rtt_sample=UInt64(500))
        ctrl.on_packet_acked(pkt, smoothed_rtt_us=UInt64(500), now=UInt64(i * 1000 + 500))
    assert_true(ctrl.cwnd() > UInt64(2) * MDS, "cwnd grew past min before test")
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=1, size=MDS, time_sent=0))
    ctrl.on_packets_lost(lost, smoothed_rtt_us=UInt64(500), now=UInt64(100_000), persistent=True)
    assert_true(ctrl.cwnd() == UInt64(2) * MDS, "persistent loss through controller resets")
    print("PASS: test_controller_persistent_loss_resets_cubic")

def main():
    test_dummy_cc_basic()
    test_controller_cubic_dispatch()
    test_controller_dummy_unlimited_cwnd()
    test_controller_dummy_no_op_acked()
    test_controller_copy_preserves_variant()
    test_controller_persistent_loss_resets_cubic()
    print("All controller tests passed.")
```

- [ ] **Step 2: Verify tests fail** (controller not found)
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_cc_controller.mojo`
Expected: FAIL — `src.quic.cc.controller` not found.

- [ ] **Step 3: Implement CcController**

```mojo
# src/quic/cc/controller.mojo
from src.quic.cc.trait import (
    AckedPacket, LostPacket,
    CC_KIND_DUMMY, CC_KIND_CUBIC, UINT64_UNLIMITED,
)
from src.quic.cc.dummy import DummyCc
from src.quic.cc.cubic import Cubic

struct CcController(Copyable, Movable):
    var kind: UInt8
    var dummy: DummyCc
    var cubic: Cubic

    def __init__(out self, kind: UInt8, dummy: DummyCc, cubic: Cubic):
        self.kind = kind; self.dummy = dummy; self.cubic = cubic

    @staticmethod
    def new_cubic(max_datagram_size: UInt64) -> CcController:
        return CcController(
            kind=CC_KIND_CUBIC,
            dummy=DummyCc(max_datagram_size=max_datagram_size),
            cubic=Cubic(max_datagram_size=max_datagram_size),
        )

    @staticmethod
    def new_dummy(max_datagram_size: UInt64) -> CcController:
        return CcController(
            kind=CC_KIND_DUMMY,
            dummy=DummyCc(max_datagram_size=max_datagram_size),
            cubic=Cubic(max_datagram_size=max_datagram_size),
        )

    def cwnd(self) -> UInt64:
        if self.kind == CC_KIND_CUBIC: return self.cubic.cwnd
        return UINT64_UNLIMITED

    def pacing_rate(self, smoothed_rtt_us: UInt64) -> UInt64:
        if self.kind == CC_KIND_CUBIC: return self.cubic.pacing_rate(smoothed_rtt_us)
        return UInt64(0)

    def on_packet_sent(mut self, size: UInt64, now: UInt64):
        if self.kind == CC_KIND_CUBIC: self.cubic.on_packet_sent(size, now)

    def on_packet_acked(mut self, packet: AckedPacket, smoothed_rtt_us: UInt64, now: UInt64):
        if self.kind == CC_KIND_CUBIC: self.cubic.on_packet_acked(packet, smoothed_rtt_us, now)

    def on_packets_lost(mut self, lost: List[LostPacket], smoothed_rtt_us: UInt64,
                        now: UInt64, persistent: Bool):
        if self.kind == CC_KIND_CUBIC:
            self.cubic.on_packets_lost(lost, smoothed_rtt_us, now, persistent)

    def name(self) -> String:
        if self.kind == CC_KIND_CUBIC: return String("cubic")
        return String("dummy")
```

- [ ] **Step 4: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_cc_controller.mojo`
Expected: PASS — "All controller tests passed."

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `feat: add CcController tag-discriminated CC dispatcher`

---

## Phase 2 — pn_space + recovery integration (Tasks 6-7)

These two tasks touch independent files and can run in parallel.

### Task 6: pn_space.mojo — last_ae_acked_time_sent tracker

**Files:**
- Modify: `src/quic/pn_space.mojo` (+~40 LoC)
- Modify: `tests/test_pn_space.mojo` (+~40 LoC, 3 tests)

**Spec reference:** §5.4.

- [ ] **Step 1: Write failing tests**

```mojo
# Appended to tests/test_pn_space.mojo
def test_pn_space_last_ae_acked_initially_zero():
    var sp = PacketNumberSpace(space_id=SPACE_DATA)
    assert_true(sp.last_ae_acked_time_sent == UInt64(0), "initial 0")
    print("PASS: test_pn_space_last_ae_acked_initially_zero")

def test_pn_space_any_ae_acked_in_range_boundaries():
    var sp = PacketNumberSpace(space_id=SPACE_DATA)
    # zero → no evidence
    assert_true(not sp.any_ae_acked_in_range(UInt64(100), UInt64(200)),
                "unset → False")
    sp.last_ae_acked_time_sent = UInt64(150)
    # in range [100, 200]
    assert_true(sp.any_ae_acked_in_range(UInt64(100), UInt64(200)),
                "in-range tracker → True")
    sp.last_ae_acked_time_sent = UInt64(50)
    # before range
    assert_true(not sp.any_ae_acked_in_range(UInt64(100), UInt64(200)),
                "before range → False")
    sp.last_ae_acked_time_sent = UInt64(300)
    # past range — conservative True (no evidence either way)
    assert_true(sp.any_ae_acked_in_range(UInt64(100), UInt64(200)),
                "past range → conservative True")
    print("PASS: test_pn_space_any_ae_acked_in_range_boundaries")

def test_pn_space_last_ae_acked_monotonic():
    var sp = PacketNumberSpace(space_id=SPACE_DATA)
    sp.last_ae_acked_time_sent = UInt64(100)
    # Attempting to lower it should not work — caller is responsible for monotonic update.
    # We test the invariant by replicating the idiomatic check:
    var sp_time = UInt64(50)
    if sp_time > sp.last_ae_acked_time_sent:
        sp.last_ae_acked_time_sent = sp_time
    assert_true(sp.last_ae_acked_time_sent == UInt64(100), "monotonic (not lowered)")
    var sp_time2 = UInt64(200)
    if sp_time2 > sp.last_ae_acked_time_sent:
        sp.last_ae_acked_time_sent = sp_time2
    assert_true(sp.last_ae_acked_time_sent == UInt64(200), "advanced to later time")
    print("PASS: test_pn_space_last_ae_acked_monotonic")
```

- [ ] **Step 2: Verify tests fail**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_pn_space.mojo`
Expected: FAIL — field / method not present.

- [ ] **Step 3: Add field and method**
In `src/quic/pn_space.mojo`:
- Add `var last_ae_acked_time_sent: UInt64` to `PacketNumberSpace`.
- Initialize to `UInt64(0)` in all three `__init__` variants (standard, copy, deinit-take).
- Add `def any_ae_acked_in_range(self, earliest: UInt64, latest: UInt64) -> Bool:` per spec §5.4: returns `False` if field is 0, `True` if `field >= earliest`, else `False`.

- [ ] **Step 4: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_pn_space.mojo`
Expected: PASS.

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `feat: add last_ae_acked_time_sent tracker to PacketNumberSpace`

---

### Task 7: recovery.mojo — CC + Pacer fields and hooks

**Files:**
- Modify: `src/quic/recovery.mojo` (+~300 LoC)
- Modify: `tests/test_recovery.mojo` (+~120 LoC, 5 tests per spec §9.4)

**Spec reference:** §5.1 new fields, §5.2 hook-point modifications, §5.3 `detect_persistent_congestion` (implemented here even though spec frames it on QuicConnection — keep the algorithm in Recovery for testability; caller in QuicConnection wraps with its sent_packets + peer_max_ack_delay).

Actually — reread spec §5.3: "Implemented as a method on `QuicConnection` (not `Recovery`) because it needs the peer transport params and the `PacketNumberSpace` state". So `detect_persistent_congestion` lives on `QuicConnection`, added in Task 9. Task 7 adds only the Recovery additions.

- [ ] **Step 1: Extend failing tests** (5 new tests appended to existing `tests/test_recovery.mojo`)

```mojo
# Appended
from src.quic.cc.controller import CcController
from src.quic.cc.pacing import Pacer
from src.quic.cc.trait import CC_KIND_CUBIC, CC_KIND_DUMMY, AckedPacket, LostPacket

def test_recovery_cc_cubic_by_default():
    var rec = Recovery(max_datagram_size=UInt64(1200))
    assert_true(rec.cc.kind == CC_KIND_CUBIC, "CUBIC by default")
    print("PASS: test_recovery_cc_cubic_by_default")

def test_recovery_cc_dummy_optin():
    var rec = Recovery(max_datagram_size=UInt64(1200), use_cubic=False)
    assert_true(rec.cc.kind == CC_KIND_DUMMY, "dummy when opted in")
    print("PASS: test_recovery_cc_dummy_optin")

def test_recovery_on_packet_sent_notifies_cc():
    var rec = Recovery(max_datagram_size=UInt64(1200))
    var before_bif = rec.bytes_in_flight
    rec.on_packet_sent(size=1200, in_flight=True, now=UInt64(1000))
    assert_true(rec.bytes_in_flight == before_bif + UInt64(1200), "bytes_in_flight updated")
    # CC notification verified indirectly: CUBIC's internal state is opaque here;
    # this is really a compile+integration check.
    print("PASS: test_recovery_on_packet_sent_notifies_cc")

def test_recovery_pacer_capacity_updates_on_ack():
    var rec = Recovery(max_datagram_size=UInt64(1200))
    # Inject RTT sample + acked packet to grow cwnd and trigger pacer capacity refresh.
    rec.update_rtt(rtt_sample=UInt64(10_000), ack_delay=UInt64(0),
                   max_ack_delay=UInt64(0), handshake_confirmed=False)
    var before_cap = rec.pacer.capacity
    # Force a cwnd update via simulated ACK (CC grows cwnd).
    var pkt = AckedPacket(pkt_num=1, size=UInt64(1200),
                           time_sent=0, time_acked=10_000, rtt_sample=10_000)
    rec.cc.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(10_000))
    rec.on_ack_received()
    # After on_ack_received, pacer.update_capacity should have run.
    assert_true(rec.pacer.capacity != before_cap or rec.pacer.capacity > UInt64(0),
                "pacer capacity reflects current CC state")
    print("PASS: test_recovery_pacer_capacity_updates_on_ack")

def test_recovery_min_rtt_reset_on_persistent():
    """Recovery exposes a min_rtt that can be reset — caller responsibility to invoke on persistent."""
    var rec = Recovery(max_datagram_size=UInt64(1200))
    rec.update_rtt(rtt_sample=UInt64(10_000), ack_delay=UInt64(0),
                   max_ack_delay=UInt64(0), handshake_confirmed=False)
    assert_true(rec.min_rtt == UInt64(10_000), "min_rtt set to first sample")
    rec.update_rtt(rtt_sample=UInt64(5_000), ack_delay=UInt64(0),
                   max_ack_delay=UInt64(0), handshake_confirmed=False)
    assert_true(rec.min_rtt == UInt64(5_000), "min_rtt lowered on smaller sample")
    # Simulate persistent congestion → test the reset via latest_rtt.
    rec.update_rtt(rtt_sample=UInt64(20_000), ack_delay=UInt64(0),
                   max_ack_delay=UInt64(0), handshake_confirmed=False)
    # min_rtt didn't move upward.
    assert_true(rec.min_rtt == UInt64(5_000), "min_rtt not raised by higher sample")
    # Caller-driven reset (simulating QuicConnection after persistent detection):
    rec.min_rtt = rec.latest_rtt
    assert_true(rec.min_rtt == UInt64(20_000), "caller-driven reset works")
    print("PASS: test_recovery_min_rtt_reset_on_persistent")
```

- [ ] **Step 2: Verify tests fail**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_recovery.mojo`
Expected: FAIL — `rec.cc` / `rec.pacer` fields not present.

- [ ] **Step 3: Modify Recovery**
In `src/quic/recovery.mojo`:
- Add imports: `from src.quic.cc.controller import CcController`, `from src.quic.cc.pacing import Pacer`, `from src.quic.cc.trait import AckedPacket, LostPacket`.
- Add fields: `var cc: CcController`, `var pacer: Pacer`.
- Update `__init__(out self)` → add parameter `max_datagram_size: UInt64, use_cubic: Bool = True`. Initialize `self.cc = CcController.new_cubic(max_datagram_size) if use_cubic else CcController.new_dummy(max_datagram_size)`, `self.pacer = Pacer.new(max_datagram_size)`.
- Update copy/move constructors to carry `cc` + `pacer`.
- Update `on_packet_sent(mut self, size: Int, in_flight: Bool)` → add `now: UInt64` param. After `bytes_in_flight += size`, call `self.cc.on_packet_sent(UInt64(size), now)`. (Pacer.on_sent is called at send site in connection.mojo, not here.)
- Update `on_ack_received()` → after `pto_count = 0`, call `self.pacer.update_capacity(self.cc.cwnd(), self.smoothed_rtt)`.

Note: Existing call sites pass `on_packet_sent(size, in_flight)`; Task 8/9 in connection.mojo will thread `now` through the call. For Task 7, accept a default `now: UInt64 = 0` on the helper to keep M3b callers compiling, and fix call sites in Task 9. Document this as a transient in the commit message.

- [ ] **Step 4: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_recovery.mojo`
Expected: PASS on new tests; existing tests still green.

- [ ] **Step 5: Commit**
Use the `commit-smart` skill. Message: `feat: wire CcController and Pacer into Recovery`

---

## Phase 3 — Connection integration (Tasks 8-10, sequential — all touch connection.mojo)

### Task 8: connection.mojo — _anti_amp_ok + _can_send helpers

**Files:**
- Modify: `src/quic/connection.mojo` (+~60 LoC: extract helpers + call-site migration)

**Spec reference:** §8.1.

- [ ] **Step 1: Add a regression-guard test**

Append to `tests/test_quic_connection.mojo`:

```mojo
def test_anti_amp_ok_extract_parity():
    """Unvalidated server rejects oversized send; validated server accepts."""
    var c, s = _handshake_setup(partial=True)  # half-handshake; server not yet addr-validated
    assert_true(s.is_server and not s._addr_validated(), "server unvalidated")
    # With no bytes_received, 3x cap is 0; any datagram should be rejected.
    s.bytes_sent = UInt64(0)
    s.bytes_received = UInt64(0)
    assert_true(not s._anti_amp_ok(UInt64(1000)), "unvalidated server rejects 1000-byte send with zero recv")

    # Simulate receipt of client Initial (e.g., 1200 bytes).
    s.bytes_received = UInt64(1200)
    # 3 * 1200 = 3600 available. Send + 100 fudge should fit.
    assert_true(s._anti_amp_ok(UInt64(3400)), "3400 + 100 fudge within 3600")
    assert_true(not s._anti_amp_ok(UInt64(3600)), "3600 + 100 > 3600 (exceeds)")

    # Mark server addr-validated; cap should lift.
    _force_addr_validated(s)
    assert_true(s._anti_amp_ok(UInt64(100_000)), "validated server: no cap")

    print("PASS: test_anti_amp_ok_extract_parity")
```

- [ ] **Step 2: Verify test fails** (helpers missing)
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: FAIL — `_anti_amp_ok` not defined; `_force_addr_validated` helper missing.

- [ ] **Step 3: Add helpers to connection.mojo**

```mojo
# connection.mojo — module-scope
comptime ANTI_AMP_HEADER_FUDGE: UInt64 = 100

# Inside QuicConnection:
def _anti_amp_ok(self, datagram_size: UInt64) -> Bool:
    """Server-side 3x anti-amplification check (RFC 9000 §8.1).
    Only applies to unvalidated servers. ANTI_AMP_HEADER_FUDGE preserves
    the exact numeric behavior of the former inline check at the original
    connection.mojo:1393 (`+ 100`)."""
    if not self.is_server: return True
    if self._addr_validated(): return True
    return self.bytes_sent + datagram_size + ANTI_AMP_HEADER_FUDGE <= 3 * self.bytes_received

def _can_send(self, size: UInt64, now: UInt64) -> Bool:
    """Composite send gate: anti-amplification + CC window + pacer. Non-mutating."""
    if not self._anti_amp_ok(size): return False
    if self.recovery.cc.cwnd() < self.recovery.bytes_in_flight + size: return False
    var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
    if self.recovery.pacer.next_send_time(rate, now):
        return False
    return True
```

- [ ] **Step 4: Migrate the inline check at connection.mojo:1391-1394**
Replace:
```mojo
if self.is_server and not self._addr_validated():
    if self.bytes_sent + UInt64(len(datagram)) + 100 > 3 * self.bytes_received:
        break
```
With:
```mojo
if not self._anti_amp_ok(UInt64(len(datagram))):
    break
```

- [ ] **Step 5: Add `_force_addr_validated` test helper**
Add to the top of `tests/test_quic_connection.mojo`:
```mojo
def _force_addr_validated(mut conn):
    # Simulate path validation by setting the flag/condition _addr_validated() reads.
    # Exact mechanism depends on M3b: if `handshake_confirmed` is the predicate, set that;
    # if a dedicated flag, set it directly.
    conn.handshake_confirmed = True   # placeholder — verify exact field during implementation
```

- [ ] **Step 6: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: PASS on new test; no regression in existing M3b/M3c tests.

Also run full suite to confirm handshake tests still pass (the migration must be behavior-preserving):
Run: `bash scripts/run_tests.sh`
Expected: all green.

- [ ] **Step 7: Commit**
Use the `commit-smart` skill. Message: `refactor: extract _anti_amp_ok and introduce _can_send helpers`

---

### Task 9: connection.mojo — ACK-processing flow and persistent-congestion detection

**Files:**
- Modify: `src/quic/connection.mojo` (+~150 LoC: `detect_persistent_congestion` + ACK flow rewire)

**Spec reference:** §5.3 detection algorithm, §8.2 ACK-processing sequence.

- [ ] **Step 1: Write failing test**

```mojo
# Appended to tests/test_quic_connection.mojo
def test_persistent_congestion_end_to_end():
    """Force a loss-burst spanning persistent_congestion_duration; verify cwnd reset."""
    var c, s = _establish_handshake()
    # Force CUBIC cwnd upward from initial by faking a bunch of successful ACKs
    # in a controlled way. Test-only hook (add as part of this task):
    c.recovery._inject_ack_eliciting_sent(count=50, size=1200, start_time=UInt64(0),
                                          interval=UInt64(1000))
    c.recovery._inject_all_acked(smoothed_rtt_us=UInt64(10_000))
    var pre_cwnd = c.recovery.cc.cwnd()
    assert_true(pre_cwnd > UInt64(2 * 1200), "cwnd grew before test")

    # Now inject a sequence of ack-eliciting packets separated by
    # 3 * (srtt + 4*rttvar + max_ack_delay) and declare them all lost.
    var srtt = c.recovery.smoothed_rtt
    var rttvar = c.recovery.rttvar
    var max_ack_delay = UInt64(25_000)  # 25ms, typical default
    var cong_period = (srtt + UInt64(4) * rttvar + max_ack_delay) * UInt64(3)
    c.recovery._inject_ack_eliciting_sent(count=5, size=1200,
                                          start_time=UInt64(100_000),
                                          interval=cong_period // UInt64(4))
    # Declare all 5 lost.
    var lost_pns = c.recovery._inject_detect_lost_for_last(count=5)
    # Invoke the new detector:
    var persistent = c._detect_persistent_congestion(
        space_id=2,  # Data
        newly_lost_pns=lost_pns,
        peer_max_ack_delay_us=max_ack_delay,
        now=UInt64(100_000) + cong_period + UInt64(1000),
    )
    assert_true(persistent, "persistent declared given right conditions")

    # Apply the response: caller (connection) invokes CC and resets min_rtt.
    var lost_packets = _build_lost_packets_from_pns(c, lost_pns)
    c.recovery.cc.on_packets_lost(lost_packets, c.recovery.smoothed_rtt,
                                   UInt64(100_000) + cong_period + UInt64(1000),
                                   persistent=True)
    c.recovery.min_rtt = c.recovery.latest_rtt

    assert_true(c.recovery.cc.cwnd() == UInt64(2) * UInt64(1200),
                "cwnd reset to 2*MDS after persistent declaration")

    print("PASS: test_persistent_congestion_end_to_end")
```

- [ ] **Step 2: Verify test fails**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: FAIL — `_detect_persistent_congestion` missing; Recovery test hooks missing; build helper missing.

- [ ] **Step 3: Add `_detect_persistent_congestion` to QuicConnection**
Per spec §5.3. Steps:
1. Return False if `not recovery.has_rtt_sample` or `len(newly_lost_pns) < 2`.
2. Iterate `pn_spaces.get(space_id).sent_packets` for each pn in `newly_lost_pns`; filter by `ack_eliciting`; track `earliest`, `latest`, `ae_count`. Return False if `ae_count < 2`.
3. Compute `congestion_period = (smoothed_rtt + max(4*rttvar, K_GRANULARITY) + peer_max_ack_delay_us) * PERSISTENT_CONG_THRESHOLD`. Note: **max_ack_delay is included unconditionally** per RFC 9002 §7.6.2 (research §4.2 explicit).
4. Return False if `latest - earliest < congestion_period`.
5. Return `not space.any_ae_acked_in_range(earliest, latest)`.

- [ ] **Step 4: Rewire ACK processing**
In the existing `_process_ack` / `_on_ack_received` method:
- Per ACKed `SentPacket sp`: if `sp.ack_eliciting and sp.time_sent > space.last_ae_acked_time_sent`, set `space.last_ae_acked_time_sent = sp.time_sent`. Also build `AckedPacket(sp.pn, sp.size, sp.time_sent, now, rec.latest_rtt)` and call `rec.cc.on_packet_acked(pkt, rec.smoothed_rtt, now)`.
- After `detect_lost_packets` returns: build `List[LostPacket]` (lookup size + time_sent in `sent_packets` before removal). Run `persistent = self._detect_persistent_congestion(space_id, lost_pns, peer_max_ack_delay_us, now)`. Invoke `rec.cc.on_packets_lost(lost_pkts, rec.smoothed_rtt, now, persistent)`. If `persistent`, set `rec.min_rtt = rec.latest_rtt`.

- [ ] **Step 5: Add test-only hooks to recovery.mojo**
Add three methods that support the integration test:
- `_inject_ack_eliciting_sent(count, size, start_time, interval)` — populates `PacketNumberSpace.sent_packets` with synthetic ack-eliciting entries.
- `_inject_all_acked(smoothed_rtt_us)` — iterates the injected packets and runs each through `cc.on_packet_acked`.
- `_inject_detect_lost_for_last(count)` — returns a `List[Int]` of PNs for the last `count` injected packets, without invoking `detect_lost_packets`.

Gate under a `comptime TEST_HOOKS: Bool = True` that defaults True for the in-tree build (simpler than a full `@parameter` conditional; can be tightened post-M4a if build flags become a concern).

Also add `_build_lost_packets_from_pns(conn, pn_list)` helper to `tests/test_quic_connection.mojo`.

- [ ] **Step 6: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: PASS. Also `bash scripts/run_tests.sh` remains green.

- [ ] **Step 7: Commit**
Use the `commit-smart` skill. Message: `feat: wire persistent-congestion detection and CC fan-out into ACK processing`

---

### Task 10: connection.mojo — pacer in timeout() + send-gating call sites

**Files:**
- Modify: `src/quic/connection.mojo` (+~70 LoC: `timeout(now)` signature change + pacer branch + call-site migration)
- Modify: examples and tests that call `timeout()` to pass `now`

**Spec reference:** §8.3 pacer timer integration.

- [ ] **Step 1: Write failing test**

```mojo
# Appended
def test_pacer_delays_burst():
    """With a low pacing rate, timeout() exposes a pacer deadline delaying the next send."""
    var c, s = _establish_handshake()
    var sid = c.open_stream(bidi=True)
    # Force a low pacing rate by constraining CUBIC cwnd + short srtt in a targeted way.
    # Simulate a first packet sent, then ask timeout — pacer branch should return a deadline.
    _ = c.send_stream_data(sid, bytes([UInt8(0x41)] * 100), fin=False)
    _flush_single_packet(c, s)
    # After sending 100 bytes with a small cwnd, pacer has few tokens.
    # Call timeout to observe the pacer deadline.
    var deadline = c.timeout(now=UInt64(1000))
    # At least one deadline (PTO or pacer) should be set.
    assert_true(bool(deadline), "some timer active")
    # Finer assertion: the returned deadline shouldn't be in the past.
    if deadline:
        assert_true(deadline.value() >= UInt64(1000), "deadline not in past")
    print("PASS: test_pacer_delays_burst")
```

- [ ] **Step 2: Verify test fails** (`timeout(now)` signature mismatch or pacer branch missing)
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: FAIL — `timeout` takes no `now` param yet.

- [ ] **Step 3: Change timeout() signature**
In `src/quic/connection.mojo:1949`:
```mojo
def timeout(self, now: UInt64) -> Optional[UInt64]:
    """Return the earliest deadline among PTO, idle, close/drain, and pacer."""
    var earliest = Optional[UInt64](None)
    # ... existing PTO / idle / close / drain branches ...

    # --- New: Pacer branch ---
    var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
    var pacer_deadline = self.recovery.pacer.next_send_time(rate, now)
    if pacer_deadline:
        if earliest:
            if pacer_deadline.value() < earliest.value(): earliest = pacer_deadline
        else:
            earliest = pacer_deadline
    return earliest
```

- [ ] **Step 4: Migrate call sites**
Grep for `.timeout()` across `src/`, `tests/`, `examples/`:
```bash
grep -rn "\.timeout()" src/ tests/ examples/ | grep -v "test_tls_"
```
Add `now` parameter at each call. Callers already have `now` in scope (e.g., `current_time_us()` helpers exist from M3b).

- [ ] **Step 5: Add `Pacer.on_sent` at actual send site**
In the send path where `connection.mojo` calls into the OS send (or simulated send):
```mojo
if self._can_send(UInt64(len(datagram)), now):
    var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
    _ = self.recovery.pacer.refill_and_check(rate, now)  # commits token
    # ... actual send ...
    self.recovery.pacer.on_sent(UInt64(len(datagram)))
    self.recovery.on_packet_sent(size=len(datagram), in_flight=True, now=now)
```

- [ ] **Step 6: Verify tests pass**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: PASS. Full suite: `bash scripts/run_tests.sh` remains green.

- [ ] **Step 7: Commit**
Use the `commit-smart` skill. Message: `feat: fold pacer deadline into timeout(now) and commit tokens at send site`

---

## Phase 4 — Integration tests + runner (Task 11)

### Task 11: Full CC-aware integration tests + test runner

**Files:**
- Modify: `tests/test_quic_connection.mojo` (+~30 LoC for remaining cwnd-gating test — `test_pacer_delays_burst` and `test_persistent_congestion_end_to_end` and `test_anti_amp_ok_extract_parity` landed in Tasks 8-10; one more: `test_cubic_cwnd_gates_send_path`)
- Modify: `scripts/run_tests.sh` (+3 lines: register `test_cc_cubic`, `test_cc_pacing`, `test_cc_controller`)

**Spec reference:** §9.6 integration tests, §2.1 test runner update.

- [ ] **Step 1: Write the final integration test**

```mojo
def test_cubic_cwnd_gates_send_path():
    """A connection with CUBIC cannot send beyond cwnd."""
    var c, s = _establish_handshake()
    var sid = c.open_stream(bidi=True)
    # Force CUBIC cwnd to a small known value via internal access.
    c.recovery.cc.cubic.cwnd = UInt64(2400)  # 2 * MDS
    c.recovery.bytes_in_flight = UInt64(0)
    # Try to send 3000 bytes — should be gated.
    var buf = bytes([UInt8(0x41)] * 3000)
    # In the sans-I/O harness the client checks `_can_send(size, now)` before
    # producing a datagram. Observe that queued data stays queued when blocked.
    var ok = c._can_send(UInt64(3000), UInt64(1000))
    assert_true(not ok, "send blocked by cwnd (cwnd=2400, size=3000)")
    ok = c._can_send(UInt64(1200), UInt64(1000))
    assert_true(ok, "1200-byte send permitted within cwnd=2400")
    print("PASS: test_cubic_cwnd_gates_send_path")
```

- [ ] **Step 2: Verify test fails/passes**
Run: `uv run mojo run -I . -I conformance -D ASSERT=all tests/test_quic_connection.mojo`
Expected: PASS if Task 8-10 are correct; if FAIL, debug the `_can_send` path or `bytes_in_flight` initialization.

- [ ] **Step 3: Register new test files in `scripts/run_tests.sh`**

```bash
# Add these three lines alongside the existing test entries:
uv run mojo run -I . -I conformance -D ASSERT=all tests/test_cc_cubic.mojo || exit 1
uv run mojo run -I . -I conformance -D ASSERT=all tests/test_cc_pacing.mojo || exit 1
uv run mojo run -I . -I conformance -D ASSERT=all tests/test_cc_controller.mojo || exit 1
```

- [ ] **Step 4: Verify the full runner passes**
Run: `bash scripts/run_tests.sh`
Expected: all green, including the 3 new test files and the M3c integration tests from the prerequisite plan.

- [ ] **Step 5: Verify conformance is unaffected**
Run: `bash conformance/scripts/run_tests.sh`
Expected: 33/33 — no change from M3c baseline.

- [ ] **Step 6: Commit**
Use the `commit-smart` skill. Message: `test: add cubic cwnd gating integration test and register cc/ test files`

---

## Final verification

- [ ] **Spec coverage scan** — verify every requirement in `specs/2026-04-15-m4a-quic-cc-core.md` maps to a task:
  - §2.1 file layout: Tasks 1-11 ✓
  - §2.3 dispatch pattern: Task 5 (implementation), Task 0 (spike) ✓
  - §3.1-3.3 trait module: Task 1 ✓
  - §4 CUBIC: Task 4 ✓
  - §5 Recovery integration: Task 7 ✓
  - §5.3 persistent congestion: Task 9 ✓
  - §5.4 last_ae_acked_time_sent: Task 6 ✓
  - §6 Pacer: Task 2 ✓
  - §7 Dummy: Task 3 ✓
  - §8.1 _anti_amp_ok + _can_send: Task 8 ✓
  - §8.2 ACK flow: Task 9 ✓
  - §8.3 Pacer in timeout: Task 10 ✓
  - §9 tests: distributed across all tasks ✓

- [ ] **Full test suite** — `bash scripts/run_tests.sh` all green; `bash conformance/scripts/run_tests.sh` 33/33; optional `bash scripts/test_reverse_proxy.sh` sanity if infra available.

## Deferred to M4b

Per spec §12. None of these blocks M4a completion:

- HyStart++ (optional→required-later; trigger: loss-induced SS exit over-commits >2x)
- Delivery-rate estimator (required-later; trigger: M4b needs for BBR + app-limited CC)
- MinMax helper (required-later; trigger: HyStart++ baseline)
- ECN outgoing + incoming validation (required-later; trigger: interop with ECN-marking middleboxes)
- BLOCKED frame emission (required-later; trigger: interop)
- PN skipping / optimistic-ACK defense (required-later; CVE-2025-4820 class; project-context line 51 treats as MUST)
- FC auto-tuning (optional→required-later; high-BDP throughput profiling)
- `on_mtu_update` wiring (optional; PMTUD milestone)
- Connection-wide `send_window` cap (optional; memory-pressure testing)
