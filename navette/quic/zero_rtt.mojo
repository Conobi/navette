# navette/quic/zero_rtt.mojo
#
# Zero-RTT buffering, anti-replay helpers, and ZeroRttState.

from std.collections import Optional, Span
from std.memory import Pointer
from navette.tls.lib import SharedLibrary
from navette.tls.early_data_store import InMemoryEarlyDataStore
from navette.quic.profile import ProfileState, CounterId, PROFILE_ACCEPT

comptime ZERO_RTT_BUFFER_MAX_PKTS: Int = 16
comptime ZERO_RTT_BUFFER_MAX_BYTES: Int = 32 * 1024  # 32 KiB


# ── ZeroRttState ────────────────────────────────────────────────────


@fieldwise_init
struct ZeroRttState(Movable):
    """Per-connection 0-RTT buffering and anti-replay state."""

    var enabled: Bool
    var buffer: List[List[Byte]]
    var buffer_bytes: Int
    var draining: Bool
    var replay_decision: UInt8
    var now_ms_override: Optional[UInt64]
    var early_data_store_ptr: Optional[
        Pointer[InMemoryEarlyDataStore, MutUntrackedOrigin]
    ]

    def is_enabled(self) -> Bool:
        """True if the server config opted into 0-RTT."""
        return self.enabled

    def buffer_or_drop(mut self, packet: Span[Byte, _]) -> Bool:
        """Buffer a 0-RTT packet for later replay.

        Returns True if buffered, False if dropped (cap exceeded).
        Bounded by ZERO_RTT_BUFFER_MAX_PKTS and ZERO_RTT_BUFFER_MAX_BYTES.
        """
        if len(self.buffer) >= ZERO_RTT_BUFFER_MAX_PKTS:
            return False
        if self.buffer_bytes + len(packet) > ZERO_RTT_BUFFER_MAX_BYTES:
            return False
        var copy = List[Byte](capacity=len(packet))
        for b in packet:
            copy.append(b)
        self.buffer.append(copy^)
        self.buffer_bytes += len(packet)
        return True


# ── Free functions ──────────────────────────────────────────────────


def invoke_replay_authenticator_ffi(
    lib: SharedLibrary,
    conn_handle: Int32,
    mut out_buf: InlineArray[UInt8, 32],
    mut out_len: UInt,
) -> Int32:
    """Call `rlsm_quic_server_conn_replay_authenticator`.

    Returns FFI rc (0=success, 1=no random captured, -1=anomaly).
    Resolving the symbol can raise; reported as -1 so the caller's
    fail-closed branch treats an unreachable authenticator like an
    unavailable one.
    """
    var rlib = lib.inner_ptr()
    try:
        return rlib[].quic_server_conn_replay_authenticator(
            conn_handle,
            out_buf.unsafe_ptr(),
            Pointer(to=out_len),
        )
    except:
        return Int32(-1)


def drive_replay_check_for_test(
    mut zrtt: ZeroRttState,
    mut prof: ProfileState,
    simulated_rc: Int32,
    simulated_decision_kind: UInt8,
    simulated_raises: Bool,
) raises:
    """Test-only entry point mirroring the integration block's transitions.

    Exercises the resulting `zrtt.replay_decision` value + the recorded
    counter for every reachable branch. The production block has one
    additional defensive `zrtt.early_data_store_ptr is None` fallback
    that collapses onto the same `no_authenticator` outcome as
    `simulated_rc != 0`. A static check in check_integrations.sh
    enforces this is callable only from `tests/`.

    Args:
        simulated_rc: FFI return code (0=success, 1=no authenticator,
            -1=anomaly). rc != 0 takes the no_authenticator branch.
        simulated_decision_kind: ReplayDecision.kind when rc == 0 and
            not raises (0=accept, 1=duplicate, 2=per_key_quota,
            3=global_ceiling).
        simulated_raises: True to simulate store.check_and_record
            raising; takes the no_authenticator branch.
    """
    if zrtt.replay_decision != UInt8(0):
        return

    if simulated_rc != Int32(0):
        zrtt.replay_decision = UInt8(2)
        prof.record_replay_reject_no_authenticator()
        return

    if simulated_raises:
        zrtt.replay_decision = UInt8(2)
        prof.record_replay_reject_no_authenticator()
        return

    if simulated_decision_kind == UInt8(0):
        # accept
        zrtt.replay_decision = UInt8(1)
        prof.record_replay_accept()
    elif simulated_decision_kind == UInt8(1):
        # duplicate
        zrtt.replay_decision = UInt8(2)
        prof.record_replay_reject_duplicate()
    elif simulated_decision_kind == UInt8(2):
        # per_key_quota
        zrtt.replay_decision = UInt8(2)
        prof.record_replay_reject_per_key_quota()
    else:
        # global_ceiling (kind == 3)
        zrtt.replay_decision = UInt8(2)
        prof.record_replay_reject_global_ceiling()
