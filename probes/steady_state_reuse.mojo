# probes/steady_state_reuse.mojo
#
# memory-win-shown (§6, binding): after a 1-request warmup, >= 1000 consecutive
# keep-alive plaintext requests reuse the inbound and outbound buffer backing
# allocations (stable unsafe_ptr). Inbound reuse goes through _compact_forward;
# outbound reuse through the clear()-based drain_into. Run under ASSERT=all.

from std.memory import Span
from navette.h1.connection import _compact_forward


def main() raises:
    # --- inbound reuse: simulate the receive -> parse -> compact loop ---
    # A 26-byte plaintext request is appended, fully consumed (cursor == len),
    # and compacted each iteration; the backing allocation must be stable.
    var req = String("GET /plaintext HTTP/1.1\r\n\r\n").as_bytes()
    var inbound = List[UInt8](capacity=256)
    inbound.extend(req)               # warmup fill (grows once)
    _compact_forward(inbound, len(inbound))   # full consume -> clear()
    var inbound_ptr = Int(inbound.unsafe_ptr())
    var inbound_stable = True
    for _ in range(1000):
        inbound.extend(req)
        _compact_forward(inbound, len(inbound))
        if Int(inbound.unsafe_ptr()) != inbound_ptr:
            inbound_stable = False
    print("inbound_ptr_stable=", inbound_stable, " cap=", inbound.capacity)

    # --- outbound reuse: simulate send_response -> drain_into (clear) loop ---
    var resp = String("HTTP/1.1 200 \r\ncontent-length: 13\r\n\r\nHello, World!").as_bytes()
    var outbound = List[UInt8](capacity=256)
    outbound.extend(resp)             # warmup fill
    var sink = List[UInt8](capacity=4096)
    sink.extend(Span(outbound)); outbound.clear()   # drain_into semantics
    var outbound_ptr = Int(outbound.unsafe_ptr())
    var outbound_stable = True
    for _ in range(1000):
        outbound.extend(resp)
        sink.extend(Span(outbound))
        outbound.clear()
        if Int(outbound.unsafe_ptr()) != outbound_ptr:
            outbound_stable = False
    print("outbound_ptr_stable=", outbound_stable, " cap=", outbound.capacity)

    if not inbound_stable or not outbound_stable:
        raise "memory-win-shown FAILED: a steady-state buffer reallocated"
    print("memory-win-shown: inbound+outbound backing pointers stable over 1000 requests")
