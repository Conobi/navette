# tests/fuzz/lib/shrink.mojo
#
# Delta-debug-style input minimization for fuzz disagreement-reproducers.


def minimize(
    input: List[UInt8],
    property_fn: def(List[UInt8]) raises thin -> Bool,
    max_calls: Int = 200,
) raises -> List[UInt8]:
    """Minimize `input` while preserving the property that `property_fn(input) == True`.

    Strategy:
      1. Binary halving — try keeping the first half, then the second half.
      2. Drop-each-chunk — for chunk sizes 1, 2, 4, ..., try dropping each chunk.

    `property_fn` returns True when the input still triggers the disagreement.
    Bounded to `max_calls` property_fn invocations to keep CI budget tight.
    """
    var current = List[UInt8](capacity=len(input))
    for i in range(len(input)):
        current.append(input[i])
    var calls = 0
    if not property_fn(current):
        return current^  # property doesn't hold; nothing to shrink

    # Phase 1: binary halving
    var changed = True
    while changed and calls < max_calls:
        changed = False
        if len(current) <= 1:
            break
        var half = len(current) // 2
        # Try keeping first half
        var first = List[UInt8](capacity=half)
        for i in range(half):
            first.append(current[i])
        calls += 1
        if property_fn(first):
            current = first^
            changed = True
            continue
        # Try keeping second half
        var second = List[UInt8](capacity=len(current) - half)
        for i in range(half, len(current)):
            second.append(current[i])
        calls += 1
        if property_fn(second):
            current = second^
            changed = True

    # Phase 2: drop-each-chunk (chunk size 1, doubling up to len/2)
    var chunk_size = 1
    while chunk_size < len(current) and calls < max_calls:
        var i = 0
        var made_progress = False
        while i + chunk_size <= len(current) and calls < max_calls:
            var trial = List[UInt8](capacity=len(current) - chunk_size)
            for j in range(i):
                trial.append(current[j])
            for j in range(i + chunk_size, len(current)):
                trial.append(current[j])
            calls += 1
            if property_fn(trial):
                current = trial^
                made_progress = True
                # Don't increment i — try dropping at the same offset again
            else:
                i += chunk_size
        if not made_progress:
            chunk_size = chunk_size * 2

    return current^
