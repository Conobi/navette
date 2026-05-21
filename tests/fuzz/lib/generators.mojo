# tests/fuzz/lib/generators.mojo
#
# Input generators for fuzz harnesses.
# All draw determinism from a SplitMix64 PRNG instance.

from tests.fuzz.lib.prng import SplitMix64


def random_bytes_geom(mut rng: SplitMix64, mean_len: Int, cap_len: Int) -> List[UInt8]:
    """Generate a random byte sequence with geometric length distribution.

    Length is drawn from a geometric distribution with mean = `mean_len`,
    capped at `cap_len`. Bytes are uniform random UInt8.
    """
    # Approximate geometric draw via inverse CDF: len = floor(-mean * ln(U)).
    # We can't use math.log on UInt64; use a coin-flip approximation:
    # successive bits decide whether to continue.
    var length = 0
    var coin_p_continue_per_byte = mean_len  # bigger mean = more "continue" iterations
    while length < cap_len:
        var u = rng.next_u64() % UInt64(coin_p_continue_per_byte + 1)
        if u == 0:
            break
        length += 1
    var out = List[UInt8](capacity=length)
    for _ in range(length):
        out.append(rng.next_u8())
    return out^


def mutate(mut rng: SplitMix64, seed: List[UInt8]) -> List[UInt8]:
    """Apply 1-3 random mutations to `seed`.

    Mutation ops: bitflip, byte-flip, chunk-splice, insert, delete, dup.
    """
    var out = List[UInt8](capacity=len(seed))
    for i in range(len(seed)):
        out.append(seed[i])
    var n_mutations = Int(rng.next_below(UInt64(3))) + 1
    for _ in range(n_mutations):
        var op = Int(rng.next_below(UInt64(6)))
        if len(out) == 0:
            # Force an insert if empty
            op = 3
        if op == 0:  # bitflip
            var idx = Int(rng.next_below(UInt64(len(out))))
            var bit = Int(rng.next_below(UInt64(8)))
            out[idx] = out[idx] ^ UInt8(1 << bit)
        elif op == 1:  # byte-flip (replace with random byte)
            var idx = Int(rng.next_below(UInt64(len(out))))
            out[idx] = rng.next_u8()
        elif op == 2:  # chunk-splice (overwrite random region)
            var start = Int(rng.next_below(UInt64(len(out))))
            var end = start + Int(rng.next_below(UInt64(len(out) - start + 1)))
            for j in range(start, end):
                out[j] = rng.next_u8()
        elif op == 3:  # insert random byte
            var idx = Int(rng.next_below(UInt64(len(out) + 1)))
            var b = rng.next_u8()
            var new_out = List[UInt8](capacity=len(out) + 1)
            for j in range(idx):
                new_out.append(out[j])
            new_out.append(b)
            for j in range(idx, len(out)):
                new_out.append(out[j])
            out = new_out^
        elif op == 4:  # delete random byte
            if len(out) > 0:
                var idx = Int(rng.next_below(UInt64(len(out))))
                var new_out = List[UInt8](capacity=len(out) - 1)
                for j in range(len(out)):
                    if j != idx:
                        new_out.append(out[j])
                out = new_out^
        else:  # dup last byte
            if len(out) > 0:
                out.append(out[len(out) - 1])
    return out^


def weighted_pick(mut rng: SplitMix64, weights: List[Int]) -> Int:
    """Pick an index in [0, len(weights)) with probability proportional to weights[i]."""
    var total = 0
    for i in range(len(weights)):
        total += weights[i]
    if total <= 0:
        return 0
    var roll = Int(rng.next_below(UInt64(total)))
    var acc = 0
    for i in range(len(weights)):
        acc += weights[i]
        if roll < acc:
            return i
    return len(weights) - 1
