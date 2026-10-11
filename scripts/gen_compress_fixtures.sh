#!/usr/bin/env bash
# Generate deterministic gzip/brotli fixtures for the decoder boundary tests
# into tests/fixtures/compress/ (gitignored). Needs python3, gzip, brotli.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/tests/fixtures/compress"
mkdir -p "$OUT"
for tool in python3 gzip brotli; do
    command -v "$tool" >/dev/null || { echo "missing $tool (apt install python3 gzip brotli)" >&2; exit 1; }
done

text() {  # text <bytes> <file>: repeating ASCII text, exact size
    python3 -c "import sys; s=b'the quick brown fox jumps over the lazy dog 0123456789\n'; n=int(sys.argv[1]); sys.stdout.buffer.write((s*(n//len(s)+1))[:n])" "$1" > "$2"
}
noise() {  # noise <bytes> <file>: seeded pseudo-random bytes (low ratio)
    python3 -c "import random,sys; r=random.Random(1234); sys.stdout.buffer.write(r.randbytes(int(sys.argv[1])))" "$1" > "$2"
}
pack() {  # pack <name>: <name>.bin -> <name>.gz and <name>.br
    gzip -n -9 -c "$OUT/$1.bin" > "$OUT/$1.gz"
    brotli -f -q 9 -o "$OUT/$1.br" "$OUT/$1.bin"
}

for n in 262143 262144 262145 1048576; do text "$n" "$OUT/text_$n.bin"; pack "text_$n"; done
if [ "${NAVETTE_TEST_LARGE:-0}" = "1" ]; then text 10485760 "$OUT/text_10485760.bin"; pack text_10485760; fi
noise 2097152 "$OUT/noise_2m.bin"; pack noise_2m
head -c 33554432 /dev/zero > "$OUT/zeros_32m.bin"; gzip -n -9 -c "$OUT/zeros_32m.bin" > "$OUT/zeros_32m.gz"; rm "$OUT/zeros_32m.bin"
head -c 67108864 /dev/zero | brotli -q 11 -c > "$OUT/zeros_64m.br"
text 70000 "$OUT/member_a.bin"; noise 50000 "$OUT/member_b.bin"
gzip -n -9 -c "$OUT/member_a.bin" > "$OUT/member_a.gz"; gzip -n -9 -c "$OUT/member_b.bin" > "$OUT/member_b.gz"
cat "$OUT/member_a.gz" "$OUT/member_b.gz" > "$OUT/multi.gz"
cat "$OUT/member_a.bin" "$OUT/member_b.bin" > "$OUT/multi.bin"
python3 -c "import os,sys; print(os.path.getsize(sys.argv[1]))" "$OUT/member_a.gz" > "$OUT/multi.boundary"
echo "fixtures written to $OUT"
