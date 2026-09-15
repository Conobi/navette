#!/bin/bash
# Measure allocation counts per request for navette and TQUIC under identical long-conn load.
# Usage: bash bench/alloc_count/measure.sh

set -euo pipefail

SHIM="$(dirname "$0")/liballoc_count.so"
EXAMPLE_DIR="/home/donokami/Projets/perso/navette/examples/static_h3_server"
DATA_DIR="/tmp/tquic-data"
DURATION=10
CONNS=25
THREADS=4
CONCURRENT_REQS=10

mkdir -p "$DATA_DIR/static"
[ -f "$DATA_DIR/static/5k.bin" ] || dd if=/dev/urandom of="$DATA_DIR/static/5k.bin" bs=5120 count=1 2>/dev/null

CLIENT_CMD="docker run --rm --network host --cpuset-cpus=2-5 --entrypoint /usr/local/bin/tquic_client tquic-bench:latest --threads $THREADS --max-concurrent-conns $CONNS --max-requests-per-conn 0 --max-concurrent-requests $CONCURRENT_REQS --total-requests-per-thread 0 --send-udp-payload-size 1350 --duration $DURATION --connect-to 127.0.0.1:8445 https://127.0.0.1:8445/static/5k.bin"

echo "=== NAVETTE SERVER ==="

# Start navette with alloc counting
STATIC_PORT=8445 STATIC_BODY_SIZE=5120 \
  LD_PRELOAD="$SHIM" \
  "$EXAMPLE_DIR/static_h3_server" 2>/tmp/navette-alloc.log &
NAVETTE_PID=$!
sleep 2

# Reset counters
kill -USR1 $NAVETTE_PID 2>/dev/null
sleep 0.5

# Run client
echo "Running client for ${DURATION}s..."
$CLIENT_CMD 2>&1 | tee /tmp/navette-client.log

# Dump counters
sleep 1
kill -USR1 $NAVETTE_PID 2>/dev/null
sleep 0.5

# Extract results
echo "--- navette alloc counts ---"
grep '\[alloc_count\]' /tmp/navette-alloc.log | tail -1

# Extract rps from client
echo "--- navette client output (rps) ---"
grep -iE 'requests|total|succeeded|rps|throughput' /tmp/navette-client.log || true

kill $NAVETTE_PID 2>/dev/null
wait $NAVETTE_PID 2>/dev/null || true
sleep 2

echo ""
echo "=== TQUIC SERVER ==="

# Start TQUIC server with alloc counting (need to mount shim into Docker)
# First, check if tquic_server supports the same static file serving
docker run --rm -d \
  --name tquic-alloc-test \
  --network host \
  --cpuset-cpus=0 \
  -v "$SHIM:/usr/local/lib/liballoc_count.so:ro" \
  -v "$DATA_DIR:/data:ro" \
  -v "$EXAMPLE_DIR/certs:/certs:ro" \
  --entrypoint /bin/sh \
  tquic-bench:latest \
  -c 'LD_PRELOAD=/usr/local/lib/liballoc_count.so /usr/local/bin/tquic_server --listen 0.0.0.0:8445 --root /data --cert /certs/server.crt --key /certs/server.key 2>/tmp/tquic-alloc.log &
      sleep 999999' || {
    echo "TQUIC server Docker start failed"
    exit 1
  }
sleep 3

# Reset counters - send SIGUSR1 to the tquic_server process inside Docker
docker exec tquic-alloc-test sh -c 'kill -USR1 $(pgrep tquic_server)' 2>/dev/null
sleep 0.5

# Run client
echo "Running client for ${DURATION}s..."
$CLIENT_CMD 2>&1 | tee /tmp/tquic-client.log

# Dump counters
sleep 1
docker exec tquic-alloc-test sh -c 'kill -USR1 $(pgrep tquic_server)' 2>/dev/null
sleep 0.5

# Extract results
echo "--- TQUIC alloc counts ---"
docker exec tquic-alloc-test cat /tmp/tquic-alloc.log 2>/dev/null | grep '\[alloc_count\]' | tail -1

echo "--- TQUIC client output (rps) ---"
grep -iE 'requests|total|succeeded|rps|throughput' /tmp/tquic-client.log || true

# Cleanup
docker stop tquic-alloc-test 2>/dev/null || true
docker rm tquic-alloc-test 2>/dev/null || true

echo ""
echo "=== DONE ==="
echo "Compute: allocs_per_request = total_alloc / requests"
