#!/usr/bin/env bash
# h2-throughput.sh — Phase 0 throughput tier.
#
# Boots each server in turn, runs warmup + measured h2load against an
# endpoint set, captures req/s + p50/p99/p999/bytes-per-req per row to
# bench/profile/baselines/h2-throughput.csv.
#
# This is the *trend metric* for H2 perf work: every optimization PR
# appends a row, and we read the CSV to spot regressions across
# /baseline2, /json/, /static/.
#
# Knobs (env):
#   N           h2load -n (default 200000)
#   C           h2load -c (default 50)
#   M           h2load -m (default 16)
#   WARMUP_REQS h2load warmup -n (default 5000)
#   SERVERS     space-separated; default "mojo-net hyper"
#   ENDPOINTS   space-separated; default = three-endpoint mix
#   OUT_CSV     append target (default bench/profile/baselines/h2-throughput.csv)
#
# Measured per row: timestamp, git_sha, server, endpoint, n, c, m,
# reqs_per_s, p50_us, p99_us, p999_us, bytes_per_req.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARENA="$REPO_ROOT/bench/.httparena"
CERTS_DIR="$ARENA/certs"
DATA_DIR="$ARENA/data"

N="${N:-200000}"
C="${C:-50}"
M="${M:-16}"
WARMUP_REQS="${WARMUP_REQS:-5000}"
SERVERS="${SERVERS:-mojo-net hyper}"
# Endpoint set: small body, JSON-ish, static file. Static fallback uses
# the smallest committed fixture in HttpArena's data/static.
ENDPOINTS_DEFAULT='/baseline2?a=1&b=2 /json/50?m=6 /static/footer.html'
ENDPOINTS="${ENDPOINTS:-$ENDPOINTS_DEFAULT}"

OUT_CSV="${OUT_CSV:-$REPO_ROOT/bench/profile/baselines/h2-throughput.csv}"

if [ ! -d "$ARENA" ]; then
    echo "error: $ARENA not found. Clone HttpArena into bench/.httparena first." >&2
    exit 1
fi

mkdir -p "$(dirname "$OUT_CSV")"
if [ ! -s "$OUT_CSV" ]; then
    echo "timestamp,git_sha,server,endpoint,n,c,m,reqs_per_s,p50_us,p99_us,p999_us,bytes_per_req" > "$OUT_CSV"
fi

GIT_SHA="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

DOCKER_FLAGS=(
    -d --rm --network host
    --security-opt seccomp=unconfined
    --ulimit memlock=-1:-1
    --ulimit nofile=1048576:1048576
    -v "$DATA_DIR/dataset.json:/data/dataset.json:ro"
    -v "$DATA_DIR/static:/data/static:ro"
    -v "$CERTS_DIR:/certs:ro"
)

wait_for_h2() {
    local tries=20
    while ! docker run --rm --network host h2load:latest -n 10 -c 1 -m 1 \
        "https://127.0.0.1:8443/baseline2?a=1&b=2" 2>&1 | grep -q "10 succeeded"; do
        tries=$((tries - 1))
        [ $tries -le 0 ] && return 1
        sleep 1
    done
    return 0
}

# Compute p50/p99/p999 of column 3 (microseconds-until-end) from h2load --log-file output.
# h2load log line format: "<start_us>\t<status>\t<resp_us>".
percentiles() {
    local logfile="$1"
    awk -F'\t' 'NR>0 && $2~/^2/ {print $3}' "$logfile" | sort -n | awk '
        { v[NR]=$1 }
        END {
            n=NR
            if (n==0) { print "0,0,0"; exit }
            p50=v[int(n*0.50+0.5)]
            p99=v[int(n*0.99+0.5)]
            p999=v[int(n*0.999+0.5)]
            if (p50=="")  p50=v[n]
            if (p99=="")  p99=v[n]
            if (p999=="") p999=v[n]
            printf "%d,%d,%d\n", p50, p99, p999
        }'
}

run_one() {
    local server="$1" endpoint="$2"
    local image="httparena-$server"

    echo
    echo "============================================"
    echo "  $server  ${endpoint}"
    echo "============================================"
    docker rm -f "bench-throughput-$server" >/dev/null 2>&1 || true
    docker run --name "bench-throughput-$server" "${DOCKER_FLAGS[@]}" "$image" >/dev/null
    if ! wait_for_h2; then
        echo "[$server] FAIL: h2 didn't accept requests within 20s" >&2
        docker rm -f "bench-throughput-$server" >/dev/null 2>&1 || true
        return
    fi

    # Warmup (discarded).
    docker run --rm --network host h2load:latest \
        -n "$WARMUP_REQS" -c "$C" -m "$M" \
        "https://127.0.0.1:8443${endpoint}" >/dev/null 2>&1 || true

    # Measured run with per-request log → percentiles.
    local logdir
    logdir="$(mktemp -d)"
    chmod 777 "$logdir"
    local h2load_out
    h2load_out="$(docker run --rm --network host \
        --user "$(id -u):$(id -g)" \
        -v "$logdir:/log" \
        h2load:latest \
        -n "$N" -c "$C" -m "$M" \
        --log-file=/log/req.tsv \
        "https://127.0.0.1:8443${endpoint}" 2>&1)"

    docker rm -f "bench-throughput-$server" >/dev/null 2>&1 || true

    local reqs_per_s
    reqs_per_s="$(echo "$h2load_out" | awk -F'[, ]+' '/^finished in/ {for(i=1;i<=NF;i++) if ($i ~ /req\/s/){print $(i-1); exit}}')"
    [ -z "$reqs_per_s" ] && reqs_per_s=0

    # bytes/req = total traffic bytes / total requests
    local total_bytes
    total_bytes="$(echo "$h2load_out" | awk '/^traffic:/ {match($0, /\(([0-9]+)\)/, a); print a[1]; exit}')"
    [ -z "$total_bytes" ] && total_bytes=0
    local bytes_per_req=0
    if [ "$N" -gt 0 ] 2>/dev/null; then
        bytes_per_req=$(( total_bytes / N ))
    fi

    local pcts
    pcts="$(percentiles "$logdir/req.tsv")"
    rm -rf "$logdir"

    echo "[$server $endpoint] reqs/s=$reqs_per_s p50/p99/p999=$pcts us  bytes/req=$bytes_per_req"
    echo "$TS,$GIT_SHA,$server,$endpoint,$N,$C,$M,$reqs_per_s,$pcts,$bytes_per_req" >> "$OUT_CSV"

    sleep 2
}

for server in $SERVERS; do
    for endpoint in $ENDPOINTS; do
        run_one "$server" "$endpoint"
    done
done

echo
echo "Appended $(wc -l < "$OUT_CSV") total rows to $OUT_CSV"
