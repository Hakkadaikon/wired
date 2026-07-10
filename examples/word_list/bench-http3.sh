#!/usr/bin/env bash
# HTTP/3 latency bench: N requests, min/median/p90 of handshake and total.
# Run from the OUTSIDE machine against a wired_server started in the driver
# you want to measure, then flip the driver and run again:
#   plain     ./wired_server --port 4433
#   busy-poll ./wired_server --port 4433 --busy-poll
#   xdp       sudo ./wired_server --ifindex <n> --ip <a.b.c.d> --port 4433 --skb-mode
# Usage:
#   URL=https://<IP>:4433/ N=20 ./bench-http3.sh
# CURL overrides the client command (default: dockerized curl with HTTP/3).
set -u

URL="${URL:?set URL=https://<IP>:4433/}"
N="${N:-20}"
CURL="${CURL:-docker run --rm ymuski/curl-http3 curl}"

TIMES="$(mktemp /tmp/wired-bench.XXXXXX)"
trap 'rm -f "$TIMES"' EXIT

echo "=== $N requests to $URL ==="
for i in $(seq 1 "$N"); do
  $CURL --http3-only --insecure -o /dev/null -s \
    -w '%{time_appconnect} %{time_total}\n' \
    "$URL" -d hello --max-time 8 >>"$TIMES" || echo "request $i FAILED"
done

# column <n>: sorted min / median / p90, in milliseconds
col_stats() {
  awk -v c="$1" '{print $c}' "$TIMES" | sort -n | awk '
    {v[NR] = $1}
    END {
      if (!NR) {print "no data"; exit}
      printf "min %.1fms  median %.1fms  p90 %.1fms  (n=%d)\n",
        v[1]*1000, v[int((NR+1)/2)]*1000, v[int(NR*0.9+0.5)]*1000, NR
    }'
}

echo "handshake (time_appconnect):"
col_stats 1
echo "total     (time_total):"
col_stats 2
