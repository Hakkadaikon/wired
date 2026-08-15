#!/bin/bash
# Loopback-lane driver for one server: N rounds of (ttfb n=100, load
# n=10000 c=20), pinned CPU layout, one speed line per run plus one usage
# line per load round (raw /proc counters only -- lib/aggregate.mjs does
# every derivation). Usage:
#   run-lane.sh <name> <port> <rounds> <server-cmd...>
# Env: BENCH_CLIENT (benchclient binary, default: <this dir>/client/benchclient),
#      SERVER_CPU / CLIENT_CPUS (default 3 / 0,1; shifted down when nproc<4).
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
NAME=$1; PORT=$2; ROUNDS=$3; shift 3
CLIENT=${BENCH_CLIENT:-$DIR/client/benchclient}
NCPU=$(nproc)
SERVER_CPU=${SERVER_CPU:-$((NCPU >= 4 ? 3 : NCPU - 1))}
CLIENT_CPUS=${CLIENT_CPUS:-0,1}
HZ=$(getconf CLK_TCK)
URL="https://127.0.0.1:$PORT/1k.bin"

taskset -c "$SERVER_CPU" "$@" >"/tmp/bench-$NAME.server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 1.5

# /proc/<pid>/stat utime+stime (fields 14+15, counted after the ')' so a
# space in comm cannot shift them), summed over all threads by the kernel.
cpu_ticks() { awk '{sub(/.*\) /, ""); print $12 + $13}' "/proc/$SRV/stat"; }
rss_kb() { awk -v k="$1" '$1 == k":" {print $2}' "/proc/$SRV/status"; }

echo "$NAME r0 usage kind=idle reqs=0 dticks=0 wall_ms=0 hz=$HZ vmhwm_kb=$(rss_kb VmHWM) vmrss_kb=$(rss_kb VmRSS)"

for r in $(seq 1 "$ROUNDS"); do
  echo -n "$NAME r$r "
  taskset -c "$CLIENT_CPUS" "$CLIENT" -mode ttfb -n 100 -url "$URL"
  T0=$(cpu_ticks); W0=$(date +%s%3N)
  echo -n "$NAME r$r "
  taskset -c "$CLIENT_CPUS" "$CLIENT" -mode load -n 10000 -c 20 -url "$URL"
  T1=$(cpu_ticks); W1=$(date +%s%3N)
  echo "$NAME r$r usage kind=load reqs=10000 dticks=$((T1 - T0)) wall_ms=$((W1 - W0)) hz=$HZ vmhwm_kb=$(rss_kb VmHWM) vmrss_kb=$(rss_kb VmRSS)"
done

kill $SRV 2>/dev/null
wait 2>/dev/null
exit 0
