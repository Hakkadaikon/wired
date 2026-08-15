#!/bin/bash
# Run the interop-runner goodput case for each server and emit one markdown
# row per server (the runner's own 5-repetition mean ± sd). A failed run
# gets an explicit "run failed" cell instead of silently vanishing.
# Usage: goodput-ci.sh <runner-dir> <servers-csv>
set -u
RUNNER=$1
SERVERS=$2
cd "$RUNNER"
echo "| Server | Goodput (5 runs) |"
echo "|---|---|"
IFS=, read -ra list <<< "$SERVERS"
for s in "${list[@]}"; do
  # The runner's compose file uses fixed container names; debris from an
  # interrupted earlier run would fail every following one with a name
  # conflict, so sweep them first.
  docker rm -f sim server client >/dev/null 2>&1 || true
  .venv/bin/python run.py -s "$s" -c quic-go -t goodput > "ci-$s.log" 2>&1
  out=$(grep -o 'G: [0-9]* (± [0-9]*) kbps' "ci-$s.log" | head -1)
  echo "| $s | ${out:-run failed (see ci-$s.log artifact)} |"
done
