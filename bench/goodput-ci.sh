#!/bin/bash
# Run the interop-runner goodput case for each server and emit one markdown
# row per server (the runner's own 5-repetition mean ± sd). A failed run
# gets an explicit "run failed" cell instead of silently vanishing, and the
# script exits non-zero so a CI job cannot go green without measurements.
# Usage: goodput-ci.sh <runner-dir> <servers-csv>
set -u
RUNNER=$1
SERVERS=$2
cd "$RUNNER"
fail=0
echo "| Server | Goodput (5 runs) |"
echo "|---|---|"
IFS=, read -ra list <<< "$SERVERS"
for s in "${list[@]}"; do
  # The runner's compose file uses fixed container names; debris from an
  # interrupted earlier run would fail every following one with a name
  # conflict, so sweep them first.
  docker rm -f sim server client >/dev/null 2>&1 || true
  # --debug: a compliance-check failure only names its cause at debug level
  # (the ci-*.log artifacts are per-server, so the volume is acceptable).
  .venv/bin/python run.py --debug -s "$s" -c quic-go -t goodput \
    > "ci-$s.log" 2>&1
  out=$(grep -o 'G: [0-9]* (± [0-9]*) kbps' "ci-$s.log" | head -1)
  if [ -z "$out" ]; then fail=1; fi
  echo "| $s | ${out:-run failed (see ci-$s.log artifact)} |"
done
exit "$fail"
