#!/usr/bin/env bash
# Orchestrates one load-test run: start wired_server + a static frontend
# server, scrape the logged cert fingerprint, run run-load-test.mjs, then
# tear both servers down -- so `just e2e-load` is a single command with no
# manual fingerprint copy-paste. See ../justfile for the recipes that call
# this.
set -euo pipefail

cd "$(dirname "$0")/.."   # examples/moqt_chat/

SERVER_LOG="$(mktemp)"
FRONTEND_PORT=8091   # distinct from serve-frontend's 8443 / dev-frontend's 5173
# wired_server binds with SO_REUSEPORT (srvrun.c's srvrun_listen), which lets
# the kernel accept a second bind on the same port without erroring -- but it
# also means a NEXT run of this script that starts before this run's server
# has actually finished exiting can have its Initial packets hashed onto the
# still-closing old socket by the kernel's SO_REUSEPORT load balancing
# (that socket's process is mid-SIGTERM and never answers them). `wait`ing
# on SERVER_PID after the kill (not just sending the signal) closes that
# window: the old socket is gone before this script's trap returns, so the
# next run's bind is the only listener on the port.
trap 'kill "${SERVER_PID:-0}" "${FRONTEND_PID:-0}" 2>/dev/null || true; wait "${SERVER_PID:-0}" 2>/dev/null || true; rm -f "$SERVER_LOG"' EXIT

./wired_server >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
  grep -q 'cert sha-256 fingerprint:' "$SERVER_LOG" && break
  sleep 0.1
done
CERT_HASH="$(grep -o 'fingerprint: .*' "$SERVER_LOG" | sed 's/fingerprint: //')"
if [ -z "$CERT_HASH" ]; then
  echo "server did not print a fingerprint within 5s; log:" >&2
  cat "$SERVER_LOG" >&2
  exit 1
fi

python3 -m http.server "$FRONTEND_PORT" --directory frontend/out >/dev/null 2>&1 &
FRONTEND_PID=$!
sleep 1

node e2e/run-load-test.mjs \
  --url="http://localhost:$FRONTEND_PORT/" \
  --cert-hash="$CERT_HASH" \
  "$@"
