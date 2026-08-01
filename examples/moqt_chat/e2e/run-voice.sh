#!/usr/bin/env bash
# Same orchestration as run.sh (start wired_server + static frontend, scrape
# the cert fingerprint, tear down after), but runs the chat+voice load test
# instead of the chat-only one -- see run-voice-load-test.mjs.
set -euo pipefail

cd "$(dirname "$0")/.."   # examples/moqt_chat/

SERVER_LOG="$(mktemp)"
FRONTEND_PORT=8092   # distinct from run.sh's 8091

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

node e2e/run-voice-load-test.mjs \
  --url="http://localhost:$FRONTEND_PORT/" \
  --cert-hash="$CERT_HASH" \
  "$@"
