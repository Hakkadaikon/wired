#!/usr/bin/env bash
# Stability-scenario orchestration: static frontend + Chrome pin only. The
# wired_server itself is spawned (and killed/restarted) by run-scenario.mjs,
# so scenarios can exercise server crashes and fingerprint re-scrapes.
set -euo pipefail

cd "$(dirname "$0")/.."   # examples/moqt_chat/

SCENARIO="${1:?usage: run-stability.sh <scenario-id> [--args...]}"
shift

# Stale servers keep 4433/udp via SO_REUSEPORT and silently steal packets
# from the scenario's own server -- sweep them first.
pgrep -x wired_server >/dev/null 2>&1 && { pkill -x wired_server; sleep 0.5; } || true

FRONTEND_PORT=8093   # distinct from run.sh (8091) / run-voice.sh (8092)
trap 'kill "${FRONTEND_PID:-0}" 2>/dev/null || true' EXIT
python3 -m http.server "$FRONTEND_PORT" --directory frontend/out >/dev/null 2>&1 &
FRONTEND_PID=$!
sleep 1

# Chrome 150+ fails this server's cert-hash pinning (CERTIFICATE_VERIFY_FAILED);
# pin the known-good 146 build unless the caller already chose one.
CHROME_146="$HOME/.cache/puppeteer/chrome/linux-146.0.7680.153/chrome-linux64/chrome"
if [ -z "${CHROME_PATH:-}" ] && [ -x "$CHROME_146" ]; then
  export CHROME_PATH="$CHROME_146"
fi

node e2e/run-scenario.mjs \
  --scenario="$SCENARIO" \
  --url="http://localhost:$FRONTEND_PORT/" \
  "$@"
