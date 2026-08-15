#!/bin/bash
# Prepare a quic-interop-runner checkout for the goodput lane: clone at the
# pinned commit, create its venv, and register wired (server role) in
# implementations_quic.json. Usage: goodput-setup.sh <runner-dir>
set -eu
RUNNER=$1
PIN=1d6f655
if [ ! -d "$RUNNER/.git" ]; then
  git clone https://github.com/quic-interop/quic-interop-runner "$RUNNER"
fi
git -C "$RUNNER" checkout -q "$PIN"
python3 -m venv "$RUNNER/.venv"
"$RUNNER/.venv/bin/pip" install -q -r "$RUNNER/requirements.txt"
tmp=$(mktemp)
jq '.wired = {"image": "wired-interop", "url": "https://github.com/Hakkadaikon/wired", "role": "server"}' \
  "$RUNNER/implementations_quic.json" > "$tmp"
mv "$tmp" "$RUNNER/implementations_quic.json"
