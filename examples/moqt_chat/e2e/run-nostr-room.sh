#!/bin/sh
# s25-nostr-room needs a frontend built with NEXT_PUBLIC_NOSTR_HOST set to
# the scenario's host key (user1's fixed test key, 0x01..): set it, then
# build and run the scenario through the usual recipe.
#   ./e2e/run-nostr-room.sh [--shots=<dir>]
set -eu
cd "$(dirname "$0")"
NEXT_PUBLIC_NOSTR_HOST=$(node --input-type=module -e \
  'import { pubkeyOf } from "./lib/nostrE2e.mjs"; console.log(pubkeyOf(1));')
export NEXT_PUBLIC_NOSTR_HOST
cd ..
exec just e2e-stability s25-nostr-room "$@"
