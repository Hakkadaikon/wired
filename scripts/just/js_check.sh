#!/bin/sh
# The moqt_chat frontend and e2e scripts: biome, the type check, both unit
# suites, and their complexity limits -- frontend CCN <= 10; e2e CCN and
# both Halstead sets capped at the maximum when the gate was added (see
# PROFILES in scripts/halstead.py). Needs node + pnpm and both
# node_modules installed.
. scripts/just/lib.sh
nix_reexec "$0" "$@"
set -eu
fe=examples/moqt_chat/frontend
e2e=examples/moqt_chat/e2e
(cd "$fe" && pnpm check && npx tsc --noEmit -p . && pnpm test)
"$fe/node_modules/.bin/biome" ci --config-path="$fe/biome.json" --error-on-warnings "$e2e"
(cd "$e2e" && node --test test/*.test.mjs)
lizard -x '*/node_modules/*' --CCN 10 -w "$fe/src"
lizard -x '*/node_modules/*' --CCN 26 -w "$e2e"
sh scripts/just/rca.sh --check --profile frontend "$fe/src"
sh scripts/just/rca.sh --check --profile e2e "$e2e"
