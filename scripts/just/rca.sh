#!/bin/sh
# Halstead/MI/exits/parameters per function and file (rust-code-analysis):
# a report, or with --check the limits scripts/halstead.py enforces.
# Usage: rca.sh [--check [--profile NAME]] path...  (profiles: halstead.py)
. scripts/just/lib.sh
nix_reexec "$0" "$@"
set -eu
mode=""
if [ "${1:-}" = "--check" ]; then
    mode=--check
    shift
fi
if [ "${1:-}" = "--profile" ]; then
    mode="$mode --profile $2"
    shift 2
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for p in "$@"; do
    rust-code-analysis-cli -m -O json -I '*.[ch]' '*.py' '*.ts' '*.tsx' '*.mjs' '*.js' \
        -X '*node_modules*' -p "$p" -o "$tmp" >/dev/null
done
# shellcheck disable=SC2086 # $mode is zero to three words
python3 scripts/halstead.py $mode "$tmp"
