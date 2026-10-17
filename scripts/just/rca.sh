#!/bin/sh
# Halstead/MI/exits/parameters per function and file (rust-code-analysis):
# a report, or with --check the limits scripts/halstead.py enforces.
# Usage: rca.sh [--check] path...
. scripts/just/lib.sh
nix_reexec "$0" "$@"
set -eu
mode=""
if [ "${1:-}" = "--check" ]; then
    mode=--check
    shift
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for p in "$@"; do
    rust-code-analysis-cli -m -O json -I '*.[ch]' '*.py' '*.ts' '*.tsx' \
        -p "$p" -o "$tmp" >/dev/null
done
python3 scripts/halstead.py $mode "$tmp"
