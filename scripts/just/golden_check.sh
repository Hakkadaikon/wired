#!/bin/sh
# tests/app/moqt_golden.h has no drift from
# examples/moqt_chat/testvectors/moqt_golden.json.
. scripts/just/lib.sh
nix_reexec "$0" "$@"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
python3 scripts/gen_moqt_golden.py "$tmp/moqt_golden.h"
clang-format -style=file:.clang-format -i "$tmp/moqt_golden.h"
diff -u tests/app/moqt_golden.h "$tmp/moqt_golden.h"
