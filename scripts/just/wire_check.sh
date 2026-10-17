#!/bin/sh
# Every src/**/*.c is in tests/run.c once and builds one object. A mismatch
# means a source is committed but never built or tested. Run after `ninja`.
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
find src -name '*.c' | sed 's|^src/||' | sort > "$tmp/src"
grep '^#include ".*\.c"' tests/run.c | grep -v '_test\.c"' \
    | sed 's/^#include "//; s/"$//' | sort > "$tmp/inc"
nsrc=$(wc -l < "$tmp/src")
nobj=$(find build/src -name '*.o' | wc -l)
echo "src .c: $nsrc / freestanding .o: $nobj"
[ "$nsrc" -eq "$nobj" ] || { echo "WIRING MISMATCH: a source compiles to no object" >&2; exit 1; }
# unity build: every src .c included once, except sys.c (its only symbol
# is the SDK's own _start; the hosted binary uses libc's startup).
miss=$(comm -23 "$tmp/src" "$tmp/inc")
[ "$miss" = "common/platform/sys/sys.c" ] || { echo "WIRING MISMATCH: not in run.c:"; echo "$miss"; exit 1; } >&2
gone=$(comm -13 "$tmp/src" "$tmp/inc")
[ -z "$gone" ] || { echo "WIRING MISMATCH: run.c includes deleted sources:"; echo "$gone"; exit 1; } >&2
echo "wiring OK ($nsrc sources, sys.c excluded from the unity TU by design)"
