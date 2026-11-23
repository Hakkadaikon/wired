#!/bin/sh
# Secret-taint constant-time check (tests/ct/ct_taint.c) under valgrind
# memcheck. Every leak = 1 case (the negative control) must still be
# reported -- memcheck's exit 99, not a crash or an output mismatch -- else
# the harness is blind; then every gated case must run clean.
# `ct_check.sh <case>` runs one case (`neg`: expected to fail).
set -eu
ninja build/ct_taint
vg() {
    valgrind -q --error-exitcode=99 --track-origins=yes ./build/ct_taint "$@"
}
if [ $# -gt 0 ]; then
    vg "$@"
    exit
fi
for c in $(./build/ct_taint leaks); do
    rc=0
    vg "$c" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 99 ]; then
        echo "ct-check: $c exited $rc, not memcheck's 99 (blind harness, crash, or fixed: set leak = 0)" >&2
        exit 1
    fi
    echo "ct-check: $c reported (expected)"
done
vg
