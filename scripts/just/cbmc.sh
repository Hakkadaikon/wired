#!/bin/sh
# Bounded model checks under verify/cbmc (CBMC from the flake's verify
# shell): every property holds, and every reachable line in the harness
# is reached (--cover location, over the harness itself only -- no
# __CPROVER_cover calls to maintain, and no extra CBMC run combining
# --cover with a custom-declared builtin, which produced an internal
# CBMC error when tried: https://github.com/diffblue/cbmc docs don't
# recommend mixing them). A harness with dead code would otherwise pass
# while checking less than it claims to.
set -eu
status=0
for h in verify/cbmc/*.c; do
    echo "== $h"
    if ! cbmc -Isrc --unwind 9 --unwinding-assertions --bounds-check \
        --pointer-check "$h"; then
        status=1
    fi
    # Coverage over the harness file's own lines only: --cover location
    # also walks the srvrun_gen.h it includes, and that shared header's
    # own branches (e.g. its unused-by-this-model short-circuit paths)
    # are not this harness's lines to cover.
    cover=$(cbmc -Isrc --unwind 9 --cover location "$h" | grep "file $h ")
    total=$(echo "$cover" | wc -l)
    hit=$(echo "$cover" | grep -c ': SATISFIED$')
    echo "$hit of $total lines of $h covered"
    if [ "$hit" != "$total" ]; then
        status=1
    fi
done
exit "$status"
