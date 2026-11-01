#!/bin/sh
# Mutation-tests verify/cbmc's two harnesses against five hand-written
# mutants of src/app/http3/server/srvrun/srvrun_gen.h (run by `just
# cbmc-mutate`). Each mutant is a full copy of the real src/ tree with
# one line of srvrun_gen.h changed, placed so `#include
# "app/http3/server/srvrun/srvrun_gen.h"` resolves to the mutant instead
# of the real header (a flat `-I <dir>` with the header loose in it does
# NOT work: the compiler still finds the real header via -Isrc first,
# and the mutant is silently skipped -- this script copies the whole
# src/ tree per mutant specifically to avoid that trap).
#
# For each mutant this prints, for each of the two harnesses, whether
# CBMC's verdict on the real code (VERIFICATION SUCCESSFUL) flips to
# VERIFICATION FAILED. mut1/mut2/mut4/mut5 must flip at least one
# harness (a real behavior change the properties are sensitive to);
# mut3 must NOT flip either harness -- it removes the `r_gen != 0`
# guard in srvrun_wt_ref_shaped, which srvrun_gen.h's own comment
# documents as defense-in-depth that the real code's open-before-active
# ordering (srvrun_start.c, srvrun_live.c) makes unreachable, so the
# model correctly cannot tell the guarded and unguarded code apart.
# This script fails (exit 1) if any expectation is violated, so a
# weakened property or a fixed "unreachable" guard that becomes
# reachable both show up as a red `just cbmc-mutate`, not as a stale
# prose claim in a commit message.
set -eu

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mutate() {
    # mutate NAME SEARCH REPLACE: a full src/ copy with one substitution
    # in srvrun_gen.h. The copy lands at "$dir/src" so "-I$dir" mirrors
    # this repo's own "-Isrc" (srvrun_gen.h's #include path is
    # "app/http3/server/srvrun/srvrun_gen.h", i.e. relative to a src/
    # root) -- putting the copy one level off here is exactly the bug
    # that made every mutant silently fall through to the real header
    # the first time this script was written, so the directory check
    # right after `cp` is load-bearing, not decoration.
    name=$1 search=$2 replace=$3
    dir="$tmp/$name"
    mkdir -p "$dir"
    cp -r src "$dir/src"
    gen="$dir/src/app/http3/server/srvrun/srvrun_gen.h"
    [ -f "$gen" ] || {
        echo "mutate: $gen missing after copy, directory layout is wrong" >&2
        exit 1
    }
    sed "s#$search#$replace#" src/app/http3/server/srvrun/srvrun_gen.h \
        > "$gen.new"
    if cmp -s "$gen" "$gen.new"; then
        echo "mutate: $name's substitution did not change srvrun_gen.h" >&2
        exit 1
    fi
    mv "$gen.new" "$gen"
}

# mut1: srvrun_wt_gen_next never advances (always returns *last unchanged).
mutate mut1 \
    '\*last += 1 + (\*last == (u32)-1);' \
    '(void)0;'
# mut2: srvrun_wt_ref_resolves ignores the caller's generation entirely.
mutate mut2 \
    'return cur_gen == r_gen;' \
    'return 1;'
# mut3 (expected NOT to be caught): drop the r_gen != 0 guard.
mutate mut3 \
    'return r_s != 0 \&\& r_gen != 0;' \
    'return r_s != 0;'
# mut4: srvrun_conn_gen_next never advances.
mutate mut4 \
    'static inline u32 srvrun_conn_gen_next(u32 gen) { return gen + 1; }' \
    'static inline u32 srvrun_conn_gen_next(u32 gen) { return gen; }'
# mut5: srvrun_conn_gen_live ignores the generation match.
mutate mut5 \
    'return up \&\& gen == want;' \
    'return up;'

status=0
for m in mut1 mut2 mut3 mut4 mut5; do
    any_caught=0
    for h in verify/cbmc/*.c; do
        verdict=$(cbmc -I"$tmp/$m/src" --unwind 9 --unwinding-assertions \
            --bounds-check --pointer-check "$h" | grep -E '^VERIFICATION')
        echo "$m $h: $verdict"
        [ "$verdict" = "VERIFICATION FAILED" ] && any_caught=1
        if [ "$m" = mut3 ] && [ "$verdict" = "VERIFICATION FAILED" ]; then
            echo "mutate: mut3 was caught by $h, expected it not to be" >&2
            status=1
        fi
    done
    if [ "$m" != mut3 ] && [ "$any_caught" = 0 ]; then
        echo "mutate: $m was caught by neither harness, expected at least one" >&2
        status=1
    fi
done

exit "$status"
