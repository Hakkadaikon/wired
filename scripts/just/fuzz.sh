#!/bin/sh
# Fuzz harnesses. Usage: fuzz.sh smoke  -- every harness builds (one
# parallel ninja call) and survives one run (the per-PR gate);
# fuzz.sh ci SECS -- each harness for SECS seconds, seeding from and growing
# fuzz/corpus/<harness>/ (the nightly sweep; the Fuzz workflow only uploads
# the grown corpus, inputs worth keeping are committed by hand).
set -eu
harnesses() { for f in fuzz/fuzz_*.c; do echo "${f%.c}"; done; }
if [ "$1" = smoke ]; then
    # shellcheck disable=SC2046 # one target per word
    ninja $(harnesses)
    for t in $(harnesses); do "./$t" -runs=1 -artifact_prefix=fuzz/; done
else
    for t in $(harnesses); do
        ninja "$t"
        "./$t" -max_total_time="$2" -artifact_prefix=fuzz/ "fuzz/corpus/${t#fuzz/}"
    done
fi
