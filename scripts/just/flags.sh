# shellcheck shell=sh
# Compile flag sets (sourced by gen_ninja.sh, cov.sh, cognitive.sh).
# Max simultaneous connections per server process: each slot is a fixed
# array (~1.9MiB/conn of BSS); 4 matches moqt_chat's participant pool.
# Override: `CONNTABLE_CAP=256 just ninja`.

CC=clang
TARGET="-target x86_64-unknown-linux-gnu"
# Shared warning/optimization base of the three compile flag sets.
WARNFLAGS="-Wall -Wextra -Werror -O2"
CONNFLAGS="-DWIRED_CONNTABLE_CAP=${CONNTABLE_CAP:-4}"
# freestanding: every src file must compile with no libc at all (the product
# constraint). Also the base of the example binaries (plus -DWIRED_DEBUG).
CFLAGS="$TARGET -ffreestanding -fno-stack-protector -fno-builtin -nostdlib -static $WARNFLAGS $CONNFLAGS -Isrc"
# hosted test: -mbranches-within-32B-boundaries works around this host's
# Cascade Lake JCC erratum, which otherwise swings test runtime ~40% on
# code-placement luck and makes perf comparisons between commits meaningless.
TESTFLAGS="$WARNFLAGS $CONNFLAGS -mbranches-within-32B-boundaries -Isrc -Itests"
# fuzz: hosted, ASan + libFuzzer.
FUZZFLAGS="$WARNFLAGS -g -fsanitize=fuzzer,address -Isrc"
# clang-tidy: CERT C + bug finders, minus this repo's unavoidable noise --
# `_start` is a required entry point (reserved-identifier, dcl37) and every
# p256_fe is `const u64*` (easily-swappable-parameters). readability checks
# (6k+ hits) are left out on purpose, except cognitive complexity.
TIDYCHECKS="-*,cert-*,bugprone-*,clang-analyzer-*,-bugprone-easily-swappable-parameters,-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp,readability-function-cognitive-complexity"
# Cognitive complexity <= 4 for every function: the tree's maximum when the
# limit was set (`just cognitive` reports every score).
TIDYCONFIG="{CheckOptions: {readability-function-cognitive-complexity.Threshold: 4}}"
TIDYFLAGS="$TARGET -ffreestanding -nostdlib -fno-builtin -Isrc"
export CC CFLAGS TESTFLAGS FUZZFLAGS TIDYCHECKS TIDYCONFIG TIDYFLAGS
