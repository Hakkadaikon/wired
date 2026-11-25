# shellcheck shell=sh
# Compile flag sets (sourced by gen_ninja.sh, cov.sh, cognitive.sh).
# Max simultaneous connections per server process: each slot is a fixed
# array (~10 MiB/conn of BSS, docs/architecture/memory.md 3). Override:
# `CONNTABLE_CAP=256 just ninja`. The moqt_chat server does not use it:
# its room profile sets 16 (ROOMCONNFLAG below).

CC=clang
# The ISA to build for: the host's (x86_64 or aarch64), or WIRED_ARCH to
# cross-compile the freestanding objects (linking needs that ISA's linker).
WIRED_ARCH="${WIRED_ARCH:-$(uname -m)}"
TARGET="-target ${WIRED_ARCH}-unknown-linux-gnu"
# -mbranches-within-32B-boundaries: an x86 assembler option (see TESTFLAGS).
JCCFLAGS=""
if [ "$WIRED_ARCH" = x86_64 ]; then
  JCCFLAGS="-mbranches-within-32B-boundaries"
fi
# aarch64: inline the atomics (LL/SC or LSE) instead of calling libgcc's
# outline helpers (__aarch64_cas8_acq_rel ...), which -nostdlib lacks.
ISAFLAGS=""
if [ "$WIRED_ARCH" = aarch64 ]; then
  ISAFLAGS="-mno-outline-atomics"
fi
# Shared warning/optimization base of the three compile flag sets.
WARNFLAGS="-Wall -Wextra -Werror -O2"
CONNFLAGS="-DWIRED_CONNTABLE_CAP=${CONNTABLE_CAP:-4}"
# Concurrent WT sessions per connection (header default 2); CI also runs the
# suite with WT_SESSIONS=3 so nothing hard-codes 2.
if [ -n "${WT_SESSIONS:-}" ]; then
  CONNFLAGS="$CONNFLAGS -DWIRED_SRVRUN_MAX_WT_SESSIONS=$WT_SESSIONS"
fi
# freestanding: every src file must compile with no libc at all (the product
# constraint). Also the base of the example binaries (plus -DWIRED_DEBUG).
CFLAGS="$TARGET $ISAFLAGS -ffreestanding -fno-stack-protector -fno-builtin -nostdlib -static $WARNFLAGS $CONNFLAGS -Isrc"
# hosted test: -mbranches-within-32B-boundaries works around this host's
# Cascade Lake JCC erratum, which otherwise swings test runtime ~40% on
# code-placement luck and makes perf comparisons between commits meaningless.
TESTFLAGS="$WARNFLAGS $CONNFLAGS $JCCFLAGS -Isrc -Itests"
# test-san (CI only, too slow for the dev loop): the same unity test with
# ASan + UBSan, so a stack/global/heap out-of-bounds access or UB aborts the
# run at the faulting line (a stack canary would only catch a write that
# reaches the canary, at return). -fno-inline-functions: ASan gives
# every local its own redzoned slot, so with the test_* callees inlined
# test_srvrun's frame grew from 8.5MB to 2.3GB and overflowed the stack.
SANFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -fno-inline-functions"
SANTESTFLAGS="$TESTFLAGS $SANFLAGS"
# san-check (CI only): the freestanding build with UBSan + array-bounds checks in trap
# mode (no runtime, so it links without libc; a hit is SIGILL at the faulting
# instruction). ASan cannot be used here: its runtime needs libc.
SANCFLAGS="$CFLAGS -fsanitize=undefined,bounds -fsanitize-trap=all -fno-omit-frame-pointer"
# fuzz: hosted, ASan + libFuzzer.
FUZZFLAGS="$WARNFLAGS -g -fsanitize=fuzzer,address -Isrc"
# moqt_chat room profile (src/common/profile/moqt_room.h): the SDK's larger
# per-room limits, built into build/profile/moqt_room/ for the moqt_chat
# server and into build/quic_test_room so the suite runs at those values.
ROOMFLAG="-DWIRED_PROFILE_MOQT_ROOM"
# The room server's connection table (not the room test, whose fixtures
# are sized for CONNFLAGS): 3 rooms x 4 people plus 4 spare for joins being
# refused (4 would refuse a 5th connection before the room logic could say
# room-full). -U first: CONNFLAGS already defined it.
ROOMCONNFLAG="-UWIRED_CONNTABLE_CAP -DWIRED_CONNTABLE_CAP=16"
# clang-tidy: CERT C + bug finders, minus this repo's unavoidable noise --
# `_start` is a required entry point (reserved-identifier, dcl37) and every
# p256_fe is `const u64*` (easily-swappable-parameters). readability checks
# (6k+ hits) are left out on purpose, except cognitive complexity.
TIDYCHECKS="-*,cert-*,bugprone-*,clang-analyzer-*,-bugprone-easily-swappable-parameters,-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp,readability-function-cognitive-complexity"
# Cognitive complexity <= 4 for every function: the tree's maximum when the
# limit was set (`just cognitive` reports every score).
TIDYCONFIG="{CheckOptions: {readability-function-cognitive-complexity.Threshold: 4}}"
TIDYFLAGS="$TARGET -ffreestanding -nostdlib -fno-builtin -Isrc"
export CC ROOMFLAG ROOMCONNFLAG CFLAGS SANCFLAGS TESTFLAGS SANTESTFLAGS FUZZFLAGS TIDYCHECKS TIDYCONFIG TIDYFLAGS
