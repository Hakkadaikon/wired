# wired build. libc-free, x86_64-linux only.
#
# Comments: the line right above a recipe is its `just --list` summary;
# details live inside the body (ignore-comments keeps them out of the echo).

set ignore-comments

# --- toolchain --------------------------------------------------------------

cc := "clang"
target := "-target x86_64-unknown-linux-gnu"
# Shared warning/optimization base of the three compile flag sets.
warnflags := "-Wall -Wextra -Werror -O2"
# Max simultaneous connections per server process. Each slot is a fixed array
# (~1.9MiB/conn of BSS); 4 matches moqt_chat's participant pool.
# Override: `CONNTABLE_CAP=256 just build`.
connflags := "-DWIRED_CONNTABLE_CAP=" + env("CONNTABLE_CAP", "4")
# freestanding: every src file must compile with no libc at all (the product
# constraint). Also the base of the example binaries (plus -DWIRED_DEBUG).
cflags := (target + " -ffreestanding -fno-stack-protector -fno-builtin -nostdlib -static "
    + warnflags + " " + connflags + " -Isrc")
# hosted test: -mbranches-within-32B-boundaries works around this host's
# Cascade Lake JCC erratum, which otherwise swings test runtime ~40% on
# code-placement luck and makes perf comparisons between commits meaningless.
testflags := warnflags + " " + connflags + " -mbranches-within-32B-boundaries -Isrc -Itests"
# fuzz: hosted, ASan + libFuzzer.
fuzzflags := warnflags + " -g -fsanitize=fuzzer,address -Isrc"
# clang-tidy: CERT C + bug finders, minus this repo's unavoidable noise —
# `_start` is a required entry point (reserved-identifier, dcl37) and every
# p256_fe is `const u64*` (easily-swappable-parameters). readability checks
# (6k+ hits) are left out on purpose.
tidychecks := ("-*,cert-*,bugprone-*,clang-analyzer-*"
    + ",-bugprone-easily-swappable-parameters,-bugprone-reserved-identifier"
    + ",-cert-dcl37-c,-cert-dcl51-cpp")
tidyflags := target + " -ffreestanding -nostdlib -fno-builtin -Isrc"
# The C sources clang-format owns.
csrcs := '''$(find src tests examples fuzz guide/snippets -name node_modules -prune -o \( -name '*.c' -o -name '*.h' \) -print)'''
# True outside the devShell when nix exists. Recipes that need CI's pinned
# tools then re-exec themselves as `nix develop -c just <recipe>`.
no_nix_shell := '[ -z "${IN_NIX_SHELL:-}" ] && command -v nix >/dev/null 2>&1'

# --- environment ------------------------------------------------------------

# One-time bootstrap: install nix when absent.
setup:
    # Afterwards `nix develop` provides clang/just/lizard/doxygen (flake.nix).
    @command -v nix >/dev/null 2>&1 \
        && echo "nix already installed: $(nix --version)" \
        || curl -fsSL https://install.determinate.systems/nix | sh -s -- install

# Run any recipe inside the flake devShell, e.g. `just nix test`.
nix +args:
    nix develop -c just {{args}}

# --- build ------------------------------------------------------------------

# Full build: fmt + freestanding compile (ninja) + lint.
build:
    #!/usr/bin/env sh
    # In the devShell so all three legs use the pinned toolchain.
    {{no_nix_shell}} && exec nix develop -c just build
    just fmt && just ninja && just lint

# Regenerate build.ninja from the current source list.
gen-ninja:
    # Every variant (freestanding, tests, fuzz, examples, guide) lives in one
    # build.ninja; see scripts/gen_ninja.sh.
    CFLAGS="{{cflags}}" TESTFLAGS="{{testflags}}" FUZZFLAGS="{{fuzzflags}}" \
        CC="{{cc}}" sh scripts/gen_ninja.sh

# Compile freestanding (all of src/, or the named ninja targets).
ninja *targets: gen-ninja
    # No targets = every src/**/*.c into build/<path>.o (the libc-independence
    # proof). Targets: examples/<name>/wired_server, guide, build/src/<path>.o.
    ninja {{targets}}

# Archive the SDK objects into build/libwired.a.
lib: gen-ninja
    # sys.o is left out: applications supply their own _start.
    ninja build/libwired.a

# Emit compile_commands.json for clangd/IDEs.
compdb: gen-ninja
    ninja -t compdb > compile_commands.json

# --- test -------------------------------------------------------------------

# Run all tests (hosted, assertions on).
test: fmt gen-ninja
    #!/usr/bin/env sh
    # The single-TU unity build CI gates on. Stack raised: test_srvrun's frame
    # outgrew the 8MB default.
    set -eu
    ulimit -s unlimited 2>/dev/null || ulimit -s 65536
    ninja build/quic_test && build/quic_test

# Same tests as `test`, ~4x faster (parallel shard TUs).
test-fast: fmt gen-ninja
    #!/usr/bin/env sh
    # Shards cannot see static/typedef/macro collisions across shards, so
    # `test` stays the authoritative gate.
    set -eu
    ulimit -s unlimited 2>/dev/null || ulimit -s 65536
    python3 scripts/gen_shards.py
    ninja build/quic_test_fast && build/quic_test_fast

# ccn + test.
check: ccn test

# CCN <= 3 for every function (lizard).
ccn *paths="src":
    # Default is all of src/ (the gate); pass files to measure only those.
    lizard {{paths}} --CCN 3 -w

# Check every src/**/*.c is in tests/run.c once and builds one object.
wire-check: ninja
    #!/usr/bin/env sh
    # A mismatch means a source is committed but never built or tested.
    set -eu
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    find src -name '*.c' | sed 's|^src/||' | sort > "$tmp/src"
    grep '^#include ".*\.c"' tests/run.c | grep -v '_test\.c"' \
        | sed 's/^#include "//; s/"$//' | sort > "$tmp/inc"
    nsrc=$(wc -l < "$tmp/src"); nobj=$(find build/src -name '*.o' | wc -l)
    echo "src .c: $nsrc / freestanding .o: $nobj"
    [ "$nsrc" -eq "$nobj" ] || { echo "WIRING MISMATCH: a source compiles to no object" >&2; exit 1; }
    # unity build: every src .c included once, except sys.c (its only symbol
    # is the SDK's own _start; the hosted binary uses libc's startup).
    miss=$(comm -23 "$tmp/src" "$tmp/inc")
    [ "$miss" = "common/platform/sys/sys.c" ] || { echo "WIRING MISMATCH: not in run.c:"; echo "$miss"; exit 1; } >&2
    gone=$(comm -13 "$tmp/src" "$tmp/inc")
    [ -z "$gone" ] || { echo "WIRING MISMATCH: run.c includes deleted sources:"; echo "$gone"; exit 1; } >&2
    echo "wiring OK ($nsrc sources, sys.c excluded from the unity TU by design)"

# Line coverage of the unity test (LLVM source-based).
cov: fmt
    #!/usr/bin/env sh
    # Its own instrumented binary, so instrumentation never leaks into `test`.
    set -eu
    mkdir -p build
    {{cc}} {{testflags}} -fprofile-instr-generate -fcoverage-mapping \
        tests/run.c -o build/quic_test_cov
    LLVM_PROFILE_FILE=build/quic_test.profraw ./build/quic_test_cov
    llvm-profdata merge -sparse build/quic_test.profraw -o build/quic_test.profdata
    llvm-cov export build/quic_test_cov -instr-profile=build/quic_test.profdata \
        -ignore-filename-regex='tests/' -format=lcov > build/lcov.info
    llvm-cov report build/quic_test_cov -instr-profile=build/quic_test.profdata \
        -ignore-filename-regex='tests/'

# Run the unity test binary under valgrind --track-origins.
valgrind: gen-ninja
    # Names the uninitialized read behind a "sometimes passes" hang. Slow.
    # --max-stackframe covers test_srvrun's ~8.5MB frame.
    ninja build/quic_test
    valgrind --error-exitcode=99 --track-origins=yes --max-stackframe=9000000 \
        --suppressions=tests/valgrind.supp ./build/quic_test

# Verify tests/app/moqt_golden.h has no drift.
golden-check:
    #!/usr/bin/env sh
    # Regenerated from examples/moqt_chat/testvectors/moqt_golden.json.
    {{no_nix_shell}} && exec nix develop -c just golden-check
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    python3 scripts/gen_moqt_golden.py "$tmp/moqt_golden.h"
    clang-format -style=file:.clang-format -i "$tmp/moqt_golden.h"
    diff -u tests/app/moqt_golden.h "$tmp/moqt_golden.h"

# --- fuzz -------------------------------------------------------------------

# Per-PR gate: every fuzz harness builds and survives one run.
fuzz-smoke: gen-ninja
    #!/usr/bin/env sh
    set -eu
    for f in fuzz/fuzz_*.c; do t=${f%.c}; ninja "$t"
        "./$t" -runs=1 -artifact_prefix=fuzz/
    done

# Nightly sweep: every fuzz harness for secs seconds each.
fuzz-ci secs="120": gen-ninja
    #!/usr/bin/env sh
    # Each run seeds from and grows fuzz/corpus/<harness>/ (the Fuzz workflow
    # commits it).
    set -eu
    for f in fuzz/fuzz_*.c; do t=${f%.c}; ninja "$t"
        "./$t" -max_total_time={{secs}} -artifact_prefix=fuzz/ "fuzz/corpus/${t#fuzz/}"
    done

# --- format & lint (pinned toolchain) ---------------------------------------

# Format the C sources in place with the pinned clang-format.
fmt:
    #!/usr/bin/env sh
    {{no_nix_shell}} && exec nix develop -c just fmt
    if [ -z "${IN_NIX_SHELL:-}" ]; then
        echo "warning: no nix; formatting with the host clang-format (may disagree with CI's pin)" >&2
    fi
    clang-format -i {{csrcs}}

# Verify C formatting without writing (fails on diff).
fmt-check:
    #!/usr/bin/env sh
    {{no_nix_shell}} && exec nix develop -c just fmt-check
    clang-format --dry-run --Werror {{csrcs}}

# Static analysis (CERT C + bug finders); any warning fails.
lint:
    #!/usr/bin/env sh
    # Pinned clang-tidy, since findings differ across versions.
    {{no_nix_shell}} && exec nix develop -c just lint
    clang-tidy -checks='{{tidychecks}}' --warnings-as-errors='*' --quiet $(find src -name '*.c') -- {{tidyflags}}

# --- docs -------------------------------------------------------------------

# Regenerate the public-API reference into docs/sdk (doxygen).
docs:
    #!/usr/bin/env sh
    # INPUT = wired.h's transitive includes; the rest is docs/Doxyfile.
    set -eu
    rm -rf docs/sdk
    inputs="$(cd src && clang -I. -E -H wired.h 2>&1 >/dev/null \
        | grep -o '\./.*\.h' | sed 's|^\./|src/|' | sort -u | tr '\n' ' ')"
    [ -n "$inputs" ] || { echo "docs: deriving INPUT from wired.h failed" >&2; exit 1; }
    ( cat docs/Doxyfile; printf 'INPUT = src/wired.h %s\n' "$inputs" ) | doxygen -

# Build and run the guide snippets, compare with their golden.txt.
guide-verify *ids: (ninja "guide")
    # No ids = all. Needs go + node 22 on PATH.
    cd guide && node runner/run.ts {{ids}}
