# wired build. libc-free, x86_64-linux only.

cc := "clang"
# Shared warning/optimization base; the three flag sets below extend it.
warnflags := "-Wall -Wextra -Werror -O2"
# Max simultaneous connections per server process (WIRED_CONNTABLE_CAP).
# Each slot is a fixed array (~1.9MiB/conn of BSS); 4 matches moqt_chat's
# participant pool. Override: `CONNTABLE_CAP=256 just build`.
conntable_cap := env_var_or_default("CONNTABLE_CAP", "4")
connflags := "-DWIRED_CONNTABLE_CAP=" + conntable_cap
# freestanding: the product constraint -- every src file must compile with no
# libc at all. Also used (plus -DWIRED_DEBUG) for the example binaries.
cflags := "-target x86_64-unknown-linux-gnu -ffreestanding -fno-stack-protector -fno-builtin -nostdlib -static " + warnflags + " " + connflags + " -Isrc"
# hosted test: -mbranches-within-32B-boundaries because this host's Xeon
# (Cascade Lake) has the JCC erratum; without it, test runtime swings ~40% on
# code-placement luck, making perf comparisons between commits meaningless.
testflags := warnflags + " " + connflags + " -mbranches-within-32B-boundaries -Isrc -Itests"
# fuzz: hosted with ASan+libFuzzer instrumentation.
fuzzflags := warnflags + " -g -fsanitize=fuzzer,address -Isrc"

# Re-exec the named recipe inside the pinned flake devShell when nix exists
# and we are not already in it (tool versions must match CI's pin).
in_nix := 'if [ -z "${IN_NIX_SHELL:-}" ] && command -v nix >/dev/null 2>&1; then exec nix develop -c just'
# The C sources clang-format owns.
csrcs := "$(find src tests examples fuzz guide/snippets -name node_modules -prune -o \\( -name '*.c' -o -name '*.h' \\) -print)"

# After it, `nix develop` provides clang/just/lizard/doxygen (flake.nix).
# One-time bootstrap: install nix when absent.
setup:
    @command -v nix >/dev/null 2>&1 \
        && echo "nix already installed: $(nix --version)" \
        || curl -fsSL https://install.determinate.systems/nix | sh -s -- install

# The pinned toolchain CI checks against, e.g. `just nix test`.
# Run any recipe inside the flake devShell.
nix +args:
    nix develop -c just {{args}}

# Runs in the devShell so all three legs use the pinned toolchain.
# Full build: fmt + freestanding compile (ninja) + lint.
build:
    #!/usr/bin/env sh
    {{in_nix}} build; fi
    just fmt && just ninja && just lint

# sys.o is left out: applications supply their own _start.
# Archive the SDK objects into build/libwired.a.
lib: gen-ninja
    ninja build/libwired.a

# Every build variant (freestanding objects, hosted tests, fuzz, examples,
# guide) lives in one file; see scripts/gen_ninja.sh.
# Regenerate build.ninja from the current source list.
gen-ninja:
    CFLAGS="{{cflags}}" TESTFLAGS="{{testflags}}" FUZZFLAGS="{{fuzzflags}}" \
        CC="{{cc}}" sh scripts/gen_ninja.sh

# No targets = every src/**/*.c freestanding into build/<path>.o (the libc
# independence proof). Or name targets: examples/<name>/wired_server, guide,
# build/src/<path>.o.
# Compile freestanding (all of src/, or the named ninja targets).
ninja *targets: gen-ninja
    ninja {{targets}}

# The single-TU unity build CI gates on. The stack limit is raised because
# test_srvrun's frame outgrew the 8MB default.
# Run all tests (hosted, assertions on).
test: fmt gen-ninja
    #!/usr/bin/env sh
    set -eu
    ulimit -s unlimited 2>/dev/null || ulimit -s 65536
    ninja build/quic_test && build/quic_test

# Shards cannot see static/typedef/macro collisions across shards, so
# `test` stays the authoritative gate.
# Same tests as `test`, ~4x faster (parallel shard TUs).
test-fast: fmt gen-ninja
    #!/usr/bin/env sh
    set -eu
    ulimit -s unlimited 2>/dev/null || ulimit -s 65536
    python3 scripts/gen_shards.py
    ninja build/quic_test_fast && build/quic_test_fast

# Its own instrumented binary, so instrumentation never leaks into `test`.
# Line coverage of the unity test (LLVM source-based).
cov: fmt
    #!/usr/bin/env sh
    set -eu
    mkdir -p build
    clang {{testflags}} -fprofile-instr-generate -fcoverage-mapping \
        tests/run.c -o build/quic_test_cov
    LLVM_PROFILE_FILE=build/quic_test.profraw ./build/quic_test_cov
    llvm-profdata merge -sparse build/quic_test.profraw -o build/quic_test.profdata
    llvm-cov export build/quic_test_cov -instr-profile=build/quic_test.profdata \
        -ignore-filename-regex='tests/' -format=lcov > build/lcov.info
    llvm-cov report build/quic_test_cov -instr-profile=build/quic_test.profdata \
        -ignore-filename-regex='tests/'

# Default is all of src/ (the gate); pass files to measure only those.
# CCN <= 3 for every function (lizard).
ccn *paths="src":
    lizard {{paths}} --CCN 3 -w

# A mismatch means a source is committed but never built or tested.
# Check every src/**/*.c is in tests/run.c once and builds one object.
wire-check: ninja
    #!/usr/bin/env sh
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

# Names the uninitialized read behind a "sometimes passes" hang. Slow.
# --max-stackframe covers test_srvrun's ~8.5MB frame.
# Run the unity test binary under valgrind --track-origins.
valgrind: gen-ninja
    ninja build/quic_test
    valgrind --error-exitcode=99 --track-origins=yes --max-stackframe=9000000 \
        --suppressions=tests/valgrind.supp ./build/quic_test

# Emit compile_commands.json for clangd/IDEs.
compdb: gen-ninja
    ninja -t compdb > compile_commands.json

# Each run seeds from and grows fuzz/corpus/<harness>/ (the Fuzz workflow
# commits it).
# Nightly sweep: every fuzz harness for secs seconds each.
fuzz-ci secs="120": gen-ninja
    #!/usr/bin/env sh
    set -eu
    for f in fuzz/fuzz_*.c; do t=${f%.c}; ninja "$t"
        "./$t" -max_total_time={{secs}} -artifact_prefix=fuzz/ "fuzz/corpus/${t#fuzz/}"
    done

# Per-PR gate: every fuzz harness builds and survives one run.
fuzz-smoke: gen-ninja
    #!/usr/bin/env sh
    set -eu
    for f in fuzz/fuzz_*.c; do t=${f%.c}; ninja "$t"
        "./$t" -runs=1 -artifact_prefix=fuzz/
    done

# Format the C sources in place with the pinned clang-format.
fmt:
    #!/usr/bin/env sh
    {{in_nix}} fmt; fi
    if [ -z "${IN_NIX_SHELL:-}" ]; then
        echo "warning: no nix; formatting with the host clang-format (may disagree with CI's pin)" >&2
    fi
    clang-format -i {{csrcs}}

# Verify C formatting without writing (fails on diff).
fmt-check:
    #!/usr/bin/env sh
    {{in_nix}} fmt-check; fi
    clang-format --dry-run --Werror {{csrcs}}

# Regenerated from examples/moqt_chat/testvectors/moqt_golden.json.
# Verify tests/app/moqt_golden.h has no drift.
golden-check:
    #!/usr/bin/env sh
    {{in_nix}} golden-check; fi
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    python3 scripts/gen_moqt_golden.py "$tmp/moqt_golden.h"
    clang-format -style=file:.clang-format -i "$tmp/moqt_golden.h"
    diff -u tests/app/moqt_golden.h "$tmp/moqt_golden.h"

# clang-tidy check set: CERT C secure-coding rules + bug finders, minus the
# unavoidable-in-this-repo noise. `_start` is a required freestanding entry point
# (reserved-identifier / dcl37 excluded); every p256_fe is `const u64*` so
# easily-swappable-parameters fires everywhere (excluded). readability style
# checks (6k+ hits) are intentionally left out — signal over noise.
tidychecks := "-*,cert-*,bugprone-*,clang-analyzer-*,-bugprone-easily-swappable-parameters,-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp"
tidyflags := "-target x86_64-unknown-linux-gnu -ffreestanding -nostdlib -fno-builtin -Isrc"

# Pinned clang-tidy, since findings differ across versions.
# Static analysis (CERT C + bug finders); any warning fails.
lint:
    #!/usr/bin/env sh
    {{in_nix}} lint; fi
    clang-tidy -checks='{{tidychecks}}' --warnings-as-errors='*' --quiet $(find src -name '*.c') -- {{tidyflags}}

# No ids = all. Needs go + node 22 on PATH.
# Build and run the guide snippets, compare with their golden.txt.
guide-verify *ids: (ninja "guide")
    cd guide && node runner/run.ts {{ids}}

# Inputs are wired.h's transitive includes; config in docs/Doxyfile.
# Regenerate the public-API reference into docs/sdk (doxygen).
docs:
    rm -rf docs/sdk
    inputs="$(cd src && clang -I. -E -H wired.h 2>&1 >/dev/null \
        | grep -o '\./.*\.h' | sed 's|^\./|src/|' | sort -u | tr '\n' ' ')"; \
    [ -n "$inputs" ] || { echo "docs: deriving INPUT from wired.h failed" >&2; exit 1; }; \
    ( cat docs/Doxyfile; printf 'INPUT = src/wired.h %s\n' "$inputs" ) | doxygen -

# ccn + test.
check: ccn test
