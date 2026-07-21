# wired build. libc-free, x86_64-linux only.

cc := "clang"
# Shared warning/optimization base; the three flag sets below extend it.
warnflags := "-Wall -Wextra -Werror -O2"
# freestanding: the product constraint -- every src file must compile with no
# libc at all. Also used (plus -DQUIC_DEBUG) for the example binaries.
cflags := "-target x86_64-linux-gnu -ffreestanding -fno-stack-protector -fno-builtin -nostdlib -static " + warnflags + " -Isrc"
# hosted test: -mbranches-within-32B-boundaries because this host's Xeon
# (Cascade Lake) has the JCC erratum; without it, test runtime swings ~40% on
# code-placement luck, making perf comparisons between commits meaningless.
testflags := warnflags + " -mbranches-within-32B-boundaries -Isrc -Itests"
# fuzz: hosted with ASan+libFuzzer instrumentation.
fuzzflags := warnflags + " -g -fsanitize=fuzzer,address -Isrc"

# one-time bootstrap: install nix (Determinate Systems installer) when absent.
# After it, `nix develop` provides clang/just/lizard/doxygen from flake.nix.
# On a machine without just itself, run the curl line directly.
setup:
    @command -v nix >/dev/null 2>&1 \
        && echo "nix already installed: $(nix --version)" \
        || curl -fsSL https://install.determinate.systems/nix | sh -s -- install

# run any recipe inside the flake devShell — the pinned toolchain (latest
# LLVM clang/clang-format/clang-tidy, the exact versions CI checks against).
# e.g. `just nix fmt`, `just nix test`, `just nix build`. Host-installed
# tools may be older and format/lint differently; when in doubt, go through
# this instead of calling the recipe bare.
nix +args:
    nix develop -c just {{args}}

# full build: format, compile freestanding (ninja), then static analysis.
# fmt normalizes sources, ninja proves libc independence per file, lint runs
# the CERT C / bug-finding checks. Run as one pipeline so a normal
# `just build` keeps sources tidy and surfaces lint findings.
# Reroutes once into the flake devShell (like fmt/lint) so all three legs —
# including ninja's clang — run the pinned toolchain in a single entry.
build:
    #!/usr/bin/env sh
    if [ -z "$IN_NIX_SHELL" ] && command -v nix >/dev/null 2>&1; then
        exec nix develop -c just build
    fi
    just fmt ninja lint

# archive the compiled SDK objects into build/libwired.a (a ninja target;
# sys.o is excluded there — its only symbol is the SDK's own _start stub,
# and applications supply their own entry point).
lib: gen-ninja
    ninja build/libwired.a

# regenerate build.ninja from the current source list. Covers every build
# variant this repo has (freestanding per-object, hosted unity test, the 3
# fuzz harnesses) in one file, each behind its own rule since different
# flags mean incompatible .o ABIs -- see scripts/gen_ninja.sh.
gen-ninja:
    CFLAGS="{{cflags}}" TESTFLAGS="{{testflags}}" FUZZFLAGS="{{fuzzflags}}" \
        CC="{{cc}}" sh scripts/gen_ninja.sh

# compile every src/**/*.c freestanding to build/<path>.o (proves libc
# independence; path-qualified objects keep the count check honest despite
# shared basenames). Regenerates build.ninja first so new/removed sources are
# picked up; ninja's default target is the freestanding set (see
# scripts/gen_ninja.sh), so a bare `ninja` here never drags in the hosted
# test/fuzz variants.
ninja: gen-ninja
    ninja

# run all tests (hosted, with assertions). fmt first so the unity build is
# always compiled from formatted sources — run inside `nix develop` so the
# pinned clang-format (the one CI checks against) is the one that formats.
test: fmt gen-ninja
    ninja build/quic_test && build/quic_test

# cyclomatic complexity gate: CCN must be <= 3
ccn:
    lizard src --CCN 3 -w

# wiring integrity: every src/**/*.c must be #include'd once in tests/run.c
# (the unity TU) and compile to exactly one path-qualified build/<path>.o.
# A mismatch means a source is committed but never built or tested -- the
# failure mode that once shipped 48 unwired files as a stale green. Run
# after any wiring change; part of the pre-commit gate.
wire-check: ninja
    #!/usr/bin/env sh
    set -eu
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    find src -name '*.c' | sed 's|^src/||' | sort > "$tmp/src"
    grep '^#include ".*\.c"' tests/run.c | grep -v '_test\.c"' \
        | sed 's/^#include "//; s/"$//' | sort > "$tmp/inc"
    nsrc=$(wc -l < "$tmp/src"); nobj=$(find build -name '*.o' | wc -l)
    echo "src .c: $nsrc / freestanding .o: $nobj"
    [ "$nsrc" -eq "$nobj" ] || { echo "WIRING MISMATCH: a source compiles to no object" >&2; exit 1; }
    # unity build: every src .c included once, except sys.c (its only symbol
    # is the SDK's own _start; the hosted binary uses libc's startup).
    miss=$(comm -23 "$tmp/src" "$tmp/inc")
    [ "$miss" = "common/platform/sys/sys.c" ] || { echo "WIRING MISMATCH: not in run.c:"; echo "$miss"; exit 1; } >&2
    gone=$(comm -13 "$tmp/src" "$tmp/inc")
    [ -z "$gone" ] || { echo "WIRING MISMATCH: run.c includes deleted sources:"; echo "$gone"; exit 1; } >&2
    echo "wiring OK ($nsrc sources, sys.c excluded from the unity TU by design)"

# run the unity test binary under valgrind. Freestanding code has no
# implicit zeroing, and every nondeterministic hang so far was an
# uninitialized read (e.g. the ec_mul accumulator); valgrind
# --track-origins names the culprit in one run. Slow -- run after wiring a
# new domain or on any "sometimes passes" symptom, not on every commit.
valgrind: gen-ninja
    ninja build/quic_test
    valgrind --error-exitcode=99 --track-origins=yes ./build/quic_test

# emit compile_commands.json for clangd/IDEs from the ninja graph
compdb: gen-ninja
    ninja -t compdb > compile_commands.json

# build the libFuzzer harness for the invariant packet-header parser and
# the coalesced-datagram splitter (hosted, ASan+libFuzzer; src/ untouched).
fuzz-header: gen-ninja
    ninja fuzz/fuzz_header

# build the libFuzzer harness for the QPACK dynamic-table Indexed Field Line
# decoder (hosted, ASan+libFuzzer; src/ untouched).
fuzz-qpack: gen-ninja
    ninja fuzz/fuzz_qpack

# build the libFuzzer harness for the X.509 certificate parser and the
# TBSCertificate field extractor (hosted, ASan+libFuzzer; src/ untouched).
fuzz-x509: gen-ninja
    ninja fuzz/fuzz_x509

# run every fuzz harness for secs wall-clock seconds each (default 120), for
# CI: a bounded regression sweep, not an open-ended fuzzing campaign. Exits
# non-zero on any crash/leak (libFuzzer's own exit code).
fuzz-ci secs="120":
    just fuzz-header && ./fuzz/fuzz_header -max_total_time={{secs}} -artifact_prefix=fuzz/
    just fuzz-qpack && ./fuzz/fuzz_qpack -max_total_time={{secs}} -artifact_prefix=fuzz/
    just fuzz-x509 && ./fuzz/fuzz_x509 -max_total_time={{secs}} -artifact_prefix=fuzz/

# format all sources in place (clang-format, .clang-format config).
# Reroutes itself through the flake devShell when run outside one: a host
# clang-format of another version reflows differently and CI's fmt-check
# rejects the result (2026-07-05: a host-18.x `just fmt` undid the pinned
# layout across 8 files). Without nix it runs the host binary as a last
# resort and says so.
fmt:
    #!/usr/bin/env sh
    if [ -z "$IN_NIX_SHELL" ] && command -v nix >/dev/null 2>&1; then
        exec nix develop -c just fmt
    fi
    if [ -z "$IN_NIX_SHELL" ]; then
        echo "warning: no nix; formatting with the host clang-format (may disagree with CI's pin)" >&2
    fi
    clang-format -i $(find src tests \( -name '*.c' -o -name '*.h' \))

# verify formatting without writing (fails on diff); same devShell reroute
# as fmt so the verdict matches CI's pinned clang-format.
fmt-check:
    #!/usr/bin/env sh
    if [ -z "$IN_NIX_SHELL" ] && command -v nix >/dev/null 2>&1; then
        exec nix develop -c just fmt-check
    fi
    clang-format --dry-run --Werror $(find src tests \( -name '*.c' -o -name '*.h' \))

# clang-tidy check set: CERT C secure-coding rules + bug finders, minus the
# unavoidable-in-this-repo noise. `_start` is a required freestanding entry point
# (reserved-identifier / dcl37 excluded); every p256_fe is `const u64*` so
# easily-swappable-parameters fires everywhere (excluded). readability style
# checks (6k+ hits) are intentionally left out — signal over noise.
tidychecks := "-*,cert-*,bugprone-*,clang-analyzer-*,-bugprone-easily-swappable-parameters,-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp"
tidyflags := "-target x86_64-linux-gnu -ffreestanding -nostdlib -fno-builtin -Isrc"

# CERT C secure-coding checks only (JPCERT/SEI CERT C via clang-tidy cert-*).
cert:
    clang-tidy -checks='-*,cert-*,-cert-dcl37-c,-cert-dcl51-cpp' $(find src -name '*.c') -- {{tidyflags}}

# static analysis: CERT C rules (see `cert`) plus bug finders. Includes cert.
lint:
    #!/usr/bin/env sh
    # same devShell reroute as fmt: clang-tidy findings differ across versions
    if [ -z "$IN_NIX_SHELL" ] && command -v nix >/dev/null 2>&1; then
        exec nix develop -c just lint
    fi
    clang-tidy -checks='{{tidychecks}}' $(find src -name '*.c') -- {{tidyflags}}

# regenerate the public-API reference into docs/sdk. The input set is derived
# from wired.h's transitive includes at run time, so it never drifts from the
# real public API surface. Config lives in docs/Doxyfile.
docs:
    rm -rf docs/sdk
    inputs="$(cd src && clang -I. -E -H wired.h 2>&1 >/dev/null \
        | grep -o '\./.*\.h' | sed 's|^\./|src/|' | sort -u | tr '\n' ' ')"; \
    [ -n "$inputs" ] || { echo "docs: deriving INPUT from wired.h failed" >&2; exit 1; }; \
    ( cat docs/Doxyfile; printf 'INPUT = src/wired.h %s\n' "$inputs" ) | doxygen -

# everything
check: ccn test
