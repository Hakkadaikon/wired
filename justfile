# wired build. libc-free, x86_64-linux only.

cc := "clang"
cflags := "-target x86_64-linux-gnu -ffreestanding -fno-stack-protector -fno-builtin -nostdlib -static -Wall -Wextra -Werror -O2 -Isrc"
# -mbranches-within-32B-boundaries: this host's Xeon (Cascade Lake) has the
# JCC erratum; without it, test runtime swings ~40% on code-placement luck,
# making perf comparisons between commits meaningless.
testflags := "-Wall -Wextra -Werror -O2 -mbranches-within-32B-boundaries -Isrc -Itests"

# one-time bootstrap: install nix (Determinate Systems installer) when absent.
# After it, `nix develop` provides clang/just/lizard/doxygen from flake.nix.
# On a machine without just itself, run the curl line directly.
setup:
    @command -v nix >/dev/null 2>&1 \
        && echo "nix already installed: $(nix --version)" \
        || curl -fsSL https://install.determinate.systems/nix | sh -s -- install

# full build: format, compile freestanding (ninja), then static analysis.
# fmt normalizes sources, ninja proves libc independence per file, lint runs
# the CERT C / bug-finding checks. Run as one pipeline so a normal
# `just build` keeps sources tidy and surfaces lint findings.
build: fmt ninja lint

# archive the compiled SDK objects into build/libwired.a. Excludes sys.o,
# whose only symbol is the SDK's own _start stub — applications supply their
# own entry point and link the rest of the SDK from this library.
lib: ninja
    ar rcs build/libwired.a $(find build -name '*.o' ! -path 'build/src/common/platform/sys/sys.o')

# compile every src/**/*.c freestanding to build/<path>.o (proves libc
# independence; path-qualified objects keep the count check honest despite
# shared basenames). build.ninja is regenerated from the current source list,
# then ninja does parallel, header-dep incremental compilation.
ninja:
    CFLAGS="{{cflags}}" CC="{{cc}}" sh scripts/gen_ninja.sh
    ninja

# run all tests (hosted, with assertions)
test:
    mkdir -p build
    {{cc}} {{testflags}} tests/run.c -o build/quic_test && build/quic_test

# cyclomatic complexity gate: CCN must be <= 3
ccn:
    lizard src --CCN 3 -w

# format all sources in place (clang-format, .clang-format config)
fmt:
    clang-format -i $(find src tests \( -name '*.c' -o -name '*.h' \))

# verify formatting without writing (fails on diff)
fmt-check:
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
