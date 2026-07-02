# wired build. libc-free, x86_64-linux only.

cc := "clang"
cflags := "-target x86_64-linux-gnu -ffreestanding -fno-stack-protector -fno-builtin -nostdlib -static -Wall -Wextra -Werror -O2 -Isrc"
# -mbranches-within-32B-boundaries: this host's Xeon (Cascade Lake) has the
# JCC erratum; without it, test runtime swings ~40% on code-placement luck,
# making perf comparisons between commits meaningless.
testflags := "-Wall -Wextra -Werror -O2 -mbranches-within-32B-boundaries -Isrc -Itests"

# full build: format, compile freestanding, then static analysis.
# fmt normalizes sources, compile-all proves libc independence, lint runs the
# CERT C / bug-finding checks. Run as one pipeline so a normal `just build`
# keeps sources tidy and surfaces lint findings.
#build: fmt compile lint
build: fmt ninja lint

# compile every domain freestanding (proves libc independence) into one .o
# sources are auto-discovered; adding a src/**.c file needs no edit here
compile:
    mkdir -p build
    find src -name '*.c' | while read -r f; do \
        o="build/${f%.c}.o"; mkdir -p "$(dirname "$o")"; \
        {{cc}} {{cflags}} -c "$f" -o "$o" || exit 1; \
    done

# fast incremental/parallel build via ninja (generates build.ninja first)
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

# everything
check: ccn test
