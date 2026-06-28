# quic_vibe build. libc-free, x86_64-linux only.

cc := "clang"
cflags := "-target x86_64-linux-gnu -ffreestanding -fno-stack-protector -fno-builtin -nostdlib -static -Wall -Wextra -Werror -O2 -Isrc"
testflags := "-Wall -Wextra -Werror -O2 -Isrc -Itests"

# compile every domain freestanding (proves libc independence) into one .o
# sources are auto-discovered; adding a src/**.c file needs no edit here
build:
    mkdir -p build
    find src -name '*.c' | while read -r f; do \
        o="build/${f%.c}.o"; mkdir -p "$(dirname "$o")"; \
        {{cc}} {{cflags}} -c "$f" -o "$o" || exit 1; \
    done

# fast incremental/parallel build via ninja (generates build.ninja first)
ninja:
    sh scripts/gen_ninja.sh
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

# static analysis (clang-tidy, freestanding flags after --)
lint:
    clang-tidy -checks='-*,bugprone-*,clang-analyzer-*,readability-*' $(find src -name '*.c') -- -target x86_64-linux-gnu -ffreestanding -nostdlib -Isrc

# everything
check: ccn test
