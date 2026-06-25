# quic_vibe build. libc-free, x86_64-linux only.

cc := "clang"
cflags := "-target x86_64-linux-gnu -ffreestanding -fno-stack-protector -fno-builtin -nostdlib -static -Wall -Wextra -Werror -O2 -Isrc"
testflags := "-Wall -Wextra -Werror -O2 -Isrc -Itests"

# compile every domain freestanding (proves libc independence) into one .o
build:
    mkdir -p build
    {{cc}} {{cflags}} -c src/sys/sys.c src/varint/varint.c src/packet/header.c src/packet/pnum.c src/tparam/tparam.c src/frame/frame.c
    mv *.o build/

# run all tests (hosted, with assertions)
test:
    mkdir -p build
    {{cc}} {{testflags}} tests/run.c -o build/quic_test && build/quic_test

# cyclomatic complexity gate: CCN must be <= 3
ccn:
    lizard src --CCN 3 -w

# everything
check: ccn test
