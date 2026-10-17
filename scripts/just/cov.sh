#!/bin/sh
# Line coverage of the unity test (LLVM source-based), from its own
# instrumented binary so instrumentation never leaks into `test`.
set -eu
. scripts/just/lib.sh
. scripts/just/flags.sh
raise_stack
# build/unity/run.c: tests/run.c with a .text section per .c (gen_ninja.sh).
ninja build/unity/run.c
# shellcheck disable=SC2086 # TESTFLAGS is a word list
"$CC" $TESTFLAGS -fprofile-instr-generate -fcoverage-mapping \
    build/unity/run.c -o build/quic_test_cov
LLVM_PROFILE_FILE=build/quic_test.profraw ./build/quic_test_cov
llvm-profdata merge -sparse build/quic_test.profraw -o build/quic_test.profdata
llvm-cov export build/quic_test_cov -instr-profile=build/quic_test.profdata \
    -ignore-filename-regex='tests/|build/' -format=lcov > build/lcov.info
llvm-cov report build/quic_test_cov -instr-profile=build/quic_test.profdata \
    -ignore-filename-regex='tests/|build/'
