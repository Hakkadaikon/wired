#!/bin/sh
# The single-TU unity build CI gates on (ninja target build/quic_test), or
# with --fast the parallel shard TUs: the same tests ~3x faster, but shards
# cannot see static/typedef/macro collisions across shards, so the single
# TU stays the authoritative gate. --san: the single TU under ASan + UBSan
# (CI only).
set -eu
. scripts/just/lib.sh
raise_stack
# detect_stack_use_after_return=1: a view of a returned frame's local is
# caught too. The ASan build runs SDK threads as pthreads (thread.h,
# WIRED_THREAD_PTHREAD), so each has its own TLS and fake stack.
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_stack_use_after_return=1}"
if [ "${1:-}" = "--san" ]; then
    ninja build/quic_test_san && build/quic_test_san
elif [ "${1:-}" = "--fast" ]; then
    python3 scripts/gen_shards.py
    ninja build/quic_test_fast && build/quic_test_fast
else
    ninja build/quic_test && build/quic_test
fi
