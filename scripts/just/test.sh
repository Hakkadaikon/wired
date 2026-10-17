#!/bin/sh
# The single-TU unity build CI gates on (ninja target build/quic_test), or
# with --fast the parallel shard TUs: the same tests ~3x faster, but shards
# cannot see static/typedef/macro collisions across shards, so the single
# TU stays the authoritative gate.
set -eu
. scripts/just/lib.sh
raise_stack
if [ "${1:-}" = "--fast" ]; then
    python3 scripts/gen_shards.py
    ninja build/quic_test_fast && build/quic_test_fast
else
    ninja build/quic_test && build/quic_test
fi
