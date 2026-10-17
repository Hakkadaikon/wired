#!/bin/sh
# The unity test binary under valgrind --track-origins: names the
# uninitialized read behind a "sometimes passes" hang. Slow.
# --max-stackframe covers test_srvrun's ~8.5MB frame.
set -eu
ninja build/quic_test
valgrind --error-exitcode=99 --track-origins=yes --max-stackframe=9000000 \
    --suppressions=tests/valgrind.supp ./build/quic_test
