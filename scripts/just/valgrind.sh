#!/bin/sh
# The unity test binary under valgrind --track-origins: names the
# uninitialized read behind a "sometimes passes" hang. Slow.
# test_srvrun's frame is tens of MB (25.6MB when measured): valgrind gives
# the client its own main stack, 16MB at most unless --main-stacksize asks
# for more, whatever `ulimit -s` says. 1GiB like raise_stack (lib.sh).
set -eu
ninja build/quic_test
valgrind --error-exitcode=99 --track-origins=yes \
    --max-stackframe=1073741824 --main-stacksize=1073741824 \
    --suppressions=tests/valgrind.supp ./build/quic_test
