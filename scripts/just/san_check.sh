#!/bin/sh
# The production (freestanding) build with UBSan + array-bounds checks in
# trap mode, exercised for real: build/san/ holds the SDK, examples and guide
# snippets compiled with $SANCFLAGS (flags.sh), and the guide runner drives
# the snippets over loopback. A check that fires kills the server with
# SIGILL, which shows up as a failed snippet. Needs go + node 22.
set -eu
ninja san
cd guide && GUIDE_BIN="$(pwd)/../build/san/guide" node runner/run.ts "$@"
