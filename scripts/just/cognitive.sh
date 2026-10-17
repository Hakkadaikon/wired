#!/bin/sh
# Report only: per-function cognitive complexity of the C under the given
# paths (pinned clang-tidy); 0 scores are not listed.
. scripts/just/lib.sh
nix_reexec "$0" "$@"
. scripts/just/flags.sh
# shellcheck disable=SC2016 # $@ and $TIDYFLAGS expand in the inner sh
find "$@" -name '*.c' -print0 | xargs -0r -P "$(nproc)" -n 8 sh -c '
    clang-tidy --quiet -checks="-*,readability-function-cognitive-complexity" \
    -config="{CheckOptions: {readability-function-cognitive-complexity.Threshold: 0, readability-function-cognitive-complexity.DescribeBasicIncrements: false}}" \
    "$@" -- $TIDYFLAGS 2>/dev/null' _ | grep -E 'cognitive complexity of|error:'
