#!/bin/sh
# Format the C sources in place with the pinned clang-format, or with
# --check verify them without writing (fails on a diff). The sources are
# taken largest first, 8 files per clang-format process, one process per
# core (a process per file spent most of the time starting clang-format).
. scripts/just/lib.sh
nix_reexec "$0" "$@"
set -eu
# csrcs MODE [FIND-ARGS...]: run clang-format MODE (a word list) over them.
csrcs() {
    mode=$1
    shift
    # shellcheck disable=SC2086 # $mode is a word list
    find src tests examples fuzz guide/snippets -name node_modules -prune -o \
        \( -name '*.c' -o -name '*.h' \) "$@" -print0 \
        | xargs -0r ls -S | xargs -r -P "$(nproc)" -n 8 clang-format $mode
}
if [ "${1:-}" = "--check" ]; then
    csrcs "--dry-run --Werror"
    exit
fi
if [ -z "${IN_NIX_SHELL:-}" ]; then
    echo "warning: no nix; formatting with the host clang-format (may disagree with CI's pin)" >&2
fi
# Only files changed since the last run with the same clang-format and
# .clang-format (the stamp holds the version); anything else redoes all.
mkdir -p build
stamp=build/.fmt-stamp
ver=$(clang-format --version)
newer=""
if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$ver" ] \
    && [ .clang-format -ot "$stamp" ]; then newer="-newer $stamp"; fi
printf '%s\n' "$ver" > "$stamp.new"
# shellcheck disable=SC2086 # $newer is zero or two words
csrcs -i $newer
mv "$stamp.new" "$stamp"
