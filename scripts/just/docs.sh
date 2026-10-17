#!/bin/sh
# Regenerate the public-API reference into docs/sdk (doxygen). INPUT is
# wired.h's transitive includes; the rest is docs/Doxyfile.
set -eu
rm -rf docs/sdk
inputs="$(cd src && clang -I. -E -H wired.h 2>&1 >/dev/null \
    | grep -o '\./.*\.h' | sed 's|^\./|src/|' | sort -u | tr '\n' ' ')"
[ -n "$inputs" ] || { echo "docs: deriving INPUT from wired.h failed" >&2; exit 1; }
( cat docs/Doxyfile; printf 'INPUT = src/wired.h %s\n' "$inputs" ) | doxygen -
