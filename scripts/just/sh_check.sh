#!/bin/sh
# Every tracked shell script passes shellcheck (following sourced files),
# and the justfile is in `just --fmt` form.
. scripts/just/lib.sh
nix_reexec "$0" "$@"
set -eu
# shellcheck disable=SC2046 # one path per word
shellcheck -x $(git ls-files '*.sh')
just --fmt --check --unstable
