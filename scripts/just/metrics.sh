#!/bin/sh
# Report only: function NLOC/CCN/length/nesting (ND) and file NLOC (lizard).
. scripts/just/lib.sh
nix_reexec "$0" "$@"
lizard -END "$@"
