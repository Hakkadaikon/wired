#!/bin/sh
# Full build in the devShell, so all three legs use the pinned toolchain.
. scripts/just/lib.sh
nix_reexec "$0" "$@"
just fmt && just ninja && just lint
