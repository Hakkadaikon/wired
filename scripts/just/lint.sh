#!/bin/sh
# Static analysis (CERT C + bug finders + cognitive complexity) with the
# pinned clang-tidy, since findings differ across versions. One file per
# ninja job, in parallel; a file is re-checked only when it or a header it
# includes changed (build/lint/*.stamp). -k 0 reports every finding.
# ponytail: the stamps do not record the clang-tidy version; remove
# build/lint after a toolchain bump.
. scripts/just/lib.sh
nix_reexec "$0" "$@"
ninja -k 0 -j "$(nproc)" lint
