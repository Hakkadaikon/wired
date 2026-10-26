#!/bin/sh
# Python under scripts/: ruff lint and format, the stdlib-unittest suite in
# tests/scripts/, CCN <= 3 (lizard; its nesting depth is not reliable
# for Python, so not checked), and the vuln-ledger check (row rules plus
# reach.py). Halstead is part of `just halstead-check`.
. scripts/just/lib.sh
nix_reexec "$0" "$@"
set -eu
ruff check scripts tests/scripts
ruff format --check scripts tests/scripts
python3 -m unittest discover tests/scripts
lizard scripts --CCN 3 -w
python3 scripts/vulnaudit/ledger_check.py docs/security/vuln-ledger.md
