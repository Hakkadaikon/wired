#!/bin/sh
# One-time bootstrap: install nix when absent. Afterwards `nix develop`
# provides clang/just/lizard/doxygen (flake.nix).
if command -v nix >/dev/null 2>&1; then
    echo "nix already installed: $(nix --version)"
else
    curl -fsSL https://install.determinate.systems/nix | sh -s -- install
fi
