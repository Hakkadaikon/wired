# shellcheck shell=sh
# Shared by the scripts under scripts/just/ (sourced, not run).

# Re-run the calling script inside the flake devShell, so it uses CI's
# pinned toolchain, when nix exists and we are not in the devShell yet.
# Usage: nix_reexec "$0" "$@"
nix_reexec() {
    if [ -z "${IN_NIX_SHELL:-}" ] && command -v nix >/dev/null 2>&1; then
        exec nix develop -c sh "$@"
    fi
}

# The test binary's frame (test_srvrun) outgrew the 8MB default stack.
raise_stack() {
    # shellcheck disable=SC3045 # not POSIX, but dash and bash both have it
    ulimit -s unlimited 2>/dev/null || ulimit -s 65536
}
