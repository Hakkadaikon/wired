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
# A fixed 1GiB, not `unlimited`: an unlimited stack switches the kernel to
# the legacy bottom-up mmap layout, which overlaps ASan's shadow memory and
# aborts the sanitized test binary before main.
raise_stack() {
    # shellcheck disable=SC3045 # not POSIX, but dash and bash both have it
    ulimit -s 1048576 2>/dev/null || ulimit -s 65536
}
