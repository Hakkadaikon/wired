{
  description = "wired: a libc-free QUIC SDK in C for x86_64-linux and aarch64-linux";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      shells = system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
        default = pkgs.mkShell {
          # llvmPackages_latest: the newest stable LLVM nixpkgs ships; still
          # pinned by flake.lock, so it only moves on an explicit
          # `nix flake update`. clang-tools ships clang-format/clang-tidy (not
          # part of clang); listed first so its wrapped binaries win on PATH.
          packages = [
            pkgs.llvmPackages_latest.clang-tools
            pkgs.llvmPackages_latest.clang
            # llvm ships llvm-profdata/llvm-cov (source-based coverage, `just cov`)
            pkgs.llvmPackages_latest.llvm
            pkgs.just
            pkgs.python3Packages.lizard # a python tool; no top-level attr
            # Halstead and maintainability index (`just halstead`)
            pkgs.rust-code-analysis
            # Python lint/format for scripts/ and shell lint for scripts/ and
            # the examples' helper scripts
            pkgs.ruff
            pkgs.shellcheck
            pkgs.doxygen
            pkgs.ninja
            # memcheck and its client-request header (`just ct-check`,
            # `just valgrind`)
            pkgs.valgrind
            # moqt_chat's NIP-05 resolver helper (examples/moqt_chat/nip05d)
            pkgs.go
          ];
        };
        # Verification-time tools kept out of the build shell: CBMC for the
        # bounded model checks under verify/cbmc (`just cbmc`).
        verify = pkgs.mkShell {
          packages = [ pkgs.cbmc ];
        };
      };
    in {
      devShells = nixpkgs.lib.genAttrs systems shells;
    };
}
