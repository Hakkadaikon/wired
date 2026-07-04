{
  description = "wired: a libc-free QUIC SDK in C for x86_64-linux";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShells.${system}.default = pkgs.mkShell {
        # llvmPackages_latest: the newest stable LLVM nixpkgs ships; still
        # pinned by flake.lock, so it only moves on an explicit
        # `nix flake update`. clang-tools ships clang-format/clang-tidy (not
        # part of clang); listed first so its wrapped binaries win on PATH.
        packages = [
          pkgs.llvmPackages_latest.clang-tools
          pkgs.llvmPackages_latest.clang
          pkgs.just
          pkgs.python3Packages.lizard # a python tool; no top-level attr
          pkgs.doxygen
          pkgs.ninja
        ];
      };
    };
}
