{
  description = "quic_vibe: a libc-free QUIC SDK in C for x86_64-linux";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = [ pkgs.clang pkgs.just pkgs.lizard ];
      };
    };
}
