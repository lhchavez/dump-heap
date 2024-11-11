{
  description = "A flake that provides tools needed to hack on dump-heap";

  inputs.nixpkgs.url = "github:nixos/nixpkgs";

  outputs = { self, nixpkgs }: let
    mkPkgs = system: import nixpkgs {
        inherit system;
    };
    mkDevShell = system:
    let
      pkgs = mkPkgs system;
    in
    pkgs.mkShell {
      env = {
        LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
      };
      nativeBuildInputs = with pkgs; [
        python312
        ruff
        ruff-lsp
        uv
        graphviz
      ];
    };
  in
  {
    devShells.aarch64-darwin.default = mkDevShell "aarch64-darwin";
    devShells.x86_64-linux.default = mkDevShell "x86_64-linux";
  };
}
