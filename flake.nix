{
  description = "mobile-toolkit (mtk): Qualcomm EDL recovery tooling";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in
    {
      packages = forAll (pkgs: rec {
        mobile-toolkit = pkgs.rustPlatform.buildRustPackage {
          pname = "mobile-toolkit";
          version = "0.1.0";
          src = pkgs.lib.cleanSource ./.;
          cargoLock.lockFile = ./Cargo.lock;
          meta = {
            description = "Qualcomm EDL (Sahara/Firehose) recovery tool";
            license = pkgs.lib.licenses.gpl3Only;
            mainProgram = "mtk";
          };
        };
        default = mobile-toolkit;
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [ cargo rustc clippy rustfmt rust-analyzer ];
        };
      });

      # TODO: nixosModules.default — udev rule for 05c6:9008 (plugdev/uaccess)
      # and the package on PATH. Not built yet.
    };
}
