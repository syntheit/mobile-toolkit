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

      nixosModules.default = { config, lib, pkgs, ... }:
        let cfg = config.programs.mtk;
        in {
          options.programs.mtk = {
            enable = lib.mkEnableOption "mtk, the Qualcomm EDL recovery tool";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = lib.literalExpression "mobile-toolkit.packages.\${system}.default";
              description = "The mtk package to install.";
            };
            group = lib.mkOption {
              type = lib.types.str;
              default = "plugdev";
              description = "Group whose members may open EDL (05c6:9008) and fastboot (18d1) USB devices.";
            };
            blacklistQcserial = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = ''
                Blacklist the qcserial kernel module, which otherwise binds the EDL
                device as /dev/ttyUSB* (where ModemManager may probe it).
              '';
            };
          };
          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];
            users.groups.${cfg.group} = { };
            services.udev.extraRules = ''
              SUBSYSTEM=="usb", ATTRS{idVendor}=="05c6", ATTRS{idProduct}=="9008", MODE="0660", GROUP="${cfg.group}", TAG+="uaccess"
              SUBSYSTEM=="usb", ATTRS{idVendor}=="18d1", MODE="0660", GROUP="${cfg.group}", TAG+="uaccess"
            '';
            boot.blacklistedKernelModules = lib.mkIf cfg.blacklistQcserial [ "qcserial" ];
          };
        };
    };
}
