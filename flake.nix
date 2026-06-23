{
  description = "A better whois and domain intelligence toolkit";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages = rec {
          default = quien;
          quien = pkgs.callPackage (
            {buildGoModule}:
              buildGoModule (finalAttrs: {
                pname = "quien";
                version = "0.11.0";
                vendorHash = "sha256-7gP6eN+lF90kSltQMHkVTTanogEAtbLnENdZTF9f98c=";
                src = ./.;

                env.CGO_ENABLED = 0;
                ldflags = [
                  "-s"
                  "-w"
                  "-X main.version=${finalAttrs.version}"
                ];
              })
          ) {};
        };

        apps = rec {
          default = quien;
          quien = flake-utils.lib.mkApp {drv = self.packages.${system}.quien;};
        };
      }
    );
}
