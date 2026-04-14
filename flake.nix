{
  description = "A better WHOIS lookup tool";
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
                version = "v0.1.1";
                vendorHash = "sha256-q1HAlPIYe/nd5pYW+vZIABxfASlcFXhGNV71SY2ggsc=";
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
          quien = flake-utils.lib.mkApp {drv = self.packages.${system}.quien;};
          default = quien;
        };
      }
    );
}
