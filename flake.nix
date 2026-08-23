{
  description = "A secure, private peer-to-peer mesh VPN using libp2p";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        version = "1.0.4";

        # Define native package (for devShell and default binary of the host platform)
        p2p-vpn-native = (pkgs.buildGoModule.override { go = pkgs.go_1_25; }) {
          pname = "p2p-vpn";
          version = version;
          src = ./.;
          subPackages = [ "cmd/p2p-vpn" ];
          vendorHash = "sha256-U0DipYXziRVWCgatnPA8sRaih4sb/TtJbaf+OzYuGIM=";
          ldflags = [
            "-s"
            "-w"
          ];
        };

        # --- AMD64 TARGET ---

        p2p-vpn-linux-amd64 = p2p-vpn-native.overrideAttrs (oldAttrs: {
          GOOS = "linux";
          GOARCH = "amd64";
          CGO_ENABLED = "0";
          doCheck = false;

          env = builtins.removeAttrs (oldAttrs.env or { }) [
            "GOOS"
            "GOARCH"
            "CGO_ENABLED"
          ];

          # Move the cross-compiled binary to the main bin/ directory if it was cross-compiled
          postInstall = ''
            if [ -d $out/bin/linux_amd64 ]; then
              mv $out/bin/linux_amd64/p2p-vpn $out/bin/p2p-vpn
              rmdir $out/bin/linux_amd64
            fi
          '';
        });

        dockerImage-amd64 = pkgs.dockerTools.buildImage {
          name = "p2p-vpn";
          tag = "${version}-amd64";
          architecture = "amd64";

          # scratch-like image containing only the compiled static Go binary
          copyToRoot = pkgs.buildEnv {
            name = "p2p-vpn-root-amd64";
            paths = [
              p2p-vpn-linux-amd64
            ];
            pathsToLink = [ "/bin" ];
          };

          config = {
            Entrypoint = [ "/bin/p2p-vpn" ];
            Env = [
              "PATH=/bin"
            ];
          };
        };

        # --- ARM64 TARGET ---

        p2p-vpn-linux-arm64 = p2p-vpn-native.overrideAttrs (oldAttrs: {
          GOOS = "linux";
          GOARCH = "arm64";
          CGO_ENABLED = "0";
          doCheck = false;

          env = builtins.removeAttrs (oldAttrs.env or { }) [
            "GOOS"
            "GOARCH"
            "CGO_ENABLED"
          ];

          # Move the cross-compiled binary to the main bin/ directory if it was cross-compiled
          postInstall = ''
            if [ -d $out/bin/linux_arm64 ]; then
              mv $out/bin/linux_arm64/p2p-vpn $out/bin/p2p-vpn
              rmdir $out/bin/linux_arm64
            fi
          '';
        });

        dockerImage-arm64 = pkgs.dockerTools.buildImage {
          name = "p2p-vpn";
          tag = "${version}-arm64";
          architecture = "arm64";

          # scratch-like image containing only the compiled static Go binary
          copyToRoot = pkgs.buildEnv {
            name = "p2p-vpn-root-arm64";
            paths = [
              p2p-vpn-linux-arm64
            ];
            pathsToLink = [ "/bin" ];
          };

          config = {
            Entrypoint = [ "/bin/p2p-vpn" ];
            Env = [
              "PATH=/bin"
            ];
          };
        };

        # --- WINDOWS TARGET ---

        # Build for Windows amd64 using Go's native cross-compilation capabilities
        p2p-vpn-windows = (pkgs.buildGoModule.override { go = pkgs.go_1_25; }) {
          pname = "p2p-vpn-windows";
          version = version;
          src = ./.;
          subPackages = [ "cmd/p2p-vpn" ];
          vendorHash = "sha256-U0DipYXziRVWCgatnPA8sRaih4sb/TtJbaf+OzYuGIM=";
          ldflags = [
            "-s"
            "-w"
          ];
          doCheck = false;

          env = {
            GOOS = "windows";
            GOARCH = "amd64";
            CGO_ENABLED = "0";
          };
        };

      in
      {
        packages = {
          default = p2p-vpn-native;
          p2p-vpn = p2p-vpn-native;
          p2p-vpn-linux-amd64 = p2p-vpn-linux-amd64;
          p2p-vpn-linux-arm64 = p2p-vpn-linux-arm64;
          docker-amd64 = dockerImage-amd64;
          docker-arm64 = dockerImage-arm64;
          docker = dockerImage-amd64; # default to amd64
          windows = p2p-vpn-windows;
        };

        apps.default = flake-utils.lib.mkApp { drv = p2p-vpn-native; };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go
            pkgs.iproute2
          ];
        };
      }
    )
    // {
      nixosModules.default =
        {
          pkgs,
          config,
          lib,
          ...
        }:
        {
          imports = [ ./nixos/module.nix ];
          services.p2p-vpn.package = lib.mkDefault self.packages.${pkgs.system}.default;
        };
      nixosModules.p2p-vpn = self.nixosModules.default;
    };
}
