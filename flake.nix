{
  description = "A secure, private peer-to-peer mesh VPN using libp2p";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Define native package (for devShell and default binary of the host platform)
        p2p-vpn-native = (pkgs.buildGoModule.override { go = pkgs.go_1_25; }) {
          pname = "p2p-vpn";
          version = "0.1.0";
          src = ./.;
          vendorHash = "sha256-LIJgKJSLENmsIPHfz9eK6axvCYpR+TtrXek2cIa7gMM=";
          ldflags = [ "-s" "-w" ];
        };

        # --- AMD64 TARGET ---

        # Build for Linux amd64 using Go's native cross-compilation capabilities
        p2p-vpn-linux-amd64 = (pkgs.buildGoModule.override { go = pkgs.go_1_25; }) {
          pname = "p2p-vpn";
          version = "0.1.0";
          src = ./.;
          vendorHash = "sha256-LIJgKJSLENmsIPHfz9eK6axvCYpR+TtrXek2cIa7gMM=";
          ldflags = [ "-s" "-w" ];
          doCheck = false;

          env = {
            GOOS = "linux";
            GOARCH = "amd64";
            CGO_ENABLED = "0";
          };
        };

        # Fetch BusyBox for Linux amd64 from the cache
        busybox-linux-amd64 = pkgs.pkgsCross.musl64.busybox;

        dockerImage-amd64 = pkgs.dockerTools.buildImage {
          name = "p2p-vpn";
          tag = "latest-amd64";

          copyToRoot = pkgs.buildEnv {
            name = "p2p-vpn-root-amd64";
            paths = [
              p2p-vpn-linux-amd64
              busybox-linux-amd64
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

        # Build for Linux arm64 using Go's native cross-compilation capabilities
        p2p-vpn-linux-arm64 = (pkgs.buildGoModule.override { go = pkgs.go_1_25; }) {
          pname = "p2p-vpn";
          version = "0.1.0";
          src = ./.;
          vendorHash = "sha256-LIJgKJSLENmsIPHfz9eK6axvCYpR+TtrXek2cIa7gMM=";
          ldflags = [ "-s" "-w" ];
          doCheck = false;

          env = {
            GOOS = "linux";
            GOARCH = "arm64";
            CGO_ENABLED = "0";
          };
        };

        # Fetch BusyBox for Linux arm64 from the cache
        busybox-linux-arm64 = pkgs.pkgsCross.aarch64-multiplatform-musl.busybox;

        dockerImage-arm64 = pkgs.dockerTools.buildImage {
          name = "p2p-vpn";
          tag = "latest-arm64";

          copyToRoot = pkgs.buildEnv {
            name = "p2p-vpn-root-arm64";
            paths = [
              p2p-vpn-linux-arm64
              busybox-linux-arm64
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

      in
      {
        packages = {
          default = p2p-vpn-native;
          p2p-vpn = p2p-vpn-native;
          docker-amd64 = dockerImage-amd64;
          docker-arm64 = dockerImage-arm64;
          docker = dockerImage-amd64; # default to amd64
        };

        apps.default = flake-utils.lib.mkApp { drv = p2p-vpn-native; };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go
            pkgs.iproute2
          ];
        };
      }
    );
}
