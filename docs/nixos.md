# NixOS Flake Deployment Guide

This project provides a native NixOS module exposed via its flake outputs, allowing you to seamlessly integrate and configure `p2p-vpn` declaratively as a systemd service directly within your NixOS system configurations.

## 1. Add the Flake Input

First, add the `p2p-vpn` repository as an input to your system's `flake.nix`.

```nix
{
  description = "My NixOS System Flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    
    # Add p2p-vpn as an input
    p2p-vpn.url = "github:kevinpthorne/p2p-vpn";
  };

  outputs = { self, nixpkgs, p2p-vpn, ... }@inputs: {
    nixosConfigurations.my-server = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      
      # Pass the inputs to your modules so they can access the p2p-vpn module
      specialArgs = { inherit inputs; };
      
      modules = [
        ./configuration.nix
        
        # Include the p2p-vpn NixOS module here
        p2p-vpn.nixosModules.default
      ];
    };
  };
}
```

## 2. Configure the Service

Once the module is imported into your `nixosConfigurations`, you can configure the VPN daemon natively in your `configuration.nix` (or any imported module) using the `services.p2p-vpn` options.

### Example: Relay Configuration

If you are setting up a relay node, the module will automatically open the required TCP and UDP firewall ports for you:

```nix
{ config, pkgs, ... }:

{
  services.p2p-vpn = {
    enable = true;
    mode = "relay";
    cluster = "my-vpn-cluster";
    port = 4001; # Default is 4001
    
    # Required private keys (absolute paths on the host managed via sops-nix/agenix)
    dataKeyPath = "/etc/p2p-vpn/data.key";
    identityPath = "/etc/p2p-vpn/identity.key";
    
    # Optional PKI enforcement (Public info embedded as strings)
    caKey = ''
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----
    '';
    nodeSig = ''
      -----BEGIN SIGNATURE-----
      ...
      -----END SIGNATURE-----
    '';
  };
}
```

### Example: Endpoint Configuration

If you are setting up an endpoint that connects to a relay and bridges a virtual subnet:

```nix
{ config, pkgs, ... }:

{
  services.p2p-vpn = {
    enable = true;
    mode = "endpoint";
    cluster = "my-vpn-cluster";
    
    # The VPN virtual subnet IP assigned to this node
    tunIp = "10.200.0.1/24";
    
    # The Multiaddr of the bootstrap relay
    relay = "/ip4/1.2.3.4/tcp/4001/p2p/Qm...";
    
    # Required private keys (absolute paths on the host managed via sops-nix/agenix)
    dataKeyPath = "/etc/p2p-vpn/data.key";
    identityPath = "/etc/p2p-vpn/identity.key";
    
    # Optional PKI enforcement (Public info embedded as strings)
    caKey = ''
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----
    '';
    nodeSig = ''
      -----BEGIN SIGNATURE-----
      ...
      -----END SIGNATURE-----
    '';
  };
}
```

## How It Works

Under the hood, this declarative configuration:
1. Provisions a `systemd.services.p2p-vpn` daemon.
2. Runs the native Go binary compiled for your system architecture directly out of the Nix store (`inputs.p2p-vpn.packages.${system}.default`).
3. Safely grants the daemon the necessary `CAP_NET_ADMIN` capabilities and `/dev/net/tun` write access to configure the OS routing tables without requiring a root `ExecStart`.
