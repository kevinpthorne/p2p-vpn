{ config, lib, pkgs, ... }:

{
  # This NixOS module demonstrates how to run the p2p-vpn container
  # using NixOS's native OCI container management.
  # 
  # Import this file in your configuration.nix:
  # imports = [ ./p2p-vpn-container.nix ];

  # Ensure a container backend is enabled (docker or podman)
  virtualisation.oci-containers.backend = "docker"; 

  virtualisation.oci-containers.containers."p2p-vpn" = {
    image = "ghcr.io/kevinpthorne/p2p-vpn:latest";
    autoStart = true;
    
    # Required to manipulate the host's networking stack
    extraOptions = [
      "--cap-add=NET_ADMIN"
      "--network=host"
      "--device=/dev/net/tun:/dev/net/tun"
    ];
    
    # Mount the persistent directory containing keys from the NixOS host
    volumes = [
      "/etc/p2p-vpn:/etc/p2p-vpn"
    ];
    
    # Environment variable configuration
    # Uncomment and modify variables based on whether this is a relay or endpoint
    environment = {
      # --- General Settings ---
      P2P_VPN_MODE = "relay";           # "relay" or "endpoint"
      P2P_VPN_CLUSTER = "my-vpn-cluster";
      
      # --- Relay Settings (Ignore if endpoint) ---
      P2P_VPN_PORT = "4001";
      # P2P_VPN_EXT_DNS = "myrelay.example.org";
      
      # --- Endpoint Settings (Ignore if relay) ---
      # P2P_VPN_TUN_IP = "10.200.0.1/24";
      # P2P_VPN_RELAYS = "/ip4/1.2.3.4/tcp/4001/p2p/Qm...";
      
      # --- Key & PKI Paths ---
      P2P_VPN_DATAKEY = "/etc/p2p-vpn/data.key";
      P2P_VPN_IDENTITY = "/etc/p2p-vpn/identity.key";
      P2P_VPN_CA_KEY = "/etc/p2p-vpn/ca.pub";
      P2P_VPN_NODE_SIG = "/etc/p2p-vpn/node.sig";
      # P2P_VPN_ALLOWED_PEERS = "/etc/p2p-vpn/whitelist.txt";
    };
  };

  # If you are running as a Relay, automatically open the firewall port!
  networking.firewall.allowedTCPPorts = [ 4001 ];
  networking.firewall.allowedUDPPorts = [ 4001 ];
}
