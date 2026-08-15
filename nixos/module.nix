{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.p2p-vpn;
in {
  options.services.p2p-vpn = {
    enable = mkEnableOption "P2P VPN Daemon";

    package = mkOption {
      type = types.package;
      description = "The p2p-vpn package to use.";
    };

    mode = mkOption {
      type = types.enum [ "relay" "endpoint" ];
      default = "endpoint";
      description = "The operating mode of the node (relay or endpoint).";
    };
    
    port = mkOption {
      type = types.port;
      default = 4002;
      description = "Port to listen on (required for relays, random for endpoints if 0).";
    };

    cluster = mkOption {
      type = types.str;
      description = "The cluster rendezvous namespace ID.";
    };

    tunIp = mkOption {
      type = types.str;
      default = "";
      description = "The virtual TUN IP and subnet (e.g. 10.200.0.1/24) for endpoint mode.";
    };

    relay = mkOption {
      type = types.str;
      default = "";
      description = "The bootstrap relay multiaddr for endpoint mode.";
    };

    advertise = mkOption {
      type = types.str;
      default = "";
      description = "Comma-separated list of subnets to route (Option C shared subnet mode).";
    };

    dataKeyPath = mkOption {
      type = types.path;
      description = "Path to the hex-encoded data key file.";
    };

    identityPath = mkOption {
      type = types.path;
      description = "Path to the identity key file.";
    };

    caKey = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The PEM-encoded CA public key string (for PKI).";
    };

    nodeSig = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The node signature string (for PKI).";
    };
    
    allowedPeers = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The whitelist string containing allowed Peer IDs (one per line).";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.mode == "endpoint" -> (cfg.tunIp != "" && cfg.relay != "");
        message = "services.p2p-vpn: 'tunIp' and 'relay' must be set when using endpoint mode.";
      }
      {
        assertion = cfg.mode == "relay" -> (cfg.tunIp == "" && cfg.relay == "");
        message = "services.p2p-vpn: 'tunIp' and 'relay' should not be set when using relay mode.";
      }
    ];

    environment.etc = mkMerge [
      (mkIf (cfg.caKey != null) {
        "p2p-vpn/ca.pub".text = cfg.caKey;
      })
      (mkIf (cfg.nodeSig != null) {
        "p2p-vpn/node.sig".text = cfg.nodeSig;
      })
      (mkIf (cfg.allowedPeers != null) {
        "p2p-vpn/whitelist.txt".text = cfg.allowedPeers;
      })
    ];

    systemd.services.p2p-vpn = {
      description = "P2P VPN Daemon";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      preStart = ''
        # Ensure the parent directories for the keys exist so the daemon can generate the identity key on first boot
        mkdir -p $(dirname ${cfg.identityPath})
      '';

      serviceConfig = {
        ExecStart = let
          args = [
            "-mode" cfg.mode
            "-cluster" cfg.cluster
            "-datakey" cfg.dataKeyPath
            "-identity" cfg.identityPath
            "-port" (toString cfg.port)
          ] ++ optionals (cfg.tunIp != "") [ "-tun-ip" cfg.tunIp ]
            ++ optionals (cfg.relay != "") [ "-relay" cfg.relay ]
            ++ optionals (cfg.advertise != "") [ "-advertise" cfg.advertise ]
            ++ optionals (cfg.caKey != null) [ "-ca-key" "/etc/p2p-vpn/ca.pub" ]
            ++ optionals (cfg.nodeSig != null) [ "-node-sig" "/etc/p2p-vpn/node.sig" ]
            ++ optionals (cfg.allowedPeers != null) [ "-allowed-peers" "/etc/p2p-vpn/whitelist.txt" ];
        in "${cfg.package}/bin/p2p-vpn ${escapeShellArgs args}";
        
        Restart = "always";
        RestartSec = "5s";
        
        # P2P-VPN modifies the network interfaces and routing tables natively
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        DeviceAllow = "/dev/net/tun rw";
      };
    };

    # Automatically open ports for relay mode
    networking.firewall.allowedTCPPorts = mkIf (cfg.mode == "relay") [ cfg.port ];
    networking.firewall.allowedUDPPorts = mkIf (cfg.mode == "relay") [ cfg.port ];
  };
}
