# P2P VPN (p2p-vpn)

A secure, private peer-to-peer mesh VPN written in Go using libp2p, Kademlia DHT, and OS-level TUN interfaces. It allows multiple endpoints to securely bridge their networks (IPv4 spaces) without requiring port forwarding, traversing NATs via bootstrap relays (rendezvous), and encrypting data using AES-256-GCM.

It is designed to connect distinct sites, such as Kubernetes clusters, using a decentralized mesh topology.

---

## Features

- **NAT Traversal & Hole Punching:** Uses libp2p relays and hole punching to establish direct peer-to-peer links.
- **Private Swarm:** Enforced via a Pre-Shared Key (PSK) `swarm.key`.
- **End-to-End Encryption:** Extra layer of AES-256-GCM encryption on the VPN tunnel payloads.
- **Shared Subnet Mode (Option C):** Endpoints share a virtual IP space (e.g. `10.200.0.0/24`) and can peer directly over it.
- **Automatic Routing Configuration:** Automatically runs system routing commands (`ip route` or `route`) when remote subnets are discovered or peers disconnect.
- **Robust Reconnections:** Tunnels are re-established automatically on disconnects.
- **Dry-Run Mode:** Runs a mock TUN interface to simulate and test packet I/O without requiring root permissions (`sudo`).

---

## How to Build

Before compiling, fetch and resolve all required Go dependencies:
```bash
go mod tidy
```

### Local Build (Current OS/Architecture)
To compile the binary for your local machine:
```bash
go build -o p2p-vpn main.go tun.go vpn.go
```

### Multi-Platform Build (using compile.sh)
To compile binaries for multiple platforms (macOS, Linux, and Windows):
```bash
chmod +x compile.sh
./compile.sh
```
This generates the following files in the project root:
- `p2p-vpn.darwin-arm64` (for Apple Silicon macOS)
- `p2p-vpn.win-amd64.exe` (for 64-bit Windows)
- `p2p-vpn.linux-amd64` (for 64-bit Linux)
- `p2p-vpn.linux-arm64` (for 64-bit ARM Linux/Docker containers)

---

## Setup & Keys

All nodes require the same **Swarm Key** to participate in the private p2p network, and endpoints require the same **Data Key** for end-to-end encryption.

### 1. Generate the Swarm Key
Run this to generate a 32-byte swarm key:
```bash
echo -e "/key/swarm/psk/1.0.0/\n/base16/\n$(openssl rand -hex 32)" > swarm.key
```

### 2. Generate the Data Key
Endpoints must share the same data key (32-byte hex-encoded):
```bash
openssl rand -hex 32 > data.key
```

---

## How to Run

### 1. Start the Relay Node
Run the relay on a public machine (e.g. VPS) with port 4001 open.
```bash
./p2p-vpn -mode relay -port 4001 -secret swarm.key -cluster my-vpn-cluster
```
*Note the relay Multiaddr printed in the logs, e.g. `/ip4/1.2.3.4/tcp/4001/p2p/Qm...`*

### 2. Start Endpoints (using Dry-Run Mode)
To test the setup without root permissions:

**Endpoint A:**
```bash
./p2p-vpn -mode endpoint \
          -secret swarm.key \
          -cluster my-vpn-cluster \
          -datakey data.key \
          -relay "/ip4/1.2.3.4/tcp/4001/p2p/Qm..." \
          -tun-ip "10.200.0.1/24" \
          -advertise "10.100.1.0/24" \
          -dry-run
```

**Endpoint B:**
```bash
./p2p-vpn -mode endpoint \
          -secret swarm.key \
          -cluster my-vpn-cluster \
          -datakey data.key \
          -relay "/ip4/1.2.3.4/tcp/4001/p2p/Qm..." \
          -tun-ip "10.200.0.2/24" \
          -advertise "10.100.2.0/24" \
          -dry-run
```

### 3. Start Endpoints (Real VPN Mode - Requires Root)
To create actual TUN interfaces and configure the OS routes:

**Endpoint A:**
```bash
sudo ./p2p-vpn -mode endpoint \
               -secret swarm.key \
               -cluster my-vpn-cluster \
               -datakey data.key \
               -relay "/ip4/1.2.3.4/tcp/4001/p2p/Qm..." \
               -tun-ip "10.200.0.1/24" \
               -advertise "10.100.1.0/24"
```

**Endpoint B:**
```bash
sudo ./p2p-vpn -mode endpoint \
               -secret swarm.key \
               -cluster my-vpn-cluster \
               -datakey data.key \
               -relay "/ip4/1.2.3.4/tcp/4001/p2p/Qm..." \
               -tun-ip "10.200.0.2/24" \
               -advertise "10.100.2.0/24"
```

---

## Environment Variables

All parameters can be configured using environment variables (especially useful when running inside Kubernetes):

| Flag | Env Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `-mode` | `P2P_VPN_MODE` | `endpoint` | Mode: `relay` or `endpoint` |
| `-port` | `P2P_VPN_PORT` | `0` (random) | Listening port (4001 default for relay) |
| `-secret` | `P2P_VPN_SECRET` | `swarm.key` | Path to the private network key |
| `-identity` | `P2P_VPN_IDENTITY` | `identity-<mode>.key` | Node identity key file path |
| `-cluster` | `P2P_VPN_CLUSTER` | `my-k8s-cluster` | Cluster/Rendezvous namespace ID |
| `-relay` | `P2P_VPN_RELAY` | `""` | Comma-separated bootstrap relay multiaddrs |
| `-datakey` | `P2P_VPN_DATAKEY` | `""` | Path to the hex key file for GCM |
| `-tun-ip` | `P2P_VPN_TUN_IP` | `""` | Virtual subnet IP/CIDR for the TUN interface |
| `-advertise` | `P2P_VPN_ADVERTISE` | `""` | Comma-separated list of subnets to route |
| `-dry-run` | `P2P_VPN_DRY_RUN` | `false` | Enable Mock TUN device for testing |

---

## Known Issues & Limitations

### UDP Subnet Routing Source IP Mismatch
When routing UDP traffic targeting the VPN host/pod itself via its physical IP address (e.g. `iperf3 -c <physical-ip> -u`), the client receives reply packets with the virtual VPN IP as the source address instead of the physical IP due to the wildcard socket bind. This causes the client to reject the packets.

For a detailed explanation and `iptables` / Kubernetes workaround configurations, see the [Subnet Routing Guide](docs/subnet_routing.md).

