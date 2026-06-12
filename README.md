# P2P VPN (p2p-vpn)

A secure, private peer-to-peer mesh VPN written in Go using libp2p, Kademlia DHT, and OS-level TUN interfaces. It allows multiple endpoints to securely bridge their networks (IPv4 spaces) without requiring port forwarding, traversing NATs via bootstrap relays (rendezvous), and encrypting data using AES-256-GCM.

It is designed to connect distinct sites, such as Kubernetes clusters, using a decentralized mesh topology.

---

## Features

- **NAT Traversal & Hole Punching:** Uses libp2p relays and hole punching to establish direct peer-to-peer links.
- **Connection Gater Whitelist:** Optional transport-level filtering via Peer ID whitelist to instantly reject unauthorized connections without cryptographic/handshake delays.
- **Post-Quantum PKI Security:** Optional FIPS 204-compliant ML-DSA-87 (NIST Level 5) CA signature checking on handshakes to support zero-update dynamic scaling.
- **End-to-End Encryption:** Extra layer of AES-256-GCM encryption on the VPN tunnel payloads via a pre-shared `-datakey`.
- **Shared Subnet Mode (Option C):** Endpoints share a virtual IP space (e.g. `10.200.0.0/24`) and peer directly over it.
- **Automatic Routing Configuration:** Automatically runs system routing commands (`ip route` or `route`) when remote subnets are discovered or peers disconnect.
- **Robust Reconnections:** Tunnels are re-established automatically on disconnects.
- **Dry-Run Mode:** Runs a mock TUN interface to simulate and test packet I/O without requiring root permissions (`sudo`).

---

## Security Configurations

The security options are fully optional and can be layered to suit different threat models:

| Configuration | Whitelist (`-allowed-peers`) | CA PKI (`-ca-key`) | Resulting Behavior |
| :--- | :--- | :--- | :--- |
| **Open Mode** | Disabled | Disabled | Open mesh. Connections accepted from anyone. (Data still encrypted end-to-end via `-datakey`). |
| **Instant Block Mode** | **Enabled** | Disabled | Nodes not in the whitelist file are blocked instantly at connection setup with zero delay. No CA required. |
| **Dynamic Private Mode** | Disabled | **Enabled** | Nodes connect dynamically without static whitelists. Enforces CA signatures with a 5s maximum timeout for unauthorized connections. |
| **Double-Layered Mode** | **Enabled** | **Enabled** | Unrecognized nodes are blocked instantly at the transport level, and whitelisted nodes must also present valid CA signatures to exchange traffic. |

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

Endpoints require the same **Data Key** for end-to-end AES-GCM encryption. If CA-based PKI is enabled, nodes must also be signed by the CA public key.

### 1. Generate the Data Key (Required)
Endpoints must share the same data key (32-byte hex-encoded):
```bash
openssl rand -hex 32 > data.key
```

### 2. Generate the CA Key Pair (Optional PKI)
To use PKI, generate a post-quantum ML-DSA-87 CA key pair:
```bash
./p2p-vpn -mode ca-keygen
```
This writes `ca.pub` (CA Public Key) and `ca.key` (CA Private Key) to the current directory.

### 3. Sign a Node's Peer ID (Optional PKI)
For each node (relay or endpoint), sign its unique Peer ID using the CA private key. First, find the node's Peer ID by launching it or checking its identity file, then run:
```bash
./p2p-vpn -mode ca-sign -ca-key-priv ca.key -peer <node-peer-id>
```
This outputs and saves a PEM signature file named `<node-peer-id>.sig`.

---

## How to Run

### 1. Start the Relay Node
Run the relay on a public machine (e.g. VPS) with port 4001 open.

**Open Mode:**
```bash
./p2p-vpn -mode relay -port 4001 -cluster my-vpn-cluster
```

**Dynamic PKI Mode (Enforcing CA signatures):**
```bash
./p2p-vpn -mode relay \
          -port 4001 \
          -cluster my-vpn-cluster \
          -ca-key ca.pub \
          -node-sig <relay-peer-id>.sig
```
*Note the relay Multiaddr printed in the logs, e.g. `/ip4/1.2.3.4/tcp/4001/p2p/Qm...`*

### 2. Start Endpoints (using Dry-Run Mode)
To test the setup without root permissions:

**Endpoint A (Combined Mode):**
```bash
./p2p-vpn -mode endpoint \
          -cluster my-vpn-cluster \
          -datakey data.key \
          -relay "/ip4/1.2.3.4/tcp/4001/p2p/Qm..." \
          -tun-ip "10.200.0.1/24" \
          -advertise "10.100.1.0/24" \
          -ca-key ca.pub \
          -node-sig <epa-peer-id>.sig \
          -allowed-peers whitelist.txt \
          -dry-run
```

**Endpoint B (Combined Mode):**
```bash
./p2p-vpn -mode endpoint \
          -cluster my-vpn-cluster \
          -datakey data.key \
          -relay "/ip4/1.2.3.4/tcp/4001/p2p/Qm..." \
          -tun-ip "10.200.0.2/24" \
          -advertise "10.100.2.0/24" \
          -ca-key ca.pub \
          -node-sig <epb-peer-id>.sig \
          -allowed-peers whitelist.txt \
          -dry-run
```

### 3. Start Endpoints (Real VPN Mode - Requires Root)
To create actual TUN interfaces and configure the OS routes:

**Endpoint A:**
```bash
sudo ./p2p-vpn -mode endpoint \
               -cluster my-vpn-cluster \
               -datakey data.key \
               -relay "/ip4/1.2.3.4/tcp/4001/p2p/Qm..." \
               -tun-ip "10.200.0.1/24" \
               -advertise "10.100.1.0/24" \
               -ca-key ca.pub \
               -node-sig <epa-peer-id>.sig \
               -allowed-peers whitelist.txt
```

---

## Environment Variables

All parameters can be configured using environment variables (especially useful when running inside Kubernetes):

| Flag | Env Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `-mode` | `P2P_VPN_MODE` | `endpoint` | Mode: `relay`, `endpoint`, `ca-keygen`, `ca-sign`, `ca-verify` |
| `-port` | `P2P_VPN_PORT` | `0` (random) | Listening port (4001 default for relay) |
| `-identity` | `P2P_VPN_IDENTITY` | `identity-<mode>.key` | Node identity key file path |
| `-cluster` | `P2P_VPN_CLUSTER` | `my-k8s-cluster` | Cluster/Rendezvous namespace ID |
| `-relay` | `P2P_VPN_RELAY` | `""` | Comma-separated bootstrap relay multiaddrs |
| `-datakey` | `P2P_VPN_DATAKEY` | `""` | Path to the hex key file for GCM |
| `-tun-ip` | `P2P_VPN_TUN_IP` | `""` | Virtual subnet IP/CIDR for the TUN interface |
| `-advertise` | `P2P_VPN_ADVERTISE` | `""` | Comma-separated list of subnets to route |
| `-allowed-peers` | `P2P_VPN_ALLOWED_PEERS` | `""` | Path to file containing allowed Peer IDs (one per line) |
| `-ca-key` | `P2P_VPN_CA_KEY` | `""` | Path to PEM-encoded CA public key file |
| `-node-sig` | `P2P_VPN_NODE_SIG` | `""` | Path to PEM-encoded node signature file |
| `-dry-run` | `P2P_VPN_DRY_RUN` | `false` | Enable Mock TUN device for testing |

---

## Known Issues & Limitations

### UDP Subnet Routing Source IP Mismatch
When routing UDP traffic targeting the VPN host/pod itself via its physical IP address (e.g. `iperf3 -c <physical-ip> -u`), the client receives reply packets with the virtual VPN IP as the source address instead of the physical IP due to the wildcard socket bind. This causes the client to reject the packets.

For a detailed explanation and `iptables` / Kubernetes workaround configurations, see the [Subnet Routing Guide](docs/subnet_routing.md).


