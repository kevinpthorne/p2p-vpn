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

### Using Nix (Recommended)
This project includes a Nix flake to natively build, cross-compile, and package the application:
- **Build the native binary** (for your current OS/architecture):
  ```bash
  nix build
  ```
  The binary will be available at `./result/bin/p2p-vpn`.
- **Cross-compile for Windows (amd64)**:
  ```bash
  nix build .#windows
  ```
  The executable will be available at `./result/bin/p2p-vpn-windows.exe`.
- **Build the vulnerability-free `scratch` Docker images** (via Go native cross-compiling):
  ```bash
  # AMD64 Image
  nix build .#docker-amd64
  # ARM64 Image
  nix build .#docker-arm64
  ```
  These generate loaded image tarballs at `./result` containing *only* the compiled static Go binary (zero OS vulnerabilities and small footprint of ~15MB).

### Standard Go Build (requires Go 1.25.5+)
Fetch and resolve dependencies:
```bash
go mod tidy
```
- **Local build**:
  ```bash
  go build -o p2p-vpn main.go tun.go tun_darwin.go tun_linux.go tun_unsupported.go tun_windows.go
  ```
- **Multi-platform build** (using compile.sh):
  ```bash
  chmod +x compile.sh
  ./compile.sh
  ```
  This generates:
  - `p2p-vpn.darwin-arm64` (for Apple Silicon macOS)
  - `p2p-vpn.win-amd64.exe` (for 64-bit Windows)
  - `p2p-vpn.linux-amd64` (for 64-bit Linux)
  - `p2p-vpn.linux-arm64` (for 64-bit ARM Linux/Docker containers)

---

## How to Test

Unit tests run against the mock TUN interface (`MockTun`) and do not require root permissions or internet access:
```bash
go test -v ./...
```

When building via Nix, tests are automatically run inside the Nix build sandbox:
```bash
nix build .#p2p-vpn
```

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

### 4. Start Endpoints (Docker Container)
Our Docker images are packaged using Nix from a pure `scratch` base. Run the container with the `NET_ADMIN` capability and TUN device access:
```bash
docker run --rm -it \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun:/dev/net/tun \
  -e P2P_VPN_MODE=endpoint \
  -e P2P_VPN_CLUSTER=my-vpn-cluster \
  -e P2P_VPN_TUN_IP=10.200.0.1/24 \
  -e P2P_VPN_RELAY="/ip4/1.2.3.4/tcp/4001/p2p/Qm..." \
  ghcr.io/kevinpthorne/p2p-vpn:latest
```

### 5. Deploy on Kubernetes (using Helm)
We package and host the Helm chart as an OCI registry artifact on GHCR.

**Install the Helm Chart**:
```bash
helm install my-vpn oci://ghcr.io/kevinpthorne/charts/p2p-vpn --version 1.0.0 \
  --set mode=endpoint \
  --set cluster=my-vpn-cluster \
  --set tunIp=10.200.0.1/24 \
  --set relayMultiaddr="/ip4/1.2.3.4/tcp/4001/p2p/Qm..."
```

**Key Parameters in `values.yaml`**:
- `mode`: `endpoint` or `relay`.
- `secrets.create` / `existingSecret`: Options to feed key files (`data.key`, `identity.key`, `ca.pub`, `node.sig`, `whitelist.txt`) securely.
- `securityContext`: Automatically configured with `privileged: true` (or `NET_ADMIN` capabilities) to allow network interface setup.
- `tunVolume`: Mounts the host node's `/dev/net/tun` interface inside the container.

### 6. Deploy on NixOS (Declarative Flake)
This project exports a native NixOS module that runs the Go binary as a secure systemd service. For full details on how to integrate the flake and configure `services.p2p-vpn` declaratively in your `configuration.nix`, please see the [NixOS Deployment Guide](docs/nixos.md).

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


