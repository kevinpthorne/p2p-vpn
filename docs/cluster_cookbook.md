# P2P-VPN Cluster Setup Cookbook

Setting up a new secure cluster involves generating shared secrets, spinning up your Certificate Authority (CA), launching your infrastructure relays, and finally connecting your endpoints. 

This guide walks you through setting up a complete, Zero-Trust mesh network from scratch using the CLI.

---

## Phase 1: Generate Network Secrets & CA

Before any node can talk, we need to establish the cryptographic boundaries of the network.

### 1. Generate the Swarm Key
The Swarm Key isolates your network at the transport layer. Only nodes with this key can connect to each other.

```bash
# Generate a 32-byte hex-encoded libp2p swarm key
echo -e "/key/swarm/psk/1.0.0/\n/base16/\n$(openssl rand -hex 32)" > swarm.key
```

### 2. Generate the Data Payload Key
The Data Key is used to AES-encrypt the actual IP packets flowing over the VPN tunnel.

```bash
# Generate a 32-byte hex string
openssl rand -hex 32 > data.key
```

### 3. Generate the Certificate Authority (CA)
The CA is used to issue identity signatures.

```bash
# Generates ca.key (Private Key) and ca.pub (Public Key) in the current directory
./p2p-vpn -mode ca-keygen
```

> [!CAUTION]
> Your `ca.key` is the master key to your entire mesh network. Keep it completely offline and secure. Never upload it to a relay or endpoint node.

Distribute `swarm.key`, `data.key`, and `ca.pub` to **all nodes** (Relays and Endpoints).

---

## Phase 2: Setup the Relay Infrastructure

Relays sit on the public internet and help your endpoints discover each other and bypass firewalls.

### 1. Generate a Relay Identity
On the relay server, generate its unique identity key. This will also output its Peer ID.

```bash
# Generate the key and print the Peer ID
./p2p-vpn -mode relay -print-peer-id -identity identity-relay.key

# Example Output: 12D3KooWRelay123...
```

### 2. Sign the Relay Identity
Take the Relay's Peer ID back to your secure, offline CA machine to sign it. Relays do not need Virtual IPs, so we omit the `-sign-ip` flag.

```bash
./p2p-vpn -mode ca-sign -ca-key-priv ca.key -peer 12D3KooWRelay123... > relay.sig
```

### 3. Launch the Relay
Copy the `relay.sig` file to the relay server and start it up.

```bash
./p2p-vpn -mode relay \
  -port 4001 \
  -cluster "my-secure-cluster" \
  -identity identity-relay.key \
  -ca-key ca.pub \
  -node-sig relay.sig
```

Once running, note the relay's public IP address and its Peer ID. Your endpoints will need this to connect.

---

## Phase 3: Connect the Endpoints

Endpoints are the actual machines participating in the VPN (e.g. laptops, database servers).

### 1. Generate an Endpoint Identity
On the endpoint machine, generate its identity key and get its Peer ID.

```bash
./p2p-vpn -mode endpoint -print-peer-id -identity identity-ep1.key

# Example Output: 12D3KooWEndpoint456...
```

### 2. Sign the Endpoint Identity with a Virtual IP
Back on your offline CA machine, sign the endpoint's Peer ID. **Crucially, explicitly bind the Virtual IP you want to assign to this endpoint.**

```bash
# Authorize this node to use 10.200.0.5/24
./p2p-vpn -mode ca-sign -ca-key-priv ca.key -peer 12D3KooWEndpoint456... -sign-ip 10.200.0.5/24 > ep1.sig
```

### 3. Launch the Endpoint
Copy the `ep1.sig` to the endpoint machine. You will need the Multiaddr of your relay from Phase 2 (e.g., `/ip4/203.0.113.50/tcp/4001/p2p/12D3KooWRelay123...`).

```bash
# Must be run as root/sudo to create the TUN interface
sudo ./p2p-vpn -mode endpoint \
  -tun-ip "10.200.0.5/24" \
  -cluster "my-secure-cluster" \
  -identity identity-ep1.key \
  -ca-key ca.pub \
  -node-sig ep1.sig \
  -relay "/ip4/203.0.113.50/tcp/4001/p2p/12D3KooWRelay123..."
```

*(Optional)* If you want this endpoint to act as a subnet router for a physical LAN, append the `-advertise` flag: `-advertise "192.168.1.0/24"`.

---

## Phase 4 (Optional): Strict Connection Gating

To maximize security, you can create a text file containing the Peer IDs of every authorized node (relays and endpoints), one per line.

```text
12D3KooWRelay123...
12D3KooWEndpoint456...
```

Save this as `whitelist.txt` and pass `-allowed-peers whitelist.txt` when starting **every** node. This instructs the libp2p transport layer to instantly drop any connection attempt from a node not on the list, preventing unauthorized nodes from even attempting a handshake.
