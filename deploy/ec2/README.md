# EC2 Deployment Guide for P2P VPN

This guide details how to deploy the `p2p-vpn` Docker container on an Amazon EC2 instance so that it automatically boots on system startup with persistence for cryptographic keys.

## 1. Setup Host Directory & Keys

First, create a persistent directory on the host to store the node's keys:

```bash
sudo mkdir -p /etc/p2p-vpn
```

Upload your node's required keys into this directory. At minimum, you will need:
- `identity.key` (generated automatically if missing, but should be persisted)
- `data.key` (the shared symmetric key)
- `ca.pub` (the CA public key)
- `node.sig` (the node's CA signature)

```bash
sudo cp identity.key data.key ca.pub node.sig /etc/p2p-vpn/
sudo chmod 600 /etc/p2p-vpn/*.key
```

## Option A: Using Systemd (Recommended for native EC2)

1. Create the environment file:
```bash
sudo tee /etc/p2p-vpn/p2p-vpn.env > /dev/null <<EOF
P2P_VPN_MODE=endpoint
P2P_VPN_CLUSTER=my-vpn-cluster
P2P_VPN_TUN_IP=10.200.0.1/24
P2P_VPN_RELAYS=/ip4/1.2.3.4/tcp/4001/p2p/Qm...
P2P_VPN_DATAKEY=/etc/p2p-vpn/data.key
P2P_VPN_IDENTITY=/etc/p2p-vpn/identity.key
P2P_VPN_CA_KEY=/etc/p2p-vpn/ca.pub
P2P_VPN_NODE_SIG=/etc/p2p-vpn/node.sig
EOF
```
*(Make sure to update `P2P_VPN_TUN_IP` and `P2P_VPN_RELAYS` to match your cluster).*

2. Copy the `p2p-vpn.service` file to systemd:
```bash
sudo cp p2p-vpn.service /etc/systemd/system/
sudo systemctl daemon-reload
```

3. Enable and start the service so it runs on boot:
```bash
sudo systemctl enable --now p2p-vpn.service
```

## Option B: Using Docker Compose

If your EC2 instance has `docker-compose` installed, you can use the provided `docker-compose.yml` file.

1. Edit `docker-compose.yml` to set your actual `P2P_VPN_TUN_IP` and `P2P_VPN_RELAYS` environment variables.
2. Run the container in detached mode:
```bash
docker-compose up -d
```
Docker's daemon will automatically ensure the container starts on system boot due to the `restart: unless-stopped` directive.
