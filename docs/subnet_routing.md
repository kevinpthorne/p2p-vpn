# Subnet Routing & UDP Source IP Mismatch Guide

When bridging physical subnets over a peer-to-peer VPN, you may encounter an issue where UDP traffic targeting the VPN host/pod itself fails with a `Resource temporarily unavailable` error (e.g. in `iperf3 -u`), while TCP traffic and UDP traffic to *other* hosts in the subnet work fine.

This guide explains the root cause of this behavior and how to resolve it.

---

## The Root Cause: UDP Wildcard Bind & Route Selection

When an application (like `iperf3` or a DNS server) listens on a wildcard address (`0.0.0.0`), the socket is connectionless. When a UDP packet arrives via the VPN tunnel and is processed locally:

1. **Client sends UDP:** The client sends a packet to the physical IP `172.31.34.205`. The packet enters the tunnel and arrives on the VPN host's `tun0` interface.
2. **Server receives UDP:** The destination is local, so the local application processes the packet.
3. **Server replies:** The application replies to the client's virtual IP `10.200.0.1`.
4. **Kernel selects Source IP:** Because the socket is bound to `0.0.0.0` (wildcard) and connectionless, the Linux kernel determines the reply's Source IP by performing a route lookup for `10.200.0.1`.
5. **Source IP Mismatch:** The route to `10.200.0.1` goes out of `tun0` (where the local virtual IP is `10.200.0.2`). Therefore, the kernel selects `10.200.0.2` as the reply packet's Source IP.
6. **Client Rejects:** The client receives a packet from `10.200.0.2` instead of `172.31.34.205`. The client's socket discards it and sends an ICMP Port Unreachable.

> [!NOTE]
> This issue **does not affect TCP** because TCP is connection-oriented. Once a TCP handshake is established on `172.31.34.205`, the kernel binds the socket to that IP and enforces it as the source IP for all subsequent packets in the connection.

---

## How to Resolve the Issue

To resolve both forwarding to other hosts and local UDP replies, you must configure **IP forwarding** and **NAT rules** using `iptables` (or `nftables`) on the VPN gateway host/pod.

### 1. Enable IP Forwarding
The VPN gateway must be allowed to forward packets between the virtual `tun0` interface and the physical interface (e.g., `eth0` or `ens5`).
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

### 2. Configure MASQUERADE (SNAT) for other Subnet Hosts
If you want the VPN client to reach other hosts in the physical subnet (e.g., `172.31.34.100`), the reply packets must route back through the VPN gateway. The easiest way is to masquerade the client's virtual IP as the gateway's physical IP:
```bash
sudo iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -o eth0 -j MASQUERADE
```
*(Replace `eth0` with your active physical network interface).*

### 3. Configure DNAT for the VPN Host itself
To fix the UDP wildcard reply issue for services running *on the VPN host itself*, rewrite incoming packets destined to the physical IP to the virtual IP before they reach the application. The kernel's NAT engine will then automatically rewrite the reply's Source IP back to the physical IP.
```bash
sudo iptables -t nat -A PREROUTING -i tun0 -d 172.31.34.205 -j DNAT --to-destination 10.200.0.2
```
*(Replace `172.31.34.205` with the host's physical IP, and `10.200.0.2` with its virtual VPN IP).*

---

## Running inside a Kubernetes Pod

If the VPN daemon runs inside a Kubernetes Pod as a gateway, you can apply these rules in one of the following ways:

### Option A: Using an Entrypoint Script / Container Capabilities
To run `iptables` inside a container, the Pod must be granted the `NET_ADMIN` capability.

1. **Pod Configuration (`deployment.yaml`):**
   ```yaml
   securityContext:
     capabilities:
       add:
         - NET_ADMIN
   ```
2. **Container Entrypoint Script:**
   You can wrap the daemon startup in a script that detects the environment and runs the rules:
   ```bash
   #!/bin/sh
   # Enable IP Forwarding
   sysctl -w net.ipv4.ip_forward=1

   # Detect physical interface and IP (example targeting eth0)
   PHYS_INTF="eth0"
   PHYS_IP=$(ip -4 addr show dev "$PHYS_INTF" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
   VIRT_IP="10.200.0.2"

   # Apply NAT Rules
   iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -o "$PHYS_INTF" -j MASQUERADE
   iptables -t nat -A PREROUTING -i tun0 -d "$PHYS_IP" -j DNAT --to-destination "$VIRT_IP"

   # Start VPN Daemon
   exec ./p2p-vpn "$@"
   ```

### Option B: Using an Init Container
You can also run a privileged init container to enable IP forwarding on the host namespace, while keeping the main container less privileged (though `NET_ADMIN` is still required to create the `tun0` interface).
