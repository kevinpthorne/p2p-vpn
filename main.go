package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
)

func getEnv(key, defaultValue string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		return val == "true" || val == "1"
	}
	return defaultValue
}

func main() {
	// --- CLI Flags & Environment Overrides ---
	modeFlag := flag.String("mode", getEnv("P2P_VPN_MODE", "endpoint"), "Operational mode: 'relay' or 'endpoint'")
	portFlag := flag.Int("port", 0, "Listening port (Default: 4001 for relay, 0/ephemeral for endpoint)")
	secretKeyPathFlag := flag.String("secret", getEnv("P2P_VPN_SECRET", "swarm.key"), "Path to the swarm key (PSK) file")
	identityPathFlag := flag.String("identity", getEnv("P2P_VPN_IDENTITY", ""), "Path to identity file (Defaults: identity-<mode>.key)")
	clusterIDFlag := flag.String("cluster", getEnv("P2P_VPN_CLUSTER", "my-k8s-cluster"), "The cluster ID string for rendezvous")
	relayAddrsFlag := flag.String("relay", getEnv("P2P_VPN_RELAY", ""), "Comma-separated multiaddrs of bootstrap relays")
	dataKeyPathFlag := flag.String("datakey", getEnv("P2P_VPN_DATAKEY", ""), "Path to hex-encoded 32-byte AES data key file")
	tunIPFlag := flag.String("tun-ip", getEnv("P2P_VPN_TUN_IP", ""), "Virtual TUN interface IP/CIDR (e.g. 10.200.0.1/24)")
	advertiseFlag := flag.String("advertise", getEnv("P2P_VPN_ADVERTISE", ""), "Comma-separated subnets to advertise (e.g. 10.100.1.0/24)")
	dryRunFlag := flag.Bool("dry-run", getEnvBool("P2P_VPN_DRY_RUN", false), "Run with dry-run/mock TUN interface")
	flag.Parse()

	// Parse PORT env fallback if flag was 0
	finalPort := *portFlag
	if finalPort == 0 {
		if envPortStr, ok := os.LookupEnv("P2P_VPN_PORT"); ok {
			if parsedPort, err := strconv.Atoi(envPortStr); err == nil {
				finalPort = parsedPort
			}
		}
	}
	if finalPort == 0 && *modeFlag == "relay" {
		finalPort = 4001
	}

	identityPath := *identityPathFlag
	if identityPath == "" {
		identityPath = fmt.Sprintf("identity-%s.key", *modeFlag)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Load Data Encryption Key for Endpoints
	var dataKey []byte
	if *modeFlag == "endpoint" {
		if *dataKeyPathFlag != "" {
			dataKeyHex, err := os.ReadFile(*dataKeyPathFlag)
			if err != nil {
				log.Fatalf("❌ FATAL: Failed to read datakey file: %v", err)
			}
			dataKey, err = hex.DecodeString(strings.TrimSpace(string(dataKeyHex)))
			if err != nil {
				log.Fatalf("❌ FATAL: Invalid hex format in datakey file: %v", err)
			}
			if len(dataKey) != 32 {
				log.Fatalf("❌ FATAL: Datakey must be 32 bytes (64 hex characters). Got %d bytes", len(dataKey))
			}
			if err := InitCipher(dataKey); err != nil {
				log.Fatalf("❌ FATAL: Failed to initialize fast cipher: %v", err)
			}
			log.Println("🔒 AES-256-GCM End-to-End Encryption ENABLED")
		} else {
			log.Fatalf("❌ FATAL: Endpoint mode requires a -datakey or P2P_VPN_DATAKEY env variable for security.")
		}

		if *tunIPFlag == "" {
			log.Fatalf("❌ FATAL: Endpoint mode requires -tun-ip or P2P_VPN_TUN_IP (e.g. 10.200.0.1/24) for Shared Subnet setup.")
		}
	}

	// 2. Load Node Identity Private Key
	privKey, err := getIdentity(identityPath)
	if err != nil {
		log.Fatalf("❌ FATAL: Failed to manage identity key: %v", err)
	}

	// 3. Setup TUN Interface (if Endpoint)
	var tunIfce TunInterface
	if *modeFlag == "endpoint" {
		if *dryRunFlag {
			log.Println("📦 Dry-run mode enabled. Simulating TUN interface...")
			tunIfce = NewMockTun("mock-tun0")
		} else {
			var err error
			tunIfce, err = NewRealTun()
			if err != nil {
				log.Fatalf("❌ FATAL: Failed to create TUN interface: %v.\n👉 Make sure to run as root (sudo) or run with -dry-run for testing.", err)
			}
		}
		defer tunIfce.Close()

		// Configure TUN device IP
		if err := tunIfce.Configure(*tunIPFlag); err != nil {
			log.Fatalf("❌ FATAL: Failed to configure TUN interface: %v", err)
		}
		log.Printf("✅ TUN Interface %s configured with IP/CIDR %s", tunIfce.Name(), *tunIPFlag)
	}

	// 4. Setup Routing Table & Parse Subnets
	routingTable := NewRoutingTable()
	var advertisedSubnets []string
	if *advertiseFlag != "" {
		for _, s := range strings.Split(*advertiseFlag, ",") {
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				advertisedSubnets = append(advertisedSubnets, trimmed)
			}
		}
	}

	// 5. Setup Libp2p Host
	var relayAddrs []string
	if *relayAddrsFlag != "" {
		relayAddrs = strings.Split(*relayAddrsFlag, ",")
	}

	h, dhtObj, err := makeHost(ctx, *secretKeyPathFlag, *modeFlag, privKey, relayAddrs, finalPort, *clusterIDFlag)
	if err != nil {
		log.Fatalf("❌ FATAL: Failed to initialize libp2p host: %v", err)
	}
	defer h.Close()

	log.Printf("---------------------------------------------")
	log.Printf("P2P VPN Node Started. Mode: %s", strings.ToUpper(*modeFlag))
	log.Printf("Peer ID: %s", h.ID())
	log.Printf("Listen Port: %d", finalPort)
	log.Printf("Cluster ID: %s", *clusterIDFlag)
	log.Printf("---------------------------------------------")

	// 6. Connect to Bootstrap Relays
	if *modeFlag == "endpoint" {
		if len(relayAddrs) == 0 {
			log.Println("⚠️ WARNING: No bootstrap relays configured. Running in local discovery/direct dialing mode.")
		} else {
			for _, rAddr := range relayAddrs {
				trimmed := strings.TrimSpace(rAddr)
				if trimmed != "" {
					log.Printf("🔌 Connecting to bootstrap relay: %s", trimmed)
					connectToPeer(ctx, h, trimmed)
				}
			}
		}
	}

	// 7. Bootstrap DHT
	log.Println("🔄 Bootstrapping Kademlia DHT...")
	if err := dhtObj.Bootstrap(ctx); err != nil {
		log.Fatalf("❌ DHT Bootstrap failed: %v", err)
	}

	// 8. VPN Handshake and Stream Handlers
	if *modeFlag == "endpoint" {
		// Handshake Stream Handler: Receives peer subnets, configures local routing, and responds with local subnets
		h.SetStreamHandler(HandshakeProtocol, func(s network.Stream) {
			defer s.Close()
			remotePeer := s.Conn().RemotePeer()
			log.Printf("🤝 Incoming handshake stream from %s", remotePeer)

			var msg HandshakeMessage
			if err := json.NewDecoder(s).Decode(&msg); err != nil {
				log.Printf("⚠️ Failed to parse handshake message from %s: %v", remotePeer, err)
				return
			}

			log.Printf("📝 Handshake: Peer %s reports Virtual IP: %s, Subnets: %v", remotePeer, msg.VirtualIP, msg.Subnets)

			newSubnets, oldSubnets := routingTable.RegisterPeer(remotePeer, msg.VirtualIP, msg.Subnets)

			// Clean up obsolete routes
			newSet := make(map[string]bool)
			for _, s := range newSubnets {
				newSet[s] = true
			}
			for _, s := range oldSubnets {
				if !newSet[s] {
					log.Printf("🗑️ Removing obsolete route for peer %s: %s", remotePeer, s)
					tunIfce.DeleteRoute(s)
				}
			}

			// Add new routes
			for _, s := range newSubnets {
				log.Printf("➕ Adding route for peer %s: %s", remotePeer, s)
				if err := tunIfce.AddRoute(s); err != nil {
					log.Printf("⚠️ Failed to configure route %s: %v", s, err)
				}
			}

			// Respond back with our own routing information over the same stream
			resp := HandshakeMessage{
				VirtualIP: *tunIPFlag,
				Subnets:   advertisedSubnets,
			}
			encoder := json.NewEncoder(s)
			if err := encoder.Encode(&resp); err != nil {
				log.Printf("⚠️ Failed to encode response handshake to %s: %v", remotePeer, err)
				return
			}
			log.Printf("✅ Bidirectional handshake response successfully sent to %s", remotePeer)
		})

		// Tunnel Data Stream Handler: Decrypts frames and writes packets to TUN
		h.SetStreamHandler(TunnelProtocol, func(s network.Stream) {
			remotePeer := s.Conn().RemotePeer()
			log.Printf("📥 Incoming tunnel data stream established from %s", remotePeer)

			// Cache this inbound stream in our routing table to write to it!
			routingTable.SetStream(remotePeer, s)

			defer s.Close()
			defer routingTable.ClearStreamIfMatches(remotePeer, s)

			for {
				packet, err := readFrame(s, dataKey)
				if err != nil {
					if err != io.EOF {
						log.Printf("⚠️ Stream read error from %s: %v", remotePeer, err)
					}
					break
				}
				if _, err := tunIfce.Write(packet); err != nil {
					log.Printf("⚠️ Failed to inject packet to TUN interface: %v", err)
				}
			}
			log.Printf("❌ Incoming tunnel data stream closed from %s", remotePeer)
		})

		// Network notification callbacks to handle connection lifecycle
		h.Network().Notify(&network.NotifyBundle{
			ConnectedF: func(n network.Network, conn network.Conn) {
				remotePeer := conn.RemotePeer()
				log.Printf("🔌 Connected to peer: %s", remotePeer)
				if routingTable.HasPeer(remotePeer) {
					log.Printf("🤝 Peer %s already registered in routing table. Skipping handshake push.", remotePeer)
					return
				}
				// Initiate routing info handshake
				go pushHandshake(ctx, h, remotePeer, *tunIPFlag, advertisedSubnets, routingTable, tunIfce)
			},
			DisconnectedF: func(n network.Network, conn network.Conn) {
				remotePeer := conn.RemotePeer()
				log.Printf("❌ Disconnected from peer: %s", remotePeer)
				virtualIP, subnets := routingTable.UnregisterPeer(remotePeer)
				if virtualIP != "" {
					log.Printf("🧹 Cleaning up routes for disconnected peer %s", remotePeer)
					for _, s := range subnets {
						tunIfce.DeleteRoute(s)
					}
				}
			},
		})
	}

	// 9. Discovery Loop
	routingDiscovery := routing.NewRoutingDiscovery(dhtObj)
	if *modeFlag == "endpoint" {
		go func() {
			for {
				log.Println("📢 Advertising presence in DHT...")
				_, err := routingDiscovery.Advertise(ctx, *clusterIDFlag)
				if err != nil {
					log.Printf("⚠️ Advertisement error: %v", err)
				} else {
					log.Println("📢 Successfully advertised presence in DHT")
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
				}
			}
		}()
	}

	if *modeFlag == "relay" {
		log.Println("🟢 Relay Active. Waiting for peers...")
		go func() {
			for {
				log.Println("--- Relay Addresses (Share with endpoints) ---")
				for _, a := range h.Addrs() {
					log.Printf("   %s/p2p/%s", a, h.ID())
				}
				time.Sleep(5 * time.Minute)
			}
		}()
	} else {
		// Print current addresses (including relayed ones) periodically for diagnostics
		go func() {
			for {
				log.Println("--- Endpoint Current Addresses (Diagnostic) ---")
				for _, a := range h.Addrs() {
					log.Printf("   %s/p2p/%s", a, h.ID())
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
				}
			}
		}()

		// Endpoint peer discovery loop
		go func() {
			for {
				log.Println("🔎 Searching DHT for cluster peers...")
				peerChan, err := routingDiscovery.FindPeers(ctx, *clusterIDFlag)
				if err != nil {
					log.Printf("⚠️ Discovery error: %v", err)
					time.Sleep(10 * time.Second)
					continue
				}

				for p := range peerChan {
					if p.ID == h.ID() {
						continue
					}
					// Only connect if not already connected
					if h.Network().Connectedness(p.ID) != network.Connected {
						log.Printf("✨ Discovered cluster peer: %s. Dialing...", p.ID)
						if err := h.Connect(ctx, p); err != nil {
							log.Printf("⚠️ Connection failed to discovered peer %s: %v", p.ID, err)
						} else {
							log.Printf("✅ Successfully connected to discovered peer %s", p.ID)
						}
					}
				}
				time.Sleep(15 * time.Second)
			}
		}()

		// 10. Start TUN Reader Loop
		go func() {
			log.Println("🚀 TUN Reader Loop running...")
			buf := make([]byte, 2048)
			for {
				n, err := tunIfce.Read(buf)
				if err != nil {
					log.Printf("⚠️ Error reading from TUN interface: %v", err)
					time.Sleep(1 * time.Second)
					continue
				}

				packet := buf[:n]
				if len(packet) < 20 {
					continue
				}

				version := packet[0] >> 4
				if version != 4 {
					// Skipping non-IPv4 traffic
					continue
				}
				destIP := net.IP(packet[16:20])

				peerID, found := routingTable.LookupPeer(destIP)
				if !found {
					// Packet destination has no matching peer route, drop silently
					continue
				}

				// Copy packet bytes to avoid corruption from shared read buffer
				pktCopy := make([]byte, len(packet))
				copy(pktCopy, packet)

				// Push to peer worker queue
				q := routingTable.GetOrCreateQueue(peerID, ctx, h, dataKey, tunIfce)
				select {
				case q <- pktCopy:
				default:
					// Queue full, drop packet silently to handle congestion
				}
			}
		}()

		// 10b. Interactive console injection loop for mock testing
		if *dryRunFlag {
			go func() {
				scanner := bufio.NewScanner(os.Stdin)
				log.Println("💬 Interactive Chat Enabled: Type a message and press Enter to send a mock packet over the VPN!")
				for scanner.Scan() {
					text := scanner.Text()
					if text == "" {
						continue
					}

					routingTable.mu.RLock()
					if len(routingTable.peerInfo) == 0 {
						log.Println("⚠️ Cannot send packet: no remote peers discovered yet.")
						routingTable.mu.RUnlock()
						continue
					}

					var targetRoutes *PeerRoutes
					for _, routes := range routingTable.peerInfo {
						targetRoutes = routes
						break
					}
					routingTable.mu.RUnlock()

					localIP, _, _ := net.ParseCIDR(*tunIPFlag)
					remoteIP, _, _ := net.ParseCIDR(targetRoutes.VirtualIP)

					if localIP == nil || remoteIP == nil {
						log.Println("⚠️ Invalid local or remote IPs.")
						continue
					}

					pkt := makeMockUDPPacket(localIP, remoteIP, []byte(text))
					if mock, ok := tunIfce.(*MockTun); ok {
						log.Printf("🚀 Injecting mock UDP packet (src: %s, dev-tun, dst: %s, payload: %q)", localIP, remoteIP, text)
						mock.InjectPacket(pkt)
					}
				}
			}()
		}
	}

	// 11. Graceful Shutdown Handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("🧹 Shutting down... Cleaning up routes and interfaces")
	if *modeFlag == "endpoint" && tunIfce != nil {
		// Cleanup routing table routes
		_, _ = routingTable.UnregisterPeer("") // clean any local references if possible
		// Ensure we clean up routes manually or let OS clean when TUN closes
		log.Println("👋 Closing TUN interface...")
		tunIfce.Close()
	}
	log.Println("🛑 Shutdown complete.")
}

func makeMockUDPPacket(srcIP, destIP net.IP, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)

	// IP Header
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], destIP.To4())

	// UDP Header
	binary.BigEndian.PutUint16(pkt[20:22], 12345) // Src Port
	binary.BigEndian.PutUint16(pkt[22:24], 9999)  // Dest Port
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(pkt[26:28], 0)

	// Payload
	copy(pkt[28:], payload)

	return pkt
}
