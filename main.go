package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
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

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/multiformats/go-multiaddr"
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
	modeFlag := flag.String("mode", getEnv("P2P_VPN_MODE", "endpoint"), "Operational mode: 'relay', 'endpoint', 'ca-keygen', 'ca-sign', or 'ca-verify'")
	portFlag := flag.Int("port", 0, "Listening port (Default: 4001 for relay, 0/ephemeral for endpoint)")
	identityPathFlag := flag.String("identity", getEnv("P2P_VPN_IDENTITY", ""), "Path to identity file (Defaults: identity-<mode>.key)")
	clusterIDFlag := flag.String("cluster", getEnv("P2P_VPN_CLUSTER", "my-k8s-cluster"), "The cluster ID string for rendezvous")
	relayAddrsFlag := flag.String("relay", getEnv("P2P_VPN_RELAY", ""), "Comma-separated multiaddrs of bootstrap relays")
	dataKeyPathFlag := flag.String("datakey", getEnv("P2P_VPN_DATAKEY", ""), "Path to hex-encoded 32-byte AES data key file")
	tunIPFlag := flag.String("tun-ip", getEnv("P2P_VPN_TUN_IP", ""), "Virtual TUN interface IP/CIDR (e.g. 10.200.0.1/24)")
	advertiseFlag := flag.String("advertise", getEnv("P2P_VPN_ADVERTISE", ""), "Comma-separated subnets to advertise (e.g. 10.100.1.0/24)")
	dryRunFlag := flag.Bool("dry-run", getEnvBool("P2P_VPN_DRY_RUN", false), "Run with dry-run/mock TUN interface")
	allowedPeersFlag := flag.String("allowed-peers", getEnv("P2P_VPN_ALLOWED_PEERS", ""), "Path to file containing allowed Peer IDs (one per line) for Connection Gater")
	caKeyPathFlag := flag.String("ca-key", getEnv("P2P_VPN_CA_KEY", ""), "Path to the PEM-encoded CA public key file")
	nodeSigPathFlag := flag.String("node-sig", getEnv("P2P_VPN_NODE_SIG", ""), "Path to this node's PEM-encoded signature file")
	caKeyPrivPathFlag := flag.String("ca-key-priv", "", "Path to the CA's PEM-encoded private key file (for ca-sign mode)")
	peerIDFlag := flag.String("peer", "", "Target Peer ID to sign (for ca-sign mode)")
	sigPathFlag := flag.String("sig", "", "Path to the signature file to verify (for ca-verify mode)")
	printPeerIDFlag := flag.Bool("print-peer-id", false, "Print the Peer ID of the identity key and exit")
	guiFlag := flag.Bool("gui", false, "Start built-in web dashboard client interface")
	guiPortFlag := flag.Int("gui-port", 4040, "Listening port for the built-in web dashboard")
	flag.Parse()

	if *guiFlag {
		StartAPIServer(*guiPortFlag)
		return
	}

	if *printPeerIDFlag {
		identityPath := *identityPathFlag
		if identityPath == "" {
			identityPath = fmt.Sprintf("identity-%s.key", *modeFlag)
		}
		privKey, err := getIdentity(identityPath)
		if err != nil {
			log.Fatalf("❌ FATAL: Failed to manage identity key: %v", err)
		}
		pid, err := peer.IDFromPrivateKey(privKey)
		if err != nil {
			log.Fatalf("❌ FATAL: Failed to extract Peer ID: %v", err)
		}
		fmt.Println(pid.String())
		return
	}

	// --- Standalone PKI / CA Utility Modes ---
	if *modeFlag == "ca-keygen" {
		log.Println("🔑 Generating ML-DSA-87 CA key pair...")
		pk, sk, err := mldsa87.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("❌ FATAL: Failed to generate CA key: %v", err)
		}

		pkPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "ML-DSA-87 PUBLIC KEY",
			Bytes: pk.Bytes(),
		})
		skPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "ML-DSA-87 PRIVATE KEY",
			Bytes: sk.Bytes(),
		})

		if err := os.WriteFile("ca.pub", pkPEM, 0644); err != nil {
			log.Fatalf("❌ FATAL: Failed to write ca.pub: %v", err)
		}
		if err := os.WriteFile("ca.key", skPEM, 0600); err != nil {
			log.Fatalf("❌ FATAL: Failed to write ca.key: %v", err)
		}

		log.Println("✅ CA Keys successfully written to ca.pub and ca.key!")
		return
	}

	if *modeFlag == "ca-sign" {
		if *caKeyPrivPathFlag == "" {
			log.Fatalf("❌ FATAL: ca-sign mode requires the CA private key path (-ca-key-priv)")
		}
		if *peerIDFlag == "" {
			log.Fatalf("❌ FATAL: ca-sign mode requires the target Peer ID to sign (-peer)")
		}

		targetPeerID, err := peer.Decode(*peerIDFlag)
		if err != nil {
			log.Fatalf("❌ FATAL: Invalid target Peer ID: %v", err)
		}

		skPEM, err := os.ReadFile(*caKeyPrivPathFlag)
		if err != nil {
			log.Fatalf("❌ FATAL: Failed to read CA private key file: %v", err)
		}
		block, _ := pem.Decode(skPEM)
		var skBytes []byte
		if block == nil || block.Type != "ML-DSA-87 PRIVATE KEY" {
			str := strings.TrimSpace(string(skPEM))
			if hb, err := hex.DecodeString(str); err == nil {
				skBytes = hb
			} else {
				skBytes = skPEM
			}
		} else {
			skBytes = block.Bytes
		}

		sk := new(mldsa87.PrivateKey)
		if err := sk.UnmarshalBinary(skBytes); err != nil {
			log.Fatalf("❌ FATAL: Invalid CA private key format: %v", err)
		}

		msg := []byte(targetPeerID.String())
		ctxBytes := []byte("p2p-vpn-auth")
		sigBytes := make([]byte, mldsa87.SignatureSize)
		err = mldsa87.SignTo(sk, msg, ctxBytes, true, sigBytes)
		if err != nil {
			log.Fatalf("❌ FATAL: Failed to sign Peer ID: %v", err)
		}

		sigPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "ML-DSA-87 SIGNATURE",
			Bytes: sigBytes,
		})

		sigFileName := fmt.Sprintf("%s.sig", targetPeerID.String())
		if err := os.WriteFile(sigFileName, sigPEM, 0644); err == nil {
			log.Printf("✅ Signature successfully written to %s", sigFileName)
		}
		fmt.Println(string(sigPEM))
		return
	}

	if *modeFlag == "ca-verify" {
		if *caKeyPathFlag == "" {
			log.Fatalf("❌ FATAL: ca-verify mode requires the CA public key path (-ca-key)")
		}
		if *peerIDFlag == "" {
			log.Fatalf("❌ FATAL: ca-verify mode requires the target Peer ID (-peer)")
		}
		if *sigPathFlag == "" {
			log.Fatalf("❌ FATAL: ca-verify mode requires the signature file path (-sig)")
		}

		pkBytes, err := readPublicKeyBytes(*caKeyPathFlag)
		if err != nil {
			log.Fatalf("❌ FATAL: Failed to read/parse CA public key: %v", err)
		}
		pk := new(mldsa87.PublicKey)
		if err := pk.UnmarshalBinary(pkBytes); err != nil {
			log.Fatalf("❌ FATAL: Invalid CA public key format: %v", err)
		}

		sigPEM, err := os.ReadFile(*sigPathFlag)
		if err != nil {
			log.Fatalf("❌ FATAL: Failed to read signature file: %v", err)
		}
		sigBytes, err := decodeSignaturePEM(sigPEM)
		if err != nil {
			log.Fatalf("❌ FATAL: Failed to decode signature: %v", err)
		}

		targetPeerID, err := peer.Decode(*peerIDFlag)
		if err != nil {
			log.Fatalf("❌ FATAL: Invalid Peer ID: %v", err)
		}

		valid := mldsa87.Verify(pk, []byte(targetPeerID.String()), []byte("p2p-vpn-auth"), sigBytes)
		if valid {
			log.Println("✅ Success: Signature is VALID for this Peer ID!")
		} else {
			log.Println("❌ FAILED: Signature is INVALID for this Peer ID!")
			os.Exit(1)
		}
		return
	}

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

	// Load CA Public Key if configured
	if *caKeyPathFlag != "" {
		pkBytes, err := readPublicKeyBytes(*caKeyPathFlag)
		if err != nil {
			log.Fatalf("❌ FATAL: Failed to read CA public key from %q: %v", *caKeyPathFlag, err)
		}
		pubKey := new(mldsa87.PublicKey)
		if err := pubKey.UnmarshalBinary(pkBytes); err != nil {
			log.Fatalf("❌ FATAL: Invalid CA public key format: %v", err)
		}
		CAPubKey = pubKey
		log.Println("🛡️ PKI Authentication ENABLED using CA Public Key")
	}

	// Load Node Signature if configured
	if *nodeSigPathFlag != "" {
		sigPEM, err := os.ReadFile(*nodeSigPathFlag)
		if err != nil {
			log.Fatalf("❌ FATAL: Failed to read node signature file from %q: %v", *nodeSigPathFlag, err)
		}
		sigBytes, err := decodeSignaturePEM(sigPEM)
		if err != nil || len(sigBytes) == 0 {
			log.Fatalf("❌ FATAL: Failed to decode node signature: %v", err)
		}
		NodeSignature = sigBytes
		log.Println("🛡️ Node Signature loaded for CA verification")
	}

	if CAPubKey != nil && len(NodeSignature) == 0 {
		log.Println("⚠️ WARNING: CA public key is set, but no node signature (-node-sig) is configured. This node will be unable to authenticate to other CA-enforcing peers.")
	}

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

	// Parse allowed peers list if specified
	var allowedPeers []peer.ID
	if *allowedPeersFlag != "" {
		file, err := os.Open(*allowedPeersFlag)
		if err != nil {
			log.Fatalf("❌ FATAL: Failed to open allowed-peers file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			pid, err := peer.Decode(line)
			if err != nil {
				log.Fatalf("❌ FATAL: Invalid Peer ID in allowed-peers file %q: %v", line, err)
			}
			allowedPeers = append(allowedPeers, pid)
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("❌ FATAL: Error reading allowed-peers file: %v", err)
		}
		log.Printf("🔒 Loaded %d allowed Peer IDs from whitelist file", len(allowedPeers))

		// Automatically append relay Peer IDs so we can connect to them
		if *relayAddrsFlag != "" {
			for _, rAddr := range strings.Split(*relayAddrsFlag, ",") {
				trimmed := strings.TrimSpace(rAddr)
				if trimmed == "" {
					continue
				}
				ma, err := multiaddr.NewMultiaddr(trimmed)
				if err == nil {
					info, err := peer.AddrInfoFromP2pAddr(ma)
					if err == nil {
						// Add if not already present
						exists := false
						for _, existing := range allowedPeers {
							if existing == info.ID {
								exists = true
								break
							}
						}
						if !exists {
							allowedPeers = append(allowedPeers, info.ID)
							log.Printf("🔌 Auto-whitelisted Relay Peer ID: %s", info.ID)
						}
					}
				}
			}
		}
	}

	h, dhtObj, err := makeHost(ctx, *modeFlag, privKey, relayAddrs, finalPort, *clusterIDFlag, allowedPeers)
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

	// 8. VPN Handshake and Connection Handlers (Active on both Relay and Endpoint)
	h.SetStreamHandler(HandshakeProtocol, func(s network.Stream) {
		localVIP := ""
		var localSubs []string
		if *modeFlag == "endpoint" {
			localVIP = *tunIPFlag
			localSubs = advertisedSubnets
		}
		HandleIncomingHandshake(ctx, h, s, localVIP, localSubs, routingTable, tunIfce, CAPubKey, NodeSignature)
	})

	if *modeFlag == "endpoint" {
		// Tunnel Data Stream Handler: Decrypts frames and writes packets to TUN (Endpoint Only)
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
	}

	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, conn network.Conn) {
			remotePeer := conn.RemotePeer()
			log.Printf("🔌 Connected to peer: %s", remotePeer)
			if routingTable.HasPeer(remotePeer) {
				log.Printf("🤝 Peer %s already registered. Skipping handshake push.", remotePeer)
				return
			}
			// Start the CA authentication timeout kicker if PKI is enabled
			StartCAAuthKicker(ctx, h, routingTable, remotePeer, CAPubKey)

			// Initiate routing info handshake (outbound)
			localVIP := ""
			var localSubs []string
			if *modeFlag == "endpoint" {
				localVIP = *tunIPFlag
				localSubs = advertisedSubnets
			}
			go pushHandshake(ctx, h, remotePeer, localVIP, localSubs, routingTable, tunIfce, CAPubKey, NodeSignature)
		},
		DisconnectedF: func(n network.Network, conn network.Conn) {
			remotePeer := conn.RemotePeer()
			log.Printf("❌ Disconnected from peer: %s", remotePeer)
			virtualIP, subnets := routingTable.UnregisterPeer(remotePeer)
			if virtualIP != "" && tunIfce != nil {
				log.Printf("🧹 Cleaning up routes for disconnected peer %s", remotePeer)
				for _, s := range subnets {
					tunIfce.DeleteRoute(s)
				}
			}
		},
	})

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

func readPublicKeyBytes(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "ML-DSA-87 PUBLIC KEY" {
		// Fallback to raw hex
		str := strings.TrimSpace(string(data))
		if hb, err := hex.DecodeString(str); err == nil {
			return hb, nil
		}
		return data, nil
	}
	return block.Bytes, nil
}

