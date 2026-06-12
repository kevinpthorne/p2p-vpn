package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/multiformats/go-multiaddr"
)

type TestNode struct {
	id           peer.ID
	h            host.Host
	routingTable *RoutingTable
	tun          *MockTun
	ctx          context.Context
	cancel       context.CancelFunc
}

func TestMeshTopology(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clusterID := fmt.Sprintf("mesh-test-cluster-%d", time.Now().UnixNano())
	log.Printf("🧪 Running integration test with Cluster ID: %s", clusterID)

	// Ensure swarm.key exists
	swarmKeyPath := "swarm.key"
	if _, err := os.Stat(swarmKeyPath); os.IsNotExist(err) {
		t.Fatalf("swarm.key not found in working directory. Please make sure to run from the project root.")
	}

	// Load or generate a temporary data key for AES encryption
	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		t.Fatalf("failed to generate random data key: %v", err)
	}
	if err := InitCipher(dataKey); err != nil {
		t.Fatalf("failed to initialize cipher: %v", err)
	}

	// 1. Initialize 2 Relays
	log.Println("🟢 Launching 2 Relays...")
	relay1Priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		t.Fatalf("failed to generate relay1 key: %v", err)
	}
	relay2Priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		t.Fatalf("failed to generate relay2 key: %v", err)
	}

	r1Host, r1DHT, err := makeHost(ctx, swarmKeyPath, "relay", relay1Priv, nil, 4501, clusterID, nil)
	if err != nil {
		t.Fatalf("failed to start Relay 1: %v", err)
	}
	defer r1Host.Close()

	r2Host, r2DHT, err := makeHost(ctx, swarmKeyPath, "relay", relay2Priv, nil, 4502, clusterID, nil)
	if err != nil {
		t.Fatalf("failed to start Relay 2: %v", err)
	}
	defer r2Host.Close()

	if err := r1DHT.Bootstrap(ctx); err != nil {
		t.Fatalf("failed to bootstrap Relay 1 DHT: %v", err)
	}
	if err := r2DHT.Bootstrap(ctx); err != nil {
		t.Fatalf("failed to bootstrap Relay 2 DHT: %v", err)
	}

	// Get Relays multiaddrs
	r1Addr := fmt.Sprintf("%s/p2p/%s", r1Host.Addrs()[0], r1Host.ID())
	r2Addr := fmt.Sprintf("%s/p2p/%s", r2Host.Addrs()[0], r2Host.ID())
	relayAddrs := []string{r1Addr, r2Addr}

	log.Printf("📢 Relay 1 Address: %s", r1Addr)
	log.Printf("📢 Relay 2 Address: %s", r2Addr)

	// 2. Initialize 5 Endpoints
	log.Println("🟢 Launching 5 Endpoints...")
	endpoints := make([]*TestNode, 5)

	for i := 0; i < 5; i++ {
		epIdx := i + 1
		virtualIP := fmt.Sprintf("10.200.0.%d/24", epIdx)
		advertiseSubnet := fmt.Sprintf("10.100.%d.0/24", epIdx)

		epPriv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
		if err != nil {
			t.Fatalf("failed to generate key for EP %d: %v", epIdx, err)
		}

		// Port 0 lets OS allocate ephemeral port
		h, dhtObj, err := makeHost(ctx, swarmKeyPath, "endpoint", epPriv, relayAddrs, 0, clusterID, nil)
		if err != nil {
			t.Fatalf("failed to start EP %d host: %v", epIdx, err)
		}

		if err := dhtObj.Bootstrap(ctx); err != nil {
			t.Fatalf("failed to bootstrap EP %d DHT: %v", epIdx, err)
		}

		// Connect to both bootstrap relays explicitly
		connectToPeer(ctx, h, r1Addr)
		connectToPeer(ctx, h, r2Addr)

		rt := NewRoutingTable()
		mockTunName := fmt.Sprintf("mock-tun-%d", epIdx)
		tun := NewMockTun(mockTunName).(*MockTun)

		epCtx, epCancel := context.WithCancel(ctx)
		endpoints[i] = &TestNode{
			id:           h.ID(),
			h:            h,
			routingTable: rt,
			tun:          tun,
			ctx:          epCtx,
			cancel:       epCancel,
		}

		// Setup Handshake Handler
		h.SetStreamHandler(HandshakeProtocol, func(s network.Stream) {
			defer s.Close()
			remotePeer := s.Conn().RemotePeer()
			var msg HandshakeMessage
			if err := json.NewDecoder(s).Decode(&msg); err != nil {
				return
			}
			rt.RegisterPeer(remotePeer, msg.VirtualIP, msg.Subnets)
			resp := HandshakeMessage{
				VirtualIP: virtualIP,
				Subnets:   []string{advertiseSubnet},
			}
			json.NewEncoder(s).Encode(&resp)
		})

		// Setup Tunnel Protocol Handler
		h.SetStreamHandler(TunnelProtocol, func(s network.Stream) {
			remotePeer := s.Conn().RemotePeer()
			rt.SetStream(remotePeer, s)
			defer s.Close()
			defer rt.ClearStreamIfMatches(remotePeer, s)
			for {
				packet, err := readFrame(s, dataKey)
				if err != nil {
					break
				}
				if _, err := tun.Write(packet); err != nil {
					break
				}
			}
		})

		// Notify Bundle
		h.Network().Notify(&network.NotifyBundle{
			ConnectedF: func(n network.Network, conn network.Conn) {
				remotePeer := conn.RemotePeer()
				// Don't handshake with relays
				if remotePeer == r1Host.ID() || remotePeer == r2Host.ID() {
					return
				}
				if rt.HasPeer(remotePeer) {
					return
				}
				go pushHandshake(epCtx, h, remotePeer, virtualIP, []string{advertiseSubnet}, rt, tun)
			},
			DisconnectedF: func(n network.Network, conn network.Conn) {
				remotePeer := conn.RemotePeer()
				rt.UnregisterPeer(remotePeer)
			},
		})

		// Start Discovery loops
		routingDiscovery := routing.NewRoutingDiscovery(dhtObj)
		// 1. Advertiser
		go func(nodeHost host.Host) {
			for {
				routingDiscovery.Advertise(epCtx, clusterID)
				select {
				case <-epCtx.Done():
					return
				case <-time.After(5 * time.Second):
				}
			}
		}(h)

		// 2. Discoverer
		go func(nodeHost host.Host) {
			for {
				peerChan, err := routingDiscovery.FindPeers(epCtx, clusterID)
				if err == nil {
					for p := range peerChan {
						if p.ID == nodeHost.ID() || p.ID == r1Host.ID() || p.ID == r2Host.ID() {
							continue
						}
						if nodeHost.Network().Connectedness(p.ID) != network.Connected {
							nodeHost.Connect(epCtx, p)
						}
					}
				}
				select {
				case <-epCtx.Done():
					return
				case <-time.After(5 * time.Second):
				}
			}
		}(h)

		// 3. TUN Reader loop
		go func(nodeHost host.Host, rTable *RoutingTable, mockT *MockTun) {
			buf := make([]byte, 2048)
			for {
				n, err := mockT.Read(buf)
				if err != nil {
					return
				}
				packet := buf[:n]
				if len(packet) < 20 {
					continue
				}
				version := packet[0] >> 4
				if version != 4 {
					continue
				}
				destIP := net.IP(packet[16:20])
				peerID, found := rTable.LookupPeer(destIP)
				if !found {
					continue
				}
				pktCopy := make([]byte, len(packet))
				copy(pktCopy, packet)

				q := rTable.GetOrCreateQueue(peerID, epCtx, nodeHost, dataKey, mockT)
				select {
				case q <- pktCopy:
				default:
				}
			}
		}(h, rt, tun)

		defer h.Close()
		defer epCancel()
	}

	log.Println("🔄 Waiting for full mesh discovery (endpoints to find each other)...")
	
	// Wait until all endpoints have exactly 4 peers in their routing tables
	meshConnected := make(chan struct{})

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				allConnected := true
				log.Println("📊 Checking routing tables connectivity status:")
				for i, ep := range endpoints {
					ep.routingTable.mu.RLock()
					peerCount := len(ep.routingTable.peerInfo)
					ep.routingTable.mu.RUnlock()
					log.Printf("   - Endpoint %d (%s) has %d peer routes", i+1, ep.id.ShortString(), peerCount)
					if peerCount < 4 {
						allConnected = false
					}
				}
				if allConnected {
					close(meshConnected)
					return
				}
				time.Sleep(3 * time.Second)
			}
		}
	}()

	select {
	case <-meshConnected:
		log.Println("✅ Success! All 5 endpoints are fully connected to each other.")
	case <-ctx.Done():
		t.Fatalf("❌ Timeout: Endpoints failed to establish a full mesh network in time.")
	}

	// 3. Test Packet Transmission
	log.Println("🚀 Testing UDP packet routing between Endpoint 1 (10.200.0.1) and Endpoint 5 (10.200.0.5)...")
	
	// Set up verification hook on Endpoint 5's MockTun
	receivedChan := make(chan []byte, 10)
	endpoints[4].tun.OnWrite = func(pkt []byte) {
		receivedChan <- pkt
	}

	// We want to send a UDP packet from Endpoint 1 to Endpoint 5's virtual IP (10.200.0.5)
	srcIP := net.ParseIP("10.200.0.1")
	dstIP := net.ParseIP("10.200.0.5")
	payload := []byte("Hello from Endpoint 1 over 7-node Mesh!")
	pkt := makeMockUDPPacket(srcIP, dstIP, payload)

	// Inject the packet to Endpoint 1's mock TUN read channel
	log.Println("📥 Injecting UDP packet into Endpoint 1's mock TUN...")
	endpoints[0].tun.InjectPacket(pkt)

	// Wait and verify Endpoint 5 receives the packet
	select {
	case rxPkt := <-receivedChan:
		log.Println("🎉 Received packet on Endpoint 5's mock TUN!")
		if len(rxPkt) < 28 {
			t.Fatalf("received packet too small: %d bytes", len(rxPkt))
		}
		// Extract payload
		rxPayload := rxPkt[28:]
		log.Printf("   💬 Decrypted Payload: %s", string(rxPayload))
		if string(rxPayload) != string(payload) {
			t.Fatalf("expected payload %q, got %q", string(payload), string(rxPayload))
		}
		log.Println("✅ UDP routing verified successfully!")
	case <-time.After(10 * time.Second):
		t.Fatalf("❌ Timeout: Endpoint 5 failed to receive packet from Endpoint 1")
	}

	// 4. Test Subnet Packet Routing
	log.Println("🚀 Testing UDP subnet routing from Endpoint 5 (10.200.0.5) to Endpoint 1's advertised subnet IP (10.100.1.99)...")
	
	// Set up verification hook on Endpoint 1's MockTun
	receivedChanSubnet := make(chan []byte, 10)
	endpoints[0].tun.OnWrite = func(pkt []byte) {
		receivedChanSubnet <- pkt
	}

	// We want to send a UDP packet from Endpoint 5 to Endpoint 1's advertised subnet IP (10.100.1.99)
	srcIPSubnet := net.ParseIP("10.200.0.5")
	dstIPSubnet := net.ParseIP("10.100.1.99")
	payloadSubnet := []byte("Hello from Endpoint 5 to Endpoint 1 Subnet!")
	pktSubnet := makeMockUDPPacket(srcIPSubnet, dstIPSubnet, payloadSubnet)

	// Inject the packet to Endpoint 5's mock TUN read channel
	log.Println("📥 Injecting UDP packet into Endpoint 5's mock TUN...")
	endpoints[4].tun.InjectPacket(pktSubnet)

	// Wait and verify Endpoint 1 receives the packet
	select {
	case rxPkt := <-receivedChanSubnet:
		log.Println("🎉 Received packet on Endpoint 1's mock TUN!")
		if len(rxPkt) < 28 {
			t.Fatalf("received packet too small: %d bytes", len(rxPkt))
		}
		// Extract payload
		rxPayload := rxPkt[28:]
		log.Printf("   💬 Decrypted Payload: %s", string(rxPayload))
		if string(rxPayload) != string(payloadSubnet) {
			t.Fatalf("expected payload %q, got %q", string(payloadSubnet), string(rxPayload))
		}
		log.Println("✅ Subnet UDP routing verified successfully!")
	case <-time.After(10 * time.Second):
		t.Fatalf("❌ Timeout: Endpoint 1 failed to receive subnet packet from Endpoint 5")
	}
}

func TestMeshConnectionGater(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clusterID := fmt.Sprintf("gater-test-cluster-%d", time.Now().UnixNano())
	log.Printf("🧪 Running Connection Gater integration test with Cluster ID: %s", clusterID)

	swarmKeyPath := ""

	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		t.Fatalf("failed to generate random data key: %v", err)
	}
	if err := InitCipher(dataKey); err != nil {
		t.Fatalf("failed to initialize cipher: %v", err)
	}

	// 1. Generate keys for all 7 allowed nodes (2 relays + 5 endpoints)
	log.Println("🔑 Pre-generating keys and whitelisting Peer IDs...")
	relay1Priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	r1ID, _ := peer.IDFromPrivateKey(relay1Priv)
	relay2Priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	r2ID, _ := peer.IDFromPrivateKey(relay2Priv)

	epPrivs := make([]crypto.PrivKey, 5)
	epIDs := make([]peer.ID, 5)
	for i := 0; i < 5; i++ {
		epPriv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		epPrivs[i] = epPriv
		epIDs[i], _ = peer.IDFromPrivateKey(epPriv)
	}

	// Build the whitelist of allowed peers
	allowedPeers := []peer.ID{r1ID, r2ID}
	allowedPeers = append(allowedPeers, epIDs...)

	// 2. Launch 2 Relays using Connection Gater
	log.Println("🟢 Launching 2 Relays with Connection Gater...")
	r1Host, r1DHT, err := makeHost(ctx, swarmKeyPath, "relay", relay1Priv, nil, 4601, clusterID, allowedPeers)
	if err != nil {
		t.Fatalf("failed to start Relay 1: %v", err)
	}
	defer r1Host.Close()

	r2Host, r2DHT, err := makeHost(ctx, swarmKeyPath, "relay", relay2Priv, nil, 4602, clusterID, allowedPeers)
	if err != nil {
		t.Fatalf("failed to start Relay 2: %v", err)
	}
	defer r2Host.Close()

	if err := r1DHT.Bootstrap(ctx); err != nil {
		t.Fatalf("failed to bootstrap Relay 1: %v", err)
	}
	if err := r2DHT.Bootstrap(ctx); err != nil {
		t.Fatalf("failed to bootstrap Relay 2: %v", err)
	}

	r1Addr := fmt.Sprintf("%s/p2p/%s", r1Host.Addrs()[0], r1Host.ID())
	r2Addr := fmt.Sprintf("%s/p2p/%s", r2Host.Addrs()[0], r2Host.ID())
	relayAddrs := []string{r1Addr, r2Addr}

	// 3. Launch 5 Endpoints using Connection Gater
	log.Println("🟢 Launching 5 Endpoints with Connection Gater...")
	endpoints := make([]*TestNode, 5)

	for i := 0; i < 5; i++ {
		epIdx := i + 1
		virtualIP := fmt.Sprintf("10.200.0.%d/24", epIdx)
		advertiseSubnet := fmt.Sprintf("10.100.%d.0/24", epIdx)

		// Create host with Connection Gater
		h, dhtObj, err := makeHost(ctx, swarmKeyPath, "endpoint", epPrivs[i], relayAddrs, 0, clusterID, allowedPeers)
		if err != nil {
			t.Fatalf("failed to start EP %d: %v", epIdx, err)
		}

		if err := dhtObj.Bootstrap(ctx); err != nil {
			t.Fatalf("failed to bootstrap EP %d: %v", epIdx, err)
		}

		connectToPeer(ctx, h, r1Addr)
		connectToPeer(ctx, h, r2Addr)

		rt := NewRoutingTable()
		mockTunName := fmt.Sprintf("gater-mock-tun-%d", epIdx)
		tun := NewMockTun(mockTunName).(*MockTun)

		epCtx, epCancel := context.WithCancel(ctx)
		endpoints[i] = &TestNode{
			id:           h.ID(),
			h:            h,
			routingTable: rt,
			tun:          tun,
			ctx:          epCtx,
			cancel:       epCancel,
		}

		// Setup Handshake Handler
		h.SetStreamHandler(HandshakeProtocol, func(s network.Stream) {
			defer s.Close()
			remotePeer := s.Conn().RemotePeer()
			var msg HandshakeMessage
			if err := json.NewDecoder(s).Decode(&msg); err != nil {
				return
			}
			rt.RegisterPeer(remotePeer, msg.VirtualIP, msg.Subnets)
			resp := HandshakeMessage{
				VirtualIP: virtualIP,
				Subnets:   []string{advertiseSubnet},
			}
			json.NewEncoder(s).Encode(&resp)
		})

		// Setup Tunnel Handler
		h.SetStreamHandler(TunnelProtocol, func(s network.Stream) {
			remotePeer := s.Conn().RemotePeer()
			rt.SetStream(remotePeer, s)
			defer s.Close()
			defer rt.ClearStreamIfMatches(remotePeer, s)
			for {
				packet, err := readFrame(s, dataKey)
				if err != nil {
					break
				}
				if _, err := tun.Write(packet); err != nil {
					break
				}
			}
		})

		// Notify Bundle
		h.Network().Notify(&network.NotifyBundle{
			ConnectedF: func(n network.Network, conn network.Conn) {
				remotePeer := conn.RemotePeer()
				if remotePeer == r1Host.ID() || remotePeer == r2Host.ID() {
					return
				}
				if rt.HasPeer(remotePeer) {
					return
				}
				go pushHandshake(epCtx, h, remotePeer, virtualIP, []string{advertiseSubnet}, rt, tun)
			},
			DisconnectedF: func(n network.Network, conn network.Conn) {
				remotePeer := conn.RemotePeer()
				rt.UnregisterPeer(remotePeer)
			},
		})

		// Start Discovery loops
		routingDiscovery := routing.NewRoutingDiscovery(dhtObj)
		go func(nodeHost host.Host) {
			for {
				routingDiscovery.Advertise(epCtx, clusterID)
				select {
				case <-epCtx.Done():
					return
				case <-time.After(1 * time.Second):
				}
			}
		}(h)

		go func(nodeHost host.Host) {
			for {
				peerChan, err := routingDiscovery.FindPeers(epCtx, clusterID)
				if err == nil {
					for p := range peerChan {
						if p.ID == nodeHost.ID() || p.ID == r1Host.ID() || p.ID == r2Host.ID() {
							continue
						}
						if nodeHost.Network().Connectedness(p.ID) != network.Connected {
							nodeHost.Connect(epCtx, p)
						}
					}
				}
				select {
				case <-epCtx.Done():
					return
				case <-time.After(1 * time.Second):
				}
			}
		}(h)

		// TUN Reader loop
		go func(nodeHost host.Host, rTable *RoutingTable, mockT *MockTun) {
			buf := make([]byte, 2048)
			for {
				n, err := mockT.Read(buf)
				if err != nil {
					return
				}
				packet := buf[:n]
				if len(packet) < 20 {
					continue
				}
				version := packet[0] >> 4
				if version != 4 {
					continue
				}
				destIP := net.IP(packet[16:20])
				peerID, found := rTable.LookupPeer(destIP)
				if !found {
					continue
				}
				pktCopy := make([]byte, len(packet))
				copy(pktCopy, packet)

				q := rTable.GetOrCreateQueue(peerID, epCtx, nodeHost, dataKey, mockT)
				select {
				case q <- pktCopy:
				default:
				}
			}
		}(h, rt, tun)

		defer h.Close()
		defer epCancel()
	}

	log.Println("🔄 Waiting for full mesh connection-gater discovery...")
	meshConnected := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				allConnected := true
				for _, ep := range endpoints {
					ep.routingTable.mu.RLock()
					peerCount := len(ep.routingTable.peerInfo)
					ep.routingTable.mu.RUnlock()
					if peerCount < 4 {
						allConnected = false
					}
				}
				if allConnected {
					close(meshConnected)
					return
				}
				time.Sleep(1 * time.Second)
			}
		}
	}()

	select {
	case <-meshConnected:
		log.Println("✅ Success! Whitelisted endpoints are fully connected over QUIC/UDP.")
	case <-ctx.Done():
		t.Fatalf("❌ Timeout: Whitelisted endpoints failed to connect.")
	}

	// 4. Test UDP routing
	receivedChan := make(chan []byte, 10)
	endpoints[4].tun.OnWrite = func(pkt []byte) {
		receivedChan <- pkt
	}

	srcIP := net.ParseIP("10.200.0.1")
	dstIP := net.ParseIP("10.200.0.5")
	payload := []byte("Hello via QUIC and Connection Gater!")
	pkt := makeMockUDPPacket(srcIP, dstIP, payload)

	endpoints[0].tun.InjectPacket(pkt)

	select {
	case rxPkt := <-receivedChan:
		rxPayload := rxPkt[28:]
		if string(rxPayload) != string(payload) {
			t.Fatalf("expected payload %q, got %q", string(payload), string(rxPayload))
		}
		log.Println("✅ UDP packet routed successfully over Connection Gater mesh!")
	case <-time.After(10 * time.Second):
		t.Fatalf("❌ Timeout: Failed to route packet over Connection Gater mesh")
	}

	// 5. Test Unauthorized Endpoint (Endpoint 6)
	log.Println("🛡️ Testing unauthorized Endpoint 6 connection blockage...")
	ep6Priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		t.Fatalf("failed to generate ep6 key: %v", err)
	}

	// Ep6 is NOT in the whitelist (allowedPeers).
	h6, dht6, err := makeHost(ctx, swarmKeyPath, "endpoint", ep6Priv, relayAddrs, 0, clusterID, allowedPeers)
	if err != nil {
		t.Fatalf("failed to start unauthorized EP 6 host: %v", err)
	}
	defer h6.Close()
	_ = dht6

	// Attempt to dial Relay 1 explicitly.
	log.Println("🔌 Dialing Relay 1 from unauthorized Endpoint 6...")
	r1Info, _ := peer.AddrInfoFromP2pAddr(r1Host.Addrs()[0].Encapsulate(multiaddr.StringCast("/p2p/" + r1Host.ID().String())))
	err = h6.Connect(ctx, *r1Info)
	log.Printf("🔌 Dialed Relay 1. err=%v, immediate connectedness=%v", err, h6.Network().Connectedness(r1Host.ID()))
	time.Sleep(200 * time.Millisecond) // wait for responder gater to tear down connection
	log.Printf("🔌 After 200ms sleep: connectedness=%v", h6.Network().Connectedness(r1Host.ID()))
	if err == nil && h6.Network().Connectedness(r1Host.ID()) == network.Connected {
		t.Fatalf("❌ Security Violation: Unauthorized Endpoint 6 successfully connected to Relay 1!")
	}
	log.Printf("✅ Success: Connection to Relay 1 was rejected/closed as expected. Error: %v", err)

	// Attempt to dial Endpoint 1 directly.
	log.Println("🔌 Dialing Endpoint 1 from unauthorized Endpoint 6...")
	ep1Info := peer.AddrInfo{
		ID:    endpoints[0].id,
		Addrs: endpoints[0].h.Addrs(),
	}
	err = h6.Connect(ctx, ep1Info)
	log.Printf("🔌 Dialed Endpoint 1. err=%v, immediate connectedness=%v", err, h6.Network().Connectedness(endpoints[0].id))
	time.Sleep(200 * time.Millisecond) // wait for responder gater to tear down connection
	log.Printf("🔌 After 200ms sleep: connectedness=%v", h6.Network().Connectedness(endpoints[0].id))
	if err == nil && h6.Network().Connectedness(endpoints[0].id) == network.Connected {
		t.Fatalf("❌ Security Violation: Unauthorized Endpoint 6 successfully connected to Endpoint 1!")
	}
	log.Printf("✅ Success: Connection to Endpoint 1 was rejected/closed as expected. Error: %v", err)
}

func TestMeshCombinedMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clusterID := fmt.Sprintf("combined-test-cluster-%d", time.Now().UnixNano())
	log.Printf("🧪 Running Combined Mode (pnet + conngater) integration test with Cluster ID: %s", clusterID)

	swarmKeyPath := "swarm.key"

	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatalf("failed to generate random data key: %v", err)
	}
	if err := InitCipher(dataKey); err != nil {
		t.Fatalf("failed to initialize cipher: %v", err)
	}

	// 1. Generate keys and whitelist Peer IDs (including relays + 5 endpoints + endpoint 7)
	log.Println("🔑 Pre-generating keys and whitelisting Peer IDs...")
	relay1Priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	r1ID, _ := peer.IDFromPrivateKey(relay1Priv)
	relay2Priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	r2ID, _ := peer.IDFromPrivateKey(relay2Priv)

	epPrivs := make([]crypto.PrivKey, 5)
	epIDs := make([]peer.ID, 5)
	for i := 0; i < 5; i++ {
		epPriv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		epPrivs[i] = epPriv
		epIDs[i], _ = peer.IDFromPrivateKey(epPriv)
	}

	ep7Priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		t.Fatalf("failed to generate ep7 key: %v", err)
	}
	ep7ID, _ := peer.IDFromPrivateKey(ep7Priv)

	// Whitelist includes relays, EP 1..5, and EP 7
	allowedPeers := []peer.ID{r1ID, r2ID, ep7ID}
	allowedPeers = append(allowedPeers, epIDs...)

	// 2. Launch 2 Relays in Combined Mode (swarm.key + whitelist)
	log.Println("🟢 Launching 2 Relays in Combined Mode...")
	r1Host, r1DHT, err := makeHost(ctx, swarmKeyPath, "relay", relay1Priv, nil, 4701, clusterID, allowedPeers)
	if err != nil {
		t.Fatalf("failed to start Relay 1: %v", err)
	}
	defer r1Host.Close()

	r2Host, r2DHT, err := makeHost(ctx, swarmKeyPath, "relay", relay2Priv, nil, 4702, clusterID, allowedPeers)
	if err != nil {
		t.Fatalf("failed to start Relay 2: %v", err)
	}
	defer r2Host.Close()

	if err := r1DHT.Bootstrap(ctx); err != nil {
		t.Fatalf("failed to bootstrap Relay 1: %v", err)
	}
	if err := r2DHT.Bootstrap(ctx); err != nil {
		t.Fatalf("failed to bootstrap Relay 2: %v", err)
	}

	r1Addr := fmt.Sprintf("%s/p2p/%s", r1Host.Addrs()[0], r1Host.ID())
	r2Addr := fmt.Sprintf("%s/p2p/%s", r2Host.Addrs()[0], r2Host.ID())
	relayAddrs := []string{r1Addr, r2Addr}

	// 3. Launch 5 Endpoints in Combined Mode
	log.Println("🟢 Launching 5 Endpoints in Combined Mode...")
	endpoints := make([]*TestNode, 5)

	for i := 0; i < 5; i++ {
		epIdx := i + 1
		virtualIP := fmt.Sprintf("10.200.0.%d/24", epIdx)
		advertiseSubnet := fmt.Sprintf("10.100.%d.0/24", epIdx)

		h, dhtObj, err := makeHost(ctx, swarmKeyPath, "endpoint", epPrivs[i], relayAddrs, 0, clusterID, allowedPeers)
		if err != nil {
			t.Fatalf("failed to start EP %d: %v", epIdx, err)
		}

		if err := dhtObj.Bootstrap(ctx); err != nil {
			t.Fatalf("failed to bootstrap EP %d: %v", epIdx, err)
		}

		connectToPeer(ctx, h, r1Addr)
		connectToPeer(ctx, h, r2Addr)

		rt := NewRoutingTable()
		mockTunName := fmt.Sprintf("combined-mock-tun-%d", epIdx)
		tun := NewMockTun(mockTunName).(*MockTun)

		epCtx, epCancel := context.WithCancel(ctx)
		endpoints[i] = &TestNode{
			id:           h.ID(),
			h:            h,
			routingTable: rt,
			tun:          tun,
			ctx:          epCtx,
			cancel:       epCancel,
		}

		// Setup Handshake Handler
		h.SetStreamHandler(HandshakeProtocol, func(s network.Stream) {
			defer s.Close()
			remotePeer := s.Conn().RemotePeer()
			var msg HandshakeMessage
			if err := json.NewDecoder(s).Decode(&msg); err != nil {
				return
			}
			rt.RegisterPeer(remotePeer, msg.VirtualIP, msg.Subnets)
			resp := HandshakeMessage{
				VirtualIP: virtualIP,
				Subnets:   []string{advertiseSubnet},
			}
			json.NewEncoder(s).Encode(&resp)
		})

		// Setup Tunnel Handler
		h.SetStreamHandler(TunnelProtocol, func(s network.Stream) {
			remotePeer := s.Conn().RemotePeer()
			rt.SetStream(remotePeer, s)
			defer s.Close()
			defer rt.ClearStreamIfMatches(remotePeer, s)
			for {
				packet, err := readFrame(s, dataKey)
				if err != nil {
					break
				}
				if _, err := tun.Write(packet); err != nil {
					break
				}
			}
		})

		// Notify Bundle
		h.Network().Notify(&network.NotifyBundle{
			ConnectedF: func(n network.Network, conn network.Conn) {
				remotePeer := conn.RemotePeer()
				if remotePeer == r1Host.ID() || remotePeer == r2Host.ID() {
					return
				}
				if rt.HasPeer(remotePeer) {
					return
				}
				go pushHandshake(epCtx, h, remotePeer, virtualIP, []string{advertiseSubnet}, rt, tun)
			},
			DisconnectedF: func(n network.Network, conn network.Conn) {
				remotePeer := conn.RemotePeer()
				rt.UnregisterPeer(remotePeer)
			},
		})

		// Start Discovery loops
		routingDiscovery := routing.NewRoutingDiscovery(dhtObj)
		go func(nodeHost host.Host) {
			for {
				routingDiscovery.Advertise(epCtx, clusterID)
				select {
				case <-epCtx.Done():
					return
				case <-time.After(1 * time.Second):
				}
			}
		}(h)

		go func(nodeHost host.Host) {
			for {
				peerChan, err := routingDiscovery.FindPeers(epCtx, clusterID)
				if err == nil {
					for p := range peerChan {
						if p.ID == nodeHost.ID() || p.ID == r1Host.ID() || p.ID == r2Host.ID() {
							continue
						}
						if nodeHost.Network().Connectedness(p.ID) != network.Connected {
							nodeHost.Connect(epCtx, p)
						}
					}
				}
				select {
				case <-epCtx.Done():
					return
				case <-time.After(1 * time.Second):
				}
			}
		}(h)

		// TUN Reader loop
		go func(nodeHost host.Host, rTable *RoutingTable, mockT *MockTun) {
			buf := make([]byte, 2048)
			for {
				n, err := mockT.Read(buf)
				if err != nil {
					return
				}
				packet := buf[:n]
				if len(packet) < 20 {
					continue
				}
				version := packet[0] >> 4
				if version != 4 {
					continue
				}
				destIP := net.IP(packet[16:20])
				peerID, found := rTable.LookupPeer(destIP)
				if !found {
					continue
				}
				pktCopy := make([]byte, len(packet))
				copy(pktCopy, packet)

				q := rTable.GetOrCreateQueue(peerID, epCtx, nodeHost, dataKey, mockT)
				select {
				case q <- pktCopy:
				default:
				}
			}
		}(h, rt, tun)

		defer h.Close()
		defer epCancel()
	}

	log.Println("🔄 Waiting for full mesh combined-mode discovery...")
	meshConnected := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				allConnected := true
				for _, ep := range endpoints {
					ep.routingTable.mu.RLock()
					peerCount := len(ep.routingTable.peerInfo)
					ep.routingTable.mu.RUnlock()
					if peerCount < 4 {
						allConnected = false
					}
				}
				if allConnected {
					close(meshConnected)
					return
				}
				time.Sleep(1 * time.Second)
			}
		}
	}()

	select {
	case <-meshConnected:
		log.Println("✅ Success! Combined-mode endpoints are fully connected (TCP-only mode).")
	case <-ctx.Done():
		t.Fatalf("❌ Timeout: Combined-mode endpoints failed to connect.")
	}

	// 4. Test UDP routing
	receivedChan := make(chan []byte, 10)
	endpoints[4].tun.OnWrite = func(pkt []byte) {
		receivedChan <- pkt
	}

	srcIP := net.ParseIP("10.200.0.1")
	dstIP := net.ParseIP("10.200.0.5")
	payload := []byte("Hello via Combined Security Mode (TCP protected)!")
	pkt := makeMockUDPPacket(srcIP, dstIP, payload)

	endpoints[0].tun.InjectPacket(pkt)

	select {
	case rxPkt := <-receivedChan:
		rxPayload := rxPkt[28:]
		if string(rxPayload) != string(payload) {
			t.Fatalf("expected payload %q, got %q", string(payload), string(rxPayload))
		}
		log.Println("✅ UDP packet routed successfully over combined mesh!")
	case <-time.After(10 * time.Second):
		t.Fatalf("❌ Timeout: Failed to route packet over combined mesh")
	}

	// 5. Test Endpoint 6 (Has correct swarm.key, but NOT whitelisted in Connection Gater)
	log.Println("🛡️ Testing Endpoint 6 connection blockage (Gater blockage)...")
	ep6Priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		t.Fatalf("failed to generate ep6 key: %v", err)
	}

	// EP 6 is NOT whitelisted.
	h6, dht6, err := makeHost(ctx, swarmKeyPath, "endpoint", ep6Priv, relayAddrs, 0, clusterID, allowedPeers)
	if err != nil {
		t.Fatalf("failed to start EP 6: %v", err)
	}
	defer h6.Close()
	_ = dht6

	log.Println("🔌 Dialing Relay 1 from EP 6 (should be blocked by Relay 1's Gater)...")
	r1Info, _ := peer.AddrInfoFromP2pAddr(r1Host.Addrs()[0].Encapsulate(multiaddr.StringCast("/p2p/" + r1Host.ID().String())))
	err = h6.Connect(ctx, *r1Info)
	log.Printf("🔌 Dialed Relay 1 from EP 6. err=%v, immediate connectedness=%v", err, h6.Network().Connectedness(r1Host.ID()))
	time.Sleep(1 * time.Second) // wait for responder gater to tear down connection
	log.Printf("🔌 After 1s sleep: connectedness=%v", h6.Network().Connectedness(r1Host.ID()))
	if err == nil && h6.Network().Connectedness(r1Host.ID()) == network.Connected {
		t.Fatalf("❌ Security Violation: Unauthorized Endpoint 6 successfully connected to Relay 1!")
	}
	log.Printf("✅ Success: Connection to Relay 1 was rejected/closed as expected. Error: %v", err)

	// 6. Test Endpoint 7 (Whitelisted in Connection Gater, but has INCORRECT swarm.key)
	log.Println("🛡️ Testing Endpoint 7 connection blockage (pnet key mismatch)...")
	badSwarmKeyPath := "swarm_bad.key"
	err = os.WriteFile(badSwarmKeyPath, []byte("/key/swarm/psk/1.0.0/\n/base16/\nbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb\n"), 0600)
	if err != nil {
		t.Fatalf("failed to write bad swarm key: %v", err)
	}
	defer os.Remove(badSwarmKeyPath)

	// EP 7 is whitelisted, but uses `badSwarmKeyPath`.
	h7, dht7, err := makeHost(ctx, badSwarmKeyPath, "endpoint", ep7Priv, relayAddrs, 0, clusterID, allowedPeers)
	if err != nil {
		t.Fatalf("failed to start EP 7: %v", err)
	}
	defer h7.Close()
	_ = dht7

	log.Println("🔌 Dialing Relay 1 from EP 7 (should be blocked by pnet key handshake)...")
	err = h7.Connect(ctx, *r1Info)
	log.Printf("🔌 Dialed Relay 1 from EP 7. err=%v, immediate connectedness=%v", err, h7.Network().Connectedness(r1Host.ID()))
	time.Sleep(1 * time.Second) // wait for pnet handshake failure to close connection
	log.Printf("🔌 After 1s sleep: connectedness=%v", h7.Network().Connectedness(r1Host.ID()))
	if err == nil && h7.Network().Connectedness(r1Host.ID()) == network.Connected {
		t.Fatalf("❌ Security Violation: Endpoint 7 successfully connected with bad swarm.key!")
	}
	log.Printf("✅ Success: Connection to Relay 1 was rejected by pnet as expected. Error: %v", err)
}

