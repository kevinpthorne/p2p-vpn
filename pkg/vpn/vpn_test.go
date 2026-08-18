package vpn

import (
	"context"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	dht "github.com/libp2p/go-libp2p-kad-dht"
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
	dht          *dht.IpfsDHT
}

func setupTestNode(
	ctx context.Context,
	t *testing.T,
	mode string,
	privKey crypto.PrivKey,
	relayAddrs []string,
	port int,
	clusterID string,
	allowedPeers []peer.ID,
	caPub *mldsa87.PublicKey,
	nodeSig []byte,
	virtualIP string,
	advertiseSubnets []string,
) *TestNode {
	h, dhtObj, err := MakeHost(ctx, mode, privKey, relayAddrs, port, clusterID, allowedPeers, 1024, 1024, 1024, 15, 5, 4)
	if err != nil {
		t.Fatalf("failed to start %s host: %v", mode, err)
	}

	if err := dhtObj.Bootstrap(ctx); err != nil {
		t.Fatalf("failed to bootstrap %s DHT: %v", mode, err)
	}

	rt := NewRoutingTable()
	var tunIfce TunInterface
	var mockTun *MockTun
	if mode == "endpoint" {
		mockTun = NewMockTun("test-tun-" + h.ID().String()).(*MockTun)
		tunIfce = mockTun
	}

	nodeCtx, nodeCancel := context.WithCancel(ctx)

	// Set symmetric Handshake Handler
	h.SetStreamHandler(HandshakeProtocol, func(s network.Stream) {
		HandleIncomingHandshake(nodeCtx, h, s, mode, virtualIP, advertiseSubnets, rt, tunIfce, caPub, nodeSig, false)
	})

	if mode == "endpoint" {
		// Tunnel Data Stream Handler
		h.SetStreamHandler(TunnelProtocol, func(s network.Stream) {
			remotePeer := s.Conn().RemotePeer()
			rt.SetStream(remotePeer, s)
			defer s.Close()
			defer rt.ClearStreamIfMatches(remotePeer, s)
			for {
				packet, err := ReadFrame(s, nil)
				if err != nil {
					break
				}
				if _, err := mockTun.Write(packet); err != nil {
					break
				}
			}
		})
	}

	// Set connection Notify
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, conn network.Conn) {
			remotePeer := conn.RemotePeer()
			if rt.HasPeer(remotePeer) {
				return
			}
			StartCAAuthKicker(nodeCtx, h, rt, remotePeer, caPub)

			// Relays don't advertise virtual IP or subnets
			localVIP := ""
			var localSubs []string
			if mode == "endpoint" {
				localVIP = virtualIP
				localSubs = advertiseSubnets
			}
			
			for _, rAddr := range relayAddrs {
				if p2pAddr, err := multiaddr.NewMultiaddr(rAddr); err == nil {
					if info, err := peer.AddrInfoFromP2pAddr(p2pAddr); err == nil {
						if info.ID == remotePeer {
							
							break
						}
					}
				}
			}
			go PushHandshake(nodeCtx, h, remotePeer, mode, localVIP, localSubs, rt, tunIfce, caPub, nodeSig, false)
		},
		DisconnectedF: func(n network.Network, conn network.Conn) {
			remotePeer := conn.RemotePeer()
			rt.UnregisterPeer(remotePeer)
		},
	})

	return &TestNode{
		id:           h.ID(),
		h:            h,
		routingTable: rt,
		tun:          mockTun,
		ctx:          nodeCtx,
		cancel:       nodeCancel,
		dht:          dhtObj,
	}
}

func TestMeshCASecurity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clusterID := fmt.Sprintf("ca-test-cluster-%d", time.Now().UnixNano())
	log.Printf("🧪 Running CA PKI integration test (ML-DSA-87) with Cluster ID: %s", clusterID)

	// Initialize data key for GCM
	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		t.Fatalf("failed to generate random data key: %v", err)
	}
	if err := InitCipher(dataKey); err != nil {
		t.Fatalf("failed to initialize cipher: %v", err)
	}

	// 1. Generate Root CA
	caPub, caPriv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key pair: %v", err)
	}

	// Pre-generate keys and signatures for Relays and Endpoints
	r1Priv, _, _ := crypto.GenerateKeyPair(crypto.RSA, 2048)
	r1ID, _ := peer.IDFromPrivateKey(r1Priv)
	r2Priv, _, _ := crypto.GenerateKeyPair(crypto.RSA, 2048)
	r2ID, _ := peer.IDFromPrivateKey(r2Priv)

	epPrivs := make([]crypto.PrivKey, 5)
	epIDs := make([]peer.ID, 5)
	for i := 0; i < 5; i++ {
		epPrivs[i], _, _ = crypto.GenerateKeyPair(crypto.RSA, 2048)
		epIDs[i], _ = peer.IDFromPrivateKey(epPrivs[i])
	}

	// Create signatures mapped by Peer ID
	sigs := make(map[peer.ID][]byte)
	for _, id := range []peer.ID{r1ID, r2ID} {
		sig := make([]byte, mldsa87.SignatureSize)
		_ = mldsa87.SignTo(caPriv, []byte(id.String()), []byte("p2p-vpn-auth"), true, sig)
		sigs[id] = pem.EncodeToMemory(&pem.Block{
			Type:  "ML-DSA-87 SIGNATURE",
			Bytes: sig,
		})
	}
	for i, id := range epIDs {
		// 1. Base Signature
		baseSig := make([]byte, mldsa87.SignatureSize)
		_ = mldsa87.SignTo(caPriv, []byte(id.String()), []byte("p2p-vpn-auth"), true, baseSig)
		sigPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "ML-DSA-87 SIGNATURE",
			Bytes: baseSig,
		})

		// 2. Routing Signature
		virtualIP := fmt.Sprintf("10.200.0.%d/24", i+1)
		routingSig := make([]byte, mldsa87.SignatureSize)
		_ = mldsa87.SignTo(caPriv, []byte(fmt.Sprintf("%s|%s", id.String(), virtualIP)), []byte("p2p-vpn-auth"), true, routingSig)
		routingPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "ML-DSA-87 ROUTING SIGNATURE",
			Bytes: routingSig,
		})
		sigPEM = append(sigPEM, routingPEM...)
		sigs[id] = sigPEM
	}

	// 2. Launch 2 Relays (enforcing CA signatures)
	log.Println("🟢 Launching 2 Relays with CA PKI...")
	r1 := setupTestNode(ctx, t, "relay", r1Priv, nil, 4801, clusterID, nil, caPub, sigs[r1ID], "", nil)
	defer r1.h.Close()
	defer r1.cancel()

	r2 := setupTestNode(ctx, t, "relay", r2Priv, nil, 4802, clusterID, nil, caPub, sigs[r2ID], "", nil)
	defer r2.h.Close()
	defer r2.cancel()

	r1Addr := fmt.Sprintf("%s/p2p/%s", r1.h.Addrs()[0], r1.id)
	r2Addr := fmt.Sprintf("%s/p2p/%s", r2.h.Addrs()[0], r2.id)
	relayAddrs := []string{r1Addr, r2Addr}

	// 3. Launch 5 Endpoints (enforcing CA signatures)
	log.Println("🟢 Launching 5 Endpoints with CA PKI...")
	endpoints := make([]*TestNode, 5)

	for i := 0; i < 5; i++ {
		epIdx := i + 1
		virtualIP := fmt.Sprintf("10.200.0.%d/24", epIdx)
		advertiseSubnet := fmt.Sprintf("10.100.%d.0/24", epIdx)

		endpoints[i] = setupTestNode(ctx, t, "endpoint", epPrivs[i], relayAddrs, 0, clusterID, nil, caPub, sigs[epIDs[i]], virtualIP, []string{advertiseSubnet})
		defer endpoints[i].h.Close()
		defer endpoints[i].cancel()

		ConnectToPeer(ctx, endpoints[i].h, r1Addr)
		ConnectToPeer(ctx, endpoints[i].h, r2Addr)

		// Start Discovery loops
		go func(n *TestNode) {
			disc := routing.NewRoutingDiscovery(n.dht)
			for {
				disc.Advertise(n.ctx, clusterID)
				select {
				case <-n.ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}(endpoints[i])

		go func(n *TestNode) {
			disc := routing.NewRoutingDiscovery(n.dht)
			for {
				peerChan, err := disc.FindPeers(n.ctx, clusterID)
				if err == nil {
					for p := range peerChan {
						if p.ID == n.id || p.ID == r1.id || p.ID == r2.id {
							continue
						}
						if n.h.Network().Connectedness(p.ID) != network.Connected {
							n.h.Connect(n.ctx, p)
						}
					}
				}
				select {
				case <-n.ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}(endpoints[i])

		// TUN Reader loop (for packet routing)
		go func(n *TestNode) {
			buf := make([]byte, 2048)
			for {
				size, err := n.tun.Read(buf)
				if err != nil {
					return
				}
				packet := buf[:size]
				if len(packet) < 20 {
					continue
				}
				destIP := net.IP(packet[16:20])
				peerID, found := n.routingTable.LookupPeer(destIP)
				if !found {
					continue
				}
				pktCopy := make([]byte, len(packet))
				copy(pktCopy, packet)

				q := n.routingTable.GetOrCreateQueue(peerID, n.ctx, n.h, dataKey, n.tun)
				select {
				case q <- pktCopy:
				default:
				}
			}
		}(endpoints[i])
	}

	log.Println("🔄 Waiting for full mesh CA-authenticated connection...")
	meshConnected := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				allConnected := true
				for _, ep := range endpoints {
					ep.routingTable.Mu.RLock()
					peerCount := len(ep.routingTable.PeerInfo)
					ep.routingTable.Mu.RUnlock()
					if peerCount < 4 { // Should connect to the other 4 endpoints
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
		log.Println("✅ Success! Endpoints are fully connected via CA verification.")
	case <-ctx.Done():
		t.Fatalf("❌ Timeout: Endpoints failed to authenticate and connect.")
	}

	// 4. Test UDP Routing
	receivedChan := make(chan []byte, 10)
	endpoints[4].tun.OnWrite = func(pkt []byte) {
		receivedChan <- pkt
	}

	srcIP := net.ParseIP("10.200.0.1")
	dstIP := net.ParseIP("10.200.0.5")
	payload := []byte("Hello via ML-DSA-87 PKI Mesh!")
	pkt := MakeMockUDPPacket(srcIP, dstIP, payload)

	endpoints[0].tun.InjectPacket(pkt)

	select {
	case rxPkt := <-receivedChan:
		rxPayload := rxPkt[28:]
		if string(rxPayload) != string(payload) {
			t.Fatalf("expected payload %q, got %q", string(payload), string(rxPayload))
		}
		log.Println("✅ UDP packet routed successfully over CA-secured mesh!")
	case <-time.After(10 * time.Second):
		t.Fatalf("❌ Timeout: Failed to route packet over CA-secured mesh")
	}

	// 5. Test Endpoint 6 (Valid identity key, but NO signature)
	log.Println("🛡️ Testing Endpoint 6 connection blockage (no signature)...")
	ep6Priv, _, _ := crypto.GenerateKeyPair(crypto.RSA, 2048)
	ep6 := setupTestNode(ctx, t, "endpoint", ep6Priv, relayAddrs, 0, clusterID, nil, caPub, nil, "10.200.0.6/24", []string{"10.100.6.0/24"})
	defer ep6.h.Close()
	defer ep6.cancel()

	err = ep6.h.Connect(ctx, r1.h.Peerstore().PeerInfo(r1.id))
	log.Printf("🔌 Endpoint 6 dialed Relay 1. err=%v, immediate connectedness=%v", err, ep6.h.Network().Connectedness(r1.id))
	time.Sleep(2 * time.Second) // wait for kicker
	log.Printf("🔌 After 2s sleep: connectedness=%v", ep6.h.Network().Connectedness(r1.id))
	if ep6.h.Network().Connectedness(r1.id) == network.Connected {
		t.Fatalf("❌ Security Violation: Unsigned Endpoint 6 stayed connected!")
	}
	log.Println("✅ Success: Unsigned Endpoint 6 was disconnected successfully.")

	// 6. Test Endpoint 7 (Valid identity key, but signature signed by a FAKE CA)
	log.Println("🛡️ Testing Endpoint 7 connection blockage (fake CA signature)...")
	fakeCaPub, fakeCaPriv, _ := mldsa87.GenerateKey(rand.Reader)
	_ = fakeCaPub
	ep7Priv, _, _ := crypto.GenerateKeyPair(crypto.RSA, 2048)
	ep7ID, _ := peer.IDFromPrivateKey(ep7Priv)
	fakeSig := make([]byte, mldsa87.SignatureSize)
	_ = mldsa87.SignTo(fakeCaPriv, []byte(fmt.Sprintf("%s|10.200.0.7/24", ep7ID.String())), []byte("p2p-vpn-auth"), true, fakeSig)

	ep7 := setupTestNode(ctx, t, "endpoint", ep7Priv, relayAddrs, 0, clusterID, nil, caPub, fakeSig, "10.200.0.7/24", []string{"10.100.7.0/24"})
	defer ep7.h.Close()
	defer ep7.cancel()

	err = ep7.h.Connect(ctx, r1.h.Peerstore().PeerInfo(r1.id))
	log.Printf("🔌 Endpoint 7 dialed Relay 1. err=%v, immediate connectedness=%v", err, ep7.h.Network().Connectedness(r1.id))
	time.Sleep(2 * time.Second) // wait for kicker
	log.Printf("🔌 After 2s sleep: connectedness=%v", ep7.h.Network().Connectedness(r1.id))
	if ep7.h.Network().Connectedness(r1.id) == network.Connected {
		t.Fatalf("❌ Security Violation: Endpoint 7 with fake signature stayed connected!")
	}
	log.Println("✅ Success: Endpoint 7 was disconnected successfully.")
}

func TestMeshConnectionGater(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clusterID := fmt.Sprintf("gater-test-cluster-%d", time.Now().UnixNano())
	log.Printf("🧪 Running Whitelist Connection Gater integration test with Cluster ID: %s", clusterID)

	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		t.Fatalf("failed to generate random data key: %v", err)
	}
	if err := InitCipher(dataKey); err != nil {
		t.Fatalf("failed to initialize cipher: %v", err)
	}

	// 1. Generate keys for Relays and Endpoints
	relay1Priv, _, _ := crypto.GenerateKeyPair(crypto.RSA, 2048)
	r1ID, _ := peer.IDFromPrivateKey(relay1Priv)
	relay2Priv, _, _ := crypto.GenerateKeyPair(crypto.RSA, 2048)
	r2ID, _ := peer.IDFromPrivateKey(relay2Priv)

	epPrivs := make([]crypto.PrivKey, 5)
	epIDs := make([]peer.ID, 5)
	for i := 0; i < 5; i++ {
		epPrivs[i], _, _ = crypto.GenerateKeyPair(crypto.RSA, 2048)
		epIDs[i], _ = peer.IDFromPrivateKey(epPrivs[i])
	}

	allowedPeers := []peer.ID{r1ID, r2ID}
	allowedPeers = append(allowedPeers, epIDs...)

	// 2. Launch 2 Relays (whitelist active, CA disabled)
	log.Println("🟢 Launching 2 Relays with Whitelist...")
	r1 := setupTestNode(ctx, t, "relay", relay1Priv, nil, 4901, clusterID, allowedPeers, nil, nil, "", nil)
	defer r1.h.Close()
	defer r1.cancel()

	r2 := setupTestNode(ctx, t, "relay", relay2Priv, nil, 4902, clusterID, allowedPeers, nil, nil, "", nil)
	defer r2.h.Close()
	defer r2.cancel()

	r1Addr := fmt.Sprintf("%s/p2p/%s", r1.h.Addrs()[0], r1.id)
	r2Addr := fmt.Sprintf("%s/p2p/%s", r2.h.Addrs()[0], r2.id)
	relayAddrs := []string{r1Addr, r2Addr}

	// 3. Launch 5 Endpoints
	log.Println("🟢 Launching 5 Endpoints with Whitelist...")
	endpoints := make([]*TestNode, 5)

	for i := 0; i < 5; i++ {
		epIdx := i + 1
		virtualIP := fmt.Sprintf("10.200.0.%d/24", epIdx)
		advertiseSubnet := fmt.Sprintf("10.100.%d.0/24", epIdx)

		endpoints[i] = setupTestNode(ctx, t, "endpoint", epPrivs[i], relayAddrs, 0, clusterID, allowedPeers, nil, nil, virtualIP, []string{advertiseSubnet})
		defer endpoints[i].h.Close()
		defer endpoints[i].cancel()

		ConnectToPeer(ctx, endpoints[i].h, r1Addr)
		ConnectToPeer(ctx, endpoints[i].h, r2Addr)

		// Start Discovery loops
		go func(n *TestNode) {
			disc := routing.NewRoutingDiscovery(n.dht)
			for {
				disc.Advertise(n.ctx, clusterID)
				select {
				case <-n.ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}(endpoints[i])

		go func(n *TestNode) {
			disc := routing.NewRoutingDiscovery(n.dht)
			for {
				peerChan, err := disc.FindPeers(n.ctx, clusterID)
				if err == nil {
					for p := range peerChan {
						if p.ID == n.id || p.ID == r1.id || p.ID == r2.id {
							continue
						}
						if n.h.Network().Connectedness(p.ID) != network.Connected {
							n.h.Connect(n.ctx, p)
						}
					}
				}
				select {
				case <-n.ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}(endpoints[i])
	}

	log.Println("🔄 Waiting for full mesh whitelist connection...")
	meshConnected := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				allConnected := true
				for _, ep := range endpoints {
					ep.routingTable.Mu.RLock()
					peerCount := len(ep.routingTable.PeerInfo)
					ep.routingTable.Mu.RUnlock()
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
		log.Println("✅ Success! Whitelisted endpoints are fully connected.")
	case <-ctx.Done():
		t.Fatalf("❌ Timeout: Whitelisted endpoints failed to connect.")
	}

	// 4. Test Endpoint 6 (Not whitelisted)
	log.Println("🛡️ Testing Endpoint 6 connection blockage (not in whitelist)...")
	ep6Priv, _, _ := crypto.GenerateKeyPair(crypto.RSA, 2048)
	ep6 := setupTestNode(ctx, t, "endpoint", ep6Priv, relayAddrs, 0, clusterID, allowedPeers, nil, nil, "10.200.0.6/24", []string{"10.100.6.0/24"})
	defer ep6.h.Close()
	defer ep6.cancel()

	err := ep6.h.Connect(ctx, r1.h.Peerstore().PeerInfo(r1.id))
	log.Printf("🔌 Unauthorized Node dialed. err=%v, connectedness=%v", err, ep6.h.Network().Connectedness(r1.id))
	time.Sleep(200 * time.Millisecond) // gater rejects instantly
	if ep6.h.Network().Connectedness(r1.id) == network.Connected {
		t.Fatalf("❌ Security Violation: Non-whitelisted node successfully connected!")
	}
	log.Println("✅ Success: Non-whitelisted node was blocked instantly.")
}

func TestMeshCombinedMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clusterID := fmt.Sprintf("combined-test-cluster-%d", time.Now().UnixNano())
	log.Printf("🧪 Running Combined Mode (Whitelist + CA PKI) integration test with Cluster ID: %s", clusterID)

	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		t.Fatalf("failed to generate random data key: %v", err)
	}
	if err := InitCipher(dataKey); err != nil {
		t.Fatalf("failed to initialize cipher: %v", err)
	}

	// 1. Generate Root CA
	caPub, caPriv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key pair: %v", err)
	}

	// Pre-generate keys and signatures for Relays and Endpoints
	r1Priv, _, _ := crypto.GenerateKeyPair(crypto.RSA, 2048)
	r1ID, _ := peer.IDFromPrivateKey(r1Priv)
	r2Priv, _, _ := crypto.GenerateKeyPair(crypto.RSA, 2048)
	r2ID, _ := peer.IDFromPrivateKey(r2Priv)

	epPrivs := make([]crypto.PrivKey, 5)
	epIDs := make([]peer.ID, 5)
	for i := 0; i < 5; i++ {
		epPrivs[i], _, _ = crypto.GenerateKeyPair(crypto.RSA, 2048)
		epIDs[i], _ = peer.IDFromPrivateKey(epPrivs[i])
	}

	// Pre-generate EP 7 keys as well to add it to the whitelist
	ep7Priv, _, _ := crypto.GenerateKeyPair(crypto.RSA, 2048)
	ep7ID, _ := peer.IDFromPrivateKey(ep7Priv)

	allowedPeers := []peer.ID{r1ID, r2ID, ep7ID}
	allowedPeers = append(allowedPeers, epIDs...)

	sigs := make(map[peer.ID][]byte)
	for _, id := range []peer.ID{r1ID, r2ID} {
		sig := make([]byte, mldsa87.SignatureSize)
		_ = mldsa87.SignTo(caPriv, []byte(id.String()), []byte("p2p-vpn-auth"), true, sig)
		sigs[id] = pem.EncodeToMemory(&pem.Block{
			Type:  "ML-DSA-87 SIGNATURE",
			Bytes: sig,
		})
	}

	// Create dual signatures for endpoints
	allEpIDs := append([]peer.ID{ep7ID}, epIDs...)
	for i, id := range allEpIDs {
		// 1. Base Signature
		baseSig := make([]byte, mldsa87.SignatureSize)
		_ = mldsa87.SignTo(caPriv, []byte(id.String()), []byte("p2p-vpn-auth"), true, baseSig)
		sigPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "ML-DSA-87 SIGNATURE",
			Bytes: baseSig,
		})

		// 2. Routing Signature
		epIdx := i // Not exact, but we just need unique IPs for signatures
		virtualIP := fmt.Sprintf("10.200.0.%d/24", epIdx+10)
		if id != ep7ID {
			for j, e := range epIDs {
				if e == id {
					virtualIP = fmt.Sprintf("10.200.0.%d/24", j+1)
					break
				}
			}
		} else {
			virtualIP = "10.200.0.7/24"
		}

		routingSig := make([]byte, mldsa87.SignatureSize)
		_ = mldsa87.SignTo(caPriv, []byte(fmt.Sprintf("%s|%s", id.String(), virtualIP)), []byte("p2p-vpn-auth"), true, routingSig)
		routingPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "ML-DSA-87 ROUTING SIGNATURE",
			Bytes: routingSig,
		})
		sigPEM = append(sigPEM, routingPEM...)
		sigs[id] = sigPEM
	}

	// 2. Launch 2 Relays (both Whitelist and CA enabled)
	log.Println("🟢 Launching 2 Relays in Combined Mode...")
	r1 := setupTestNode(ctx, t, "relay", r1Priv, nil, 4951, clusterID, allowedPeers, caPub, sigs[r1ID], "", nil)
	defer r1.h.Close()
	defer r1.cancel()

	r2 := setupTestNode(ctx, t, "relay", r2Priv, nil, 4952, clusterID, allowedPeers, caPub, sigs[r2ID], "", nil)
	defer r2.h.Close()
	defer r2.cancel()

	r1Addr := fmt.Sprintf("%s/p2p/%s", r1.h.Addrs()[0], r1.id)
	r2Addr := fmt.Sprintf("%s/p2p/%s", r2.h.Addrs()[0], r2.id)
	relayAddrs := []string{r1Addr, r2Addr}

	// 3. Launch 5 Endpoints
	log.Println("🟢 Launching 5 Endpoints in Combined Mode...")
	endpoints := make([]*TestNode, 5)

	for i := 0; i < 5; i++ {
		epIdx := i + 1
		virtualIP := fmt.Sprintf("10.200.0.%d/24", epIdx)
		advertiseSubnet := fmt.Sprintf("10.100.%d.0/24", epIdx)

		endpoints[i] = setupTestNode(ctx, t, "endpoint", epPrivs[i], relayAddrs, 0, clusterID, allowedPeers, caPub, sigs[epIDs[i]], virtualIP, []string{advertiseSubnet})
		defer endpoints[i].h.Close()
		defer endpoints[i].cancel()

		ConnectToPeer(ctx, endpoints[i].h, r1Addr)
		ConnectToPeer(ctx, endpoints[i].h, r2Addr)

		// Start Discovery loops
		go func(n *TestNode) {
			disc := routing.NewRoutingDiscovery(n.dht)
			for {
				disc.Advertise(n.ctx, clusterID)
				select {
				case <-n.ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}(endpoints[i])

		go func(n *TestNode) {
			disc := routing.NewRoutingDiscovery(n.dht)
			for {
				peerChan, err := disc.FindPeers(n.ctx, clusterID)
				if err == nil {
					for p := range peerChan {
						if p.ID == n.id || p.ID == r1.id || p.ID == r2.id {
							continue
						}
						if n.h.Network().Connectedness(p.ID) != network.Connected {
							n.h.Connect(n.ctx, p)
						}
					}
				}
				select {
				case <-n.ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}(endpoints[i])
	}

	log.Println("🔄 Waiting for full mesh combined-mode connection...")
	meshConnected := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				allConnected := true
				for _, ep := range endpoints {
					ep.routingTable.Mu.RLock()
					peerCount := len(ep.routingTable.PeerInfo)
					ep.routingTable.Mu.RUnlock()
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
		log.Println("✅ Success! Combined-mode endpoints are fully connected.")
	case <-ctx.Done():
		t.Fatalf("❌ Timeout: Combined-mode endpoints failed to connect.")
	}

	// 4. Test Endpoint 6 (Not whitelisted -> blocked instantly by Connection Gater)
	log.Println("🛡️ Testing Endpoint 6 connection blockage (not in whitelist)...")
	ep6Priv, _, _ := crypto.GenerateKeyPair(crypto.RSA, 2048)
	ep6 := setupTestNode(ctx, t, "endpoint", ep6Priv, relayAddrs, 0, clusterID, allowedPeers, caPub, sigs[epIDs[0]], "10.200.0.6/24", []string{"10.100.6.0/24"})
	defer ep6.h.Close()
	defer ep6.cancel()

	err = ep6.h.Connect(ctx, r1.h.Peerstore().PeerInfo(r1.id))
	log.Printf("🔌 Unauthorized Node dialed. err=%v, connectedness=%v", err, ep6.h.Network().Connectedness(r1.id))
	time.Sleep(200 * time.Millisecond) // gater rejects instantly
	if ep6.h.Network().Connectedness(r1.id) == network.Connected {
		t.Fatalf("❌ Security Violation: Non-whitelisted Endpoint 6 stayed connected!")
	}
	log.Println("✅ Success: Non-whitelisted node was blocked instantly by Connection Gater.")

	// 5. Test Endpoint 7 (Whitelisted but has invalid CA signature -> rejected by CA and kicked after handshake)
	log.Println("🛡️ Testing Endpoint 7 connection blockage (whitelisted but bad signature)...")

	// EP 7 has invalid signature (nil)
	ep7 := setupTestNode(ctx, t, "endpoint", ep7Priv, relayAddrs, 0, clusterID, allowedPeers, caPub, nil, "10.200.0.7/24", []string{"10.100.7.0/24"})
	defer ep7.h.Close()
	defer ep7.cancel()

	err = ep7.h.Connect(ctx, r1.h.Peerstore().PeerInfo(r1.id))
	log.Printf("🔌 Whitelisted Node with bad sig dialed. err=%v, connectedness=%v", err, ep7.h.Network().Connectedness(r1.id))
	time.Sleep(2 * time.Second) // wait for kicker
	log.Printf("🔌 After 2s sleep: connectedness=%v", ep7.h.Network().Connectedness(r1.id))
	if ep7.h.Network().Connectedness(r1.id) == network.Connected {
		t.Fatalf("❌ Security Violation: Whitelisted node with bad signature stayed connected!")
	}
	log.Println("✅ Success: Whitelisted node with bad signature was disconnected by CA verification.")
}
