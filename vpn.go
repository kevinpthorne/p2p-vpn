package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/multiformats/go-multiaddr"
)

// Global CA and Node signature configuration for PKI authentication
var (
	CAPubKey      *mldsa87.PublicKey
	NodeSignature []byte
)

// Global active connections and state for API status telemetry
var (
	ActiveHost         host.Host
	ActiveDHT          *dht.IpfsDHT
	ActiveRoutingTable *RoutingTable
	ActiveTun          TunInterface
	TotalRxBytes       uint64
	TotalTxBytes       uint64
)


// WhitelistConnectionGater filters incoming and outgoing connections based on a peer ID whitelist
type WhitelistConnectionGater struct {
	allowedPeers map[peer.ID]bool
	mu           sync.RWMutex
}

var _ connmgr.ConnectionGater = (*WhitelistConnectionGater)(nil)

func NewWhitelistConnectionGater(allowed []peer.ID) *WhitelistConnectionGater {
	m := make(map[peer.ID]bool)
	for _, p := range allowed {
		m[p] = true
	}
	return &WhitelistConnectionGater{
		allowedPeers: m,
	}
}

func (g *WhitelistConnectionGater) InterceptPeerDial(p peer.ID) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.allowedPeers[p]
}

func (g *WhitelistConnectionGater) InterceptAddrDial(p peer.ID, addr multiaddr.Multiaddr) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.allowedPeers[p]
}

func (g *WhitelistConnectionGater) InterceptAccept(c network.ConnMultiaddrs) bool {
	return true
}

func (g *WhitelistConnectionGater) InterceptSecured(dir network.Direction, p peer.ID, c network.ConnMultiaddrs) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.allowedPeers[p]
}

func (g *WhitelistConnectionGater) InterceptUpgraded(c network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}


// Configuration Constants
const (
	TunnelProtocol    = "/p2p-vpn/tunnel/1.0.0"
	HandshakeProtocol = "/p2p-vpn/handshake/1.0.0"
)

// HandshakeMessage contains the routes and virtual IP details of an endpoint
type HandshakeMessage struct {
	VirtualIP string   `json:"virtual_ip"` // e.g. "10.200.0.1/24"
	Subnets   []string `json:"subnets"`    // e.g. ["10.100.1.0/24"]
	Signature string   `json:"signature"`  // PEM or hex encoded ML-DSA-87 signature
}

func encodeSignaturePEM(sigBytes []byte) string {
	block := &pem.Block{
		Type:  "ML-DSA-87 SIGNATURE",
		Bytes: sigBytes,
	}
	return string(pem.EncodeToMemory(block))
}

func decodeSignaturePEM(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "ML-DSA-87 SIGNATURE" {
		// Fallback to raw hex if not a valid PEM block
		str := strings.TrimSpace(string(pemBytes))
		if hexBytes, err := hex.DecodeString(str); err == nil {
			return hexBytes, nil
		}
		return pemBytes, nil
	}
	return block.Bytes, nil
}

func HandleIncomingHandshake(ctx context.Context, h host.Host, s network.Stream, localVirtualIP string, localSubnets []string, routingTable *RoutingTable, tunIfce TunInterface, caPubKey *mldsa87.PublicKey, localSignature []byte) {
	defer s.Close()
	remotePeer := s.Conn().RemotePeer()
	log.Printf("🤝 Incoming handshake stream from %s", remotePeer)

	var msg HandshakeMessage
	if err := json.NewDecoder(s).Decode(&msg); err != nil {
		log.Printf("⚠️ Failed to parse handshake message from %s: %v", remotePeer, err)
		return
	}

	// Verify CA signature if PKI is enabled
	if caPubKey != nil {
		sigBytes, err := decodeSignaturePEM([]byte(msg.Signature))
		if err != nil || len(sigBytes) == 0 {
			log.Printf("❌ Incoming handshake rejected: missing or invalid signature format from %s", remotePeer)
			s.Reset()
			h.Network().ClosePeer(remotePeer)
			return
		}
		if !mldsa87.Verify(caPubKey, []byte(remotePeer.String()), []byte("p2p-vpn-auth"), sigBytes) {
			log.Printf("❌ Incoming handshake rejected: signature verification FAILED for %s", remotePeer)
			s.Reset()
			h.Network().ClosePeer(remotePeer)
			return
		}
		log.Printf("🛡️ CA signature verified for incoming peer %s", remotePeer)
	}

	log.Printf("📝 Handshake: Peer %s reports Virtual IP: %s, Subnets: %v", remotePeer, msg.VirtualIP, msg.Subnets)

	// Register peer and configure routes if virtual IP is set
	if msg.VirtualIP != "" {
		newSubnets, oldSubnets := routingTable.RegisterPeer(remotePeer, msg.VirtualIP, msg.Subnets)
		if tunIfce != nil {
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
			for _, s := range newSubnets {
				log.Printf("➕ Adding route for peer %s: %s", remotePeer, s)
				if err := tunIfce.AddRoute(s); err != nil {
					log.Printf("⚠️ Failed to configure route %s: %v", s, err)
				}
			}
		}
	} else {
		// Register relay too
		routingTable.RegisterPeer(remotePeer, "", nil)
	}

	// Respond back with our own routing information
	respSig := ""
	if len(localSignature) > 0 {
		respSig = encodeSignaturePEM(localSignature)
	}
	resp := HandshakeMessage{
		VirtualIP: localVirtualIP,
		Subnets:   localSubnets,
		Signature: respSig,
	}
	if err := json.NewEncoder(s).Encode(&resp); err != nil {
		log.Printf("⚠️ Failed to encode response handshake to %s: %v", remotePeer, err)
		return
	}
	log.Printf("✅ Bidirectional handshake response successfully sent to %s", remotePeer)
}


// PeerRoutes holds routing information for a remote peer
type PeerRoutes struct {
	VirtualIP string
	Subnets   []string
}

// RoutingTable manages mappings from IP/Subnets to Peer IDs and streams
type RoutingTable struct {
	mu            sync.RWMutex
	ipToPeer      map[string]peer.ID
	peerInfo      map[peer.ID]*PeerRoutes
	activeStreams map[peer.ID]network.Stream
	streamMutexes map[peer.ID]*sync.Mutex
	queues        map[peer.ID]chan []byte
	queuesMu      sync.RWMutex
}

func NewRoutingTable() *RoutingTable {
	return &RoutingTable{
		ipToPeer:      make(map[string]peer.ID),
		peerInfo:      make(map[peer.ID]*PeerRoutes),
		activeStreams: make(map[peer.ID]network.Stream),
		streamMutexes: make(map[peer.ID]*sync.Mutex),
		queues:        make(map[peer.ID]chan []byte),
	}
}

func (rt *RoutingTable) RegisterPeer(pid peer.ID, virtualIP string, subnets []string) (newSubnets []string, oldSubnets []string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Strip CIDR mask for virtual IP mapping
	ip, _, err := net.ParseCIDR(virtualIP)
	if err == nil {
		rt.ipToPeer[ip.String()] = pid
	}

	oldInfo := rt.peerInfo[pid]
	if oldInfo != nil {
		oldSubnets = oldInfo.Subnets
	}

	rt.peerInfo[pid] = &PeerRoutes{
		VirtualIP: virtualIP,
		Subnets:   subnets,
	}

	return subnets, oldSubnets
}

func (rt *RoutingTable) UnregisterPeer(pid peer.ID) (virtualIP string, subnets []string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	info := rt.peerInfo[pid]
	if info != nil {
		virtualIP = info.VirtualIP
		subnets = info.Subnets
		ip, _, err := net.ParseCIDR(virtualIP)
		if err == nil {
			delete(rt.ipToPeer, ip.String())
		}
		delete(rt.peerInfo, pid)
	}

	if s, ok := rt.activeStreams[pid]; ok {
		s.Close()
		delete(rt.activeStreams, pid)
	}
	delete(rt.streamMutexes, pid)

	// Clean up packet queue
	rt.CleanQueue(pid)

	return virtualIP, subnets
}

func (rt *RoutingTable) LookupPeer(destIP net.IP) (peer.ID, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	destStr := destIP.String()
	if pid, ok := rt.ipToPeer[destStr]; ok {
		return pid, true
	}

	// Subnet routing checks
	for pid, info := range rt.peerInfo {
		for _, subnetStr := range info.Subnets {
			_, subnet, err := net.ParseCIDR(subnetStr)
			if err == nil && subnet.Contains(destIP) {
				return pid, true
			}
		}
	}

	return "", false
}

func (rt *RoutingTable) GetStream(pid peer.ID) (network.Stream, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	s, ok := rt.activeStreams[pid]
	return s, ok
}

func (rt *RoutingTable) SetStream(pid peer.ID, s network.Stream) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.activeStreams[pid] = s
}

func (rt *RoutingTable) ClearStream(pid peer.ID) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.activeStreams, pid)
}

func (rt *RoutingTable) ClearStreamIfMatches(pid peer.ID, s network.Stream) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.activeStreams[pid] == s {
		delete(rt.activeStreams, pid)
	}
}

func (rt *RoutingTable) HasPeer(pid peer.ID) bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	_, ok := rt.peerInfo[pid]
	return ok
}

func (rt *RoutingTable) GetOrCreateQueue(pid peer.ID, ctx context.Context, h host.Host, dataKey []byte, tunIfce TunInterface) chan []byte {
	rt.queuesMu.Lock()
	defer rt.queuesMu.Unlock()

	q, ok := rt.queues[pid]
	if !ok {
		q = make(chan []byte, 1024) // Buffer up to 1024 packets
		rt.queues[pid] = q
		go rt.peerWorkerLoop(ctx, pid, q, h, dataKey, tunIfce)
	}
	return q
}

func (rt *RoutingTable) CleanQueue(pid peer.ID) {
	rt.queuesMu.Lock()
	defer rt.queuesMu.Unlock()
	if q, ok := rt.queues[pid]; ok {
		close(q)
		delete(rt.queues, pid)
	}
}

func (rt *RoutingTable) peerWorkerLoop(ctx context.Context, pid peer.ID, q chan []byte, h host.Host, dataKey []byte, tunIfce TunInterface) {
	log.Printf("👤 Started packet worker loop for peer %s", pid)
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-q:
			if !ok {
				log.Printf("👤 Stopped packet worker loop for peer %s (queue closed)", pid)
				return
			}

			s, ok := rt.GetStream(pid)
			if !ok {
				// Open a new outbound stream
				transientCtx := network.WithAllowLimitedConn(ctx, "vpn-tunnel")
				var err error
				s, err = h.NewStream(transientCtx, pid, TunnelProtocol)
				if err != nil {
					log.Printf("⚠️ Failed to open outgoing stream to %s: %v", pid, err)
					// Drop packet and sleep briefly to avoid spinning
					time.Sleep(100 * time.Millisecond)
					continue
				}
				rt.SetStream(pid, s)

				// Start reader loop on this outbound stream
				go func(stream network.Stream) {
					defer stream.Close()
					defer rt.ClearStreamIfMatches(pid, stream)
					log.Printf("📥 Reader loop started on outbound tunnel stream to %s", pid)
					for {
						packet, err := readFrame(stream, dataKey)
						if err != nil {
							break
						}
						if _, err := tunIfce.Write(packet); err != nil {
							log.Printf("⚠️ Failed to inject packet to TUN interface: %v", err)
						}
					}
					log.Printf("❌ Reader loop stopped on outbound tunnel stream to %s", pid)
				}(s)
			}

			mu := rt.GetStreamMutex(pid)
			mu.Lock()
			err := writeFrame(s, pkt, dataKey)
			mu.Unlock()
			if err != nil {
				log.Printf("⚠️ Failed to write packet frame to peer %s: %v", pid, err)
				s.Reset()
				rt.ClearStreamIfMatches(pid, s)
			}
		}
	}
}

func (rt *RoutingTable) GetStreamMutex(pid peer.ID) *sync.Mutex {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	m, ok := rt.streamMutexes[pid]
	if !ok {
		m = &sync.Mutex{}
		rt.streamMutexes[pid] = m
	}
	return m
}

// Cryptography Caching & Fast Nonces
var (
	dataAEAD   cipher.AEAD
	nonceSalt  uint32
	nonceSeq   uint64
)

func InitCipher(key []byte) error {
	if len(key) == 0 {
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	dataAEAD = gcm

	// Initialize salt with random 4 bytes
	var salt [4]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return err
	}
	nonceSalt = binary.BigEndian.Uint32(salt[:])
	return nil
}

// Framing Helpers
func writeFrame(w io.Writer, payload []byte, key []byte) error {
	var nonce, ciphertext []byte
	if dataAEAD != nil {
		seq := atomic.AddUint64(&nonceSeq, 1)
		nonce = make([]byte, 12)
		binary.BigEndian.PutUint32(nonce[0:4], nonceSalt)
		binary.BigEndian.PutUint64(nonce[4:12], seq)
		ciphertext = dataAEAD.Seal(nil, nonce, payload, nil)
	} else {
		ciphertext = payload
	}

	totalLen := len(nonce) + len(ciphertext)
	if totalLen > 65535 {
		return fmt.Errorf("packet size exceeds frame maximum: %d", totalLen)
	}

	header := make([]byte, 2+len(nonce))
	binary.BigEndian.PutUint16(header[0:2], uint16(totalLen))
	copy(header[2:], nonce)

	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(ciphertext); err != nil {
		return err
	}
	atomic.AddUint64(&TotalTxBytes, uint64(len(payload)))
	return nil
}

func readFrame(r io.Reader, key []byte) ([]byte, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	totalLen := binary.BigEndian.Uint16(lenBuf)

	nonceSize := 0
	if dataAEAD != nil {
		nonceSize = 12 // Standard AES-GCM nonce size
	}

	if int(totalLen) < nonceSize {
		return nil, fmt.Errorf("frame size %d too small for nonce", totalLen)
	}

	buf := make([]byte, totalLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	var payload []byte
	var err error
	if dataAEAD != nil {
		nonce := buf[:nonceSize]
		ciphertext := buf[nonceSize:]
		payload, err = dataAEAD.Open(nil, nonce, ciphertext, nil)
	} else {
		payload, err = buf, nil
	}

	if err == nil {
		atomic.AddUint64(&TotalRxBytes, uint64(len(payload)))
	}
	return payload, err
}

func makeHost(ctx context.Context, mode string, privKey crypto.PrivKey, relayAddrs []string, port int, clusterID string, allowedPeers []peer.ID) (host.Host, *dht.IpfsDHT, error) {
	tcpListen := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port)
	udpListen := fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", port)

	var bootstrapPeers []peer.AddrInfo
	for _, addrStr := range relayAddrs {
		if addrStr == "" {
			continue
		}
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err == nil {
			pi, err := peer.AddrInfoFromP2pAddr(ma)
			if err == nil {
				bootstrapPeers = append(bootstrapPeers, *pi)
			}
		}
	}

	opts := []libp2p.Option{
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings(tcpListen, udpListen),
	}

	if mode == "relay" {
		resources := relay.DefaultResources()
		resources.Limit = nil // Disable data caps and duration limits on relayed connections
		opts = append(opts,
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(relay.WithResources(resources)),
			libp2p.EnableNATService(),
		)
	} else {
		opts = append(opts,
			libp2p.ForceReachabilityPrivate(),
			libp2p.EnableAutoRelayWithStaticRelays(bootstrapPeers),
			libp2p.EnableHolePunching(),
		)
	}

	if len(allowedPeers) > 0 {
		gater := NewWhitelistConnectionGater(allowedPeers)
		opts = append(opts, libp2p.ConnectionGater(gater))
		log.Printf("🔒 Connection Gater enabled with %d allowed peers", len(allowedPeers))
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, nil, err
	}

	dhtMode := dht.Mode(dht.ModeClient)
	if mode == "relay" {
		dhtMode = dht.Mode(dht.ModeServer)
	}

	kademliaDHT, err := dht.New(ctx, h,
		dhtMode,
		dht.ProtocolPrefix(protocolPrefixForCluster(clusterID)),
		dht.BootstrapPeers(bootstrapPeers...),
	)

	return h, kademliaDHT, err
}

func getIdentity(path string) (crypto.PrivKey, error) {
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err == nil {
			return crypto.UnmarshalPrivateKey(data)
		}
	}
	priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		return nil, err
	}
	data, _ := crypto.MarshalPrivateKey(priv)
	os.WriteFile(path, data, 0600)
	return priv, nil
}

func protocolPrefixForCluster(clusterID string) protocol.ID {
	return protocol.ID(fmt.Sprintf("/p2p-vpn/%s/kad/1.0.0", clusterID))
}

func connectToPeer(ctx context.Context, h host.Host, target string) {
	ma, err := multiaddr.NewMultiaddr(target)
	if err != nil {
		log.Printf("⚠️ Invalid bootstrap address %q: %v", target, err)
		return
	}
	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		log.Printf("⚠️ Invalid peer info for %q: %v", target, err)
		return
	}
	if err := h.Connect(ctx, *info); err != nil {
		log.Printf("❌ Failed to dial Bootstrap/Relay %s: %v", info.ID, err)
	} else {
		log.Printf("✅ Connected to Bootstrap/Relay %s", info.ID)
	}
}

// Handshake execution
func pushHandshake(ctx context.Context, h host.Host, pid peer.ID, localVirtualIP string, localSubnets []string, routingTable *RoutingTable, tunIfce TunInterface, caPubKey *mldsa87.PublicKey, localSignature []byte) {
	log.Printf("🤝 Sending routing handshake to peer %s", pid)
	handshakeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	transientCtx := network.WithAllowLimitedConn(handshakeCtx, "vpn-handshake")
	s, err := h.NewStream(transientCtx, pid, HandshakeProtocol)
	if err != nil {
		log.Printf("⚠️ Handshake stream creation failed to %s: %v", pid, err)
		return
	}
	defer s.Close()

	// 1. Write our handshake
	localSig := ""
	if len(localSignature) > 0 {
		localSig = encodeSignaturePEM(localSignature)
	}
	msg := HandshakeMessage{
		VirtualIP: localVirtualIP,
		Subnets:   localSubnets,
		Signature: localSig,
	}

	encoder := json.NewEncoder(s)
	if err := encoder.Encode(&msg); err != nil {
		log.Printf("⚠️ Handshake encoding failed: %v", err)
		return
	}

	// 2. Read responder's handshake response
	var respMsg HandshakeMessage
	decoder := json.NewDecoder(s)
	if err := decoder.Decode(&respMsg); err != nil {
		log.Printf("⚠️ Handshake response decoding failed from %s: %v", pid, err)
		return
	}

	// Verify CA signature if PKI is enabled
	if caPubKey != nil {
		sigBytes, err := decodeSignaturePEM([]byte(respMsg.Signature))
		if err != nil || len(sigBytes) == 0 {
			log.Printf("❌ Outbound handshake rejected: missing or invalid signature format from %s", pid)
			s.Reset()
			h.Network().ClosePeer(pid)
			return
		}
		if !mldsa87.Verify(caPubKey, []byte(pid.String()), []byte("p2p-vpn-auth"), sigBytes) {
			log.Printf("❌ Outbound handshake rejected: signature verification FAILED for %s", pid)
			s.Reset()
			h.Network().ClosePeer(pid)
			return
		}
		log.Printf("🛡️ CA signature verified for outbound peer %s", pid)
	}

	log.Printf("📝 Handshake response: Peer %s reports Virtual IP: %s, Subnets: %v", pid, respMsg.VirtualIP, respMsg.Subnets)

	// 3. Register peer and add routes
	if respMsg.VirtualIP != "" {
		newSubnets, oldSubnets := routingTable.RegisterPeer(pid, respMsg.VirtualIP, respMsg.Subnets)
		if tunIfce != nil {
			newSet := make(map[string]bool)
			for _, s := range newSubnets {
				newSet[s] = true
			}
			for _, s := range oldSubnets {
				if !newSet[s] {
					log.Printf("🗑️ Removing obsolete route for peer %s: %s", pid, s)
					tunIfce.DeleteRoute(s)
				}
			}
			for _, s := range newSubnets {
				log.Printf("➕ Adding route for peer %s: %s", pid, s)
				if err := tunIfce.AddRoute(s); err != nil {
					log.Printf("⚠️ Failed to configure route %s: %v", s, err)
				}
			}
		}
	} else {
		// Register relay too
		routingTable.RegisterPeer(pid, "", nil)
	}
	log.Printf("✅ Handshake successfully completed with %s", pid)
}

func StartCAAuthKicker(ctx context.Context, h host.Host, routingTable *RoutingTable, remotePeer peer.ID, caPubKey *mldsa87.PublicKey) {
	if caPubKey == nil {
		return // PKI not enforced, no kicker needed
	}
	go func() {
		// Wait up to 5 seconds for the handshake to finish
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		// If the peer is not registered in the routing table (handshake completed), disconnect it
		if !routingTable.HasPeer(remotePeer) {
			log.Printf("⚠️ Peer %s failed to authenticate via CA signature within 5 seconds. Disconnecting...", remotePeer)
			h.Network().ClosePeer(remotePeer)
		}
	}()
}

