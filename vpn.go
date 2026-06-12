package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

// Configuration Constants
const (
	TunnelProtocol    = "/p2p-vpn/tunnel/1.0.0"
	HandshakeProtocol = "/p2p-vpn/handshake/1.0.0"
)

// HandshakeMessage contains the routes and virtual IP details of an endpoint
type HandshakeMessage struct {
	VirtualIP string   `json:"virtual_ip"` // e.g. "10.200.0.1/24"
	Subnets   []string `json:"subnets"`    // e.g. ["10.100.1.0/24"]
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
}

func NewRoutingTable() *RoutingTable {
	return &RoutingTable{
		ipToPeer:      make(map[string]peer.ID),
		peerInfo:      make(map[peer.ID]*PeerRoutes),
		activeStreams: make(map[peer.ID]network.Stream),
		streamMutexes: make(map[peer.ID]*sync.Mutex),
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

// Cryptography Helpers
func encryptGCM(plaintext []byte, key []byte) (nonce []byte, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func decryptGCM(nonce, ciphertext []byte, key []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Framing Helpers
func writeFrame(w io.Writer, payload []byte, key []byte) error {
	var nonce, ciphertext []byte
	var err error
	if len(key) > 0 {
		nonce, ciphertext, err = encryptGCM(payload, key)
		if err != nil {
			return err
		}
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
	return nil
}

func readFrame(r io.Reader, key []byte) ([]byte, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	totalLen := binary.BigEndian.Uint16(lenBuf)

	nonceSize := 0
	if len(key) > 0 {
		nonceSize = 12 // Standard AES-GCM nonce size
	}

	if int(totalLen) < nonceSize {
		return nil, fmt.Errorf("frame size %d too small for nonce", totalLen)
	}

	buf := make([]byte, totalLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	if len(key) > 0 {
		nonce := buf[:nonceSize]
		ciphertext := buf[nonceSize:]
		return decryptGCM(nonce, ciphertext, key)
	}

	return buf, nil
}

// Host Factory & Identity Functions (Adapted from p2p-tunnel)
func makeHost(ctx context.Context, pskPath, mode string, privKey crypto.PrivKey, relayAddrs []string, port int, clusterID string) (host.Host, *dht.IpfsDHT, error) {
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
		opts = append(opts,
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableRelayService(),
			libp2p.EnableNATService(),
		)
	} else {
		opts = append(opts,
			libp2p.ForceReachabilityPrivate(),
			libp2p.EnableAutoRelayWithStaticRelays(bootstrapPeers),
			libp2p.EnableHolePunching(),
		)
	}

	// Private network swarm key
	pskFile, err := os.Open(pskPath)
	if err != nil {
		return nil, nil, fmt.Errorf("could not open swarm.key: %w", err)
	}
	defer pskFile.Close()

	pskBytes, err := io.ReadAll(pskFile)
	if err != nil {
		return nil, nil, err
	}
	pskFile.Seek(0, 0)
	hash := sha256.Sum256(pskBytes)
	log.Printf("🔑 Swarm Key Fingerprint: %x", hash)

	psk, err := pnet.DecodeV1PSK(pskFile)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid swarm.key format: %w", err)
	}
	opts = append(opts, libp2p.PrivateNetwork(psk))

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
func pushHandshake(ctx context.Context, h host.Host, pid peer.ID, localVirtualIP string, localSubnets []string) {
	transientCtx := network.WithAllowLimitedConn(ctx, "vpn-handshake")
	s, err := h.NewStream(transientCtx, pid, HandshakeProtocol)
	if err != nil {
		log.Printf("⚠️ Handshake stream creation failed to %s: %v", pid, err)
		return
	}
	defer s.Close()

	msg := HandshakeMessage{
		VirtualIP: localVirtualIP,
		Subnets:   localSubnets,
	}

	encoder := json.NewEncoder(s)
	if err := encoder.Encode(&msg); err != nil {
		log.Printf("⚠️ Handshake encoding failed: %v", err)
		return
	}
	log.Printf("✅ Handshake successfully sent to %s", pid)
}
