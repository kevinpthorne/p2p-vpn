package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/google/uuid"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/multiformats/go-multiaddr"
	"github.com/kevinpthorne/p2p-vpn/gui"
)

// --- Profile structures ---
type Profile struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Mode             string   `json:"mode"` // "endpoint" or "relay"
	ClusterID        string   `json:"cluster_id"`
	Port             int      `json:"port"`
	DryRun           bool     `json:"dry_run"`
	TunIP            string   `json:"tun_ip"`
	Advertise        string   `json:"advertise"`
	DataKey          string   `json:"data_key"`
	IdentityPath     string   `json:"identity_path"`
	CaKeyPath        string   `json:"ca_key_path"`
	NodeSigContent   string   `json:"node_sig_content"`
	AllowedPeersPath string   `json:"allowed_peers_path"`
	RelayAddrs       []string `json:"relay_addrs"`
}

type ProfileList struct {
	Profiles []Profile `json:"profiles"`
}

// --- Global API and VPN Control State ---
var (
	apiActiveProfile     *Profile
	apiSelectedProfileID string
	apiVPNContext        context.Context
	apiVPNCancel         context.CancelFunc
	apiVPNMutex          sync.Mutex
	apiVPNUptimeStart    time.Time
	apiActiveIP          string
	apiActiveCluster     string
	apiActiveMode        string
	apiActivePeerID      string

	// Bandwidth tracking
	lastRxBytes     uint64
	lastTxBytes     uint64
	lastSpeedTime   time.Time
	currentDownSpeed float64
	currentUpSpeed   float64
	speedMutex      sync.Mutex
)

// --- Log Interception & SSE System ---
type LogBroker struct {
	mu          sync.Mutex
	subscribers map[chan string]bool
	history     []string
	maxHistory  int
}

var broker = &LogBroker{
	subscribers: make(map[chan string]bool),
	history:     make([]string, 0),
	maxHistory:  500,
}

func (b *LogBroker) Write(p []byte) (n int, err error) {
	line := string(p)
	// Strip trailing newline for SSE clean distribution
	lineClean := strings.TrimRight(line, "\r\n")

	b.mu.Lock()
	b.history = append(b.history, lineClean)
	if len(b.history) > b.maxHistory {
		b.history = b.history[1:]
	}
	// Notify active SSE connections
	for ch := range b.subscribers {
		select {
		case ch <- lineClean:
		default:
			// Non-blocking write to prevent sluggish main loops if client is slow
		}
	}
	b.mu.Unlock()

	return len(p), nil
}

func (b *LogBroker) Subscribe() chan string {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan string, 100)
	b.subscribers[ch] = true

	// Send history to new subscriber so they don't see an empty screen
	for _, line := range b.history {
		ch <- line
	}
	return ch
}

func (b *LogBroker) Unsubscribe(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subscribers, ch)
	close(ch)
}

// --- Profiles File Storage Helpers ---
func getProfilesFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "p2p-vpn")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "profiles.json"), nil
}

func loadProfiles() (ProfileList, error) {
	path, err := getProfilesFilePath()
	if err != nil {
		return ProfileList{}, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return ProfileList{Profiles: []Profile{}}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ProfileList{}, err
	}
	var list ProfileList
	if err := json.Unmarshal(data, &list); err != nil {
		return ProfileList{}, err
	}
	return list, nil
}

func saveProfiles(list ProfileList) error {
	path, err := getProfilesFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// --- Start the API Server ---
func StartAPIServer(port int) {
	// Intercept logger outputs to broadcast via SSE
	log.SetOutput(io.MultiWriter(os.Stderr, broker))

	// Setup speed tracking calculations
	go func() {
		lastSpeedTime = time.Now()
		for {
			time.Sleep(1 * time.Second)
			speedMutex.Lock()
			now := time.Now()
			elapsed := now.Sub(lastSpeedTime).Seconds()
			if elapsed > 0 {
				rx := atomic.LoadUint64(&TotalRxBytes)
				tx := atomic.LoadUint64(&TotalTxBytes)

				currentDownSpeed = float64(rx-lastRxBytes) / elapsed
				currentUpSpeed = float64(tx-lastTxBytes) / elapsed

				lastRxBytes = rx
				lastTxBytes = tx
				lastSpeedTime = now
			}
			speedMutex.Unlock()
		}
	}()

	// Serve Static Files from embed.FS
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "index.html"
		} else {
			path = strings.TrimPrefix(path, "/")
		}

		data, err := gui.StaticFiles.ReadFile(path)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		// Set proper Content-Type headers
		if strings.HasSuffix(path, ".html") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		} else if strings.HasSuffix(path, ".css") {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		} else if strings.HasSuffix(path, ".js") {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		}
		w.Write(data)
	})

	// API Routing
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/profiles", handleProfiles)
	http.HandleFunc("/api/profiles/active", handleProfilesActive)
	http.HandleFunc("/api/identities/info", handleIdentityInfo)
	http.HandleFunc("/api/identities/generate", handleIdentityGenerate)
	http.HandleFunc("/api/signatures/install", handleSignatureInstall)
	http.HandleFunc("/api/connect", handleConnect)
	http.HandleFunc("/api/disconnect", handleDisconnect)
	http.HandleFunc("/api/logs", handleSSELogs)
	http.HandleFunc("/api/pki/generate-ca", handlePKIGenerateCA)
	http.HandleFunc("/api/pki/sign", handlePKISign)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	log.Printf("🌐 Built-in Web Server starting at http://%s/", addr)
	
	// Open default browser automatically
	go openBrowser(fmt.Sprintf("http://%s/", addr))

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("❌ API server error: %v", err)
	}
}

// --- API Route Handlers ---

func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	apiVPNMutex.Lock()
	defer apiVPNMutex.Unlock()

	connected := apiVPNCancel != nil
	uptimeSec := 0
	if connected {
		uptimeSec = int(time.Since(apiVPNUptimeStart).Seconds())
	}

	// Fetch speed stats
	speedMutex.Lock()
	downSpeed := currentDownSpeed
	upSpeed := currentUpSpeed
	speedMutex.Unlock()

	// Build peer lists
	var endpointsList []map[string]interface{}
	var relaysList []map[string]interface{}

	if connected && ActiveRoutingTable != nil {
		ActiveRoutingTable.mu.RLock()
		for pid, info := range ActiveRoutingTable.peerInfo {
			latency := -1
			// Find latency if connected in libp2p network
			if ActiveHost != nil {
				conns := ActiveHost.Network().ConnsToPeer(pid)
				if len(conns) > 0 {
					// Dummy positive latency representation or fetch actual libp2p peerstore latency
					latency = 12 // default representation fallback
					peerstoreLatency := ActiveHost.Peerstore().LatencyEWMA(pid)
					if peerstoreLatency > 0 {
						latency = int(peerstoreLatency.Milliseconds())
					}
				}
			}

			if info.VirtualIP != "" {
				endpointsList = append(endpointsList, map[string]interface{}{
					"peer_id":    pid.String(),
					"role":       "endpoint",
					"virtual_ip": info.VirtualIP,
					"latency_ms": latency,
				})
			} else {
				relaysList = append(relaysList, map[string]interface{}{
					"peer_id":    pid.String(),
					"role":       "relay",
					"virtual_ip": "",
					"latency_ms": latency,
				})
			}
		}
		ActiveRoutingTable.mu.RUnlock()
	}

	profileName := "None"
	profileId := ""
	if apiActiveProfile != nil {
		profileName = apiActiveProfile.Name
		profileId = apiActiveProfile.ID
	} else if apiSelectedProfileID != "" {
		list, err := loadProfiles()
		if err == nil {
			for _, p := range list.Profiles {
				if p.ID == apiSelectedProfileID {
					profileName = p.Name
					profileId = p.ID
					break
				}
			}
		}
	}

	response := map[string]interface{}{
		"connected":         connected,
		"active_profile":    profileName,
		"active_profile_id": profileId,
		"local_peer_id":     apiActivePeerID,
		"virtual_ip":        apiActiveIP,
		"cluster":           apiActiveCluster,
		"mode":              apiActiveMode,
		"uptime_seconds":    uptimeSec,
		"down_speed_bps":    downSpeed,
		"up_speed_bps":      upSpeed,
		"endpoints":         endpointsList,
		"relays":            relaysList,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleProfiles(w http.ResponseWriter, r *http.Request) {
	list, err := loadProfiles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Default selected profile if empty and there is one
		if apiSelectedProfileID == "" && len(list.Profiles) > 0 {
			apiSelectedProfileID = list.Profiles[0].ID
			apiVPNMutex.Lock()
			if apiVPNCancel == nil {
				apiActiveProfile = new(Profile)
				*apiActiveProfile = list.Profiles[0]
				apiActiveIP = list.Profiles[0].TunIP
				apiActiveCluster = list.Profiles[0].ClusterID
				apiActiveMode = list.Profiles[0].Mode
			}
			apiVPNMutex.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		var p Profile
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if p.ID == "" {
			p.ID = uuid.New().String()
			list.Profiles = append(list.Profiles, p)
		} else {
			found := false
			for i, existing := range list.Profiles {
				if existing.ID == p.ID {
					// Handle node signature content saving
					if p.NodeSigContent != "" && p.NodeSigContent != existing.NodeSigContent {
						// Write signature PEM file locally
						sigPath, err := writeSignatureFile(p.IdentityPath, p.NodeSigContent)
						if err == nil {
							p.NodeSigContent = strings.TrimSpace(p.NodeSigContent)
							p.NodeSigContent = sigPath // store signature file path
						}
					}
					list.Profiles[i] = p
					found = true
					break
				}
			}
			if !found {
				list.Profiles = append(list.Profiles, p)
			}
		}

		if err := saveProfiles(list); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"id": p.ID})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "Missing id parameter", http.StatusBadRequest)
			return
		}

		updated := []Profile{}
		for _, p := range list.Profiles {
			if p.ID != id {
				updated = append(updated, p)
			}
		}
		list.Profiles = updated

		if err := saveProfiles(list); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleProfilesActive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ProfileID string `json:"profile_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	list, err := loadProfiles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var target *Profile
	for i := range list.Profiles {
		if list.Profiles[i].ID == req.ProfileID {
			target = &list.Profiles[i]
			break
		}
	}

	if target == nil {
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}

	apiVPNMutex.Lock()
	if apiVPNCancel == nil {
		apiActiveProfile = new(Profile)
		*apiActiveProfile = *target
		apiActiveIP = target.TunIP
		apiActiveCluster = target.ClusterID
		apiActiveMode = target.Mode
	}
	apiSelectedProfileID = req.ProfileID
	apiVPNMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// Write signatures directly into folder
func writeSignatureFile(identityPath, sigPEM string) (string, error) {
	pid, err := getPeerIDFromKey(identityPath)
	if err != nil {
		return "", err
	}
	
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "p2p-vpn", "signatures")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	
	filePath := filepath.Join(dir, fmt.Sprintf("%s.sig", pid))
	err = os.WriteFile(filePath, []byte(strings.TrimSpace(sigPEM)), 0644)
	if err != nil {
		return "", err
	}
	return filePath, nil
}

func handleIdentityInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}

	pid, err := getPeerIDFromKey(req.Path)
	if err != nil {
		// Key might not exist, but don't error out, just return empty so UI knows
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"peer_id": ""})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"peer_id": pid})
}

func getPeerIDFromKey(path string) (string, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", errors.New("file does not exist")
	}
	privKey, err := getIdentity(path)
	if err != nil {
		return "", err
	}
	pid, err := peer.IDFromPrivateKey(privKey)
	if err != nil {
		return "", err
	}
	return pid.String(), nil
}

func handleIdentityGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}

	// Remove old if any
	_ = os.Remove(req.Path)

	privKey, err := getIdentity(req.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pid, err := peer.IDFromPrivateKey(privKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"peer_id": pid.String()})
}

func handleSignatureInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IdentityPath string `json:"identity_path"`
		Signature    string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	path, err := writeSignatureFile(req.IdentityPath, req.Signature)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"sig_path": path})
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	apiVPNMutex.Lock()
	defer apiVPNMutex.Unlock()

	if apiVPNCancel != nil {
		http.Error(w, "VPN is already running", http.StatusBadRequest)
		return
	}

	var req struct {
		ProfileID string `json:"profile_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	list, err := loadProfiles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var target *Profile
	for i := range list.Profiles {
		if list.Profiles[i].ID == req.ProfileID {
			target = &list.Profiles[i]
			break
		}
	}

	if target == nil {
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}

	// Trigger VPN Thread launch
	apiVPNContext, apiVPNCancel = context.WithCancel(context.Background())
	apiActiveProfile = new(Profile)
	*apiActiveProfile = *target
	apiVPNUptimeStart = time.Now()
	apiActiveIP = target.TunIP
	apiActiveCluster = target.ClusterID
	apiActiveMode = target.Mode

	// Zero traffic counters
	atomic.StoreUint64(&TotalRxBytes, 0)
	atomic.StoreUint64(&TotalTxBytes, 0)

	// Launch VPN in background routine
	go runVPNDaemon(apiVPNContext, target)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	apiVPNMutex.Lock()
	defer apiVPNMutex.Unlock()

	if apiVPNCancel == nil {
		http.Error(w, "VPN is not running", http.StatusBadRequest)
		return
	}

	// Trigger cancellation
	apiVPNCancel()
	apiVPNCancel = nil
	apiVPNContext = nil
	apiActiveProfile = nil
	apiActiveIP = ""
	apiActiveCluster = ""
	apiActiveMode = ""
	apiActivePeerID = ""

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleSSELogs(w http.ResponseWriter, r *http.Request) {
	// Set header for Server-Sent Events (SSE)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// Subscribe to broker
	ch := broker.Subscribe()
	defer broker.Unsubscribe(ch)

	// Watch client disconnect
	notify := r.Context().Done()

	for {
		select {
		case <-notify:
			return
		case line := <-ch:
			// Write in SSE format: data: <msg>\n\n
			fmt.Fprintf(w, "data: %s\n\n", line)
			flusher.Flush()
		}
	}
}

// PKI Helper: Generate CA
func handlePKIGenerateCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OutputDir string `json:"output_dir"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Println("🔑 Generating ML-DSA-87 CA key pair via API...")
	pk, sk, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pkPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ML-DSA-87 PUBLIC KEY",
		Bytes: pk.Bytes(),
	})
	skPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ML-DSA-87 PRIVATE KEY",
		Bytes: sk.Bytes(),
	})

	pubPath := filepath.Join(req.OutputDir, "ca.pub")
	privPath := filepath.Join(req.OutputDir, "ca.key")

	if err := os.WriteFile(pubPath, pkPEM, 0644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(privPath, skPEM, 0600); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("✅ CA Keys successfully written to %s and %s!", pubPath, privPath)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"ca_pub_path": pubPath,
		"ca_key_path": privPath,
	})
}

// PKI Helper: Sign Peer ID
func handlePKISign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CAPrivPath string `json:"ca_priv_path"`
		PeerID     string `json:"peer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	targetPeerID, err := peer.Decode(req.PeerID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid target Peer ID: %v", err), http.StatusBadRequest)
		return
	}

	skPEM, err := os.ReadFile(req.CAPrivPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read CA private key file: %v", err), http.StatusBadRequest)
		return
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
		http.Error(w, fmt.Sprintf("Invalid CA private key format: %v", err), http.StatusBadRequest)
		return
	}

	msg := []byte(targetPeerID.String())
	ctxBytes := []byte("p2p-vpn-auth")
	sigBytes := make([]byte, mldsa87.SignatureSize)
	err = mldsa87.SignTo(sk, msg, ctxBytes, true, sigBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to sign Peer ID: %v", err), http.StatusInternalServerError)
		return
	}

	sigPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ML-DSA-87 SIGNATURE",
		Bytes: sigBytes,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"signature": string(sigPEM),
	})
}

// --- Background Runner for the Core VPN daemon thread ---
func runVPNDaemon(ctx context.Context, p *Profile) {
	log.Printf("🚀 Starting VPN daemon for profile: %q", p.Name)

	// Clean references from previous runs
	ActiveHost = nil
	ActiveDHT = nil
	ActiveRoutingTable = nil
	ActiveTun = nil

	// Overwrite or create Data Key file if a raw key string was pasted
	dataKeyPath := ""
	if p.DataKey != "" {
		if _, err := os.Stat(p.DataKey); err == nil {
			dataKeyPath = p.DataKey
		} else {
			// Write key string to temporary profiles folder
			home, _ := os.UserHomeDir()
			dir := filepath.Join(home, ".config", "p2p-vpn", "keys")
			_ = os.MkdirAll(dir, 0755)
			keyFile := filepath.Join(dir, fmt.Sprintf("%s-data.key", p.ID))
			_ = os.WriteFile(keyFile, []byte(p.DataKey), 0600)
			dataKeyPath = keyFile
		}
	}

	// 1. Initialize CAPubKey
	CAPubKey = nil
	if p.CaKeyPath != "" {
		pkBytes, err := readPublicKeyBytes(p.CaKeyPath)
		if err != nil {
			log.Printf("❌ Failed to read CA public key: %v", err)
			cleanupActiveVPN()
			return
		}
		pubKey := new(mldsa87.PublicKey)
		if err := pubKey.UnmarshalBinary(pkBytes); err != nil {
			log.Printf("❌ Invalid CA public key: %v", err)
			cleanupActiveVPN()
			return
		}
		CAPubKey = pubKey
		log.Println("🛡️ PKI Authentication ENABLED using CA Public Key")
	}

	// 2. Initialize Node Signature
	NodeSignature = nil
	// Check signature content (either file path or PEM pasted content written to file)
	sigPath := p.NodeSigContent
	if sigPath != "" {
		if _, err := os.Stat(sigPath); err != nil {
			// Try reading as raw PEM string and save
			filePath, err := writeSignatureFile(p.IdentityPath, p.NodeSigContent)
			if err == nil {
				sigPath = filePath
			}
		}

		sigPEM, err := os.ReadFile(sigPath)
		if err != nil {
			log.Printf("❌ Failed to read node signature from %q: %v", sigPath, err)
			cleanupActiveVPN()
			return
		}
		sigBytes, err := decodeSignaturePEM(sigPEM)
		if err != nil || len(sigBytes) == 0 {
			log.Printf("❌ Failed to decode node signature: %v", err)
			cleanupActiveVPN()
			return
		}
		NodeSignature = sigBytes
		log.Println("🛡️ Node Signature loaded for CA verification")
	}

	// 3. Load Data Encryption Key for Endpoints
	var dataKey []byte
	if p.Mode == "endpoint" {
		if dataKeyPath != "" {
			dataKeyHex, err := os.ReadFile(dataKeyPath)
			if err != nil {
				log.Printf("❌ Failed to read datakey: %v", err)
				cleanupActiveVPN()
				return
			}
			dataKey, err = hex.DecodeString(strings.TrimSpace(string(dataKeyHex)))
			if err != nil {
				log.Printf("❌ Invalid datakey hex: %v", err)
				cleanupActiveVPN()
				return
			}
			if len(dataKey) != 32 {
				log.Printf("❌ Datakey must be 32 bytes (64 hex characters). Got %d bytes", len(dataKey))
				cleanupActiveVPN()
				return
			}
			if err := InitCipher(dataKey); err != nil {
				log.Printf("❌ Failed to initialize cipher: %v", err)
				cleanupActiveVPN()
				return
			}
			log.Println("🔒 AES-256-GCM End-to-End Encryption ENABLED")
		} else {
			log.Println("❌ Endpoint mode requires a data key!")
			cleanupActiveVPN()
			return
		}

		if p.TunIP == "" {
			log.Println("❌ Endpoint mode requires a virtual TUN IP/CIDR!")
			cleanupActiveVPN()
			return
		}
	}

	// 4. Load Node Identity Private Key
	identityPath := p.IdentityPath
	if identityPath == "" {
		identityPath = fmt.Sprintf("identity-%s.key", p.Mode)
	}
	privKey, err := getIdentity(identityPath)
	if err != nil {
		log.Printf("❌ Failed to load identity key: %v", err)
		cleanupActiveVPN()
		return
	}

	// 5. Setup TUN Interface
	var tunIfce TunInterface
	if p.Mode == "endpoint" {
		if p.DryRun {
			log.Println("📦 Dry-run mode enabled. Simulating TUN interface...")
			tunIfce = NewMockTun("mock-tun0")
		} else {
			var err error
			tunIfce, err = NewRealTun()
			if err != nil {
				log.Printf("❌ Failed to create TUN interface: %v. Make sure to run as root (sudo).", err)
				cleanupActiveVPN()
				return
			}
		}
		ActiveTun = tunIfce

		// Configure TUN device IP
		if err := tunIfce.Configure(p.TunIP); err != nil {
			log.Printf("❌ Failed to configure TUN interface: %v", err)
			cleanupActiveVPN()
			return
		}
		log.Printf("✅ TUN Interface %s configured with IP/CIDR %s", tunIfce.Name(), p.TunIP)
	}

	// 6. Setup Routing Table & Parse Subnets
	routingTable := NewRoutingTable()
	ActiveRoutingTable = routingTable

	var advertisedSubnets []string
	if p.Advertise != "" {
		for _, s := range strings.Split(p.Advertise, ",") {
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				advertisedSubnets = append(advertisedSubnets, trimmed)
			}
		}
	}

	// 7. Parse allowed peers
	var allowedPeers []peer.ID
	if p.AllowedPeersPath != "" {
		file, err := os.Open(p.AllowedPeersPath)
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				pid, err := peer.Decode(line)
				if err == nil {
					allowedPeers = append(allowedPeers, pid)
				}
			}
			log.Printf("🔒 Loaded %d allowed Peer IDs from whitelist file", len(allowedPeers))
		}

		// Auto-whitelist relays
		for _, rAddr := range p.RelayAddrs {
			ma, err := multiaddr.NewMultiaddr(rAddr)
			if err == nil {
				info, err := peer.AddrInfoFromP2pAddr(ma)
				if err == nil {
					exists := false
					for _, existing := range allowedPeers {
						if existing == info.ID {
							exists = true
							break
						}
					}
					if !exists {
						allowedPeers = append(allowedPeers, info.ID)
					}
				}
			}
		}
	}

	// 8. Make Libp2p Host
	h, dhtObj, err := makeHost(ctx, p.Mode, privKey, p.RelayAddrs, p.Port, p.ClusterID, allowedPeers)
	if err != nil {
		log.Printf("❌ Failed to initialize libp2p host: %v", err)
		cleanupActiveVPN()
		return
	}
	ActiveHost = h
	ActiveDHT = dhtObj

	apiActivePeerID = h.ID().String()

	log.Printf("---------------------------------------------")
	log.Printf("P2P VPN Node Started. Mode: %s", strings.ToUpper(p.Mode))
	log.Printf("Peer ID: %s", h.ID())
	log.Printf("Listen Port: %d", p.Port)
	log.Printf("Cluster ID: %s", p.ClusterID)
	log.Printf("---------------------------------------------")

	// 9. Connect to Relays
	if p.Mode == "endpoint" {
		for _, rAddr := range p.RelayAddrs {
			trimmed := strings.TrimSpace(rAddr)
			if trimmed != "" {
				log.Printf("🔌 Connecting to bootstrap relay: %s", trimmed)
				connectToPeer(ctx, h, trimmed)
			}
		}
	}

	// 10. Bootstrap DHT
	log.Println("🔄 Bootstrapping Kademlia DHT...")
	if err := dhtObj.Bootstrap(ctx); err != nil {
		log.Printf("❌ DHT Bootstrap failed: %v", err)
		cleanupActiveVPN()
		return
	}

	// 11. Handshake Handlers
	h.SetStreamHandler(HandshakeProtocol, func(s network.Stream) {
		localVIP := ""
		var localSubs []string
		if p.Mode == "endpoint" {
			localVIP = p.TunIP
			localSubs = advertisedSubnets
		}
		HandleIncomingHandshake(ctx, h, s, localVIP, localSubs, routingTable, tunIfce, CAPubKey, NodeSignature)
	})

	if p.Mode == "endpoint" {
		h.SetStreamHandler(TunnelProtocol, func(s network.Stream) {
			remotePeer := s.Conn().RemotePeer()
			log.Printf("📥 Incoming tunnel data stream established from %s", remotePeer)

			routingTable.SetStream(remotePeer, s)
			defer s.Close()
			defer routingTable.ClearStreamIfMatches(remotePeer, s)

			for {
				packet, err := readFrame(s, dataKey)
				if err != nil {
					break
				}
				if tunIfce != nil {
					if _, err := tunIfce.Write(packet); err != nil {
						log.Printf("⚠️ Failed to inject packet to TUN interface: %v", err)
					}
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
				return
			}
			StartCAAuthKicker(ctx, h, routingTable, remotePeer, CAPubKey)

			localVIP := ""
			var localSubs []string
			if p.Mode == "endpoint" {
				localVIP = p.TunIP
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

	// 12. Discovery Loop
	routingDiscovery := routing.NewRoutingDiscovery(dhtObj)
	if p.Mode == "endpoint" {
		go func() {
			for {
				log.Println("📢 Advertising presence in DHT...")
				_, err := routingDiscovery.Advertise(ctx, p.ClusterID)
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

	if p.Mode == "relay" {
		log.Println("🟢 Relay Active. Waiting for peers...")
		go func() {
			for {
				log.Println("--- Relay Addresses (Share with endpoints) ---")
				for _, a := range h.Addrs() {
					log.Printf("   %s/p2p/%s", a, h.ID())
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Minute):
				}
			}
		}()
	} else {
		// Endpoint print addresses
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

		// Discovery finding loop
		go func() {
			for {
				log.Println("🔎 Searching DHT for cluster peers...")
				peerChan, err := routingDiscovery.FindPeers(ctx, p.ClusterID)
				if err != nil {
					log.Printf("⚠️ Discovery error: %v", err)
					time.Sleep(10 * time.Second)
					continue
				}

				for peerInfo := range peerChan {
					if peerInfo.ID == h.ID() {
						continue
					}
					if h.Network().Connectedness(peerInfo.ID) != network.Connected {
						log.Printf("✨ Discovered cluster peer: %s. Dialing...", peerInfo.ID)
						if err := h.Connect(ctx, peerInfo); err != nil {
							log.Printf("⚠️ Connection failed to discovered peer %s: %v", peerInfo.ID, err)
						} else {
							log.Printf("✅ Successfully connected to discovered peer %s", peerInfo.ID)
						}
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(15 * time.Second):
				}
			}
		}()

		// 13. TUN Reader loop
		go func() {
			log.Println("🚀 TUN Reader Loop running...")
			buf := make([]byte, 2048)
			for {
				select {
				case <-ctx.Done():
					return
				default:
					n, err := tunIfce.Read(buf)
					if err != nil {
						time.Sleep(100 * time.Millisecond)
						continue
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

					peerID, found := routingTable.LookupPeer(destIP)
					if !found {
						continue
					}

					pktCopy := make([]byte, len(packet))
					copy(pktCopy, packet)

					q := routingTable.GetOrCreateQueue(peerID, ctx, h, dataKey, tunIfce)
					select {
					case q <- pktCopy:
					default:
					}
				}
			}
		}()
	}

	// Block until context cancelled
	<-ctx.Done()

	log.Println("🧹 Shutting down VPN engine... Cleaning up routes and interfaces")
	if tunIfce != nil {
		_, _ = routingTable.UnregisterPeer("")
		tunIfce.Close()
		log.Println("👋 Closed TUN interface.")
	}
	h.Close()
	log.Println("🛑 VPN engine shutdown complete.")
}

func cleanupActiveVPN() {
	apiVPNMutex.Lock()
	defer apiVPNMutex.Unlock()
	
	if apiVPNCancel != nil {
		apiVPNCancel()
		apiVPNCancel = nil
		apiVPNContext = nil
	}
	apiActiveProfile = nil
	apiActiveIP = ""
	apiActiveCluster = ""
	apiActiveMode = ""
	apiActivePeerID = ""
}

// Helper: Open browser cross-platform
func openBrowser(url string) {
	var err error
	switch os.Getenv("OS") { // Simple environment check, or check GOOS
	default:
		// macOS default open
		err = execCommand("open", url)
		if err != nil {
			// Linux default xdg-open
			err = execCommand("xdg-open", url)
		}
	}
	if err != nil {
		log.Printf("⚠️ Could not open default browser: %v. Please open %s manually.", err, url)
	}
}

func execCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Start()
}
