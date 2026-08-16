package vpn

import (
	"fmt"
	"io"

	"github.com/songgao/water"
)

// TunInterface defines the interface for our TUN device
type TunInterface interface {
	io.ReadWriteCloser
	Name() string
	Configure(ipCIDR string) error
	AddRoute(subnetCIDR string) error
	DeleteRoute(subnetCIDR string) error
}

// RealTun wraps the actual water.Interface
type RealTun struct {
	ifce *water.Interface
}

func NewRealTun() (TunInterface, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}
	ifce, err := water.New(config)
	if err != nil {
		return nil, err
	}
	return &RealTun{ifce: ifce}, nil
}

func (r *RealTun) Read(p []byte) (n int, err error) {
	return r.ifce.Read(p)
}

func (r *RealTun) Write(p []byte) (n int, err error) {
	return r.ifce.Write(p)
}

func (r *RealTun) Close() error {
	return r.ifce.Close()
}

func (r *RealTun) Name() string {
	return r.ifce.Name()
}

// MockTun acts as a dry-run mock TUN interface
type MockTun struct {
	name    string
	readCh  chan []byte
	OnWrite func([]byte)
}

func NewMockTun(name string) TunInterface {
	return &MockTun{
		name:   name,
		readCh: make(chan []byte, 100),
	}
}

func (m *MockTun) Read(p []byte) (n int, err error) {
	pkt, ok := <-m.readCh
	if !ok {
		return 0, io.EOF
	}
	copy(p, pkt)
	return len(pkt), nil
}

func (m *MockTun) InjectPacket(pkt []byte) {
	select {
	case m.readCh <- pkt:
	default:
		// Drop if buffer full
	}
}

func (m *MockTun) Write(p []byte) (n int, err error) {
	// Log packet writes in hex or size
	fmt.Printf("📦 [MockTUN %s] Write: intercepted raw IP packet of size %d bytes\n", m.name, len(p))
	if len(p) > 28 && p[9] == 17 { // IPv4 protocol 17 = UDP
		payload := p[28:]
		fmt.Printf("   💬 UDP Payload (Decrypted): %s\n", string(payload))
	}
	if m.OnWrite != nil {
		m.OnWrite(p)
	}
	return len(p), nil
}

func (m *MockTun) Close() error {
	fmt.Printf("📦 [MockTUN %s] Close interface\n", m.name)
	// Safe close to prevent panics on double close
	defer func() { recover() }()
	close(m.readCh)
	return nil
}

func (m *MockTun) Name() string {
	return m.name
}

func (m *MockTun) Configure(ipCIDR string) error {
	fmt.Printf("📦 [MockTUN %s] Configure: setting IP %s\n", m.name, ipCIDR)
	return nil
}

func (m *MockTun) AddRoute(subnetCIDR string) error {
	fmt.Printf("📦 [MockTUN %s] AddRoute: routing subnet %s to interface\n", m.name, subnetCIDR)
	return nil
}

func (m *MockTun) DeleteRoute(subnetCIDR string) error {
	fmt.Printf("📦 [MockTUN %s] DeleteRoute: removing route for subnet %s\n", m.name, subnetCIDR)
	return nil
}
