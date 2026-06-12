package main

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strings"

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

func (r *RealTun) Configure(ipCIDR string) error {
	ip, ipNet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", ipCIDR, err)
	}

	name := r.ifce.Name()
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		// Linux: ip addr add 10.200.0.1/24 dev tun0
		fmt.Printf("🔧 [RealTUN] Running: ip addr add %s dev %s\n", ipCIDR, name)
		cmd = exec.Command("ip", "addr", "add", ipCIDR, "dev", name)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add address: %w", err)
		}
		// Linux: ip link set dev tun0 up
		fmt.Printf("🔧 [RealTUN] Running: ip link set dev %s up\n", name)
		cmd = exec.Command("ip", "link", "set", "dev", name, "up")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to set link up: %w", err)
		}
	case "darwin":
		// macOS: ifconfig utun0 10.200.0.1 10.200.0.1 netmask 255.255.255.0 up
		mask := net.IP(ipNet.Mask).String()
		fmt.Printf("🔧 [RealTUN] Running: ifconfig %s %s %s netmask %s up\n", name, ip.String(), ip.String(), mask)
		cmd = exec.Command("ifconfig", name, ip.String(), ip.String(), "netmask", mask, "up")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to configure ifconfig: %w", err)
		}
		// On macOS, a point-to-point interface requires an explicit route for its virtual subnet
		subnetStr := ipNet.String()
		fmt.Printf("🔧 [RealTUN] Running: route add -net %s -interface %s\n", subnetStr, name)
		cmd = exec.Command("route", "add", "-net", subnetStr, "-interface", name)
		if err := cmd.Run(); err != nil {
			if !strings.Contains(err.Error(), "File exists") {
				return fmt.Errorf("failed to add subnet route on macOS: %w", err)
			}
		}
	default:
		return fmt.Errorf("unsupported platform for auto-configuration: %s", runtime.GOOS)
	}

	return nil
}

func (r *RealTun) AddRoute(subnetCIDR string) error {
	name := r.ifce.Name()
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		// Linux: ip route add 10.100.1.0/24 dev tun0
		fmt.Printf("🔧 [RealTUN] Running: ip route add %s dev %s\n", subnetCIDR, name)
		cmd = exec.Command("ip", "route", "add", subnetCIDR, "dev", name)
		if err := cmd.Run(); err != nil {
			if strings.Contains(err.Error(), "exit status 2") || strings.Contains(err.Error(), "File exists") {
				// Route already exists, ignore
				return nil
			}
			return fmt.Errorf("failed to add route: %w", err)
		}
	case "darwin":
		// macOS: route add -net 10.100.1.0/24 -interface utun0
		fmt.Printf("🔧 [RealTUN] Running: route add -net %s -interface %s\n", subnetCIDR, name)
		cmd = exec.Command("route", "add", "-net", subnetCIDR, "-interface", name)
		if err := cmd.Run(); err != nil {
			if strings.Contains(err.Error(), "File exists") {
				// Route already exists, ignore
				return nil
			}
			return fmt.Errorf("failed to add route: %w", err)
		}
	default:
		return fmt.Errorf("unsupported platform for route configuration: %s", runtime.GOOS)
	}
	return nil
}

func (r *RealTun) DeleteRoute(subnetCIDR string) error {
	name := r.ifce.Name()
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		fmt.Printf("🔧 [RealTUN] Running: ip route del %s dev %s\n", subnetCIDR, name)
		cmd = exec.Command("ip", "route", "del", subnetCIDR, "dev", name)
		if err := cmd.Run(); err != nil {
			if strings.Contains(err.Error(), "exit status 2") || strings.Contains(err.Error(), "No such process") {
				// Route already deleted or doesn't exist, ignore
				return nil
			}
			return fmt.Errorf("failed to delete route: %w", err)
		}
	case "darwin":
		fmt.Printf("🔧 [RealTUN] Running: route delete -net %s -interface %s\n", subnetCIDR, name)
		cmd = exec.Command("route", "delete", "-net", subnetCIDR, "-interface", name)
		if err := cmd.Run(); err != nil {
			if strings.Contains(err.Error(), "not in table") || strings.Contains(err.Error(), "exit status 1") {
				// Route doesn't exist, ignore
				return nil
			}
			return fmt.Errorf("failed to delete route: %w", err)
		}
	default:
		return fmt.Errorf("unsupported platform for route deletion: %s", runtime.GOOS)
	}
	return nil
}

// MockTun acts as a dry-run mock TUN interface
type MockTun struct {
	name   string
	readCh chan []byte
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
