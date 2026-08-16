//go:build windows

package vpn

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func (r *RealTun) Configure(ipCIDR string) error {
	ip, ipNet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", ipCIDR, err)
	}

	name := r.ifce.Name()
	mask := net.IP(ipNet.Mask).String()

	// Windows: netsh interface ipv4 set address name="<interface_name>" static <ip> <mask>
	fmt.Printf("🔧 [RealTUN] Running: netsh interface ipv4 set address name=\"%s\" static %s %s\n", name, ip.String(), mask)
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address", "name="+name, "static", ip.String(), mask)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure Windows IP via netsh: %w", err)
	}

	return nil
}

func (r *RealTun) AddRoute(subnetCIDR string) error {
	name := r.ifce.Name()
	fmt.Printf("🔧 [RealTUN] Running: netsh interface ipv4 add route prefix=%s interface=\"%s\"\n", subnetCIDR, name)
	cmd := exec.Command("netsh", "interface", "ipv4", "add", "route", "prefix="+subnetCIDR, "interface="+name)
	if err := cmd.Run(); err != nil {
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "exit status 1") {
			// Route might already exist, ignore
			return nil
		}
		return fmt.Errorf("failed to add route on Windows: %w", err)
	}
	return nil
}

func (r *RealTun) DeleteRoute(subnetCIDR string) error {
	name := r.ifce.Name()
	fmt.Printf("🔧 [RealTUN] Running: netsh interface ipv4 delete route prefix=%s interface=\"%s\"\n", subnetCIDR, name)
	cmd := exec.Command("netsh", "interface", "ipv4", "delete", "route", "prefix="+subnetCIDR, "interface="+name)
	if err := cmd.Run(); err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "exit status 1") {
			// Route might not exist, ignore
			return nil
		}
		return fmt.Errorf("failed to delete route on Windows: %w", err)
	}
	return nil
}
